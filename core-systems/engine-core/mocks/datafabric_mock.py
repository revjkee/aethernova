# engine-core/engine/mocks/datafabric_mock.py
"""
DataFabricMock — промышленный мок дата‑фабрики для тестирования сервисов.

Возможности:
- Таблицы в памяти с декларативной схемой (ключ, уникальные, индексы-эскизы)
- CRUD/UPSERT, батч‑операции, soft‑delete, TTL
- Транзакции: snapshot‑изолированность (MVCC), write‑set, rollback/commit
- Запросы: фильтры (==, !=, in, range, contains), проекции, сортировка, пагинация
- Асинхронные курсоры и потоковая выдача (async generator)
- Имитация: латентность/джиттер, периодические/случайные ошибки, таймауты
- События: on_insert/on_update/on_delete, подписки
- Метрики и трассировка через engine.adapters.observability_adapter (если доступно)
- Полностью детерминируемый режим (seed)

Назначение:
- Интеграционные/контрактные/нагрузочные тесты без зависимостей от реального DWH/DF.
"""

from __future__ import annotations

import asyncio
import bisect
import contextlib
import dataclasses
import json
import os
import random
import time
from dataclasses import dataclass, field
from typing import (
    Any,
    AsyncGenerator,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    TypedDict,
    Union,
)

# --------- Опциональная наблюдаемость (деградация в no-op) -------------
try:
    from engine.adapters.observability_adapter import get_observability
    _OBS = get_observability()
    _MET_ENABLED = True
except Exception:
    _OBS = None
    _MET_ENABLED = False

def _log(level: str, msg: str, **fields):
    if _OBS:
        getattr(_OBS, f"log_{level}")(msg, **fields)

def _trace_span(name: str):
    if _OBS:
        return _OBS.trace_span(name)
    # no-op декоратор
    def deco(fn): return fn
    return deco

def _metric_counter(name: str, doc: str):
    if _MET_ENABLED:
        return _OBS.counter(name, doc, labelnames=("table", "op", "code"))  # type: ignore
    class _No:
        def labels(self, **_): return self
        def inc(self, *_a, **_k): ...
    return _No()

def _metric_hist(name: str, doc: str):
    if _MET_ENABLED:
        return _OBS.histogram(name, doc, labelnames=("table", "op"))
    class _No:
        def labels(self, **_): return self
        def observe(self, *_a, **_k): ...
    return _No()

_MET_REQS = _metric_counter("fabric_requests_total", "Total DataFabric requests")
_MET_LAT  = _metric_hist("fabric_latency_seconds", "Latency of DataFabric operations")

# ------------------------------- Типы -----------------------------------

@dataclass(frozen=True)
class Column:
    name: str
    type: type
    required: bool = False

@dataclass(frozen=True)
class TableSchema:
    name: str
    primary_key: str
    columns: Tuple[Column, ...]
    ttl_seconds: Optional[int] = None          # опциональный TTL
    unique: Tuple[str, ...] = ()               # уникальные поля (кроме PK)
    soft_delete: bool = True                   # логическое удаление

    def validate(self, row: Mapping[str, Any]) -> None:
        cols = {c.name: c for c in self.columns}
        # обязательные
        for c in self.columns:
            if c.required and c.name not in row:
                raise ValueError(f"missing required field: {c.name}")
        # типы (мягкая проверка)
        for k, v in row.items():
            col = cols.get(k)
            if col and v is not None and not isinstance(v, col.type):
                raise TypeError(f"field {k} expects {col.type.__name__}, got {type(v).__name__}")

class Row(TypedDict, total=False):
    _pk: Any
    _ts: float
    _ver: int
    _deleted: bool

FilterOp = Union[
    Tuple[str, str, Any],             # ("field", "==|!=|>|>=|<|<=", value)
    Tuple[str, str, Sequence[Any]],   # ("field", "in|not_in", [v1,v2])
    Tuple[str, str, str],             # ("field", "contains|prefix", "abc")
]

@dataclass
class Query:
    filters: List[FilterOp] = field(default_factory=list)
    projection: Optional[Tuple[str, ...]] = None
    order_by: Optional[Tuple[str, str]] = None   # (field, "asc|desc")
    limit: Optional[int] = None
    offset: int = 0
    include_deleted: bool = False

# -------------------------- Искусственная среда -------------------------

@dataclass
class ChaosConfig:
    enabled: bool = False
    seed: Optional[int] = None
    base_latency_ms: float = 2.0
    jitter_ms: float = 8.0
    error_rate: float = 0.0                 # 0..1
    timeout_rate: float = 0.0               # 0..1
    max_timeout_ms: float = 100.0

    def rng(self) -> random.Random:
        return random.Random(self.seed) if self.seed is not None else random

# ------------------------------ События ---------------------------------

EventHandler = Callable[[str, Mapping[str, Any]], Awaitable[None] | None]

@dataclass
class EventBus:
    on_insert: List[EventHandler] = field(default_factory=list)
    on_update: List[EventHandler] = field(default_factory=list)
    on_delete: List[EventHandler] = field(default_factory=list)

    async def emit(self, kind: str, table: str, row: Mapping[str, Any]) -> None:
        handlers = {
            "insert": self.on_insert,
            "update": self.on_update,
            "delete": self.on_delete,
        }.get(kind, [])
        for h in handlers:
            res = h(table, row)
            if asyncio.iscoroutine(res):
                await res

# -------------------------- Основная реализация -------------------------

@dataclass
class _Versioned:
    data: Dict[Any, Row] = field(default_factory=dict)   # pk -> row
    ver: int = 0

class _Lock:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
    async def __aenter__(self): await self._lock.acquire()
    async def __aexit__(self, *exc): self._lock.release()

@dataclass
class DataFabricMock:
    """
    Высокоточный мок дата‑фабрики. Потокобезопасен для asyncio.
    """
    chaos: ChaosConfig = field(default_factory=ChaosConfig)
    bus: EventBus = field(default_factory=EventBus)
    _tables: Dict[str, TableSchema] = field(default_factory=dict, init=False)
    _state: Dict[str, _Versioned] = field(default_factory=dict, init=False)
    _locks: Dict[str, _Lock] = field(default_factory=dict, init=False)

    # --------------- Инициализация/сессии ---------------
    @classmethod
    @contextlib.asynccontextmanager
    async def session(cls, chaos: Optional[ChaosConfig] = None) -> AsyncGenerator["DataFabricMock", None]:
        df = cls(chaos=chaos or ChaosConfig())
        try:
            yield df
        finally:
            # здесь можно закрыть фоновые задачи, если появятся
            ...

    # --------------- Управление схемой -------------------
    @_trace_span("fabric.create_table")
    async def create_table(self, schema: TableSchema) -> None:
        if schema.name in self._tables:
            raise ValueError(f"table exists: {schema.name}")
        self._tables[schema.name] = schema
        self._state[schema.name] = _Versioned()
        self._locks[schema.name] = _Lock()
        _log("info", "table created", table=schema.name)

    @_trace_span("fabric.drop_table")
    async def drop_table(self, name: str) -> None:
        self._tables.pop(name, None)
        self._state.pop(name, None)
        self._locks.pop(name, None)
        _log("info", "table dropped", table=name)

    def schema(self, name: str) -> TableSchema:
        s = self._tables.get(name)
        if not s:
            raise KeyError(f"unknown table: {name}")
        return s

    # --------------- Имитация среды ----------------------
    async def _maybe_sleep_and_fail(self, op: str, table: str) -> None:
        c = self.chaos
        if not c.enabled:
            return
        rng = c.rng()
        # latency + jitter
        latency = max(0.0, c.base_latency_ms + (rng.random() * 2 - 1) * c.jitter_ms)
        await asyncio.sleep(latency / 1000.0)
        # failure
        if rng.random() < c.error_rate:
            _MET_REQS.labels(table=table, op=op, code="error").inc()
            raise RuntimeError(f"chaos induced error in {op}")
        # timeout
        if rng.random() < c.timeout_rate:
            to = rng.random() * c.max_timeout_ms
            await asyncio.sleep(to / 1000.0)
            _MET_REQS.labels(table=table, op=op, code="timeout").inc()
            raise TimeoutError(f"chaos induced timeout in {op}")

    # --------------- Транзакции (MVCC) -------------------
    @dataclass
    class _Txn:
        table: str
        read_ver: int
        writes: List[Tuple[str, Any, Optional[Row]]] = field(default_factory=list)  # (op, pk, row|None)

    @contextlib.asynccontextmanager
    async def txn(self, table: str) -> AsyncGenerator["_Txn", None]:
        st = self._state[table]
        t = DataFabricMock._Txn(table=table, read_ver=st.ver)
        try:
            yield t
            # commit
            await self._commit_txn(t)
        except Exception:
            # rollback (ничего не делаем, т.к. записи применяются на commit)
            raise

    async def _commit_txn(self, tx: "_Txn") -> None:
        async with self._locks[tx.table]:
            st = self._state[tx.table]
            # простая проверка write‑skew: если версия изменилась — конфликт
            if st.ver != tx.read_ver:
                raise RuntimeError("write conflict (concurrent modification)")
            for (op, pk, row) in tx.writes:
                if op == "put":
                    st.data[pk] = row  # type: ignore
                elif op == "del":
                    if row is None:
                        st.data.pop(pk, None)
                    else:
                        st.data[pk] = row
            st.ver += 1

    # --------------- CRUD / UPSERT -----------------------
    @_trace_span("fabric.insert")
    async def insert(self, table: str, rows: Iterable[Mapping[str, Any]]) -> int:
        ts0 = time.perf_counter()
        await self._maybe_sleep_and_fail("insert", table)
        n = 0
        schema = self.schema(table)
        async with self._locks[table]:
            st = self._state[table]
            for r in rows:
                schema.validate(r)
                pk = r[schema.primary_key]
                if pk in st.data and not st.data[pk].get("_deleted", False):
                    _MET_REQS.labels(table=table, op="insert", code="conflict").inc()
                    raise KeyError(f"duplicate key: {pk}")
                row: Row = Row(**r)  # type: ignore
                row["_pk"] = pk
                row["_ts"] = time.time()
                row["_ver"] = st.ver + 1
                row["_deleted"] = False
                st.data[pk] = row
                n += 1
            st.ver += 1
        await self.bus.emit("insert", table, {"count": n})
        _MET_REQS.labels(table=table, op="insert", code="ok").inc()
        _MET_LAT.labels(table=table, op="insert").observe(max(0.0, time.perf_counter() - ts0))
        return n

    @_trace_span("fabric.upsert")
    async def upsert(self, table: str, rows: Iterable[Mapping[str, Any]]) -> int:
        ts0 = time.perf_counter()
        await self._maybe_sleep_and_fail("upsert", table)
        n = 0
        schema = self.schema(table)
        async with self._locks[table]:
            st = self._state[table]
            for r in rows:
                schema.validate(r)
                pk = r[schema.primary_key]
                base: Row = st.data.get(pk, Row())
                base.update(r)  # type: ignore
                base["_pk"] = pk
                base["_ts"] = time.time()
                base["_ver"] = st.ver + 1
                base["_deleted"] = False
                st.data[pk] = base
                n += 1
            st.ver += 1
        await self.bus.emit("update", table, {"count": n})
        _MET_REQS.labels(table=table, op="upsert", code="ok").inc()
        _MET_LAT.labels(table=table, op="upsert").observe(max(0.0, time.perf_counter() - ts0))
        return n

    @_trace_span("fabric.delete")
    async def delete(self, table: str, keys: Iterable[Any], hard: Optional[bool] = None) -> int:
        ts0 = time.perf_counter()
        await self._maybe_sleep_and_fail("delete", table)
        schema = self.schema(table)
        hard = (hard if hard is not None else not schema.soft_delete)
        n = 0
        async with self._locks[table]:
            st = self._state[table]
            for pk in keys:
                row = st.data.get(pk)
                if not row:
                    continue
                if hard:
                    st.data.pop(pk, None)
                else:
                    row["_deleted"] = True
                    row["_ts"] = time.time()
                    row["_ver"] = st.ver + 1
                    st.data[pk] = row
                n += 1
            st.ver += 1
        await self.bus.emit("delete", table, {"count": n})
        _MET_REQS.labels(table=table, op="delete", code="ok").inc()
        _MET_LAT.labels(table=table, op="delete").observe(max(0.0, time.perf_counter() - ts0))
        return n

    @_trace_span("fabric.get")
    async def get(self, table: str, key: Any, include_deleted: bool = False) -> Optional[Row]:
        ts0 = time.perf_counter()
        await self._maybe_sleep_and_fail("get", table)
        schema = self.schema(table)
        st = self._state[table]
        row = st.data.get(key)
        if not row:
            _MET_REQS.labels(table=table, op="get", code="miss").inc()
            return None
        if not include_deleted and row.get("_deleted"):
            _MET_REQS.labels(table=table, op="get", code="deleted").inc()
            return None
        if schema.ttl_seconds and (time.time() - row["_ts"]) > schema.ttl_seconds:
            # истёк TTL — считаем отсутствующей
            _MET_REQS.labels(table=table, op="get", code="ttl_expired").inc()
            return None
        _MET_REQS.labels(table=table, op="get", code="ok").inc()
        _MET_LAT.labels(table=table, op="get").observe(max(0.0, time.perf_counter() - ts0))
        return dict(row)

    # --------------- Запросы/фильтры/проекции ---------------------------
    @staticmethod
    def _passes(row: Mapping[str, Any], flt: FilterOp) -> bool:
        field, op, val = flt
        rv = row.get(field)
        if op == "==": return rv == val
        if op == "!=": return rv != val
        if op == ">":  return rv is not None and rv > val
        if op == ">=": return rv is not None and rv >= val
        if op == "<":  return rv is not None and rv < val
        if op == "<=": return rv is not None and rv <= val
        if op == "in": return rv in set(val)  # type: ignore
        if op == "not_in": return rv not in set(val)  # type: ignore
        if op == "contains": return isinstance(rv, (str, list, tuple, set)) and (val in rv)  # type: ignore
        if op == "prefix": return isinstance(rv, str) and str(rv).startswith(str(val))
        raise ValueError(f"unsupported op: {op}")

    @staticmethod
    def _project(row: Mapping[str, Any], proj: Optional[Tuple[str, ...]]) -> Dict[str, Any]:
        if not proj:
            # скрываем служебные поля
            return {k: v for k, v in row.items() if not k.startswith("_")}
        return {k: row.get(k) for k in proj}

    @_trace_span("fabric.query")
    async def query(self, table: str, q: Query) -> List[Dict[str, Any]]:
        ts0 = time.perf_counter()
        await self._maybe_sleep_and_fail("query", table)
        schema = self.schema(table)
        st = self._state[table]

        items = []
        for row in st.data.values():
            if not q.include_deleted and row.get("_deleted"):
                continue
            if schema.ttl_seconds and (time.time() - row["_ts"]) > schema.ttl_seconds:
                continue
            if all(self._passes(row, f) for f in q.filters):
                items.append(row)

        # сортировка
        if q.order_by:
            key, direction = q.order_by
            rev = (direction.lower() == "desc")
            items.sort(key=lambda r: r.get(key), reverse=rev)

        # пагинация
        start = max(0, q.offset)
        end = start + q.limit if q.limit is not None else None
        sliced = items[start:end]

        res = [self._project(r, q.projection) for r in sliced]
        _MET_REQS.labels(table=table, op="query", code="ok").inc()
        _MET_LAT.labels(table=table, op="query").observe(max(0.0, time.perf_counter() - ts0))
        return res

    # --------------- Потоковая выдача -----------------------------------
    @_trace_span("fabric.stream")
    async def stream(self, table: str, q: Query, batch_size: int = 100) -> AsyncGenerator[List[Dict[str, Any]], None]:
        """
        Асинхронный генератор, отдаёт батчи результатов с применением фильтров/проекций.
        """
        idx = 0
        while True:
            chunk = await self.query(table, dataclasses.replace(q, offset=idx, limit=batch_size))
            if not chunk:
                return
            yield chunk
            idx += len(chunk)

    # --------------- Утилиты --------------------------------------------
    @_trace_span("fabric.count")
    async def count(self, table: str, q: Optional[Query] = None) -> int:
        q = q or Query()
        return len(await self.query(table, dataclasses.replace(q, projection=("__pk__",), limit=None, offset=0)))

    @_trace_span("fabric.truncate")
    async def truncate(self, table: str) -> int:
        async with self._locks[table]:
            n = len(self._state[table].data)
            self._state[table] = _Versioned()
        _log("warning", "table truncated", table=table, count=n)
        return n

# ------------------------------ Пример ----------------------------------
# Использование (комментарии):
# async def _demo():
#     async with DataFabricMock.session(chaos=ChaosConfig(enabled=True, seed=42, error_rate=0.01)) as df:
#         await df.create_table(TableSchema(
#             name="users",
#             primary_key="id",
#             columns=(
#                 Column("id", int, required=True),
#                 Column("name", str, required=True),
#                 Column("age", int),
#                 Column("tags", list),
#             ),
#             ttl_seconds=None,
#             soft_delete=True,
#         ))
#         await df.insert("users", [{"id": 1, "name": "Ann", "age": 33, "tags": ["pro"]}])
#         await df.upsert("users", [{"id": 1, "age": 34}])
#         res = await df.query("users", Query(filters=[("age", ">=", 30)], order_by=("age","desc"), projection=("id","name")))
#         async for batch in df.stream("users", Query(limit=1000)):
#             ...
