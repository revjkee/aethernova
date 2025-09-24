# ledger-core/adapters/legacy_migration_adapter.py
from __future__ import annotations

import abc
import asyncio
import contextlib
import csv
import dataclasses
import hashlib
import io
import json
import math
import os
import random
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    AsyncIterator,
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
    Union,
)

# Опциональные зависимости: не делаем жёстких импортов
try:
    from pydantic import BaseModel, ValidationError as PydanticValidationError
    _HAS_PYDANTIC = True
except Exception:
    _HAS_PYDANTIC = False

with contextlib.suppress(Exception):
    from jsonschema import validate as jsonschema_validate  # type: ignore
    _HAS_JSONSCHEMA = True
else:
    _HAS_JSONSCHEMA = False

# Для БД при необходимости (источник/приёмник)
with contextlib.suppress(Exception):
    import sqlalchemy as sa  # type: ignore
    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine  # type: ignore
    _HAS_SA = True
else:
    _HAS_SA = False


# ======================= Доменные типы/интерфейсы =======================

class LoadMode(str, Enum):
    FULL = "full"             # полная перегрузка
    INCREMENTAL = "incremental"  # инкремент с high-watermark


@dataclass(frozen=True)
class MigrationSourceSpec:
    """
    Описание источника данных (файл/каталог/таблица/запрос/эндпоинт).
    Только один тип за раз. Минимально необходимые поля.
    """
    name: str
    # Файлы
    path: Optional[str] = None               # CSV/JSON/NDJSON
    fmt: Optional[str] = None                # "csv" | "json" | "ndjson"
    csv_delimiter: str = ","
    # SQL (опционально)
    sql_dsn: Optional[str] = None            # например, "postgresql+asyncpg://..."
    sql_query: Optional[str] = None
    sql_hwm_column: Optional[str] = None     # колонка для high-watermark (ts/incrementing id)
    # CDC (логическая репликация/журнал)
    cdc_stream: Optional[str] = None         # имя топика/таблицы для CDC, если есть


@dataclass(frozen=True)
class MigrationTargetSpec:
    """
    Целевой приёмник (обычно Postgres таблица или абстрактный репозиторий).
    """
    name: str
    # БД
    sql_dsn: Optional[str] = None
    table: Optional[str] = None
    unique_keys: Tuple[str, ...] = tuple()       # уникальный индекс для upsert
    # Альтернативно: пользовательский лоадер
    custom_loader_id: Optional[str] = None


@dataclass(frozen=True)
class Watermark:
    """
    Состояние инкрементальной загрузки.
    """
    value: Optional[str] = None     # строковое представление (ts/число/uuid)
    ts_utc: Optional[str] = None


@dataclass
class MigrationPolicy:
    """
    Политика миграции и защитные параметры.
    """
    batch_size: int = 1000
    max_retries: int = 5
    base_backoff_sec: float = 0.05
    max_backoff_sec: float = 2.0
    jitter: float = 0.2
    validate_with_pydantic: bool = False
    validate_with_jsonschema: bool = False
    jsonschema: Optional[Mapping[str, Any]] = None
    drop_on_full_before_load: bool = False     # для FULL: сначала truncate (опасно!)
    dry_run: bool = False
    enable_tombstones: bool = True             # поддержка удалений (op=DELETE)
    enable_backpressure: bool = True           # регулировка темпа по времени отклика лоадера
    target_max_qps: Optional[float] = None     # предел запросов к приёмнику
    resume: bool = True                        # продолжать с чекпоинта
    checksum_window: int = 10_000              # каждые N записей считать контрольную сумму


@dataclass
class MigrationStats:
    processed: int = 0
    inserted: int = 0
    updated: int = 0
    deleted: int = 0
    skipped: int = 0
    failed: int = 0
    batches: int = 0
    start_ts: float = field(default_factory=time.time)
    finish_ts: float = 0.0

    def as_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


# ======================= Исключения =======================

class MigrationError(Exception):
    pass


class ValidationFailed(MigrationError):
    pass


# ======================= Абстракции стораджа состояния/чекпоинтов =======================

class StateStore(abc.ABC):
    @abc.abstractmethod
    async def get_hwm(self, source_name: str, target_name: str) -> Watermark: ...
    @abc.abstractmethod
    async def set_hwm(self, source_name: str, target_name: str, wm: Watermark) -> None: ...
    @abc.abstractmethod
    async def get_last_checksum(self, source_name: str, target_name: str) -> Optional[str]: ...
    @abc.abstractmethod
    async def set_last_checksum(self, source_name: str, target_name: str, checksum: str) -> None: ...


class FileStateStore(StateStore):
    """
    Простое файловое хранилище состояния (JSON) для оффлайн‑миграций.
    """
    def __init__(self, path: str | Path) -> None:
        self._p = Path(path)
        self._p.parent.mkdir(parents=True, exist_ok=True)
        if not self._p.exists():
            self._p.write_text(json.dumps({}))

    async def _load(self) -> Dict[str, Any]:
        try:
            return json.loads(self._p.read_text())
        except Exception:
            return {}

    async def _save(self, d: Dict[str, Any]) -> None:
        tmp = self._p.with_suffix(".tmp")
        tmp.write_text(json.dumps(d, separators=(",", ":"), sort_keys=True))
        tmp.replace(self._p)

    def _key(self, src: str, tgt: str) -> str:
        return f"{src}__{tgt}"

    async def get_hwm(self, source_name: str, target_name: str) -> Watermark:
        d = await self._load()
        x = d.get(self._key(source_name, target_name), {})
        v = x.get("hwm")
        if v is None:
            return Watermark()
        return Watermark(value=v.get("value"), ts_utc=v.get("ts_utc"))

    async def set_hwm(self, source_name: str, target_name: str, wm: Watermark) -> None:
        d = await self._load()
        k = self._key(source_name, target_name)
        x = d.get(k, {})
        x["hwm"] = {"value": wm.value, "ts_utc": wm.ts_utc}
        d[k] = x
        await self._save(d)

    async def get_last_checksum(self, source_name: str, target_name: str) -> Optional[str]:
        d = await self._load()
        x = d.get(self._key(source_name, target_name), {})
        return x.get("checksum")

    async def set_last_checksum(self, source_name: str, target_name: str, checksum: str) -> None:
        d = await self._load()
        k = self._key(source_name, target_name)
        x = d.get(k, {})
        x["checksum"] = checksum
        d[k] = x
        await self._save(d)


# ======================= Трансформации/валидаторы =======================

Transform = Callable[[Mapping[str, Any]], Mapping[str, Any]]
OpType = Literal["UPSERT", "DELETE"]  # тип операции при загрузке

@dataclass(frozen=True)
class TransformedRow:
    data: Mapping[str, Any]
    op: OpType
    idempotency_key: str


class TransformRegistry:
    """
    Реестр преобразований по имени источника/таблицы.
    """
    def __init__(self) -> None:
        self._map: Dict[str, List[Transform]] = {}

    def add(self, source_name: str, fn: Transform) -> None:
        self._map.setdefault(source_name, []).append(fn)

    def apply(self, source_name: str, row: Mapping[str, Any]) -> Mapping[str, Any]:
        out = dict(row)
        for fn in self._map.get(source_name, []):
            out = dict(fn(out))
        return out


# ======================= Экстракторы источников =======================

class Extractor(abc.ABC):
    @abc.abstractmethod
    async def stream(self, *, hwm: Optional[Watermark]) -> AsyncIterator[Mapping[str, Any]]: ...


class FileExtractor(Extractor):
    def __init__(self, spec: MigrationSourceSpec) -> None:
        self._s = spec

    async def stream(self, *, hwm: Optional[Watermark]) -> AsyncIterator[Mapping[str, Any]]:
        # Файловые форматы: csv/json/ndjson. HWM для файлов не применяется (обычно FULL).
        p = Path(self._s.path or "")
        if not p.exists():
            raise MigrationError(f"source file not found: {p}")
        if (self._s.fmt or "").lower() == "csv":
            with p.open("r", encoding="utf-8") as fh:
                reader = csv.DictReader(fh, delimiter=self._s.csv_delimiter)
                for row in reader:
                    yield dict(row)
        elif (self._s.fmt or "").lower() == "json":
            data = json.loads(p.read_text())
            if isinstance(data, list):
                for row in data:
                    yield dict(row)
            elif isinstance(data, dict):
                yield dict(data)
            else:
                raise MigrationError("json must be object or array")
        else:  # ndjson по умолчанию
            with p.open("r", encoding="utf-8") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    yield json.loads(line)


class SQLExtractor(Extractor):
    def __init__(self, spec: MigrationSourceSpec) -> None:
        if not _HAS_SA:
            raise MigrationError("SQLAlchemy not installed")
        self._s = spec
        self._engine: AsyncEngine = create_async_engine(self._s.sql_dsn)  # type: ignore[arg-type]

    async def stream(self, *, hwm: Optional[Watermark]) -> AsyncIterator[Mapping[str, Any]]:
        query = self._s.sql_query
        if not query:
            raise MigrationError("sql_query is required for SQLExtractor")
        # Добавим HWM‑фильтр, если задана колонка
        if hwm and hwm.value and self._s.sql_hwm_column:
            query = f"{query} WHERE {self._s.sql_hwm_column} > :hwm ORDER BY {self._s.sql_hwm_column} ASC"
        async with self._engine.connect() as conn:
            result = await conn.stream(sa.text(query), parameters={"hwm": hwm.value} if (hwm and hwm.value) else {})
            async for row in result:
                # row._mapping — маппинг колонок
                yield dict(row._mapping)  # type: ignore[attr-defined]


# ======================= Лоадеры (приёмники) =======================

class Loader(abc.ABC):
    @abc.abstractmethod
    async def upsert_many(self, rows: Sequence[Mapping[str, Any]], *, unique_keys: Tuple[str, ...]) -> Tuple[int, int]: ...
    @abc.abstractmethod
    async def delete_many(self, keys: Sequence[Mapping[str, Any]]) -> int: ...
    @abc.abstractmethod
    async def truncate(self) -> None: ...


class SQLLoader(Loader):
    def __init__(self, target: MigrationTargetSpec) -> None:
        if not _HAS_SA:
            raise MigrationError("SQLAlchemy not installed")
        if not target.table or not target.sql_dsn:
            raise MigrationError("target.table and target.sql_dsn are required for SQLLoader")
        self._t = target
        self._engine: AsyncEngine = create_async_engine(target.sql_dsn)  # type: ignore[arg-type]
        self._table = sa.table(target.table)  # lightweight table construct

    async def upsert_many(self, rows: Sequence[Mapping[str, Any]], *, unique_keys: Tuple[str, ...]) -> Tuple[int, int]:
        if not rows:
            return (0, 0)
        # ON CONFLICT DO UPDATE (PostgreSQL диалект)
        dialect = self._engine.dialect.name
        if "postgres" not in dialect:
            raise MigrationError("SQLLoader currently supports PostgreSQL")
        stmt = (
            sa.dialects.postgresql.insert(self._table)  # type: ignore[attr-defined]
            .values(list(rows))
            .on_conflict_do_update(
                index_elements=list(unique_keys),
                set_={c: sa.func.EXCLUDED[c] for c in rows[0].keys() if c not in unique_keys},
            )
            .returning(sa.text("xmax = 0 AS inserted"))  # trick: inserted row has xmax=0
        )
        async with self._engine.begin() as conn:
            res = await conn.execute(stmt)
            flags = [bool(r[0]) for r in res.fetchall()]
        inserted = sum(1 for f in flags if f)
        updated = len(flags) - inserted
        return inserted, updated

    async def delete_many(self, keys: Sequence[Mapping[str, Any]]) -> int:
        if not keys:
            return 0
        # Композитный ключ поддерживается
        where_clauses = []
        for k in keys:
            sub = sa.and_(*[sa.text(f"{col} = :{col}") for col in k.keys()])
            where_clauses.append(sub)
        stmt = sa.delete(self._table).where(sa.or_(*where_clauses))
        async with self._engine.begin() as conn:
            res = await conn.execute(stmt, keys)
            return int(res.rowcount or 0)

    async def truncate(self) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(sa.text(f"TRUNCATE TABLE {self._t.table}"))


# ======================= Основной адаптер =======================

AuditHook = Callable[[Mapping[str, Any]], Awaitable[None]]
MetricsHook = Callable[[str, Mapping[str, Union[int, float, str]]], Awaitable[None]]

@dataclass
class LegacyMigrationAdapter:
    source: MigrationSourceSpec
    target: MigrationTargetSpec
    state: StateStore
    transforms: TransformRegistry = field(default_factory=TransformRegistry)
    policy: MigrationPolicy = field(default_factory=MigrationPolicy)
    audit_hook: Optional[AuditHook] = None
    metrics_hook: Optional[MetricsHook] = None
    row_model: Optional[type] = None                 # pydantic BaseModel для валидации (если доступна)
    jsonschema: Optional[Mapping[str, Any]] = None   # схема альтернативно
    custom_loaders: Dict[str, Loader] = field(default_factory=dict)

    # --- публичные методы ---

    async def run(self, mode: LoadMode = LoadMode.INCREMENTAL) -> MigrationStats:
        """
        Точка входа. Выбирает режим и запускает конвейер.
        """
        if mode == LoadMode.FULL:
            return await self._run_full()
        return await self._run_incremental()

    async def _run_full(self) -> MigrationStats:
        st = MigrationStats()
        extractor = self._make_extractor()
        loader = await self._make_loader()
        if self.policy.drop_on_full_before_load and not self.policy.dry_run:
            await loader.truncate()
            await self._audit({"event": "truncate", "target": self.target.name})
        wm = Watermark(value=None, ts_utc=None)
        async for batch in self._batched(self._transforming(self._validating(extractor.stream(hwm=wm))), self.policy.batch_size):
            inserted, updated, deleted, skipped, failed = await self._apply_batch(loader, batch)
            st.inserted += inserted
            st.updated += updated
            st.deleted += deleted
            st.skipped += skipped
            st.failed += failed
            st.processed += sum(1 for _ in batch)
            st.batches += 1
        st.finish_ts = time.time()
        await self._metrics("migration_full", {"processed": st.processed, "inserted": st.inserted, "updated": st.updated, "deleted": st.deleted, "failed": st.failed})
        return st

    async def _run_incremental(self) -> MigrationStats:
        st = MigrationStats()
        extractor = self._make_extractor()
        loader = await self._make_loader()
        hwm = await self.state.get_hwm(self.source.name, self.target.name) if self.policy.resume else Watermark()
        async for batch in self._batched(self._transforming(self._validating(extractor.stream(hwm=hwm))), self.policy.batch_size):
            inserted, updated, deleted, skipped, failed = await self._apply_batch(loader, batch)
            st.inserted += inserted
            st.updated += updated
            st.deleted += deleted
            st.skipped += skipped
            st.failed += failed
            st.processed += sum(1 for _ in batch)
            st.batches += 1
            # Обновим HWM, если есть поле hwm_value в источнике
            last_hwm = self._last_hwm_from(batch)
            if last_hwm and not self.policy.dry_run:
                await self.state.set_hwm(self.source.name, self.target.name, Watermark(value=last_hwm, ts_utc=self._utc()))
        st.finish_ts = time.time()
        await self._metrics("migration_incremental", {"processed": st.processed, "inserted": st.inserted, "updated": st.updated, "deleted": st.deleted, "failed": st.failed})
        return st

    # --- внутреннее: экстракт/валид/трансформ/батч ---

    def _make_extractor(self) -> Extractor:
        if self.source.path:
            return FileExtractor(self.source)
        if self.source.sql_dsn:
            return SQLExtractor(self.source)
        raise MigrationError("unsupported source spec")

    async def _make_loader(self) -> Loader:
        if self.target.custom_loader_id and self.target.custom_loader_id in self.custom_loaders:
            return self.custom_loaders[self.target.custom_loader_id]
        if self.target.sql_dsn and self.target.table:
            return SQLLoader(self.target)
        raise MigrationError("unsupported target spec")

    async def _validating(self, it: AsyncIterator[Mapping[str, Any]]) -> AsyncIterator[Mapping[str, Any]]:
        async for row in it:
            try:
                self._validate_row(row)
                yield row
            except ValidationFailed:
                await self._audit({"event": "row_invalid", "reason": "schema", "row": self._safe_row(row)})
                # Пропускаем, но считаем как skipped/failed позже
                yield {"__invalid__": True, **row}

    def _validate_row(self, row: Mapping[str, Any]) -> None:
        if self.policy.validate_with_pydantic and _HAS_PYDANTIC and self.row_model is not None:
            try:
                self.row_model.model_validate(row)  # type: ignore[attr-defined]
            except Exception as e:
                raise ValidationFailed(str(e))
        if self.policy.validate_with_jsonschema and _HAS_JSONSCHEMA and (self.jsonschema or self.policy.jsonschema):
            try:
                jsonschema_validate(instance=row, schema=(self.jsonschema or self.policy.jsonschema))  # type: ignore[arg-type]
            except Exception as e:
                raise ValidationFailed(str(e))

    async def _transforming(self, it: AsyncIterator[Mapping[str, Any]]) -> AsyncIterator[TransformedRow]:
        async for row in it:
            if row.get("__invalid__"):
                # отметим как пропущенную запись
                yield TransformedRow(data=row, op="UPSERT", idempotency_key=self._idem_key(row))
                continue
            # определим тип операции (поддержка tombstone/CDC)
            op = "UPSERT"
            op_raw = row.get("op") or row.get("_op")
            if self.policy.enable_tombstones and op_raw and str(op_raw).upper() in ("DELETE", "D"):
                op = "DELETE"
            # применим трансформации
            data = self.transforms.apply(self.source.name, row)
            # вычислим idempotency_key (детерминированный checksum ряда по уникальным ключам или всему объекту)
            idem = self._idem_key(data)
            yield TransformedRow(data=data, op=op, idempotency_key=idem)

    async def _batched(self, it: AsyncIterator[TransformedRow], size: int) -> AsyncIterator[List[TransformedRow]]:
        batch: List[TransformedRow] = []
        async for item in it:
            batch.append(item)
            if len(batch) >= size:
                yield batch
                batch = []
        if batch:
            yield batch

    # --- загрузка батча с ретраями/бэкпрешром/чексумом ---

    async def _apply_batch(self, loader: Loader, batch: List[TransformedRow]) -> Tuple[int, int, int, int, int]:
        retries = 0
        checksum = self._checksum(batch) if self.policy.checksum_window and (sum(1 for _ in batch) >= 1) else None

        while True:
            t0 = time.perf_counter()
            try:
                upserts = [b.data for b in batch if b.op == "UPSERT" and not b.data.get("__invalid__")]
                deletes = [self._extract_keys(b.data) for b in batch if b.op == "DELETE"]
                invalids = sum(1 for b in batch if b.data.get("__invalid__"))

                ins, upd = (0, 0)
                deleted = 0

                if not self.policy.dry_run:
                    if upserts:
                        ins, upd = await loader.upsert_many(upserts, unique_keys=self.target.unique_keys)
                    if deletes:
                        deleted = await loader.delete_many(deletes)

                # метрики и аудит
                await self._metrics("batch_load", {"size": len(batch), "upserts": len(upserts), "deletes": len(deletes), "invalid": invalids, "inserted": ins, "updated": upd, "deleted": deleted})
                if checksum and not self.policy.dry_run:
                    await self.state.set_last_checksum(self.source.name, self.target.name, checksum)

                # backpressure по времени ответа
                await self._apply_backpressure(t0, len(batch))

                return ins, upd, deleted, invalids, 0

            except Exception as e:
                retries += 1
                if retries > self.policy.max_retries:
                    await self._audit({"event": "batch_failed", "error": str(e), "retries": retries})
                    # считаем весь батч failed; в продуктиве можно «раскалывать» пополам
                    return 0, 0, 0, 0, len(batch)
                # экспоненциальная задержка
                await asyncio.sleep(self._backoff_delay(retries))

    def _extract_keys(self, row: Mapping[str, Any]) -> Mapping[str, Any]:
        if not self.target.unique_keys:
            raise MigrationError("unique_keys required to perform DELETE operations")
        return {k: row[k] for k in self.target.unique_keys if k in row}

    # --- сервисные утилиты ---

    def _idem_key(self, row: Mapping[str, Any]) -> str:
        # детерминированный хеш по уникальным ключам либо по всему объекту
        if self.target.unique_keys:
            key = {k: row.get(k) for k in self.target.unique_keys}
        else:
            key = row
        b = json.dumps(key, separators=(",", ":"), sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(b).hexdigest()

    def _checksum(self, batch: Sequence[TransformedRow]) -> str:
        h = hashlib.sha256()
        for r in batch:
            h.update(r.idempotency_key.encode("ascii"))
        return h.hexdigest()

    async def _apply_backpressure(self, t0: float, n: int) -> None:
        if not self.policy.enable_backpressure:
            return
        dur = time.perf_counter() - t0
        # Простая модель: держать QPS не выше target_max_qps, либо выдерживать минимальную «работу на запись»
        if self.policy.target_max_qps and self.policy.target_max_qps > 0:
            min_time = n / float(self.policy.target_max_qps)
            if dur < min_time:
                await asyncio.sleep(min_time - dur)
        else:
            # fallback: избегать "горячего" цикла
            if dur < 0.005:
                await asyncio.sleep(0.005 - dur)

    def _backoff_delay(self, attempt: int) -> float:
        b = min(self.policy.max_backoff_sec, self.policy.base_backoff_sec * (2 ** (attempt - 1)))
        j = b * self.policy.jitter
        r = (time.perf_counter_ns() % 10_000) / 10_000.0  # псевдослучай
        return max(0.0, b + (r * 2 * j - j))

    def _last_hwm_from(self, batch: Sequence[TransformedRow]) -> Optional[str]:
        # Если источник SQL с сортировкой по sql_hwm_column — будем искать максимальное значение
        col = self.source.sql_hwm_column
        if not col:
            return None
        vals: List[Any] = []
        for r in batch:
            v = r.data.get(col)
            if v is not None:
                vals.append(v)
        if not vals:
            return None
        try:
            return str(max(vals))
        except Exception:
            return None

    async def _audit(self, event: Mapping[str, Any]) -> None:
        if self.audit_hook:
            await self.audit_hook(event)

    async def _metrics(self, name: str, tags: Mapping[str, Union[int, float, str]]) -> None:
        if self.metrics_hook:
            await self.metrics_hook(name, tags)

    def _safe_row(self, row: Mapping[str, Any]) -> Mapping[str, Any]:
        # можно вырезать PII здесь при необходимости
        return dict(row)

    def _utc(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ======================= Пример настройки и использования =======================

async def example_usage() -> None:  # pragma: no cover
    # Источник: CSV
    src = MigrationSourceSpec(
        name="legacy_customers",
        path="./data/customers.csv",
        fmt="csv",
    )
    # Приёмник: Postgres таблица customers с уникальным индексом по id
    tgt = MigrationTargetSpec(
        name="customers",
        sql_dsn="postgresql+asyncpg://user:pass@localhost:5432/app",
        table="customers",
        unique_keys=("id",),
    )

    # Реестр трансформаций: нормализация полей
    reg = TransformRegistry()
    reg.add("legacy_customers", lambda r: {**r, "email": (r.get("email") or "").strip().lower()})

    # Состояние hwm в файле
    state = FileStateStore("./.migrate/state.json")

    # Политика
    policy = MigrationPolicy(batch_size=500, validate_with_jsonschema=False, dry_run=False, target_max_qps=200)

    adapter = LegacyMigrationAdapter(
        source=src,
        target=tgt,
        state=state,
        transforms=reg,
        policy=policy,
    )
    stats = await adapter.run(mode=LoadMode.INCREMENTAL)
    print(stats.as_dict())
