# neuroforge/adapters/datafabric_adapter.py
from __future__ import annotations

import abc
import contextlib
import hashlib
import io
import json
import logging
import os
import random
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Generator, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple, Union

try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

log = logging.getLogger("neuroforge.adapters.datafabric")


# ============================== Errors & types ================================

class DataFabricError(RuntimeError):
    pass

class NotFoundError(DataFabricError):
    pass

class UnauthorizedError(DataFabricError):
    pass

class ConflictError(DataFabricError):
    pass

class RateLimitError(DataFabricError):
    def __init__(self, message: str, retry_after_s: Optional[float] = None):
        super().__init__(message)
        self.retry_after_s = retry_after_s

class SchemaMismatchError(DataFabricError):
    pass

class TransientError(DataFabricError):
    pass

Record = Dict[str, Any]
Records = Iterable[Record]
MetricsHook = Callable[[str, Dict[str, str], float], None]  # (event, labels, latency_s)


# ============================== Models & config ===============================

@dataclass(frozen=True)
class DatasetId:
    namespace: str
    name: str
    version: Optional[str] = None  # semver/label

    def urn(self) -> str:
        return f"urn:df:{self.namespace}:{self.name}" + (f":{self.version}" if self.version else "")

@dataclass(frozen=True)
class SchemaField:
    name: str
    type: str  # "string|int|float|bool|bytes|datetime|date|object|array"
    nullable: bool = True

@dataclass(frozen=True)
class DatasetSchema:
    fields: Tuple[SchemaField, ...]
    primary_keys: Tuple[str, ...] = field(default_factory=tuple)

    def to_json(self) -> Dict[str, Any]:
        return {"fields": [vars(f) for f in self.fields], "primary_keys": list(self.primary_keys)}

    @staticmethod
    def from_json(obj: Mapping[str, Any]) -> "DatasetSchema":
        fields = tuple(SchemaField(**f) for f in obj.get("fields", []))
        pks = tuple(obj.get("primary_keys", []))
        return DatasetSchema(fields=fields, primary_keys=pks)

    def field_index(self) -> Dict[str, SchemaField]:
        return {f.name: f for f in self.fields}

    def evolve_additive(self, new_fields: Sequence[SchemaField]) -> "DatasetSchema":
        idx = self.field_index()
        merged: List[SchemaField] = list(self.fields)
        for nf in new_fields:
            if nf.name in idx:
                # допускаем строго совместимый тип (тот же)
                if idx[nf.name].type != nf.type or (idx[nf.name].nullable is False and nf.nullable is True):
                    raise SchemaMismatchError(f"Incompatible change for field {nf.name}")
            else:
                merged.append(nf)
        return DatasetSchema(fields=tuple(merged), primary_keys=self.primary_keys)

def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()

@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 6
    base_delay_s: float = 0.2
    max_delay_s: float = 8.0
    jitter: float = 0.2  # 20% jitter

    def backoff(self, attempt: int) -> float:
        # exponential backoff with jitter
        d = min(self.max_delay_s, self.base_delay_s * (2 ** max(0, attempt - 1)))
        j = d * self.jitter
        return max(0.0, d + random.uniform(-j, j))

@dataclass
class CircuitBreaker:
    failure_threshold: int = 5
    recovery_time_s: float = 20.0
    _failures: int = 0
    _opened_at: Optional[float] = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def allow(self) -> bool:
        with self._lock:
            if self._opened_at is None:
                return True
            if time.time() - self._opened_at >= self.recovery_time_s:
                # half-open
                return True
            return False

    def on_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = None

    def on_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self.failure_threshold:
                self._opened_at = time.time()

@dataclass(frozen=True)
class DataFabricAdapterConfig:
    # HTTP settings (for HTTP adapter)
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    bearer_token: Optional[str] = None
    timeout_s: float = 15.0
    retries: RetryPolicy = field(default_factory=RetryPolicy)
    breaker: CircuitBreaker = field(default_factory=CircuitBreaker)
    # Streaming
    chunk_bytes: int = 2_000_000  # ~2MB
    max_records_per_chunk: int = 10_000
    # Idempotency
    idempotency_header: str = "Idempotency-Key"
    # Observability
    metrics_hook: Optional[MetricsHook] = None
    # LocalFS settings
    local_root: Path = Path("./datafabric")
    local_partition_by: Tuple[str, ...] = field(default_factory=tuple)
    # Format
    format: str = "jsonl"  # jsonl as baseline


# ============================== Abstract Adapter ===============================

class DataFabricAdapter(abc.ABC):
    """
    Унифицированный интерфейс к Data Fabric.
    """

    def __init__(self, cfg: DataFabricAdapterConfig):
        self.cfg = cfg

    # ---- Dataset lifecycle ----
    @abc.abstractmethod
    def ensure_dataset(self, ds: DatasetId, schema: DatasetSchema, additive_evolution: bool = True) -> None:
        """
        Обеспечить наличие датасета и совместимой схемы.
        additive_evolution=True разрешает добавлять новые поля.
        """

    @abc.abstractmethod
    def get_schema(self, ds: DatasetId) -> DatasetSchema:
        """
        Получить текущую схему датасета.
        """

    # ---- Write path ----
    @abc.abstractmethod
    def upsert_batch(
        self,
        ds: DatasetId,
        records: Records,
        idempotency_key: Optional[str] = None,
        txn: Optional[str] = None,
    ) -> int:
        """
        Идемпотентная батчевая запись/апдейт. Возвращает кол-во записанных строк.
        """

    @abc.abstractmethod
    def write_stream(
        self,
        ds: DatasetId,
        stream: Records,
        idempotency_key: Optional[str] = None,
        txn: Optional[str] = None,
    ) -> int:
        """
        Потоковая запись с чанками. Возвращает кол-во записанных строк.
        """

    # ---- Read path ----
    @abc.abstractmethod
    def query(
        self,
        ds: DatasetId,
        where: Optional[Mapping[str, Any]] = None,
        limit: Optional[int] = None,
        columns: Optional[Sequence[str]] = None,
    ) -> Iterator[Record]:
        """
        Простая выборка по where={col: value|[values]|op dict}, limit, columns.
        """

    # ---- Transactions (logical) ----
    @abc.abstractmethod
    def begin(self, ds: DatasetId) -> str:
        """Начать логическую транзакцию и вернуть её идентификатор."""

    @abc.abstractmethod
    def commit(self, ds: DatasetId, txn: str) -> None:
        """Зафиксировать транзакцию."""

    @abc.abstractmethod
    def abort(self, ds: DatasetId, txn: str) -> None:
        """Отменить транзакцию."""


# ============================== Utilities =====================================

def _hash_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def _normalize_record(rec: Record, schema: DatasetSchema) -> Record:
    idx = schema.field_index()
    out: Record = {}
    for f in schema.fields:
        v = rec.get(f.name)
        if v is None:
            if not f.nullable:
                raise SchemaMismatchError(f"Field {f.name} is not nullable")
            out[f.name] = None
            continue
        t = f.type
        try:
            if t == "string":
                out[f.name] = str(v)
            elif t == "int":
                out[f.name] = int(v)
            elif t == "float":
                out[f.name] = float(v)
            elif t == "bool":
                out[f.name] = bool(v)
            elif t == "bytes":
                if isinstance(v, (bytes, bytearray)):
                    out[f.name] = v.hex()
                else:
                    out[f.name] = bytes(str(v).encode("utf-8")).hex()
            elif t == "datetime":
                if isinstance(v, str):
                    out[f.name] = v
                else:
                    # ISO-8601
                    out[f.name] = datetime.fromtimestamp(float(v), tz=timezone.utc).isoformat()
            elif t == "date":
                if isinstance(v, str):
                    out[f.name] = v
                else:
                    out[f.name] = datetime.fromtimestamp(float(v), tz=timezone.utc).date().isoformat()
            elif t == "object":
                out[f.name] = v if isinstance(v, (dict, list)) else json.loads(json.dumps(v))
            elif t == "array":
                out[f.name] = list(v) if not isinstance(v, list) else v
            else:
                out[f.name] = v
        except Exception as exc:
            raise SchemaMismatchError(f"Type cast failed for field {f.name}: {exc}")
    # пропускаем лишние поля (строго по схеме)
    return out

def _idempotency_key(base: Optional[str]) -> str:
    return base or _hash_str(f"{time.time_ns()}-{random.random()}")

def _metric(hook: Optional[MetricsHook], event: str, labels: Dict[str, str], t0: float) -> None:
    if hook:
        with contextlib.suppress(Exception):
            hook(event, labels, time.perf_counter() - t0)


# ============================== HTTP Adapter ==================================

class HTTPDataFabricAdapter(DataFabricAdapter):
    """
    HTTP-адаптер к Data Fabric REST API.
    Конкретные URL/контракты настраиваются параметрами; формат обмена — JSON/JSONL.
    """

    def __init__(self, cfg: DataFabricAdapterConfig):
        super().__init__(cfg)
        if not cfg.base_url:
            raise ValueError("base_url is required for HTTPDataFabricAdapter")
        if httpx is None:
            raise RuntimeError("httpx package is required for HTTPDataFabricAdapter")
        self._client = httpx.Client(
            base_url=cfg.base_url.rstrip("/"),
            timeout=cfg.timeout_s,
            headers=self._auth_headers(),
            http2=True,
        )

    def _auth_headers(self) -> Dict[str, str]:
        h: Dict[str, str] = {"User-Agent": "neuroforge-datafabric/1.0"}
        if self.cfg.api_key:
            h["X-API-Key"] = self.cfg.api_key
        if self.cfg.bearer_token:
            h["Authorization"] = f"Bearer {self.cfg.bearer_token}"
        return h

    # ---------- API helpers with retry/breaker ----------

    def _request(self, method: str, url: str, **kw) -> httpx.Response:  # type: ignore[return-type]
        if not self.cfg.breaker.allow():
            raise TransientError("Circuit breaker open")
        rp = self.cfg.retries
        attempt = 0
        last_exc: Optional[BaseException] = None
        while attempt < rp.max_attempts:
            attempt += 1
            try:
                resp: httpx.Response = self._client.request(method, url, **kw)  # type: ignore[assignment]
                if resp.status_code in (401, 403):
                    raise UnauthorizedError("Unauthorized")
                if resp.status_code in (409,):
                    raise ConflictError(resp.text)
                if resp.status_code == 404:
                    raise NotFoundError(resp.text)
                if resp.status_code in (429,):
                    ra = float(resp.headers.get("Retry-After", "0") or 0)
                    raise RateLimitError("Rate limited", retry_after_s=ra or None)
                if 500 <= resp.status_code < 600:
                    raise TransientError(f"Server error {resp.status_code}")
                self.cfg.breaker.on_success()
                return resp
            except (RateLimitError, TransientError) as e:
                self.cfg.breaker.on_failure()
                last_exc = e
                delay = e.retry_after_s if isinstance(e, RateLimitError) and e.retry_after_s else rp.backoff(attempt)
                time.sleep(delay)
                continue
            except (httpx.TimeoutException, httpx.NetworkError) as e:  # type: ignore[attr-defined]
                self.cfg.breaker.on_failure()
                last_exc = e
                time.sleep(rp.backoff(attempt))
                continue
        assert last_exc is not None
        if isinstance(last_exc, BaseException):
            raise last_exc

    # ---------- Interface implementation ----------

    def ensure_dataset(self, ds: DatasetId, schema: DatasetSchema, additive_evolution: bool = True) -> None:
        t0 = time.perf_counter()
        try:
            # GET schema
            r = self._request("GET", f"/v1/datasets/{ds.namespace}/{ds.name}/schema")
            remote = DatasetSchema.from_json(r.json())
            # evolve if allowed
            if additive_evolution:
                # проверим необходимость добавления
                try:
                    evolved = remote.evolve_additive(schema.fields)
                    if evolved != remote:
                        self._request("PUT", f"/v1/datasets/{ds.namespace}/{ds.name}/schema", json=evolved.to_json())
                except SchemaMismatchError as e:
                    raise
            else:
                # точное совпадение требовать не будем, но проверим совместимость типов
                idx = remote.field_index()
                for f in schema.fields:
                    if f.name not in idx or idx[f.name].type != f.type:
                        raise SchemaMismatchError(f"Incompatible schema for field {f.name}")
        except NotFoundError:
            # create dataset
            body = {"id": {"namespace": ds.namespace, "name": ds.name, "version": ds.version}, "schema": schema.to_json()}
            self._request("POST", f"/v1/datasets", json=body)
        finally:
            _metric(self.cfg.metrics_hook, "df.ensure_dataset", {"ds": ds.urn()}, t0)

    def get_schema(self, ds: DatasetId) -> DatasetSchema:
        t0 = time.perf_counter()
        try:
            r = self._request("GET", f"/v1/datasets/{ds.namespace}/{ds.name}/schema")
            return DatasetSchema.from_json(r.json())
        finally:
            _metric(self.cfg.metrics_hook, "df.get_schema", {"ds": ds.urn()}, t0)

    def upsert_batch(
        self,
        ds: DatasetId,
        records: Records,
        idempotency_key: Optional[str] = None,
        txn: Optional[str] = None,
    ) -> int:
        t0 = time.perf_counter()
        total = 0
        idem = _idempotency_key(idempotency_key)
        headers = {self.cfg.idempotency_header: idem}
        if txn:
            headers["X-Transaction-ID"] = txn
        # Отправляем как JSON массив (если малый объем) или JSONL (если большой)
        buf: List[Record] = []
        size = 0
        for rec in records:
            buf.append(rec)
            size += len(json.dumps(rec, ensure_ascii=False))
        if size <= self.cfg.chunk_bytes and len(buf) <= self.cfg.max_records_per_chunk:
            r = self._request("POST", f"/v1/datasets/{ds.namespace}/{ds.name}/upsert", headers=headers, json={"rows": buf})
            total += int(r.json().get("written", len(buf)))
        else:
            # JSONL stream
            total += self.write_stream(ds, buf, idempotency_key=idem, txn=txn)
        _metric(self.cfg.metrics_hook, "df.upsert_batch", {"ds": ds.urn()}, t0)
        return total

    def write_stream(
        self,
        ds: DatasetId,
        stream: Records,
        idempotency_key: Optional[str] = None,
        txn: Optional[str] = None,
    ) -> int:
        t0 = time.perf_counter()
        idem = _idempotency_key(idempotency_key)
        headers = {
            "Content-Type": "application/x-ndjson",
            self.cfg.idempotency_header: idem,
        }
        if txn:
            headers["X-Transaction-ID"] = txn

        # Чанкуем в памяти и шлём последовательными POST /ingest
        written = 0
        chunk_buf = io.StringIO()
        rec_in_chunk = 0
        bytes_in_chunk = 0

        def _flush_chunk():
            nonlocal written, chunk_buf, rec_in_chunk, bytes_in_chunk
            if rec_in_chunk == 0:
                return
            data = chunk_buf.getvalue().encode("utf-8")
            self._request(
                "POST",
                f"/v1/datasets/{ds.namespace}/{ds.name}/ingest",
                headers=headers,
                content=data,
            )
            written += rec_in_chunk
            chunk_buf = io.StringIO()
            rec_in_chunk = 0
            bytes_in_chunk = 0

        for rec in stream:
            line = json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n"
            chunk_buf.write(line)
            rec_in_chunk += 1
            bytes_in_chunk += len(line)
            if rec_in_chunk >= self.cfg.max_records_per_chunk or bytes_in_chunk >= self.cfg.chunk_bytes:
                _flush_chunk()
        _flush_chunk()
        _metric(self.cfg.metrics_hook, "df.write_stream", {"ds": ds.urn()}, t0)
        return written

    def query(
        self,
        ds: DatasetId,
        where: Optional[Mapping[str, Any]] = None,
        limit: Optional[int] = None,
        columns: Optional[Sequence[str]] = None,
    ) -> Iterator[Record]:
        t0 = time.perf_counter()
        try:
            params: Dict[str, Any] = {}
            if limit is not None:
                params["limit"] = int(limit)
            if columns:
                params["columns"] = ",".join(columns)
            if where:
                params["where"] = json.dumps(where, ensure_ascii=False)
            r = self._request("GET", f"/v1/datasets/{ds.namespace}/{ds.name}/query", params=params)
            # Поддерживаем как JSON (массив), так и JSONL поток
            ctype = r.headers.get("Content-Type", "")
            if "application/x-ndjson" in ctype or "ndjson" in ctype:
                for line in r.iter_lines():
                    if not line:
                        continue
                    yield json.loads(line.decode("utf-8")) if isinstance(line, (bytes, bytearray)) else json.loads(line)
            else:
                data = r.json()
                rows = data if isinstance(data, list) else data.get("rows", [])
                for row in rows:
                    yield row
        finally:
            _metric(self.cfg.metrics_hook, "df.query", {"ds": ds.urn()}, t0)

    # ---------- Logical transactions ----------

    def begin(self, ds: DatasetId) -> str:
        t0 = time.perf_counter()
        try:
            r = self._request("POST", f"/v1/datasets/{ds.namespace}/{ds.name}/transactions", json={})
            txn = r.json().get("id") or r.headers.get("X-Transaction-ID")
            if not txn:
                raise DataFabricError("Transaction id missing")
            return str(txn)
        finally:
            _metric(self.cfg.metrics_hook, "df.tx.begin", {"ds": ds.urn()}, t0)

    def commit(self, ds: DatasetId, txn: str) -> None:
        t0 = time.perf_counter()
        try:
            self._request("POST", f"/v1/datasets/{ds.namespace}/{ds.name}/transactions/{txn}/commit", json={})
        finally:
            _metric(self.cfg.metrics_hook, "df.tx.commit", {"ds": ds.urn()}, t0)

    def abort(self, ds: DatasetId, txn: str) -> None:
        t0 = time.perf_counter()
        try:
            self._request("POST", f"/v1/datasets/{ds.namespace}/{ds.name}/transactions/{txn}/abort", json={})
        finally:
            _metric(self.cfg.metrics_hook, "df.tx.abort", {"ds": ds.urn()}, t0)


# ============================== Local FS Adapter ===============================

class LocalFSDataFabricAdapter(DataFabricAdapter):
    """
    Локальный файловый адаптер (референс/фолбэк).
    Формат хранения: JSONL в директории:
      {root}/{namespace}/{name}/version={version}/{partition...}/part-*.jsonl
    """

    def __init__(self, cfg: DataFabricAdapterConfig):
        super().__init__(cfg)
        _ensure_dir(cfg.local_root)
        self._schemas_dir = self.cfg.local_root / "_schemas"
        _ensure_dir(self._schemas_dir)
        self._lock = threading.RLock()
        # транзакции — логические, как временные каталоги
        self._txn_dir = self.cfg.local_root / "_tx"
        _ensure_dir(self._txn_dir)

    # -------------- Paths & helpers --------------

    def _ds_root(self, ds: DatasetId, txn: Optional[str] = None) -> Path:
        base = self._txn_dir / txn if txn else self.cfg.local_root
        p = base / ds.namespace / ds.name
        if ds.version:
            p = p / f"version={ds.version}"
        return p

    def _schema_path(self, ds: DatasetId) -> Path:
        ver = ds.version or "default"
        return self._schemas_dir / f"{ds.namespace}__{ds.name}__{ver}.schema.json"

    def _load_schema(self, ds: DatasetId) -> Optional[DatasetSchema]:
        p = self._schema_path(ds)
        if not p.exists():
            return None
        try:
            return DatasetSchema.from_json(json.loads(p.read_text(encoding="utf-8")))
        except Exception:
            return None

    def _save_schema(self, ds: DatasetId, schema: DatasetSchema) -> None:
        p = self._schema_path(ds)
        p.write_text(json.dumps(schema.to_json(), ensure_ascii=False, separators=(",", ":")), encoding="utf-8")

    def _partition_path(self, ds: DatasetId, rec: Record, root: Optional[Path] = None) -> Path:
        root = root or self._ds_root(ds)
        p = root
        for key in self.cfg.local_partition_by:
            val = rec.get(key)
            # безопасный компонент
            sval = str(val).replace("/", "_").replace("\\", "_")
            p = p / f"{key}={sval}"
        _ensure_dir(p)
        return p

    def _new_part_file(self, part_dir: Path) -> Path:
        fname = f"part-{int(time.time() * 1000)}-{random.randint(1000,9999)}.jsonl"
        return part_dir / fname

    # -------------- Interface impl --------------

    def ensure_dataset(self, ds: DatasetId, schema: DatasetSchema, additive_evolution: bool = True) -> None:
        with self._lock:
            current = self._load_schema(ds)
            if current is None:
                self._save_schema(ds, schema)
                return
            if additive_evolution:
                evolved = current.evolve_additive(schema.fields)
                if evolved != current:
                    self._save_schema(ds, evolved)
            else:
                idx = current.field_index()
                for f in schema.fields:
                    if f.name not in idx or idx[f.name].type != f.type:
                        raise SchemaMismatchError(f"Incompatible schema for field {f.name}")

    def get_schema(self, ds: DatasetId) -> DatasetSchema:
        sch = self._load_schema(ds)
        if sch is None:
            raise NotFoundError("Schema not found")
        return sch

    def upsert_batch(
        self,
        ds: DatasetId,
        records: Records,
        idempotency_key: Optional[str] = None,
        txn: Optional[str] = None,
    ) -> int:
        # Для локального бэкэнда upsert = append (демонстрационная логика)
        return self.write_stream(ds, records, idempotency_key=idempotency_key, txn=txn)

    def write_stream(
        self,
        ds: DatasetId,
        stream: Records,
        idempotency_key: Optional[str] = None,
        txn: Optional[str] = None,
    ) -> int:
        t0 = time.perf_counter()
        count = 0
        sch = self._load_schema(ds)
        if sch is None:
            raise NotFoundError("Dataset schema missing; call ensure_dataset() first")

        root = self._ds_root(ds, txn=txn)
        # basename для чанка (фиксируем в пределах функции)
        cur_file: Optional[io.TextIOBase] = None
        cur_bytes = 0
        recs_in_file = 0

        def _open_new(rec_sample: Record) -> io.TextIOBase:
            nonlocal cur_bytes, recs_in_file
            part_dir = self._partition_path(ds, rec_sample, root=root)
            fp = self._new_part_file(part_dir).open("a", encoding="utf-8")
            cur_bytes = 0
            recs_in_file = 0
            return fp

        def _maybe_rollover(sample: Record):
            nonlocal cur_file, cur_bytes, recs_in_file
            if cur_file is None:
                cur_file = _open_new(sample)
                return
            if cur_bytes >= self.cfg.chunk_bytes or recs_in_file >= self.cfg.max_records_per_chunk:
                cur_file.close()
                cur_file = _open_new(sample)

        for rec in stream:
            nrec = _normalize_record(rec, sch)
            _maybe_rollover(nrec)
            line = json.dumps(nrec, ensure_ascii=False, separators=(",", ":")) + "\n"
            assert cur_file is not None
            cur_file.write(line)
            cur_bytes += len(line)
            recs_in_file += 1
            count += 1

        if cur_file:
            cur_file.close()
        _metric(self.cfg.metrics_hook, "df.local.write_stream", {"ds": ds.urn()}, t0)
        return count

    def query(
        self,
        ds: DatasetId,
        where: Optional[Mapping[str, Any]] = None,
        limit: Optional[int] = None,
        columns: Optional[Sequence[str]] = None,
    ) -> Iterator[Record]:
        # Простой фильтр по partition-директориям и пост-фильтрация по where
        base = self._ds_root(ds)
        if not base.exists():
            raise NotFoundError("Dataset not found")
        emitted = 0
        # Вычислим стартовый список директорий
        dirs = [base]
        for key in self.cfg.local_partition_by:
            if where and key in where and where[key] is not None and not isinstance(where[key], dict):
                val = str(where[key]).replace("/", "_").replace("\\", "_")
                next_dirs = []
                for d in dirs:
                    p = d / f"{key}={val}"
                    if p.exists():
                        next_dirs.append(p)
                dirs = next_dirs
            else:
                # не ограничиваем по ключу
                pass

        def _post_filter(rec: Record) -> bool:
            if not where:
                return True
            for k, cond in where.items():
                v = rec.get(k)
                if isinstance(cond, dict):
                    # поддержим базовые операторы: {"gte": x, "lte": y, "eq": z, "in": [..]}
                    if "eq" in cond and v != cond["eq"]:
                        return False
                    if "in" in cond and v not in cond["in"]:
                        return False
                    if "gte" in cond and not (v is not None and v >= cond["gte"]):
                        return False
                    if "lte" in cond and not (v is not None and v <= cond["lte"]):
                        return False
                elif isinstance(cond, (list, tuple, set)):
                    if v not in cond:
                        return False
                else:
                    if v != cond:
                        return False
            return True

        for d in dirs:
            for fp in d.rglob("part-*.jsonl"):
                with fp.open("r", encoding="utf-8") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        rec = json.loads(line)
                        if not _post_filter(rec):
                            continue
                        if columns:
                            rec = {c: rec.get(c) for c in columns}
                        yield rec
                        emitted += 1
                        if limit is not None and emitted >= limit:
                            return

    # ---------- Logical transactions as temp dirs ----------

    def begin(self, ds: DatasetId) -> str:
        txn = _hash_str(f"{ds.urn()}-{time.time_ns()}-{random.random()}")
        _ensure_dir(self._ds_root(ds, txn=txn))
        return txn

    def commit(self, ds: DatasetId, txn: str) -> None:
        staging = self._ds_root(ds, txn=txn)
        final = self._ds_root(ds)
        if not staging.exists():
            raise NotFoundError("Transaction not found")
        _ensure_dir(final.parent)
        # перемещаем содержимое staging в final
        for p in staging.rglob("*"):
            rel = p.relative_to(staging)
            dst = final / rel
            if p.is_dir():
                _ensure_dir(dst)
            else:
                _ensure_dir(dst.parent)
                data = p.read_bytes()
                dst.write_bytes(data)
        # удаляем staging
        for p in sorted(staging.rglob("*"), reverse=True):
            if p.is_file():
                p.unlink(missing_ok=True)  # type: ignore[arg-type]
            else:
                with contextlib.suppress(Exception):
                    p.rmdir()
        with contextlib.suppress(Exception):
            staging.rmdir()

    def abort(self, ds: DatasetId, txn: str) -> None:
        staging = self._ds_root(ds, txn=txn)
        if not staging.exists():
            return
        for p in sorted(staging.rglob("*"), reverse=True):
            if p.is_file():
                p.unlink(missing_ok=True)  # type: ignore[arg-type]
            else:
                with contextlib.suppress(Exception):
                    p.rmdir()
        with contextlib.suppress(Exception):
            staging.rmdir()


# ============================== Factory =======================================

def create_adapter_from_env() -> DataFabricAdapter:
    """
    Удобная фабрика: HTTP при наличии BASE_URL, иначе LocalFS.
    """
    cfg = DataFabricAdapterConfig(
        base_url=os.getenv("DF_BASE_URL") or None,
        api_key=os.getenv("DF_API_KEY") or None,
        bearer_token=os.getenv("DF_BEARER_TOKEN") or None,
        timeout_s=float(os.getenv("DF_TIMEOUT_S", "15")),
        chunk_bytes=int(os.getenv("DF_CHUNK_BYTES", "2000000")),
        max_records_per_chunk=int(os.getenv("DF_MAX_RECORDS_PER_CHUNK", "10000")),
        local_root=Path(os.getenv("DF_LOCAL_ROOT", "./datafabric")),
        local_partition_by=tuple(os.getenv("DF_PARTITION_BY", "").split(",")) if os.getenv("DF_PARTITION_BY") else tuple(),
        format=os.getenv("DF_FORMAT", "jsonl"),
    )
    if cfg.base_url:
        if httpx is None:
            raise RuntimeError("httpx is required for HTTP adapter; unset DF_BASE_URL to use LocalFS")
        return HTTPDataFabricAdapter(cfg)
    return LocalFSDataFabricAdapter(cfg)


# ============================== Example (commented) ===========================

# Example usage:
# ds = DatasetId(namespace="ml", name="events", version="v1")
# schema = DatasetSchema(fields=(
#     SchemaField("event_id", "string", False),
#     SchemaField("ts", "datetime", False),
#     SchemaField("user_id", "string", True),
#     SchemaField("value", "float", True),
# ), primary_keys=("event_id",))
#
# adapter = create_adapter_from_env()
# adapter.ensure_dataset(ds, schema)
# txn = adapter.begin(ds)
# try:
#     written = adapter.write_stream(ds, ({"event_id": str(i), "ts": _utcnow(), "value": i*0.1} for i in range(1000)), txn=txn)
#     adapter.commit(ds, txn)
# except Exception:
#     adapter.abort(ds, txn)
#     raise
# for row in adapter.query(ds, where={"value": {"gte": 10.0}}, limit=5, columns=["event_id", "value"]):
#     print(row)
