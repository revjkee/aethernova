# path: oblivionvault-core/oblivionvault/adapters/datafabric_adapter.py
from __future__ import annotations

import asyncio
import logging
import time
import json
import hashlib
import hmac
import os
from abc import ABC, abstractmethod
from typing import (
    Any,
    AsyncIterator,
    AsyncIterable,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    Tuple,
    Union,
    Set,
)

# -----------------------------
# Optional deps (safe fallbacks)
# -----------------------------
try:
    # pydantic v2
    from pydantic import BaseModel, Field, ConfigDict, ValidationError
except Exception:  # pragma: no cover
    # Lightweight fallback if pydantic is unavailable
    class BaseModel:  # type: ignore
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

        def model_dump(self) -> Dict[str, Any]:
            return self.__dict__

    class ValidationError(Exception):
        pass

    def Field(default=None, **kwargs):
        return default

    ConfigDict = dict  # type: ignore

try:
    # OpenTelemetry is optional
    from opentelemetry import trace as ot_trace  # type: ignore
    _OT_TRACER = ot_trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _OT_TRACER = None  # type: ignore

# -----------------------------
# Logging
# -----------------------------
LOG = logging.getLogger("oblivionvault.datafabric")
if not LOG.handlers:
    # Safe default console handler; production can override logging config
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )
    handler.setFormatter(formatter)
    LOG.addHandler(handler)
LOG.setLevel(logging.INFO)


# -----------------------------
# Errors
# -----------------------------
class DataFabricError(Exception):
    """Base error for DataFabric adapter."""


class DataFabricTimeout(DataFabricError):
    """Operation exceeded allowed time."""


class DataFabricAuthError(DataFabricError):
    """Access/authorization error (scope/tenant/principal)."""


class DataFabricSchemaError(DataFabricError):
    """Schema or validation error."""


class DataFabricConflict(DataFabricError):
    """Conflict or version mismatch."""


class DataFabricUnavailable(DataFabricError):
    """Backend is unavailable (transient)."""


class CircuitOpen(DataFabricError):
    """Circuit breaker is open; short-circuit operation."""


# -----------------------------
# Models
# -----------------------------
class AccessContext(BaseModel):
    """Zero-Trust access context used to authorize each operation."""
    model_config = ConfigDict(extra="allow") if isinstance(ConfigDict, dict) else ConfigDict(extra="allow")  # type: ignore

    tenant_id: str = Field(..., description="Tenant identifier")
    principal_id: str = Field(..., description="Actor/user identifier")
    scopes: Set[str] = Field(default_factory=set, description="Granted scopes")
    trace_id: Optional[str] = Field(default=None, description="Correlation/trace id")


class DataEnvelope(BaseModel):
    """Canonical envelope stored in DataFabric."""
    model_config = ConfigDict(extra="forbid") if isinstance(ConfigDict, dict) else ConfigDict(extra="forbid")  # type: ignore

    dataset: str
    key: str
    payload: Dict[str, Any]
    schema_version: str
    created_at: float
    updated_at: float
    signature: Optional[str] = None  # HMAC (optional)


class QuerySpec(BaseModel):
    """Query over a dataset."""
    model_config = ConfigDict(extra="forbid") if isinstance(ConfigDict, dict) else ConfigDict(extra="forbid")  # type: ignore

    dataset: str
    filter: Dict[str, Any] = Field(default_factory=dict)
    limit: Optional[int] = None
    order_by: Optional[List[str]] = None


class OperationResult(BaseModel):
    """Structured result for write/delete operations."""
    model_config = ConfigDict(extra="forbid") if isinstance(ConfigDict, dict) else ConfigDict(extra="forbid")  # type: ignore

    ok: bool
    items: int
    status: str
    elapsed_ms: int
    warnings: List[str] = Field(default_factory=list)
    trace_id: Optional[str] = None


# -----------------------------
# Transport (backend) interface
# -----------------------------
class DataFabricTransport(ABC):
    """
    Abstract transport for DataFabric operations.
    Implementations: S3/Delta/BigQuery/Snowflake/ClickHouse/etc.
    """

    @abstractmethod
    async def write(self, ctx: AccessContext, envelopes: Sequence[DataEnvelope]) -> None:
        ...

    @abstractmethod
    async def read(self, ctx: AccessContext, dataset: str, keys: Sequence[str]) -> List[DataEnvelope]:
        ...

    @abstractmethod
    async def query(self, ctx: AccessContext, spec: QuerySpec) -> AsyncIterator[DataEnvelope]:
        ...

    @abstractmethod
    async def delete(self, ctx: AccessContext, dataset: str, keys: Sequence[str]) -> int:
        ...

    @abstractmethod
    async def list_datasets(self, ctx: AccessContext) -> List[str]:
        ...

    @abstractmethod
    async def health(self, ctx: Optional[AccessContext] = None) -> Dict[str, Any]:
        ...


# -----------------------------
# Retry policy
# -----------------------------
class RetryPolicy(BaseModel):
    """Exponential backoff retry settings."""
    model_config = ConfigDict(extra="forbid") if isinstance(ConfigDict, dict) else ConfigDict(extra="forbid")  # type: ignore

    max_attempts: int = 5
    initial_backoff_s: float = 0.15
    max_backoff_s: float = 2.5
    jitter_s: float = 0.05
    retry_on: Tuple[type, ...] = (DataFabricUnavailable, DataFabricTimeout,)

    def next_backoff(self, attempt: int) -> float:
        base = min(self.max_backoff_s, self.initial_backoff_s * (2 ** (attempt - 1)))
        # simple bounded jitter
        return max(0.0, base + (self.jitter_s * ((hash(attempt) % 100) / 100.0 - 0.5)))


# -----------------------------
# Circuit Breaker
# -----------------------------
class CircuitBreaker:
    """
    Simple in-memory circuit breaker (thread-safe for asyncio context).
    States: CLOSED -> OPEN -> HALF_OPEN -> CLOSED
    """

    __slots__ = (
        "_lock",
        "_state",
        "_failure_count",
        "_opened_at",
        "_failure_threshold",
        "_recovery_time_s",
        "_half_open_successes_needed",
        "_half_open_successes",
    )

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_time_s: float = 5.0,
        half_open_successes_needed: int = 2,
    ):
        self._lock = asyncio.Lock()
        self._state = "CLOSED"
        self._failure_count = 0
        self._opened_at = 0.0
        self._failure_threshold = failure_threshold
        self._recovery_time_s = recovery_time_s
        self._half_open_successes_needed = half_open_successes_needed
        self._half_open_successes = 0

    async def allow(self) -> None:
        async with self._lock:
            if self._state == "OPEN":
                if time.time() - self._opened_at >= self._recovery_time_s:
                    self._state = "HALF_OPEN"
                    self._half_open_successes = 0
                else:
                    raise CircuitOpen("circuit open")
            # CLOSED or HALF_OPEN -> allowed

    async def on_success(self) -> None:
        async with self._lock:
            if self._state == "HALF_OPEN":
                self._half_open_successes += 1
                if self._half_open_successes >= self._half_open_successes_needed:
                    self._state = "CLOSED"
                    self._failure_count = 0
                    self._opened_at = 0.0
            else:
                self._failure_count = 0

    async def on_failure(self) -> None:
        async with self._lock:
            self._failure_count += 1
            if self._failure_count >= self._failure_threshold:
                self._state = "OPEN"
                self._opened_at = time.time()


# -----------------------------
# Idempotency cache (in-memory)
# -----------------------------
class _TTLCache:
    """Simple async-safe TTL cache for idempotent results."""
    def __init__(self, ttl_s: float = 600.0, max_entries: int = 10000):
        self._ttl_s = ttl_s
        self._max_entries = max_entries
        self._store: Dict[str, Tuple[float, OperationResult]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[OperationResult]:
        async with self._lock:
            item = self._store.get(key)
            if not item:
                return None
            ts, val = item
            if (time.time() - ts) > self._ttl_s:
                self._store.pop(key, None)
                return None
            return val

    async def put(self, key: str, value: OperationResult) -> None:
        async with self._lock:
            # Evict if too large (simple policy)
            if len(self._store) >= self._max_entries:
                # remove oldest
                oldest_key = min(self._store.items(), key=lambda kv: kv[1][0])[0]
                self._store.pop(oldest_key, None)
            self._store[key] = (time.time(), value)


# -----------------------------
# Utilities
# -----------------------------
def _require_scopes(ctx: AccessContext, needed: Set[str]) -> None:
    missing = needed - set(ctx.scopes or set())
    if missing:
        raise DataFabricAuthError(f"missing scopes: {sorted(missing)}")


def _stable_json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _hmac_sign(secret: Optional[bytes], data: Dict[str, Any]) -> Optional[str]:
    if not secret:
        return None
    msg = _stable_json(data).encode("utf-8")
    mac = hmac.new(secret, msg, hashlib.sha256).hexdigest()
    return mac


class _TracerCtx:
    """Context manager for optional OpenTelemetry spans."""
    def __init__(self, name: str, attrs: Optional[Dict[str, Any]] = None):
        self._name = name
        self._attrs = attrs or {}
        self._span = None

    def __enter__(self):
        if _OT_TRACER:
            self._span = _OT_TRACER.start_span(self._name)
            for k, v in self._attrs.items():
                try:
                    self._span.set_attribute(k, v)
                except Exception:
                    pass
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._span:
            if exc:
                try:
                    self._span.record_exception(exc)
                    self._span.set_attribute("error", True)
                except Exception:
                    pass
            try:
                self._span.end()
            except Exception:
                pass


async def _async_retry(
    func: Callable[[], Any],
    policy: RetryPolicy,
    timeout_s: Optional[float] = None,
    breaker: Optional[CircuitBreaker] = None,
    op_name: str = "operation",
    trace_attrs: Optional[Dict[str, Any]] = None,
) -> Any:
    attempt = 0
    with _TracerCtx(f"datafabric.{op_name}", trace_attrs):
        while True:
            attempt += 1
            if breaker:
                await breaker.allow()
            try:
                if timeout_s is not None:
                    return await asyncio.wait_for(func(), timeout=timeout_s)
                else:
                    return await func()
            except policy.retry_on as e:
                if attempt >= policy.max_attempts:
                    if breaker:
                        await breaker.on_failure()
                    LOG.warning(
                        "retry_exhausted op=%s attempts=%s err=%s",
                        op_name, attempt, type(e).__name__,
                    )
                    raise
                backoff = policy.next_backoff(attempt)
                LOG.info(
                    "retry op=%s attempt=%s backoff_s=%.3f err=%s",
                    op_name, attempt, backoff, type(e).__name__,
                )
                await asyncio.sleep(backoff)
                continue
            except asyncio.TimeoutError as e:
                if attempt >= policy.max_attempts:
                    if breaker:
                        await breaker.on_failure()
                    raise DataFabricTimeout(f"timeout for {op_name}") from e
                backoff = policy.next_backoff(attempt)
                LOG.info(
                    "retry_timeout op=%s attempt=%s backoff_s=%.3f",
                    op_name, attempt, backoff,
                )
                await asyncio.sleep(backoff)
                continue
            except CircuitOpen:
                # Propagate immediately
                raise
            except Exception as e:
                # Non-retriable
                if breaker:
                    await breaker.on_failure()
                LOG.exception("non_retriable op=%s err=%s", op_name, type(e).__name__)
                raise
            finally:
                # On success path above we return; on exceptions we may mark failure.
                pass


# -----------------------------
# Schema Validator type
# -----------------------------
SchemaValidator = Callable[[str, str, Dict[str, Any]], None]
# signature: (dataset, schema_version, payload) -> None or raise DataFabricSchemaError


# -----------------------------
# Adapter
# -----------------------------
class DataFabricAdapter:
    """
    High-reliability async adapter around DataFabricTransport with:
    - retries + circuit breaker
    - timeouts and concurrency limits
    - idempotency cache for write/delete
    - optional HMAC signatures
    - optional schema validation
    - scope-based authorization (Zero-Trust friendly)
    - chunked/batched writes
    - optional OpenTelemetry tracing
    """

    def __init__(
        self,
        transport: DataFabricTransport,
        *,
        retry_policy: Optional[RetryPolicy] = None,
        breaker: Optional[CircuitBreaker] = None,
        default_timeout_s: float = 15.0,
        max_concurrency: int = 64,
        chunk_size: int = 500,
        hmac_secret: Optional[Union[str, bytes]] = None,
        schema_validator: Optional[SchemaValidator] = None,
        idempotency_ttl_s: float = 600.0,
    ):
        self._transport = transport
        self._retry = retry_policy or RetryPolicy()
        self._breaker = breaker or CircuitBreaker()
        self._default_timeout_s = default_timeout_s
        self._sem = asyncio.Semaphore(max_concurrency)
        self._chunk_size = max(1, chunk_size)
        self._schema_validator = schema_validator
        if isinstance(hmac_secret, str):
            hmac_secret = hmac_secret.encode("utf-8")
        self._hmac_secret: Optional[bytes] = hmac_secret
        self._idem_cache = _TTLCache(ttl_s=idempotency_ttl_s)

    # -------- Public API --------

    async def health_check(self, ctx: Optional[AccessContext] = None) -> Dict[str, Any]:
        async def _call():
            return await self._transport.health(ctx)
        return await _async_retry(
            _call,
            policy=self._retry,
            timeout_s=self._default_timeout_s,
            breaker=self._breaker,
            op_name="health",
            trace_attrs={"phase": "health"},
        )

    async def list_datasets(self, ctx: AccessContext) -> List[str]:
        _require_scopes(ctx, {"df:list"})
        async def _call():
            async with self._sem:
                return await self._transport.list_datasets(ctx)
        return await _async_retry(
            _call,
            policy=self._retry,
            timeout_s=self._default_timeout_s,
            breaker=self._breaker,
            op_name="list_datasets",
            trace_attrs={"tenant": ctx.tenant_id},
        )

    async def get_records(
        self,
        ctx: AccessContext,
        dataset: str,
        keys: Sequence[str],
        *,
        timeout_s: Optional[float] = None,
    ) -> List[DataEnvelope]:
        _require_scopes(ctx, {"df:read"})
        if not keys:
            return []
        async def _call():
            async with self._sem:
                return await self._transport.read(ctx, dataset, keys)
        res = await _async_retry(
            _call,
            policy=self._retry,
            timeout_s=timeout_s or self._default_timeout_s,
            breaker=self._breaker,
            op_name="read",
            trace_attrs={"dataset": dataset, "count": len(keys)},
        )
        await self._breaker.on_success()
        return res

    async def query(
        self,
        ctx: AccessContext,
        spec: QuerySpec,
        *,
        timeout_s: Optional[float] = None,
    ) -> AsyncIterator[DataEnvelope]:
        _require_scopes(ctx, {"df:read"})
        async def _gen() -> AsyncIterator[DataEnvelope]:
            async def _call():
                async with self._sem:
                    return self._transport.query(ctx, spec)
            # We wrap the async iterator to apply timeout per chunk/next
            aiter = await _async_retry(
                _call,
                policy=self._retry,
                timeout_s=timeout_s or self._default_timeout_s,
                breaker=self._breaker,
                op_name="query.open",
                trace_attrs={"dataset": spec.dataset},
            )
            try:
                async for env in aiter:
                    yield env
                await self._breaker.on_success()
            except Exception as e:
                LOG.exception("query_iter_error dataset=%s err=%s", spec.dataset, type(e).__name__)
                raise
        return _gen()

    async def upsert_records(
        self,
        ctx: AccessContext,
        dataset: str,
        records: Union[Iterable[Dict[str, Any]], AsyncIterable[Dict[str, Any]]],
        *,
        schema_version: str,
        id_key: str,
        idempotency_key: Optional[str] = None,
        timeout_s: Optional[float] = None,
    ) -> OperationResult:
        _require_scopes(ctx, {"df:write"})
        started = time.perf_counter()

        # Idempotency
        idem_key = await self._make_idem_key(
            op="upsert",
            dataset=dataset,
            schema_version=schema_version,
            id_key=id_key,
            idempotency_key=idempotency_key,
            records=records,
        )
        cached = await self._idem_cache.get(idem_key)
        if cached:
            return cached

        total = 0
        warnings: List[str] = []

        async def _process_chunk(chunk: List[Dict[str, Any]]) -> None:
            envelopes = self._build_envelopes(dataset, schema_version, id_key, chunk)
            async def _call():
                async with self._sem:
                    await self._transport.write(ctx, envelopes)
            await _async_retry(
                _call,
                policy=self._retry,
                timeout_s=timeout_s or self._default_timeout_s,
                breaker=self._breaker,
                op_name="write",
                trace_attrs={"dataset": dataset, "count": len(envelopes)},
            )

        # Iterate records in chunks
        try:
            async for chunk in _iter_chunks(records, self._chunk_size):
                if not chunk:
                    continue
                # Validate + Sign performed in _build_envelopes
                await _process_chunk(chunk)
                total += len(chunk)
            await self._breaker.on_success()
        except ValidationError as ve:
            raise DataFabricSchemaError(str(ve)) from ve
        except CircuitOpen:
            raise
        except Exception as e:
            LOG.exception("upsert_failed dataset=%s err=%s", dataset, type(e).__name__)
            raise

        elapsed_ms = int((time.perf_counter() - started) * 1000)
        result = OperationResult(
            ok=True,
            items=total,
            status="upserted",
            elapsed_ms=elapsed_ms,
            warnings=warnings,
            trace_id=ctx.trace_id,
        )
        await self._idem_cache.put(idem_key, result)
        return result

    async def delete_records(
        self,
        ctx: AccessContext,
        dataset: str,
        keys: Sequence[str],
        *,
        idempotency_key: Optional[str] = None,
        timeout_s: Optional[float] = None,
    ) -> OperationResult:
        _require_scopes(ctx, {"df:delete"})
        started = time.perf_counter()

        if not keys:
            return OperationResult(
                ok=True, items=0, status="deleted", elapsed_ms=0, warnings=[], trace_id=ctx.trace_id
            )

        idem_key = await self._make_idem_key(
            op="delete",
            dataset=dataset,
            keys=keys,
            idempotency_key=idempotency_key,
        )
        cached = await self._idem_cache.get(idem_key)
        if cached:
            return cached

        async def _call():
            async with self._sem:
                return await self._transport.delete(ctx, dataset, keys)

        deleted = await _async_retry(
            _call,
            policy=self._retry,
            timeout_s=timeout_s or self._default_timeout_s,
            breaker=self._breaker,
            op_name="delete",
            trace_attrs={"dataset": dataset, "count": len(keys)},
        )
        await self._breaker.on_success()

        elapsed_ms = int((time.perf_counter() - started) * 1000)
        result = OperationResult(
            ok=True,
            items=int(deleted),
            status="deleted",
            elapsed_ms=elapsed_ms,
            warnings=[],
            trace_id=ctx.trace_id,
        )
        await self._idem_cache.put(idem_key, result)
        return result

    # -------- Helpers --------

    def _build_envelopes(
        self,
        dataset: str,
        schema_version: str,
        id_key: str,
        records: Sequence[Dict[str, Any]],
    ) -> List[DataEnvelope]:
        now = time.time()
        envelopes: List[DataEnvelope] = []
        for rec in records:
            if id_key not in rec or not rec[id_key]:
                raise DataFabricSchemaError(f"missing id key: {id_key}")
            payload = dict(rec)

            # Validate schema if validator provided
            if self._schema_validator:
                try:
                    self._schema_validator(dataset, schema_version, payload)
                except DataFabricSchemaError:
                    raise
                except Exception as e:
                    raise DataFabricSchemaError(str(e)) from e

            env = DataEnvelope(
                dataset=dataset,
                key=str(rec[id_key]),
                payload=payload,
                schema_version=schema_version,
                created_at=now,
                updated_at=now,
                signature=None,  # filled below if secret set
            )

            if self._hmac_secret:
                env.signature = _hmac_sign(self._hmac_secret, {
                    "dataset": env.dataset,
                    "key": env.key,
                    "schema_version": env.schema_version,
                    "payload": env.payload,
                    "created_at": env.created_at,
                    "updated_at": env.updated_at,
                })

            envelopes.append(env)
        return envelopes

    async def _make_idem_key(
        self,
        *,
        op: str,
        dataset: str,
        idempotency_key: Optional[str] = None,
        **op_kwargs: Any,
    ) -> str:
        """
        Build a stable idempotency key for the operation.
        If explicit idempotency_key provided, it dominates.
        """
        if idempotency_key:
            return f"{op}:{dataset}:{idempotency_key}"

        # Note: For large request bodies, this uses only hashes (no raw data)
        hasher = hashlib.sha256()
        hasher.update(op.encode("utf-8"))
        hasher.update(b":")
        hasher.update(dataset.encode("utf-8"))
        hasher.update(b":")
        # Normalize kwargs into stable JSON
        # If records stream passed, we compute a rolling hash lazily via snapshot
        normalized = await _snapshot_for_idem(op_kwargs)
        hasher.update(_stable_json(normalized).encode("utf-8"))
        return hasher.hexdigest()


# -----------------------------
# Iteration utilities
# -----------------------------
async def _iter_chunks(
    items: Union[Iterable[Dict[str, Any]], AsyncIterable[Dict[str, Any]]],
    chunk_size: int,
) -> AsyncIterator[List[Dict[str, Any]]]:
    if hasattr(items, "__aiter__"):
        buff: List[Dict[str, Any]] = []
        async for item in items:  # type: ignore
            buff.append(item)
            if len(buff) >= chunk_size:
                yield buff
                buff = []
        if buff:
            yield buff
    else:
        buff: List[Dict[str, Any]] = []
        for item in items:  # type: ignore
            buff.append(item)
            if len(buff) >= chunk_size:
                yield buff
                buff = []
        if buff:
            yield buff


async def _snapshot_for_idem(op_kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a compact snapshot for idempotency hashing:
    - For 'records' we compute a rolling sha256 over stable-json of each record.
    - For 'keys' we include a stable, sorted tuple.
    """
    result: Dict[str, Any] = {}
    for k, v in op_kwargs.items():
        if k == "records":
            # compute stream hash
            hasher = hashlib.sha256()
            if hasattr(v, "__aiter__"):
                async for rec in v:  # type: ignore
                    hasher.update(_stable_json(rec).encode("utf-8"))
            else:
                for rec in v:  # type: ignore
                    hasher.update(_stable_json(rec).encode("utf-8"))
            result["records_hash"] = hasher.hexdigest()
        elif k == "keys":
            try:
                result["keys"] = tuple(sorted(str(x) for x in v))
            except Exception:
                result["keys"] = "unhashable"
        else:
            result[k] = v
    return result
