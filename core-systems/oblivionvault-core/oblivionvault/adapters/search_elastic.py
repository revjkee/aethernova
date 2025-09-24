# file: oblivionvault/adapters/search_elastic.py
"""
Async Elasticsearch adapter for oblivionvault-core.

Features:
- Async client (ES 7/8 compatible import)
- Resiliency: exponential backoff retries, circuit breaker
- Secure logging: secret redaction, error shaping
- Index management: ensure index, aliases, optional rollover
- CRUD: get, exists, index/upsert, update, delete
- Search: bool DSL, pagination, PIT + search_after streaming
- Bulk: buffered bulk with concurrency control
- Observability: optional OpenTelemetry spans, structured logging
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import time
from dataclasses import dataclass, field
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Literal,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    TypedDict,
    Union,
)

# ---- Optional imports: Elasticsearch client & exceptions (ES 7/8) ----
try:
    # ES 8.x client still provides AsyncElasticsearch
    from elasticsearch import AsyncElasticsearch  # type: ignore
    from elasticsearch import (
        NotFoundError,  # type: ignore
        ApiError,  # type: ignore
        ConnectionError as ESConnectionError,  # type: ignore
        TransportError,  # type: ignore
    )
except Exception:  # pragma: no cover - fallback if package not present at import time
    AsyncElasticsearch = object  # type: ignore
    class NotFoundError(Exception): ...
    class ApiError(Exception): ...
    class ESConnectionError(Exception): ...
    class TransportError(Exception): ...

# ---- Optional imports: OpenTelemetry ----
try:
    from opentelemetry import trace  # type: ignore
    _TRACER = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _TRACER = None  # type: ignore


# ---- Logging setup ----
_LOG = logging.getLogger("oblivionvault.search.elastic")
if not _LOG.handlers:
    # Leave handler configuration to application; set level conservative here.
    _LOG.setLevel(logging.INFO)


# ---- Types ----

class Hit(TypedDict, total=False):
    _index: str
    _id: str
    _score: Optional[float]
    _source: Dict[str, Any]
    sort: List[Any]
    fields: Dict[str, Any]
    highlight: Dict[str, Any]


class SearchResult(TypedDict):
    hits: List[Hit]
    total: int
    took_ms: int
    pit_id: Optional[str]


BulkAction = Dict[str, Any]  # conforms to ES bulk format: [{ "index": {...}}, {...doc...}, ...]


# ---- Exceptions ----

class ElasticAdapterError(Exception):
    pass


class ElasticConfigError(ElasticAdapterError):
    pass


class ElasticRetryError(ElasticAdapterError):
    pass


class ElasticCircuitOpenError(ElasticAdapterError):
    pass


class ElasticIndexNotFound(ElasticAdapterError):
    pass


class ElasticDocumentNotFound(ElasticAdapterError):
    pass


# ---- Helpers ----

_REDACTION_KEYS = {"password", "pass", "secret", "token", "api_key", "authorization"}


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: ("***" if k.lower() in _REDACTION_KEYS else _redact(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(_redact(v) for v in value)
    if isinstance(value, str) and any(k in value.lower() for k in _REDACTION_KEYS):
        return "***"
    return value


def _maybe_span(name: str):
    """Context manager factory for optional OpenTelemetry spans."""
    class _Noop:
        def __enter__(self): return self
        def __exit__(self, exc_type, exc, tb): return False
        def set_attribute(self, *_args, **_kwargs): pass

    if _TRACER is None:
        return _Noop()
    return _TRACER.start_as_current_span(name)


# ---- Config ----

@dataclass(frozen=True)
class ElasticConfig:
    hosts: Tuple[str, ...] = field(default_factory=lambda: ("http://localhost:9200",))
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None  # format: id:api_key or just api_key for Cloud
    cloud_id: Optional[str] = None
    verify_certs: bool = True
    ca_certs: Optional[str] = None
    request_timeout: float = 10.0
    max_retries: int = 3  # transport-level
    retry_on_status: Tuple[int, ...] = (502, 503, 504)
    index_prefix: str = "oblivionvault"
    sniff_on_start: bool = False
    sniff_on_connection_fail: bool = False
    http_compress: bool = True
    headers: Mapping[str, str] = field(default_factory=dict)

    def client_kwargs(self) -> Dict[str, Any]:
        kwargs: Dict[str, Any] = dict(
            request_timeout=self.request_timeout,
            retry_on_status=list(self.retry_on_status),
            max_retries=self.max_retries,
            verify_certs=self.verify_certs,
            http_compress=self.http_compress,
            sniff_on_start=self.sniff_on_start,
            sniff_on_connection_fail=self.sniff_on_connection_fail,
            headers=dict(self.headers),
        )
        if self.cloud_id:
            kwargs["cloud_id"] = self.cloud_id
        else:
            kwargs["hosts"] = list(self.hosts)

        if self.api_key:
            kwargs["api_key"] = self.api_key
        elif self.username and self.password:
            kwargs["basic_auth"] = (self.username, self.password)
        if self.ca_certs:
            kwargs["ca_certs"] = self.ca_certs
        return kwargs

    def index_full_name(self, base: str) -> str:
        return f"{self.index_prefix}-{base}".lower()


# ---- Circuit Breaker ----

class CircuitBreaker:
    """
    Simple async-aware circuit breaker:
    - close -> failures increase -> open after threshold
    - open  -> short-circuits until timeout elapsed -> half-open
    - half-open -> single trial; success closes, failure re-opens
    """
    def __init__(self, failure_threshold: int = 5, reset_timeout: float = 30.0):
        self._failure_threshold = max(1, failure_threshold)
        self._reset_timeout = max(1.0, reset_timeout)
        self._state: Literal["closed", "open", "half-open"] = "closed"
        self._fail_count = 0
        self._opened_at = 0.0
        self._lock = asyncio.Lock()

    async def allow(self) -> None:
        async with self._lock:
            if self._state == "open":
                if time.monotonic() - self._opened_at >= self._reset_timeout:
                    self._state = "half-open"
                else:
                    raise ElasticCircuitOpenError("Circuit is open")
            # closed or half-open: allow

    async def on_success(self) -> None:
        async with self._lock:
            self._fail_count = 0
            self._state = "closed"

    async def on_failure(self) -> None:
        async with self._lock:
            self._fail_count += 1
            if self._state == "half-open":
                self._state = "open"
                self._opened_at = time.monotonic()
            elif self._fail_count >= self._failure_threshold:
                self._state = "open"
                self._opened_at = time.monotonic()

    @property
    def state(self) -> str:
        return self._state


# ---- Adapter ----

class AsyncElasticAdapter:
    """
    Production-grade async adapter for Elasticsearch.

    Usage:
        cfg = ElasticConfig(...)
        adapter = AsyncElasticAdapter(cfg, base_index="artifacts")
        async with adapter:
            await adapter.ensure_index(mappings=..., settings=...)
            await adapter.index_doc("id1", {"a": 1})
            res = await adapter.search(bool_query={"must": [{"term": {"a": 1}}]})
    """

    def __init__(
        self,
        config: ElasticConfig,
        base_index: str,
        *,
        default_mappings: Optional[Mapping[str, Any]] = None,
        default_settings: Optional[Mapping[str, Any]] = None,
        alias: Optional[str] = None,
        retry_attempts: int = 5,
        retry_base_delay: float = 0.2,
        circuit_failure_threshold: int = 6,
        circuit_reset_timeout: float = 20.0,
    ) -> None:
        if AsyncElasticsearch is object:
            raise ElasticConfigError("elasticsearch python client is not installed")
        self._cfg = config
        self._index_base = base_index
        self._index = config.index_full_name(base_index)
        self._alias = alias or self._index
        self._default_mappings = dict(default_mappings or {})
        self._default_settings = dict(default_settings or {})
        self._client: Optional[AsyncElasticsearch] = None
        self._retry_attempts = max(1, retry_attempts)
        self._retry_base_delay = max(0.01, retry_base_delay)
        self._breaker = CircuitBreaker(
            failure_threshold=circuit_failure_threshold,
            reset_timeout=circuit_reset_timeout,
        )
        self._closed = True

    # ---- Lifecycle ----

    async def __aenter__(self) -> "AsyncElasticAdapter":
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def connect(self) -> None:
        if self._client is None:
            kwargs = self._cfg.client_kwargs()
            safe_kwargs = _redact(kwargs)
            _LOG.debug("Elasticsearch client init", extra={"kwargs": safe_kwargs})
            self._client = AsyncElasticsearch(**kwargs)
        self._closed = False

    async def close(self) -> None:
        if self._client is not None and not self._closed:
            try:
                await self._client.close()
            finally:
                self._closed = True

    # ---- Low-level helpers ----

    async def _retrying(self, op_name: str, func: Callable[[], Awaitable[Any]]) -> Any:
        await self._breaker.allow()
        attempt = 0
        while True:
            try:
                with _maybe_span(f"elastic.{op_name}") as span:
                    if hasattr(span, "set_attribute"):
                        span.set_attribute("elastic.op", op_name)
                        span.set_attribute("elastic.index", self._index)
                        span.set_attribute("elastic.alias", self._alias)
                    result = await func()
                    await self._breaker.on_success()
                    return result
            except (ESConnectionError, TransportError, ApiError) as e:
                attempt += 1
                retriable = _is_retriable_error(e)
                if not retriable or attempt >= self._retry_attempts:
                    await self._breaker.on_failure()
                    shaped = _shape_error(e)
                    _LOG.error(
                        "Elasticsearch op failed",
                        extra={
                            "op": op_name,
                            "attempt": attempt,
                            "index": self._index,
                            "error": shaped,
                        },
                    )
                    raise ElasticRetryError(f"{op_name} failed after {attempt} attempts") from e
                # jittered exponential backoff
                delay = _backoff_delay(self._retry_base_delay, attempt)
                _LOG.warning(
                    "Elasticsearch op retrying",
                    extra={"op": op_name, "attempt": attempt, "delay_s": round(delay, 3)},
                )
                await asyncio.sleep(delay)
            except Exception as e:  # non-ES errors
                await self._breaker.on_failure()
                _LOG.exception("Unexpected error in Elasticsearch op %s", op_name)
                raise

    def _require_client(self) -> AsyncElasticsearch:
        if self._client is None:
            raise ElasticConfigError("Elasticsearch client is not connected. Call connect() or use context manager.")
        return self._client

    # ---- Health ----

    async def ping(self) -> bool:
        client = self._require_client()
        return bool(await self._retrying("ping", lambda: client.ping()))

    # ---- Index management ----

    async def ensure_index(
        self,
        *,
        mappings: Optional[Mapping[str, Any]] = None,
        settings: Optional[Mapping[str, Any]] = None,
        create_alias: bool = True,
    ) -> None:
        """
        Idempotently ensure index exists with provided mappings/settings.
        Optionally create an alias pointing to it.
        """
        client = self._require_client()
        idx = self._index
        _mappings = dict(self._default_mappings)
        if mappings:
            _mappings.update(mappings)
        _settings = dict(self._default_settings)
        if settings:
            _settings.update(settings)

        async def _exists() -> bool:
            return await client.indices.exists(index=idx)  # type: ignore[attr-defined]

        exists = await self._retrying("indices.exists", _exists)
        if not exists:
            async def _create():
                body: Dict[str, Any] = {}
                if _settings:
                    body["settings"] = _settings
                if _mappings:
                    body["mappings"] = _mappings
                return await client.indices.create(index=idx, **({"settings": _settings} if _settings else {}), **({"mappings": _mappings} if _mappings else {}))  # type: ignore[attr-defined]

            await self._retrying("indices.create", _create)
            _LOG.info("Created index", extra={"index": idx})

        if create_alias and self._alias:
            await self._ensure_alias(self._alias, idx)

    async def _ensure_alias(self, alias: str, index: str) -> None:
        client = self._require_client()

        async def _exists_alias() -> bool:
            return await client.indices.exists_alias(name=alias)  # type: ignore[attr-defined]

        has_alias = await self._retrying("indices.exists_alias", _exists_alias)
        if not has_alias:
            async def _put():
                return await client.indices.put_alias(index=index, name=alias)  # type: ignore[attr-defined]
            await self._retrying("indices.put_alias", _put)
            _LOG.info("Created alias", extra={"alias": alias, "index": index})

    async def rollover_if_needed(
        self,
        alias: Optional[str] = None,
        conditions: Optional[Mapping[str, Any]] = None,
        *,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Trigger ES rollover if conditions are met. Requires write alias.
        Example conditions: {"max_age": "7d", "max_size": "50gb", "max_docs": 10_000_000}
        """
        client = self._require_client()
        alias = alias or self._alias
        if not alias:
            raise ElasticConfigError("Rollover requires a write alias")
        payload = {"conditions": conditions or {"max_age": "7d"}}
        if dry_run:
            payload["dry_run"] = True

        async def _roll():
            return await client.indices.rollover(alias=alias, body=payload)  # type: ignore[attr-defined]

        res = await self._retrying("indices.rollover", _roll)
        _LOG.info("Rollover executed", extra={"alias": alias, "dry_run": dry_run, "rolled": bool(res.get("rolled_over"))})
        return res

    # ---- CRUD ----

    async def get(self, doc_id: str, *, _source: Optional[Sequence[str]] = None) -> Dict[str, Any]:
        client = self._require_client()
        async def _op():
            return await client.get(index=self._alias, id=doc_id, _source_includes=list(_source) if _source else None)  # type: ignore
        try:
            res = await self._retrying("get", _op)
        except NotFoundError as e:
            raise ElasticDocumentNotFound(doc_id) from e
        src = res.get("_source") or {}
        return src

    async def exists(self, doc_id: str) -> bool:
        client = self._require_client()
        async def _op():
            return await client.exists(index=self._alias, id=doc_id)  # type: ignore
        return bool(await self._retrying("exists", _op))

    async def index_doc(
        self,
        doc_id: Optional[str],
        document: Mapping[str, Any],
        *,
        refresh: Optional[Literal["wait_for", "true", "false"]] = None,
        pipeline: Optional[str] = None,
        routing: Optional[str] = None,
    ) -> str:
        client = self._require_client()
        body = dict(document)
        async def _op():
            return await client.index(
                index=self._alias,
                id=doc_id,
                document=body,
                refresh=refresh,
                pipeline=pipeline,
                routing=routing,
            )  # type: ignore
        res = await self._retrying("index", _op)
        return str(res.get("_id"))

    async def update_doc(
        self,
        doc_id: str,
        partial: Mapping[str, Any],
        *,
        refresh: Optional[Literal["wait_for", "true", "false"]] = None,
        detect_noop: bool = True,
        upsert: Optional[Mapping[str, Any]] = None,
        routing: Optional[str] = None,
    ) -> None:
        client = self._require_client()
        body: Dict[str, Any] = {"doc": dict(partial), "doc_as_upsert": False, "detect_noop": detect_noop}
        if upsert is not None:
            body["upsert"] = dict(upsert)
        async def _op():
            return await client.update(
                index=self._alias,
                id=doc_id,
                body=body,
                refresh=refresh,
                routing=routing,
            )  # type: ignore
        await self._retrying("update", _op)

    async def delete_doc(self, doc_id: str, *, refresh: Optional[Literal["wait_for", "true", "false"]] = None) -> bool:
        client = self._require_client()
        async def _op():
            return await client.delete(index=self._alias, id=doc_id, refresh=refresh, ignore=[404])  # type: ignore
        res = await self._retrying("delete", _op)
        return res.get("result") in {"deleted", "not_found"}

    # ---- Search ----

    @staticmethod
    def _build_bool_query(
        *,
        must: Optional[Sequence[Mapping[str, Any]]] = None,
        filter: Optional[Sequence[Mapping[str, Any]]] = None,
        should: Optional[Sequence[Mapping[str, Any]]] = None,
        must_not: Optional[Sequence[Mapping[str, Any]]] = None,
        minimum_should_match: Optional[int] = None,
    ) -> Dict[str, Any]:
        parts: Dict[str, Any] = {}
        if must: parts["must"] = list(must)
        if filter: parts["filter"] = list(filter)
        if should:
            parts["should"] = list(should)
            if minimum_should_match is not None:
                parts["minimum_should_match"] = minimum_should_match
        if must_not: parts["must_not"] = list(must_not)
        return {"bool": parts} if parts else {"match_all": {}}

    async def search(
        self,
        *,
        must: Optional[Sequence[Mapping[str, Any]]] = None,
        filter: Optional[Sequence[Mapping[str, Any]]] = None,
        should: Optional[Sequence[Mapping[str, Any]]] = None,
        must_not: Optional[Sequence[Mapping[str, Any]]] = None,
        minimum_should_match: Optional[int] = None,
        size: int = 50,
        from_: int = 0,
        sort: Optional[Sequence[Union[str, Mapping[str, Any]]]] = None,
        source_includes: Optional[Sequence[str]] = None,
        source_excludes: Optional[Sequence[str]] = None,
        track_total_hits: Union[bool, int] = True,
        highlight: Optional[Mapping[str, Any]] = None,
        aggs: Optional[Mapping[str, Any]] = None,
    ) -> SearchResult:
        client = self._require_client()
        query = self._build_bool_query(
            must=must, filter=filter, should=should, must_not=must_not, minimum_should_match=minimum_should_match
        )
        body: Dict[str, Any] = {"query": query, "size": size, "from": from_, "track_total_hits": track_total_hits}
        if sort: body["sort"] = list(sort)
        if source_includes or source_excludes:
            body["_source"] = {}
            if source_includes: body["_source"]["includes"] = list(source_includes)
            if source_excludes: body["_source"]["excludes"] = list(source_excludes)
        if highlight: body["highlight"] = dict(highlight)
        if aggs: body["aggs"] = dict(aggs)

        async def _op():
            return await client.search(index=self._alias, body=body)  # type: ignore

        res = await self._retrying("search", _op)
        total = _extract_total(res)
        hits = [hit for hit in res.get("hits", {}).get("hits", [])]
        took_ms = int(res.get("took", 0))
        return {"hits": hits, "total": total, "took_ms": took_ms, "pit_id": None}

    async def search_stream(
        self,
        *,
        must: Optional[Sequence[Mapping[str, Any]]] = None,
        filter: Optional[Sequence[Mapping[str, Any]]] = None,
        should: Optional[Sequence[Mapping[str, Any]]] = None,
        must_not: Optional[Sequence[Mapping[str, Any]]] = None,
        minimum_should_match: Optional[int] = None,
        page_size: int = 500,
        keep_alive: str = "2m",
        sort: Optional[Sequence[Union[str, Mapping[str, Any]]]] = None,
        source_includes: Optional[Sequence[str]] = None,
        source_excludes: Optional[Sequence[str]] = None,
    ) -> AsyncIterator[Hit]:
        """
        Stream results using PIT + search_after for large scans with stable sort.
        """
        client = self._require_client()
        query = self._build_bool_query(
            must=must, filter=filter, should=should, must_not=must_not, minimum_should_match=minimum_should_match
        )
        sort_clause = list(sort or [{"_shard_doc": "asc"}])
        pit_id = await self._open_pit(keep_alive=keep_alive)
        try:
            search_after: Optional[List[Any]] = None
            while True:
                body: Dict[str, Any] = {
                    "size": page_size,
                    "query": query,
                    "sort": sort_clause,
                    "pit": {"id": pit_id, "keep_alive": keep_alive},
                }
                if search_after:
                    body["search_after"] = search_after
                if source_includes or source_excludes:
                    body["_source"] = {}
                    if source_includes: body["_source"]["includes"] = list(source_includes)
                    if source_excludes: body["_source"]["excludes"] = list(source_excludes)

                async def _op():
                    return await client.search(body=body)  # type: ignore

                res = await self._retrying("search", _op)
                hits = res.get("hits", {}).get("hits", [])
                if not hits:
                    return
                for h in hits:
                    yield h  # type: ignore[misc]
                search_after = hits[-1].get("sort")
                pit_id = res.get("pit_id", pit_id)
        finally:
            await self._close_pit(pit_id)

    async def _open_pit(self, keep_alive: str) -> str:
        client = self._require_client()
        async def _op():
            return await client.open_point_in_time(index=self._alias, keep_alive=keep_alive)  # type: ignore
        res = await self._retrying("open_point_in_time", _op)
        pid = res.get("pit_id")
        if not pid:
            raise ElasticAdapterError("Failed to open PIT")
        return str(pid)

    async def _close_pit(self, pit_id: Optional[str]) -> None:
        if not pit_id:
            return
        client = self._require_client()
        async def _op():
            return await client.close_point_in_time(body={"pit_id": pit_id})  # type: ignore
        try:
            await self._retrying("close_point_in_time", _op)
        except Exception:
            _LOG.warning("Failed to close PIT", extra={"pit_id": pit_id})

    # ---- Delete by query ----

    async def delete_by_query(
        self,
        *,
        must: Optional[Sequence[Mapping[str, Any]]] = None,
        filter: Optional[Sequence[Mapping[str, Any]]] = None,
        must_not: Optional[Sequence[Mapping[str, Any]]] = None,
        refresh: bool = False,
        conflicts: Literal["proceed", "abort"] = "proceed",
        batch_size: int = 1000,
        timeout: str = "5m",
    ) -> Dict[str, Any]:
        client = self._require_client()
        query = self._build_bool_query(must=must, filter=filter, must_not=must_not)
        params = {
            "refresh": refresh,
            "conflicts": conflicts,
            "requests_per_second": -1,  # unlimited
            "slices": "auto",
            "timeout": timeout,
            "body": {"query": query, "batch_size": batch_size},
        }

        async def _op():
            return await client.delete_by_query(index=self._alias, **params)  # type: ignore

        res = await self._retrying("delete_by_query", _op)
        return res

    # ---- Bulk ----

    async def bulk(
        self,
        actions: Iterable[BulkAction],
        *,
        refresh: Optional[Literal["wait_for", "true", "false"]] = None,
        raise_on_error: bool = True,
        chunk_size: int = 500,
        concurrency: int = 2,
        timeout: str = "2m",
    ) -> Tuple[int, int]:
        """
        Execute bulk actions (pre-formatted) with bounded concurrency.
        Returns (items_ok, items_failed).
        """
        client = self._require_client()

        async def _gen_chunks() -> AsyncIterator[List[BulkAction]]:
            chunk: List[BulkAction] = []
            for a in actions:
                chunk.append(a)
                if len(chunk) >= chunk_size:
                    yield chunk
                    chunk = []
            if chunk:
                yield chunk

        sem = asyncio.Semaphore(concurrency)
        ok = 0
        failed = 0

        async def _send(chunk: List[BulkAction]) -> None:
            nonlocal ok, failed
            async with sem:
                async def _op():
                    return await client.bulk(
                        operations=chunk,  # ES 8
                        refresh=refresh,
                        timeout=timeout,
                        index=self._alias,
                    )  # type: ignore
                res = await self._retrying("bulk", _op)
                if res.get("errors"):
                    for item in res.get("items", []):
                        # item like {'index': {'status': 201, 'error': {...}}}
                        action_name, info = next(iter(item.items()))
                        status = info.get("status", 0)
                        if 200 <= status < 300:
                            ok += 1
                        else:
                            failed += 1
                            if raise_on_error:
                                _LOG.error("Bulk item failed", extra={"action": action_name, "info": _redact(info)})
                    if raise_on_error and failed:
                        raise ElasticAdapterError(f"Bulk had {failed} failed items")
                else:
                    ok += len(res.get("items", []))

        tasks = [asyncio.create_task(_send(chunk)) async for chunk in _gen_chunks()]
        if tasks:
            await asyncio.gather(*tasks)
        return ok, failed

    # ---- Utilities ----

    async def refresh(self) -> None:
        client = self._require_client()
        async def _op():
            return await client.indices.refresh(index=self._alias)  # type: ignore[attr-defined]
        await self._retrying("indices.refresh", _op)

    @property
    def index(self) -> str:
        return self._index

    @property
    def alias(self) -> str:
        return self._alias


# ---- Error shaping & retry policy ----

def _shape_error(e: Exception) -> Dict[str, Any]:
    shaped: Dict[str, Any] = {"type": type(e).__name__, "message": str(e)}
    # Try to extract status code safely
    status = getattr(e, "status", None) or getattr(e, "meta", None)
    if hasattr(status, "status"):
        try:
            shaped["status"] = int(status.status)  # type: ignore
        except Exception:
            pass
    elif hasattr(e, "status"):
        try:
            shaped["status"] = int(getattr(e, "status"))
        except Exception:
            pass
    return shaped


def _is_retriable_error(e: Exception) -> bool:
    if isinstance(e, ESConnectionError):
        return True
    if isinstance(e, TransportError):
        code = getattr(e, "status_code", None) or getattr(e, "status", None)
        return code in (502, 503, 504, 408)
    if isinstance(e, ApiError):
        code = getattr(e, "status_code", None) or getattr(e, "status", None)
        return code in (429, 502, 503, 504, 408)
    return False


def _backoff_delay(base: float, attempt: int, max_delay: float = 5.0) -> float:
    # exponential with full jitter
    exp = min(max_delay, base * (2 ** (attempt - 1)))
    return random.uniform(0, exp)


# ---- Minimal convenience factories ----

def make_adapter_from_env(
    base_index: str,
    *,
    default_mappings: Optional[Mapping[str, Any]] = None,
    default_settings: Optional[Mapping[str, Any]] = None,
    alias: Optional[str] = None,
) -> AsyncElasticAdapter:
    """
    Create adapter from environment variables:
    - ES_HOSTS (comma-separated), ES_USERNAME, ES_PASSWORD, ES_API_KEY, ES_CLOUD_ID
    - ES_VERIFY_CERTS=true/false, ES_CA_CERTS, ES_REQ_TIMEOUT, ES_INDEX_PREFIX
    """
    hosts = tuple(h.strip() for h in os.getenv("ES_HOSTS", "http://localhost:9200").split(",") if h.strip())
    cfg = ElasticConfig(
        hosts=hosts,
        username=os.getenv("ES_USERNAME") or None,
        password=os.getenv("ES_PASSWORD") or None,
        api_key=os.getenv("ES_API_KEY") or None,
        cloud_id=os.getenv("ES_CLOUD_ID") or None,
        verify_certs=os.getenv("ES_VERIFY_CERTS", "true").lower() == "true",
        ca_certs=os.getenv("ES_CA_CERTS") or None,
        request_timeout=float(os.getenv("ES_REQ_TIMEOUT", "10")),
        index_prefix=os.getenv("ES_INDEX_PREFIX", "oblivionvault"),
    )
    return AsyncElasticAdapter(
        cfg,
        base_index=base_index,
        default_mappings=default_mappings,
        default_settings=default_settings,
        alias=alias,
    )
