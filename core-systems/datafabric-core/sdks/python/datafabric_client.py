# -*- coding: utf-8 -*-
"""
DataFabric Python SDK (industrial-grade)

Features:
- Sync & Async clients (httpx)
- Auth: Bearer (OIDC/JWT) or API-Key, optional mTLS (httpx.SSLConfig)
- Timeouts, retries (exponential backoff + jitter), circuit-like gating
- Idempotency-Key for safe POST/PUT
- Pydantic models for requests/responses
- Pagination iterators
- Structured logging
- Optional OpenTelemetry tracing (if installed)
- Strict type hints

Env (safe defaults):
  DATAFABRIC_BASE_URL=https://api.example.org
  DATAFABRIC_API_KEY=...
  DATAFABRIC_BEARER_TOKEN=...
  DATAFABRIC_TIMEOUT_SECONDS=10
  DATAFABRIC_RETRIES=3
  DATAFABRIC_USER_AGENT=datafabric-sdk-python/1.0
  DATAFABRIC_VERIFY_TLS=true
  DATAFABRIC_CA_BUNDLE=/etc/ssl/certs/ca-bundle.crt
"""

from __future__ import annotations

import os
import sys
import time
import uuid
import json
import math
import types
import logging
import functools
import contextlib
from typing import Any, Dict, Iterable, Iterator, AsyncIterator, List, Optional, Tuple, Type, TypeVar, Union, Callable

import httpx
from pydantic import BaseModel, Field, AnyHttpUrl, ValidationError, conint, constr, root_validator

# Optional OpenTelemetry
try:
    from opentelemetry import trace  # type: ignore
    from opentelemetry.trace import Tracer
except Exception:  # pragma: no cover
    trace = None
    Tracer = None  # type: ignore

__all__ = [
    "DatafabricClient",
    "AsyncDatafabricClient",
    "ClientConfig",
    "ApiError",
    "RateLimitedError",
    "UnauthorizedError",
    "NotFoundError",
    "ConflictError",
    "ServerError",
    "IngestEvent",
    "PublishAck",
    "PublishResult",
    "Dataset",
    "DatasetVersion",
    "Paged",
]

# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------
LOG = logging.getLogger("datafabric.sdk")
if not LOG.handlers:
    _h = logging.StreamHandler(sys.stderr)
    _fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(message)s")
    _h.setFormatter(_fmt)
    LOG.addHandler(_h)
LOG.setLevel(logging.INFO)

# ------------------------------------------------------------------------------
# Config & Models
# ------------------------------------------------------------------------------

def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.lower() in ("1", "true", "yes", "y", "on")

class ClientConfig(BaseModel):
    base_url: AnyHttpUrl = Field(default=os.getenv("DATAFABRIC_BASE_URL", "https://api.example.org"))
    api_key: Optional[str] = Field(default=os.getenv("DATAFABRIC_API_KEY"))
    bearer_token: Optional[str] = Field(default=os.getenv("DATAFABRIC_BEARER_TOKEN"))
    timeout_seconds: float = Field(default=float(os.getenv("DATAFABRIC_TIMEOUT_SECONDS", "10")))
    retries: conint(ge=0, le=10) = Field(default=int(os.getenv("DATAFABRIC_RETRIES", "3")))
    user_agent: str = Field(default=os.getenv("DATAFABRIC_USER_AGENT", "datafabric-sdk-python/1.0"))
    verify_tls: bool = Field(default=_env_bool("DATAFABRIC_VERIFY_TLS", True))
    ca_bundle: Optional[str] = Field(default=os.getenv("DATAFABRIC_CA_BUNDLE"))
    # Optional mTLS (provide client cert and key)
    client_cert: Optional[str] = Field(default=os.getenv("DATAFABRIC_CLIENT_CERT"))
    client_key: Optional[str] = Field(default=os.getenv("DATAFABRIC_CLIENT_KEY"))
    # Idempotency defaults
    idempotency_for_post: bool = Field(default=True)
    # Max payload size (defense-in-depth)
    max_payload_bytes: int = Field(default=10 * 1024 * 1024)  # 10 MiB

    @root_validator
    def _auth_choice(cls, values):  # type: ignore
        # Accept either API key or Bearer (or both; bearer has precedence)
        return values

# Common DTOs (align with earlier proto/avro SQL shapes; names are illustrative)

class IngestEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: constr(strip_whitespace=True, min_length=1)
    source: constr(strip_whitespace=True, min_length=1)
    schema_uri: constr(strip_whitespace=True, min_length=1)
    schema_version: conint(ge=1) = 1
    payload: Dict[str, Any]
    produced_at: Optional[int] = Field(None, description="epoch micros")
    idempotency_key: Optional[str] = None
    key: Optional[str] = None
    labels: Dict[str, str] = Field(default_factory=dict)
    checksum_sha256_hex: Optional[str] = None

class PublishAck(BaseModel):
    event_id: str
    code: str
    message: Optional[str] = None
    duplicate: Optional[bool] = None
    partition: Optional[int] = None
    offset: Optional[int] = None
    visible_at: Optional[int] = None  # epoch micros

class PublishResult(BaseModel):
    acks: List[PublishAck]

class DatasetVersion(BaseModel):
    version: conint(ge=1)
    schema_uri: str
    schema_version: conint(ge=1) = 1
    format: str = Field(regex="^(JSON|AVRO|PROTOBUF|PARQUET|CSV)$")
    source_uri: Optional[str] = None
    sink_uri: Optional[str] = None
    is_default: bool = False
    labels: Dict[str, str] = Field(default_factory=dict)

class Dataset(BaseModel):
    dataset_id: Optional[str] = None
    tenant_id: constr(strip_whitespace=True, min_length=1)
    name: constr(strip_whitespace=True, min_length=1)
    description: Optional[str] = None
    type: str = Field(regex="^(STREAM|BATCH|VIRTUAL)$")
    state: str = Field(default="ACTIVE", regex="^(ACTIVE|INACTIVE|DEPRECATED|DELETED)$")
    access_level: str = Field(default="INTERNAL", regex="^(PUBLIC|INTERNAL|RESTRICTED)$")
    storage_policy: str = Field(default="TTL", regex="^(TTL|FOREVER)$")
    storage_ttl_seconds: conint(ge=1) = 180 * 24 * 3600
    default_format: str = Field(default="PARQUET", regex="^(JSON|AVRO|PROTOBUF|PARQUET|CSV)$")
    labels: Dict[str, str] = Field(default_factory=dict)
    annotations: Dict[str, Any] = Field(default_factory=dict)
    versions: List[DatasetVersion] = Field(default_factory=list)

class Paged(BaseModel):
    items: List[Any]
    next_page_token: Optional[str] = None

# ------------------------------------------------------------------------------
# Errors
# ------------------------------------------------------------------------------

class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(f"{status} {code}: {message}")
        self.status = status
        self.code = code
        self.message = message
        self.details = details or {}

class UnauthorizedError(ApiError): ...
class NotFoundError(ApiError): ...
class ConflictError(ApiError): ...
class RateLimitedError(ApiError): ...
class ServerError(ApiError): ...

def _raise_for_status(resp: httpx.Response) -> None:
    if 200 <= resp.status_code < 300:
        return
    payload = {}
    try:
        payload = resp.json()
    except Exception:
        payload = {"message": resp.text}
    code = str(payload.get("code") or resp.status_code)
    msg = str(payload.get("message") or resp.reason_phrase)
    if resp.status_code == 401:
        raise UnauthorizedError(resp.status_code, code, msg, payload)
    if resp.status_code == 404:
        raise NotFoundError(resp.status_code, code, msg, payload)
    if resp.status_code == 409:
        raise ConflictError(resp.status_code, code, msg, payload)
    if resp.status_code == 429:
        raise RateLimitedError(resp.status_code, code, msg, payload)
    if 500 <= resp.status_code < 600:
        raise ServerError(resp.status_code, code, msg, payload)
    raise ApiError(resp.status_code, code, msg, payload)

# ------------------------------------------------------------------------------
# Retry / Backoff
# ------------------------------------------------------------------------------

Retryable = Tuple[httpx.TimeoutException, httpx.ConnectError, httpx.ReadTimeout, ServerError, RateLimitedError]
def _is_retryable(exc: Exception) -> bool:
    from httpx import TimeoutException, ConnectError, ReadTimeout, RemoteProtocolError
    return isinstance(exc, (TimeoutException, ConnectError, ReadTimeout, RemoteProtocolError, ServerError, RateLimitedError))

def _sleep_backoff(attempt: int) -> float:
    # exponential backoff with jitter; cap ~ 10s
    base = min(10.0, 0.25 * (2 ** max(0, attempt - 1)))
    # decorrelated jitter
    return 0.5 * base + (base * os.urandom(1)[0] / 255.0)

# ------------------------------------------------------------------------------
# Base HTTP Client
# ------------------------------------------------------------------------------

_T = TypeVar("_T", bound=BaseModel)

class _BaseClient:
    def __init__(self, cfg: Optional[ClientConfig] = None, client: Optional[httpx.Client] = None) -> None:
        self.cfg = cfg or ClientConfig()
        self._ext_client = client
        self._headers_base = {
            "User-Agent": self.cfg.user_agent,
            "Accept": "application/json",
        }
        if self.cfg.bearer_token:
            self._headers_base["Authorization"] = f"Bearer {self.cfg.bearer_token}"
        elif self.cfg.api_key:
            self._headers_base["X-API-Key"] = self.cfg.api_key

        self._timeout = httpx.Timeout(self.cfg.timeout_seconds)
        self._verify = self.cfg.verify_tls
        self._cert = None
        if self.cfg.ca_bundle:
            self._verify = self.cfg.ca_bundle
        if self.cfg.client_cert and self.cfg.client_key:
            self._cert = (self.cfg.client_cert, self.cfg.client_key)

        self._tracer: Optional[Tracer] = trace.get_tracer(__name__) if trace else None

    # ---- Serialization helpers ----
    def _parse(self, model: Type[_T], data: Any) -> _T:
        if isinstance(data, model):
            return data
        return model.parse_obj(data)

    def _dump(self, model_or_dict: Union[BaseModel, Dict[str, Any]]) -> Dict[str, Any]:
        if isinstance(model_or_dict, BaseModel):
            return json.loads(model_or_dict.json(exclude_none=True))
        return model_or_dict

    # ---- Idempotency ----
    @staticmethod
    def _idem_key(provided: Optional[str]) -> str:
        return provided or str(uuid.uuid4())

    # ---- Headers merge ----
    def _headers(self, extra: Optional[Dict[str, str]] = None, idem_key: Optional[str] = None) -> Dict[str, str]:
        h = dict(self._headers_base)
        if idem_key:
            h["Idempotency-Key"] = idem_key
        if extra:
            h.update(extra)
        return h

# ------------------------------------------------------------------------------
# Sync Client
# ------------------------------------------------------------------------------

class DatafabricClient(_BaseClient):
    """
    Synchronous client.

    Usage:
        from datafabric_client import DatafabricClient, Dataset

        client = DatafabricClient()
        ds = client.catalog_create(Dataset(
            tenant_id="public", name="Purchases", type="STREAM"
        ))
        for item in client.catalog_list(tenant_id="public"):
            print(item.name)
    """

    def __init__(self, cfg: Optional[ClientConfig] = None, client: Optional[httpx.Client] = None) -> None:
        super().__init__(cfg, client)
        self._client = client or httpx.Client(
            base_url=str(self.cfg.base_url),
            timeout=self._timeout,
            headers=self._headers_base,
            verify=self._verify,
            cert=self._cert,
            http2=True,
        )

    def close(self) -> None:
        if self._ext_client is None:
            self._client.close()

    # Context manager
    def __enter__(self) -> "DatafabricClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ---- Core request with retries ----
    def _request(self, method: str, url: str, *, json_body: Optional[Dict[str, Any]] = None,
                 params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None,
                 idempotency_key: Optional[str] = None) -> httpx.Response:
        attempts = max(0, int(self.cfg.retries)) + 1
        final_exc: Optional[Exception] = None
        h = self._headers(headers, idempotency_key)

        if json_body is not None:
            raw = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
            if len(raw) > self.cfg.max_payload_bytes:
                raise ValueError("Payload too large")
        else:
            raw = None

        for attempt in range(1, attempts + 1):
            try:
                with self._span(method, url):
                    resp = self._client.request(method, url, params=params, content=raw, headers=h)
                _raise_for_status(resp)
                return resp
            except Exception as e:
                final_exc = e
                if not _is_retryable(e) or attempt >= attempts:
                    raise
                sleep_s = _sleep_backoff(attempt)
                LOG.warning("Retrying %s %s after error: %s (attempt %d/%d, sleep %.2fs)",
                            method, url, e, attempt, attempts, sleep_s)
                time.sleep(sleep_s)
        assert final_exc is not None
        raise final_exc

    @contextlib.contextmanager
    def _span(self, method: str, url: str):
        if not self._tracer:
            yield
            return
        with self._tracer.start_as_current_span(f"HTTP {method} {url}") as span:
            try:
                yield
            finally:
                pass

    # ------------------------------------------------------------------------------
    # Catalog methods
    # ------------------------------------------------------------------------------

    def catalog_create(self, dataset: Dataset) -> Dataset:
        body = self._dump(dataset)
        resp = self._request("POST", "/v1/stream/catalog/datasets", json_body=body,
                             idempotency_key=self._idem_key(dataset.labels.get("idem")) if self.cfg.idempotency_for_post else None)
        return self._parse(Dataset, resp.json())

    def catalog_get(self, dataset_id: str) -> Dataset:
        resp = self._request("GET", f"/v1/stream/catalog/datasets/{dataset_id}")
        return self._parse(Dataset, resp.json())

    def catalog_update(self, dataset: Dataset) -> Dataset:
        if not dataset.dataset_id:
            raise ValueError("dataset.dataset_id required for update")
        body = self._dump(dataset)
        resp = self._request("PUT", f"/v1/stream/catalog/datasets/{dataset.dataset_id}", json_body=body,
                             idempotency_key=self._idem_key(dataset.labels.get("idem")) if self.cfg.idempotency_for_post else None)
        return self._parse(Dataset, resp.json())

    def catalog_delete(self, dataset_id: str) -> bool:
        resp = self._request("DELETE", f"/v1/stream/catalog/datasets/{dataset_id}")
        return resp.status_code == 204 or bool(resp.json().get("success", False))

    def catalog_list(self, *, tenant_id: Optional[str] = None, page_size: int = 100) -> Iterator[Dataset]:
        token: Optional[str] = None
        while True:
            params = {"page_size": page_size}
            if token:
                params["page_token"] = token
            if tenant_id:
                params["tenant_id"] = tenant_id
            resp = self._request("GET", "/v1/stream/catalog/datasets", params=params)
            payload = resp.json()
            items = payload.get("datasets") or payload.get("items") or []
            for it in items:
                yield self._parse(Dataset, it)
            token = payload.get("next_page_token")
            if not token:
                break

    # ------------------------------------------------------------------------------
    # Ingest methods
    # ------------------------------------------------------------------------------

    def ingest_publish(self, events: List[IngestEvent], *,
                       priority: str = "NORMAL",
                       dedup_strategy: str = "EVENT_ID",
                       dedup_ttl_seconds: int = 86400,
                       idempotency_key: Optional[str] = None) -> PublishResult:
        body = {
            "events": [self._dump(e) for e in events],
            "priority": priority,
            "dedup": {"strategy": dedup_strategy, "ttl_seconds": dedup_ttl_seconds},
        }
        idem = self._idem_key(idempotency_key) if self.cfg.idempotency_for_post else None
        resp = self._request("POST", "/v1/data/ingest/publish", json_body=body, idempotency_key=idem)
        return self._parse(PublishResult, resp.json())

    # ------------------------------------------------------------------------------
    # Object storage helpers (presign-aware)
    # ------------------------------------------------------------------------------

    def object_get_presigned(self, bucket: str, key: str, *, method: str = "GET", ttl_seconds: int = 600) -> str:
        params = {"bucket": bucket, "key": key, "method": method, "ttl": ttl_seconds}
        resp = self._request("GET", "/v1/objects/presign", params=params)
        return str(resp.json()["url"])

# ------------------------------------------------------------------------------
# Async Client
# ------------------------------------------------------------------------------

class AsyncDatafabricClient(_BaseClient):
    """
    Asynchronous client.

    Usage:
        async with AsyncDatafabricClient() as client:
            async for ds in client.catalog_list(tenant_id="public"):
                print(ds.name)
    """

    def __init__(self, cfg: Optional[ClientConfig] = None, client: Optional[httpx.AsyncClient] = None) -> None:
        super().__init__(cfg, client)
        self._client = client or httpx.AsyncClient(
            base_url=str(self.cfg.base_url),
            timeout=self._timeout,
            headers=self._headers_base,
            verify=self._verify,
            cert=self._cert,
            http2=True,
        )

    async def aclose(self) -> None:
        if self._ext_client is None:
            await self._client.aclose()

    async def __aenter__(self) -> "AsyncDatafabricClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def _request(self, method: str, url: str, *, json_body: Optional[Dict[str, Any]] = None,
                       params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None,
                       idempotency_key: Optional[str] = None) -> httpx.Response:
        attempts = max(0, int(self.cfg.retries)) + 1
        final_exc: Optional[Exception] = None
        h = self._headers(headers, idempotency_key)

        if json_body is not None:
            raw = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
            if len(raw) > self.cfg.max_payload_bytes:
                raise ValueError("Payload too large")
        else:
            raw = None

        for attempt in range(1, attempts + 1):
            try:
                async with self._aspan(method, url):
                    resp = await self._client.request(method, url, params=params, content=raw, headers=h)
                _raise_for_status(resp)
                return resp
            except Exception as e:
                final_exc = e
                if not _is_retryable(e) or attempt >= attempts:
                    raise
                sleep_s = _sleep_backoff(attempt)
                LOG.warning("Retrying %s %s after error: %s (attempt %d/%d, sleep %.2fs)",
                            method, url, e, attempt, attempts, sleep_s)
                await _async_sleep(sleep_s)
        assert final_exc is not None
        raise final_exc

    @contextlib.asynccontextmanager
    async def _aspan(self, method: str, url: str):
        if not self._tracer:
            yield
            return
        with self._tracer.start_as_current_span(f"HTTP {method} {url}") as span:
            try:
                yield
            finally:
                pass

    # ---- Catalog ----
    async def catalog_create(self, dataset: Dataset) -> Dataset:
        body = self._dump(dataset)
        resp = await self._request("POST", "/v1/stream/catalog/datasets", json_body=body,
                                   idempotency_key=self._idem_key(dataset.labels.get("idem")) if self.cfg.idempotency_for_post else None)
        return self._parse(Dataset, resp.json())

    async def catalog_get(self, dataset_id: str) -> Dataset:
        resp = await self._request("GET", f"/v1/stream/catalog/datasets/{dataset_id}")
        return self._parse(Dataset, resp.json())

    async def catalog_update(self, dataset: Dataset) -> Dataset:
        if not dataset.dataset_id:
            raise ValueError("dataset.dataset_id required for update")
        body = self._dump(dataset)
        resp = await self._request("PUT", f"/v1/stream/catalog/datasets/{dataset.dataset_id}", json_body=body,
                                   idempotency_key=self._idem_key(dataset.labels.get("idem")) if self.cfg.idempotency_for_post else None)
        return self._parse(Dataset, resp.json())

    async def catalog_delete(self, dataset_id: str) -> bool:
        resp = await self._request("DELETE", f"/v1/stream/catalog/datasets/{dataset_id}")
        return resp.status_code == 204 or bool(resp.json().get("success", False))

    async def catalog_list(self, *, tenant_id: Optional[str] = None, page_size: int = 100) -> AsyncIterator[Dataset]:
        token: Optional[str] = None
        while True:
            params = {"page_size": page_size}
            if token:
                params["page_token"] = token
            if tenant_id:
                params["tenant_id"] = tenant_id
            resp = await self._request("GET", "/v1/stream/catalog/datasets", params=params)
            payload = resp.json()
            items = payload.get("datasets") or payload.get("items") or []
            for it in items:
                yield self._parse(Dataset, it)
            token = payload.get("next_page_token")
            if not token:
                break

    # ---- Ingest ----
    async def ingest_publish(self, events: List[IngestEvent], *,
                             priority: str = "NORMAL",
                             dedup_strategy: str = "EVENT_ID",
                             dedup_ttl_seconds: int = 86400,
                             idempotency_key: Optional[str] = None) -> PublishResult:
        body = {
            "events": [self._dump(e) for e in events],
            "priority": priority,
            "dedup": {"strategy": dedup_strategy, "ttl_seconds": dedup_ttl_seconds},
        }
        idem = self._idem_key(idempotency_key) if self.cfg.idempotency_for_post else None
        resp = await self._request("POST", "/v1/data/ingest/publish", json_body=body, idempotency_key=idem)
        return self._parse(PublishResult, resp.json())

# ------------------------------------------------------------------------------
# Async sleep helper
# ------------------------------------------------------------------------------

async def _async_sleep(seconds: float) -> None:
    # lightweight local awaitable to avoid importing asyncio at import-time if not needed
    import asyncio
    await asyncio.sleep(seconds)

# ------------------------------------------------------------------------------
# CLI utility (optional)
# ------------------------------------------------------------------------------

def _cli() -> int:
    import argparse
    p = argparse.ArgumentParser(prog="datafabric-client", description="DataFabric SDK CLI")
    p.add_argument("--base-url", default=os.getenv("DATAFABRIC_BASE_URL"))
    p.add_argument("--api-key", default=os.getenv("DATAFABRIC_API_KEY"))
    p.add_argument("--bearer", default=os.getenv("DATAFABRIC_BEARER_TOKEN"))
    sub = p.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("catalog-list")
    sc.add_argument("--tenant", default=None)
    sc.add_argument("--page-size", type=int, default=50)

    sp = sub.add_parser("ingest-publish")
    sp.add_argument("--tenant", required=True)
    sp.add_argument("--source", required=True)
    sp.add_argument("--schema-uri", required=True)
    sp.add_argument("--count", type=int, default=1)

    args = p.parse_args()
    cfg = ClientConfig(
        base_url=args.base_url or "https://api.example.org",
        api_key=args.api_key,
        bearer_token=args.bearer,
    )

    if args.cmd == "catalog-list":
        with DatafabricClient(cfg) as c:
            for ds in c.catalog_list(tenant_id=args.tenant, page_size=args.page_size):
                print(json.dumps(ds.dict(), ensure_ascii=False))
        return 0

    if args.cmd == "ingest-publish":
        evs = []
        for i in range(args.count):
            evs.append(IngestEvent(
                tenant_id=args.tenant,
                source=args.source,
                schema_uri=args.schema_uri,
                payload={"i": i, "msg": "hello"},
            ))
        with DatafabricClient(cfg) as c:
            res = c.ingest_publish(evs)
            print(json.dumps(res.dict(), ensure_ascii=False, indent=2))
        return 0

    return 1

if __name__ == "__main__":  # pragma: no cover
    sys.exit(_cli())
