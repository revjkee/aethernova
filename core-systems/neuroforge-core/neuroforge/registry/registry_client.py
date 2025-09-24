# file: neuroforge-core/neuroforge/registry/registry_client.py
from __future__ import annotations

import asyncio
import json
import logging
import random
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import (
    Any,
    AsyncGenerator,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

try:
    import httpx  # type: ignore
except Exception as e:  # pragma: no cover
    httpx = None  # type: ignore

logger = logging.getLogger(__name__)

# =============================================================================
# Конфигурация и утилиты
# =============================================================================

@dataclass(frozen=True)
class RetryConfig:
    max_attempts: int = 3
    base_delay_ms: int = 100
    max_delay_ms: int = 3000
    multiplier: float = 2.0
    jitter: float = 0.3  # 30% джиттер


@dataclass(frozen=True)
class CircuitBreakerConfig:
    failure_threshold: int = 5
    recovery_time_seconds: int = 30


@dataclass(frozen=True)
class ClientConfig:
    base_url: str = "https://api.neuroforge.example.com"
    api_key: Optional[str] = None        # альтернативно к Bearer
    bearer_token: Optional[str] = None   # предпочтительно
    tenant_id: Optional[str] = None
    # Таймауты/конкурентность
    timeout_seconds: float = 30.0
    connect_timeout_seconds: float = 3.0
    max_concurrency: int = 64
    # Поведение
    retry: RetryConfig = field(default_factory=RetryConfig)
    cb: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)
    # Ограничения
    default_page_limit: int = 100
    # Пользовательские заголовки
    default_headers: Mapping[str, str] = field(default_factory=dict)


def _jittered_backoff_seconds(attempt: int, cfg: RetryConfig) -> float:
    base = min(cfg.max_delay_ms / 1000.0, (cfg.base_delay_ms / 1000.0) * (cfg.multiplier ** (attempt - 1)))
    if cfg.jitter > 0:
        delta = base * cfg.jitter
        return random.uniform(max(0.0, base - delta), base + delta)
    return base


class _CircuitBreaker:
    def __init__(self, cfg: CircuitBreakerConfig) -> None:
        self.cfg = cfg
        self.failures = 0
        self.open_until = 0.0

    def allow(self) -> bool:
        if self.open_until == 0.0:
            return True
        if time.time() >= self.open_until:
            # полузакрытое: позволяем попытки и быстро закроем при успехе
            self.failures = max(0, self.cfg.failure_threshold - 1)
            self.open_until = 0.0
            return True
        return False

    def on_success(self) -> None:
        self.failures = 0
        self.open_until = 0.0

    def on_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.cfg.failure_threshold:
            self.open_until = time.time() + self.cfg.recovery_time_seconds


# =============================================================================
# Исключения SDK с маппингом HTTP
# =============================================================================

class ApiError(Exception):
    status: Optional[int] = None
    problem: Optional[Mapping[str, Any]] = None

    def __init__(self, message: str, status: Optional[int] = None, problem: Optional[Mapping[str, Any]] = None) -> None:
        super().__init__(message)
        self.status = status
        self.problem = problem or {}

class TransportError(ApiError): ...
class TimeoutError(ApiError): ...
class Unauthorized(ApiError): ...
class Forbidden(ApiError): ...
class NotFound(ApiError): ...
class Conflict(ApiError): ...
class TooManyRequests(ApiError): ...
class UnprocessableEntity(ApiError): ...
class ServerError(ApiError): ...
class Unavailable(ApiError): ...
class BadRequest(ApiError): ...


def _raise_for_status(status: int, body: bytes | str | None) -> None:
    text = ""
    if isinstance(body, bytes):
        text = body.decode("utf-8", "ignore")[:512]
    elif isinstance(body, str):
        text = body[:512]

    problem: Mapping[str, Any] = {}
    if text:
        try:
            problem = json.loads(text)
        except Exception:
            problem = {"detail": text}

    if status == 400:
        raise BadRequest("bad request", status, problem)
    if status == 401:
        raise Unauthorized("unauthorized", status, problem)
    if status == 403:
        raise Forbidden("forbidden", status, problem)
    if status == 404:
        raise NotFound("not found", status, problem)
    if status == 409:
        raise Conflict("conflict", status, problem)
    if status == 422:
        raise UnprocessableEntity("validation error", status, problem)
    if status == 429:
        raise TooManyRequests("rate limited", status, problem)
    if status in (500, 502, 503, 504):
        if status == 503:
            raise Unavailable("service unavailable", status, problem)
        raise ServerError("server error", status, problem)
    if status >= 400:
        raise ApiError(f"http {status}", status, problem)


# =============================================================================
# Модели (минимально необходимые типы)
# =============================================================================

@dataclass
class PageMeta:
    limit: int
    nextCursor: Optional[str] = None
    totalApprox: Optional[int] = None


@dataclass
class Dataset:
    id: str
    name: str
    source: str
    title: Optional[str] = None
    description: Optional[str] = None
    schemaRef: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)
    createdAt: Optional[str] = None
    updatedAt: Optional[str] = None


@dataclass
class DatasetCreate:
    name: str
    source: str
    title: Optional[str] = None
    description: Optional[str] = None
    schemaRef: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class DatasetPatch:
    title: Optional[str] = None
    description: Optional[str] = None
    schemaRef: Optional[str] = None
    tags: Optional[Dict[str, str]] = None


@dataclass
class Model:
    id: str
    name: str
    description: Optional[str] = None
    latestVersion: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)
    createdAt: Optional[str] = None
    updatedAt: Optional[str] = None


@dataclass
class ModelRegister:
    name: str
    description: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class ModelVersion:
    id: str
    version: str
    modelUri: str
    metrics: Dict[str, float] = field(default_factory=dict)
    labels: Dict[str, str] = field(default_factory=dict)
    createdAt: Optional[str] = None


@dataclass
class ModelVersionCreate:
    version: str
    modelUri: str
    metrics: Dict[str, float] = field(default_factory=dict)
    labels: Dict[str, str] = field(default_factory=dict)


@dataclass
class TrainingJob:
    id: str
    status: str
    datasetRef: str
    model: Dict[str, Any]
    createdAt: Optional[str] = None
    updatedAt: Optional[str] = None
    startedAt: Optional[str] = None
    finishedAt: Optional[str] = None
    lastError: Optional[str] = None
    metrics: Dict[str, float] = field(default_factory=dict)


@dataclass
class TrainingJobCreate:
    datasetRef: str
    model: Dict[str, str]
    hyperparams: Dict[str, str] = field(default_factory=dict)
    resources: Dict[str, Any] = field(default_factory=dict)
    webhooks: Dict[str, str] = field(default_factory=dict)


@dataclass
class PresignRequest:
    path: str
    operation: str = "put"  # "put"|"get"
    contentType: Optional[str] = None
    size: Optional[int] = None
    sha256: Optional[str] = None


@dataclass
class PresignResponse:
    url: str
    method: str
    headers: Dict[str, str] = field(default_factory=dict)
    expiresInSeconds: int = 0
    etag: Optional[str] = None


# =============================================================================
# Основной асинхронный клиент
# =============================================================================

class RegistryClient:
    """
    Асинхронный клиент Neuroforge Core API (datasets/models/jobs/artifacts/events).

    Пример:
        cfg = ClientConfig(base_url="https://api...", bearer_token="...", tenant_id="acme")
        async with RegistryClient(cfg) as client:
            ds = await client.create_dataset(DatasetCreate(name="qa_squad_dev", source="s3://..."))
            async for item in client.list_datasets_iter(q="domain:qa"):
                ...
    """

    def __init__(self, cfg: ClientConfig) -> None:
        if httpx is None:  # pragma: no cover
            raise RuntimeError("httpx is required")
        self.cfg = cfg
        self._client = httpx.AsyncClient(
            base_url=cfg.base_url.rstrip("/"),
            timeout=httpx.Timeout(cfg.timeout_seconds, connect=cfg.connect_timeout_seconds),
            limits=httpx.Limits(
                max_connections=cfg.max_concurrency,
                max_keepalive_connections=min(16, cfg.max_concurrency),
            ),
            headers=self._default_headers(),
        )
        self._sema = asyncio.Semaphore(cfg.max_concurrency)
        self._cb = _CircuitBreaker(cfg.cb)

    # ------------- lifecycle -------------

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "RegistryClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:  # type: ignore[override]
        await self.aclose()

    # ------------- headers -------------

    def _default_headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.cfg.bearer_token:
            h["Authorization"] = f"Bearer {self.cfg.bearer_token}"
        elif self.cfg.api_key:
            h["X-API-Key"] = self.cfg.api_key
        if self.cfg.tenant_id:
            h["X-Tenant-Id"] = self.cfg.tenant_id
        if self.cfg.default_headers:
            h.update(dict(self.cfg.default_headers))
        return h

    # ------------- core request -------------

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any | None = None,
        query: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        idempotent: bool = False,
        stream: bool = False,
    ) -> httpx.Response | AsyncGenerator[bytes, None]:
        if not self._cb.allow():
            raise Unavailable("circuit open")

        hdrs = dict(headers or {})
        # X-Request-Id — для трассировки
        hdrs.setdefault("X-Request-Id", str(uuid.uuid4()))
        if idempotent:
            hdrs.setdefault("Idempotency-Key", str(uuid.uuid4()))

        attempt = 0
        async with self._sema:
            while True:
                attempt += 1
                try:
                    if stream:
                        r = await self._client.stream(method, path, params=query, headers=hdrs, json=json_body)
                    else:
                        r = await self._client.request(method, path, params=query, headers=hdrs, json=json_body)

                    if r.status_code in (408,):  # Request Timeout
                        raise TimeoutError("request timeout", r.status_code)
                    if r.status_code in (429, 500, 502, 503, 504):
                        # retryable
                        body = await r.aread() if stream else r.content
                        _raise_for_status(r.status_code, body)  # кинет конкретное исключение
                    if r.status_code >= 400:
                        # non-retryable
                        body = await r.aread() if stream else r.content
                        _raise_for_status(r.status_code, body)
                    # success
                    self._cb.on_success()
                    if stream:
                        async def _agen() -> AsyncGenerator[bytes, None]:
                            async with r:
                                async for chunk in r.aiter_raw():
                                    if chunk:
                                        yield chunk
                        return _agen()
                    return r

                except (httpx.ReadTimeout, httpx.ConnectTimeout):
                    err: ApiError = TimeoutError("timeout")
                except (httpx.ReadError, httpx.RemoteProtocolError):
                    err = TransportError("transport error")
                except TooManyRequests as e:
                    err = e
                except ServerError as e:
                    err = e
                except Unavailable as e:
                    err = e
                except ApiError as e:
                    # другие ошибки — не ретраим
                    raise e
                except Exception as e:
                    err = TransportError(str(e))

                # retry branch
                self._cb.on_failure()
                if attempt >= max(1, self.cfg.retry.max_attempts):
                    raise err
                await asyncio.sleep(_jittered_backoff_seconds(attempt, self.cfg.retry))

    # ------------- datasets -------------

    async def create_dataset(self, payload: DatasetCreate, *, idempotency_key: Optional[str] = None) -> Dataset:
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        r = await self._request("POST", "/v1/datasets", json_body=asdict(payload), headers=headers, idempotent=True)
        data = r.json()
        return Dataset(**data)

    async def list_datasets(
        self, *, cursor: Optional[str] = None, limit: Optional[int] = None, q: Optional[str] = None, sort: Optional[str] = None
    ) -> Tuple[List[Dataset], PageMeta, Optional[str]]:
        params: Dict[str, Any] = {}
        if cursor:
            params["cursor"] = cursor
        params["limit"] = int(limit or self.cfg.default_page_limit)
        if q:
            params["q"] = q
        if sort:
            params["sort"] = sort
        r = await self._request("GET", "/v1/datasets", query=params)
        data = r.json()
        items = [Dataset(**x) for x in data.get("items", [])]
        meta_raw = data.get("meta", {}) or {}
        next_cursor = r.headers.get("X-Next-Cursor") or meta_raw.get("nextCursor")
        meta = PageMeta(limit=meta_raw.get("limit", params["limit"]), nextCursor=next_cursor, totalApprox=meta_raw.get("totalApprox"))
        return items, meta, next_cursor

    async def list_datasets_iter(
        self, *, limit: Optional[int] = None, q: Optional[str] = None, sort: Optional[str] = None
    ) -> AsyncGenerator[Dataset, None]:
        cursor: Optional[str] = None
        while True:
            items, _meta, cursor = await self.list_datasets(cursor=cursor, limit=limit, q=q, sort=sort)
            for it in items:
                yield it
            if not cursor:
                break

    async def get_dataset(self, dataset_id: str) -> Dataset:
        r = await self._request("GET", f"/v1/datasets/{dataset_id}")
        return Dataset(**r.json())

    async def patch_dataset(self, dataset_id: str, patch: DatasetPatch) -> Dataset:
        r = await self._request("PATCH", f"/v1/datasets/{dataset_id}", json_body={k: v for k, v in asdict(patch).items() if v is not None})
        return Dataset(**r.json())

    async def delete_dataset(self, dataset_id: str) -> None:
        await self._request("DELETE", f"/v1/datasets/{dataset_id}")

    # ------------- models -------------

    async def register_model(self, payload: ModelRegister, *, idempotency_key: Optional[str] = None) -> Model:
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        r = await self._request("POST", "/v1/models", json_body=asdict(payload), headers=headers, idempotent=True)
        return Model(**r.json())

    async def list_models(self, *, cursor: Optional[str] = None, limit: Optional[int] = None, q: Optional[str] = None) -> Tuple[List[Model], PageMeta, Optional[str]]:
        params: Dict[str, Any] = {}
        if cursor:
            params["cursor"] = cursor
        params["limit"] = int(limit or self.cfg.default_page_limit)
        if q:
            params["q"] = q
        r = await self._request("GET", "/v1/models", query=params)
        data = r.json()
        items = [Model(**x) for x in data.get("items", [])]
        meta_raw = data.get("meta", {}) or {}
        next_cursor = meta_raw.get("nextCursor")
        meta = PageMeta(limit=meta_raw.get("limit", params["limit"]), nextCursor=next_cursor, totalApprox=meta_raw.get("totalApprox"))
        return items, meta, next_cursor

    async def list_models_iter(self, *, limit: Optional[int] = None, q: Optional[str] = None) -> AsyncGenerator[Model, None]:
        cursor: Optional[str] = None
        while True:
            items, _meta, cursor = await self.list_models(cursor=cursor, limit=limit, q=q)
            for it in items:
                yield it
            if not cursor:
                break

    async def get_model(self, model_id: str) -> Model:
        r = await self._request("GET", f"/v1/models/{model_id}")
        return Model(**r.json())

    async def create_model_version(
        self, model_id: str, payload: ModelVersionCreate, *, idempotency_key: Optional[str] = None
    ) -> ModelVersion:
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        r = await self._request("POST", f"/v1/models/{model_id}/versions", json_body=asdict(payload), headers=headers, idempotent=True)
        return ModelVersion(**r.json())

    async def list_model_versions(
        self, model_id: str, *, cursor: Optional[str] = None, limit: Optional[int] = None
    ) -> Tuple[List[ModelVersion], PageMeta, Optional[str]]:
        params: Dict[str, Any] = {}
        if cursor:
            params["cursor"] = cursor
        params["limit"] = int(limit or self.cfg.default_page_limit)
        r = await self._request("GET", f"/v1/models/{model_id}/versions", query=params)
        data = r.json()
        items = [ModelVersion(**x) for x in data.get("items", [])]
        meta_raw = data.get("meta", {}) or {}
        next_cursor = meta_raw.get("nextCursor")
        meta = PageMeta(limit=meta_raw.get("limit", params["limit"]), nextCursor=next_cursor, totalApprox=meta_raw.get("totalApprox"))
        return items, meta, next_cursor

    async def list_model_versions_iter(self, model_id: str, *, limit: Optional[int] = None) -> AsyncGenerator[ModelVersion, None]:
        cursor: Optional[str] = None
        while True:
            items, _meta, cursor = await self.list_model_versions(model_id, cursor=cursor, limit=limit)
            for it in items:
                yield it
            if not cursor:
                break

    # ------------- training jobs -------------

    async def submit_training_job(self, payload: TrainingJobCreate, *, idempotency_key: Optional[str] = None) -> TrainingJob:
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        r = await self._request("POST", "/v1/jobs/training", json_body=asdict(payload), headers=headers, idempotent=True)
        return TrainingJob(**r.json())

    async def list_training_jobs(
        self, *, status: Optional[str] = None, cursor: Optional[str] = None, limit: Optional[int] = None
    ) -> Tuple[List[TrainingJob], PageMeta, Optional[str]]:
        params: Dict[str, Any] = {}
        if status:
            params["status"] = status
        if cursor:
            params["cursor"] = cursor
        params["limit"] = int(limit or self.cfg.default_page_limit)
        r = await self._request("GET", "/v1/jobs/training", query=params)
        data = r.json()
        items = [TrainingJob(**x) for x in data.get("items", [])]
        meta_raw = data.get("meta", {}) or {}
        next_cursor = meta_raw.get("nextCursor")
        meta = PageMeta(limit=meta_raw.get("limit", params["limit"]), nextCursor=next_cursor, totalApprox=meta_raw.get("totalApprox"))
        return items, meta, next_cursor

    async def list_training_jobs_iter(self, *, status: Optional[str] = None, limit: Optional[int] = None) -> AsyncGenerator[TrainingJob, None]:
        cursor: Optional[str] = None
        while True:
            items, _meta, cursor = await self.list_training_jobs(status=status, cursor=cursor, limit=limit)
            for it in items:
                yield it
            if not cursor:
                break

    async def get_training_job(self, job_id: str) -> TrainingJob:
        r = await self._request("GET", f"/v1/jobs/training/{job_id}")
        return TrainingJob(**r.json())

    async def cancel_training_job(self, job_id: str, *, idempotency_key: Optional[str] = None) -> None:
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        await self._request("POST", f"/v1/jobs/training/{job_id}:cancel", headers=headers, idempotent=True)

    async def get_training_events_page(
        self, job_id: str, *, cursor: Optional[str] = None, limit: Optional[int] = None
    ) -> Tuple[List[Mapping[str, Any]], Optional[str]]:
        params: Dict[str, Any] = {}
        if cursor:
            params["cursor"] = cursor
        params["limit"] = int(limit or self.cfg.default_page_limit)
        r = await self._request("GET", f"/v1/jobs/training/{job_id}/events", query=params)
        data = r.json()
        items = list(data.get("items", []))
        next_cursor = data.get("meta", {}).get("nextCursor")
        return items, next_cursor

    async def stream_training_events(self, job_id: str) -> AsyncGenerator[Mapping[str, Any], None]:
        """
        SSE-стрим: возвращает объекты событий (dict), взятые из data: {...}.
        """
        agen = await self._request("GET", f"/v1/jobs/training/{job_id}/events:stream", stream=True)
        assert callable(getattr(agen, "__aiter__", None))
        async for chunk in agen:  # type: ignore
            # Парсим text/event-stream; читаем построчно
            # chunk может содержать несколько строк
            try:
                text = chunk.decode("utf-8", "ignore")
            except Exception:
                continue
            for line in text.splitlines():
                line = line.strip()
                if not line or not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    return
                try:
                    obj = json.loads(data)
                    yield obj
                except Exception:
                    continue

    # ------------- artifacts presign -------------

    async def presign_artifact(self, req: PresignRequest, *, idempotency_key: Optional[str] = None) -> PresignResponse:
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        r = await self._request("POST", "/v1/artifacts/presign", json_body=asdict(req), headers=headers, idempotent=True)
        return PresignResponse(**r.json())

    # ------------- events ingest -------------

    async def ingest_training_event(self, event: Mapping[str, Any]) -> None:
        await self._request("POST", "/v1/events/training", json_body=dict(event))

    # ------------- health/info -------------

    async def healthz(self) -> Mapping[str, Any]:
        r = await self._request("GET", "/healthz")
        return r.json()

    async def livez(self) -> None:
        await self._request("GET", "/livez")

    async def info(self) -> Mapping[str, Any]:
        r = await self._request("GET", "/v1/info")
        return r.json()
