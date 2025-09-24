# cybersecurity-core/cybersecurity/adapters/engine_core_adapter.py
from __future__ import annotations

import abc
import asyncio
import contextlib
import hashlib
import hmac
import json
import logging
import os
import random
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    httpx = None  # type: ignore

from pydantic import BaseModel, Field, HttpUrl, ValidationError, ConfigDict

__all__ = [
    "Priority",
    "TaskStatus",
    "ErrorPayload",
    "EngineCommand",
    "EngineResponse",
    "HealthReport",
    "EngineCoreConfig",
    "EngineCoreAdapter",
    "HttpEngineCoreAdapter",
    "InMemoryEngineCoreAdapter",
    "build_adapter_from_env",
]

logger = logging.getLogger(__name__)


# ============================================================================
# Helpers
# ============================================================================

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid7() -> str:
    try:
        return str(uuid.uuid7())
    except AttributeError:
        return str(uuid.uuid4())


# ---- Reliability primitives ------------------------------------------------

class _TokenBucket:
    def __init__(self, rate_per_sec: float, capacity: Optional[float] = None) -> None:
        self.rate = max(0.001, rate_per_sec)
        self.capacity = capacity if capacity and capacity > 0 else max(1.0, self.rate * 2)
        self.tokens = self.capacity
        self.last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self.last
                self.last = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return
                await asyncio.sleep((tokens - self.tokens) / self.rate)


class _CBState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, reset_timeout: float = 30.0) -> None:
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.failures = 0
        self.state = _CBState.CLOSED
        self.opened_at: Optional[float] = None
        self._lock = asyncio.Lock()

    async def allow(self) -> None:
        async with self._lock:
            if self.state == _CBState.OPEN:
                assert self.opened_at is not None
                if time.monotonic() - self.opened_at >= self.reset_timeout:
                    self.state = _CBState.HALF_OPEN
                else:
                    raise RuntimeError("circuit_open")

    async def success(self) -> None:
        async with self._lock:
            self.failures = 0
            self.state = _CBState.CLOSED
            self.opened_at = None

    async def failure(self) -> None:
        async with self._lock:
            self.failures += 1
            if self.failures >= self.failure_threshold:
                self.state = _CBState.OPEN
                self.opened_at = time.monotonic()


async def _retry_async(
    op,
    *,
    retries: int,
    base_delay: float,
    max_delay: float,
    jitter: float = 0.2,
    retry_on: Tuple[type, ...] = (Exception,),
):
    attempt = 0
    while True:
        try:
            return await op()
        except retry_on as e:
            attempt += 1
            if attempt > retries:
                raise
            delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
            delay = delay * (1.0 + random.uniform(-jitter, jitter))
            await asyncio.sleep(max(0.001, delay))


# ============================================================================
# Domain contracts
# ============================================================================

class Priority(str, Enum):
    LOW = "LOW"
    NORMAL = "NORMAL"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TaskStatus(str, Enum):
    ACCEPTED = "ACCEPTED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELED = "CANCELED"
    UNKNOWN = "UNKNOWN"


class ErrorPayload(BaseModel):
    code: str = Field(..., examples=["bad_request", "unauthorized", "internal"])
    message: str
    details: Optional[Dict[str, Any]] = None


class EngineCommand(BaseModel):
    """
    Унифицированная команда для ядра движка (engine-core).
    """
    model_config = ConfigDict(extra="allow")

    name: str = Field(..., description="Уникальное имя/тип команды, например 'intel.normalize'")
    params: Dict[str, Any] = Field(default_factory=dict, description="Параметры команды")
    priority: Priority = Priority.NORMAL
    deadline: Optional[datetime] = Field(default=None, description="Дедлайн выполнения")
    tenant_id: Optional[str] = None
    source: Optional[str] = Field(default=None, description="Идентификатор источника/сервиса")
    tags: Sequence[str] = Field(default_factory=list)
    correlation_id: Optional[str] = None
    idempotency_key: Optional[str] = None

    def ensure_keys(self) -> None:
        if not self.correlation_id:
            self.correlation_id = _uuid7()
        if not self.idempotency_key:
            base = json.dumps(
                {"n": self.name, "p": self.params, "t": self.tenant_id, "d": str(self.deadline)},
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            self.idempotency_key = hashlib.sha256(base).hexdigest()


class EngineResponse(BaseModel):
    request_id: str = Field(..., description="Correlation/Request ID")
    task_id: Optional[str] = None
    status: TaskStatus
    result: Optional[Dict[str, Any]] = None
    error: Optional[ErrorPayload] = None
    received_at: datetime = Field(default_factory=_now)


class HealthReport(BaseModel):
    ok: bool
    detail: Dict[str, Any] = Field(default_factory=dict)
    checked_at: datetime = Field(default_factory=_now)


# ============================================================================
# Config
# ============================================================================

class EngineCoreConfig(BaseModel):
    """
    Конфиг адаптера движка.
    """
    base_url: Optional[HttpUrl] = Field(default=None, description="Базовый URL HTTP API движка")
    api_prefix: str = Field(default="/v1/engine")
    token_env: Optional[str] = Field(default="ENGINE_TOKEN")
    hmac_secret_env: Optional[str] = Field(default=None, description="ENV с секретом для HMAC-SHA256 подписи")
    verify_ssl: bool = True
    timeout_seconds: float = 15.0
    max_retries: int = 3
    backoff_base: float = 0.2
    backoff_max: float = 2.5
    rate_limit_per_sec: float = 20.0
    concurrent_requests: int = 16
    default_headers: Dict[str, str] = Field(default_factory=dict)


# ============================================================================
# Adapter interface
# ============================================================================

class EngineCoreAdapter(abc.ABC):
    @abc.abstractmethod
    async def submit_command(self, cmd: EngineCommand) -> EngineResponse: ...

    @abc.abstractmethod
    async def get_task(self, task_id: str, *, correlation_id: Optional[str] = None) -> EngineResponse: ...

    @abc.abstractmethod
    async def cancel_task(self, task_id: str, *, correlation_id: Optional[str] = None) -> EngineResponse: ...

    @abc.abstractmethod
    async def request_raw(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Tuple[int, Dict[str, Any], Dict[str, Any]]: ...

    @abc.abstractmethod
    async def health(self) -> HealthReport: ...

    @abc.abstractmethod
    async def aclose(self) -> None: ...


# ============================================================================
# HTTP implementation
# ============================================================================

class HttpEngineCoreAdapter(EngineCoreAdapter):
    """
    HTTP-адаптер с:
      - Bearer из ENV
      - HMAC-SHA256 подписью тела (X-Signed, X-Timestamp)
      - Idempotency-Key и X-Correlation-ID
      - rate-limit, retry, circuit-breaker
    """
    def __init__(self, cfg: EngineCoreConfig) -> None:
        if httpx is None:
            raise RuntimeError("httpx is required for HttpEngineCoreAdapter")
        if not cfg.base_url:
            raise ValueError("base_url is required for HTTP adapter")

        self.cfg = cfg
        self._rate = _TokenBucket(rate_per_sec=cfg.rate_limit_per_sec)
        self._cb = CircuitBreaker()
        self._sem = asyncio.Semaphore(cfg.concurrent_requests)

        headers: Dict[str, str] = {"Accept": "application/json"}
        headers.update(cfg.default_headers or {})
        token = os.getenv(cfg.token_env) if cfg.token_env else None
        if token:
            headers["Authorization"] = f"Bearer {token}"

        self._hmac_secret = os.getenv(cfg.hmac_secret_env) if cfg.hmac_secret_env else None

        self._client = httpx.AsyncClient(
            base_url=str(cfg.base_url),
            headers=headers,
            verify=cfg.verify_ssl,
            timeout=cfg.timeout_seconds,
        )

    # ---- public API --------------------------------------------------------

    async def submit_command(self, cmd: EngineCommand) -> EngineResponse:
        cmd.ensure_keys()
        path = f"{self.cfg.api_prefix}/commands"
        payload = cmd.model_dump()
        status_code, body, resp_headers = await self._request("POST", path, json_body=payload, correlation_id=cmd.correlation_id, idempotency_key=cmd.idempotency_key)
        return self._to_engine_response(status_code, body, correlation_id=cmd.correlation_id)

    async def get_task(self, task_id: str, *, correlation_id: Optional[str] = None) -> EngineResponse:
        cid = correlation_id or _uuid7()
        path = f"{self.cfg.api_prefix}/tasks/{task_id}"
        status_code, body, _ = await self._request("GET", path, correlation_id=cid)
        return self._to_engine_response(status_code, body, correlation_id=cid, task_id=task_id)

    async def cancel_task(self, task_id: str, *, correlation_id: Optional[str] = None) -> EngineResponse:
        cid = correlation_id or _uuid7()
        path = f"{self.cfg.api_prefix}/tasks/{task_id}"
        status_code, body, _ = await self._request("DELETE", path, correlation_id=cid)
        return self._to_engine_response(status_code, body, correlation_id=cid, task_id=task_id)

    async def request_raw(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Tuple[int, Dict[str, Any], Dict[str, Any]]:
        status_code, body, resp_headers = await self._request(method, path, json_body=json_body, extra_headers=dict(headers or {}))
        return status_code, body, resp_headers

    async def health(self) -> HealthReport:
        try:
            status_code, body, _ = await self._request("GET", f"{self.cfg.api_prefix}/health")
            ok = status_code == 200 and bool(body.get("ok", True))
            return HealthReport(ok=ok, detail=body or {})
        except Exception as e:  # pragma: no cover - network dependent
            logger.warning("engine.health_failed", extra={"error": str(e)})
            return HealthReport(ok=False, detail={"error": str(e)})

    async def aclose(self) -> None:
        with contextlib.suppress(Exception):
            await self._client.aclose()

    # ---- internals ---------------------------------------------------------

    def _hmac_headers(self, body_bytes: bytes) -> Dict[str, str]:
        if not self._hmac_secret:
            return {}
        ts = str(int(time.time()))
        sig = hmac.new(self._hmac_secret.encode("utf-8"), body_bytes + ts.encode("utf-8"), hashlib.sha256).hexdigest()
        return {"X-Signed": "HMAC-SHA256", "X-Timestamp": ts, "X-Signature": sig}

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        extra_headers: Optional[MutableMapping[str, str]] = None,
    ) -> Tuple[int, Dict[str, Any], Dict[str, Any]]:
        await self._rate.acquire()
        await self._cb.allow()

        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if correlation_id:
            headers["X-Correlation-ID"] = correlation_id
            headers["X-Request-ID"] = correlation_id
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        if extra_headers:
            headers.update(extra_headers)

        body_bytes = b""
        if json_body is not None:
            body_bytes = json.dumps(json_body, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
            headers.update(self._hmac_headers(body_bytes))

        async def _do():
            resp = await self._client.request(method.upper(), path, content=body_bytes if body_bytes else None, headers=headers)
            # Retry только на 5xx/сетевые
            if resp.status_code >= 500:
                raise RuntimeError(f"upstream_5xx:{resp.status_code}")
            return resp

        try:
            resp = await _retry_async(
                _do,
                retries=self.cfg.max_retries,
                base_delay=self.cfg.backoff_base,
                max_delay=self.cfg.backoff_max,
                retry_on=(httpx.TransportError, httpx.ReadTimeout, RuntimeError),
            )
            await self._cb.success()
        except Exception:
            await self._cb.failure()
            raise

        try:
            data = resp.json()
        except Exception:
            data = {}

        # Структурированное логирование
        logger.info(
            "engine.http",
            extra={
                "path": path,
                "code": resp.status_code,
                "cid": correlation_id,
                "len": len(body_bytes) if body_bytes else 0,
            },
        )
        return resp.status_code, data or {}, dict(resp.headers or {})

    @staticmethod
    def _to_engine_response(
        status_code: int,
        body: Dict[str, Any],
        *,
        correlation_id: Optional[str],
        task_id: Optional[str] = None,
    ) -> EngineResponse:
        # Унифицированные правила маппинга
        status_map: Dict[int, TaskStatus] = {
            200: TaskStatus.COMPLETED,
            201: TaskStatus.ACCEPTED,
            202: TaskStatus.ACCEPTED,
            204: TaskStatus.COMPLETED,
            400: TaskStatus.FAILED,
            401: TaskStatus.FAILED,
            403: TaskStatus.FAILED,
            404: TaskStatus.UNKNOWN,
            409: TaskStatus.FAILED,
            422: TaskStatus.FAILED,
            429: TaskStatus.FAILED,
            499: TaskStatus.FAILED,
            500: TaskStatus.FAILED,
            502: TaskStatus.FAILED,
            503: TaskStatus.FAILED,
            504: TaskStatus.FAILED,
        }
        status = status_map.get(status_code, TaskStatus.UNKNOWN)

        # Возможные ключи тела от разных реализаций
        err = None
        if "error" in body and isinstance(body["error"], dict):
            try:
                err = ErrorPayload(**body["error"])
            except ValidationError:
                err = ErrorPayload(code="error", message=str(body.get("error")), details={"raw": body.get("error")})
        elif status not in (TaskStatus.ACCEPTED, TaskStatus.RUNNING, TaskStatus.COMPLETED) and body:
            err = ErrorPayload(code="error", message=json.dumps(body, ensure_ascii=False)[:512])

        result = None
        # Популярные поля контрактов
        for key in ("result", "data", "payload"):
            if key in body:
                if isinstance(body[key], dict):
                    result = body[key]
                else:
                    result = {"value": body[key]}
                break

        tid = task_id or body.get("task_id") or body.get("id") or body.get("job_id")

        # Специальные статусы
        body_status = str(body.get("status") or "").upper()
        if body_status in TaskStatus.__members__:
            status = TaskStatus[body_status]

        return EngineResponse(
            request_id=correlation_id or body.get("correlation_id") or _uuid7(),
            task_id=str(tid) if tid else None,
            status=status,
            result=result,
            error=err,
        )


# ============================================================================
# In-memory implementation (for tests and local dev)
# ============================================================================

@dataclass
class _Task:
    status: TaskStatus
    created_at: datetime
    result: Optional[Dict[str, Any]] = None
    error: Optional[ErrorPayload] = None


class InMemoryEngineCoreAdapter(EngineCoreAdapter):
    """
    Простая in-memory реализация для локальной разработки и тестов.
    """
    def __init__(self) -> None:
        self._tasks: Dict[str, _Task] = {}
        self._lock = asyncio.Lock()

    async def submit_command(self, cmd: EngineCommand) -> EngineResponse:
        cmd.ensure_keys()
        async with self._lock:
            tid = _uuid7()
            # имитируем очередь и быстрый переход в RUNNING
            self._tasks[tid] = _Task(status=TaskStatus.ACCEPTED, created_at=_now())
        # Небольшая симуляция
        asyncio.create_task(self._transition(tid))
        return EngineResponse(request_id=cmd.correlation_id or _uuid7(), task_id=tid, status=TaskStatus.ACCEPTED, result={"queued": True})

    async def _transition(self, tid: str) -> None:
        await asyncio.sleep(0.01)
        async with self._lock:
            t = self._tasks.get(tid)
            if not t:
                return
            t.status = TaskStatus.RUNNING
        await asyncio.sleep(0.02)
        async with self._lock:
            t = self._tasks.get(tid)
            if not t:
                return
            t.status = TaskStatus.COMPLETED
            t.result = {"ok": True}

    async def get_task(self, task_id: str, *, correlation_id: Optional[str] = None) -> EngineResponse:
        async with self._lock:
            t = self._tasks.get(task_id)
            if not t:
                return EngineResponse(request_id=correlation_id or _uuid7(), task_id=task_id, status=TaskStatus.UNKNOWN, error=ErrorPayload(code="not_found", message="Task not found"))
            return EngineResponse(request_id=correlation_id or _uuid7(), task_id=task_id, status=t.status, result=t.result, error=t.error)

    async def cancel_task(self, task_id: str, *, correlation_id: Optional[str] = None) -> EngineResponse:
        async with self._lock:
            t = self._tasks.get(task_id)
            if not t:
                return EngineResponse(request_id=correlation_id or _uuid7(), task_id=task_id, status=TaskStatus.UNKNOWN, error=ErrorPayload(code="not_found", message="Task not found"))
            if t.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELED):
                return EngineResponse(request_id=correlation_id or _uuid7(), task_id=task_id, status=t.status, result=t.result, error=t.error)
            t.status = TaskStatus.CANCELED
            return EngineResponse(request_id=correlation_id or _uuid7(), task_id=task_id, status=TaskStatus.CANCELED, result={"canceled": True})

    async def request_raw(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Tuple[int, Dict[str, Any], Dict[str, Any]]:
        # эхо для дебага
        return 200, {"method": method, "path": path, "json": json_body or {}, "headers": dict(headers or {})}, {}

    async def health(self) -> HealthReport:
        return HealthReport(ok=True, detail={"inmemory": True})

    async def aclose(self) -> None:
        return None


# ============================================================================
# Factory
# ============================================================================

def build_adapter_from_env(prefix: str = "ENGINE_") -> EngineCoreAdapter:
    """
    Пример переменных окружения:
      ENGINE_PROVIDER=http|memory
      ENGINE_BASE_URL=https://engine.example.com
      ENGINE_API_PREFIX=/v1/engine
      ENGINE_TOKEN=... (если token_env=ENGINE_TOKEN)
      ENGINE_HMAC_SECRET_ENV=ENGINE_HMAC_SECRET
      ENGINE_VERIFY_SSL=true
      ENGINE_TIMEOUT=15
      ENGINE_RATELIMIT=20
    """
    provider = os.getenv(f"{prefix}PROVIDER", "http").lower()

    if provider in ("mem", "memory", "inmemory"):
        return InMemoryEngineCoreAdapter()

    base_url = os.getenv(f"{prefix}BASE_URL")
    api_prefix = os.getenv(f"{prefix}API_PREFIX", "/v1/engine")
    token_env = os.getenv(f"{prefix}TOKEN_ENV", "ENGINE_TOKEN")
    hmac_env = os.getenv(f"{prefix}HMAC_SECRET_ENV")
    verify_ssl = os.getenv(f"{prefix}VERIFY_SSL", "true").lower() == "true"
    timeout = float(os.getenv(f"{prefix}TIMEOUT", "15"))
    retries = int(os.getenv(f"{prefix}RETRIES", "3"))
    backoff_base = float(os.getenv(f"{prefix}BACKOFF_BASE", "0.2"))
    backoff_max = float(os.getenv(f"{prefix}BACKOFF_MAX", "2.5"))
    ratelimit = float(os.getenv(f"{prefix}RATELIMIT", "20"))
    concurrency = int(os.getenv(f"{prefix}CONCURRENCY", "16"))

    cfg = EngineCoreConfig(
        base_url=base_url,
        api_prefix=api_prefix,
        token_env=token_env,
        hmac_secret_env=hmac_env,
        verify_ssl=verify_ssl,
        timeout_seconds=timeout,
        max_retries=retries,
        backoff_base=backoff_base,
        backoff_max=backoff_max,
        rate_limit_per_sec=ratelimit,
        concurrent_requests=concurrency,
    )
    return HttpEngineCoreAdapter(cfg)


# ============================================================================
# Self-test (optional)
# ============================================================================

async def _selftest() -> None:  # pragma: no cover - utility
    adapter = InMemoryEngineCoreAdapter()
    cmd = EngineCommand(name="intel.normalize", params={"value": "8.8.8.8"}, priority=Priority.HIGH, source="selftest")
    r = await adapter.submit_command(cmd)
    logger.info("submit", extra={"resp": r.model_dump()})
    if r.task_id:
        s1 = await adapter.get_task(r.task_id)
        s2 = await adapter.get_task(r.task_id)
        c = await adapter.cancel_task(r.task_id)
        logger.info("status1", extra={"resp": s1.model_dump()})
        logger.info("status2", extra={"resp": s2.model_dump()})
        logger.info("cancel", extra={"resp": c.model_dump()})
    h = await adapter.health()
    logger.info("health", extra={"ok": h.ok})

if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    asyncio.run(_selftest())
