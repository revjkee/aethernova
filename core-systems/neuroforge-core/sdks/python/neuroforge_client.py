# neuroforge-core/sdks/python/neuroforge_client.py
"""
Neuroforge Python SDK (production-grade).

Requirements:
  - python >= 3.9
  - httpx >= 0.24
Optional:
  - opentelemetry-api >= 1.23 (auto-tracing if present)

Features:
  - Sync and Async clients (context managers)
  - API key or Bearer token auth
  - Timeouts, retries with exponential backoff + jitter, respect Retry-After
  - Simple circuit breaker to protect backend on persistent failures
  - Idempotency via Idempotency-Key
  - Pagination iterators
  - Streaming logs/metrics (NDJSON or chunked lines)
  - Chunked artifact uploads
  - Structured exceptions with response context
  - Correlation and Request-ID headers
  - Optional OpenTelemetry spans (inject trace headers)
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, AsyncIterator, Callable, Dict, Generator, Iterable, Iterator, List, Literal, Optional, Tuple, Union, overload

try:
    import httpx  # type: ignore
except Exception as exc:  # pragma: no cover
    raise ImportError("neuroforge_client requires httpx. Install with: pip install httpx") from exc

# Optional OpenTelemetry
try:
    from opentelemetry import trace  # type: ignore
    from opentelemetry.trace.status import Status, StatusCode  # type: ignore
    _otel_available = True
except Exception:  # pragma: no cover
    _otel_available = False

__all__ = [
    "NeuroforgeClient",
    "AsyncNeuroforgeClient",
    "NeuroforgeError",
    "NetworkError",
    "AuthError",
    "NotFoundError",
    "ConflictError",
    "RateLimitError",
    "ServerError",
    "APIError",
    "SubmitTrainingJobResponse",
    "TrainingJob",
]

# -----------------------------
# Logging
# -----------------------------
logger = logging.getLogger("neuroforge.client")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s neuroforge %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


# -----------------------------
# Exceptions
# -----------------------------
class NeuroforgeError(Exception):
    """Base SDK error."""


class NetworkError(NeuroforgeError):
    """Transport-level error."""


class AuthError(NeuroforgeError):
    """Authentication/authorization failure."""


class NotFoundError(NeuroforgeError):
    """404 Not Found."""


class ConflictError(NeuroforgeError):
    """409 Conflict / Precondition failed."""


class RateLimitError(NeuroforgeError):
    """429 Too Many Requests."""

    def __init__(self, message: str, retry_after: Optional[float] = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class ServerError(NeuroforgeError):
    """5xx."""


class APIError(NeuroforgeError):
    """Other API error with details."""

    def __init__(self, status_code: int, code: Optional[str], message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(f"{status_code} {code or ''} {message}".strip())
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details or {}


# -----------------------------
# Models (lightweight)
# -----------------------------
@dataclass(frozen=True)
class TrainingJob:
    name: str
    state: str
    priority: Optional[str] = None
    etag: Optional[str] = None
    create_time: Optional[str] = None
    update_time: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    error: Optional[Dict[str, Any]] = None
    final_metrics: Optional[Dict[str, float]] = None

    @staticmethod
    def from_json(data: Dict[str, Any]) -> "TrainingJob":
        return TrainingJob(
            name=data.get("name", ""),
            state=data.get("state", ""),
            priority=data.get("priority"),
            etag=data.get("etag"),
            create_time=data.get("create_time"),
            update_time=data.get("update_time"),
            start_time=data.get("start_time"),
            end_time=data.get("end_time"),
            error=data.get("error"),
            final_metrics=data.get("final_metrics"),
        )


@dataclass(frozen=True)
class SubmitTrainingJobResponse:
    job: TrainingJob

    @staticmethod
    def from_json(data: Dict[str, Any]) -> "SubmitTrainingJobResponse":
        return SubmitTrainingJobResponse(job=TrainingJob.from_json(data.get("job", {})))


# -----------------------------
# Helpers
# -----------------------------
def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _uuid() -> str:
    return str(uuid.uuid4())


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    try:
        # seconds or HTTP-date; here we support seconds
        return float(value)
    except Exception:
        return None


def _backoff_delay(attempt: int, base: float, cap: float, jitter: float) -> float:
    # exponential backoff with full jitter
    import random
    exp = min(cap, base * (2 ** (attempt - 1)))
    return random.uniform(0, exp * jitter + (exp * (1 - jitter)))


def _default_user_agent() -> str:
    return f"neuroforge-python-sdk/1.0 httpx/{getattr(httpx, '__version__', 'unknown')}"


# -----------------------------
# Circuit breaker (simple)
# -----------------------------
@dataclass
class _Circuit:
    failures: int = 0
    opened_at: float = 0.0
    open_window_s: float = 10.0
    failure_threshold: int = 5

    def allow(self) -> bool:
        if self.failures < self.failure_threshold:
            return True
        # open
        if time.time() - self.opened_at > self.open_window_s:
            # half-open
            return True
        return False

    def record_success(self) -> None:
        self.failures = 0
        self.opened_at = 0.0

    def record_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.failure_threshold:
            self.opened_at = time.time()


# -----------------------------
# Base config
# -----------------------------
@dataclass(frozen=True)
class _Config:
    base_url: str
    api_key: Optional[str]
    bearer_token: Optional[str]
    timeout_s: float
    max_retries: int
    backoff_base_s: float
    backoff_cap_s: float
    backoff_jitter: float
    user_agent: str
    x_request_id: Optional[str]
    telemetry: bool
    otel_service_name: Optional[str]
    default_headers: Dict[str, str]
    idempotency_header: str = "Idempotency-Key"
    request_id_header: str = "X-Request-ID"
    correlation_header: str = "X-Correlation-ID"

    @staticmethod
    def from_env(
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        bearer_token: Optional[str] = None,
        timeout_s: Optional[float] = None,
        max_retries: Optional[int] = None,
        telemetry: Optional[bool] = None,
    ) -> "_Config":
        return _Config(
            base_url=base_url or os.getenv("NEUROFORGE_BASE_URL", "http://localhost:8080/v1"),
            api_key=api_key or os.getenv("NEUROFORGE_API_KEY"),
            bearer_token=bearer_token or os.getenv("NEUROFORGE_BEARER_TOKEN"),
            timeout_s=timeout_s or float(os.getenv("NEUROFORGE_TIMEOUT_S", "15")),
            max_retries=max_retries or int(os.getenv("NEUROFORGE_MAX_RETRIES", "3")),
            backoff_base_s=float(os.getenv("NEUROFORGE_BACKOFF_BASE_S", "0.2")),
            backoff_cap_s=float(os.getenv("NEUROFORGE_BACKOFF_CAP_S", "2.0")),
            backoff_jitter=float(os.getenv("NEUROFORGE_BACKOFF_JITTER", "0.8")),
            user_agent=os.getenv("NEUROFORGE_USER_AGENT", _default_user_agent()),
            x_request_id=os.getenv("NEUROFORGE_REQUEST_ID"),
            telemetry=bool(str(os.getenv("NEUROFORGE_TELEMETRY", "true")).lower() in ("1", "true", "yes")),
            otel_service_name=os.getenv("NEUROFORGE_OTEL_SERVICE_NAME"),
            default_headers={},
        )


# -----------------------------
# HTTP core
# -----------------------------
class _HttpCore:
    def __init__(self, cfg: _Config, client: Union[httpx.Client, httpx.AsyncClient], is_async: bool) -> None:
        self._cfg = cfg
        self._client = client
        self._is_async = is_async
        self._circuit = _Circuit()

    def _auth_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if self._cfg.api_key:
            headers["X-API-Key"] = self._cfg.api_key
        if self._cfg.bearer_token:
            headers["Authorization"] = f"Bearer {self._cfg.bearer_token}"
        return headers

    def _telemetry_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if self._cfg.x_request_id:
            headers[self._cfg.request_id_header] = self._cfg.x_request_id
        headers["User-Agent"] = self._cfg.user_agent
        # Correlation header can be provided by caller per request
        return headers

    async def _async_send(self, req: httpx.Request) -> httpx.Response:
        return await self._client.send(req, stream=req.stream is not None)

    def _sync_send(self, req: httpx.Request) -> httpx.Response:
        return self._client.send(req, stream=req.stream is not None)

    def _build_request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        content: Optional[Union[bytes, Iterable[bytes]]] = None,
        timeout: Optional[float] = None,
        idempotency_key: Optional[str] = None,
        correlation_id: Optional[str] = None,
        stream: bool = False,
    ) -> httpx.Request:
        hdrs: Dict[str, str] = {}
        hdrs.update(self._cfg.default_headers)
        hdrs.update(self._auth_headers())
        hdrs.update(self._telemetry_headers())
        if correlation_id:
            hdrs[self._cfg.correlation_header] = correlation_id
        if idempotency_key:
            hdrs[self._cfg.idempotency_header] = idempotency_key

        req = self._client.build_request(
            method=method,
            url=url,
            params=params or None,
            headers=hdrs if headers is None else {**hdrs, **headers},
            json=json_body,
            content=content,
            timeout=timeout or self._cfg.timeout_s,
        )
        req.stream = stream  # type: ignore[attr-defined]
        return req

    def _raise_for_status(self, resp: httpx.Response) -> None:
        sc = resp.status_code
        if 200 <= sc < 300:
            return
        text = ""
        code = None
        details = None
        try:
            payload = resp.json()
            code = payload.get("code")
            text = payload.get("message") or payload.get("error") or resp.text
            details = payload.get("details")
        except Exception:
            text = resp.text

        if sc in (401, 403):
            raise AuthError(text or "Unauthorized")
        if sc == 404:
            raise NotFoundError(text or "Not found")
        if sc in (409, 412):
            raise ConflictError(text or "Conflict")
        if sc == 429:
            raise RateLimitError(text or "Rate limited", retry_after=_parse_retry_after(resp.headers.get("Retry-After")))
        if 500 <= sc:
            raise ServerError(text or "Server error")
        raise APIError(sc, code, text or "API error", details)

    def _otel_span(self, name: str):
        if not self._cfg.telemetry or not _otel_available:
            class _Noop:
                def __enter__(self): return self
                def __exit__(self, exc_type, exc, tb): return False
                def set_status(self, *_args, **_kwargs): pass
                def set_attribute(self, *_args, **_kwargs): pass
            return _Noop()
        tracer = trace.get_tracer(self._cfg.otel_service_name or "neuroforge.client")
        return tracer.start_as_current_span(name)

    def _should_retry(self, method: str, err: Exception, resp: Optional[httpx.Response]) -> Tuple[bool, Optional[float]]:
        # Retry for network and 5xx and 429; also 409 if idempotent.
        if isinstance(err, (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteError, httpx.NetworkError)):
            return True, None
        if resp is not None:
            if resp.status_code in (500, 502, 503, 504):
                return True, _parse_retry_after(resp.headers.get("Retry-After"))
            if resp.status_code == 429:
                return True, _parse_retry_after(resp.headers.get("Retry-After"))
            if resp.status_code in (409, 412) and method.upper() in ("GET", "HEAD"):
                return True, None
        return False, None

    def _compose_url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        base = self._cfg.base_url.rstrip("/")
        return f"{base}/{path.lstrip('/')}"

    # Core request with retries and circuit breaker
    def _request(
        self,
        method: str,
        path: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        content: Optional[Union[bytes, Iterable[bytes]]] = None,
        timeout: Optional[float] = None,
        idempotency_key: Optional[str] = None,
        correlation_id: Optional[str] = None,
        stream: bool = False,
    ) -> httpx.Response:
        if not self._circuit.allow():
            raise ServerError("Circuit breaker open")
        url = self._compose_url(path)
        attempt = 0
        last_exc: Optional[Exception] = None
        with self._otel_span("neuroforge.request") as span:
            while True:
                attempt += 1
                req = self._build_request(
                    method, url, headers=headers, params=params, json_body=json_body,
                    content=content, timeout=timeout, idempotency_key=idempotency_key,
                    correlation_id=correlation_id, stream=stream
                )
                try:
                    resp = self._sync_send(req)
                    if 200 <= resp.status_code < 300:
                        self._circuit.record_success()
                        if _otel_available and span:
                            span.set_attribute("http.status_code", resp.status_code)
                        return resp
                    retry, ra = self._should_retry(method, Exception("status"), resp)
                    if not retry or attempt > self._cfg.max_retries:
                        self._circuit.record_failure()
                        self._raise_for_status(resp)
                    delay = ra if ra is not None else _backoff_delay(attempt, self._cfg.backoff_base_s, self._cfg.backoff_cap_s, self._cfg.backoff_jitter)
                    time.sleep(delay)
                except httpx.TimeoutException as e:
                    last_exc = e
                    if attempt > self._cfg.max_retries:
                        self._circuit.record_failure()
                        raise NetworkError(f"Timeout: {e}") from e
                    time.sleep(_backoff_delay(attempt, self._cfg.backoff_base_s, self._cfg.backoff_cap_s, self._cfg.backoff_jitter))
                except httpx.HTTPError as e:
                    last_exc = e
                    if attempt > self._cfg.max_retries:
                        self._circuit.record_failure()
                        raise NetworkError(str(e)) from e
                    time.sleep(_backoff_delay(attempt, self._cfg.backoff_base_s, self._cfg.backoff_cap_s, self._cfg.backoff_jitter))
                except Exception as e:
                    self._circuit.record_failure()
                    if _otel_available and span:
                        span.set_status(Status(StatusCode.ERROR, description=str(e)))
                    raise
        # Should never hit
        raise NetworkError(str(last_exc or "Request failed"))

    async def _request_async(
        self,
        method: str,
        path: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        content: Optional[Union[bytes, AsyncIterator[bytes], Iterable[bytes]]] = None,
        timeout: Optional[float] = None,
        idempotency_key: Optional[str] = None,
        correlation_id: Optional[str] = None,
        stream: bool = False,
    ) -> httpx.Response:
        if not self._circuit.allow():
            raise ServerError("Circuit breaker open")
        url = self._compose_url(path)
        attempt = 0
        last_exc: Optional[Exception] = None
        # httpx AsyncClient supports async generator as content
        with self._otel_span("neuroforge.request") as span:
            while True:
                attempt += 1
                req = self._client.build_request(
                    method=method,
                    url=url,
                    params=params or None,
                    headers=(lambda: {**self._cfg.default_headers, **self._auth_headers(), **self._telemetry_headers(), **(headers or {})})(),
                    json=json_body,
                    content=content,
                    timeout=timeout or self._cfg.timeout_s,
                )
                req.stream = stream  # type: ignore[attr-defined]
                try:
                    resp = await self._async_send(req)
                    if 200 <= resp.status_code < 300:
                        self._circuit.record_success()
                        if _otel_available and span:
                            span.set_attribute("http.status_code", resp.status_code)
                        return resp
                    retry, ra = self._should_retry(method, Exception("status"), resp)
                    if not retry or attempt > self._cfg.max_retries:
                        self._circuit.record_failure()
                        self._raise_for_status(resp)
                    delay = ra if ra is not None else _backoff_delay(attempt, self._cfg.backoff_base_s, self._cfg.backoff_cap_s, self._cfg.backoff_jitter)
                    await asyncio.sleep(delay)
                except httpx.TimeoutException as e:
                    last_exc = e
                    if attempt > self._cfg.max_retries:
                        self._circuit.record_failure()
                        raise NetworkError(f"Timeout: {e}") from e
                    await asyncio.sleep(_backoff_delay(attempt, self._cfg.backoff_base_s, self._cfg.backoff_cap_s, self._cfg.backoff_jitter))
                except httpx.HTTPError as e:
                    last_exc = e
                    if attempt > self._cfg.max_retries:
                        self._circuit.record_failure()
                        raise NetworkError(str(e)) from e
                    await asyncio.sleep(_backoff_delay(attempt, self._cfg.backoff_base_s, self._cfg.backoff_cap_s, self._cfg.backoff_jitter))
                except Exception as e:
                    self._circuit.record_failure()
                    if _otel_available and span:
                        span.set_status(Status(StatusCode.ERROR, description=str(e)))
                    raise
        raise NetworkError(str(last_exc or "Request failed"))


# -----------------------------
# Public Client (sync)
# -----------------------------
class NeuroforgeClient:
    """
    Synchronous client.

    Example:
        from neuroforge_client import NeuroforgeClient

        with NeuroforgeClient(base_url="https://api.neuroforge.example/v1", api_key="...") as nf:
            job_spec = {...}
            resp = nf.submit_training_job(job_spec)
            print(resp.job.name)
    """

    def __init__(
        self,
        *,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        bearer_token: Optional[str] = None,
        timeout_s: Optional[float] = None,
        max_retries: Optional[int] = None,
        telemetry: Optional[bool] = None,
        default_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        cfg = _Config.from_env(base_url, api_key, bearer_token, timeout_s, max_retries, telemetry)
        if default_headers:
            cfg = dataclasses.replace(cfg, default_headers={**cfg.default_headers, **default_headers})
        self._client = httpx.Client(timeout=cfg.timeout_s)
        self._core = _HttpCore(cfg, self._client, is_async=False)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "NeuroforgeClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ------------- API methods -------------

    def submit_training_job(
        self,
        job: Dict[str, Any],
        *,
        validate_only: bool = False,
        idempotency_key: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> SubmitTrainingJobResponse:
        payload = {
            "idempotency_key": idempotency_key or _uuid(),
            "correlation_id": correlation_id or _uuid(),
            "validate_only": validate_only,
            "job": job,
        }
        resp = self._core._request("POST", "trainingJobs:submit", json_body=payload, idempotency_key=payload["idempotency_key"], correlation_id=payload["correlation_id"])
        data = resp.json()
        return SubmitTrainingJobResponse.from_json(data)

    def get_training_job(self, name: str) -> TrainingJob:
        resp = self._core._request("GET", f"trainingJobs/{name}")
        return TrainingJob.from_json(resp.json())

    def cancel_training_job(self, name: str, *, reason: str = "", etag: Optional[str] = None) -> TrainingJob:
        payload = {"name": name, "reason": reason}
        if etag:
            payload["etag"] = etag
        resp = self._core._request("POST", f"trainingJobs/{name}:cancel", json_body=payload, idempotency_key=_uuid())
        return TrainingJob.from_json(resp.json())

    def list_training_jobs(self, *, filter: str = "", page_size: int = 50) -> Iterator[TrainingJob]:
        token: Optional[str] = None
        while True:
            params = {"filter": filter, "page_size": page_size}
            if token:
                params["page_token"] = token
            resp = self._core._request("GET", "trainingJobs", params=params)
            data = resp.json()
            for j in data.get("jobs", []):
                yield TrainingJob.from_json(j)
            token = data.get("next_page_token")
            if not token:
                break

    def stream_logs(self, name: str, *, since_time: Optional[datetime] = None, min_level: Optional[str] = None) -> Iterator[Dict[str, Any]]:
        params: Dict[str, Any] = {}
        if since_time:
            params["since_time"] = since_time.astimezone(timezone.utc).isoformat()
        if min_level:
            params["min_level"] = min_level
        resp = self._core._request("GET", f"trainingJobs/{name}:logs", params=params, timeout=self._core._cfg.timeout_s, stream=True)
        try:
            for line in resp.iter_lines():
                if not line:
                    continue
                try:
                    yield json.loads(line.decode("utf-8"))
                except Exception:
                    yield {"time": _now_utc_iso(), "level": "INFO", "message": line.decode("utf-8")}
        finally:
            resp.close()

    def stream_metrics(self, name: str, *, since_time: Optional[datetime] = None) -> Iterator[Dict[str, Any]]:
        params: Dict[str, Any] = {}
        if since_time:
            params["since_time"] = since_time.astimezone(timezone.utc).isoformat()
        resp = self._core._request("GET", f"trainingJobs/{name}:metrics", params=params, stream=True)
        try:
            for line in resp.iter_lines():
                if not line:
                    continue
                yield json.loads(line.decode("utf-8"))
        finally:
            resp.close()

    def upload_artifact(
        self,
        parent: str,
        *,
        data: Optional[bytes] = None,
        file_path: Optional[str] = None,
        chunk_size: int = 2 * 1024 * 1024,
        checksum: Optional[str] = None,
    ) -> Dict[str, Any]:
        assert (data is not None) ^ (file_path is not None), "Provide either data or file_path"
        path = f"{parent}:upload"
        idk = _uuid()
        if data is not None:
            total = len(data)
            def gen() -> Iterable[bytes]:
                sent = 0
                while sent < total:
                    chunk = data[sent: sent + chunk_size]
                    sent += len(chunk)
                    payload = {"chunk": base64.b64encode(chunk).decode("ascii"), "last": sent >= total}
                    if checksum:
                        payload["checksum"] = checksum
                    yield (json.dumps(payload) + "\n").encode("utf-8")
            headers = {"Content-Type": "application/x-ndjson"}
            resp = self._core._request("POST", path, headers=headers, content=gen(), idempotency_key=idk, timeout=None)
            return resp.json()
        else:
            sz = os.path.getsize(file_path)  # type: ignore[arg-type]
            def genf() -> Iterable[bytes]:
                sent = 0
                with open(file_path, "rb") as f:  # type: ignore[arg-type]
                    while True:
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break
                        sent += len(chunk)
                        payload = {"chunk": base64.b64encode(chunk).decode("ascii"), "last": sent >= sz}
                        if checksum:
                            payload["checksum"] = checksum
                        yield (json.dumps(payload) + "\n").encode("utf-8")
            headers = {"Content-Type": "application/x-ndjson"}
            resp = self._core._request("POST", path, headers=headers, content=genf(), idempotency_key=idk, timeout=None)
            return resp.json()


# -----------------------------
# Public Client (async)
# -----------------------------
class AsyncNeuroforgeClient:
    """
    Asynchronous client.

    Example:
        async with AsyncNeuroforgeClient(base_url="https://api.neuroforge.example/v1", api_key="...") as nf:
            job_spec = {...}
            resp = await nf.submit_training_job(job_spec)
            print(resp.job.name)
    """

    def __init__(
        self,
        *,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        bearer_token: Optional[str] = None,
        timeout_s: Optional[float] = None,
        max_retries: Optional[int] = None,
        telemetry: Optional[bool] = None,
        default_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        cfg = _Config.from_env(base_url, api_key, bearer_token, timeout_s, max_retries, telemetry)
        if default_headers:
            cfg = dataclasses.replace(cfg, default_headers={**cfg.default_headers, **default_headers})
        self._client = httpx.AsyncClient(timeout=cfg.timeout_s)
        self._core = _HttpCore(cfg, self._client, is_async=True)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "AsyncNeuroforgeClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    # ------------- API methods -------------

    async def submit_training_job(
        self,
        job: Dict[str, Any],
        *,
        validate_only: bool = False,
        idempotency_key: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> SubmitTrainingJobResponse:
        payload = {
            "idempotency_key": idempotency_key or _uuid(),
            "correlation_id": correlation_id or _uuid(),
            "validate_only": validate_only,
            "job": job,
        }
        resp = await self._core._request_async("POST", "trainingJobs:submit", json_body=payload, idempotency_key=payload["idempotency_key"], correlation_id=payload["correlation_id"])
        return SubmitTrainingJobResponse.from_json(resp.json())

    async def get_training_job(self, name: str) -> TrainingJob:
        resp = await self._core._request_async("GET", f"trainingJobs/{name}")
        return TrainingJob.from_json(resp.json())

    async def cancel_training_job(self, name: str, *, reason: str = "", etag: Optional[str] = None) -> TrainingJob:
        payload = {"name": name, "reason": reason}
        if etag:
            payload["etag"] = etag
        resp = await self._core._request_async("POST", f"trainingJobs/{name}:cancel", json_body=payload, idempotency_key=_uuid())
        return TrainingJob.from_json(resp.json())

    async def list_training_jobs(self, *, filter: str = "", page_size: int = 50) -> AsyncIterator[TrainingJob]:
        token: Optional[str] = None
        while True:
            params = {"filter": filter, "page_size": page_size}
            if token:
                params["page_token"] = token
            resp = await self._core._request_async("GET", "trainingJobs", params=params)
            data = resp.json()
            for j in data.get("jobs", []):
                yield TrainingJob.from_json(j)
            token = data.get("next_page_token")
            if not token:
                break

    async def stream_logs(self, name: str, *, since_time: Optional[datetime] = None, min_level: Optional[str] = None) -> AsyncIterator[Dict[str, Any]]:
        params: Dict[str, Any] = {}
        if since_time:
            params["since_time"] = since_time.astimezone(timezone.utc).isoformat()
        if min_level:
            params["min_level"] = min_level
        resp = await self._core._request_async("GET", f"trainingJobs/{name}:logs", params=params, stream=True)
        try:
            async for line in resp.aiter_lines():
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except Exception:
                    yield {"time": _now_utc_iso(), "level": "INFO", "message": line}
        finally:
            await resp.aclose()

    async def stream_metrics(self, name: str, *, since_time: Optional[datetime] = None) -> AsyncIterator[Dict[str, Any]]:
        params: Dict[str, Any] = {}
        if since_time:
            params["since_time"] = since_time.astimezone(timezone.utc).isoformat()
        resp = await self._core._request_async("GET", f"trainingJobs/{name}:metrics", params=params, stream=True)
        try:
            async for line in resp.aiter_lines():
                if not line:
                    continue
                yield json.loads(line)
        finally:
            await resp.aclose()

    async def upload_artifact(
        self,
        parent: str,
        *,
        data: Optional[bytes] = None,
        file_path: Optional[str] = None,
        chunk_size: int = 2 * 1024 * 1024,
        checksum: Optional[str] = None,
    ) -> Dict[str, Any]:
        assert (data is not None) ^ (file_path is not None), "Provide either data or file_path"
        path = f"{parent}:upload"
        idk = _uuid()
        if data is not None:
            total = len(data)
            async def agen() -> AsyncIterator[bytes]:
                sent = 0
                while sent < total:
                    chunk = data[sent: sent + chunk_size]
                    sent += len(chunk)
                    payload = {"chunk": base64.b64encode(chunk).decode("ascii"), "last": sent >= total}
                    if checksum:
                        payload["checksum"] = checksum
                    yield (json.dumps(payload) + "\n").encode("utf-8")
            headers = {"Content-Type": "application/x-ndjson"}
            resp = await self._core._request_async("POST", path, headers=headers, content=agen(), idempotency_key=idk, timeout=None)
            return resp.json()
        else:
            sz = os.path.getsize(file_path)  # type: ignore[arg-type]
            async def agenf() -> AsyncIterator[bytes]:
                sent = 0
                loop = asyncio.get_running_loop()
                with open(file_path, "rb") as f:  # type: ignore[arg-type]
                    while True:
                        chunk = await loop.run_in_executor(None, f.read, chunk_size)
                        if not chunk:
                            break
                        sent += len(chunk)
                        payload = {"chunk": base64.b64encode(chunk).decode("ascii"), "last": sent >= sz}
                        if checksum:
                            payload["checksum"] = checksum
                        yield (json.dumps(payload) + "\n").encode("utf-8")
            headers = {"Content-Type": "application/x-ndjson"}
            resp = await self._core._request_async("POST", path, headers=headers, content=agenf(), idempotency_key=idk, timeout=None)
            return resp.json()
