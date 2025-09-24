# cybersecurity-core/cybersecurity/adapters/blackvault_adapter.py
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional, Protocol, Tuple

# ======================================================================================
# Исключения
# ======================================================================================

class ApiError(Exception):
    def __init__(self, message: str, status: Optional[int] = None, code: Optional[str] = None, request_id: Optional[str] = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.request_id = request_id


class TimeoutError_(Exception):
    pass


class CircuitOpenError(Exception):
    pass


class RateLimitError(Exception):
    pass


# ======================================================================================
# Утилиты
# ======================================================================================

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _uuid() -> str:
    return str(uuid.uuid4())

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _hmac_sha256_hex(secret: bytes, data: bytes) -> str:
    return hmac.new(secret, data, hashlib.sha256).hexdigest()

def _build_signing_payload(method: str, path_qs: str, content_sha256: str, timestamp: str) -> bytes:
    # Совместимо с нашей IAM/SDK семантикой: METHOD\n/path?qs\n<sha256>\n<ts>
    return f"{method.upper()}\n{path_qs}\n{content_sha256}\n{timestamp}".encode("utf-8")

def _clamp(n: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, n))

async def _sleep(ms: float) -> None:
    await asyncio.sleep(ms / 1000.0)


# ======================================================================================
# Rate limiter (token-bucket) и Circuit breaker
# ======================================================================================

class _TokenBucket:
    def __init__(self, rate_per_sec: float, burst: Optional[int] = None) -> None:
        self.rate = max(0.0, rate_per_sec)
        self.capacity = max(1, burst if burst is not None else int(max(1.0, self.rate * 2)))
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self._cond = asyncio.Condition()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.updated
        if self.rate > 0:
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        else:
            self.tokens = self.capacity
        self.updated = now

    async def acquire(self, timeout_sec: float | None) -> None:
        if self.rate == 0:
            return
        start = time.monotonic()
        async with self._cond:
            while True:
                self._refill()
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                if timeout_sec is not None and (time.monotonic() - start) >= timeout_sec:
                    raise RateLimitError("rate limit acquire timeout")
                await asyncio.wait_for(self._cond.wait(), timeout=0.05)

class _CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, cooldown_sec: float = 15.0) -> None:
        self.failure_threshold = max(1, failure_threshold)
        self.cooldown = max(0.1, cooldown_sec)
        self.state = "closed"  # closed|open|half
        self.failures = 0
        self.opened_at = 0.0
        self._half_inflight = False

    def allow(self) -> bool:
        now = time.monotonic()
        if self.state == "closed":
            return True
        if self.state == "open":
            if now - self.opened_at >= self.cooldown:
                self.state = "half"
                self._half_inflight = False
                return True
            return False
        # half
        if not self._half_inflight:
            self._half_inflight = True
            return True
        return False

    def on_success(self) -> None:
        self.failures = 0
        self.state = "closed"
        self._half_inflight = False

    def on_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.failure_threshold:
            self.state = "open"
            self.opened_at = time.monotonic()
            self._half_inflight = False


# ======================================================================================
# Конфигурация клиента
# ======================================================================================

@dataclass(slots=True)
class RetryPolicy:
    max_retries: int = 3
    base_delay_ms: int = 300
    max_delay_ms: int = 10_000
    jitter: bool = True

@dataclass(slots=True)
class BlackVaultConfig:
    base_url: str
    api_key: Optional[str] = None
    oauth_token: Optional[str] = None
    hmac_secret: Optional[bytes] = None
    hmac_key_prefix: Optional[str] = None  # для x-key-prefix (идентификация секрета)
    organization_id: Optional[str] = None
    user_agent: str = "blackvault-adapter/1.0"
    request_timeout_ms: int = 30_000
    rate_limit_per_sec: float = 0.0
    rate_acquire_timeout_sec: float = 30.0
    circuit_failure_threshold: int = 5
    circuit_cooldown_sec: float = 15.0
    default_headers: Dict[str, str] = field(default_factory=dict)
    retry: RetryPolicy = field(default_factory=RetryPolicy)

    # Пути (можно переопределить под конкретный BlackVault)
    # POST {blobs_path} -> { "ref": "..." }
    # GET  {blobs_path}/{ref}
    # POST {presign_path} body: { "ref": "...", "expires_in": 3600 }
    blobs_path: str = "/v1/blobs"
    presign_path: str = "/v1/blobs/presign"

# ======================================================================================
# HTTP-клиентный протокол и реализации
# ======================================================================================

class AsyncHttpResponse(Protocol):
    status: int
    headers: Mapping[str, str]
    async def json(self) -> Any: ...
    async def read(self) -> bytes: ...
    async def text(self) -> str: ...

class AsyncHttpClient(Protocol):
    async def request(self, method: str, url: str, *, headers: Mapping[str, str], data: bytes | None, timeout: float) -> AsyncHttpResponse: ...
    async def close(self) -> None: ...

class _AioHttpResponse:
    def __init__(self, resp) -> None:
        self._resp = resp
        self.status = resp.status
        # normalize headers to lower-case keys
        self.headers = {k.lower(): v for k, v in resp.headers.items()}

    async def json(self) -> Any:
        return await self._resp.json(content_type=None)

    async def read(self) -> bytes:
        return await self._resp.read()

    async def text(self) -> str:
        return await self._resp.text()

class _AioHttpClient:
    def __init__(self) -> None:
        import aiohttp  # type: ignore
        self._session = aiohttp.ClientSession(raise_for_status=False)

    async def request(self, method: str, url: str, *, headers: Mapping[str, str], data: bytes | None, timeout: float) -> AsyncHttpResponse:
        import aiohttp  # type: ignore
        try:
            async with self._session.request(
                method=method,
                url=url,
                headers=dict(headers),
                data=data,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as resp:
                return _AioHttpResponse(resp)
        except asyncio.TimeoutError as ex:
            raise TimeoutError_() from ex

    async def close(self) -> None:
        await self._session.close()

class _StdlibResponse:
    def __init__(self, status: int, headers: Mapping[str, str], body: bytes) -> None:
        self.status = status
        self.headers = {k.lower(): v for k, v in headers.items()}
        self._body = body

    async def json(self) -> Any:
        return json.loads(self._body.decode("utf-8") if self._body else "null")

    async def read(self) -> bytes:
        return self._body

    async def text(self) -> str:
        return self._body.decode("utf-8")

class _StdlibClient:
    """Fallback через urllib в thread pool. Без внешних зависимостей."""
    def __init__(self) -> None:
        pass

    async def request(self, method: str, url: str, *, headers: Mapping[str, str], data: bytes | None, timeout: float) -> AsyncHttpResponse:
        import urllib.request
        import urllib.error
        req = urllib.request.Request(url=url, method=method, data=data)
        for k, v in headers.items():
            req.add_header(k, v)

        def _call() -> Tuple[int, Dict[str, str], bytes]:
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    status = resp.status
                    hdrs = {k: v for k, v in resp.headers.items()}
                    body = resp.read()
                    return status, hdrs, body
            except urllib.error.HTTPError as e:
                status = e.code
                hdrs = dict(e.headers.items()) if e.headers else {}
                body = e.read() if hasattr(e, "read") else b""
                return status, hdrs, body
            except urllib.error.URLError as e:
                # таймаут и сетевые ошибки
                raise TimeoutError_() if isinstance(e.reason, TimeoutError) else e

        status, hdrs, body = await asyncio.to_thread(_call)
        return _StdlibResponse(status, hdrs, body)

    async def close(self) -> None:
        return

def _get_http_client() -> AsyncHttpClient:
    with contextlib.suppress(Exception):
        import aiohttp  # noqa: F401
        return _AioHttpClient()
    return _StdlibClient()

# ======================================================================================
# Базовый HTTP клиент с аутентификацией, HMAC и ретраями
# ======================================================================================

class _HttpCore:
    def __init__(self, cfg: BlackVaultConfig) -> None:
        self.cfg = cfg
        self.http = _get_http_client()
        self.bucket = _TokenBucket(cfg.rate_limit_per_sec, burst=int(cfg.rate_limit_per_sec * 2) if cfg.rate_limit_per_sec > 0 else 1)
        self.circuit = _CircuitBreaker(cfg.circuit_failure_threshold, cfg.circuit_cooldown_sec)

    async def close(self) -> None:
        await self.http.close()

    async def request(self, method: str, path: str, *, headers: Optional[Mapping[str, str]] = None, data: bytes | None) -> AsyncHttpResponse:
        if not self.circuit.allow():
            raise CircuitOpenError("circuit breaker is open")

        # Rate limit
        await self.bucket.acquire(self.cfg.rate_acquire_timeout_sec)

        url = self._build_url(path)
        req_id = headers.get("x-request-id") if headers else None
        req_id = req_id or _uuid()

        # Базовые заголовки
        hdrs: Dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": self.cfg.user_agent,
            "x-request-id": req_id,
            **(self.cfg.default_headers or {}),
            **(headers or {}),
        }
        if self.cfg.organization_id:
            hdrs.setdefault("X-Org-Id", self.cfg.organization_id)

        # Аутентификация
        if self.cfg.oauth_token:
            hdrs.setdefault("Authorization", f"Bearer {self.cfg.oauth_token}")
        elif self.cfg.api_key:
            hdrs.setdefault("X-API-Key", self.cfg.api_key)

        # Контроль целостности и HMAC подпись
        body = data or b""
        content_sha256 = _sha256_hex(body)
        hdrs.setdefault("x-content-sha256", content_sha256)
        ts = str(int(time.time() * 1000))
        if self.cfg.hmac_secret:
            payload = _build_signing_payload(method, path, content_sha256, ts)
            signature = _hmac_sha256_hex(self.cfg.hmac_secret, payload)
            hdrs["x-timestamp"] = ts
            hdrs["x-signature"] = signature
            hdrs["x-signature-alg"] = "HMAC-SHA256"
            if self.cfg.hmac_key_prefix:
                hdrs["x-key-prefix"] = self.cfg.hmac_key_prefix

        # Content-Type по умолчанию для JSON/байтов
        if body and "Content-Type" not in {k.title(): v for k, v in hdrs.items()} and method in ("POST", "PUT"):
            hdrs["Content-Type"] = "application/octet-stream"

        # Ретраи
        attempt = 0
        last_exc: Optional[Exception] = None
        while True:
            try:
                timeout = self.cfg.request_timeout_ms / 1000.0
                async with asyncio.timeout(timeout):
                    resp = await self.http.request(method, url, headers=hdrs, data=body, timeout=timeout)
                if self._should_retry(resp.status) and attempt < self.cfg.retry.max_retries:
                    attempt += 1
                    await _sleep(self._backoff_ms(attempt))
                    continue
                if resp.status >= 400:
                    # пытаться распарсить ошибку
                    try:
                        j = await resp.json()
                        msg = j.get("error", {}).get("message") or j.get("message") or f"HTTP {resp.status}"
                        code = j.get("error", {}).get("code")
                    except Exception:
                        msg, code = f"HTTP {resp.status}", None
                    self.circuit.on_failure()
                    raise ApiError(msg, status=resp.status, code=code, request_id=req_id)
                self.circuit.on_success()
                return resp
            except TimeoutError_ as ex:
                last_exc = ex
            except CircuitOpenError:
                raise
            except Exception as ex:
                last_exc = ex

            if attempt < self.cfg.retry.max_retries:
                attempt += 1
                await _sleep(self._backoff_ms(attempt))
                continue
            self.circuit.on_failure()
            raise last_exc or ApiError("request failed", status=None, code=None, request_id=req_id)

    def _should_retry(self, status: int) -> bool:
        return status >= 500 or status == 429

    def _backoff_ms(self, attempt: int) -> int:
        base = self.cfg.retry.base_delay_ms * (2 ** (attempt - 1))
        capped = int(_clamp(base, self.cfg.retry.base_delay_ms, self.cfg.retry.max_delay_ms))
        if self.cfg.retry.jitter:
            # full jitter
            return int(os.urandom(1)[0] / 255 * capped)
        return capped

    def _build_url(self, path: str) -> str:
        base = self.cfg.base_url.rstrip("/")
        if not path.startswith("/"):
            path = "/" + path
        return base + path


# ======================================================================================
# Публичный адаптер BlackVault + совместимость c ArtifactStore протоколом
# ======================================================================================

class ArtifactStore(Protocol):
    async def put_blob(self, name: str, data: bytes, content_type: str = "application/octet-stream") -> str: ...
    async def get_blob(self, ref: str) -> bytes: ...
    async def presign(self, ref: str, expires_in_sec: int = 3600) -> str: ...

@dataclass(slots=True)
class PutBlobResponse:
    ref: str

class BlackVaultAdapter(ArtifactStore):
    """
    Интеграция с BlackVault:
      - POST {blobs_path} (body=bytes, headers: Content-Type, X-Name?, Idempotency-Key?)
        -> { "ref": "<opaque-string>" }
      - GET  {blobs_path}/{ref} -> raw bytes
      - POST {presign_path} { "ref": "...", "expires_in": 3600 } -> { "url": "..." }

    Семантика HMAC и заголовков согласована с остальными модулями Aethernova.
    """
    def __init__(self, cfg: BlackVaultConfig) -> None:
        self.cfg = cfg
        self.http = _HttpCore(cfg)

    async def close(self) -> None:
        await self.http.close()

    # ----------------- ArtifactStore API -----------------

    async def put_blob(self, name: str, data: bytes, content_type: str = "application/octet-stream", *, idempotency_key: Optional[str] = None, tags: Optional[Mapping[str, str]] = None) -> str:
        headers: Dict[str, str] = {
            "Content-Type": content_type,
            "x-artifact-name": name,
        }
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        if tags:
            headers["x-artifact-tags"] = json.dumps(dict(tags), separators=(",", ":"))

        path = self.cfg.blobs_path
        resp = await self.http.request("POST", path, headers=headers, data=data)
        try:
            j = await resp.json()
        except Exception:
            raise ApiError("invalid JSON from BlackVault on put_blob", status=resp.status)
        ref = j.get("ref")
        if not ref:
            raise ApiError("missing 'ref' in BlackVault response", status=resp.status)
        return str(ref)

    async def get_blob(self, ref: str) -> bytes:
        path = f"{self.cfg.blobs_path}/{ref}"
        resp = await self.http.request("GET", path, headers={}, data=None)
        # попытка интерпретировать как бинарь; если сервер вернёт JSON-ошибку — _HttpCore уже бросит ApiError
        return await resp.read()

    async def presign(self, ref: str, expires_in_sec: int = 3600) -> str:
        path = self.cfg.presign_path
        payload = {"ref": ref, "expires_in": int(expires_in_sec)}
        headers = {"Content-Type": "application/json"}
        resp = await self.http.request("POST", path, headers=headers, data=json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        try:
            j = await resp.json()
        except Exception:
            raise ApiError("invalid JSON from BlackVault on presign", status=resp.status)
        url = j.get("url")
        if not url:
            raise ApiError("missing 'url' in BlackVault presign response", status=resp.status)
        return str(url)

    # ----------------- Доп. операции (необязательные) -----------------

    async def delete_blob(self, ref: str) -> None:
        path = f"{self.cfg.blobs_path}/{ref}"
        await self.http.request("DELETE", path, headers={}, data=None)

    async def stat_blob(self, ref: str) -> Dict[str, Any]:
        # расширение: HEAD или GET метаданных — конкретный эндпоинт зависит от BlackVault.
        # По умолчанию реализуем GET /v1/blobs/{ref}/meta
        path = f"{self.cfg.blobs_path}/{ref}/meta"
        resp = await self.http.request("GET", path, headers={}, data=None)
        try:
            return await resp.json()
        except Exception:
            raise ApiError("invalid JSON from BlackVault on stat_blob", status=resp.status)

    # ----------------- Вспомогательные методы -----------------

    @staticmethod
    def build_default_config(base_url: str, *, api_key: Optional[str] = None, oauth_token: Optional[str] = None, hmac_secret: Optional[bytes] = None, hmac_key_prefix: Optional[str] = None, organization_id: Optional[str] = None) -> BlackVaultConfig:
        return BlackVaultConfig(
            base_url=base_url,
            api_key=api_key,
            oauth_token=oauth_token,
            hmac_secret=hmac_secret,
            hmac_key_prefix=hmac_key_prefix,
            organization_id=organization_id,
        )


# ======================================================================================
# Интеграция с ранее определённым протоколом ArtifactStore (из модуля vuln.orchestrator)
# --------------------------------------------------------------------------------------
# Если вы используете ScannerOrchestrator.ArtifactStore из cybersecurity/vuln/scanner_orchestrator.py,
# этот адаптер уже совместим: методы put_blob/get_blob/presign совпадают по сигнатурам.
# ======================================================================================

__all__ = [
    "ApiError",
    "TimeoutError_",
    "CircuitOpenError",
    "RateLimitError",
    "RetryPolicy",
    "BlackVaultConfig",
    "BlackVaultAdapter",
    "ArtifactStore",
]
