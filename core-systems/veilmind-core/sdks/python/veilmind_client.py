# veilmind-core/sdks/python/veilmind_client.py
# -*- coding: utf-8 -*-
"""
Veilmind Python SDK (industrial-grade)

Features:
- Sync and Async clients (httpx)
- Strict timeouts, exponential backoff with jitter
- Idempotent POST via Idempotency-Key
- mTLS/TLS config, custom CA
- Optional OpenTelemetry propagation
- Secret-safe logging (redaction), capped log length
- Content-SHA256 header for integrity (json/bytes/file)
- Typed exceptions and minimal dataclass models

Python: 3.9+
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple, Union, Literal, Callable

try:
    import httpx  # runtime dependency
except Exception as e:  # pragma: no cover
    raise ImportError("veilmind_client requires 'httpx' package") from e

# Optional OpenTelemetry
try:  # pragma: no cover
    from opentelemetry.propagate import inject as otel_inject  # type: ignore
except Exception:
    otel_inject = None

__all__ = [
    "ClientConfig",
    "VeilmindClient",
    "AsyncVeilmindClient",
    "VeilmindError",
    "AuthError",
    "ClientError",
    "ServerError",
    "RateLimitError",
    "TimeoutError",
    "Decision",
]

# ------------------------------
# Redaction / Logging utilities
# ------------------------------

_REDACT_MASK = "[REDACTED]"
_REDACT_KEYS = {
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "authorization",
    "api_key",
    "apikey",
    "cookie",
    "set-cookie",
    "session",
    "private_key",
    "client_secret",
    "db_password",
    "jwt",
    "otp",
}

_RE_PATTERNS = [
    re.compile(r"(?i)bearer\s+[a-z0-9._\-]+"),
    re.compile(r"\beyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b"),  # JWT
    re.compile(r"\b\d{13,19}\b"),  # PAN (broad)
    re.compile(r"(?i)\b(pwd|pass(word)?|secret|token|key)\b\s*[:=]\s*\S+"),
]


def _redact_text(s: str, max_len: int = 2048) -> str:
    out = s
    for rx in _RE_PATTERNS:
        out = rx.sub(_REDACT_MASK, out)
    if len(out) > max_len:
        out = out[:max_len] + "...(truncated)"
    return out


def _redact_headers(h: Mapping[str, str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in h.items():
        kk = k.lower()
        if kk in _REDACT_KEYS:
            out[k] = _REDACT_MASK
        elif kk in ("authorization", "cookie", "set-cookie"):
            out[k] = _REDACT_MASK
        else:
            out[k] = _redact_text(v, max_len=256)
    return out


def _safe_json_dump(data: Any, max_len: int = 2048) -> str:
    try:
        txt = json.dumps(data, ensure_ascii=False, sort_keys=True)
        return _redact_text(txt, max_len=max_len)
    except Exception:
        return "<unserializable>"


# ------------------------------
# Config / Models
# ------------------------------

@dataclass
class ClientConfig:
    base_url: str
    api_token: Optional[str] = None  # Bearer token
    # TLS/mTLS
    verify: Union[bool, str] = True  # True | path_to_ca_bundle
    cert: Optional[Union[str, Tuple[str, str]]] = None  # path_to_cert or (cert, key)
    # timeouts and retries
    timeout: float = 10.0            # total timeout seconds per request
    connect_timeout: float = 5.0
    read_timeout: float = 5.0
    write_timeout: float = 5.0
    retries: int = 3                 # number of retry attempts on retryable statuses
    backoff_base: float = 0.2
    backoff_max: float = 2.5
    retry_on_status: Tuple[int, ...] = (408, 425, 429, 500, 502, 503, 504)
    retry_on_methods: Tuple[str, ...] = ("GET", "HEAD", "PUT", "DELETE", "OPTIONS")
    # Enable idempotency for POST by always sending Idempotency-Key header
    idempotent_post: bool = True
    # Transport options
    proxy: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    user_agent: str = "veilmind-sdk-python/1.0"
    # Logging
    logger: Optional[logging.Logger] = None
    log_requests: bool = False
    log_bodies: bool = False  # careful: still redacted
    # Misc
    otel_enabled: bool = True
    request_hook: Optional[Callable[[httpx.Request], None]] = None
    response_hook: Optional[Callable[[httpx.Response], None]] = None

    def __post_init__(self) -> None:
        if not self.base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must start with http:// or https://")
        self.base_url = self.base_url.rstrip("/")
        if self.logger is None:
            lg = logging.getLogger("veilmind.sdk")
            if not lg.handlers:
                h = logging.StreamHandler()
                fmt = logging.Formatter("[%(levelname)s] %(message)s")
                h.setFormatter(fmt)
                lg.addHandler(h)
            lg.setLevel(logging.INFO)
            self.logger = lg


@dataclass
class Decision:
    decision: Literal["allow", "deny", "mask", "tokenize", "redact", "quarantine"]
    reasons: Tuple[str, ...] = tuple()
    evidence: Dict[str, Any] = field(default_factory=dict)


# ------------------------------
# Exceptions
# ------------------------------

class VeilmindError(Exception):
    def __init__(self, message: str, *, status: Optional[int] = None, body: Optional[str] = None):
        super().__init__(message)
        self.status = status
        self.body = body

    def __str__(self) -> str:
        base = super().__str__()
        if self.status is not None:
            base += f" (status={self.status})"
        if self.body:
            base += f" body={_redact_text(self.body, max_len=512)}"
        return base


class AuthError(VeilmindError):
    pass


class ClientError(VeilmindError):
    pass


class ServerError(VeilmindError):
    pass


class RateLimitError(VeilmindError):
    pass


class TimeoutError(VeilmindError):
    pass


# ------------------------------
# Base client
# ------------------------------

class _BaseClient:
    def __init__(self, cfg: ClientConfig, *, async_mode: bool):
        self.cfg = cfg
        self._async = async_mode
        self._timeout = httpx.Timeout(
            timeout=cfg.timeout,
            connect=cfg.connect_timeout,
            read=cfg.read_timeout,
            write=cfg.write_timeout,
        )
        self._headers = {
            "User-Agent": cfg.user_agent,
            "Accept": "application/json",
        }
        if cfg.api_token:
            self._headers["Authorization"] = f"Bearer {cfg.api_token}"
        self._client: Union[httpx.Client, httpx.AsyncClient, None] = None

    # ----- transport lifecycle -----

    def _build_client(self) -> Union[httpx.Client, httpx.AsyncClient]:
        transport_kwargs = dict(verify=self.cfg.verify, cert=self.cfg.cert, timeout=self._timeout, headers=self.cfg.headers)
        if self.cfg.proxy:
            transport_kwargs["proxies"] = self.cfg.proxy  # type: ignore[assignment]
        if self._async:
            return httpx.AsyncClient(base_url=self.cfg.base_url, **transport_kwargs)
        else:
            return httpx.Client(base_url=self.cfg.base_url, **transport_kwargs)

    def _ensure_client(self) -> None:
        if self._client is None:
            self._client = self._build_client()

    # ----- logging helpers -----

    def _log_request(self, req: httpx.Request, body: Optional[Union[str, bytes]]) -> None:
        if not self.cfg.log_requests:
            return
        hdrs = _redact_headers(dict(req.headers))
        msg = f"{req.method} {req.url}"
        if self.cfg.log_bodies and body is not None:
            if isinstance(body, bytes):
                try:
                    body_txt = body.decode("utf-8", "replace")
                except Exception:
                    body_txt = "<bytes>"
            else:
                body_txt = body
            msg += f"\nHeaders: {hdrs}\nBody: {_redact_text(body_txt)}"
        else:
            msg += f"\nHeaders: {hdrs}"
        self.cfg.logger.info(msg)

    def _log_response(self, resp: httpx.Response) -> None:
        if not self.cfg.log_requests:
            return
        hdrs = _redact_headers(dict(resp.headers))
        line = f"Response {resp.status_code} for {resp.request.method} {resp.request.url}\nHeaders: {hdrs}"
        if self.cfg.log_bodies:
            with contextlib.suppress(Exception):
                txt = resp.text
                line += f"\nBody: {_redact_text(txt)}"
        self.cfg.logger.info(line)

    # ----- integrity -----

    @staticmethod
    def _sha256_of_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _sha256_of_file(path: str, chunk_size: int = 1024 * 1024) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    # ----- prepare -----

    def _headers_with_integrity(
        self,
        headers: Dict[str, str],
        payload: Optional[Union[bytes, str, Dict[str, Any]]] = None,
        file_path: Optional[str] = None,
    ) -> Dict[str, str]:
        h = dict(self._headers)
        h.update(headers)
        # OpenTelemetry propagation
        if self.cfg.otel_enabled and otel_inject is not None:
            try:
                otel_inject(lambda k, v: h.__setitem__(k, v))  # type: ignore[arg-type]
            except Exception:
                pass
        # Integrity
        if file_path:
            sha = self._sha256_of_file(file_path)
            h["Content-SHA256"] = sha
        elif payload is not None:
            if isinstance(payload, dict):
                raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            elif isinstance(payload, str):
                raw = payload.encode("utf-8")
            elif isinstance(payload, bytes):
                raw = payload
            else:
                raw = bytes()
            if raw:
                h["Content-SHA256"] = self._sha256_of_bytes(raw)
        return h

    # ----- retries/backoff -----

    def _sleep(self, seconds: float) -> None:
        if self._async:
            # replaced in Async subclass
            raise RuntimeError

        time.sleep(seconds)

    async def _sleep_async(self, seconds: float) -> None:
        await asyncio.sleep(seconds)

    def _compute_backoff(self, attempt: int) -> float:
        base = min(self.cfg.backoff_max, self.cfg.backoff_base * (2 ** (attempt - 1)))
        # Full jitter
        return 0.5 * base + (os.urandom(1)[0] / 255.0) * 0.5 * base

    def _should_retry(self, method: str, status: Optional[int], exc: Optional[Exception]) -> bool:
        if exc is not None:
            return True  # network/timeout
        if status in self.cfg.retry_on_status:
            return method in self.cfg.retry_on_methods
        return False

    # ----- core request -----

    def _prepare_idempotency(self, method: str, headers: Dict[str, str]) -> None:
        if method.upper() == "POST" and self.cfg.idempotent_post and "Idempotency-Key" not in headers:
            headers["Idempotency-Key"] = str(uuid.uuid4())

    def _raise_for_status(self, resp: httpx.Response) -> None:
        status = resp.status_code
        body = None
        with contextlib.suppress(Exception):
            body = resp.text
        msg = f"HTTP error {status}"
        if status in (401, 403):
            raise AuthError(msg, status=status, body=body)
        if status == 429:
            raise RateLimitError(msg, status=status, body=body)
        if 400 <= status < 500:
            raise ClientError(msg, status=status, body=body)
        if status >= 500:
            raise ServerError(msg, status=status, body=body)

    # Sync path
    def _request(
        self,
        method: str,
        path: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        data: Optional[Union[str, bytes]] = None,
        file_path: Optional[str] = None,
    ) -> httpx.Response:
        self._ensure_client()
        assert isinstance(self._client, httpx.Client)
        method_u = method.upper()
        headers = headers or {}
        self._prepare_idempotency(method_u, headers)
        hdrs = self._headers_with_integrity(headers, payload=json_body or data, file_path=file_path)

        # Build request body
        content = None
        request_json = None
        files = None
        if file_path:
            files = {"file": open(file_path, "rb")}
        elif json_body is not None:
            request_json = json_body
        elif data is not None:
            content = data

        req = self._client.build_request(method_u, path, headers=hdrs, params=params, json=request_json, content=content, files=files)
        body_for_log = None
        if self.cfg.log_bodies:
            if request_json is not None:
                body_for_log = _safe_json_dump(request_json)
            elif isinstance(content, (str, bytes)):
                body_for_log = content if isinstance(content, str) else content.decode("utf-8", "replace")
        self._log_request(req, body_for_log)

        attempt = 0
        while True:
            attempt += 1
            exc: Optional[Exception] = None
            resp: Optional[httpx.Response] = None
            try:
                resp = self._client.send(req, timeout=self._timeout)
                self._log_response(resp)
                if resp.status_code == 408 or resp.status_code == 504:
                    raise httpx.TimeoutException("request timeout")
                if self._should_retry(method_u, resp.status_code, None) and attempt <= self.cfg.retries:
                    delay = self._compute_backoff(attempt)
                    self.cfg.logger.info(f"Retrying in {delay:.2f}s (status={resp.status_code})")
                    self._sleep(delay)
                    continue
                self._raise_for_status(resp)
                return resp
            except httpx.TimeoutException as e:
                exc = e
                if attempt > self.cfg.retries:
                    raise TimeoutError("request timeout") from e
            except httpx.HTTPError as e:
                exc = e
                if attempt > self.cfg.retries:
                    raise ClientError(f"http error: {e}") from e
            finally:
                # Close file handle after request if used
                if files and "file" in files:
                    with contextlib.suppress(Exception):
                        files["file"].close()

            if not self._should_retry(method_u, None, exc) or attempt > self.cfg.retries:
                # give up
                if isinstance(exc, httpx.TimeoutException):
                    raise TimeoutError("request timeout") from exc
                raise ClientError("request failed") from exc
            delay = self._compute_backoff(attempt)
            self.cfg.logger.info(f"Retrying in {delay:.2f}s (network error)")
            self._sleep(delay)

    # Async path
    async def _request_async(
        self,
        method: str,
        path: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        data: Optional[Union[str, bytes]] = None,
        file_path: Optional[str] = None,
    ) -> httpx.Response:
        self._ensure_client()
        assert isinstance(self._client, httpx.AsyncClient)
        method_u = method.upper()
        headers = headers or {}
        self._prepare_idempotency(method_u, headers)
        hdrs = self._headers_with_integrity(headers, payload=json_body or data, file_path=file_path)

        request_json = None
        content = None
        files = None
        if file_path:
            files = {"file": open(file_path, "rb")}
        elif json_body is not None:
            request_json = json_body
        elif data is not None:
            content = data

        req = self._client.build_request(method_u, path, headers=hdrs, params=params, json=request_json, content=content, files=files)
        body_for_log = None
        if self.cfg.log_bodies:
            if request_json is not None:
                body_for_log = _safe_json_dump(request_json)
            elif isinstance(content, (str, bytes)):
                body_for_log = content if isinstance(content, str) else content.decode("utf-8", "replace")
        self._log_request(req, body_for_log)

        attempt = 0
        while True:
            attempt += 1
            exc: Optional[Exception] = None
            resp: Optional[httpx.Response] = None
            try:
                resp = await self._client.send(req, timeout=self._timeout)
                self._log_response(resp)
                if resp.status_code == 408 or resp.status_code == 504:
                    raise httpx.TimeoutException("request timeout")
                if self._should_retry(method_u, resp.status_code, None) and attempt <= self.cfg.retries:
                    delay = self._compute_backoff(attempt)
                    self.cfg.logger.info(f"Retrying in {delay:.2f}s (status={resp.status_code})")
                    await self._sleep_async(delay)
                    continue
                self._raise_for_status(resp)
                return resp
            except httpx.TimeoutException as e:
                exc = e
                if attempt > self.cfg.retries:
                    raise TimeoutError("request timeout") from e
            except httpx.HTTPError as e:
                exc = e
                if attempt > self.cfg.retries:
                    raise ClientError(f"http error: {e}") from e
            finally:
                if files and "file" in files:
                    with contextlib.suppress(Exception):
                        files["file"].close()

            if not self._should_retry(method_u, None, exc) or attempt > self.cfg.retries:
                if isinstance(exc, httpx.TimeoutException):
                    raise TimeoutError("request timeout") from exc
                raise ClientError("request failed") from exc
            delay = self._compute_backoff(attempt)
            self.cfg.logger.info(f"Retrying in {delay:.2f}s (network error)")
            await self._sleep_async(delay)

    # ----- high-level API -----

    # Health check
    def health(self) -> Dict[str, Any]:
        r = self._request("GET", "/health")
        return r.json()

    async def health_async(self) -> Dict[str, Any]:
        r = await self._request_async("GET", "/health")
        return r.json()

    # Policy evaluation (Zero Trust posture + rules)
    def check_policy(self, context: Mapping[str, Any], policies: Iterable[Mapping[str, Any]]) -> Decision:
        payload = {"context": dict(context), "policies": list(policies)}
        r = self._request("POST", "/v1/policy/evaluate", json_body=payload, headers={"Content-Type": "application/json"})
        data = r.json()
        return Decision(
            decision=str(data.get("decision", "deny")).lower(),  # safe default
            reasons=tuple(data.get("reasons", []) or []),
            evidence=data.get("evidence", {}) or {},
        )

    async def check_policy_async(self, context: Mapping[str, Any], policies: Iterable[Mapping[str, Any]]) -> Decision:
        payload = {"context": dict(context), "policies": list(policies)}
        r = await self._request_async("POST", "/v1/policy/evaluate", json_body=payload, headers={"Content-Type": "application/json"})
        data = r.json()
        return Decision(
            decision=str(data.get("decision", "deny")).lower(),
            reasons=tuple(data.get("reasons", []) or []),
            evidence=data.get("evidence", {}) or {},
        )

    # Redaction service
    def redact(self, payload: Mapping[str, Any], ruleset_id: Optional[str] = None) -> Dict[str, Any]:
        body = {"payload": payload}
        if ruleset_id:
            body["ruleset_id"] = ruleset_id
        r = self._request("POST", "/v1/redact", json_body=body, headers={"Content-Type": "application/json"})
        return r.json()

    async def redact_async(self, payload: Mapping[str, Any], ruleset_id: Optional[str] = None) -> Dict[str, Any]:
        body = {"payload": payload}
        if ruleset_id:
            body["ruleset_id"] = ruleset_id
        r = await self._request_async("POST", "/v1/redact", json_body=body, headers={"Content-Type": "application/json"})
        return r.json()

    # Submit PII event (Avro-JSON compatible)
    def submit_pii_event(self, event: Mapping[str, Any]) -> Dict[str, Any]:
        r = self._request("POST", "/v1/pii/events", json_body=dict(event), headers={"Content-Type": "application/json"})
        return r.json()

    async def submit_pii_event_async(self, event: Mapping[str, Any]) -> Dict[str, Any]:
        r = await self._request_async("POST", "/v1/pii/events", json_body=dict(event), headers={"Content-Type": "application/json"})
        return r.json()

    # File scanning (optional path)
    def scan_file(self, file_path: str, *, dataset_id: Optional[str] = None) -> Dict[str, Any]:
        params = {"dataset_id": dataset_id} if dataset_id else None
        r = self._request("POST", "/v1/scan/file", file_path=file_path, headers={}, params=params)
        return r.json()

    async def scan_file_async(self, file_path: str, *, dataset_id: Optional[str] = None) -> Dict[str, Any]:
        params = {"dataset_id": dataset_id} if dataset_id else None
        r = await self._request_async("POST", "/v1/scan/file", file_path=file_path, headers={}, params=params)
        return r.json()

    # ----- context managers / closing -----

    def close(self) -> None:
        if isinstance(self._client, httpx.Client):
            self._client.close()
        self._client = None

    async def aclose(self) -> None:
        if isinstance(self._client, httpx.AsyncClient):
            await self._client.aclose()
        self._client = None


class VeilmindClient(_BaseClient):
    """
    Synchronous client. Use as:

        cfg = ClientConfig(base_url="https://veilmind.example", api_token="...secret...")
        with VeilmindClient(cfg) as c:
            print(c.health())
    """
    def __init__(self, cfg: ClientConfig):
        super().__init__(cfg, async_mode=False)

    def __enter__(self) -> "VeilmindClient":
        self._ensure_client()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class AsyncVeilmindClient(_BaseClient):
    """
    Asynchronous client. Use as:

        cfg = ClientConfig(base_url="https://veilmind.example", api_token="...secret...")
        async with AsyncVeilmindClient(cfg) as c:
            print(await c.health_async())
    """
    def __init__(self, cfg: ClientConfig):
        super().__init__(cfg, async_mode=True)

    async def __aenter__(self) -> "AsyncVeilmindClient":
        self._ensure_client()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()
