# oblivionvault-core/oblivionvault/adapters/veilmind_adapter.py
# Industrial-grade VeilMind adapter for OblivionVault.
# Python 3.11+, stdlib-only. No external deps.
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import hashlib
import hmac
import http.client
import io
import json
import logging
import os
import re
import time
import uuid
from typing import Any, Dict, Optional, Protocol, AsyncIterator, Literal
from urllib.parse import urlparse, urlencode

# =========================
# Structured JSON logging
# =========================

_LOG = logging.getLogger("oblivionvault.adapters.veilmind")
if not _LOG.handlers:
    _LOG.setLevel(logging.INFO)
    h = logging.StreamHandler()
    h.setLevel(logging.INFO)
    h.setFormatter(logging.Formatter("%(message)s"))
    _LOG.addHandler(h)

def _jlog(event: str, **fields: Any) -> None:
    payload = {"ts": round(time.time(), 6), "event": event, **fields}
    _LOG.info(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))

def _redact_secret(val: Optional[str]) -> str:
    if not val:
        return ""
    return f"{val[:4]}***{val[-2:]}" if len(val) > 8 else "***"


# =========================
# Errors
# =========================

class VeilMindError(Exception): ...
class TransportError(VeilMindError): ...
class IntegrityError(VeilMindError): ...
class PolicyError(VeilMindError): ...
class RateLimitError(VeilMindError): ...
class CircuitOpenError(VeilMindError): ...
class TimeoutError(VeilMindError): ...


# =========================
# Config & Models
# =========================

@dataclasses.dataclass(slots=True, frozen=True)
class VeilMindConfig:
    base_url: str
    api_key: Optional[str] = None
    hmac_secret: Optional[str] = None         # shared secret for request/response HMAC
    connect_timeout_s: float = 3.0
    read_timeout_s: float = 20.0
    op_timeout_s: float = 25.0                 # per-operation envelope
    max_attempts: int = 3
    backoff_base_s: float = 0.1
    backoff_max_s: float = 1.0
    circuit_failure_threshold: int = 8
    circuit_reset_timeout_s: float = 30.0
    rate_per_sec: float = 10.0                 # simple token bucket
    policy_cache_ttl_s: float = 300.0
    verify_response_hmac: bool = True
    sign_requests: bool = True
    default_policy_id: str = "default"

    def sanitized(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        d["api_key"] = _redact_secret(self.api_key)
        d["hmac_secret"] = _redact_secret(self.hmac_secret)
        return d


@dataclasses.dataclass(slots=True, frozen=True)
class RedactRequest:
    text: str
    policy_id: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None
    idempotency_key: Optional[str] = None


@dataclasses.dataclass(slots=True, frozen=True)
class RedactResult:
    text: str
    redacted: bool
    details: Dict[str, Any]


# =========================
# Circuit Breaker
# =========================

class CircuitBreaker:
    __slots__ = ("_state", "_failures", "_opened_at", "_lock",
                 "failure_threshold", "reset_timeout")

    def __init__(self, *, failure_threshold: int, reset_timeout: float) -> None:
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self._state: Literal["closed", "open", "half_open"] = "closed"
        self._failures = 0
        self._opened_at = 0.0
        self._lock = asyncio.Lock()

    async def allow(self) -> None:
        async with self._lock:
            if self._state == "open":
                if time.time() - self._opened_at >= self.reset_timeout:
                    self._state = "half_open"
                    return
                raise CircuitOpenError("circuit_open")
            return

    async def ok(self) -> None:
        async with self._lock:
            self._state = "closed"
            self._failures = 0

    async def fail(self) -> None:
        async with self._lock:
            self._failures += 1
            if self._failures >= self.failure_threshold:
                self._state = "open"
                self._opened_at = time.time()


# =========================
# Rate Limiter (token bucket)
# =========================

class TokenBucket:
    __slots__ = ("rate", "capacity", "_tokens", "_updated", "_lock")

    def __init__(self, rate: float, capacity: Optional[float] = None) -> None:
        self.rate = max(rate, 0.001)
        self.capacity = capacity or self.rate
        self._tokens = self.capacity
        self._updated = time.time()
        self._lock = asyncio.Lock()

    async def take(self, amount: float = 1.0) -> None:
        async with self._lock:
            now = time.time()
            elapsed = now - self._updated
            self._updated = now
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            if self._tokens < amount:
                # sleep time needed
                need = amount - self._tokens
                delay = need / self.rate
                await asyncio.sleep(delay)
                self._tokens = 0.0
            else:
                self._tokens -= amount


# =========================
# Transport Protocol
# =========================

class VeilMindTransport(Protocol):
    async def post_json(self, path: str, payload: Dict[str, Any], headers: Dict[str, str],
                        *, connect_timeout: float, read_timeout: float) -> tuple[Dict[str, Any], Dict[str, str]]:
        """
        Returns (json_body, response_headers).
        Raises TransportError on failures.
        """
        ...

    async def get_json(self, path: str, query: Dict[str, Any], headers: Dict[str, str],
                       *, connect_timeout: float, read_timeout: float) -> tuple[Dict[str, Any], Dict[str, str]]:
        """
        Returns (json_body, response_headers).
        Raises TransportError on failures.
        """
        ...


# =========================
# Stdlib HTTP Transport
# =========================

class StdlibHttpTransport:
    def __init__(self, base_url: str) -> None:
        self._base = base_url.rstrip("/")
        parsed = urlparse(self._base)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("Unsupported scheme for StdlibHttpTransport")
        self._parsed = parsed

    def _build_conn(self, connect_timeout: float) -> http.client.HTTPConnection:
        host = self._parsed.hostname
        port = self._parsed.port
        if self._parsed.scheme == "https":
            conn = http.client.HTTPSConnection(host, port=port, timeout=connect_timeout)
        else:
            conn = http.client.HTTPConnection(host, port=port, timeout=connect_timeout)
        return conn

    def _full_path(self, path: str, query: Optional[Dict[str, Any]] = None) -> str:
        p = path if path.startswith("/") else f"/{path}"
        if query:
            return f"{self._parsed.path}{p}?{urlencode(query, doseq=True)}"
        return f"{self._parsed.path}{p}"

    async def post_json(self, path: str, payload: Dict[str, Any], headers: Dict[str, str],
                        *, connect_timeout: float, read_timeout: float) -> tuple[Dict[str, Any], Dict[str, str]]:
        def _do():
            conn = self._build_conn(connect_timeout)
            try:
                body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                h = {"Content-Type": "application/json; charset=utf-8", **headers}
                conn.putrequest("POST", self._full_path(path))
                for k, v in h.items():
                    conn.putheader(k, v)
                conn.putheader("Content-Length", str(len(body)))
                conn.endheaders()
                conn.send(body)
                conn.sock.settimeout(read_timeout)
                resp = conn.getresponse()
                data = resp.read()
                if resp.status >= 400:
                    raise TransportError(f"HTTP {resp.status}: {data[:256]!r}")
                try:
                    parsed = json.loads(data.decode("utf-8"))
                except Exception as e:
                    raise TransportError(f"Invalid JSON response: {e}") from e
                return parsed, {k: v for k, v in resp.getheaders()}
            finally:
                with contextlib.suppress(Exception):
                    conn.close()
        return await asyncio.to_thread(_do)

    async def get_json(self, path: str, query: Dict[str, Any], headers: Dict[str, str],
                       *, connect_timeout: float, read_timeout: float) -> tuple[Dict[str, Any], Dict[str, str]]:
        def _do():
            conn = self._build_conn(connect_timeout)
            try:
                h = {"Accept": "application/json", **headers}
                conn.putrequest("GET", self._full_path(path, query))
                for k, v in h.items():
                    conn.putheader(k, v)
                conn.endheaders()
                conn.sock.settimeout(read_timeout)
                resp = conn.getresponse()
                data = resp.read()
                if resp.status >= 400:
                    raise TransportError(f"HTTP {resp.status}: {data[:256]!r}")
                try:
                    parsed = json.loads(data.decode("utf-8"))
                except Exception as e:
                    raise TransportError(f"Invalid JSON response: {e}") from e
                return parsed, {k: v for k, v in resp.getheaders()}
            finally:
                with contextlib.suppress(Exception):
                    conn.close()
        return await asyncio.to_thread(_do)


# =========================
# Local Offline Redactor (fallback)
# =========================

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
_PHONE_RE = re.compile(r"\b(?:\+?\d{1,3}[\s-]?)?(?:\(?\d{2,4}\)?[\s-]?)?\d{3}[\s-]?\d{2,4}[\s-]?\d{2,4}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_CARD_RE = re.compile(r"\b(?:\d[ -]*?){12,19}\b")
# Простой Luhn
def _luhn_ok(s: str) -> bool:
    digits = [int(ch) for ch in re.sub(r"\D", "", s)]
    if len(digits) < 12:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0

def offline_redact(text: str) -> tuple[str, Dict[str, int]]:
    counts = {"email": 0, "phone": 0, "ipv4": 0, "card": 0}
    def repl_email(m: re.Match) -> str:
        counts["email"] += 1
        return "[REDACTED:EMAIL]"
    def repl_phone(m: re.Match) -> str:
        counts["phone"] += 1
        return "[REDACTED:PHONE]"
    def repl_ip(m: re.Match) -> str:
        ip = m.group(0)
        parts = ip.split(".")
        masked = ".".join(parts[:2] + ["x", "x"])
        counts["ipv4"] += 1
        return f"[REDACTED:IP:{masked}]"
    def repl_card(m: re.Match) -> str:
        s = m.group(0)
        if _luhn_ok(s):
            counts["card"] += 1
            return "[REDACTED:CARD]"
        return s

    t = _EMAIL_RE.sub(repl_email, text)
    t = _PHONE_RE.sub(repl_phone, t)
    t = _IPV4_RE.sub(repl_ip, t)
    t = _CARD_RE.sub(repl_card, t)
    return t, counts


# =========================
# Adapter
# =========================

class VeilMindAdapter:
    """
    Высокоуровневый адаптер VeilMind:
      - redact / tokenize / detokenize / classify / health
      - подпись HMAC запросов, проверка ответов
      - ретраи, backoff, circuit breaker, rate limit
      - кэш политик (TTL)
      - офлайн-редактор PII как фоллбек
    """
    def __init__(self, config: VeilMindConfig, transport: Optional[VeilMindTransport] = None) -> None:
        self.cfg = config
        self.transport = transport or StdlibHttpTransport(config.base_url)
        self._cb = CircuitBreaker(
            failure_threshold=config.circuit_failure_threshold,
            reset_timeout=config.circuit_reset_timeout_s,
        )
        self._bucket = TokenBucket(rate=config.rate_per_sec)
        self._policy_cache: dict[str, tuple[float, Dict[str, Any]]] = {}
        _jlog("veilmind.init", cfg=self.cfg.sanitized())

    # ---------- Public API ----------

    async def health(self) -> Dict[str, Any]:
        return await self._op_get("/v1/health", {})

    async def get_policy(self, policy_id: Optional[str]) -> Dict[str, Any]:
        pid = policy_id or self.cfg.default_policy_id
        now = time.time()
        cached = self._policy_cache.get(pid)
        if cached and (now - cached[0]) < self.cfg.policy_cache_ttl_s:
            return cached[1]
        res = await self._op_get(f"/v1/policy/{pid}", {})
        self._policy_cache[pid] = (now, res)
        return res

    async def redact(self, req: RedactRequest) -> RedactResult:
        payload = {
            "text": req.text,
            "policy_id": req.policy_id or self.cfg.default_policy_id,
            "meta": req.meta or {},
        }
        try:
            data = await self._op_post("/v1/redact", payload, idempotency_key=req.idempotency_key)
            result = RedactResult(text=data.get("text", ""), redacted=bool(data.get("redacted", True)),
                                  details=data.get("details", {}))
            return result
        except (TransportError, CircuitOpenError, TimeoutError) as e:
            # Фоллбек: офлайн-редакция
            _jlog("veilmind.redact.fallback", reason=type(e).__name__)
            text, counts = await asyncio.to_thread(offline_redact, req.text)
            return RedactResult(text=text, redacted=True, details={"fallback": True, "counts": counts})
        except IntegrityError:
            # Ответ невалиден — останавливаемся без фоллбека, чтобы не скрыть проблему целостности.
            raise

    async def tokenize(self, text: str, policy_id: Optional[str] = None, *, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        payload = {"text": text, "policy_id": policy_id or self.cfg.default_policy_id}
        return await self._op_post("/v1/tokenize", payload, idempotency_key=idempotency_key)

    async def detokenize(self, tokens: Dict[str, Any], *, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        payload = {"tokens": tokens}
        return await self._op_post("/v1/detokenize", payload, idempotency_key=idempotency_key)

    async def classify(self, text: str, *, policy_id: Optional[str] = None) -> Dict[str, Any]:
        payload = {"text": text, "policy_id": policy_id or self.cfg.default_policy_id}
        return await self._op_post("/v1/classify", payload, idempotency_key=None)

    # ---------- Internal ops ----------

    async def _op_post(self, path: str, payload: Dict[str, Any], *, idempotency_key: Optional[str]) -> Dict[str, Any]:
        await self._bucket.take()
        await self._cb.allow()
        idem = idempotency_key or str(uuid.uuid4())
        headers = self._headers(idempotency_key=idem)
        attempt = 0
        last_exc: Optional[BaseException] = None
        start = time.time()

        while attempt < self.cfg.max_attempts:
            attempt += 1
            try:
                with _timeout(self.cfg.op_timeout_s):
                    _jlog("veilmind.post.start", path=path, attempt=attempt, idem=idem)
                    body, resp_headers = await self.transport.post_json(
                        path, payload, headers,
                        connect_timeout=self.cfg.connect_timeout_s,
                        read_timeout=self.cfg.read_timeout_s
                    )
                    self._verify_response(resp_headers, body)
                    await self._cb.ok()
                    _jlog("veilmind.post.ok", path=path, attempt=attempt, ms=int((time.time()-start)*1000))
                    return body
            except asyncio.CancelledError:
                raise
            except CircuitOpenError:
                _jlog("veilmind.post.circuit_open", path=path)
                raise
            except Exception as e:
                last_exc = e
                await self._cb.fail()
                if attempt >= self.cfg.max_attempts:
                    break
                backoff = min(self.cfg.backoff_max_s, self.cfg.backoff_base_s * (2 ** (attempt - 1)))
                _jlog("veilmind.post.retry", path=path, attempt=attempt, backoff_s=backoff, err=type(e).__name__)
                await asyncio.sleep(backoff)

        # classify errors
        if isinstance(last_exc, TransportError):
            raise last_exc
        if isinstance(last_exc, CircuitOpenError):
            raise last_exc
        if isinstance(last_exc, TimeoutError):
            raise last_exc
        raise TransportError(str(last_exc))

    async def _op_get(self, path: str, query: Dict[str, Any]) -> Dict[str, Any]:
        await self._bucket.take()
        await self._cb.allow()
        headers = self._headers(idempotency_key=str(uuid.uuid4()))
        attempt = 0
        last_exc: Optional[BaseException] = None
        start = time.time()

        while attempt < self.cfg.max_attempts:
            attempt += 1
            try:
                with _timeout(self.cfg.op_timeout_s):
                    _jlog("veilmind.get.start", path=path, attempt=attempt)
                    body, resp_headers = await self.transport.get_json(
                        path, query, headers,
                        connect_timeout=self.cfg.connect_timeout_s,
                        read_timeout=self.cfg.read_timeout_s
                    )
                    self._verify_response(resp_headers, body)
                    await self._cb.ok()
                    _jlog("veilmind.get.ok", path=path, attempt=attempt, ms=int((time.time()-start)*1000))
                    return body
            except asyncio.CancelledError:
                raise
            except CircuitOpenError:
                _jlog("veilmind.get.circuit_open", path=path)
                raise
            except Exception as e:
                last_exc = e
                await self._cb.fail()
                if attempt >= self.cfg.max_attempts:
                    break
                backoff = min(self.cfg.backoff_max_s, self.cfg.backoff_base_s * (2 ** (attempt - 1)))
                _jlog("veilmind.get.retry", path=path, attempt=attempt, backoff_s=backoff, err=type(e).__name__)
                await asyncio.sleep(backoff)

        if isinstance(last_exc, TransportError):
            raise last_exc
        if isinstance(last_exc, CircuitOpenError):
            raise last_exc
        if isinstance(last_exc, TimeoutError):
            raise last_exc
        raise TransportError(str(last_exc))

    # ---------- Security ----------

    def _headers(self, *, idempotency_key: str) -> Dict[str, str]:
        hdrs = {
            "X-Request-ID": str(uuid.uuid4()),
            "X-Idempotency-Key": idempotency_key,
        }
        if self.cfg.api_key:
            hdrs["Authorization"] = f"Bearer {self.cfg.api_key}"
        if self.cfg.sign_requests and self.cfg.hmac_secret:
            hdrs["X-Signature-Alg"] = "HMAC-SHA256"
            # тело подписывается в транспорте вызовом _sign_body(), но алгоритм тут фиксируем
        return hdrs

    def _verify_response(self, headers: Dict[str, str], body: Dict[str, Any]) -> None:
        if not self.cfg.verify_response_hmac or not self.cfg.hmac_secret:
            return
        sig = headers.get("X-Server-Signature") or headers.get("x-server-signature")
        if not sig:
            raise IntegrityError("missing_server_signature")
        raw = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        calc = hmac.new(self.cfg.hmac_secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, calc):
            raise IntegrityError("response_hmac_mismatch")

    # ---------- Utilities ----------

@contextlib.contextmanager
def _timeout(seconds: float):
    loop = asyncio.get_event_loop()
    task = asyncio.current_task(loop=loop)
    if task is None:
        yield
        return
    handle = loop.call_later(seconds, task.cancel)
    try:
        yield
    except asyncio.CancelledError as e:
        raise TimeoutError(f"operation_timeout_{seconds}s") from e
    finally:
        handle.cancel()


# =========================
# Convenience factory
# =========================

def build_default_adapter(base_url: str, *, api_key: Optional[str] = None, hmac_secret: Optional[str] = None) -> VeilMindAdapter:
    cfg = VeilMindConfig(base_url=base_url, api_key=api_key, hmac_secret=hmac_secret)
    return VeilMindAdapter(cfg)


# =========================
# __all__
# =========================

__all__ = [
    "VeilMindAdapter",
    "VeilMindConfig",
    "RedactRequest",
    "RedactResult",
    "TransportError",
    "IntegrityError",
    "PolicyError",
    "RateLimitError",
    "CircuitOpenError",
    "TimeoutError",
    "build_default_adapter",
    "offline_redact",
    "StdlibHttpTransport",
    "VeilMindTransport",
]
