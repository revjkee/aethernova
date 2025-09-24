from __future__ import annotations

import asyncio
import base64
import dataclasses
import datetime as dt
import functools
import hmac
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Awaitable, Callable, Dict, Mapping, MutableMapping, Optional, Sequence, Tuple, TypedDict, Union

# Optional deps: httpx, cryptography, PyJWT
try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # lazy-optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
    from cryptography.hazmat.primitives.hashes import Hash, SHA256  # type: ignore
    from cryptography.hazmat.primitives.serialization import load_pem_public_key  # type: ignore
    from cryptography.exceptions import InvalidTag  # type: ignore
except Exception:  # pragma: no cover
    AESGCM = None

try:
    import jwt  # PyJWT  # type: ignore
    from jwt import PyJWKClient  # type: ignore
except Exception:  # pragma: no cover
    jwt = None
    PyJWKClient = None


# ----------------------------- Logging (structured JSON) -----------------------------

class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = {
            "ts": dt.datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            base["exc_info"] = self.formatException(record.exc_info)
        # Attach extra fields if present
        for k, v in record.__dict__.items():
            if k in ("msg", "args", "created", "levelname", "name", "exc_info"):
                continue
            if k.startswith("_"):  # hide internals
                continue
            try:
                json.dumps(v)  # ensure serializable
                base[k] = v
            except Exception:
                base[k] = repr(v)
        return json.dumps(base, separators=(",", ":"), ensure_ascii=False)

def _setup_default_logger(name: str = "oblivionvault.security") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonLogFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


LOGGER = _setup_default_logger()


# ----------------------------- Errors -----------------------------

class SecurityCoreError(Exception): ...
class TransportError(SecurityCoreError): ...
class TokenVerificationError(SecurityCoreError): ...
class AuthorizationDenied(SecurityCoreError): ...
class CryptoError(SecurityCoreError): ...
class ConfigurationError(SecurityCoreError): ...


# ----------------------------- Utility -----------------------------

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _ub64u(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + pad).encode("ascii"))

def _redact(value: Optional[str], keep: int = 4) -> str:
    if not value:
        return ""
    return value[:keep] + "..." + str(len(value))

def _now_utc() -> dt.datetime:
    return dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc)

def _ct_eq(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    if isinstance(a, str): a = a.encode()
    if isinstance(b, str): b = b.encode()
    return hmac.compare_digest(a, b)


# ----------------------------- Data Models -----------------------------

@dataclass(frozen=True)
class SecurityCoreSettings:
    endpoint: Optional[str] = None
    api_key: Optional[str] = None
    jwks_url: Optional[str] = None
    issuer: Optional[str] = None
    audience: Optional[str] = None
    request_timeout_s: float = 5.0
    max_retries: int = 3
    retry_backoff_base_ms: int = 100
    circuit_fail_threshold: int = 8
    circuit_half_open_after_s: float = 15.0
    cache_ttl_s: int = 300
    kms_key_id: Optional[str] = None
    audit_channel: Optional[str] = None  # logical stream name
    mtls_cert: Optional[str] = None
    mtls_key: Optional[str] = None
    verify_tls: bool = True

    def validate(self) -> None:
        if not self.endpoint and not self.jwks_url:
            # allowed for fully-local flows, but warn
            LOGGER.warning("No endpoint/jwks_url configured; remote features disabled.")
        if self.request_timeout_s <= 0:
            raise ConfigurationError("request_timeout_s must be > 0")
        if self.max_retries < 0:
            raise ConfigurationError("max_retries must be >= 0")


@dataclass(frozen=True)
class Principal:
    sub: str
    roles: Tuple[str, ...] = field(default_factory=tuple)
    attrs: Mapping[str, Any] = field(default_factory=dict)
    exp: Optional[int] = None
    iat: Optional[int] = None
    iss: Optional[str] = None
    aud: Optional[Union[str, Sequence[str]]] = None


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str
    policy_id: Optional[str] = None
    obligations: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SealedBlob:
    v: int
    alg: str
    kms_key_id: str
    iv: str
    tag: str
    wrapped_key: str
    aad: Optional[str]
    ct: str
    created: str
    meta: Mapping[str, Any] = field(default_factory=dict)


# ----------------------------- Transport Abstraction -----------------------------

class AsyncTransport:
    async def get(self, path: str, headers: Mapping[str, str] | None = None, params: Mapping[str, Any] | None = None) -> Dict[str, Any]:
        raise NotImplementedError

    async def post(self, path: str, json_body: Mapping[str, Any], headers: Mapping[str, str] | None = None) -> Dict[str, Any]:
        raise NotImplementedError


class HttpxTransport(AsyncTransport):
    def __init__(self, base_url: str, timeout_s: float, verify_tls: bool, api_key: Optional[str] = None,
                 mtls_cert: Optional[str] = None, mtls_key: Optional[str] = None) -> None:
        if httpx is None:
            raise TransportError("httpx is required for HttpxTransport")
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=timeout_s,
            verify=verify_tls,
            cert=(mtls_cert, mtls_key) if (mtls_cert and mtls_key) else None,
        )
        self._api_key = api_key

    async def _headers(self, extra: Mapping[str, str] | None) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self._api_key:
            h["Authorization"] = f"Bearer {self._api_key}"
        if extra:
            h.update(extra)
        return h

    async def get(self, path: str, headers: Mapping[str, str] | None = None, params: Mapping[str, Any] | None = None) -> Dict[str, Any]:
        try:
            resp = await self._client.get(path, headers=await self._headers(headers), params=params or {})
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            raise TransportError(str(e)) from e

    async def post(self, path: str, json_body: Mapping[str, Any], headers: Mapping[str, str] | None = None) -> Dict[str, Any]:
        try:
            resp = await self._client.post(path, headers=await self._headers(headers), json=json_body)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            raise TransportError(str(e)) from e

    async def aclose(self) -> None:
        await self._client.aclose()


class NullTransport(AsyncTransport):
    async def get(self, path: str, headers: Mapping[str, str] | None = None, params: Mapping[str, Any] | None = None) -> Dict[str, Any]:
        raise TransportError("No transport configured")
    async def post(self, path: str, json_body: Mapping[str, Any], headers: Mapping[str, str] | None = None) -> Dict[str, Any]:
        raise TransportError("No transport configured")


# ----------------------------- Circuit Breaker & Retry -----------------------------

class _Circuit:
    def __init__(self, threshold: int, half_open_after_s: float) -> None:
        self.threshold = threshold
        self.half_open_after_s = half_open_after_s
        self.failures = 0
        self.opened_at: Optional[float] = None
        self._lock = asyncio.Lock()

    async def on_success(self) -> None:
        async with self._lock:
            self.failures = 0
            self.opened_at = None

    async def on_failure(self) -> None:
        async with self._lock:
            self.failures += 1
            if self.failures >= self.threshold and self.opened_at is None:
                self.opened_at = time.time()

    async def allow(self) -> bool:
        async with self._lock:
            if self.opened_at is None:
                return True
            if (time.time() - self.opened_at) >= self.half_open_after_s:
                # half-open: allow one trial
                self.failures = max(0, self.threshold - 1)
                self.opened_at = None
                return True
            return False


async def _retry_call(coro_factory: Callable[[], Awaitable[Any]],
                      retries: int, base_backoff_ms: int, circuit: _Circuit, op_name: str) -> Any:
    attempt = 0
    while True:
        if not await circuit.allow():
            raise TransportError(f"Circuit open for operation: {op_name}")
        try:
            result = await coro_factory()
            await circuit.on_success()
            return result
        except TransportError as e:
            attempt += 1
            await circuit.on_failure()
            if attempt > retries:
                raise
            sleep_ms = base_backoff_ms * (2 ** (attempt - 1))
            jitter = secrets.randbelow(max(1, sleep_ms // 2))
            await asyncio.sleep((sleep_ms + jitter) / 1000.0)


# ----------------------------- Cache (TTL) -----------------------------

class _TTLCache:
    def __init__(self, ttl_s: int) -> None:
        self.ttl = ttl_s
        self._store: Dict[str, Tuple[float, Any]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            v = self._store.get(key)
            if not v:
                return None
            exp, val = v
            if time.time() > exp:
                self._store.pop(key, None)
                return None
            return val

    async def set(self, key: str, val: Any) -> None:
        async with self._lock:
            self._store[key] = (time.time() + self.ttl, val)


# ----------------------------- Audit (hash chain) -----------------------------

@dataclass
class _AuditState:
    prev_hash: str = field(default_factory=lambda: _b64u(os.urandom(32)))
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

class AuditEvent(TypedDict, total=False):
    ts: str
    actor: str
    action: str
    resource: str
    allow: bool
    reason: str
    meta: Dict[str, Any]
    prev_hash: str
    hash: str
    channel: str

def _hash_event(ev: Mapping[str, Any]) -> str:
    data = json.dumps(ev, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return _b64u(sha256(data).digest())


# ----------------------------- Adapter -----------------------------

class SecurityCoreAdapter:
    def __init__(self, settings: SecurityCoreSettings,
                 transport: Optional[AsyncTransport] = None,
                 audit_sink: Optional[Callable[[AuditEvent], Awaitable[None]]] = None,
                 logger: Optional[logging.Logger] = None) -> None:
        settings.validate()
        self.settings = settings
        self.transport = transport or (HttpxTransport(settings.endpoint, settings.request_timeout_s, settings.verify_tls,
                                                     settings.api_key, settings.mtls_cert, settings.mtls_key)
                                       if settings.endpoint else NullTransport())
        self.logger = logger or LOGGER
        self.circuit = _Circuit(settings.circuit_fail_threshold, settings.circuit_half_open_after_s)
        self.cache = _TTLCache(settings.cache_ttl_s)
        self._jwks_client: Optional[PyJWKClient] = None
        self._audit_state = _AuditState()
        self._audit_sink = audit_sink or self._default_audit_sink

    # ----------------- Public API -----------------

    async def verify_token(self, token: str) -> Principal:
        if not token:
            raise TokenVerificationError("Empty token")
        try:
            if self.settings.jwks_url:
                if jwt is None or PyJWKClient is None:
                    raise TokenVerificationError("PyJWT required for JWKS verification")
                if self._jwks_client is None:
                    self._jwks_client = PyJWKClient(self.settings.jwks_url)  # JWKS cache handled by client
                signing_key = self._jwks_client.get_signing_key_from_jwt(token)
                options = {"require": ["exp", "iat"], "verify_signature": True}
                decoded = jwt.decode(
                    token,
                    signing_key.key,
                    algorithms=["RS256", "ES256", "EdDSA"],
                    audience=self.settings.audience,
                    issuer=self.settings.issuer,
                    options=options,
                )
            else:
                decoded = await self._remote_introspect(token)

            return Principal(
                sub=str(decoded.get("sub") or decoded.get("uid") or ""),
                roles=tuple(decoded.get("roles") or ()),
                attrs=decoded.get("attr") or decoded.get("claims") or {},
                exp=decoded.get("exp"), iat=decoded.get("iat"),
                iss=decoded.get("iss"), aud=decoded.get("aud"),
            )
        except TokenVerificationError:
            raise
        except Exception as e:
            raise TokenVerificationError(str(e)) from e

    async def authorize(self, principal: Principal, action: str, resource: str,
                        context: Optional[Mapping[str, Any]] = None) -> Decision:
        body = {
            "subject": {"id": principal.sub, "roles": list(principal.roles), "attrs": dict(principal.attrs)},
            "action": action,
            "resource": resource,
            "context": dict(context or {}),
        }
        async def call() -> Dict[str, Any]:
            return await self.transport.post("/v1/policy/authorize", body)

        if isinstance(self.transport, NullTransport):
            # Secure-by-default: deny when no policy backend
            decision = Decision(False, "No policy backend configured", None, {})
            await self._audit(principal.sub, action, resource, decision)
            raise AuthorizationDenied(decision.reason)

        try:
            resp = await _retry_call(call, self.settings.max_retries, self.settings.retry_backoff_base_ms, self.circuit, "authorize")
        except TransportError as e:
            decision = Decision(False, f"Transport error: {e}", None, {})
            await self._audit(principal.sub, action, resource, decision)
            raise AuthorizationDenied(decision.reason) from e

        allow = bool(resp.get("allow"))
        decision = Decision(allow=allow, reason=str(resp.get("reason", "")),
                            policy_id=resp.get("policy_id"), obligations=resp.get("obligations") or {})
        await self._audit(principal.sub, action, resource, decision)
        if not allow:
            raise AuthorizationDenied(decision.reason)
        return decision

    async def seal(self, plaintext: bytes, aad: Optional[bytes] = None,
                   meta: Optional[Mapping[str, Any]] = None) -> SealedBlob:
        if AESGCM is None:
            raise CryptoError("cryptography is required for AES-GCM")
        if not self.settings.kms_key_id:
            raise CryptoError("kms_key_id must be configured")

        dek = os.urandom(32)
        iv = os.urandom(12)
        aes = AESGCM(dek)
        ct = aes.encrypt(iv, plaintext, aad)
        tag = ct[-16:]
        ct_no_tag = ct[:-16]
        try:
            wrapped = await self._kms_wrap(dek)
        finally:
            del dek  # minimize key lifetime

        blob = SealedBlob(
            v=1,
            alg="AES-256-GCM+KMS",
            kms_key_id=self.settings.kms_key_id,
            iv=_b64u(iv),
            tag=_b64u(tag),
            wrapped_key=_b64u(wrapped),
            aad=_b64u(aad) if aad else None,
            ct=_b64u(ct_no_tag),
            created=_now_utc().isoformat(),
            meta=dict(meta or {}),
        )
        return blob

    async def unseal(self, blob: SealedBlob, aad: Optional[bytes] = None) -> bytes:
        if AESGCM is None:
            raise CryptoError("cryptography is required for AES-GCM")
        if blob.alg != "AES-256-GCM+KMS" or blob.v != 1:
            raise CryptoError("Unsupported blob format")

        dek = await self._kms_unwrap(_ub64u(blob.wrapped_key))
        aes = AESGCM(dek)
        ct = _ub64u(blob.ct) + _ub64u(blob.tag)
        iv = _ub64u(blob.iv)
        aad_bytes = _ub64u(blob.aad) if blob.aad else aad
        try:
            pt = aes.decrypt(iv, ct, aad_bytes)
            return pt
        except InvalidTag as e:
            raise CryptoError("AEAD tag verification failed") from e
        finally:
            del dek

    async def sign(self, payload: bytes, key_id: Optional[str] = None, alg: str = "EdDSA") -> str:
        kid = key_id or self.settings.kms_key_id
        if not kid:
            raise CryptoError("kms_key_id must be configured for signing")
        body = {"key_id": kid, "alg": alg, "payload": _b64u(payload)}
        async def call() -> Dict[str, Any]:
            return await self.transport.post("/v1/crypto/sign", body)

        resp = await _retry_call(call, self.settings.max_retries, self.settings.retry_backoff_base_ms, self.circuit, "sign")
        sig = resp.get("signature")
        if not isinstance(sig, str):
            raise CryptoError("Invalid signature response")
        return sig

    async def verify(self, payload: bytes, signature: str, key_id: Optional[str] = None, alg: str = "EdDSA") -> bool:
        kid = key_id or self.settings.kms_key_id
        if not kid:
            raise CryptoError("kms_key_id must be configured for verify")
        body = {"key_id": kid, "alg": alg, "payload": _b64u(payload), "signature": signature}
        async def call() -> Dict[str, Any]:
            return await self.transport.post("/v1/crypto/verify", body)

        resp = await _retry_call(call, self.settings.max_retries, self.settings.retry_backoff_base_ms, self.circuit, "verify")
        ok = bool(resp.get("valid"))
        return ok

    # ----------------- Internals -----------------

    async def _remote_introspect(self, token: str) -> Dict[str, Any]:
        if isinstance(self.transport, NullTransport):
            raise TokenVerificationError("No transport for token introspection")
        body = {"token": token, "audience": self.settings.audience, "issuer": self.settings.issuer}
        async def call() -> Dict[str, Any]:
            return await self.transport.post("/v1/auth/introspect", body)
        try:
            resp = await _retry_call(call, self.settings.max_retries, self.settings.retry_backoff_base_ms, self.circuit, "introspect")
            if not resp.get("active", False):
                raise TokenVerificationError("Token inactive")
            return resp.get("claims") or {}
        except TransportError as e:
            raise TokenVerificationError(str(e)) from e

    async def _kms_wrap(self, dek: bytes) -> bytes:
        if isinstance(self.transport, NullTransport):
            # Local dev fallback: never use in prod; included to keep adapter functional without backend
            salt = sha256((self.settings.kms_key_id or "local") .encode()).digest()
            return hmac.new(salt, dek, sha256).digest()
        body = {"key_id": self.settings.kms_key_id, "dek": _b64u(dek)}
        async def call() -> Dict[str, Any]:
            return await self.transport.post("/v1/kms/wrap", body)
        resp = await _retry_call(call, self.settings.max_retries, self.settings.retry_backoff_base_ms, self.circuit, "kms_wrap")
        wrapped = resp.get("wrapped")
        if not isinstance(wrapped, str):
            raise CryptoError("Invalid KMS wrap response")
        return _ub64u(wrapped)

    async def _kms_unwrap(self, wrapped: bytes) -> bytes:
        if isinstance(self.transport, NullTransport):
            # not possible to unwrap deterministic HMAC; deny
            raise CryptoError("No KMS backend configured for unwrap")
        body = {"key_id": self.settings.kms_key_id, "wrapped": _b64u(wrapped)}
        async def call() -> Dict[str, Any]:
            return await self.transport.post("/v1/kms/unwrap", body)
        resp = await _retry_call(call, self.settings.max_retries, self.settings.retry_backoff_base_ms, self.circuit, "kms_unwrap")
        dek_b64 = resp.get("dek")
        if not isinstance(dek_b64, str):
            raise CryptoError("Invalid KMS unwrap response")
        return _ub64u(dek_b64)

    async def _default_audit_sink(self, event: AuditEvent) -> None:
        # Sink to log only; replace via DI for SIEM/S3/etc.
        self.logger.info("audit", extra={"audit": event})

    async def _audit(self, actor: str, action: str, resource: str, decision: Decision, meta: Optional[Dict[str, Any]] = None) -> None:
        async with self._audit_state.lock:
            prev = self._audit_state.prev_hash
            e: AuditEvent = {
                "ts": _now_utc().isoformat(),
                "actor": actor,
                "action": action,
                "resource": resource,
                "allow": decision.allow,
                "reason": decision.reason,
                "meta": dict(meta or {}),
                "prev_hash": prev,
                "channel": self.settings.audit_channel or "default",
            }
            e["hash"] = _hash_event({k: v for k, v in e.items() if k != "hash"})
            self._audit_state.prev_hash = e["hash"]
        try:
            await self._audit_sink(e)
        except Exception as sink_err:  # never break main flow due to audit
            self.logger.error("audit_sink_failed", extra={"error": repr(sink_err)})

    # ----------------- Context manager (optional) -----------------

    async def aclose(self) -> None:
        if isinstance(self.transport, HttpxTransport):
            try:
                await self.transport.aclose()  # type: ignore[attr-defined]
            except Exception:
                pass

    async def __aenter__(self) -> "SecurityCoreAdapter":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()


__all__ = [
    "SecurityCoreSettings",
    "SecurityCoreAdapter",
    "Principal",
    "Decision",
    "SealedBlob",
    "SecurityCoreError",
    "TransportError",
    "TokenVerificationError",
    "AuthorizationDenied",
    "CryptoError",
    "ConfigurationError",
    "AsyncTransport",
    "HttpxTransport",
    "NullTransport",
]
