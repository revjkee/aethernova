# File: zero-trust-core/zero_trust/enforcement/pep_http.py
# Purpose: Industrial-grade Zero Trust HTTP Policy Enforcement Point (PEP) for ASGI stacks.
# Compat: Python 3.10+, any ASGI app (FastAPI/Starlette/Quart/etc.)
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple

# Optional crypto for SPKI extraction from PEM (mTLS), gracefully optional.
try:
    from cryptography.hazmat.primitives.serialization import load_pem_x509_certificate  # type: ignore
    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    _HAVE_CRYPTO = False


# =========================
# Public Settings
# =========================

@dataclass
class PEPSettings:
    # Skips/downgrades
    skip_paths: Tuple[str, ...] = ("/health", "/ready", "/metrics")
    allow_cors_preflight: bool = True

    # Binding policies
    require_binding_paths: Tuple[str, ...] = ("POST:/admin/*", "GET:/internal/keys/*")
    dpop_required_percent: int = 0  # gradual rollout 0..100

    # Headers and extraction
    request_id_header: str = "x-request-id"
    propagated_subject_headers: bool = True
    forwarded_for_header: str = "x-forwarded-for"
    real_ip_header: str = "x-real-ip"

    # mTLS extraction via reverse proxy
    mtls_spki_header: str = "x-mtls-spki"      # precomputed SPKI SHA-256 (hex or base64)
    mtls_pem_header: str = "ssl-client-cert"   # PEM cert (URL-decoded by proxy); requires cryptography to parse

    # DPoP
    dpop_header: str = "dpop"          # raw DPoP JWT (optional, PDP may compute jkt)
    dpop_jkt_header: str = "dpop-jkt"  # precomputed JWK thumbprint (base64url)

    # Introspection cache
    cache_enabled: bool = True
    cache_ttl: float = 1.0  # seconds; keep tiny to reduce staleness
    cache_max_entries: int = 20000

    # Response shaping
    www_authenticate_realm: str = "ZeroTrust"
    problem_type_base: str = "about:blank"  # or your doc endpoint

    # Safe body sampling (for audit hooks surrounding the PEP)
    sample_request_body: bool = False
    sample_max_bytes: int = 2048

    # Environment integration
    def load_env(self) -> "PEPSettings":
        def _get(name: str, default: Any) -> str:
            return os.getenv(name, default)
        self.request_id_header = _get("ZT_HTTP_REQ_ID", self.request_id_header)
        self.dpop_required_percent = int(os.getenv("ZT_BINDING_DPOP_PERCENT", str(self.dpop_required_percent)))
        r = os.getenv("ZT_BINDING_REQUIRE_PATHS")
        if r:
            self.require_binding_paths = tuple(x for x in r.split(",") if x)
        s = os.getenv("ZT_PEP_SKIP_PATHS")
        if s:
            self.skip_paths = tuple(x for x in s.split(",") if x)
        return self


# =========================
# Decision & Verifier Interfaces
# =========================

@dataclass
class AuthzDecision:
    allow: bool
    step_up_required: bool = False
    error: str = ""
    # principal/session
    subject_id: str = ""
    tenant_id: str = ""
    roles: Tuple[str, ...] = tuple()
    session_id: str = ""
    token_id: str = ""
    risk_action: str = "allow"  # allow|step_up|deny
    risk_score: int = 0
    # cnf-binding
    cnf_type: str = "none"      # none|dpop_jkt|mtls_x5t_s256|jwk_thumbprint
    cnf_value: str = ""
    # obligations: headers to set for upstream if allowed
    obligations: Dict[str, str] = field(default_factory=dict)


class TokenVerifier:
    """
    Abstract verification interface. Implement in your authn service library.
    It must validate:
      - Token presence and signature/claims (iss/aud/exp/nbf/sub/tenant)
      - Optional PoP/DPoP binding (via jkt from DPoP JWT or precomputed)
      - Optional mTLS binding (SPKI SHA-256)
      - Policy decision (allow/step_up/deny) per method/path and risk
    """
    async def verify(
        self,
        *,
        method: str,
        path: str,
        token: str,
        audience: str,
        request_id: str,
        dpop: Optional[str],
        dpop_jkt: Optional[str],
        peer_spki_sha256: Optional[str],
        require_binding: bool,
        client_ip: str,
        headers: Mapping[str, str],
    ) -> AuthzDecision:
        raise NotImplementedError


# =========================
# Lightweight TTL cache (token -> decision)
# =========================

class _TTLCache:
    __slots__ = ("ttl", "max_entries", "_store")

    def __init__(self, ttl: float, max_entries: int) -> None:
        self.ttl = ttl
        self.max_entries = max_entries
        self._store: Dict[str, Tuple[float, AuthzDecision]] = {}

    def get(self, key: str) -> Optional[AuthzDecision]:
        now = time.monotonic()
        item = self._store.get(key)
        if not item:
            return None
        exp, val = item
        if exp < now:
            self._store.pop(key, None)
            return None
        return val

    def put(self, key: str, val: AuthzDecision) -> None:
        if len(self._store) >= self.max_entries:
            # cheap eviction: drop random old-ish item
            self._store.pop(next(iter(self._store)), None)
        self._store[key] = (time.monotonic() + self.ttl, val)


# =========================
# Utilities
# =========================

_BEARER_RE = re.compile(r"^\s*Bearer\s+([A-Za-z0-9\-\._~\+\/]+=*)\s*$", re.IGNORECASE)

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _normalize_headers(items: Iterable[Tuple[bytes, bytes]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in items:
        name = k.decode("latin1").strip().lower()
        val = v.decode("latin1").strip()
        out[name] = f"{out[name]},{val}" if name in out else val
    return out

def _path_matches(path: str, patterns: Iterable[str]) -> bool:
    for p in patterns:
        if not p:
            continue
        if p.endswith("*"):
            if path.startswith(p[:-1]):
                return True
        elif path == p:
            return True
    return False

def _match_method_path(method: str, path: str, patterns: Iterable[str]) -> bool:
    key = f"{method.upper()}:{path}"
    for p in patterns:
        if p.endswith("*"):
            if key.startswith(p[:-1]):
                return True
        elif key == p:
            return True
    return False

def _gen_request_id() -> str:
    return str(uuid.uuid4())

def _extract_client_ip(headers: Mapping[str, str], scope: Mapping[str, Any], st: PEPSettings) -> Tuple[str, str]:
    fwd = headers.get(st.forwarded_for_header, "")
    real = headers.get(st.real_ip_header, "")
    client = "-"
    if fwd:
        client = fwd.split(",")[0].strip()
    elif real:
        client = real.strip()
    else:
        client_addr = scope.get("client")
        if isinstance(client_addr, (list, tuple)) and client_addr:
            client = str(client_addr[0])
    return client, fwd

def _extract_bearer(md: Mapping[str, str]) -> Optional[str]:
    v = md.get("authorization", "")
    if not v:
        return None
    m = _BEARER_RE.match(v)
    if not m:
        return None
    return m.group(1)

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("ascii", errors="ignore")).hexdigest()

def _extract_dpop(md: Mapping[str, str], st: PEPSettings) -> Tuple[Optional[str], Optional[str]]:
    return (md.get(st.dpop_header), md.get(st.dpop_jkt_header))

def _spki_from_pem(pem_str: str) -> Optional[str]:
    if not _HAVE_CRYPTO:
        return None
    try:
        pem_bytes = pem_str.encode("utf-8")
        cert = load_pem_x509_certificate(pem_bytes)
        pub = cert.public_key()
        # Use default encoding/format for key type to get SubjectPublicKeyInfo
        enc = pub.public_bytes.__defaults__[0]  # type: ignore
        fmt = pub.public_bytes.__defaults__[1]  # type: ignore
        spki = pub.public_bytes(enc, fmt)
        return hashlib.sha256(spki).hexdigest()
    except Exception:
        return None

def _extract_peer_spki(headers: Mapping[str, str], st: PEPSettings) -> Optional[str]:
    # Prefer explicit SPKI header from ingress
    spki = headers.get(st.mtls_spki_header)
    if spki:
        # normalize
        s = spki.strip()
        if re.fullmatch(r"[0-9a-fA-F]{64}", s):
            return s.lower()
        try:
            raw = base64.b64decode(s, validate=True)
            return hashlib.sha256(raw).hexdigest()
        except Exception:
            pass
    # Or PEM if provided
    pem = headers.get(st.mtls_pem_header)
    if pem:
        # Many proxies URL-encode PEM; attempt to decode %
        try:
            from urllib.parse import unquote_plus
            pem = unquote_plus(pem)
        except Exception:
            pass
        return _spki_from_pem(pem)
    return None

def _problem(status: int, title: str, detail: str, st: PEPSettings, request_id: str, extra: Optional[Dict[str, Any]] = None) -> Tuple[int, Dict[str, str], bytes]:
    body: Dict[str, Any] = {
        "type": st.problem_type_base,
        "title": title,
        "status": status,
        "detail": detail,
        "request_id": request_id,
        "ts": _now_iso(),
    }
    if extra:
        body.update(extra)
    data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    headers = {
        "content-type": "application/problem+json; charset=utf-8",
        st.request_id_header: request_id,
        "cache-control": "no-store",
    }
    return status, headers, data


# =========================
# ASGI PEP Middleware
# =========================

class HttpPolicyEnforcementPoint:
    """
    ASGI middleware that enforces Zero Trust authentication and binding policies.

    Typical usage with FastAPI:
        app = FastAPI()
        verifier = YourTokenVerifier(...)
        pep = HttpPolicyEnforcementPoint(app, verifier, audience="api://default", settings=PEPSettings().load_env())
        app.add_middleware(lambda app: pep)  # or app.middleware("http")(pep) for Starlette style

    The middleware:
      - Skips health/metrics
      - Extracts Authorization, DPoP, mTLS SPKI
      - Requires binding for configured METHOD:/path/*
      - Delegates verification/authorization to TokenVerifier
      - On allow: attaches auth context to request.state.zt_auth and forwards
      - On step-up: 401 with WWW-Authenticate and JSON problem
      - On deny: 401/403 with JSON problem
    """

    def __init__(
        self,
        app: Callable,
        verifier: TokenVerifier,
        *,
        audience: str = "api://default",
        settings: Optional[PEPSettings] = None,
    ) -> None:
        self.app = app
        self.verifier = verifier
        self.settings = (settings or PEPSettings()).load_env()
        self.audience = audience
        self._cache = _TTLCache(self.settings.cache_ttl, self.settings.cache_max_entries) if self.settings.cache_enabled else None

    async def __call__(self, scope: Mapping[str, Any], receive: Callable, send: Callable) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        method: str = scope.get("method", "GET").upper()
        path: str = scope.get("path", "/")
        # Skip endpoints
        if _path_matches(path, self.settings.skip_paths):
            await self.app(scope, receive, send)
            return
        # CORS preflight
        if self.settings.allow_cors_preflight and method == "OPTIONS":
            await self.app(scope, receive, send)
            return

        headers_raw: List[Tuple[bytes, bytes]] = scope.get("headers", [])  # type: ignore
        headers = _normalize_headers(headers_raw)

        # Request ID
        request_id = headers.get(self.settings.request_id_header, "") or _gen_request_id()

        # Client IP
        client_ip, fwd_chain = _extract_client_ip(headers, scope, self.settings)

        # Extract credentials
        token = _extract_bearer(headers)
        dpop, dpop_jkt = _extract_dpop(headers, self.settings)
        peer_spki = _extract_peer_spki(headers, self.settings)

        # If endpoint is public (e.g., OpenAPI), verifier can still decide allow without token
        require_binding = _match_method_path(method, path, self.settings.require_binding_paths)

        # Cache lookup (only if we have a token)
        cache_key = None
        if self._cache and token:
            # Scope cache by method+path because PDP may depend on it
            cache_key = f"{method}:{path}:{_hash_token(token)}:{bool(require_binding)}:{dpop_jkt or ''}:{peer_spki or ''}"
            cached = self._cache.get(cache_key)
            if cached:
                if cached.allow:
                    await self._on_allow(scope, receive, send, request_id, cached)
                else:
                    await self._on_deny(send, request_id, cached, method, path)
                return

        # If token missing, immediately challenge unless verifier allows anonymous methods
        if not token:
            await self._challenge_unauth(send, request_id, "missing bearer token")
            return

        # Delegate to verifier
        try:
            decision = await self.verifier.verify(
                method=method,
                path=path,
                token=token,
                audience=self.audience,
                request_id=request_id,
                dpop=dpop,
                dpop_jkt=dpop_jkt,
                peer_spki_sha256=peer_spki,
                require_binding=require_binding,
                client_ip=client_ip,
                headers=headers,
            )
        except Exception:
            # Do not leak details
            await self._challenge_unauth(send, request_id, "token verification error")
            return

        # Cache decision (short TTL)
        if self._cache and cache_key:
            self._cache.put(cache_key, decision)

        # Enforce decision
        if not decision.allow:
            await self._on_deny(send, request_id, decision, method, path)
            return
        if decision.step_up_required:
            await self._on_stepup(send, request_id, decision)
            return

        await self._on_allow(scope, receive, send, request_id, decision)

    # =========================
    # Decision Handlers
    # =========================

    async def _on_allow(
        self,
        scope: Mapping[str, Any],
        receive: Callable,
        send: Callable,
        request_id: str,
        decision: AuthzDecision,
    ) -> None:
        # Attach auth context to request.state
        state = scope.setdefault("state", {})  # type: ignore
        state["zt_auth"] = {
            "subject_id": decision.subject_id,
            "tenant_id": decision.tenant_id,
            "roles": list(decision.roles),
            "session_id": decision.session_id,
            "token_id": decision.token_id,
            "risk_action": decision.risk_action,
            "risk_score": decision.risk_score,
            "cnf_type": decision.cnf_type,
            "cnf_value": decision.cnf_value,
            "request_id": request_id,
        }

        # Intercept response start to inject headers (request id, subject)
        async def _send(message: Mapping[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                # append headers
                hdrs: List[Tuple[bytes, bytes]] = list(message.get("headers", []))
                hdrs.append((self.settings.request_id_header.encode("ascii"), request_id.encode("ascii")))
                if self.settings.propagated_subject_headers:
                    if decision.subject_id:
                        hdrs.append((b"x-subject-id", decision.subject_id.encode("utf-8")))
                    if decision.tenant_id:
                        hdrs.append((b"x-tenant-id", decision.tenant_id.encode("utf-8")))
                # obligations from PDP (safe, short values only)
                for k, v in (decision.obligations or {}).items():
                    try:
                        hdrs.append((k.lower().encode("ascii"), str(v).encode("utf-8")))
                    except Exception:
                        continue
                message = dict(message)
                message["headers"] = hdrs
            await send(message)

        await self.app(scope, receive, _send)

    async def _on_stepup(self, send: Callable, request_id: str, decision: AuthzDecision) -> None:
        # 401 with hint; WWW-Authenticate includes step_up methods if known
        status, headers, body = _problem(
            401,
            "step_up_required",
            decision.error or "additional authentication is required",
            self.settings,
            request_id,
            extra={"risk_action": decision.risk_action, "risk_score": decision.risk_score},
        )
        headers["www-authenticate"] = f'Bearer realm="{self.settings.www_authenticate_realm}", error="insufficient_authentication"'
        await _send_response(send, status, headers, body)

    async def _on_deny(self, send: Callable, request_id: str, decision: AuthzDecision, method: str, path: str) -> None:
        # 401 for unauthenticated, 403 for authenticated-but-forbidden; here we use 401 unless PDP indicates otherwise
        code = 401 if decision.error.lower().startswith("unauth") or not decision.subject_id else 403
        status, headers, body = _problem(
            code,
            "access_denied",
            decision.error or "access denied",
            self.settings,
            request_id,
            extra={
                "risk_action": decision.risk_action,
                "risk_score": decision.risk_score,
                "method": method,
                "path": path,
            },
        )
        if code == 401:
            headers["www-authenticate"] = f'Bearer realm="{self.settings.www_authenticate_realm}", error="invalid_token"'
        await _send_response(send, status, headers, body)

    async def _challenge_unauth(self, send: Callable, request_id: str, reason: str) -> None:
        status, headers, body = _problem(
            401,
            "unauthenticated",
            reason,
            self.settings,
            request_id,
        )
        headers["www-authenticate"] = f'Bearer realm="{self.settings.www_authenticate_realm}", error="invalid_request"'
        await _send_response(send, status, headers, body)


# =========================
# ASGI send helper
# =========================

async def _send_response(send: Callable, status: int, headers: Mapping[str, str], body: bytes) -> None:
    hdr_bytes = [(k.encode("ascii"), v.encode("latin1")) for k, v in headers.items()]
    await send({"type": "http.response.start", "status": status, "headers": hdr_bytes})
    await send({"type": "http.response.body", "body": body})


# =========================
# Example stub verifier (DO NOT USE IN PROD)
# =========================

class ExampleVerifier(TokenVerifier):
    """
    Development-only verifier: trusts any non-empty token, simulates binding checks.
    Replace with production verifier that validates JWT/JWE, cnf (DPoP/mTLS), and policy with your PDP.
    """
    def __init__(self, *, allow_anonymous_paths: Tuple[str, ...] = ("/docs", "/openapi.json")) -> None:
        self.allow_anonymous_paths = allow_anonymous_paths

    async def verify(
        self,
        *,
        method: str,
        path: str,
        token: str,
        audience: str,
        request_id: str,
        dpop: Optional[str],
        dpop_jkt: Optional[str],
        peer_spki_sha256: Optional[str],
        require_binding: bool,
        client_ip: str,
        headers: Mapping[str, str],
    ) -> AuthzDecision:
        if not token:
            # allow some anonymous read-only endpoints
            if path in self.allow_anonymous_paths and method == "GET":
                return AuthzDecision(allow=True, subject_id="", tenant_id="")
            return AuthzDecision(allow=False, error="unauthenticated")

        if require_binding and not (dpop_jkt or peer_spki_sha256):
            return AuthzDecision(allow=False, error="binding required (DPoP or mTLS)")

        # Fake subject/session claims for demo
        principal = {
            "subject_id": "sub-123",
            "tenant_id": "acme",
            "roles": ("user",),
        }
        session = {
            "session_id": "sess-xyz",
            "token_id": "tok-abc",
            "risk_action": "allow",
            "risk_score": 5,
        }
        return AuthzDecision(
            allow=True,
            subject_id=principal["subject_id"],
            tenant_id=principal["tenant_id"],
            roles=principal["roles"],
            session_id=session["session_id"],
            token_id=session["token_id"],
            risk_action=session["risk_action"],
            risk_score=session["risk_score"],
            cnf_type="dpop_jkt" if dpop_jkt else ("mtls_x5t_s256" if peer_spki_sha256 else "none"),
            cnf_value=dpop_jkt or (peer_spki_sha256 or ""),
            obligations={"x-authenticated": "true"},
        )


# =========================
# Integration hints (commented)
# =========================
# FastAPI:
#   from fastapi import FastAPI
#   app = FastAPI()
#   pep = HttpPolicyEnforcementPoint(app, verifier=ExampleVerifier(), audience="api://default")
#   app.middleware("http")(pep)
#
# In route handlers (FastAPI/Starlette):
#   from fastapi import Request
#   async def handler(req: Request):
#       ac = getattr(req.state, "zt_auth", {})
#       ...
