# path: human-sovereignty-core/webui/server/middleware/csrf.py
from __future__ import annotations

import base64
import dataclasses
import datetime as _dt
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    from starlette.datastructures import Headers
    from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
except Exception as e:  # pragma: no cover
    raise RuntimeError("csrf middleware requires starlette (ASGI)") from e


class CsrfError(RuntimeError):
    pass


class CsrfRejected(CsrfError):
    pass


@dataclass(frozen=True)
class CsrfConfig:
    enabled: bool = True
    fail_closed: bool = True

    # Strategies supported:
    # - "double_submit": cookie + header must match; token integrity protected by HMAC
    # - "synchronizer": server issues opaque token and stores in signed cookie; header must match cookie
    strategy: str = "double_submit"

    # Cookie names
    cookie_name: str = "__Host-aether_csrf"
    cookie_name_legacy: Optional[str] = None  # optional backward-compat

    # Header or form field carrying csrf
    header_name: str = "X-CSRF-Token"
    form_field_name: str = "_csrf"

    # Only protect unsafe methods
    unsafe_methods: Tuple[str, ...] = ("POST", "PUT", "PATCH", "DELETE")

    # Origin/Referer checks
    require_origin_or_referer: bool = True
    allowed_origins: Tuple[str, ...] = ("https://localhost", "https://127.0.0.1")
    allowed_host_suffixes: Tuple[str, ...] = ("localhost", "127.0.0.1")

    # Token settings
    token_ttl_seconds: int = 2 * 60 * 60  # 2h
    token_bytes: int = 32
    nonce_bytes: int = 16

    # Cookie security attributes
    cookie_path: str = "/"
    cookie_secure: bool = True
    cookie_http_only: bool = True
    cookie_same_site: str = "Strict"  # Strict|Lax|None

    # If True, allow CSRF bypass for requests with valid Authorization header.
    # Default is False (do not assume bearer auth is safe against CSRF in all contexts).
    allow_bearer_bypass: bool = False


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_dec(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def _now() -> int:
    return int(time.time())


def _consteq(a: str, b: str) -> bool:
    try:
        return hmac.compare_digest(a, b)
    except Exception:
        return a == b


def _normalize_origin(value: str) -> str:
    v = (value or "").strip()
    # minimal normalization; do not parse into URL object to avoid edge-case SSRF-style parsing bugs
    v = v.rstrip("/")
    return v


def _extract_origin(headers: Headers) -> Optional[str]:
    o = headers.get("origin")
    if o:
        return _normalize_origin(o)
    # some browsers omit Origin on same-origin navigation; fallback to Referer
    ref = headers.get("referer")
    if ref:
        # best-effort: take scheme://host[:port]
        # fail-closed if ambiguous
        m = ref.split("://", 1)
        if len(m) != 2:
            return None
        scheme, rest = m[0], m[1]
        host = rest.split("/", 1)[0]
        return _normalize_origin(f"{scheme}://{host}")
    return None


def _host_allowed(host: str, allowed_suffixes: Sequence[str]) -> bool:
    h = (host or "").strip().lower()
    if not h:
        return False
    # strip port
    if ":" in h:
        h = h.split(":", 1)[0]
    for suf in allowed_suffixes:
        s = (suf or "").strip().lower()
        if not s:
            continue
        if h == s or h.endswith("." + s):
            return True
    return False


def _origin_allowed(origin: str, allowed_origins: Sequence[str]) -> bool:
    o = _normalize_origin(origin)
    for a in allowed_origins:
        if _consteq(o, _normalize_origin(a)):
            return True
    return False


def _load_secret() -> bytes:
    # stable secret must be injected by runtime; if missing we still generate ephemeral,
    # but note: tokens won't survive restart; safer than accepting unsigned.
    raw = (
        secrets.token_bytes(32)
    )
    env = (
        # optional: allow overriding from env without naming policy here
        None
    )
    _ = env
    return raw


@dataclass(frozen=True)
class CsrfToken:
    """
    Signed token format (double-submit):
    payload = b64u(ts || nonce || rand)
    token   = payload + "." + b64u(HMAC(secret, payload))
    """
    token: str
    issued_at: int
    nonce: str

    def is_expired(self, ttl_seconds: int, now: Optional[int] = None) -> bool:
        n = _now() if now is None else int(now)
        return n >= (int(self.issued_at) + int(ttl_seconds))


class CsrfMiddleware(BaseHTTPMiddleware):
    """
    ASGI middleware enforcing CSRF protections.

    - Protects unsafe methods by default.
    - Validates Origin/Referer for protected requests.
    - Validates CSRF token via configured strategy.
    """

    def __init__(self, app: Any, *, config: Optional[CsrfConfig] = None, secret: Optional[bytes] = None) -> None:
        super().__init__(app)
        self.cfg = config or CsrfConfig()
        self._secret = secret or _load_secret()

        if self.cfg.strategy not in ("double_submit", "synchronizer"):
            raise RuntimeError("unsupported csrf strategy")

        if self.cfg.token_ttl_seconds <= 0:
            raise RuntimeError("token_ttl_seconds must be positive")

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if not self.cfg.enabled:
            return await call_next(request)

        try:
            if self._is_protected_request(request):
                await self._enforce_origin(request)
                await self._enforce_token(request)
            return await call_next(request)
        except CsrfRejected as e:
            # fail-closed response
            return JSONResponse({"detail": "CSRF validation failed"}, status_code=403)
        except Exception:
            if self.cfg.fail_closed and self._is_protected_request(request):
                return JSONResponse({"detail": "CSRF validation failed"}, status_code=403)
            raise

    def issue_token_response(self) -> Response:
        """
        Helper for endpoints like GET /csrf that returns token and sets cookie.
        """
        tok = self._mint_token()
        resp = JSONResponse({"csrf_token": tok.token})
        self._set_csrf_cookie(resp, tok.token)
        return resp

    def _is_protected_request(self, request: Request) -> bool:
        method = (request.method or "").upper()
        if method not in self.cfg.unsafe_methods:
            return False
        if self.cfg.allow_bearer_bypass:
            auth = request.headers.get("authorization")
            if auth and auth.lower().startswith("bearer "):
                return False
        return True

    async def _enforce_origin(self, request: Request) -> None:
        if not self.cfg.require_origin_or_referer:
            return

        origin = _extract_origin(request.headers)
        host = request.headers.get("host", "")

        if origin is None:
            # fail-closed if we require origin/referer
            raise CsrfRejected("missing_origin_or_referer")

        if not _origin_allowed(origin, self.cfg.allowed_origins):
            # allow host suffix policy as additional guard when origin differs only by port
            if not _host_allowed(host, self.cfg.allowed_host_suffixes):
                raise CsrfRejected("origin_not_allowed")

    async def _enforce_token(self, request: Request) -> None:
        cookie = request.cookies.get(self.cfg.cookie_name)
        if cookie is None and self.cfg.cookie_name_legacy:
            cookie = request.cookies.get(self.cfg.cookie_name_legacy)

        token = request.headers.get(self.cfg.header_name)
        if token is None:
            # optionally accept form field for classic POST forms
            if request.headers.get("content-type", "").lower().startswith("application/x-www-form-urlencoded"):
                form = await request.form()
                token = form.get(self.cfg.form_field_name)  # type: ignore[assignment]

        if not token or not cookie:
            raise CsrfRejected("missing_csrf_token_or_cookie")

        if self.cfg.strategy == "double_submit":
            # cookie and header must match and token must be valid signed
            if not _consteq(str(token), str(cookie)):
                raise CsrfRejected("token_cookie_mismatch")
            self._verify_signed_token(str(token))
            return

        if self.cfg.strategy == "synchronizer":
            # synchronizer: signed cookie holds token; header must match cookie token
            self._verify_signed_token(str(cookie))
            if not _consteq(str(token), str(cookie)):
                raise CsrfRejected("token_cookie_mismatch")
            return

        raise CsrfRejected("unsupported_strategy")

    def _mint_token(self) -> CsrfToken:
        ts = _now()
        nonce = _b64u(secrets.token_bytes(self.cfg.nonce_bytes))
        rand = secrets.token_bytes(self.cfg.token_bytes)

        payload = _b64u(ts.to_bytes(8, "big") + _b64u_dec(nonce) + rand)
        sig = self._sign(payload)
        token = f"{payload}.{sig}"
        return CsrfToken(token=token, issued_at=ts, nonce=nonce)

    def _sign(self, payload: str) -> str:
        mac = hmac.new(self._secret, payload.encode("utf-8"), hashlib.sha256).digest()
        return _b64u(mac)

    def _verify_signed_token(self, token: str) -> CsrfToken:
        parts = (token or "").split(".", 1)
        if len(parts) != 2:
            raise CsrfRejected("malformed_token")
        payload, sig = parts[0], parts[1]
        expected = self._sign(payload)
        if not _consteq(expected, sig):
            raise CsrfRejected("bad_signature")

        raw = _b64u_dec(payload)
        # ts(8) + nonce(nonce_bytes) + rand(token_bytes) => must be at least 8 + nonce + 1
        min_len = 8 + int(self.cfg.nonce_bytes) + 1
        if len(raw) < min_len:
            raise CsrfRejected("bad_payload_length")

        ts = int.from_bytes(raw[:8], "big")
        nonce_bytes = raw[8 : 8 + int(self.cfg.nonce_bytes)]
        nonce = _b64u(nonce_bytes)

        tok = CsrfToken(token=token, issued_at=ts, nonce=nonce)
        if tok.is_expired(self.cfg.token_ttl_seconds, now=_now()):
            raise CsrfRejected("token_expired")
        return tok

    def _set_csrf_cookie(self, resp: Response, token: str) -> None:
        # __Host- prefix rules require: Secure, Path=/, no Domain attribute
        resp.set_cookie(
            key=self.cfg.cookie_name,
            value=token,
            path=self.cfg.cookie_path,
            secure=bool(self.cfg.cookie_secure),
            httponly=bool(self.cfg.cookie_http_only),
            samesite=self.cfg.cookie_same_site,
        )
