from __future__ import annotations

import contextvars
import secrets
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

try:
    from starlette.types import ASGIApp, Message, Receive, Scope, Send
except Exception:  # pragma: no cover
    ASGIApp = Any  # type: ignore
    Scope = Dict[str, Any]  # type: ignore
    Receive = Any  # type: ignore
    Send = Any  # type: ignore
    Message = Dict[str, Any]  # type: ignore


request_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("request_id", default=None)
trace_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("trace_id", default=None)


_REQUEST_ID_HEADER_DEFAULT = "x-request-id"
_TRACE_ID_HEADER_DEFAULT = "x-trace-id"
_CORRELATION_ID_HEADER_DEFAULT = "x-correlation-id"

# Accept:
# - UUIDv4 hex without dashes: 32 hex chars
# - UUID with dashes
# - base32/base64url-like safe tokens: 16..128 chars
_REQID_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}|[A-Za-z0-9_-]{16,128})$")


def _now_epoch_seconds() -> int:
    return int(time.time())


def _normalize_header_name(name: str) -> str:
    if not isinstance(name, str) or not name.strip():
        raise ValueError("header name must be non-empty string")
    return name.strip().lower()


def _decode_headers(scope: Scope) -> Dict[str, str]:
    raw = scope.get("headers") or []
    out: Dict[str, str] = {}
    for k, v in raw:
        try:
            ks = k.decode("latin-1").lower()
            vs = v.decode("latin-1")
        except Exception:
            continue
        if ks not in out:
            out[ks] = vs
    return out


def _encode_headers(headers: Iterable[Tuple[str, str]]) -> List[Tuple[bytes, bytes]]:
    out: List[Tuple[bytes, bytes]] = []
    for k, v in headers:
        out.append((k.encode("latin-1"), v.encode("latin-1")))
    return out


def _is_valid_request_id(value: str) -> bool:
    if not isinstance(value, str) or not value:
        return False
    v = value.strip()
    if not v:
        return False
    if len(v) > 128:
        return False
    return bool(_REQID_RE.fullmatch(v))


def _generate_request_id() -> str:
    # 128-bit token, base64url-safe without padding (22 chars typical), but allow 24.
    # Use a stable length to reduce fingerprinting variance.
    return secrets.token_urlsafe(16)


def get_request_id() -> Optional[str]:
    return request_id_var.get()


def get_trace_id() -> Optional[str]:
    return trace_id_var.get()


@dataclass(frozen=True, slots=True)
class RequestIdConfig:
    request_id_header: str = _REQUEST_ID_HEADER_DEFAULT
    trace_id_header: str = _TRACE_ID_HEADER_DEFAULT
    correlation_id_header: str = _CORRELATION_ID_HEADER_DEFAULT

    trust_incoming_headers: bool = False
    emit_response_headers: bool = True

    # If incoming headers are not trusted, middleware will still read them
    # for correlation, but will generate its own authoritative ids.
    # If true, invalid incoming values will be dropped.
    strict_incoming_validation: bool = True

    # Optional prefix for internally generated ids to distinguish origin.
    internal_prefix: str = "hs"

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id_header", _normalize_header_name(self.request_id_header))
        object.__setattr__(self, "trace_id_header", _normalize_header_name(self.trace_id_header))
        object.__setattr__(self, "correlation_id_header", _normalize_header_name(self.correlation_id_header))

        if not isinstance(self.trust_incoming_headers, bool):
            raise ValueError("trust_incoming_headers must be bool")
        if not isinstance(self.emit_response_headers, bool):
            raise ValueError("emit_response_headers must be bool")
        if not isinstance(self.strict_incoming_validation, bool):
            raise ValueError("strict_incoming_validation must be bool")

        if not isinstance(self.internal_prefix, str):
            raise ValueError("internal_prefix must be string")
        p = self.internal_prefix.strip()
        if not p:
            raise ValueError("internal_prefix must be non-empty")
        if len(p) > 16:
            raise ValueError("internal_prefix too long")
        object.__setattr__(self, "internal_prefix", p)


def _build_internal_id(prefix: str) -> str:
    token = _generate_request_id()
    # Ensure we keep within 128 length constraints.
    return f"{prefix}-{token}"


class RequestIdASGIMiddleware:
    """
    ASGI middleware:
    - sets request_id and trace_id into contextvars
    - optionally emits headers back in response
    - supports safe incoming header handling

    Works with Starlette/FastAPI as raw ASGI middleware.
    """

    def __init__(self, app: ASGIApp, config: Optional[RequestIdConfig] = None) -> None:
        self.app = app
        self.cfg = config or RequestIdConfig()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        headers = _decode_headers(scope)
        incoming_rid = headers.get(self.cfg.request_id_header)
        incoming_tid = headers.get(self.cfg.trace_id_header)
        incoming_cid = headers.get(self.cfg.correlation_id_header)

        def _sanitize_incoming(v: Optional[str]) -> Optional[str]:
            if v is None:
                return None
            vv = v.strip()
            if not vv:
                return None
            if self.cfg.strict_incoming_validation and not _is_valid_request_id(vv):
                return None
            return vv

        incoming_rid = _sanitize_incoming(incoming_rid)
        incoming_tid = _sanitize_incoming(incoming_tid)
        incoming_cid = _sanitize_incoming(incoming_cid)

        if self.cfg.trust_incoming_headers:
            rid = incoming_rid or _build_internal_id(self.cfg.internal_prefix)
            tid = incoming_tid or rid
        else:
            rid = _build_internal_id(self.cfg.internal_prefix)
            tid = _build_internal_id(self.cfg.internal_prefix)

        cid = incoming_cid or rid

        rid_token = request_id_var.set(rid)
        tid_token = trace_id_var.set(tid)

        async def send_wrapper(message: Message) -> None:
            if self.cfg.emit_response_headers and message.get("type") == "http.response.start":
                raw_headers: List[Tuple[bytes, bytes]] = list(message.get("headers") or [])
                # Do not duplicate if already set by upstream.
                lower_existing = {k.decode("latin-1").lower() for k, _ in raw_headers}

                to_add: List[Tuple[str, str]] = []
                if self.cfg.request_id_header not in lower_existing:
                    to_add.append((self.cfg.request_id_header, rid))
                if self.cfg.trace_id_header not in lower_existing:
                    to_add.append((self.cfg.trace_id_header, tid))
                if self.cfg.correlation_id_header not in lower_existing:
                    to_add.append((self.cfg.correlation_id_header, cid))

                # Add a minimal server timestamp for correlation if desired by sinks.
                # Kept as stable integer seconds.
                if "x-server-time" not in lower_existing:
                    to_add.append(("x-server-time", str(_now_epoch_seconds())))

                raw_headers.extend(_encode_headers(to_add))
                message["headers"] = raw_headers

            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            # Ensure context cleanup to prevent leakage across requests.
            request_id_var.reset(rid_token)
            trace_id_var.reset(tid_token)


class RequestIdWSGIMiddleware:
    """
    WSGI middleware (legacy support).
    - stores request id in environ
    - emits response header
    """

    def __init__(self, app: Callable[..., Any], config: Optional[RequestIdConfig] = None) -> None:
        self.app = app
        self.cfg = config or RequestIdConfig()

    def __call__(self, environ: Dict[str, Any], start_response: Callable[..., Any]) -> Any:
        # WSGI header normalization: HTTP_X_REQUEST_ID
        def _env_header(name: str) -> str:
            return "HTTP_" + name.upper().replace("-", "_")

        incoming_rid = environ.get(_env_header(self.cfg.request_id_header))
        incoming_tid = environ.get(_env_header(self.cfg.trace_id_header))
        incoming_cid = environ.get(_env_header(self.cfg.correlation_id_header))

        def _sanitize(v: Any) -> Optional[str]:
            if v is None:
                return None
            if not isinstance(v, str):
                return None
            vv = v.strip()
            if not vv:
                return None
            if self.cfg.strict_incoming_validation and not _is_valid_request_id(vv):
                return None
            return vv

        incoming_rid = _sanitize(incoming_rid)
        incoming_tid = _sanitize(incoming_tid)
        incoming_cid = _sanitize(incoming_cid)

        if self.cfg.trust_incoming_headers:
            rid = incoming_rid or _build_internal_id(self.cfg.internal_prefix)
            tid = incoming_tid or rid
        else:
            rid = _build_internal_id(self.cfg.internal_prefix)
            tid = _build_internal_id(self.cfg.internal_prefix)

        cid = incoming_cid or rid

        environ["hs.request_id"] = rid
        environ["hs.trace_id"] = tid
        environ["hs.correlation_id"] = cid

        rid_token = request_id_var.set(rid)
        tid_token = trace_id_var.set(tid)

        def _start_response(status: str, headers: List[Tuple[str, str]], exc_info: Any = None) -> Any:
            if self.cfg.emit_response_headers:
                existing = {k.lower() for k, _ in headers}
                if self.cfg.request_id_header not in existing:
                    headers.append((self.cfg.request_id_header, rid))
                if self.cfg.trace_id_header not in existing:
                    headers.append((self.cfg.trace_id_header, tid))
                if self.cfg.correlation_id_header not in existing:
                    headers.append((self.cfg.correlation_id_header, cid))
                if "x-server-time" not in existing:
                    headers.append(("x-server-time", str(_now_epoch_seconds())))
            return start_response(status, headers, exc_info)

        try:
            return self.app(environ, _start_response)
        finally:
            request_id_var.reset(rid_token)
            trace_id_var.reset(tid_token)
