# File: zero-trust-core/api/grpc/interceptors/auth.py
# Purpose: Industrial-grade Zero Trust auth interceptor for gRPC (sync and asyncio)
# Python: 3.10+

from __future__ import annotations

import binascii
import hashlib
import logging
import os
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, Mapping, Optional, Sequence, Tuple

try:
    import grpc
    from grpc import HandlerCallDetails, ServerInterceptor
except Exception as _e:  # pragma: no cover
    grpc = None  # type: ignore
    HandlerCallDetails = object  # type: ignore
    ServerInterceptor = object  # type: ignore

try:
    from grpc import aio as grpc_aio  # type: ignore
except Exception:  # pragma: no cover
    grpc_aio = None  # type: ignore

# Optional: compute SPKI SHA-256 from peer cert
try:
    from cryptography import x509  # type: ignore
    from cryptography.hazmat.primitives.serialization import load_pem_x509_certificate
    from cryptography.hazmat.primitives import hashes
    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    _HAVE_CRYPTO = False


# =========================
# Public settings and models
# =========================

@dataclass
class Settings:
    audience: str = "api://default"
    require_binding_for_methods: Tuple[str, ...] = (
        "/zero.trust.v1.Admin/*",
        "/zero.trust.v1.Secrets/*",
    )
    allow_unauthenticated_methods: Tuple[str, ...] = (
        "/grpc.health.v1.Health/Check",
        "/grpc.health.v1.Health/Watch",
        "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    )
    request_id_header: str = "x-request-id"
    propagate_subject_headers: bool = True  # add subject/tenant to trailing metadata
    log_name: str = "zt.grpc.auth"
    log_level: int = logging.INFO

    def load_env(self) -> "Settings":
        self.audience = os.getenv("ZT_GRPC_AUD", self.audience)
        def _list(env: str, default: Tuple[str, ...]) -> Tuple[str, ...]:
            v = os.getenv(env)
            return tuple([s for s in (v.split(",") if v else []) if s]) or default
        self.require_binding_for_methods = _list("ZT_GRPC_REQUIRE_BINDING", self.require_binding_for_methods)
        self.allow_unauthenticated_methods = _list("ZT_GRPC_ALLOW_UNAUTH", self.allow_unauthenticated_methods)
        self.request_id_header = os.getenv("ZT_GRPC_REQ_ID", self.request_id_header)
        self.log_name = os.getenv("ZT_GRPC_LOG", self.log_name)
        try:
            self.log_level = getattr(logging, os.getenv("ZT_GRPC_LOG_LEVEL", "").upper(), self.log_level)
        except Exception:
            pass
        return self


@dataclass
class AuthContext:
    subject_id: str = ""
    tenant_id: str = ""
    roles: Tuple[str, ...] = ()
    session_id: str = ""
    token_id: str = ""
    risk_action: str = "allow"  # allow|step_up|deny
    risk_score: int = 0
    cnf_type: str = "none"      # none|dpop_jkt|mtls_x5t_s256|jwk_thumbprint
    cnf_value: str = ""
    binding_required: bool = False
    peer_spki_sha256: str = ""  # base64 or hex (implementation-defined)
    dpop_jkt: str = ""          # base64url JWK thumbprint if provided
    request_id: str = ""
    full_method: str = ""       # /package.Service/Method


@dataclass
class AuthzDecision:
    allow: bool
    step_up_required: bool = False
    principal: Dict[str, Any] = field(default_factory=dict)  # subject_id, tenant_id, roles
    session: Dict[str, Any] = field(default_factory=dict)    # session_id, token_id, risk_action, risk_score
    cnf: Dict[str, str] = field(default_factory=dict)        # type, value
    error: str = ""


class TokenVerifier:
    """
    Interface for token verification.
    Implement verify() to validate Bearer token and cnf-binding.
    """
    def verify(
        self,
        token: str,
        *,
        audience: str,
        method: str,
        dpop_jkt: Optional[str],
        peer_spki_sha256: Optional[str],
        require_binding: bool,
        metadata: Mapping[str, str],
    ) -> AuthzDecision:
        raise NotImplementedError


# =========================
# Utilities
# =========================

_BEARER_RE = re.compile(r"^\s*Bearer\s+([A-Za-z0-9\-\._~\+\/]+=*)\s*$", re.IGNORECASE)


def _logger(name: str, level: int) -> logging.Logger:
    log = logging.getLogger(name)
    if not log.handlers:
        h = logging.StreamHandler()
        f = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        h.setFormatter(f)
        log.addHandler(h)
    log.setLevel(level)
    return log


def _gen_request_id() -> str:
    return str(uuid.uuid4())


def _meta_to_dict(meta: Optional[Sequence[Tuple[str, str]]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not meta:
        return out
    for k, v in meta:
        lk = k.strip().lower()
        out[lk] = v.strip()
    return out


def _match(full_method: str, patterns: Iterable[str]) -> bool:
    # patterns like /pkg.Svc/* or /pkg.Svc/Method
    for p in patterns:
        if p.endswith("/*"):
            if full_method.startswith(p[:-1]):
                return True
        elif full_method == p:
            return True
    return False


def _extract_bearer(md: Mapping[str, str]) -> Optional[str]:
    v = md.get("authorization", "")
    if not v:
        return None
    m = _BEARER_RE.match(v)
    if not m:
        return None
    return m.group(1)


def _extract_dpop_jkt(md: Mapping[str, str]) -> Optional[str]:
    # In gRPC metadata, DPoP may be proxied via "dpop" key (non-standard)
    # Expecting a precomputed jkt or raw DPoP JWT; for simplicity accept jkt via "dpop-jkt"
    return md.get("dpop-jkt") or None


def _auth_abort(ctx: Any, code: Any, msg: str) -> None:
    if hasattr(ctx, "abort"):
        ctx.abort(code, msg)
    # aio contexts raise exceptions in handler wrappers; abort handled by grpc runtime


def _compute_spki_sha256_from_pem(pem_bytes: bytes) -> Optional[str]:
    if not _HAVE_CRYPTO:
        return None
    try:
        cert = load_pem_x509_certificate(pem_bytes)
        spki = cert.public_key().public_bytes(
            encoding=cert.public_key().__class__.public_bytes.__defaults__[0],  # type: ignore
            format=cert.public_key().__class__.public_bytes.__defaults__[1],   # type: ignore
        )
        digest = hashlib.sha256(spki).hexdigest()
        return digest
    except Exception:
        return None


def _extract_peer_cert_spki_sha256(ctx: Any) -> Optional[str]:
    """
    Attempt to compute SPKI SHA-256 thumbprint from peer certificate via auth_context().
    Falls back to None if not available or cryptography missing.
    """
    try:
        auth_ctx = ctx.auth_context()
    except Exception:
        auth_ctx = {}
    # Common key in gRPC Python TLS: 'x509_pem_cert'
    pem_list = auth_ctx.get("x509_pem_cert") or auth_ctx.get("transport_security_type")
    if not pem_list:
        return None
    # 'x509_pem_cert' -> [b"-----BEGIN CERTIFICATE-----..."]
    for item in pem_list:
        if isinstance(item, (bytes, bytearray)) and b"BEGIN CERTIFICATE" in item:
            return _compute_spki_sha256_from_pem(bytes(item))
    return None


def _trailing(kv: Mapping[str, str]) -> Sequence[Tuple[str, str]]:
    return [(k, v) for k, v in kv.items()]


# =========================
# Core interceptor implementation
# =========================

class AuthInterceptor(ServerInterceptor):
    """
    Sync gRPC ServerInterceptor that enforces Zero Trust token and binding policies.
    """

    def __init__(self, verifier: TokenVerifier, settings: Optional[Settings] = None) -> None:
        if grpc is None:  # pragma: no cover
            raise RuntimeError("grpc is not available")
        self.verifier = verifier
        self.settings = (settings or Settings()).load_env()
        self.log = _logger(self.settings.log_name, self.settings.log_level)

    def intercept_service(
        self,
        continuation: Callable[[HandlerCallDetails], Any],
        handler_call_details: HandlerCallDetails,
    ):
        handler = continuation(handler_call_details)
        if handler is None:
            return None

        def unary_unary_wrapper(behavior):
            def _call(request, context):
                return self._handle(request, context, handler_call_details, behavior)
            return _call

        def unary_stream_wrapper(behavior):
            def _call(request, context):
                return self._handle(request, context, handler_call_details, behavior, streaming_response=True)
            return _call

        def stream_unary_wrapper(behavior):
            def _call(request_iterator, context):
                return self._handle(request_iterator, context, handler_call_details, behavior, streaming_request=True)
            return _call

        def stream_stream_wrapper(behavior):
            def _call(request_iterator, context):
                return self._handle(request_iterator, context, handler_call_details, behavior, streaming_request=True, streaming_response=True)
            return _call

        # Wrap underlying RPC handlers with our auth logic
        if handler.unary_unary:
            return grpc.unary_unary_rpc_method_handler(
                unary_unary_wrapper(handler.unary_unary),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.unary_stream:
            return grpc.unary_stream_rpc_method_handler(
                unary_stream_wrapper(handler.unary_stream),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.stream_unary:
            return grpc.stream_unary_rpc_method_handler(
                stream_unary_wrapper(handler.stream_unary),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.stream_stream:
            return grpc.stream_stream_rpc_method_handler(
                stream_stream_wrapper(handler.stream_stream),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        return handler  # pragma: no cover

    # Core per-request logic
    def _handle(
        self,
        request_or_iter,
        context: Any,
        details: HandlerCallDetails,
        behavior: Callable,
        *,
        streaming_request: bool = False,
        streaming_response: bool = False,
    ):
        method = details.method or ""
        md = _meta_to_dict(details.invocation_metadata or [])
        request_id = md.get(self.settings.request_id_header, "") or _gen_request_id()

        # Allow unauthenticated methods
        if _match(method, self.settings.allow_unauthenticated_methods):
            self._attach_trailing(context, request_id=request_id)
            return behavior(request_or_iter, context)

        token = _extract_bearer(md)
        dpop_jkt = _extract_dpop_jkt(md)
        peer_spki = _extract_peer_cert_spki_sha256(context)

        require_binding = _match(method, self.settings.require_binding_for_methods)

        if not token:
            self.log.warning("unauthenticated request", extra={"method": method, "request_id": request_id})
            context.set_trailing_metadata(_trailing({self.settings.request_id_header: request_id}))
            _auth_abort(context, grpc.StatusCode.UNAUTHENTICATED, "missing bearer token")
            return None  # unreachable

        try:
            decision = self.verifier.verify(
                token,
                audience=self.settings.audience,
                method=method,
                dpop_jkt=dpop_jkt,
                peer_spki_sha256=peer_spki,
                require_binding=require_binding,
                metadata=md,
            )
        except Exception as e:
            self.log.error("token verification failed", exc_info=True)
            context.set_trailing_metadata(_trailing({self.settings.request_id_header: request_id}))
            _auth_abort(context, grpc.StatusCode.UNAUTHENTICATED, "token verification error")
            return None  # unreachable

        if not decision.allow:
            self._attach_trailing(context, request_id=request_id)
            code = grpc.StatusCode.UNAUTHENTICATED
            msg = decision.error or "unauthenticated"
            _auth_abort(context, code, msg)
            return None  # unreachable

        if decision.step_up_required:
            self._attach_trailing(context, request_id=request_id)
            _auth_abort(context, grpc.StatusCode.PERMISSION_DENIED, "step-up required")
            return None  # unreachable

        # Build AuthContext for downstream code
        ac = AuthContext(
            subject_id=str(decision.principal.get("subject_id", "")),
            tenant_id=str(decision.principal.get("tenant_id", "")),
            roles=tuple(decision.principal.get("roles", []) or []),
            session_id=str(decision.session.get("session_id", "")),
            token_id=str(decision.session.get("token_id", "")),
            risk_action=str(decision.session.get("risk_action", "allow")),
            risk_score=int(decision.session.get("risk_score", 0) or 0),
            cnf_type=str(decision.cnf.get("type", "none")),
            cnf_value=str(decision.cnf.get("value", "")),
            binding_required=require_binding,
            peer_spki_sha256=peer_spki or "",
            dpop_jkt=dpop_jkt or "",
            request_id=request_id,
            full_method=method,
        )

        # Attach to context via user-defined attributes for later access
        setattr(context, "_zt_auth_context", ac)

        # Add trailing metadata and optional subject propagation
        trailing = {self.settings.request_id_header: request_id}
        if self.settings.propagate_subject_headers:
            if ac.subject_id:
                trailing["x-subject-id"] = ac.subject_id
            if ac.tenant_id:
                trailing["x-tenant-id"] = ac.tenant_id
        self._attach_trailing(context, **trailing)

        return behavior(request_or_iter, context)

    def _attach_trailing(self, context: Any, **kv: str) -> None:
        try:
            context.set_trailing_metadata(_trailing(kv))
        except Exception:
            pass


# =========================
# AsyncIO interceptor
# =========================

class AioAuthInterceptor(grpc_aio.ServerInterceptor if grpc_aio else object):  # type: ignore
    """
    AsyncIO gRPC ServerInterceptor with the same semantics as AuthInterceptor.
    """

    def __init__(self, verifier: TokenVerifier, settings: Optional[Settings] = None) -> None:
        if grpc_aio is None:  # pragma: no cover
            raise RuntimeError("grpc.aio is not available")
        self.verifier = verifier
        self.settings = (settings or Settings()).load_env()
        self.log = _logger(self.settings.log_name, self.settings.log_level)

    async def intercept_service(self, continuation, handler_call_details):
        handler = await continuation(handler_call_details)
        if handler is None:
            return None

        async def uu(request, context):
            return await self._handle(request, context, handler_call_details, handler.unary_unary)

        async def us(request, context):
            return await self._handle(request, context, handler_call_details, handler.unary_stream, streaming_response=True)

        async def su(request_iterator, context):
            return await self._handle(request_iterator, context, handler_call_details, handler.stream_unary, streaming_request=True)

        async def ss(request_iterator, context):
            return await self._handle(request_iterator, context, handler_call_details, handler.stream_stream, streaming_request=True, streaming_response=True)

        if handler.unary_unary:
            return grpc_aio.unary_unary_rpc_method_handler(uu, request_deserializer=handler.request_deserializer, response_serializer=handler.response_serializer)
        if handler.unary_stream:
            return grpc_aio.unary_stream_rpc_method_handler(us, request_deserializer=handler.request_deserializer, response_serializer=handler.response_serializer)
        if handler.stream_unary:
            return grpc_aio.stream_unary_rpc_method_handler(su, request_deserializer=handler.request_deserializer, response_serializer=handler.response_serializer)
        if handler.stream_stream:
            return grpc_aio.stream_stream_rpc_method_handler(ss, request_deserializer=handler.request_deserializer, response_serializer=handler.response_serializer)
        return handler  # pragma: no cover

    async def _handle(
        self,
        request_or_iter,
        context: Any,
        details: Any,
        behavior: Callable,
        *,
        streaming_request: bool = False,
        streaming_response: bool = False,
    ):
        method = details.method or ""
        md = _meta_to_dict(details.invocation_metadata or [])
        request_id = md.get(self.settings.request_id_header, "") or _gen_request_id()

        # Allow unauthenticated methods
        if _match(method, self.settings.allow_unauthenticated_methods):
            await self._attach_trailing(context, request_id=request_id)
            return await behavior(request_or_iter, context)

        token = _extract_bearer(md)
        dpop_jkt = _extract_dpop_jkt(md)
        peer_spki = _extract_peer_cert_spki_sha256(context)

        require_binding = _match(method, self.settings.require_binding_for_methods)

        if not token:
            self.log.warning("unauthenticated request", extra={"method": method, "request_id": request_id})
            await self._attach_trailing(context, request_id=request_id)
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "missing bearer token")
            return None  # unreachable

        try:
            decision = self.verifier.verify(
                token,
                audience=self.settings.audience,
                method=method,
                dpop_jkt=dpop_jkt,
                peer_spki_sha256=peer_spki,
                require_binding=require_binding,
                metadata=md,
            )
        except Exception:
            self.log.error("token verification failed", exc_info=True)
            await self._attach_trailing(context, request_id=request_id)
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "token verification error")
            return None  # unreachable

        if not decision.allow:
            await self._attach_trailing(context, request_id=request_id)
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, decision.error or "unauthenticated")
            return None  # unreachable

        if decision.step_up_required:
            await self._attach_trailing(context, request_id=request_id)
            await context.abort(grpc.StatusCode.PERMISSION_DENIED, "step-up required")
            return None  # unreachable

        ac = AuthContext(
            subject_id=str(decision.principal.get("subject_id", "")),
            tenant_id=str(decision.principal.get("tenant_id", "")),
            roles=tuple(decision.principal.get("roles", []) or []),
            session_id=str(decision.session.get("session_id", "")),
            token_id=str(decision.session.get("token_id", "")),
            risk_action=str(decision.session.get("risk_action", "allow")),
            risk_score=int(decision.session.get("risk_score", 0) or 0),
            cnf_type=str(decision.cnf.get("type", "none")),
            cnf_value=str(decision.cnf.get("value", "")),
            binding_required=require_binding,
            peer_spki_sha256=peer_spki or "",
            dpop_jkt=dpop_jkt or "",
            request_id=request_id,
            full_method=method,
        )
        setattr(context, "_zt_auth_context", ac)

        trailing = {self.settings.request_id_header: request_id}
        if self.settings.propagate_subject_headers:
            if ac.subject_id:
                trailing["x-subject-id"] = ac.subject_id
            if ac.tenant_id:
                trailing["x-tenant-id"] = ac.tenant_id
        await self._attach_trailing(context, **trailing)

        return await behavior(request_or_iter, context)

    async def _attach_trailing(self, context: Any, **kv: str) -> None:
        try:
            await context.set_trailing_metadata(_trailing(kv))
        except Exception:
            pass


# =========================
# Helpers for application code
# =========================

def get_auth_context(ctx: Any) -> AuthContext:
    """
    Retrieve AuthContext from ServicerContext in handlers.
    """
    return getattr(ctx, "_zt_auth_context", AuthContext())


# =========================
# Example verifier (stub)
# =========================

class ExampleVerifier(TokenVerifier):
    """
    Stub verifier for development and tests. Do not use in production.
    Replace with real implementation that validates JWT signature, claims and cnf-binding.
    """
    def verify(
        self,
        token: str,
        *,
        audience: str,
        method: str,
        dpop_jkt: Optional[str],
        peer_spki_sha256: Optional[str],
        require_binding: bool,
        metadata: Mapping[str, str],
    ) -> AuthzDecision:
        # Example: accept any non-empty token, simulate binding if required
        if require_binding and not (dpop_jkt or peer_spki_sha256):
            return AuthzDecision(allow=False, error="binding required")
        principal = {"subject_id": "sub-123", "tenant_id": "acme", "roles": ["user"]}
        session = {"session_id": "sess-xyz", "token_id": "tok-abc", "risk_action": "allow", "risk_score": 10}
        cnf = {}
        if dpop_jkt:
            cnf = {"type": "dpop_jkt", "value": dpop_jkt}
        elif peer_spki_sha256:
            cnf = {"type": "mtls_x5t_s256", "value": peer_spki_sha256}
        return AuthzDecision(allow=True, principal=principal, session=session, cnf=cnf)


# =========================
# Usage examples (comments)
# =========================
# Sync:
#   server = grpc.server(futures.ThreadPoolExecutor(), interceptors=[AuthInterceptor(YourVerifier(), Settings().load_env())])
#
# Async:
#   server = grpc_aio.server(interceptors=[AioAuthInterceptor(YourVerifier(), Settings().load_env())])
#
# In a handler:
#   def GetSecret(self, request, context):
#       ac = get_auth_context(context)
#       if "admin" not in ac.roles:
#           context.abort(grpc.StatusCode.PERMISSION_DENIED, "admin role required")
#       ...
