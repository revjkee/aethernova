# file: security-core/api/grpc/server.py
from __future__ import annotations

import asyncio
import base64
import logging
import os
import signal
import time
import types
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, Optional, Tuple

import grpc
from grpc.aio import ServerInterceptor, ServicerContext

# ===== Generated protobuf imports =====
# Adjust import path to your generated modules layout.
try:
    # Example: python_out placed under security_core/schemas/proto/v1/security
    from security_core.schemas.proto.v1.security import authn_pb2, authn_pb2_grpc
except Exception:
    # Fallback if using package "aethernova.security.v1" from option go/java/csharp namespace
    from aethernova.security.v1 import authn_pb2, authn_pb2_grpc  # type: ignore

# Health & reflection
from grpc_health.v1 import health, health_pb2_grpc
from grpc_reflection.v1alpha import reflection

# =========================
# ===== Configuration  =====
# =========================

GRPC_HOST = os.getenv("GRPC_HOST", "0.0.0.0")
GRPC_PORT = int(os.getenv("GRPC_PORT", "7001"))
GRPC_MAX_WORKERS = int(os.getenv("GRPC_MAX_WORKERS", "64"))
GRPC_MAX_CONCURRENCY = int(os.getenv("GRPC_MAX_CONCURRENCY", "0"))  # 0 = unlimited
GRPC_MAX_RECV_MB = int(os.getenv("GRPC_MAX_RECV_MB", "16"))
GRPC_MAX_SEND_MB = int(os.getenv("GRPC_MAX_SEND_MB", "16"))
GRPC_KEEPALIVE_TIME_SEC = int(os.getenv("GRPC_KEEPALIVE_TIME_SEC", "60"))
GRPC_KEEPALIVE_TIMEOUT_SEC = int(os.getenv("GRPC_KEEPALIVE_TIMEOUT_SEC", "20"))
GRPC_KEEPALIVE_PERMIT_WITHOUT_CALLS = int(os.getenv("GRPC_KEEPALIVE_PERMIT_WITHOUT_CALLS", "1"))

TLS_CERT = os.getenv("GRPC_TLS_CERT")  # path to server cert (PEM)
TLS_KEY = os.getenv("GRPC_TLS_KEY")    # path to private key (PEM)

DEV_MOCK = os.getenv("SECURITY_CORE_DEV_MOCK", "0") == "1"

# =========================
# ===== Logging setup  =====
# =========================

logger = logging.getLogger("security_core.grpc")
_log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, _log_level, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

def redact_token(val: Optional[str]) -> str:
    if not val:
        return ""
    if len(val) <= 8:
        return "****"
    return val[:4] + "…" + val[-3:]

# ===============================
# ===== Request ID context  =====
# ===============================

@dataclass
class RequestCtx:
    request_id: str
    start_ts: float

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if dt else None

def _get_meta(md: Iterable[Tuple[str, str]], key: str) -> Optional[str]:
    for k, v in md:
        if k.lower() == key.lower():
            return v
    return None

class RequestIdInterceptor(ServerInterceptor):
    async def intercept_service(self, continuation, handler_call_details):
        method = handler_call_details.method
        md = handler_call_details.invocation_metadata or ()
        rid = _get_meta(md, "x-request-id") or str(uuid.uuid4())
        ctx = RequestCtx(request_id=rid, start_ts=time.time())

        # attach ctx into 'context' via closure
        handler = await continuation(handler_call_details)

        async def wrap_unary_unary(request, context: ServicerContext):
            try:
                context.set_trailing_metadata((("x-request-id", rid),))
                return await handler.unary_unary(request, context)  # type: ignore[attr-defined]
            finally:
                dur = (time.time() - ctx.start_ts) * 1000.0
                logger.info("grpc.request",
                            extra={"rid": rid, "method": method, "duration_ms": round(dur, 2)})

        async def wrap_unary_stream(request, context: ServicerContext):
            try:
                context.set_trailing_metadata((("x-request-id", rid),))
                async for resp in handler.unary_stream(request, context):  # type: ignore[attr-defined]
                    yield resp
            finally:
                dur = (time.time() - ctx.start_ts) * 1000.0
                logger.info("grpc.request",
                            extra={"rid": rid, "method": method, "duration_ms": round(dur, 2)})

        # Support only unary-unary here (our service methods are unary-unary)
        if hasattr(handler, "unary_unary"):
            return grpc.aio.unary_unary_rpc_method_handler(
                lambda req, c: wrap_unary_unary(req, c),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if hasattr(handler, "unary_stream"):
            return grpc.aio.unary_stream_rpc_method_handler(
                lambda req, c: wrap_unary_stream(req, c),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        return handler

class ExceptionInterceptor(ServerInterceptor):
    async def intercept_service(self, continuation, handler_call_details):
        handler = await continuation(handler_call_details)

        async def wrap_unary_unary(request, context: ServicerContext):
            try:
                return await handler.unary_unary(request, context)  # type: ignore[attr-defined]
            except grpc.RpcError:
                raise
            except Exception as e:
                logger.exception("grpc.unhandled", extra={"method": handler_call_details.method})
                context.set_code(grpc.StatusCode.INTERNAL)
                context.set_details("internal error")
                return types.SimpleNamespace()  # empty response

        if hasattr(handler, "unary_unary"):
            return grpc.aio.unary_unary_rpc_method_handler(
                lambda req, c: wrap_unary_unary(req, c),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        return handler

# ====================================
# ===== Domain service abstraction  ===
# ====================================

class AuthDomainService:
    async def begin_password_auth(self, identifier: str, password: str, context: dict) -> Tuple[Dict[str, Any], Dict[str, Any] | None]:
        raise NotImplementedError

    async def complete_mfa(self, challenge_id: str, proof: Dict[str, Any], context: dict) -> Dict[str, Any]:
        raise NotImplementedError

    async def start_webauthn_registration(self, principal_id: str, context: dict) -> Dict[str, Any]:
        raise NotImplementedError

    async def finish_webauthn_registration(self, principal_id: str, attestation: Dict[str, Any], context: dict) -> Dict[str, Any]:
        raise NotImplementedError

    async def start_webauthn_auth(self, identifier: Optional[str], context: dict) -> Dict[str, Any]:
        raise NotImplementedError

    async def finish_webauthn_auth(self, identifier: Optional[str], assertion: Dict[str, Any], context: dict) -> Tuple[Dict[str, Any], Dict[str, Any] | None]:
        raise NotImplementedError

    async def start_passwordless(self, identifier: str, method: str, context: dict) -> Dict[str, Any]:
        raise NotImplementedError

    async def complete_passwordless(self, req: Dict[str, Any], context: dict) -> Dict[str, Any]:
        raise NotImplementedError

    async def refresh(self, refresh_token: str, context: dict) -> Dict[str, Any]:
        raise NotImplementedError

    async def introspect(self, token: str, assumed_type: Optional[str], context: dict) -> Dict[str, Any]:
        raise NotImplementedError

    async def revoke(self, token: str, ttype: str, reason: Optional[str], context: dict) -> bool:
        raise NotImplementedError

    async def logout(self, session_id: Optional[str], context: dict) -> bool:
        raise NotImplementedError

    async def get_session(self, session_id: str) -> Dict[str, Any]:
        raise NotImplementedError

    async def list_sessions(self, principal_id: str, page_size: int, page_token: Optional[str], active_only: bool) -> Dict[str, Any]:
        raise NotImplementedError

# ====================================
# ===== DEV mock implementation    ===
# ====================================

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

class DevAuthDomainService(AuthDomainService):
    """DEV‑mock: deterministic, secure‑ish behavior for local runs only."""
    def __init__(self) -> None:
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._refresh_index: Dict[str, str] = {}  # refresh -> session_id
        self._access_index: Dict[str, str] = {}   # access -> session_id
        self._principal = {
            "id": "demo-user",
            "username": "demo",
            "display_name": "Demo User",
            "created_at": _iso(_now_utc()),
        }

    def _new_token(self) -> str:
        return uuid.uuid4().hex + uuid.uuid4().hex

    def _mk_success(self, session_id: str, access: str, refresh: str) -> Dict[str, Any]:
        now = _now_utc()
        return {
            "principal": self._principal,
            "session": {
                "id": session_id,
                "principal_id": self._principal["id"],
                "methods": ["PASSWORD"],
                "created_at": _iso(now),
                "expires_at": _iso(now + timedelta(days=7)),
                "access_token_id": access[:16],
                "refresh_token_id": refresh[:16],
            },
            "access_token": {
                "id": access[:16],
                "type": "ACCESS",
                "issuer": "aethernova://auth",
                "subject": self._principal["id"],
                "issued_at": _iso(now),
                "expires_at": _iso(now + timedelta(minutes=15)),
                "jwt_compact": access,
                "session_id": session_id,
            },
            "refresh_token": {
                "id": refresh[:16],
                "type": "REFRESH",
                "issuer": "aethernova://auth",
                "subject": self._principal["id"],
                "issued_at": _iso(now),
                "expires_at": _iso(now + timedelta(days=7)),
                "opaque": refresh,
                "session_id": session_id,
            },
            "id_token_issued": False,
        }

    async def begin_password_auth(self, identifier: str, password: str, context: dict) -> Tuple[Dict[str, Any], Dict[str, Any] | None]:
        # Password "demo123" -> success, иначе потребуем MFA
        if password == "demo123":
            session_id = str(uuid.uuid4())
            access, refresh = self._new_token(), self._new_token()
            self._sessions[session_id] = {"revoked": False}
            self._access_index[access] = session_id
            self._refresh_index[refresh] = session_id
            return self._mk_success(session_id, access, refresh), None
        else:
            ch_id = uuid.uuid4().hex
            return {}, {
                "challenge_id": ch_id,
                "allowed_methods": ["TOTP", "WEBAUTHN", "SMS_OTP"],
                "expires_at": _iso(_now_utc() + timedelta(minutes=5)),
                "risk": {"level": "MEDIUM", "score": 0.42},
                "otp": {
                    "challenge_id": ch_id,
                    "channel": "SMS",
                    "masked_destination": "+1******89",
                    "code_length": 6,
                    "expires_at": _iso(_now_utc() + timedelta(minutes=5)),
                }
            }

    async def complete_mfa(self, challenge_id: str, proof: Dict[str, Any], context: dict) -> Dict[str, Any]:
        # Accept "000000" или WebAuthn
        if proof.get("totp_code") == "000000" or proof.get("sms_code") == "000000" or proof.get("email_code") == "000000" or proof.get("recovery_code") == "RECOVER-OK" or proof.get("webauthn"):
            session_id = str(uuid.uuid4())
            access, refresh = self._new_token(), self._new_token()
            self._sessions[session_id] = {"revoked": False}
            self._access_index[access] = session_id
            self._refresh_index[refresh] = session_id
            return self._mk_success(session_id, access, refresh)
        raise grpc.RpcError(grpc.StatusCode.UNAUTHENTICATED, "MFA verification failed")  # type: ignore[arg-type]

    async def start_webauthn_registration(self, principal_id: str, context: dict) -> Dict[str, Any]:
        return {
            "challenge_b64url": _b64u(os.urandom(32)),
            "rp_id": "aethernova.local",
            "rp_name": "Aethernova",
            "user_id_b64url": _b64u(principal_id.encode()),
            "user_name": "demo",
            "user_display_name": "Demo User",
            "exclude_credentials": [],
            "resident_key_required": False,
            "user_verification_required": True,
            "expires_at": _iso(_now_utc() + timedelta(minutes=5)),
        }

    async def finish_webauthn_registration(self, principal_id: str, attestation: Dict[str, Any], context: dict) -> Dict[str, Any]:
        return {
            "credential_id_b64url": attestation.get("credential_id_b64url", ""),
            "aaguid": "00000000-0000-0000-0000-000000000000",
            "public_key_cose": b"",  # intentionally blank in mock
            "sign_count": 0,
            "attestation_format": "none",
            "transports": ["usb", "ble", "nfc", "internal"],
            "user_verification": True,
            "resident_key": False,
            "rp_id": "aethernova.local",
            "name": "Demo Passkey",
            "registered_at": _iso(_now_utc()),
        }

    async def start_webauthn_auth(self, identifier: Optional[str], context: dict) -> Dict[str, Any]:
        return {
            "challenge_b64url": _b64u(os.urandom(32)),
            "rp_id": "aethernova.local",
            "allow_credentials": [],
            "user_verification_required": True,
            "expires_at": _iso(_now_utc() + timedelta(minutes=5)),
        }

    async def finish_webauthn_auth(self, identifier: Optional[str], assertion: Dict[str, Any], context: dict) -> Tuple[Dict[str, Any], Dict[str, Any] | None]:
        session_id = str(uuid.uuid4())
        access, refresh = self._new_token(), self._new_token()
        self._sessions[session_id] = {"revoked": False}
        self._access_index[access] = session_id
        self._refresh_index[refresh] = session_id
        return self._mk_success(session_id, access, refresh), None

    async def start_passwordless(self, identifier: str, method: str, context: dict) -> Dict[str, Any]:
        if method in ("EMAIL_OTP", "SMS_OTP"):
            ch_id = uuid.uuid4().hex
            return {"otp": {
                "challenge_id": ch_id, "channel": "EMAIL" if method == "EMAIL_OTP" else "SMS",
                "masked_destination": "a***@e***.com" if method == "EMAIL_OTP" else "+1******89",
                "code_length": 6, "expires_at": _iso(_now_utc() + timedelta(minutes=5))
            }}
        if method == "EMAIL_LINK":
            return {"info": "link-sent"}
        if method == "WEBAUTHN":
            return await self.start_webauthn_auth(identifier, context)
        return {}

    async def complete_passwordless(self, req: Dict[str, Any], context: dict) -> Dict[str, Any]:
        # Accept any provided proof in mock
        session_id = str(uuid.uuid4())
        access, refresh = self._new_token(), self._new_token()
        self._sessions[session_id] = {"revoked": False}
        self._access_index[access] = session_id
        self._refresh_index[refresh] = session_id
        return self._mk_success(session_id, access, refresh)

    async def refresh(self, refresh_token: str, context: dict) -> Dict[str, Any]:
        if refresh_token not in self._refresh_index:
            raise grpc.RpcError(grpc.StatusCode.UNAUTHENTICATED, "invalid refresh")  # type: ignore[arg-type]
        old_session = self._refresh_index[refresh_token]
        access, new_refresh = self._new_token(), self._new_token()
        self._access_index[access] = old_session
        self._refresh_index[new_refresh] = old_session
        self._refresh_index.pop(refresh_token, None)
        return self._mk_success(old_session, access, new_refresh)

    async def introspect(self, token: str, assumed_type: Optional[str], context: dict) -> Dict[str, Any]:
        now = _now_utc()
        session_id = self._access_index.get(token) or self._refresh_index.get(token)
        if not session_id:
            return {"active": False, "evaluated_at": _iso(now)}
        ttype = "ACCESS" if token in self._access_index else "REFRESH"
        exp = now + (timedelta(minutes=15) if ttype == "ACCESS" else timedelta(days=7))
        return {
            "active": True,
            "token": {
                "id": token[:16], "type": ttype, "issuer": "aethernova://auth",
                "subject": self._principal["id"], "issued_at": _iso(now - timedelta(minutes=1)),
                "expires_at": _iso(exp),
                "jwt_compact": token if ttype == "ACCESS" else None,
                "opaque": token if ttype == "REFRESH" else None,
                "session_id": session_id,
            },
            "principal": self._principal,
            "session": {"id": session_id, "principal_id": self._principal["id"], "created_at": _iso(now - timedelta(minutes=1))},
            "evaluated_at": _iso(now),
        }

    async def revoke(self, token: str, ttype: str, reason: Optional[str], context: dict) -> bool:
        if ttype == "REFRESH":
            return self._refresh_index.pop(token, None) is not None
        if ttype == "ACCESS":
            return self._access_index.pop(token, None) is not None
        return False

    async def logout(self, session_id: Optional[str], context: dict) -> bool:
        if not session_id:
            return True
        if session_id in self._sessions:
            self._sessions[session_id]["revoked"] = True
            return True
        return False

    async def get_session(self, session_id: str) -> Dict[str, Any]:
        if session_id not in self._sessions:
            raise grpc.RpcError(grpc.StatusCode.NOT_FOUND, "session not found")  # type: ignore[arg-type]
        return {"id": session_id, "principal_id": self._principal["id"], "created_at": _iso(_now_utc())}

    async def list_sessions(self, principal_id: str, page_size: int, page_token: Optional[str], active_only: bool) -> Dict[str, Any]:
        items = []
        for sid in list(self._sessions.keys())[:page_size]:
            items.append({"id": sid, "principal_id": principal_id, "created_at": _iso(_now_utc())})
        return {"sessions": items, "next_page_token": None}

# ====================================
# ===== gRPC Servicer binding      ===
# ====================================

class AuthnGrpcServer(authn_pb2_grpc.AuthenticationServiceServicer):
    def __init__(self, domain: AuthDomainService):
        self.domain = domain

    # ----- Helpers to map domain dicts into protobuf -----

    def _pb_principal(self, d: Dict[str, Any]) -> authn_pb2.Principal:
        return authn_pb2.Principal(
            id=d.get("id", ""),
            tenant_id=d.get("tenant_id") or None,
            external_id=d.get("external_id") or None,
            username=d.get("username") or None,
            email=d.get("email") or None,
            phone_e164=d.get("phone_e164") or None,
            display_name=d.get("display_name") or None,
            roles=d.get("roles", []),
            disabled=bool(d.get("disabled", False)),
            created_at=self._ts(d.get("created_at")),
            updated_at=self._ts(d.get("updated_at")),
            attributes=d.get("attributes", {}),
        )

    def _pb_device(self, d: Optional[Dict[str, Any]]) -> Optional[authn_pb2.Device]:
        if not d:
            return None
        return authn_pb2.Device(
            id=d.get("id") or None,
            platform=getattr(authn_pb2, f"PLATFORM_{(d.get('platform') or 'OTHER')}"),
            os_version=d.get("os_version") or None,
            model=d.get("model") or None,
            user_agent=d.get("user_agent") or None,
            fingerprint=d.get("fingerprint") or None,
            trusted=d.get("trusted") if d.get("trusted") is not None else False,
            compliant=d.get("compliant") if d.get("compliant") is not None else False,
            attested=d.get("attested") if d.get("attested") is not None else False,
            attestation_provider=d.get("attestation_provider") or None,
            created_at=self._ts(d.get("created_at")),
            last_seen_at=self._ts(d.get("last_seen_at")),
        )

    def _pb_risk(self, d: Optional[Dict[str, Any]]) -> Optional[authn_pb2.RiskSignals]:
        if not d:
            return None
        level = d.get("level")
        level_enum = getattr(authn_pb2, f"RISK_LEVEL_{level}", authn_pb2.RISK_LEVEL_LOW) if level else authn_pb2.RISK_LEVEL_LOW
        return authn_pb2.RiskSignals(
            level=level_enum,
            score=d.get("score") or 0.0,
            reason=d.get("reason") or "",
            anomalies=d.get("anomalies", []),
            ip_address=d.get("ip_address") or None,
            geoip_country=d.get("geoip_country") or None,
            geoip_city=d.get("geoip_city") or None,
            via_proxy=d.get("via_proxy") or False,
            via_tor=d.get("via_tor") or False,
            velocity_exceeded=d.get("velocity_exceeded") or False,
            historical_ips=d.get("historical_ips", []),
        )

    def _pb_token(self, d: Dict[str, Any]) -> authn_pb2.Token:
        alg = d.get("alg")
        alg_enum = getattr(authn_pb2, f"SIGALG_{alg}", authn_pb2.SIGALG_ED25519) if alg else authn_pb2.SIGALG_ED25519
        ttype = getattr(authn_pb2, f"TOKEN_TYPE_{d.get('type', 'ACCESS')}", authn_pb2.TOKEN_TYPE_ACCESS)
        t = authn_pb2.Token(
            id=d.get("id") or "",
            type=ttype,
            alg=alg_enum,
            key_id=d.get("key_id") or None,
            issuer=d.get("issuer") or None,
            subject=d.get("subject") or None,
            audience=d.get("audience", []),
            issued_at=self._ts(d.get("issued_at")),
            expires_at=self._ts(d.get("expires_at")),
            not_before=self._ts(d.get("not_before")),
            scopes=d.get("scopes", []),
            client_id=d.get("client_id") or None,
            session_id=d.get("session_id") or None,
        )
        if d.get("jwt_compact"):
            t.jwt_compact = d["jwt_compact"]
        elif d.get("paseto"):
            t.paseto = d["paseto"].encode() if isinstance(d["paseto"], str) else d["paseto"]
        elif d.get("opaque"):
            t.opaque = d["opaque"].encode() if isinstance(d["opaque"], str) else d["opaque"]
        if "claims" in d and isinstance(d["claims"], dict):
            from google.protobuf import struct_pb2
            st = struct_pb2.Struct()
            st.update(d["claims"])
            t.claims.CopyFrom(st)
        return t

    def _pb_session(self, d: Dict[str, Any]) -> authn_pb2.Session:
        methods = []
        for m in d.get("methods", []):
            methods.append(getattr(authn_pb2, f"AUTH_METHOD_{m}", authn_pb2.AUTH_METHOD_PASSWORD))
        return authn_pb2.Session(
            id=d.get("id", ""),
            principal_id=d.get("principal_id", ""),
            methods=methods,
            device=self._pb_device(d.get("device")),
            ip_address=d.get("ip_address") or None,
            user_agent=d.get("user_agent") or None,
            location=d.get("location") or None,
            risk=self._pb_risk(d.get("risk")),
            revoked=d.get("revoked") or False,
            revoke_reason=d.get("revoke_reason") or None,
            created_at=self._ts(d.get("created_at")),
            last_seen_at=self._ts(d.get("last_seen_at")),
            expires_at=self._ts(d.get("expires_at")),
            access_token_id=d.get("access_token_id") or None,
            refresh_token_id=d.get("refresh_token_id") or None,
        )

    def _pb_success(self, d: Dict[str, Any]) -> authn_pb2.AuthSuccess:
        out = authn_pb2.AuthSuccess(
            principal=self._pb_principal(d["principal"]),
            session=self._pb_session(d["session"]),
            access_token=self._pb_token(d["access_token"]),
            refresh_token=self._pb_token(d["refresh_token"]),
            id_token_issued=bool(d.get("id_token_issued", False)),
        )
        if d.get("id_token"):
            out.id_token.CopyFrom(self._pb_token(d["id_token"]))
        return out

    def _pb_webauthn_challenge(self, d: Dict[str, Any]) -> authn_pb2.WebAuthnAuthChallenge:
        return authn_pb2.WebAuthnAuthChallenge(
            challenge_b64url=d["challenge_b64url"],
            rp_id=d["rp_id"],
            allow_credentials=d.get("allow_credentials", []),
            user_verification_required=bool(d.get("user_verification_required", True)),
            expires_at=self._ts(d.get("expires_at")),
        )

    def _pb_webauthn_options(self, d: Dict[str, Any]) -> authn_pb2.WebAuthnRegisterOptions:
        return authn_pb2.WebAuthnRegisterOptions(
            challenge_b64url=d["challenge_b64url"],
            rp_id=d["rp_id"],
            rp_name=d["rp_name"],
            user_id_b64url=d["user_id_b64url"],
            user_name=d["user_name"],
            user_display_name=d.get("user_display_name") or "",
            exclude_credentials=d.get("exclude_credentials", []),
            resident_key_required=bool(d.get("resident_key_required", False)),
            user_verification_required=bool(d.get("user_verification_required", True)),
            expires_at=self._ts(d.get("expires_at")),
        )

    def _pb_mfa_required(self, d: Dict[str, Any]) -> authn_pb2.MfaChallengeRequired:
        methods = [getattr(authn_pb2, f"AUTH_METHOD_{m}", authn_pb2.AUTH_METHOD_TOTP) for m in d.get("allowed_methods", [])]
        out = authn_pb2.MfaChallengeRequired(
            challenge_id=d["challenge_id"],
            allowed_methods=methods,
            expires_at=self._ts(d.get("expires_at")),
            risk=self._pb_risk(d.get("risk")),
        )
        if d.get("webauthn"):
            out.webauthn.CopyFrom(self._pb_webauthn_challenge(d["webauthn"]))
        if d.get("otp"):
            otp = d["otp"]
            ch_enum = authn_pb2.OTP_CHANNEL_EMAIL if otp.get("channel") == "EMAIL" else authn_pb2.OTP_CHANNEL_SMS
            out.otp.CopyFrom(authn_pb2.OtpChallenge(
                challenge_id=otp["challenge_id"],
                channel=ch_enum,
                masked_destination=otp["masked_destination"],
                code_length=int(otp.get("code_length", 6)),
                ttl=authn_pb2.google_dot_protobuf_dot_duration__pb2.Duration(seconds=300),
                expires_at=self._ts(otp.get("expires_at")),
            ))
        return out

    def _ts(self, iso: Optional[str]):
        if not iso:
            return None
        # google.protobuf.Timestamp expected
        from google.protobuf.timestamp_pb2 import Timestamp
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        ts = Timestamp()
        ts.FromDatetime(dt)
        return ts

    def _context_to_dict(self, ctx: authn_pb2.ClientContext) -> Dict[str, Any]:
        d: Dict[str, Any] = {}
        if ctx.request_id: d["request_id"] = ctx.request_id
        if ctx.ip_address: d["ip_address"] = ctx.ip_address
        if ctx.user_agent: d["user_agent"] = ctx.user_agent
        if ctx.timezone: d["timezone"] = ctx.timezone
        # headers/extra as Struct
        if ctx.HasField("headers"):
            d["headers"] = dict(ctx.headers)
        if ctx.HasField("extra"):
            d["extra"] = dict(ctx.extra)
        if ctx.HasField("device"):
            d["device"] = {
                "id": ctx.device.id or None,
                "platform": ctx.device.DevicePlatform.Name(ctx.device.platform).replace("PLATFORM_", ""),
                "user_agent": ctx.device.user_agent or None,
                "model": ctx.device.model or None,
            }
        return d

    # ----- RPC methods -----

    async def BeginPasswordAuth(self, request: authn_pb2.BeginPasswordAuthRequest, context: ServicerContext):
        ctx = self._context_to_dict(request.context) if request.HasField("context") else {}
        success, mfa = await self.domain.begin_password_auth(request.identifier, request.password, ctx)
        resp = authn_pb2.BeginPasswordAuthResponse()
        if mfa:
            resp.mfa.CopyFrom(self._pb_mfa_required(mfa))
        else:
            resp.success.CopyFrom(self._pb_success(success))
        return resp

    async def CompleteMfa(self, request: authn_pb2.CompleteMfaRequest, context: ServicerContext):
        ctx = self._context_to_dict(request.context) if request.HasField("context") else {}
        proof: Dict[str, Any] = {}
        if request.totp_code: proof["totp_code"] = request.totp_code
        if request.sms_code: proof["sms_code"] = request.sms_code
        if request.email_code: proof["email_code"] = request.email_code
        if request.recovery_code: proof["recovery_code"] = request.recovery_code
        if request.HasField("webauthn"):
            proof["webauthn"] = {
                "credential_id_b64url": request.webauthn.credential_id_b64url,
                "client_data_json": request.webauthn.client_data_json,
                "authenticator_data": request.webauthn.authenticator_data,
                "signature": request.webauthn.signature,
                "user_handle": request.webauthn.user_handle,
            }
        success = await self.domain.complete_mfa(request.challenge_id, proof, ctx)
        return authn_pb2.CompleteMfaResponse(success=self._pb_success(success))

    async def StartWebAuthnRegistration(self, request: authn_pb2.StartWebAuthnRegistrationRequest, context: ServicerContext):
        ctx = self._context_to_dict(request.context) if request.HasField("context") else {}
        opts = await self.domain.start_webauthn_registration(request.principal_id, ctx)
        return authn_pb2.StartWebAuthnRegistrationResponse(options=self._pb_webauthn_options(opts),
                                                          expires_at=self._ts(opts.get("expires_at")))

    async def FinishWebAuthnRegistration(self, request: authn_pb2.FinishWebAuthnRegistrationRequest, context: ServicerContext):
        ctx = self._context_to_dict(request.context) if request.HasField("context") else {}
        att = {
            "credential_id_b64url": request.attestation.credential_id_b64url,
            "client_data_json": request.attestation.client_data_json,
            "attestation_object": request.attestation.attestation_object,
        }
        cred = await self.domain.finish_webauthn_registration(request.principal_id, att, ctx)
        out = authn_pb2.FinishWebAuthnRegistrationResponse()
        out.credential.CopyFrom(authn_pb2.WebAuthnCredential(
            credential_id_b64url=cred["credential_id_b64url"],
            aaguid=cred.get("aaguid", ""),
            public_key_cose=cred.get("public_key_cose", b""),
            sign_count=int(cred.get("sign_count", 0)),
            attestation_format=cred.get("attestation_format", "none"),
            transports=cred.get("transports", []),
            user_verification=bool(cred.get("user_verification", True)),
            resident_key=bool(cred.get("resident_key", False)),
            rp_id=cred.get("rp_id", ""),
            name=cred.get("name", ""),
            registered_at=self._ts(cred.get("registered_at")),
        ))
        return out

    async def StartWebAuthnAuthentication(self, request: authn_pb2.StartWebAuthnAuthenticationRequest, context: ServicerContext):
        ctx = self._context_to_dict(request.context) if request.HasField("context") else {}
        ch = await self.domain.start_webauthn_auth(request.identifier or None, ctx)
        return authn_pb2.StartWebAuthnAuthenticationResponse(challenge=self._pb_webauthn_challenge(ch))

    async def FinishWebAuthnAuthentication(self, request: authn_pb2.FinishWebAuthnAuthenticationRequest, context: ServicerContext):
        ctx = self._context_to_dict(request.context) if request.HasField("context") else {}
        assertion = {
            "credential_id_b64url": request.assertion.credential_id_b64url,
            "client_data_json": request.assertion.client_data_json,
            "authenticator_data": request.assertion.authenticator_data,
            "signature": request.assertion.signature,
            "user_handle": request.assertion.user_handle,
        }
        success, mfa = await self.domain.finish_webauthn_auth(request.identifier or None, assertion, ctx)
        out = authn_pb2.FinishWebAuthnAuthenticationResponse()
        if mfa:
            out.mfa.CopyFrom(self._pb_mfa_required(mfa))
        else:
            out.success.CopyFrom(self._pb_success(success))
        return out

    async def StartPasswordless(self, request: authn_pb2.StartPasswordlessRequest, context: ServicerContext):
        ctx = self._context_to_dict(request.context) if request.HasField("context") else {}
        res = await self.domain.start_passwordless(request.identifier, authn_pb2.PasswordlessMethod.Name(request.method), ctx)
        out = authn_pb2.StartPasswordlessResponse()
        if "otp" in res:
            otp = res["otp"]
            ch_enum = authn_pb2.OTP_CHANNEL_EMAIL if otp.get("channel") == "EMAIL" else authn_pb2.OTP_CHANNEL_SMS
            out.otp.CopyFrom(authn_pb2.OtpChallenge(
                challenge_id=otp["challenge_id"],
                channel=ch_enum,
                masked_destination=otp["masked_destination"],
                code_length=int(otp.get("code_length", 6)),
                expires_at=self._ts(otp.get("expires_at")),
            ))
        if "info" in res and isinstance(res["info"], str):
            out.info.value = res["info"]
        if "webauthn" in res:
            out.webauthn.CopyFrom(self._pb_webauthn_challenge(res["webauthn"]))
        return out

    async def CompletePasswordless(self, request: authn_pb2.CompletePasswordlessRequest, context: ServicerContext):
        ctx = self._context_to_dict(request.context) if request.HasField("context") else {}
        req: Dict[str, Any] = {"identifier": request.identifier}
        if request.email_link_token: req["email_link_token"] = request.email_link_token
        if request.sms_code: req["sms_code"] = request.sms_code
        if request.email_code: req["email_code"] = request.email_code
        if request.HasField("webauthn"):
            req["webauthn"] = {
                "credential_id_b64url": request.webauthn.credential_id_b64url,
                "client_data_json": request.webauthn.client_data_json,
                "authenticator_data": request.webauthn.authenticator_data,
                "signature": request.webauthn.signature,
                "user_handle": request.webauthn.user_handle,
            }
        success = await self.domain.complete_passwordless(req, ctx)
        return authn_pb2.CompletePasswordlessResponse(success=self._pb_success(success))

    async def RefreshAccessToken(self, request: authn_pb2.RefreshAccessTokenRequest, context: ServicerContext):
        ctx = self._context_to_dict(request.context) if request.HasField("context") else {}
        success = await self.domain.refresh(request.refresh_token, ctx)
        return authn_pb2.RefreshAccessTokenResponse(success=self._pb_success(success))

    async def IntrospectToken(self, request: authn_pb2.IntrospectTokenRequest, context: ServicerContext):
        ctx = self._context_to_dict(request.context) if request.HasField("context") else {}
        d = await self.domain.introspect(request.token, authn_pb2.TokenType.Name(request.assumed_type) if request.assumed_type else None, ctx)
        out = authn_pb2.IntrospectTokenResponse(
            active=bool(d.get("active", False)),
            evaluated_at=self._ts(d.get("evaluated_at")),
        )
        if d.get("token"): out.token.CopyFrom(self._pb_token(d["token"]))
        if d.get("principal"): out.principal.CopyFrom(self._pb_principal(d["principal"]))
        if d.get("session"): out.session.CopyFrom(self._pb_session(d["session"]))
        if d.get("risk"): out.risk.CopyFrom(self._pb_risk(d["risk"]))
        return out

    async def RevokeToken(self, request: authn_pb2.RevokeTokenRequest, context: ServicerContext):
        ctx = self._context_to_dict(request.context) if request.HasField("context") else {}
        ttype = authn_pb2.TokenType.Name(request.type)
        revoked = await self.domain.revoke(request.token, ttype, request.reason.value if request.HasField("reason") else None, ctx)
        return authn_pb2.RevokeTokenResponse(revoked=bool(revoked))

    async def Logout(self, request: authn_pb2.LogoutRequest, context: ServicerContext):
        ctx = self._context_to_dict(request.context) if request.HasField("context") else {}
        revoked = await self.domain.logout(request.session_id or None, ctx)
        return authn_pb2.LogoutResponse(revoked=bool(revoked))

    async def GetSession(self, request: authn_pb2.GetSessionRequest, context: ServicerContext):
        d = await self.domain.get_session(request.session_id)
        return authn_pb2.GetSessionResponse(session=self._pb_session(d))

    async def ListSessions(self, request: authn_pb2.ListSessionsRequest, context: ServicerContext):
        d = await self.domain.list_sessions(
            request.principal_id, request.page_size or 20, request.page_token or None, request.active_only
        )
        out = authn_pb2.ListSessionsResponse(sessions=[self._pb_session(x) for x in d.get("sessions", [])],
                                             next_page_token=d.get("next_page_token") or "")
        return out

# ===========================
# ===== Server bootstrap  ====
# ===========================

def _server_options() -> Iterable[Tuple[str, Any]]:
    return (
        ("grpc.max_concurrent_streams", GRPC_MAX_CONCURRENCY),
        ("grpc.max_receive_message_length", GRPC_MAX_RECV_MB * 1024 * 1024),
        ("grpc.max_send_message_length", GRPC_MAX_SEND_MB * 1024 * 1024),
        ("grpc.keepalive_time_ms", GRPC_KEEPALIVE_TIME_SEC * 1000),
        ("grpc.keepalive_timeout_ms", GRPC_KEEPALIVE_TIMEOUT_SEC * 1000),
        ("grpc.keepalive_permit_without_calls", GRPC_KEEPALIVE_PERMIT_WITHOUT_CALLS),
    )

async def create_server() -> grpc.aio.Server:
    interceptors = [RequestIdInterceptor(), ExceptionInterceptor()]
    server = grpc.aio.server(options=_server_options(), interceptors=interceptors)
    # DI: choose domain
    domain: AuthDomainService
    if DEV_MOCK:
        logger.warning("Starting gRPC server with DEV AuthDomainService mock. DO NOT USE IN PRODUCTION.")
        domain = DevAuthDomainService()
    else:
        raise RuntimeError("AuthDomainService is not wired. Set SECURITY_CORE_DEV_MOCK=1 for local runs or provide real service.")

    # Register services
    authn_pb2_grpc.add_AuthenticationServiceServicer_to_server(AuthnGrpcServer(domain), server)

    # Health & reflection
    health_servicer = health.HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)
    service_names = (
        authn_pb2.DESCRIPTOR.services_by_name["AuthenticationService"].full_name,
        health.SERVICE_NAME,
        reflection.SERVICE_NAME,
    )
    reflection.enable_server_reflection(service_names, server)
    health_servicer.set(service_names[0], health_pb2_grpc.health__pb2.HealthCheckResponse.SERVING)  # type: ignore[attr-defined]

    # Bind
    addr = f"{GRPC_HOST}:{GRPC_PORT}"
    if TLS_CERT and TLS_KEY:
        with open(TLS_CERT, "rb") as f:
            cert = f.read()
        with open(TLS_KEY, "rb") as f:
            key = f.read()
        creds = grpc.ssl_server_credentials(((key, cert),))
        server.add_secure_port(addr, creds)
        logger.info(f"gRPC listening (TLS) on {addr}")
    else:
        server.add_insecure_port(addr)
        logger.info(f"gRPC listening (PLAINTEXT) on {addr}")

    return server

async def serve() -> None:
    server = await create_server()
    await server.start()

    stop_event = asyncio.Event()

    def _handle_sig(*_):
        logger.info("Signal received, shutting down gracefully...")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_sig)
        except NotImplementedError:
            pass  # Windows

    await stop_event.wait()
    await server.stop(grace=None)
    logger.info("gRPC server stopped.")

if __name__ == "__main__":
    asyncio.run(serve())
