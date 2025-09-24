from __future__ import annotations

import datetime as dt
import ipaddress
import json
import logging
import os
import uuid
from typing import Any, Dict, List, Optional, Protocol, Tuple, TypedDict, Union

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Path, Query, Request, Response, status
from fastapi.responses import JSONResponse

# ---- Pydantic v2 with fallback to v1 -------------------------------------
try:
    from pydantic import BaseModel, Field, IPvAnyAddress, ValidationError, field_validator, model_validator, SecretStr
    _PYD_VER = 2
except Exception:  # noqa: BLE001
    from pydantic import BaseModel, Field, IPvAnyAddress, ValidationError  # type: ignore
    from pydantic import validator as field_validator, root_validator as model_validator  # type: ignore
    from pydantic import SecretStr  # type: ignore
    _PYD_VER = 1

# ---- Optional OTEL --------------------------------------------------------
try:
    from opentelemetry import trace  # type: ignore
    _TRACER = trace.get_tracer(__name__)
except Exception:  # noqa: BLE001
    _TRACER = None

# ---- Optional config integration -----------------------------------------
try:
    from avm_core.config import get_settings  # type: ignore
except Exception:  # noqa: BLE001
    get_settings = None  # type: ignore

log = logging.getLogger("security-core.api.vpn")

router = APIRouter(prefix="/vpn/v1", tags=["vpn"])

UTC = dt.timezone.utc

# =============================================================================
# Error model / helpers
# =============================================================================

class ApiError(BaseModel):
    code: str = Field(..., examples=["invalid_request", "unauthorized", "not_found"])
    message: str
    request_id: str
    details: Optional[Dict[str, Any]] = None


def error_response(status_code: int, code: str, message: str, request_id: str, details: Optional[Dict[str, Any]] = None) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=ApiError(code=code, message=message, request_id=request_id, details=details or {}).model_dump()  # type: ignore
        if hasattr(ApiError, "model_dump") else  # pydantic v1 fallback
        ApiError(code=code, message=message, request_id=request_id, details=details or {}).dict()
    )

# =============================================================================
# Security / principal
# =============================================================================

class Principal(BaseModel):
    subject: str
    source: str = "header"
    scopes: List[str] = Field(default_factory=list)
    org_id: Optional[str] = None


async def principal_dep(
    request: Request,
    x_user_id: Optional[str] = Header(default=None, alias="X-User-Id"),
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
) -> Principal:
    """
    Примитивная зависимость безопасности:
    - Принимает X-User-Id или Bearer токен (заглушка).
    - В проде замените на реальную проверку JWT/OIDC и загрузку субъектов/ролей.
    """
    if x_user_id:
        return Principal(subject=x_user_id, source="header", scopes=["vpn:read", "vpn:write"])
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1]
        if not token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        # Заглушка разбора токена; добавьте проверку подписи и извлечение subject/org/скопов.
        return Principal(subject="bearer:subject", source="bearer", scopes=["vpn:read", "vpn:write"])
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

# =============================================================================
# Repository interface + in-memory implementation
# =============================================================================

class VpnState(str):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class VpnSession(BaseModel):
    id: str
    user_id: str
    device_id: str
    region: str
    client_ip: Optional[IPvAnyAddress] = None
    assigned_ip: Optional[IPvAnyAddress] = None
    tunnel_id: Optional[str] = None  # идентификатор на стороне VPN‑сервера
    state: str = VpnState.ACTIVE
    created_at: dt.datetime = Field(default_factory=lambda: dt.datetime.now(tz=UTC))
    expires_at: Optional[dt.datetime] = None
    last_seen_at: Optional[dt.datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("expires_at")  # type: ignore[misc]
    def _must_be_future(cls, v: Optional[dt.datetime]):  # noqa: N805
        if v and v.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware")
        return v


class VpnSessionCreate(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=256)
    device_id: str = Field(..., min_length=1, max_length=256)
    region: str = Field(..., min_length=1, max_length=64, examples=["eu-north-1"])
    requested_ip: Optional[IPvAnyAddress] = None
    ttl_seconds: int = Field(3600, ge=300, le=86400)
    client_ip: Optional[IPvAnyAddress] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class VpnSessionUpdate(BaseModel):
    # heartbeat/last_seen, продление, метаданные
    extend_ttl_seconds: Optional[int] = Field(default=None, ge=60, le=86400)
    client_ip: Optional[IPvAnyAddress] = None
    metadata: Optional[Dict[str, Any]] = None


class VpnConfigFormat(str):
    WIREGUARD = "wireguard"
    OPENVPN = "openvpn"


class VpnConfigResponse(BaseModel):
    format: str
    config: str  # текст конфигурации
    expires_at: Optional[dt.datetime] = None


class PageMeta(BaseModel):
    page: int
    size: int
    total: int


class VpnSessionList(BaseModel):
    items: List[VpnSession]
    meta: PageMeta


class VpnSessionRepository(Protocol):
    async def create(self, data: VpnSessionCreate, assigned_ip: Optional[str], principal: Principal, ttl: int) -> VpnSession: ...
    async def get(self, session_id: str, principal: Principal) -> Optional[VpnSession]: ...
    async def list(self, principal: Principal, state: Optional[str], page: int, size: int, user_id: Optional[str]) -> Tuple[List[VpnSession], int]: ...
    async def update(self, session_id: str, patch: VpnSessionUpdate, principal: Principal) -> Optional[VpnSession]: ...
    async def revoke(self, session_id: str, principal: Principal) -> Optional[VpnSession]: ...


class InMemoryRepo(VpnSessionRepository):
    def __init__(self) -> None:
        self._data: Dict[str, VpnSession] = {}
        self._ip_cursor = 10

    def _assign_ip(self) -> str:
        # Простая раздача адресов 10.0.0.X — замените на IPAM
        ip = f"10.0.0.{self._ip_cursor}"
        self._ip_cursor += 1
        return ip

    async def create(self, data: VpnSessionCreate, assigned_ip: Optional[str], principal: Principal, ttl: int) -> VpnSession:
        sid = str(uuid.uuid4())
        now = dt.datetime.now(tz=UTC)
        exp = now + dt.timedelta(seconds=ttl)
        sess = VpnSession(
            id=sid,
            user_id=data.user_id,
            device_id=data.device_id,
            region=data.region,
            client_ip=data.client_ip,
            assigned_ip=ipaddress.ip_address(assigned_ip or self._assign_ip()),  # type: ignore
            tunnel_id=None,
            state=VpnState.ACTIVE,
            created_at=now,
            expires_at=exp,
            last_seen_at=now,
            metadata=data.metadata,
        )
        self._data[sid] = sess
        return sess

    async def get(self, session_id: str, principal: Principal) -> Optional[VpnSession]:
        sess = self._data.get(session_id)
        if not sess:
            return None
        if sess.expires_at and sess.expires_at < dt.datetime.now(tz=UTC) and sess.state == VpnState.ACTIVE:
            sess.state = VpnState.EXPIRED
        return sess

    async def list(self, principal: Principal, state: Optional[str], page: int, size: int, user_id: Optional[str]) -> Tuple[List[VpnSession], int]:
        items = list(self._data.values())
        if state:
            items = [s for s in items if s.state == state]
        if user_id:
            items = [s for s in items if s.user_id == user_id]
        total = len(items)
        start = (page - 1) * size
        end = start + size
        return items[start:end], total

    async def update(self, session_id: str, patch: VpnSessionUpdate, principal: Principal) -> Optional[VpnSession]:
        sess = self._data.get(session_id)
        if not sess:
            return None
        now = dt.datetime.now(tz=UTC)
        if patch.extend_ttl_seconds:
            if not sess.expires_at:
                sess.expires_at = now + dt.timedelta(seconds=patch.extend_ttl_seconds)
            else:
                sess.expires_at = min(sess.expires_at + dt.timedelta(seconds=patch.extend_ttl_seconds),
                                      now + dt.timedelta(days=1))
        if patch.client_ip:
            sess.client_ip = patch.client_ip
        if patch.metadata:
            sess.metadata.update(patch.metadata)
        sess.last_seen_at = now
        if sess.expires_at and sess.expires_at < now and sess.state == VpnState.ACTIVE:
            sess.state = VpnState.EXPIRED
        self._data[session_id] = sess
        return sess

    async def revoke(self, session_id: str, principal: Principal) -> Optional[VpnSession]:
        sess = self._data.get(session_id)
        if not sess:
            return None
        sess.state = VpnState.REVOKED
        self._data[session_id] = sess
        return sess

# =============================================================================
# Idempotency cache (process-local). Replace with Redis in prod.
# =============================================================================

class _IdemRecord(TypedDict):
    status: int
    body: Dict[str, Any]
    headers: Dict[str, str]

class IdempotencyCache:
    def __init__(self) -> None:
        self._store: Dict[str, _IdemRecord] = {}

    def _key(self, principal: Principal, route: str, idem_key: str) -> str:
        return f"{principal.subject}:{route}:{idem_key}"

    def get(self, principal: Principal, route: str, idem_key: Optional[str]) -> Optional[_IdemRecord]:
        if not idem_key:
            return None
        return self._store.get(self._key(principal, route, idem_key))

    def set(self, principal: Principal, route: str, idem_key: Optional[str], record: _IdemRecord) -> None:
        if not idem_key:
            return
        self._store[self._key(principal, route, idem_key)] = record

_idem = IdempotencyCache()

# =============================================================================
# Dependencies
# =============================================================================

_repo_singleton: Optional[VpnSessionRepository] = None

def get_repo() -> VpnSessionRepository:
    global _repo_singleton
    if _repo_singleton is None:
        _repo_singleton = InMemoryRepo()
    return _repo_singleton


def _request_id(request: Request) -> str:
    return request.headers.get("X-Request-Id") or str(uuid.uuid4())


def _audit(event: str, payload: Dict[str, Any]) -> None:
    try:
        log.info("audit event=%s payload=%s", event, json.dumps(payload, ensure_ascii=False))
    except Exception:  # noqa: BLE001
        log.info("audit event=%s payload=%s", event, str(payload))

# =============================================================================
# Routes
# =============================================================================

@router.post(
    "/sessions",
    response_model=VpnSession,
    responses={
        400: {"model": ApiError},
        401: {"model": ApiError},
        409: {"model": ApiError},
    },
    status_code=status.HTTP_201_CREATED,
)
async def create_session(
    request: Request,
    payload: VpnSessionCreate = Body(...),
    principal: Principal = Depends(principal_dep),
    repo: VpnSessionRepository = Depends(get_repo),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
) -> Union[VpnSession, JSONResponse]:
    rid = _request_id(request)

    # Idempotency check
    cached = _idem.get(principal, "POST:/vpn/v1/sessions", idempotency_key)
    if cached:
        return JSONResponse(status_code=cached["status"], content=cached["body"], headers=cached.get("headers", {}))

    # Optional allowlist of regions from config
    if get_settings:
        try:
            st = get_settings()
            allowed_origins = st.net.cors_allowed_origins  # not used here, just sample; plug your own policy
            _ = allowed_origins
        except Exception:
            pass

    ttl = int(payload.ttl_seconds)
    assigned_ip = str(payload.requested_ip) if payload.requested_ip else None

    if assigned_ip:
        # basic validation: ensure RFC1918 if IPv4
        try:
            ip_obj = ipaddress.ip_address(assigned_ip)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                if not ip_obj.is_private:
                    return error_response(status.HTTP_400_BAD_REQUEST, "invalid_request", "requested_ip must be private RFC1918", rid)
        except ValueError:
            return error_response(status.HTTP_400_BAD_REQUEST, "invalid_request", "requested_ip is invalid", rid)

    sess = await repo.create(payload, assigned_ip, principal, ttl)

    body = sess.model_dump() if hasattr(sess, "model_dump") else sess.dict()  # type: ignore
    headers = {"X-Request-Id": rid}
    _idem.set(principal, "POST:/vpn/v1/sessions", idempotency_key, {"status": status.HTTP_201_CREATED, "body": body, "headers": headers})
    _audit("vpn.session.create", {"request_id": rid, "principal": principal.subject, "session_id": sess.id, "user_id": sess.user_id, "region": sess.region})
    return JSONResponse(status_code=status.HTTP_201_CREATED, content=body, headers=headers)


@router.get(
    "/sessions/{session_id}",
    response_model=VpnSession,
    responses={404: {"model": ApiError}, 401: {"model": ApiError}},
)
async def get_session(
    request: Request,
    session_id: str = Path(..., min_length=3),
    principal: Principal = Depends(principal_dep),
    repo: VpnSessionRepository = Depends(get_repo),
):
    rid = _request_id(request)
    sess = await repo.get(session_id, principal)
    if not sess:
        return error_response(status.HTTP_404_NOT_FOUND, "not_found", "session not found", rid)
    _audit("vpn.session.get", {"request_id": rid, "principal": principal.subject, "session_id": sess.id})
    return sess


@router.get(
    "/sessions",
    response_model=VpnSessionList,
    responses={401: {"model": ApiError}},
)
async def list_sessions(
    request: Request,
    principal: Principal = Depends(principal_dep),
    repo: VpnSessionRepository = Depends(get_repo),
    state: Optional[str] = Query(default=None, pattern="^(active|revoked|expired)$"),
    user_id: Optional[str] = Query(default=None, min_length=1),
    page: int = Query(default=1, ge=1, le=100000),
    size: int = Query(default=50, ge=1, le=500),
):
    rid = _request_id(request)
    items, total = await repo.list(principal, state, page, size, user_id)
    _audit("vpn.session.list", {"request_id": rid, "principal": principal.subject, "count": len(items), "total": total})
    return VpnSessionList(items=items, meta=PageMeta(page=page, size=size, total=total))


@router.post(
    "/sessions/{session_id}/heartbeat",
    response_model=VpnSession,
    responses={404: {"model": ApiError}, 401: {"model": ApiError}},
)
async def heartbeat_session(
    request: Request,
    session_id: str = Path(...),
    principal: Principal = Depends(principal_dep),
    repo: VpnSessionRepository = Depends(get_repo),
    payload: VpnSessionUpdate = Body(default=VpnSessionUpdate()),
):
    rid = _request_id(request)
    patch = payload or VpnSessionUpdate()
    patch.extend_ttl_seconds = patch.extend_ttl_seconds or 60  # минимум обновляем на 60 сек
    sess = await repo.update(session_id, patch, principal)
    if not sess:
        return error_response(status.HTTP_404_NOT_FOUND, "not_found", "session not found", rid)
    _audit("vpn.session.heartbeat", {"request_id": rid, "principal": principal.subject, "session_id": session_id})
    return sess


@router.post(
    "/sessions/{session_id}/rotate",
    response_model=VpnSession,
    responses={404: {"model": ApiError}, 401: {"model": ApiError}, 409: {"model": ApiError}},
)
async def rotate_session(
    request: Request,
    session_id: str = Path(...),
    principal: Principal = Depends(principal_dep),
    repo: VpnSessionRepository = Depends(get_repo),
):
    rid = _request_id(request)
    sess = await repo.get(session_id, principal)
    if not sess:
        return error_response(status.HTTP_404_NOT_FOUND, "not_found", "session not found", rid)
    if sess.state != VpnState.ACTIVE:
        return error_response(status.HTTP_409_CONFLICT, "invalid_state", "session is not active", rid)

    # Здесь должна быть реальная ротация ключей/конфига (PKI/WireGuard). Заглушка: продление TTL и отметка last_seen.
    patch = VpnSessionUpdate(extend_ttl_seconds=300)
    sess = await repo.update(session_id, patch, principal)
    _audit("vpn.session.rotate", {"request_id": rid, "principal": principal.subject, "session_id": session_id})
    return sess


@router.delete(
    "/sessions/{session_id}",
    response_model=VpnSession,
    responses={404: {"model": ApiError}, 401: {"model": ApiError}},
)
async def revoke_session(
    request: Request,
    session_id: str = Path(...),
    principal: Principal = Depends(principal_dep),
    repo: VpnSessionRepository = Depends(get_repo),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    rid = _request_id(request)

    cached = _idem.get(principal, "DELETE:/vpn/v1/sessions", idempotency_key)
    if cached:
        return JSONResponse(status_code=cached["status"], content=cached["body"], headers=cached.get("headers", {}))

    sess = await repo.revoke(session_id, principal)
    if not sess:
        return error_response(status.HTTP_404_NOT_FOUND, "not_found", "session not found", rid)

    body = sess.model_dump() if hasattr(sess, "model_dump") else sess.dict()  # type: ignore
    headers = {"X-Request-Id": rid}
    _idem.set(principal, "DELETE:/vpn/v1/sessions", idempotency_key, {"status": status.HTTP_200_OK, "body": body, "headers": headers})
    _audit("vpn.session.revoke", {"request_id": rid, "principal": principal.subject, "session_id": session_id})
    return JSONResponse(status_code=status.HTTP_200_OK, content=body, headers=headers)


@router.get(
    "/sessions/{session_id}/config",
    response_model=VpnConfigResponse,
    responses={404: {"model": ApiError}, 401: {"model": ApiError}},
)
async def get_vpn_config(
    request: Request,
    session_id: str = Path(...),
    fmt: str = Query(default=VpnConfigFormat.WIREGUARD, pattern="^(wireguard|openvpn)$"),
    principal: Principal = Depends(principal_dep),
    repo: VpnSessionRepository = Depends(get_repo),
):
    rid = _request_id(request)
    sess = await repo.get(session_id, principal)
    if not sess:
        return error_response(status.HTTP_404_NOT_FOUND, "not_found", "session not found", rid)
    if sess.state != VpnState.ACTIVE:
        return error_response(status.HTTP_409_CONFLICT, "invalid_state", "session is not active", rid)

    # Генерация конфигурации — заглушки. В проде интегрируйте с реальным конфигуратором.
    if fmt == VpnConfigFormat.WIREGUARD:
        cfg = _render_wireguard_config(sess)
    else:
        cfg = _render_openvpn_config(sess)

    _audit("vpn.session.config", {"request_id": rid, "principal": principal.subject, "session_id": session_id, "format": fmt})
    return VpnConfigResponse(format=fmt, config=cfg, expires_at=sess.expires_at)


# =============================================================================
# Renderers (stubs) — replace with real config generation
# =============================================================================

def _render_wireguard_config(sess: VpnSession) -> str:
    assigned_ip = sess.assigned_ip or "10.0.0.2"
    return (
        "[Interface]\n"
        f"PrivateKey = <REDACTED>\n"
        f"Address = {assigned_ip}/32\n"
        f"DNS = 1.1.1.1\n\n"
        "[Peer]\n"
        "PublicKey = <SERVER_PUBKEY>\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        "Endpoint = vpn.example.com:51820\n"
        "PersistentKeepalive = 25\n"
    )


def _render_openvpn_config(sess: VpnSession) -> str:
    return (
        "client\n"
        "dev tun\n"
        "proto udp\n"
        "remote vpn.example.com 1194\n"
        "resolv-retry infinite\n"
        "nobind\n"
        "persist-key\n"
        "persist-tun\n"
        "remote-cert-tls server\n"
        "cipher AES-256-GCM\n"
        "verb 3\n"
        "<key>\nREDACTED\n</key>\n"
        "<cert>\nREDACTED\n</cert>\n"
        "<ca>\nREDACTED\n</ca>\n"
    )
