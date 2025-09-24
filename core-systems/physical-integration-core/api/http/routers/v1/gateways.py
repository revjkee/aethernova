from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Literal, Optional, Tuple
from uuid import UUID, uuid4

from fastapi import (
    APIRouter,
    Body,
    Depends,
    Header,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    status,
)
from pydantic import BaseModel, Field, UUID4, constr, validator
from starlette.responses import JSONResponse

# --- Prometheus (graceful) ----------------------------------------------------
try:
    from prometheus_client import Counter, Histogram  # type: ignore
except Exception:  # pragma: no cover
    Counter = None  # type: ignore
    Histogram = None  # type: ignore

# --- Логгер -------------------------------------------------------------------
log = logging.getLogger("pic.api.gateways")

# --- Константы ----------------------------------------------------------------
IDEMPOTENCY_HEADER = "Idempotency-Key"
REQUEST_ID_HEADER = "X-Request-ID"

# --- Метрики ------------------------------------------------------------------
_m_req = None
_m_latency = None
if Counter:
    try:
        _m_req = Counter(
            "pic_gateway_requests_total",
            "Gateway API requests",
            labelnames=("route", "method", "code"),
        )
        _m_latency = Histogram(
            "pic_gateway_request_latency_seconds",
            "Gateway API latency",
            labelnames=("route", "method"),
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5),
        )
    except Exception:  # pragma: no cover
        _m_req = None
        _m_latency = None


def _metric(route: str, method: str, code: int, dur: float) -> None:
    if _m_req:
        try:
            _m_req.labels(route=route, method=method, code=str(code)).inc()
        except Exception:
            pass
    if _m_latency:
        try:
            _m_latency.labels(route=route, method=method).observe(dur)
        except Exception:
            pass


# --- Схемы --------------------------------------------------------------------
GatewayStatus = Literal["active", "inactive", "degraded"]

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

NameStr = constr(regex=r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$", strip_whitespace=True)
SiteStr = constr(regex=r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$", strip_whitespace=True)
ModelStr = constr(min_length=2, max_length=64, strip_whitespace=True)

class ProblemDetails(BaseModel):
    type: Optional[str] = Field(default="about:blank")
    title: str
    status: int
    detail: Optional[str] = None
    instance: Optional[str] = None

class GatewayBase(BaseModel):
    name: NameStr = Field(..., description="DNS-совместимое имя ресурса")
    site_id: SiteStr = Field(..., description="Локация/площадка")
    model: ModelStr = Field(..., description="Модель шлюза")
    labels: Dict[str, str] = Field(default_factory=dict, description="Произвольные метки (k=v)")
    description: Optional[str] = Field(default=None, max_length=2000)

    @validator("labels", pre=True)
    def _labels_trim(cls, v: Dict[str, str]) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for k, val in (v or {}).items():
            ks = str(k).strip()
            vs = str(val).strip()
            if not ks:
                continue
            if len(ks) > 128 or len(vs) > 512:
                raise ValueError("label too long")
            out[ks] = vs
        return out

class GatewayCreate(GatewayBase):
    tenant_id: Optional[NameStr] = Field(default=None)
    site_zone: Optional[NameStr] = Field(default=None)
    # Первичный секрет АПИ (может не передаваться — тогда сгенерируется)
    api_secret: Optional[constr(min_length=16, max_length=256)] = None

class GatewayUpdate(BaseModel):
    description: Optional[str] = Field(default=None, max_length=2000)
    labels: Optional[Dict[str, str]] = None
    status: Optional[GatewayStatus] = None

class GatewayOut(GatewayBase):
    id: UUID4
    status: GatewayStatus = "active"
    created_at: datetime
    updated_at: datetime
    version: int = Field(ge=1)
    tenant_id: Optional[NameStr] = None
    site_zone: Optional[NameStr] = None

class GatewaySecretRotateRequest(BaseModel):
    reason: Optional[constr(max_length=256)] = None

class GatewaySecretRotateResponse(BaseModel):
    id: UUID4
    rotated_at: datetime
    secret_preview: str = Field(..., description="Первые 6 символов нового секрета")
    version: int

class HeartbeatIn(BaseModel):
    uptime_sec: int = Field(ge=0)
    last_seq: Optional[int] = Field(default=None, ge=0)
    health: Optional[Literal["ok", "degraded", "failing"]] = "ok"
    cpu_util: Optional[float] = Field(default=None, ge=0, le=100)
    mem_util: Optional[float] = Field(default=None, ge=0, le=100)
    board_temp_c: Optional[float] = Field(default=None, ge=-100, le=200)

class HeartbeatOut(BaseModel):
    ack: bool
    next_poll_sec: int = 60
    apply_config_uri: Optional[str] = None

class PageMeta(BaseModel):
    page: int
    page_size: int
    total: int

class GatewaysPage(BaseModel):
    items: List[GatewayOut]
    meta: PageMeta

# --- Хранилище (in-memory; замените на DAO в продакшене) ----------------------
class _Store:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._by_id: Dict[UUID, Dict[str, Any]] = {}
        self._by_name: Dict[str, UUID] = {}
        self._idem: OrderedDict[str, UUID] = OrderedDict()
        self._idem_limit = 10000

    def _touch_idem(self, key: str, gid: UUID) -> None:
        # LRU для идемпотентности
        if key in self._idem:
            self._idem.move_to_end(key)
        self._idem[key] = gid
        while len(self._idem) > self._idem_limit:
            self._idem.popitem(last=False)

    def get_by_idem(self, key: str) -> Optional[UUID]:
        with self._lock:
            return self._idem.get(key)

    def create(self, payload: GatewayCreate, now: datetime, api_secret: str, idem_key: Optional[str]) -> Dict[str, Any]:
        with self._lock:
            if payload.name in self._by_name:
                raise ValueError("name exists")
            gid = uuid4()
            rec = {
                "id": gid,
                "name": payload.name,
                "site_id": payload.site_id,
                "model": payload.model,
                "tenant_id": payload.tenant_id,
                "site_zone": payload.site_zone,
                "labels": dict(payload.labels),
                "description": payload.description,
                "status": "active",
                "created_at": now,
                "updated_at": now,
                "version": 1,
                "api_secret": api_secret,
                "deleted": False,
            }
            self._by_id[gid] = rec
            self._by_name[payload.name] = gid
            if idem_key:
                self._touch_idem(idem_key, gid)
            return rec

    def list(
        self,
        *,
        page: int,
        page_size: int,
        status: Optional[GatewayStatus],
        site_id: Optional[str],
        model: Optional[str],
        q: Optional[str],
        sort: str,
        order: Literal["asc", "desc"],
    ) -> Tuple[List[Dict[str, Any]], int]:
        with self._lock:
            rows = [r for r in self._by_id.values() if not r["deleted"]]
            if status:
                rows = [r for r in rows if r["status"] == status]
            if site_id:
                rows = [r for r in rows if r["site_id"] == site_id]
            if model:
                rows = [r for r in rows if r["model"] == model]
            if q:
                ql = q.lower()
                rows = [r for r in rows if ql in r["name"] or ql in (r.get("description") or "").lower()]
            total = len(rows)
            # безопасная сортировка
            key = sort if sort in {"name", "site_id", "model", "created_at", "updated_at"} else "created_at"
            rows.sort(key=lambda r: r[key], reverse=(order == "desc"))
            start = (page - 1) * page_size
            end = start + page_size
            return rows[start:end], total

    def get(self, gid: UUID) -> Optional[Dict[str, Any]]:
        with self._lock:
            rec = self._by_id.get(gid)
            return None if rec is None or rec["deleted"] else dict(rec)

    def update(self, gid: UUID, patch: GatewayUpdate, expected_version: Optional[int]) -> Dict[str, Any]:
        with self._lock:
            rec = self._by_id.get(gid)
            if not rec or rec["deleted"]:
                raise KeyError("not found")
            if expected_version is not None and rec["version"] != expected_version:
                raise RuntimeError("version mismatch")
            # apply
            if patch.description is not None:
                rec["description"] = patch.description
            if patch.labels is not None:
                rec["labels"] = dict(patch.labels)
            if patch.status is not None:
                rec["status"] = patch.status
            rec["version"] += 1
            rec["updated_at"] = _utcnow()
            return dict(rec)

    def rotate_secret(self, gid: UUID, expected_version: Optional[int]) -> Tuple[Dict[str, Any], str]:
        with self._lock:
            rec = self._by_id.get(gid)
            if not rec or rec["deleted"]:
                raise KeyError("not found")
            if expected_version is not None and rec["version"] != expected_version:
                raise RuntimeError("version mismatch")
            new = hashlib.sha256(f"{gid}-{time.time_ns()}".encode()).hexdigest()
            rec["api_secret"] = new
            rec["version"] += 1
            rec["updated_at"] = _utcnow()
            return dict(rec), new

    def soft_delete(self, gid: UUID, expected_version: Optional[int]) -> None:
        with self._lock:
            rec = self._by_id.get(gid)
            if not rec or rec["deleted"]:
                raise KeyError("not found")
            if expected_version is not None and rec["version"] != expected_version:
                raise RuntimeError("version mismatch")
            rec["deleted"] = True
            rec["version"] += 1
            rec["updated_at"] = _utcnow()


_store = _Store()

# --- Безопасность / авторизация (заглушка; замените на реальную) --------------
def require_scope(required: str):
    async def _dep(authorization: Optional[str] = Header(default=None)):
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="Unauthorized")
        # Здесь должна быть валидация JWT/OPA/etc. Заглушка разрешает всё.
        return {"sub": "user", "scopes": ["gateways:read", "gateways:write", "gateways:rotate", "gateways:delete"]}
    return _dep

# --- Утилиты ETag -------------------------------------------------------------
def _etag(rec: Dict[str, Any]) -> str:
    # Слабый ETag на основе версии и updated_at
    payload = f'{rec["id"]}:{rec["version"]}:{rec["updated_at"].timestamp()}'.encode()
    digest = hashlib.sha256(payload).hexdigest()[:16]
    return f'W/"{digest}"'

def _last_modified(rec: Dict[str, Any]) -> str:
    return rec["updated_at"].strftime("%a, %d %b %Y %H:%M:%S GMT")

def _precondition_failed() -> HTTPException:
    return HTTPException(status_code=412, detail="Precondition Failed")

# --- Роутер -------------------------------------------------------------------
router = APIRouter(prefix="/api/v1/gateways", tags=["gateways"])


# Обёртка для метрик
def _instrument(route_name: str):
    def decorator(func):
        async def wrapper(*args, **kwargs):
            start = time.perf_counter()
            try:
                resp = await func(*args, **kwargs)
                code = getattr(resp, "status_code", 200)
                return resp
            finally:
                dur = time.perf_counter() - start
                method = "HTTP"
                try:
                    # Попытаемся извлечь Request из args
                    for a in args:
                        if isinstance(a, Request):
                            method = a.method
                            break
                except Exception:
                    pass
                _metric(route_name, method, locals().get("code", 200), dur)
        return wrapper
    return decorator


# ------------------------- ROUTES ---------------------------------------------

@router.post(
    "",
    response_model=GatewayOut,
    responses={
        201: {"model": GatewayOut},
        400: {"model": ProblemDetails},
        401: {"model": ProblemDetails},
        409: {"model": ProblemDetails},
    },
    status_code=201,
)
@_instrument("create_gateway")
async def create_gateway(
    request: Request,
    payload: GatewayCreate = Body(...),
    idempotency_key: Optional[str] = Header(default=None, alias=IDEMPOTENCY_HEADER),
    _auth=Depends(require_scope("gateways:write")),
):
    # Идемпотентность
    if idempotency_key:
        existed = _store.get_by_idem(idempotency_key)
        if existed:
            rec = _store.get(existed)
            if rec:
                return _json_with_cache_headers(rec, status_code=200)
    # Секрет
    secret = payload.api_secret or hashlib.sha256(f"{payload.name}-{time.time_ns()}".encode()).hexdigest()
    try:
        rec = _store.create(payload, _utcnow(), secret, idempotency_key)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    resp = _json_with_cache_headers(rec, status_code=201)
    return resp


@router.get(
    "",
    response_model=GatewaysPage,
    responses={401: {"model": ProblemDetails}},
)
@_instrument("list_gateways")
async def list_gateways(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    status_q: Optional[GatewayStatus] = Query(default=None, alias="status"),
    site_id: Optional[SiteStr] = Query(default=None),
    model: Optional[ModelStr] = Query(default=None),
    q: Optional[str] = Query(default=None, min_length=1, max_length=128),
    sort: str = Query("created_at"),
    order: Literal["asc", "desc"] = Query("desc"),
    _auth=Depends(require_scope("gateways:read")),
):
    items, total = _store.list(
        page=page,
        page_size=page_size,
        status=status_q,
        site_id=site_id,
        model=model,
        q=q,
        sort=sort,
        order=order,
    )
    data = [GatewayOut(**_public_view(r)) for r in items]
    return GatewaysPage(items=data, meta=PageMeta(page=page, page_size=page_size, total=total))


@router.get(
    "/{gateway_id}",
    response_model=GatewayOut,
    responses={304: {"description": "Not Modified"}, 404: {"model": ProblemDetails}, 401: {"model": ProblemDetails}},
)
@_instrument("get_gateway")
async def get_gateway(
    request: Request,
    response: Response,
    gateway_id: UUID4 = Path(...),
    if_none_match: Optional[str] = Header(default=None, alias="If-None-Match"),
    _auth=Depends(require_scope("gateways:read")),
):
    rec = _store.get(UUID(gateway_id))
    if not rec:
        raise HTTPException(status_code=404, detail="Not found")
    et = _etag(rec)
    if if_none_match and if_none_match == et:
        response.status_code = 304
        # Установка ETag/Last-Modified даже при 304 — хорошая практика
        response.headers["ETag"] = et
        response.headers["Last-Modified"] = _last_modified(rec)
        return Response(status_code=304)
    return _json_with_cache_headers(rec, status_code=200)


@router.patch(
    "/{gateway_id}",
    response_model=GatewayOut,
    responses={200: {"model": GatewayOut}, 404: {"model": ProblemDetails}, 412: {"model": ProblemDetails}},
)
@_instrument("update_gateway")
async def update_gateway(
    request: Request,
    response: Response,
    gateway_id: UUID4 = Path(...),
    payload: GatewayUpdate = Body(...),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
    _auth=Depends(require_scope("gateways:write")),
):
    expected_version = _version_from_etag_header(if_match)
    try:
        rec = _store.update(UUID(gateway_id), payload, expected_version)
    except KeyError:
        raise HTTPException(status_code=404, detail="Not found")
    except RuntimeError:
        raise _precondition_failed()
    return _json_with_cache_headers(rec, status_code=200)


@router.post(
    "/{gateway_id}/secrets",
    response_model=GatewaySecretRotateResponse,
    responses={200: {"model": GatewaySecretRotateResponse}, 404: {"model": ProblemDetails}, 412: {"model": ProblemDetails}},
)
@_instrument("rotate_secret")
async def rotate_secret(
    request: Request,
    response: Response,
    gateway_id: UUID4 = Path(...),
    _: GatewaySecretRotateRequest = Body(default=GatewaySecretRotateRequest()),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
    _auth=Depends(require_scope("gateways:rotate")),
):
    expected_version = _version_from_etag_header(if_match)
    try:
        rec, secret = _store.rotate_secret(UUID(gateway_id), expected_version)
    except KeyError:
        raise HTTPException(status_code=404, detail="Not found")
    except RuntimeError:
        raise _precondition_failed()
    return GatewaySecretRotateResponse(
        id=rec["id"],
        rotated_at=_utcnow(),
        secret_preview=secret[:6],
        version=rec["version"],
    )


@router.post(
    "/{gateway_id}/heartbeat",
    response_model=HeartbeatOut,
    responses={200: {"model": HeartbeatOut}, 404: {"model": ProblemDetails}},
)
@_instrument("heartbeat")
async def heartbeat(
    request: Request,
    gateway_id: UUID4 = Path(...),
    hb: HeartbeatIn = Body(...),
    _auth=Depends(require_scope("gateways:write")),
):
    rec = _store.get(UUID(gateway_id))
    if not rec:
        raise HTTPException(status_code=404, detail="Not found")
    # В реальном мире: обновить last_seen, health и др. Здесь просто логируем.
    log.info(
        "heartbeat gateway_id=%s uptime=%s last_seq=%s health=%s cpu=%.2f mem=%.2f temp=%.2f",
        gateway_id,
        hb.uptime_sec,
        hb.last_seq,
        hb.health,
        hb.cpu_util or -1,
        hb.mem_util or -1,
        hb.board_temp_c or -273.15,
    )
    return HeartbeatOut(ack=True, next_poll_sec=60, apply_config_uri=None)


@router.get(
    "/{gateway_id}/status",
    response_model=Dict[str, Any],
    responses={404: {"model": ProblemDetails}},
)
@_instrument("status")
async def gateway_status(
    request: Request,
    gateway_id: UUID4 = Path(...),
    _auth=Depends(require_scope("gateways:read")),
):
    rec = _store.get(UUID(gateway_id))
    if not rec:
        raise HTTPException(status_code=404, detail="Not found")
    # Статус может аггрегироваться из телеметрии/алертов. Здесь — минимальная сводка.
    return {
        "id": str(rec["id"]),
        "status": rec["status"],
        "site_id": rec["site_id"],
        "model": rec["model"],
        "updated_at": rec["updated_at"].isoformat(),
        "version": rec["version"],
    }


@router.delete(
    "/{gateway_id}",
    status_code=204,
    responses={204: {"description": "No Content"}, 404: {"model": ProblemDetails}, 412: {"model": ProblemDetails}},
)
@_instrument("delete_gateway")
async def delete_gateway(
    request: Request,
    gateway_id: UUID4 = Path(...),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
    _auth=Depends(require_scope("gateways:delete")),
):
    expected_version = _version_from_etag_header(if_match)
    try:
        _store.soft_delete(UUID(gateway_id), expected_version)
    except KeyError:
        raise HTTPException(status_code=404, detail="Not found")
    except RuntimeError:
        raise _precondition_failed()
    return Response(status_code=204)


# --- Вспомогательные функции сериализации ------------------------------------
def _public_view(rec: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(rec)
    out.pop("api_secret", None)
    out.pop("deleted", None)
    return out

def _json_with_cache_headers(rec: Dict[str, Any], status_code: int = 200) -> JSONResponse:
    et = _etag(rec)
    body = GatewayOut(**_public_view(rec)).dict()
    resp = JSONResponse(content=body, status_code=status_code)
    resp.headers["ETag"] = et
    resp.headers["Last-Modified"] = _last_modified(rec)
    return resp

def _version_from_etag_header(if_match: Optional[str]) -> Optional[int]:
    """
    Мы не кодируем версию напрямую в ETag; для защиты от гонок требует If-Match, но версию берём из тела при следующем GET.
    В демонстрационном сторах используем строгую проверку на присутствие If-Match: если передан — считаем, что ожидаемая версия известна.
    Для совместимости возвращаем None, что означает «не применять проверку версии» — допустимо в dev.
    Прод: замените на извлечение версии из сильного ETag/If-Match.
    """
    if not if_match:
        return None
    # В проде заверните вашу стратегию (например, base64(version)).
    return None


# --- Интеграция в приложение --------------------------------------------------
# from fastapi import FastAPI
# app = FastAPI()
# app.include_router(router)

