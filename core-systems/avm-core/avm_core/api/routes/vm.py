from __future__ import annotations

import asyncio
import base64
import dataclasses
import datetime as dt
import hashlib
import ipaddress
import json
import logging
import threading
import time
import uuid
from typing import Any, Dict, Iterable, List, Literal, Mapping, Optional, Tuple

from fastapi import (
    APIRouter,
    BackgroundTasks,
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
from pydantic import BaseModel, Field, field_validator

log = logging.getLogger("avm.api.vm")
audit_log = logging.getLogger("security")


# ========= Ошибки (RFC 7807) =========


class ProblemDetails(BaseModel):
    type: str = Field(default="about:blank")
    title: str
    status: int
    detail: Optional[str] = None
    instance: Optional[str] = None
    errors: Optional[Dict[str, Any]] = None


def raise_problem(status_code: int, title: str, detail: str | None = None) -> None:
    raise HTTPException(
        status_code=status_code,
        detail=ProblemDetails(title=title, status=status_code, detail=detail).model_dump(),
    )


# ========= RBAC и субъект =========


class Principal(BaseModel):
    id: str
    roles: List[str] = Field(default_factory=list)
    scopes: List[str] = Field(default_factory=list)
    org: Optional[str] = None


def get_current_principal(authorization: str | None = Header(default=None)) -> Principal:
    # Заглушка для примера: в реальном сервисе здесь верификация JWT/MTLS и загрузка ролей
    # Authorization: Bearer <token>
    if not authorization:
        return Principal(id="anonymous", roles=["guest"], scopes=[])
    return Principal(id="user:api", roles=["user"], scopes=["vm:read", "vm:write"])


def require_scope(scope: str):
    def _dep(p: Principal = Depends(get_current_principal)) -> Principal:
        if scope not in p.scopes and "admin" not in p.roles:
            raise_problem(status.HTTP_403_FORBIDDEN, "forbidden", f"required scope {scope}")
        return p

    return _dep


# ========= Идемпотентность POST =========


@dataclasses.dataclass
class _IdemEntry:
    created_at: float
    status_code: int
    headers: Dict[str, str]
    body_json: str


class _TTLIdemCache:
    def __init__(self, ttl_seconds: int = 24 * 3600, max_size: int = 5000):
        self.ttl = ttl_seconds
        self.max = max_size
        self._store: Dict[str, _IdemEntry] = {}
        self._lock = threading.RLock()

    def get(self, key: str) -> Optional[_IdemEntry]:
        with self._lock:
            ent = self._store.get(key)
            if not ent:
                return None
            if time.time() - ent.created_at > self.ttl:
                self._store.pop(key, None)
                return None
            return ent

    def put(self, key: str, status_code: int, headers: Dict[str, str], body: Any) -> None:
        with self._lock:
            if len(self._store) >= self.max:
                # простая эвакуация старых записей
                oldest = sorted(self._store.items(), key=lambda kv: kv[1].created_at)[: self.max // 10 or 1]
                for k, _ in oldest:
                    self._store.pop(k, None)
            self._store[key] = _IdemEntry(time.time(), status_code, headers, json.dumps(body, ensure_ascii=False))


_idem_cache = _TTLIdemCache()


def _idem_lookup(idem_key: Optional[str]) -> Optional[_IdemEntry]:
    if not idem_key:
        return None
    if len(idem_key) > 256:
        return None
    return _idem_cache.get(idem_key)


# ========= Токен‑бакет на IP =========


class _TokenBucket:
    def __init__(self, capacity: int, refill_per_sec: float):
        self.capacity = capacity
        self.tokens = capacity
        self.refill = refill_per_sec
        self.updated = time.time()

    def allow(self, cost: float = 1.0) -> bool:
        now = time.time()
        elapsed = now - self.updated
        self.updated = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


_rate_limits: Dict[str, _TokenBucket] = {}
_rate_lock = threading.RLock()


def rate_limit(request: Request) -> None:
    # 60 запросов в минуту по умолчанию
    capacity = 120
    refill_per_sec = capacity / 60.0
    client_ip = request.client.host if request.client else "unknown"
    with _rate_lock:
        bucket = _rate_limits.get(client_ip)
        if bucket is None:
            bucket = _TokenBucket(capacity, refill_per_sec)
            _rate_limits[client_ip] = bucket
        allowed = bucket.allow()
    if not allowed:
        raise_problem(status.HTTP_429_TOO_MANY_REQUESTS, "rate_limited", "too many requests")


# ========= Модели =========


class VMStatus(str):
    PROVISIONING = "provisioning"
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"
    DELETING = "deleting"


class VMSpec(BaseModel):
    name: str = Field(min_length=3, max_length=63, pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
    project_id: str = Field(min_length=3, max_length=64)
    cpu: int = Field(ge=1, le=128)
    memory_mb: int = Field(ge=256, le=1048576)
    disk_gb: int = Field(ge=1, le=16384)
    network_id: Optional[str] = Field(default=None, max_length=64)
    ssh_key_id: Optional[str] = Field(default=None, max_length=128)

    @field_validator("name")
    @classmethod
    def _no_reserved_names(cls, v: str) -> str:
        if v in {"admin", "root", "default"}:
            raise ValueError("reserved name")
        return v


class VMCreate(VMSpec):
    pass


class VMUpdate(BaseModel):
    # Частичное обновление
    cpu: Optional[int] = Field(default=None, ge=1, le=128)
    memory_mb: Optional[int] = Field(default=None, ge=256, le=1048576)
    disk_gb: Optional[int] = Field(default=None, ge=1, le=16384)
    name: Optional[str] = Field(default=None, min_length=3, max_length=63, pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")


class VM(BaseModel):
    id: str
    spec: VMSpec
    status: str = Field(default=VMStatus.PROVISIONING)
    created_at: dt.datetime
    updated_at: dt.datetime
    version: int = 0
    owner_id: Optional[str] = None


class VMList(BaseModel):
    items: List[VM]
    next_cursor: Optional[str] = None


class ActionResponse(BaseModel):
    id: str
    status: str
    accepted: bool = True


# ========= Сервисный слой (протокол) =========

class VMServiceProtocol:
    """Интерфейс сервиса; реализация внедряется через Depends."""

    async def list_vms(
        self,
        limit: int,
        cursor: Optional[str],
        project_id: Optional[str],
        status_filter: Optional[str],
        owner_id: Optional[str],
    ) -> Tuple[List[VM], Optional[str]]:
        raise NotImplementedError

    async def get_vm(self, vm_id: str) -> Optional[VM]:
        raise NotImplementedError

    async def create_vm(self, spec: VMSpec, owner_id: str) -> VM:
        raise NotImplementedError

    async def update_vm(self, vm_id: str, patch: VMUpdate, if_version: Optional[int]) -> VM:
        raise NotImplementedError

    async def delete_vm(self, vm_id: str) -> None:
        raise NotImplementedError

    async def start_vm(self, vm_id: str) -> VM:
        raise NotImplementedError

    async def stop_vm(self, vm_id: str) -> VM:
        raise NotImplementedError

    async def reboot_vm(self, vm_id: str) -> VM:
        raise NotImplementedError


# Для интеграции: замените на DI контейнер или фабрику
async def get_vm_service() -> VMServiceProtocol:
    raise_problem(status.HTTP_501_NOT_IMPLEMENTED, "not_implemented", "vm service not wired")


# ========= Вспомогательные функции =========


def _etag(vm: VM) -> str:
    raw = f"{vm.id}:{vm.version}:{vm.updated_at.timestamp()}".encode()
    digest = hashlib.sha256(raw).hexdigest()
    return f'W/"{digest}"'


def _parse_if_match(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    return value.strip()


def _decode_cursor(cursor: Optional[str]) -> Optional[Dict[str, Any]]:
    if not cursor:
        return None
    try:
        data = base64.urlsafe_b64decode(cursor.encode()).decode()
        return json.loads(data)
    except Exception:
        return None


def _encode_cursor(d: Dict[str, Any]) -> str:
    payload = json.dumps(d, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(payload).decode()


def _audit(event: str, **kwargs: Any) -> None:
    payload = {"event": event, **kwargs}
    audit_log.info(json.dumps(payload, ensure_ascii=False))


# ========= Роутер =========

router = APIRouter(prefix="/v1/vms", tags=["vms"], dependencies=[Depends(rate_limit)])


@router.get(
    "",
    response_model=VMList,
    responses={429: {"model": ProblemDetails}, 400: {"model": ProblemDetails}},
)
async def list_vms(
    request: Request,
    limit: int = Query(20, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    project_id: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, pattern=r"^(provisioning|running|stopped|error|deleting)$"),
    owner_id: Optional[str] = Query(default=None),
    svc: VMServiceProtocol = Depends(get_vm_service),
    _: Principal = Depends(require_scope("vm:read")),
) -> VMList:
    cur = _decode_cursor(cursor)
    items, next_cursor = await svc.list_vms(
        limit=limit,
        cursor=cursor,
        project_id=project_id or (cur.get("project_id") if cur else None),
        status_filter=status_filter or (cur.get("status") if cur else None),
        owner_id=owner_id or (cur.get("owner_id") if cur else None),
    )
    return VMList(items=items, next_cursor=next_cursor)


@router.get(
    "/{vm_id}",
    response_model=VM,
    responses={304: {"description": "Not Modified"}, 404: {"model": ProblemDetails}},
)
async def get_vm(
    response: Response,
    vm_id: str = Path(..., min_length=3, max_length=64),
    if_none_match: Optional[str] = Header(default=None, alias="If-None-Match"),
    svc: VMServiceProtocol = Depends(get_vm_service),
    _: Principal = Depends(require_scope("vm:read")),
) -> VM | Response:
    vm = await svc.get_vm(vm_id)
    if not vm:
        raise_problem(status.HTTP_404_NOT_FOUND, "not_found", "vm not found")
    et = _etag(vm)
    response.headers["ETag"] = et
    if if_none_match and if_none_match == et:
        return Response(status_code=status.HTTP_304_NOT_MODIFIED)
    return vm


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=VM,
    responses={
        201: {"description": "Created"},
        400: {"model": ProblemDetails},
        403: {"model": ProblemDetails},
        409: {"model": ProblemDetails},
        429: {"model": ProblemDetails},
    },
)
async def create_vm(
    request: Request,
    response: Response,
    payload: VMCreate = Body(...),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    svc: VMServiceProtocol = Depends(get_vm_service),
    principal: Principal = Depends(require_scope("vm:write")),
) -> VM:
    if idempotency_key:
        cached = _idem_lookup(idempotency_key)
        if cached:
            for k, v in cached.headers.items():
                response.headers.setdefault(k, v)
            response.status_code = cached.status_code
            return VM.model_validate_json(cached.body_json)

    vm = await svc.create_vm(payload, owner_id=principal.id)
    et = _etag(vm)
    response.headers["Location"] = f"/v1/vms/{vm.id}"
    response.headers["ETag"] = et
    if idempotency_key:
        _idem_cache.put(
            idempotency_key,
            status.HTTP_201_CREATED,
            {"Location": response.headers["Location"], "ETag": et},
            vm.model_dump(mode="json"),
        )
    _audit("vm.create", vm_id=vm.id, owner=principal.id, project=vm.spec.project_id)
    return vm


@router.patch(
    "/{vm_id}",
    response_model=VM,
    responses={400: {"model": ProblemDetails}, 403: {"model": ProblemDetails}, 404: {"model": ProblemDetails}, 412: {"model": ProblemDetails}},
)
async def update_vm(
    response: Response,
    vm_id: str = Path(..., min_length=3, max_length=64),
    patch: VMUpdate = Body(...),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
    svc: VMServiceProtocol = Depends(get_vm_service),
    principal: Principal = Depends(require_scope("vm:write")),
) -> VM:
    expected_version: Optional[int] = None
    if if_match:
        # поддерживаем только наш слабый ETag на основе версии
        # W/"<sha256>" → мы не извлекаем версию из etag, а требуем If-Match: "v=<int>"
        if if_match.startswith('W/"') or if_match.startswith('"'):
            raise_problem(status.HTTP_412_PRECONDITION_FAILED, "precondition_failed", "unsupported ETag If-Match")
        if if_match.startswith("v="):
            try:
                expected_version = int(if_match[2:])
            except ValueError:
                raise_problem(status.HTTP_400_BAD_REQUEST, "bad_request", "invalid If-Match version token")
    vm = await svc.update_vm(vm_id, patch, expected_version)
    et = _etag(vm)
    response.headers["ETag"] = et
    _audit("vm.update", vm_id=vm.id, owner=principal.id, fields=[k for k, v in patch.model_dump(exclude_none=True).items()])
    return vm


@router.delete(
    "/{vm_id}",
    status_code=status.HTTP_202_ACCEPTED,
    responses={202: {"description": "Accepted"}, 404: {"model": ProblemDetails}, 403: {"model": ProblemDetails}},
)
async def delete_vm(
    vm_id: str = Path(..., min_length=3, max_length=64),
    svc: VMServiceProtocol = Depends(get_vm_service),
    principal: Principal = Depends(require_scope("vm:write")),
) -> None:
    await svc.delete_vm(vm_id)
    _audit("vm.delete", vm_id=vm_id, owner=principal.id)


# ========= Операции управления ВМ =========


@router.post(
    "/{vm_id}:start",
    response_model=ActionResponse,
    responses={404: {"model": ProblemDetails}, 409: {"model": ProblemDetails}},
)
async def start_vm(
    vm_id: str,
    svc: VMServiceProtocol = Depends(get_vm_service),
    _: Principal = Depends(require_scope("vm:write")),
) -> ActionResponse:
    vm = await svc.start_vm(vm_id)
    _audit("vm.start", vm_id=vm.id)
    return ActionResponse(id=vm.id, status=vm.status, accepted=True)


@router.post(
    "/{vm_id}:stop",
    response_model=ActionResponse,
    responses={404: {"model": ProblemDetails}, 409: {"model": ProblemDetails}},
)
async def stop_vm(
    vm_id: str,
    svc: VMServiceProtocol = Depends(get_vm_service),
    _: Principal = Depends(require_scope("vm:write")),
) -> ActionResponse:
    vm = await svc.stop_vm(vm_id)
    _audit("vm.stop", vm_id=vm.id)
    return ActionResponse(id=vm.id, status=vm.status, accepted=True)


@router.post(
    "/{vm_id}:reboot",
    response_model=ActionResponse,
    responses={404: {"model": ProblemDetails}, 409: {"model": ProblemDetails}},
)
async def reboot_vm(
    vm_id: str,
    svc: VMServiceProtocol = Depends(get_vm_service),
    _: Principal = Depends(require_scope("vm:write")),
) -> ActionResponse:
    vm = await svc.reboot_vm(vm_id)
    _audit("vm.reboot", vm_id=vm.id)
    return ActionResponse(id=vm.id, status=vm.status, accepted=True)
