# cybersecurity-core/api/http/routers/v1/scans.py
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import re
from datetime import datetime, timezone
from enum import Enum
from typing import AsyncGenerator, Dict, List, Optional, Tuple, Union
from uuid import UUID

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Body,
    Depends,
    Header,
    HTTPException,
    Path,
    Query,
    Response,
    status,
)
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import AnyHttpUrl, BaseModel, Field, root_validator, validator

# === Dependencies expected from project (provided elsewhere in cybersecurity-core) ===
# Async DB session (SQLAlchemy)
try:
    from cybersecurity_core.db.dependencies import get_async_session
except Exception:  # pragma: no cover - fallback for static analysis
    async def get_async_session():
        raise RuntimeError("get_async_session is not wired")

# Principal / RBAC
try:
    from cybersecurity_core.auth.dependencies import get_current_principal
    from cybersecurity_core.auth.models import Principal  # org_id: UUID, roles: set[str]
except Exception:  # pragma: no cover
    class Principal(BaseModel):
        sub: str
        org_id: Optional[UUID]
        roles: List[str] = []

    async def get_current_principal() -> Principal:
        raise RuntimeError("get_current_principal is not wired")

# Repository interface
try:
    from cybersecurity_core.repositories.scans import (
        ScanRepository,
        ScanFilters,
        PageCursor,
        FindingFilters,
    )
except Exception:  # pragma: no cover - minimal protocol-like stubs
    class ScanRepository:  # type: ignore
        async def create_scan(self, *args, **kwargs): ...
        async def get_scan(self, *args, **kwargs): ...
        async def find_scan_by_idempo(self, *args, **kwargs): ...
        async def search_scans(self, *args, **kwargs): ...
        async def cancel_scan(self, *args, **kwargs): ...
        async def retry_scan(self, *args, **kwargs): ...
        async def list_findings(self, *args, **kwargs): ...
        async def stream_findings_ndjson(self, *args, **kwargs): ...
        async def get_artifact(self, *args, **kwargs): ...
        async def update_status_callback(self, *args, **kwargs): ...

    class ScanFilters(BaseModel):  # type: ignore
        ...

    class PageCursor(BaseModel):  # type: ignore
        ...

    class FindingFilters(BaseModel):  # type: ignore
        ...

try:
    from cybersecurity_core.repositories.dependencies import get_scan_repository
except Exception:  # pragma: no cover
    async def get_scan_repository() -> ScanRepository:
        raise RuntimeError("get_scan_repository is not wired")

# Enqueue job into task bus
try:
    from cybersecurity_core.tasks.scan_queue import enqueue_scan_job
except Exception:  # pragma: no cover
    async def enqueue_scan_job(*args, **kwargs):
        # Fallback: no-op; in prod this publishes to broker
        return None

# Settings
try:
    from cybersecurity_core.settings import Settings, get_settings
except Exception:  # pragma: no cover
    class Settings(BaseModel):
        scanner_hmac_secret: str = "CHANGE_ME"
        results_max_page_size: int = 1000
        scans_max_page_size: int = 200
        api_etag_salt: str = "etag-salt"

    async def get_settings() -> Settings:
        return Settings()


logger = logging.getLogger("cybersecurity_core.api.scans")

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


# =========================
# Models (Pydantic v1)
# =========================

class ScanType(str, Enum):
    port = "port"
    vuln = "vuln"
    web = "web"
    cloud = "cloud"
    mobile = "mobile"
    container = "container"
    custom = "custom"


class ScanStatus(str, Enum):
    pending = "pending"
    queued = "queued"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    cancelled = "cancelled"
    timeout = "timeout"
    partial = "partial"


class Severity(str, Enum):
    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


TARGET_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)
TARGET_URL_RE = re.compile(r"^(https?|ftp)://[^\s/$.?#].[^\s]*$", re.IGNORECASE)


def _is_ip_or_cidr(s: str) -> bool:
    try:
        if "/" in s:
            ipaddress.ip_network(s, strict=False)
        else:
            ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


class ScanCreateOptions(BaseModel):
    profile: Optional[str] = Field(
        None, description="Имя профиля инструмента (набор пресетов/политик)"
    )
    timeout_seconds: Optional[int] = Field(
        None, ge=30, le=24 * 3600, description="Таймаут выполнения"
    )
    parallelism: Optional[int] = Field(
        None, ge=1, le=1024, description="Количество параллельных воркеров"
    )
    extra_args: Dict[str, Union[str, int, float, bool]] = Field(
        default_factory=dict, description="Произвольные параметры для сканера"
    )


class ScanCreateRequest(BaseModel):
    scan_type: ScanType = Field(..., description="Тип сканирования")
    targets: List[str] = Field(
        ..., min_items=1, max_items=10000, description="Список целей (IP/ CIDR / домены / URL)"
    )
    options: ScanCreateOptions = Field(
        default_factory=ScanCreateOptions, description="Опции сканера"
    )
    priority: int = Field(
        5, ge=0, le=10, description="Приоритет постановки в очередь (0..10, чем больше — выше)"
    )
    tags: List[str] = Field(default_factory=list, description="Теги скана")
    tlp: Optional[str] = Field(
        None,
        description="Метка распространения (например, TLP:CLEAR|GREEN|AMBER|AMBER+STRICT|RED)",
        regex=r"^(TLP:CLEAR|TLP:GREEN|TLP:AMBER|TLP:AMBER\+STRICT|TLP:RED)$",
    )
    schedule_cron: Optional[str] = Field(
        None, description="Cron-расписание для периодических сканов"
    )
    note: Optional[str] = Field(None, max_length=2000, description="Заметка оператора")

    @validator("targets", each_item=True)
    def validate_target(cls, v: str) -> str:
        s = v.strip()
        if _is_ip_or_cidr(s):
            return s
        if TARGET_DOMAIN_RE.match(s):
            return s
        if TARGET_URL_RE.match(s):
            return s
        raise ValueError("target must be IP, CIDR, domain or URL")


class ScanSummary(BaseModel):
    id: UUID
    org_id: Optional[UUID]
    scan_type: ScanType
    status: ScanStatus
    created_at: datetime
    updated_at: datetime
    queued_at: Optional[datetime]
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    progress: int = Field(0, ge=0, le=100)
    targets_count: int
    priority: int
    tags: List[str] = []
    tlp: Optional[str] = None
    etag: Optional[str] = None


class CreateScanResponse(BaseModel):
    scan: ScanSummary
    idempotent_reuse: bool = False


class PageMeta(BaseModel):
    next_cursor: Optional[str] = None
    limit: int


class ScanListResponse(BaseModel):
    items: List[ScanSummary]
    page: PageMeta


class Finding(BaseModel):
    id: UUID
    scan_id: UUID
    title: str
    severity: Severity
    cvss: Optional[float] = Field(None, ge=0.0, le=10.0)
    cve: List[str] = Field(default_factory=list)
    asset: str
    description: Optional[str] = None
    evidence: Optional[Dict[str, Union[str, int, float, bool, dict, list]]] = None
    first_seen: datetime
    last_seen: datetime


class FindingsListResponse(BaseModel):
    items: List[Finding]
    page: PageMeta


class CallbackPayload(BaseModel):
    status: ScanStatus
    progress: Optional[int] = Field(None, ge=0, le=100)
    findings_added: Optional[int] = Field(None, ge=0)
    severity_counts: Optional[Dict[Severity, int]] = None
    message: Optional[str] = Field(None, max_length=4000)


# =========================
# RBAC helpers
# =========================

def _require_roles(principal: Principal, allowed: Tuple[str, ...]) -> None:
    roles = set(getattr(principal, "roles", []) or [])
    if not (roles.intersection(allowed)):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")


# =========================
# ETag helpers
# =========================

def _compute_etag(obj_updated_at: datetime, settings: Settings) -> str:
    # Weak ETag based on timestamp + salt
    base = f"{obj_updated_at.replace(microsecond=0).isoformat()}|{settings.api_etag_salt}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


# =========================
# Routes
# =========================

@router.post(
    "",
    response_model=CreateScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Создать скан (идемпотентно)",
)
async def create_scan(
    payload: ScanCreateRequest = Body(...),
    background: BackgroundTasks = None,
    idempotency_key: Optional[str] = Header(
        None, alias="Idempotency-Key", description="Ключ идемпотентности для повторных попыток"
    ),
    principal: Principal = Depends(get_current_principal),
    session=Depends(get_async_session),
    repo: ScanRepository = Depends(get_scan_repository),
):
    _require_roles(principal, ("admin", "analyst"))
    idempo = idempotency_key.strip() if idempotency_key else None
    existing = None
    if idempo:
        try:
            existing = await repo.find_scan_by_idempo(session=session, org_id=principal.org_id, key=idempo)
        except Exception:
            logger.exception("idempotency lookup failed")

    if existing:
        # Возвращаем существующую запись
        settings = await get_settings()
        etag = _compute_etag(existing["updated_at"], settings)
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=CreateScanResponse(
                scan=ScanSummary(**{**existing, "etag": etag}), idempotent_reuse=True
            ).dict(),
            headers={"ETag": etag},
        )

    # Создать запись скана
    try:
        record = await repo.create_scan(
            session=session,
            org_id=principal.org_id,
            payload=payload.dict(),
            idempotency_key=idempo,
            created_by=principal.sub,
        )
    except Exception as e:
        logger.exception("create_scan failed")
        raise HTTPException(status_code=500, detail="failed to create scan") from e

    # Поставить задачу в очередь
    background.add_task(enqueue_scan_job, scan_id=record["id"])

    settings = await get_settings()
    etag = _compute_etag(record["updated_at"], settings)
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=CreateScanResponse(scan=ScanSummary(**{**record, "etag": etag}), idempotent_reuse=False).dict(),
        headers={"ETag": etag},
    )


@router.get(
    "/{scan_id}",
    response_model=ScanSummary,
    summary="Получить скан по ID (ETag/304)",
)
async def get_scan(
    scan_id: UUID = Path(...),
    if_none_match: Optional[str] = Header(None, alias="If-None-Match"),
    principal: Principal = Depends(get_current_principal),
    session=Depends(get_async_session),
    repo: ScanRepository = Depends(get_scan_repository),
):
    _require_roles(principal, ("admin", "analyst", "viewer"))
    record = await repo.get_scan(session=session, org_id=principal.org_id, scan_id=scan_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")

    settings = await get_settings()
    etag = _compute_etag(record["updated_at"], settings)
    if if_none_match and if_none_match == etag:
        return Response(status_code=status.HTTP_304_NOT_MODIFIED)

    return JSONResponse(
        content=ScanSummary(**{**record, "etag": etag}).dict(),
        headers={"ETag": etag},
    )


@router.get(
    "",
    response_model=ScanListResponse,
    summary="Список сканов (фильтры, cursor-пагинация)",
)
async def list_scans(
    status_in: Optional[List[ScanStatus]] = Query(None),
    scan_type: Optional[ScanType] = Query(None),
    tag: Optional[str] = Query(None),
    target_like: Optional[str] = Query(None, description="Подстрока цели (LIKE/ILIKE)"),
    created_from: Optional[datetime] = Query(None),
    created_to: Optional[datetime] = Query(None),
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    principal: Principal = Depends(get_current_principal),
    session=Depends(get_async_session),
    repo: ScanRepository = Depends(get_scan_repository),
    settings: Settings = Depends(get_settings),
):
    _require_roles(principal, ("admin", "analyst", "viewer"))
    limit = min(limit, settings.scans_max_page_size)
    filters = {
        "status_in": [s.value for s in status_in] if status_in else None,
        "scan_type": scan_type.value if scan_type else None,
        "tag": tag,
        "target_like": target_like,
        "created_from": created_from,
        "created_to": created_to,
    }
    page = await repo.search_scans(
        session=session,
        org_id=principal.org_id,
        filters=filters,
        cursor=cursor,
        limit=limit,
    )
    # page: {"items":[{...}], "next_cursor": "..."}
    items = []
    for it in page["items"]:
        etag = _compute_etag(it["updated_at"], settings)
        items.append(ScanSummary(**{**it, "etag": etag}))
    return ScanListResponse(items=items, page=PageMeta(next_cursor=page.get("next_cursor"), limit=limit))


@router.post(
    "/{scan_id}:cancel",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Отменить скан",
)
async def cancel_scan(
    scan_id: UUID = Path(...),
    principal: Principal = Depends(get_current_principal),
    session=Depends(get_async_session),
    repo: ScanRepository = Depends(get_scan_repository),
):
    _require_roles(principal, ("admin", "analyst"))
    ok = await repo.cancel_scan(session=session, org_id=principal.org_id, scan_id=scan_id)
    if not ok:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="cannot cancel")
    return {"accepted": True}


@router.post(
    "/{scan_id}:retry",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ретрай скана",
)
async def retry_scan(
    scan_id: UUID = Path(...),
    principal: Principal = Depends(get_current_principal),
    session=Depends(get_async_session),
    repo: ScanRepository = Depends(get_scan_repository),
    background: BackgroundTasks = None,
):
    _require_roles(principal, ("admin", "analyst"))
    ok = await repo.retry_scan(session=session, org_id=principal.org_id, scan_id=scan_id, requested_by=principal.sub)
    if not ok:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="cannot retry")
    background.add_task(enqueue_scan_job, scan_id=scan_id)
    return {"accepted": True}


@router.get(
    "/{scan_id}/findings",
    response_model=FindingsListResponse,
    summary="Список находок по скану (пагинация)",
)
async def list_findings(
    scan_id: UUID = Path(...),
    severity_in: Optional[List[Severity]] = Query(None),
    q: Optional[str] = Query(None, description="Поиск по названию/описанию"),
    cursor: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=5000),
    principal: Principal = Depends(get_current_principal),
    session=Depends(get_async_session),
    repo: ScanRepository = Depends(get_scan_repository),
    settings: Settings = Depends(get_settings),
):
    _require_roles(principal, ("admin", "analyst", "viewer"))
    limit = min(limit, settings.results_max_page_size)
    filters = {
        "severity_in": [s.value for s in severity_in] if severity_in else None,
        "q": q,
    }
    page = await repo.list_findings(
        session=session,
        org_id=principal.org_id,
        scan_id=scan_id,
        filters=filters,
        cursor=cursor,
        limit=limit,
    )
    items = [Finding(**it) for it in page["items"]]
    return FindingsListResponse(items=items, page=PageMeta(next_cursor=page.get("next_cursor"), limit=limit))


@router.get(
    "/{scan_id}/findings.ndjson",
    summary="Стрим находок в NDJSON",
)
async def stream_findings_ndjson(
    scan_id: UUID = Path(...),
    principal: Principal = Depends(get_current_principal),
    session=Depends(get_async_session),
    repo: ScanRepository = Depends(get_scan_repository),
):
    _require_roles(principal, ("admin", "analyst", "viewer"))

    async def gen() -> AsyncGenerator[bytes, None]:
        async for line in repo.stream_findings_ndjson(session=session, org_id=principal.org_id, scan_id=scan_id):
            # Ожидается, что line — JSON-словарь; сериализуем в NDJSON
            yield (json.dumps(line, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")

    return StreamingResponse(gen(), media_type="application/x-ndjson")


@router.get(
    "/{scan_id}/artifacts/{artifact_id}",
    summary="Загрузить артефакт скана (binary)",
)
async def download_artifact(
    scan_id: UUID = Path(...),
    artifact_id: UUID = Path(...),
    principal: Principal = Depends(get_current_principal),
    session=Depends(get_async_session),
    repo: ScanRepository = Depends(get_scan_repository),
):
    _require_roles(principal, ("admin", "analyst", "viewer"))
    found = await repo.get_artifact(session=session, org_id=principal.org_id, scan_id=scan_id, artifact_id=artifact_id)
    if not found:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="artifact not found")
    # found: {"content_type": "...", "filename": "...", "data": <bytes>}
    return Response(
        content=found["data"],
        media_type=found.get("content_type") or "application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{found.get("filename") or str(artifact_id)}"',
        },
    )


# =========================
# Secure scanner callback (HMAC)
# =========================

def _verify_hmac(signature_header: str, body_bytes: bytes, secret: str) -> bool:
    """
    signature_header: "sha256=<base64digest>"
    """
    try:
        algo, b64 = signature_header.split("=", 1)
        if algo.lower() != "sha256":
            return False
        expected = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).digest()
        provided = base64.b64decode(b64)
        return hmac.compare_digest(expected, provided)
    except Exception:
        return False


@router.post(
    "/{scan_id}/callback",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Callback от сканера (HMAC-подписанный)",
)
async def scanner_callback(
    scan_id: UUID = Path(...),
    payload: CallbackPayload = Body(...),
    signature: str = Header(..., alias="X-Scanner-Signature", description="sha256=<base64digest>"),
    settings: Settings = Depends(get_settings),
    session=Depends(get_async_session),
    repo: ScanRepository = Depends(get_scan_repository),
):
    # Проверка HMAC
    raw = json.dumps(payload.dict(), separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if not _verify_hmac(signature, raw, settings.scanner_hmac_secret):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid signature")

    try:
        await repo.update_status_callback(
            session=session,
            scan_id=scan_id,
            status=payload.status.value,
            progress=payload.progress,
            findings_added=payload.findings_added,
            severity_counts={k.value: v for k, v in (payload.severity_counts or {}).items()},
            message=payload.message,
        )
    except Exception as e:
        logger.exception("scanner_callback failed")
        raise HTTPException(status_code=500, detail="callback processing failed") from e

    return {"accepted": True}
