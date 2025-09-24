# chronowatch-core/api/http/routers/v1/windows.py
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Dict, Iterable, Literal, Optional
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator

# ------------------------------------------------------------------------------
# Utilities
# ------------------------------------------------------------------------------

_DURATION_RE = re.compile(r"^(?P<value>\d+)(?P<unit>ms|s|m|h|d|w)$")
_ISO8601_RE = re.compile(
    r"^P(?:(?P<weeks>\d+)W)?(?:(?P<days>\d+)D)?(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+)S)?)?$",
    re.IGNORECASE,
)


def parse_duration(text: str) -> timedelta:
    """
    Parse duration in compact or ISO-8601 form.
    Supported compact units: ms, s, m, h, d, w (e.g., "5m", "1h", "250ms", "7d").
    Supported ISO-8601 subset: PnW nD TnH nM nS (e.g., "PT5M", "P1DT2H", "P2W").
    Raises ValueError on invalid format.
    """
    text = text.strip()
    m = _DURATION_RE.match(text)
    if m:
        val = int(m.group("value"))
        unit = m.group("unit")
        if unit == "ms":
            return timedelta(milliseconds=val)
        if unit == "s":
            return timedelta(seconds=val)
        if unit == "m":
            return timedelta(minutes=val)
        if unit == "h":
            return timedelta(hours=val)
        if unit == "d":
            return timedelta(days=val)
        if unit == "w":
            return timedelta(weeks=val)
    im = _ISO8601_RE.match(text)
    if im:
        weeks = int(im.group("weeks") or 0)
        days = int(im.group("days") or 0)
        hours = int(im.group("hours") or 0)
        minutes = int(im.group("minutes") or 0)
        seconds = int(im.group("seconds") or 0)
        return timedelta(weeks=weeks, days=days, hours=hours, minutes=minutes, seconds=seconds)
    raise ValueError(f"Invalid duration format: {text}")


def to_timezone(dt: datetime, tz_name: str) -> datetime:
    tz = ZoneInfo(tz_name)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(tz)


def align_floor(dt: datetime, step: timedelta, tz_name: str) -> datetime:
    """
    Floor-align datetime to step boundary in a given timezone.
    """
    tz = ZoneInfo(tz_name)
    dt_tz = dt.astimezone(tz)
    epoch = datetime(1970, 1, 1, tzinfo=tz)
    delta = dt_tz - epoch
    seconds = int(delta.total_seconds())
    step_s = int(step.total_seconds())
    if step_s <= 0:
        return dt_tz
    aligned_s = (seconds // step_s) * step_s
    return epoch + timedelta(seconds=aligned_s)


def compute_etag(payload: Any) -> str:
    normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(normalized).hexdigest()


def ensure_no_store_headers(resp: Response, etag: Optional[str] = None, request_id: Optional[str] = None) -> None:
    resp.headers["Cache-Control"] = "no-store"
    if etag:
        resp.headers["ETag"] = etag
    if request_id:
        resp.headers["X-Request-Id"] = request_id


# ------------------------------------------------------------------------------
# Schemas
# ------------------------------------------------------------------------------

class WindowType(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["fixed", "rolling"]


class RollingWindowSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["rolling"] = "rolling"
    size: str = Field(..., description="Длительность окна, например: 5m, 1h, PT30M")
    step: Optional[str] = Field(None, description="Шаг выравнивания. Если не задан, равен size.")
    timezone: str = Field(default="UTC", description="IANA таймзона для вычисления границ.")
    align: bool = Field(default=True, description="Выравнивать начальную границу по step.")
    offset: Optional[str] = Field(None, description="Сдвиг окна назад от 'now' (например, 1m).")

    @field_validator("size")
    @classmethod
    def _validate_size(cls, v: str) -> str:
        _ = parse_duration(v)  # raises if invalid
        return v

    @field_validator("step")
    @classmethod
    def _validate_step(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        _ = parse_duration(v)
        return v

    @field_validator("timezone")
    @classmethod
    def _validate_tz(cls, v: str) -> str:
        # raises if invalid zone
        _ = ZoneInfo(v)
        return v


class FixedWindowSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["fixed"] = "fixed"
    start: datetime = Field(..., description="ISO8601 datetime. Если без таймзоны — предполагается UTC.")
    end: datetime = Field(..., description="ISO8601 datetime. Должен быть больше start.")
    timezone: str = Field(default="UTC", description="IANA таймзона для выравнивания/отображения.")
    align: bool = Field(default=False, description="При true — выравнять start вниз, end вверх по step, если задан.")
    step: Optional[str] = Field(None, description="Шаг выравнивания границ; опционально.")

    @model_validator(mode="after")
    def _validate_range(self) -> "FixedWindowSpec":
        s = self.start
        e = self.end
        if s.tzinfo is None:
            s = s.replace(tzinfo=UTC)
        if e.tzinfo is None:
            e = e.replace(tzinfo=UTC)
        if e <= s:
            raise ValueError("end must be greater than start")
        # optional align check
        if self.align and self.step:
            step_td = parse_duration(self.step)
            tz = self.timezone
            s_al = align_floor(s, step_td, tz)
            if s_al != s.astimezone(ZoneInfo(tz)):
                # alignment will be applied at runtime; we only ensure step validity
                pass
        return self

    @field_validator("timezone")
    @classmethod
    def _validate_tz(cls, v: str) -> str:
        _ = ZoneInfo(v)
        return v

    @field_validator("step")
    @classmethod
    def _validate_step(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        _ = parse_duration(v)
        return v


WindowSpec = Annotated[RollingWindowSpec | FixedWindowSpec, Field(discriminator="type")]


class WindowBase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(..., min_length=1, max_length=100, pattern=r"^[a-z0-9]([-a-z0-9_.]*[a-z0-9])?$")
    description: Optional[str] = Field(None, max_length=1024)
    labels: Dict[str, str] = Field(default_factory=dict, description="Произвольные метки (до 128 шт.)")
    spec: WindowSpec


class WindowCreate(WindowBase):
    pass


class WindowUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    description: Optional[str] = Field(None, max_length=1024)
    labels: Optional[Dict[str, str]] = None
    spec: Optional[WindowSpec] = None


class WindowStored(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: UUID
    version: int
    created_at: datetime
    updated_at: datetime
    etag: str
    name: str
    description: Optional[str]
    labels: Dict[str, str]
    spec: WindowSpec


class WindowList(BaseModel):
    model_config = ConfigDict(extra="forbid")
    total: int
    items: list[WindowStored]


class PreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    spec: WindowSpec
    now: Optional[datetime] = None


class PreviewResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    start: datetime
    end: datetime
    duration_ms: int
    aligned: bool


# ------------------------------------------------------------------------------
# Service layer (in-memory reference; replace with DB-backed implementation)
# ------------------------------------------------------------------------------

class WindowService:
    """
    Thread-safe in-memory implementation. Replace with DB repository in production.
    """
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._store: dict[UUID, WindowStored] = {}
        self._by_name: dict[str, UUID] = {}
        self._idem: dict[str, UUID] = {}  # Idempotency-Key -> resource id

    def _compute_etag(self, payload: dict[str, Any]) -> str:
        return compute_etag(payload)

    def list(self, offset: int, limit: int) -> tuple[int, list[WindowStored]]:
        with self._lock:
            items = list(self._store.values())
            items.sort(key=lambda r: (r.created_at, r.id))
            total = len(items)
            sliced = items[offset : offset + limit]
            return total, sliced

    def get(self, id_: UUID) -> Optional[WindowStored]:
        with self._lock:
            return self._store.get(id_)

    def get_by_name(self, name: str) -> Optional[WindowStored]:
        with self._lock:
            rid = self._by_name.get(name)
            return self._store.get(rid) if rid else None

    def create(self, data: WindowCreate, idem_key: Optional[str]) -> WindowStored:
        with self._lock:
            if idem_key:
                if idem_key in self._idem:
                    rid = self._idem[idem_key]
                    existing = self._store.get(rid)
                    if existing:
                        return existing

            if self._by_name.get(data.name):
                raise ValueError("name already exists")

            now = datetime.now(UTC)
            spec_payload = json.loads(data.spec.model_dump_json())
            payload = {
                "name": data.name,
                "description": data.description,
                "labels": data.labels,
                "spec": spec_payload,
            }
            etag = self._compute_etag(payload)
            rec = WindowStored(
                id=uuid4(),
                version=1,
                created_at=now,
                updated_at=now,
                etag=etag,
                name=data.name,
                description=data.description,
                labels=data.labels,
                spec=data.spec,
            )
            self._store[rec.id] = rec
            self._by_name[rec.name] = rec.id
            if idem_key:
                self._idem[idem_key] = rec.id
            return rec

    def update(self, id_: UUID, patch: WindowUpdate, if_match: Optional[str]) -> WindowStored:
        with self._lock:
            rec = self._store.get(id_)
            if not rec:
                raise KeyError("not found")
            if if_match and rec.etag != if_match:
                raise PermissionError("etag_mismatch")

            # Apply updates
            data = rec.model_dump()
            if patch.description is not None:
                data["description"] = patch.description
            if patch.labels is not None:
                data["labels"] = patch.labels
            if patch.spec is not None:
                data["spec"] = json.loads(patch.spec.model_dump_json())

            now = datetime.now(UTC)
            # Recompute ETag/version
            payload = {
                "name": data["name"],
                "description": data["description"],
                "labels": data["labels"],
                "spec": data["spec"],
            }
            etag = self._compute_etag(payload)

            new_rec = WindowStored(
                id=rec.id,
                version=rec.version + 1,
                created_at=rec.created_at,
                updated_at=now,
                etag=etag,
                name=rec.name,
                description=data["description"],
                labels=data["labels"],
                spec=patch.spec if patch.spec is not None else rec.spec,
            )
            self._store[id_] = new_rec
            return new_rec

    def delete(self, id_: UUID, if_match: Optional[str]) -> None:
        with self._lock:
            rec = self._store.get(id_)
            if not rec:
                raise KeyError("not found")
            if if_match and rec.etag != if_match:
                raise PermissionError("etag_mismatch")
            del self._store[id_]
            self._by_name.pop(rec.name, None)

    def compute_preview(self, spec: WindowSpec, now: Optional[datetime]) -> PreviewResult:
        now = now or datetime.now(UTC)
        if now.tzinfo is None:
            now = now.replace(tzinfo=UTC)

        if isinstance(spec, RollingWindowSpec):
            size = parse_duration(spec.size)
            step = parse_duration(spec.step) if spec.step else size
            tz = spec.timezone
            offset = parse_duration(spec.offset) if spec.offset else timedelta(0)
            end = to_timezone(now - offset, tz)
            start = end - size
            aligned = False
            if spec.align:
                end_al = align_floor(end, step, tz)
                start_al = end_al - size
                start, end = start_al, end_al
                aligned = True
            return PreviewResult(
                start=start.astimezone(UTC),
                end=end.astimezone(UTC),
                duration_ms=int(size.total_seconds() * 1000),
                aligned=aligned,
            )

        if isinstance(spec, FixedWindowSpec):
            tz = spec.timezone
            start = spec.start if spec.start.tzinfo else spec.start.replace(tzinfo=UTC)
            end = spec.end if spec.end.tzinfo else spec.end.replace(tzinfo=UTC)
            aligned = False
            if spec.align and spec.step:
                step = parse_duration(spec.step)
                start_al = align_floor(start, step, tz)
                # end align up to next boundary if not aligned
                end_floor = align_floor(end - timedelta(microseconds=1), step, tz)
                end_al = end_floor + step
                start, end = start_al, end_al
                aligned = True
            dur = end - start
            return PreviewResult(
                start=start.astimezone(UTC), end=end.astimezone(UTC), duration_ms=int(dur.total_seconds() * 1000), aligned=aligned
            )

        # Should not reach
        raise ValueError("Unsupported spec type")


# Singleton in-memory service for this process
_service = WindowService()


def get_service() -> WindowService:
    return _service


# ------------------------------------------------------------------------------
# Router
# ------------------------------------------------------------------------------

router = APIRouter(prefix="/v1/windows", tags=["windows"])


def _require_etag_header(etag: Optional[str]) -> str:
    if not etag:
        raise HTTPException(status_code=status.HTTP_428_PRECONDITION_REQUIRED, detail="ETag (If-Match) is required")
    return etag


# Common query/headers types
Limit = Annotated[int, Query(ge=1, le=200, description="Макс. элементов на странице (1..200)")]
Offset = Annotated[int, Query(ge=0, description="Смещение выборки")]
RequestId = Annotated[Optional[str], Header(None, alias="X-Request-Id")]
IfMatch = Annotated[Optional[str], Header(None, alias="If-Match")]
IfNoneMatch = Annotated[Optional[str], Header(None, alias="If-None-Match")]
IdempotencyKey = Annotated[Optional[str], Header(None, alias="Idempotency-Key")]


@router.get("", response_model=WindowList, status_code=status.HTTP_200_OK)
def list_windows(
    response: Response,
    limit: Limit = 50,
    offset: Offset = 0,
    request_id: RequestId = None,
    svc: WindowService = Depends(get_service),
):
    total, items = svc.list(offset=offset, limit=limit)
    ensure_no_store_headers(response, request_id=request_id)
    return WindowList(total=total, items=items)


@router.head("", status_code=status.HTTP_200_OK)
def head_windows(
    response: Response,
    limit: Limit = 1,
    offset: Offset = 0,
    request_id: RequestId = None,
    svc: WindowService = Depends(get_service),
):
    total, items = svc.list(offset=offset, limit=limit)
    etag_payload = {"total": total, "first": items[0].etag if items else ""}
    ensure_no_store_headers(response, etag=compute_etag(etag_payload), request_id=request_id)
    return Response(status_code=status.HTTP_200_OK)


@router.get("/{id}", response_model=WindowStored, status_code=status.HTTP_200_OK)
def get_window(
    id: UUID,
    response: Response,
    if_none_match: IfNoneMatch = None,
    request_id: RequestId = None,
    svc: WindowService = Depends(get_service),
):
    rec = svc.get(id)
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Window not found")
    if if_none_match and if_none_match == rec.etag:
        # Not modified
        response.status_code = status.HTTP_304_NOT_MODIFIED
        ensure_no_store_headers(response, etag=rec.etag, request_id=request_id)
        return Response(status_code=status.HTTP_304_NOT_MODIFIED)
    ensure_no_store_headers(response, etag=rec.etag, request_id=request_id)
    return rec


@router.post("", response_model=WindowStored, status_code=status.HTTP_201_CREATED)
def create_window(
    data: WindowCreate,
    response: Response,
    request_id: RequestId = None,
    idem_key: IdempotencyKey = None,
    svc: WindowService = Depends(get_service),
):
    try:
        rec = svc.create(data, idem_key=idem_key)
    except ValueError as e:
        # duplicate name
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    ensure_no_store_headers(response, etag=rec.etag, request_id=request_id)
    response.headers["Location"] = f"/v1/windows/{rec.id}"
    return rec


@router.put("/{id}", response_model=WindowStored, status_code=status.HTTP_200_OK)
def update_window(
    id: UUID,
    patch: WindowUpdate,
    response: Response,
    if_match: IfMatch = None,
    request_id: RequestId = None,
    svc: WindowService = Depends(get_service),
):
    etag = _require_etag_header(if_match)
    try:
        rec = svc.update(id, patch, if_match=etag)
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Window not found")
    except PermissionError:
        raise HTTPException(status_code=status.HTTP_412_PRECONDITION_FAILED, detail="ETag mismatch")
    ensure_no_store_headers(response, etag=rec.etag, request_id=request_id)
    return rec


@router.delete("/{id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_window(
    id: UUID,
    response: Response,
    if_match: IfMatch = None,
    request_id: RequestId = None,
    svc: WindowService = Depends(get_service),
):
    etag = _require_etag_header(if_match)
    try:
        svc.delete(id, if_match=etag)
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Window not found")
    except PermissionError:
        raise HTTPException(status_code=status.HTTP_412_PRECONDITION_FAILED, detail="ETag mismatch")
    ensure_no_store_headers(response, request_id=request_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/preview", response_model=PreviewResult, status_code=status.HTTP_200_OK)
def preview_window(
    req: PreviewRequest,
    response: Response,
    request_id: RequestId = None,
    svc: WindowService = Depends(get_service),
):
    try:
        result = svc.compute_preview(req.spec, now=req.now)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
    ensure_no_store_headers(response, request_id=request_id)
    return result


@router.post("/validate", status_code=status.HTTP_204_NO_CONTENT)
def validate_spec(
    req: PreviewRequest,
    response: Response,
    request_id: RequestId = None,
):
    """
    Быстрая валидация модели spec без сохранения.
    """
    # Конструирование модели уже валидирует поля, дополнительно проверим вычисление
    try:
        _ = parse_duration(req.spec.step) if getattr(req.spec, "step", None) else None
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Invalid step: {e}")
    ensure_no_store_headers(response, request_id=request_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# Optional: get by name for convenience
@router.get("/by-name/{name}", response_model=WindowStored, status_code=status.HTTP_200_OK)
def get_by_name(
    name: str,
    response: Response,
    if_none_match: IfNoneMatch = None,
    request_id: RequestId = None,
    svc: WindowService = Depends(get_service),
):
    rec = svc.get_by_name(name)
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Window not found")
    if if_none_match and if_none_match == rec.etag:
        response.status_code = status.HTTP_304_NOT_MODIFIED
        ensure_no_store_headers(response, etag=rec.etag, request_id=request_id)
        return Response(status_code=status.HTTP_304_NOT_MODIFIED)
    ensure_no_store_headers(response, etag=rec.etag, request_id=request_id)
    return rec
