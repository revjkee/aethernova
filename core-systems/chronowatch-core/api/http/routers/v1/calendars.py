from __future__ import annotations

import base64
import json
import logging
import os
import re
import time
import uuid
from datetime import datetime, timedelta
from typing import Annotated, Any, Dict, Iterable, List, Literal, Optional, Tuple

import anyio
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, field_validator, model_validator
from zoneinfo import ZoneInfo

# SQLAlchemy async setup
from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    and_,
    func,
    select,
    update,
    delete,
    MetaData,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

log = logging.getLogger("chronowatch.api.calendars")

router = APIRouter(prefix="/api/v1/calendars", tags=["calendars"])

# ------------------------------------------------------------------------------
# DB session dependency (fallback if app.db.get_session is not available)
# ------------------------------------------------------------------------------

try:
    # If the main app defines a shared session factory, reuse it
    from app.db import get_session as _get_session  # type: ignore

    async def get_session() -> AsyncSession:  # pragma: no cover - integration path
        return await _get_session()

except Exception:  # pragma: no cover - self-contained fallback
    _DSN = os.getenv(
        "CHRONO_DB_DSN",
        "postgresql+asyncpg://user:pass@localhost:5432/chronowatch",
    )
    _engine = create_async_engine(_DSN, pool_pre_ping=True, future=True)
    _session_factory = async_sessionmaker(_engine, expire_on_commit=False)

    async def get_session() -> AsyncSession:
        async with _session_factory() as s:
            yield s

# ------------------------------------------------------------------------------
# Minimal schema using SQLAlchemy Core (to keep this file self-contained)
# In production these tables should live in a dedicated models module/migrations.
# ------------------------------------------------------------------------------

metadata = MetaData()

CALENDARS = Table(
    "calendars",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("name", String(128), nullable=False, index=True),
    Column("timezone", String(64), nullable=False),
    # Working hours structure:
    # { "mon":[["09:00","18:00"]], "tue":[...], ... "sun":[...] }
    Column("work_hours", JSON, nullable=False),
    # Optional opaque payload for downstream consumers (e.g., tenant info)
    Column("attributes", JSON, nullable=True),
    Column("enabled", Boolean, nullable=False, server_default="true"),
    Column("created_at", BigInteger, nullable=False, index=True),
    Column("updated_at", BigInteger, nullable=False, index=True),
    Column("owner", String(128), nullable=False, index=True),
)

CAL_EXCEPTIONS = Table(
    "calendar_exceptions",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("calendar_id", String(36), ForeignKey("calendars.id", ondelete="CASCADE"), index=True, nullable=False),
    # kind: holiday/override_open/override_closed
    Column("kind", String(32), nullable=False),
    # Unix epoch millis in calendar's timezone wall-clock mapped to UTC instant
    Column("start_ms", BigInteger, nullable=False, index=True),
    Column("end_ms", BigInteger, nullable=False, index=True),
    Column("note", Text, nullable=True),
    Column("created_at", BigInteger, nullable=False),
    Column("owner", String(128), nullable=False, index=True),
)

# ------------------------------------------------------------------------------
# Pydantic DTOs
# ------------------------------------------------------------------------------

WEEKDAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
HHMM_RE = re.compile(r"^\d{2}:\d{2}$")


class WorkHours(BaseModel):
    """
    Work hours per weekday. Each value is a list of [start,end) HH:MM local time tuples.
    Example: { "mon":[["09:00","18:00"]], "tue":[["09:00","18:00"]], ... }
    """

    mon: List[Tuple[str, str]] = Field(default_factory=list)
    tue: List[Tuple[str, str]] = Field(default_factory=list)
    wed: List[Tuple[str, str]] = Field(default_factory=list)
    thu: List[Tuple[str, str]] = Field(default_factory=list)
    fri: List[Tuple[str, str]] = Field(default_factory=list)
    sat: List[Tuple[str, str]] = Field(default_factory=list)
    sun: List[Tuple[str, str]] = Field(default_factory=list)

    @field_validator(*WEEKDAYS, mode="before")
    @classmethod
    def _validate_intervals(cls, v: Any) -> Any:
        if v is None:
            return []
        if not isinstance(v, list):
            raise ValueError("weekday value must be a list of [HH:MM,HH:MM] pairs")
        for item in v:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                raise ValueError("each interval must be [HH:MM, HH:MM]")
            a, b = item
            if not (isinstance(a, str) and isinstance(b, str) and HHMM_RE.match(a) and HHMM_RE.match(b)):
                raise ValueError("interval times must be HH:MM")
            if a == b:
                raise ValueError("interval start must not equal end")
        return v

    def as_dict(self) -> Dict[str, List[Tuple[str, str]]]:
        return {k: getattr(self, k) for k in WEEKDAYS}


class CalendarCreate(BaseModel):
    name: str = Field(min_length=3, max_length=128)
    timezone: str = Field(description="IANA timezone, e.g. Europe/Stockholm")
    work_hours: WorkHours
    attributes: Dict[str, Any] | None = None
    enabled: bool = True
    owner: str = Field(min_length=3, max_length=128, pattern=r"^[a-z0-9._:-]{3,128}$")

    @field_validator("timezone")
    @classmethod
    def tz_valid(cls, v: str) -> str:
        try:
            ZoneInfo(v)
        except Exception as e:
            raise ValueError(f"invalid timezone: {v}") from e
        return v


class CalendarUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=3, max_length=128)
    work_hours: Optional[WorkHours] = None
    attributes: Optional[Dict[str, Any]] = None
    enabled: Optional[bool] = None


class CalendarOut(BaseModel):
    id: str
    name: str
    timezone: str
    work_hours: WorkHours
    attributes: Dict[str, Any] | None
    enabled: bool
    owner: str
    created_at: int
    updated_at: int


class PageToken(BaseModel):
    created_at: int
    id: str


def _encode_page_token(created_at: int, id_: str) -> str:
    return base64.urlsafe_b64encode(json.dumps({"created_at": created_at, "id": id_}).encode()).decode()


def _decode_page_token(token: str) -> PageToken:
    try:
        data = json.loads(base64.urlsafe_b64decode(token.encode()).decode())
        return PageToken(**data)
    except Exception as e:
        raise HTTPException(status_code=400, detail="invalid page_token") from e


# Exceptions DTOs
ExceptionKind = Literal["holiday", "override_open", "override_closed"]


class CalendarExceptionCreate(BaseModel):
    kind: ExceptionKind
    start_ms: int = Field(ge=0)
    end_ms: int = Field(ge=0)
    note: Optional[str] = Field(default=None, max_length=400)
    owner: str = Field(min_length=3, max_length=128, pattern=r"^[a-z0-9._:-]{3,128}$")

    @model_validator(mode="after")
    def _check_interval(self) -> "CalendarExceptionCreate":
        if self.end_ms <= self.start_ms:
            raise ValueError("end_ms must be greater than start_ms")
        return self


class CalendarExceptionOut(BaseModel):
    id: str
    calendar_id: str
    kind: ExceptionKind
    start_ms: int
    end_ms: int
    note: Optional[str]
    created_at: int
    owner: str


class BusinessTimeResponse(BaseModel):
    calendar_id: str
    start_ms: int
    end_ms: int
    business_duration_ms: int
    intervals: List[Tuple[int, int]]


class NextWindowResponse(BaseModel):
    calendar_id: str
    from_ms: int
    open_ms: int
    close_ms: int


# ------------------------------------------------------------------------------
# Utility functions
# ------------------------------------------------------------------------------

def _now_ms() -> int:
    return int(time.time() * 1000)


def _new_id() -> str:
    # uuid7 if available in Python 3.12+ else uuid4
    if hasattr(uuid, "uuid7"):
        return uuid.uuid7().hex
    return str(uuid.uuid4())


def _weekday_key(dt: datetime) -> str:
    # Monday=0 ... Sunday=6 -> mon..sun
    return WEEKDAYS[dt.weekday()]


def _localize(ts_ms: int, tz: str) -> datetime:
    return datetime.fromtimestamp(ts_ms / 1000, tz=ZoneInfo(tz))


def _to_utc_ms(dt: datetime) -> int:
    return int(dt.astimezone(ZoneInfo("UTC")).timestamp() * 1000)


def _merge_intervals(intervals: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    if not intervals:
        return []
    ints = sorted(intervals, key=lambda x: (x[0], x[1]))
    merged: List[Tuple[int, int]] = []
    cur_s, cur_e = ints[0]
    for s, e in ints[1:]:
        if s <= cur_e:
            cur_e = max(cur_e, e)
        else:
            merged.append((cur_s, cur_e))
            cur_s, cur_e = s, e
    merged.append((cur_s, cur_e))
    return merged


def _subtract_intervals(base: List[Tuple[int, int]], cuts: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    # Subtract each cut from base intervals
    if not base:
        return []
    if not cuts:
        return base
    cuts = _merge_intervals(cuts)
    result: List[Tuple[int, int]] = []
    for b_start, b_end in base:
        cur = [(b_start, b_end)]
        for c_start, c_end in cuts:
            nxt: List[Tuple[int, int]] = []
            for s, e in cur:
                if c_end <= s or c_start >= e:
                    nxt.append((s, e))
                else:
                    if c_start > s:
                        nxt.append((s, c_start))
                    if c_end < e:
                        nxt.append((c_end, e))
            cur = nxt
        result.extend(cur)
    return _merge_intervals(result)


def _clamp_intervals(intervals: List[Tuple[int, int]], a: int, b: int) -> List[Tuple[int, int]]:
    res: List[Tuple[int, int]] = []
    for s, e in intervals:
        s2, e2 = max(s, a), min(e, b)
        if s2 < e2:
            res.append((s2, e2))
    return res


def _daily_windows_local(day: datetime, wh: WorkHours) -> List[Tuple[datetime, datetime]]:
    key = _weekday_key(day)
    windows: List[Tuple[datetime, datetime]] = []
    for start_str, end_str in getattr(wh, key):
        sh, sm = map(int, start_str.split(":"))
        eh, em = map(int, end_str.split(":"))
        start_dt = day.replace(hour=sh, minute=sm, second=0, microsecond=0)
        end_dt = day.replace(hour=eh, minute=em, second=0, microsecond=0)
        if end_dt <= start_dt:
            continue
        windows.append((start_dt, end_dt))
    return windows


def _build_open_intervals(calendar: Dict[str, Any], start_ms: int, end_ms: int, exceptions: List[Dict[str, Any]]) -> List[Tuple[int, int]]:
    tz = calendar["timezone"]
    wh = WorkHours(**calendar["work_hours"])

    start_local = _localize(start_ms, tz)
    end_local = _localize(end_ms, tz)

    # Normalize to 00:00 of start day
    cursor = start_local.replace(hour=0, minute=0, second=0, microsecond=0)
    days: List[Tuple[datetime, datetime]] = []
    while cursor <= end_local:
        days.append((cursor, cursor + timedelta(days=1)))
        cursor += timedelta(days=1)

    # Build normal open windows in UTC ms
    opens: List[Tuple[int, int]] = []
    for d0, _ in days:
        for s_loc, e_loc in _daily_windows_local(d0, wh):
            opens.append((_to_utc_ms(s_loc), _to_utc_ms(e_loc)))

    # Apply exceptions
    closes: List[Tuple[int, int]] = []
    extra_opens: List[Tuple[int, int]] = []
    for exc in exceptions:
        kind = exc["kind"]
        s, e = int(exc["start_ms"]), int(exc["end_ms"])
        if kind in ("holiday", "override_closed"):
            closes.append((s, e))
        elif kind == "override_open":
            extra_opens.append((s, e))

    # Normal open minus explicit closes
    opens = _subtract_intervals(_merge_intervals(opens), _merge_intervals(closes))
    # Plus explicit extra opens
    all_opens = _merge_intervals(opens + extra_opens)
    # Clamp to requested window
    return _clamp_intervals(all_opens, start_ms, end_ms)


# ------------------------------------------------------------------------------
# OPA authorization hook (optional, no-op if OPA_URL not set)
# ------------------------------------------------------------------------------

OPA_URL = os.getenv("OPA_URL")  # e.g., http://opa:8181/v1/data/chronowatch/policies/time_guard

async def _opa_authorize(action: str, request: Request, payload: Dict[str, Any]) -> None:
    if not OPA_URL:
        return
    try:
        import httpx  # lazy import

        input_doc = {
            "env": os.getenv("ENV", "prod"),
            "request": {
                "action": action,
                "method": request.method,
                "path": str(request.url.path),
                "client_ip": request.client.host if request.client else "0.0.0.0",
                "now_unix_ms": _now_ms(),
                **payload,
            },
            "auth": {
                "jwt": {"verified": False, "claims": {}},
                "mtls": {"present": False},
                "principal": {"sub": request.headers.get("x-subject", "anonymous"), "roles": request.headers.get("x-roles", "").split(",")},
            },
        }
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(OPA_URL, json={"input": input_doc})
            resp.raise_for_status()
            data = resp.json()
        decision = data.get("result") or {}
        if not decision.get("allow", False):
            raise HTTPException(status_code=403, detail={"denies": decision.get("denies", []), "constraints": decision.get("constraints")})
    except HTTPException:
        raise
    except Exception as e:
        log.warning("OPA check failed: %s", e)


# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------

@router.get("", response_model=Dict[str, Any])
async def list_calendars(
    request: Request,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    page_token: Annotated[Optional[str], Query()] = None,
    session: AsyncSession = Depends(get_session),
):
    await _opa_authorize("calendar.list", request, payload={})
    # keyset pagination by (created_at desc, id desc)
    if page_token:
        pt = _decode_page_token(page_token)
        stmt = (
            select(CALENDARS)
            .where(
                (CALENDARS.c.created_at < pt.created_at)
                | ((CALENDARS.c.created_at == pt.created_at) & (CALENDARS.c.id < pt.id))
            )
            .order_by(CALENDARS.c.created_at.desc(), CALENDARS.c.id.desc())
            .limit(limit)
        )
    else:
        stmt = select(CALENDARS).order_by(CALENDARS.c.created_at.desc(), CALENDARS.c.id.desc()).limit(limit)

    rows = (await session.execute(stmt)).mappings().all()
    items: List[CalendarOut] = []
    for r in rows:
        items.append(
            CalendarOut(
                id=r["id"],
                name=r["name"],
                timezone=r["timezone"],
                work_hours=WorkHours(**r["work_hours"]),
                attributes=r["attributes"],
                enabled=r["enabled"],
                owner=r["owner"],
                created_at=r["created_at"],
                updated_at=r["updated_at"],
            )
        )

    next_token = None
    if len(rows) == limit:
        last = rows[-1]
        next_token = _encode_page_token(last["created_at"], last["id"])

    return {"items": [i.model_dump() for i in items], "next_page_token": next_token}


@router.post("", status_code=status.HTTP_201_CREATED, response_model=CalendarOut)
async def create_calendar(
    request: Request,
    body: CalendarCreate,
    session: AsyncSession = Depends(get_session),
):
    await _opa_authorize("calendar.create", request, payload={"calendar": body.model_dump()})

    cal_id = _new_id()
    now = _now_ms()

    stmt = CALENDARS.insert().values(
        id=cal_id,
        name=body.name.strip(),
        timezone=body.timezone,
        work_hours=body.work_hours.as_dict(),
        attributes=body.attributes or None,
        enabled=bool(body.enabled),
        owner=body.owner,
        created_at=now,
        updated_at=now,
    )
    await session.execute(stmt)
    await session.commit()

    return CalendarOut(
        id=cal_id,
        name=body.name.strip(),
        timezone=body.timezone,
        work_hours=body.work_hours,
        attributes=body.attributes or None,
        enabled=bool(body.enabled),
        owner=body.owner,
        created_at=now,
        updated_at=now,
    )


@router.get("/{calendar_id}", response_model=CalendarOut)
async def get_calendar(
    request: Request,
    calendar_id: str,
    session: AsyncSession = Depends(get_session),
):
    await _opa_authorize("calendar.get", request, payload={"calendar_id": calendar_id})

    row = (await session.execute(select(CALENDARS).where(CALENDARS.c.id == calendar_id))).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="calendar not found")
    return CalendarOut(
        id=row["id"],
        name=row["name"],
        timezone=row["timezone"],
        work_hours=WorkHours(**row["work_hours"]),
        attributes=row["attributes"],
        enabled=row["enabled"],
        owner=row["owner"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


@router.patch("/{calendar_id}", response_model=CalendarOut)
async def update_calendar(
    request: Request,
    calendar_id: str,
    body: CalendarUpdate,
    session: AsyncSession = Depends(get_session),
):
    await _opa_authorize("calendar.update", request, payload={"calendar_id": calendar_id, "patch": body.model_dump(exclude_none=True)})

    row = (await session.execute(select(CALENDARS).where(CALENDARS.c.id == calendar_id))).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="calendar not found")

    patch: Dict[str, Any] = {}
    if body.name is not None:
        patch["name"] = body.name.strip()
    if body.work_hours is not None:
        patch["work_hours"] = body.work_hours.as_dict()
    if body.attributes is not None:
        patch["attributes"] = body.attributes
    if body.enabled is not None:
        patch["enabled"] = bool(body.enabled)
    if patch:
        patch["updated_at"] = _now_ms()
        await session.execute(update(CALENDARS).where(CALENDARS.c.id == calendar_id).values(**patch))
        await session.commit()

    row = (await session.execute(select(CALENDARS).where(CALENDARS.c.id == calendar_id))).mappings().first()
    return CalendarOut(
        id=row["id"],
        name=row["name"],
        timezone=row["timezone"],
        work_hours=WorkHours(**row["work_hours"]),
        attributes=row["attributes"],
        enabled=row["enabled"],
        owner=row["owner"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


@router.delete("/{calendar_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_calendar(
    request: Request,
    calendar_id: str,
    session: AsyncSession = Depends(get_session),
):
    await _opa_authorize("calendar.delete", request, payload={"calendar_id": calendar_id})

    res = await session.execute(delete(CAL_EXCEPTIONS).where(CAL_EXCEPTIONS.c.calendar_id == calendar_id))
    res2 = await session.execute(delete(CALENDARS).where(CALENDARS.c.id == calendar_id))
    await session.commit()
    if res2.rowcount == 0:
        raise HTTPException(status_code=404, detail="calendar not found")
    return None


# ------------------------ Exceptions management -------------------------------

@router.post("/{calendar_id}/exceptions", status_code=status.HTTP_201_CREATED, response_model=CalendarExceptionOut)
async def add_exception(
    request: Request,
    calendar_id: str,
    body: CalendarExceptionCreate,
    session: AsyncSession = Depends(get_session),
):
    await _opa_authorize("calendar.exceptions.create", request, payload={"calendar_id": calendar_id, "exception": body.model_dump()})

    # ensure calendar exists and get tz (not used here, but may be used for validation)
    cal = (await session.execute(select(CALENDARS.c.id).where(CALENDARS.c.id == calendar_id))).first()
    if not cal:
        raise HTTPException(status_code=404, detail="calendar not found")

    exc_id = _new_id()
    now = _now_ms()
    await session.execute(
        CAL_EXCEPTIONS.insert().values(
            id=exc_id,
            calendar_id=calendar_id,
            kind=body.kind,
            start_ms=body.start_ms,
            end_ms=body.end_ms,
            note=body.note,
            created_at=now,
            owner=body.owner,
        )
    )
    await session.commit()
    return CalendarExceptionOut(
        id=exc_id,
        calendar_id=calendar_id,
        kind=body.kind,
        start_ms=body.start_ms,
        end_ms=body.end_ms,
        note=body.note,
        created_at=now,
        owner=body.owner,
    )


@router.get("/{calendar_id}/exceptions", response_model=Dict[str, Any])
async def list_exceptions(
    request: Request,
    calendar_id: str,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    start_ms: Annotated[Optional[int], Query(ge=0)] = None,
    end_ms: Annotated[Optional[int], Query(ge=0)] = None,
    session: AsyncSession = Depends(get_session),
):
    await _opa_authorize("calendar.exceptions.list", request, payload={"calendar_id": calendar_id})

    if start_ms is not None and end_ms is not None and end_ms <= start_ms:
        raise HTTPException(status_code=400, detail="end_ms must be greater than start_ms")

    # ensure calendar exists
    cal = (await session.execute(select(CALENDARS.c.id).where(CALENDARS.c.id == calendar_id))).first()
    if not cal:
        raise HTTPException(status_code=404, detail="calendar not found")

    stmt = select(CAL_EXCEPTIONS).where(CAL_EXCEPTIONS.c.calendar_id == calendar_id)
    if start_ms is not None and end_ms is not None:
        stmt = stmt.where((CAL_EXCEPTIONS.c.end_ms > start_ms) & (CAL_EXCEPTIONS.c.start_ms < end_ms))
    stmt = stmt.order_by(CAL_EXCEPTIONS.c.start_ms.asc()).limit(limit)

    rows = (await session.execute(stmt)).mappings().all()
    items = [
        CalendarExceptionOut(
            id=r["id"],
            calendar_id=r["calendar_id"],
            kind=r["kind"],
            start_ms=r["start_ms"],
            end_ms=r["end_ms"],
            note=r["note"],
            created_at=r["created_at"],
            owner=r["owner"],
        ).model_dump()
        for r in rows
    ]
    return {"items": items}


@router.delete("/{calendar_id}/exceptions/{exception_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_exception(
    request: Request,
    calendar_id: str,
    exception_id: str,
    session: AsyncSession = Depends(get_session),
):
    await _opa_authorize("calendar.exceptions.delete", request, payload={"calendar_id": calendar_id, "exception_id": exception_id})

    res = await session.execute(
        delete(CAL_EXCEPTIONS).where(
            (CAL_EXCEPTIONS.c.calendar_id == calendar_id) & (CAL_EXCEPTIONS.c.id == exception_id)
        )
    )
    await session.commit()
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail="exception not found")
    return None


# ----------------------- Business time calculations --------------------------

@router.get("/{calendar_id}/business-time", response_model=BusinessTimeResponse)
async def business_time(
    request: Request,
    calendar_id: str,
    start_ms: Annotated[int, Query(ge=0)],
    end_ms: Annotated[int, Query(ge=0)],
    session: AsyncSession = Depends(get_session),
):
    await _opa_authorize("calendar.business_time", request, payload={"calendar_id": calendar_id, "start_ms": start_ms, "end_ms": end_ms})

    if end_ms <= start_ms:
        raise HTTPException(status_code=400, detail="end_ms must be greater than start_ms")

    row = (await session.execute(select(CALENDARS).where(CALENDARS.c.id == calendar_id))).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="calendar not found")

    exc_rows = (
        await session.execute(
            select(CAL_EXCEPTIONS)
            .where(
                (CAL_EXCEPTIONS.c.calendar_id == calendar_id)
                & (CAL_EXCEPTIONS.c.end_ms > start_ms)
                & (CAL_EXCEPTIONS.c.start_ms < end_ms)
            )
            .order_by(CAL_EXCEPTIONS.c.start_ms.asc())
        )
    ).mappings().all()

    exceptions = [dict(r) for r in exc_rows]
    calendar = dict(row)
    opens = _build_open_intervals(calendar, start_ms, end_ms, exceptions)
    duration = sum(e - s for s, e in opens)
    return BusinessTimeResponse(
        calendar_id=calendar_id,
        start_ms=start_ms,
        end_ms=end_ms,
        business_duration_ms=duration,
        intervals=opens,
    )


@router.get("/{calendar_id}/next-window", response_model=NextWindowResponse)
async def next_window(
    request: Request,
    calendar_id: str,
    from_ms: Annotated[int, Query(ge=0)],
    max_horizon_hours: Annotated[int, Query(ge=1, le=168)] = 168,
    session: AsyncSession = Depends(get_session),
):
    await _opa_authorize("calendar.next_window", request, payload={"calendar_id": calendar_id, "from_ms": from_ms})

    row = (await session.execute(select(CALENDARS).where(CALENDARS.c.id == calendar_id))).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="calendar not found")

    horizon_ms = from_ms + max_horizon_hours * 3600_000
    exc_rows = (
        await session.execute(
            select(CAL_EXCEPTIONS)
            .where(
                (CAL_EXCEPTIONS.c.calendar_id == calendar_id)
                & (CAL_EXCEPTIONS.c.end_ms > from_ms)
                & (CAL_EXCEPTIONS.c.start_ms < horizon_ms)
            )
            .order_by(CAL_EXCEPTIONS.c.start_ms.asc())
        )
    ).mappings().all()

    exceptions = [dict(r) for r in exc_rows]
    calendar = dict(row)

    # Build a small forward window and find first open interval
    opens = _build_open_intervals(calendar, from_ms, horizon_ms, exceptions)
    if not opens:
        raise HTTPException(status_code=404, detail="no open window in horizon")
    open_ms, close_ms = opens[0]
    return NextWindowResponse(calendar_id=calendar_id, from_ms=from_ms, open_ms=open_ms, close_ms=close_ms)
