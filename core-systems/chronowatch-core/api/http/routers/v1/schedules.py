from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from chronowatch.db import session_scope
from chronowatch.models import Schedule, Job
from chronowatch.schemas import ScheduleCreate, ScheduleOut
from chronowatch.security.rbac import require_admin

router = APIRouter(prefix="/api/v1/schedules", tags=["schedules"])

# -----------------------------
# Pydantic I/O models
# -----------------------------
class ScheduleUpdate(BaseModel):
    interval_sec: Optional[int] = Field(default=None, ge=1)
    args: Optional[dict[str, Any]] = None
    enabled: Optional[bool] = None
    recalc_next_run: bool = Field(
        default=False,
        description="Если true и изменён interval_sec или enabled==True, next_run_at станет now()+interval_sec.",
    )

class PageMeta(BaseModel):
    total: int
    page: int
    page_size: int
    has_next: bool

class ScheduleListResponse(BaseModel):
    items: list[ScheduleOut]
    meta: PageMeta

# -----------------------------
# Dependencies
# -----------------------------
async def get_db() -> AsyncSession:
    async with session_scope() as s:
        yield s

# -----------------------------
# Helpers
# -----------------------------
_SORTABLE: dict[str, Any] = {
    "id": Schedule.id,
    "job_id": Schedule.job_id,
    "next_run_at": Schedule.next_run_at,
    "interval_sec": Schedule.interval_sec,
    "created_at": Schedule.created_at,
    "enabled": Schedule.enabled,
}

def _safe_sort(sort_by: str, order: Literal["asc", "desc"]) -> Any:
    col = _SORTABLE.get(sort_by)
    if col is None:
        raise HTTPException(status_code=400, detail=f"unsupported sort field: {sort_by}")
    return desc(col) if order == "desc" else col

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

# -----------------------------
# Routes
# -----------------------------
@router.get("", response_model=ScheduleListResponse, summary="List schedules with filters")
async def list_schedules(
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    sort_by: str = Query("next_run_at"),
    order: Literal["asc", "desc"] = Query("asc"),
    job_id: Optional[int] = Query(None, description="Filter by job_id"),
    enabled: Optional[bool] = Query(None),
    next_run_before: Optional[datetime] = Query(None),
    next_run_after: Optional[datetime] = Query(None),
) -> ScheduleListResponse:
    where = []
    if job_id is not None:
        where.append(Schedule.job_id == job_id)
    if enabled is not None:
        where.append(Schedule.enabled == enabled)
    if next_run_before is not None:
        where.append(Schedule.next_run_at < next_run_before)
    if next_run_after is not None:
        where.append(Schedule.next_run_at >= next_run_after)

    stmt_count = select(func.count()).select_from(Schedule).where(and_(*where)) if where else select(func.count()).select_from(Schedule)
    total: int = (await db.execute(stmt_count)).scalar_one()

    order_expr = _safe_sort(sort_by, order)
    offset = (page - 1) * page_size
    stmt = (
        select(Schedule)
        .where(and_(*where)) if where else select(Schedule)
    )
    stmt = stmt.order_by(order_expr).offset(offset).limit(page_size)

    items = list((await db.execute(stmt)).scalars().all())
    has_next = (offset + len(items)) < total

    return ScheduleListResponse(
        items=[ScheduleOut.model_validate(i, from_attributes=True) for i in items],
        meta=PageMeta(total=total, page=page, page_size=page_size, has_next=has_next),
    )

@router.get("/{schedule_id}", response_model=ScheduleOut, summary="Get schedule by id")
async def get_schedule(schedule_id: int, db: AsyncSession = Depends(get_db)) -> ScheduleOut:
    sch = await db.get(Schedule, schedule_id)
    if not sch:
        raise HTTPException(status_code=404, detail="schedule not found")
    return ScheduleOut.model_validate(sch, from_attributes=True)

@router.post("", response_model=ScheduleOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin)], summary="Create schedule")
async def create_schedule(payload: ScheduleCreate, db: AsyncSession = Depends(get_db)) -> ScheduleOut:
    # Ensure job exists and enabled
    job = await db.get(Job, payload.job_id)
    if not job:
        raise HTTPException(status_code=400, detail="job not found")
    if not job.enabled:
        raise HTTPException(status_code=409, detail="job is disabled")

    now = _utc_now()
    next_run = now if payload.interval_sec is None else now.replace(microsecond=0) + (payload.interval_sec or 0) * (timezone.utc.utcoffset(now) or 0)  # will be overridden below
    # Proper computation:
    if payload.interval_sec:
        from datetime import timedelta
        next_run = now + timedelta(seconds=payload.interval_sec)
    else:
        next_run = now

    sch = Schedule(
        job_id=payload.job_id,
        cron=None,  # зарезервировано на будущее
        interval_sec=payload.interval_sec,
        next_run_at=next_run,
        args=payload.args,
        enabled=payload.enabled,
    )
    db.add(sch)
    await db.flush()
    return ScheduleOut.model_validate(sch, from_attributes=True)

@router.patch("/{schedule_id}", response_model=ScheduleOut, dependencies=[Depends(require_admin)], summary="Partial update schedule")
async def patch_schedule(
    schedule_id: int,
    payload: ScheduleUpdate,
    db: AsyncSession = Depends(get_db),
) -> ScheduleOut:
    sch = await db.get(Schedule, schedule_id)
    if not sch:
        raise HTTPException(status_code=404, detail="schedule not found")

    changed_interval = False
    if payload.interval_sec is not None:
        sch.interval_sec = payload.interval_sec
        changed_interval = True
    if payload.args is not None:
        sch.args = payload.args
    if payload.enabled is not None:
        sch.enabled = payload.enabled

    # Recalculate next_run_at if requested and interval present or schedule re-enabled
    if payload.recalc_next_run and (changed_interval or payload.enabled is True):
        from datetime import timedelta
        now = _utc_now()
        interval = sch.interval_sec or 1
        sch.next_run_at = now + timedelta(seconds=interval)

    await db.flush()
    return ScheduleOut.model_validate(sch, from_attributes=True)

@router.put("/{schedule_id}/enable", response_model=ScheduleOut, dependencies=[Depends(require_admin)], summary="Enable schedule")
async def enable_schedule(schedule_id: int, db: AsyncSession = Depends(get_db)) -> ScheduleOut:
    sch = await db.get(Schedule, schedule_id)
    if not sch:
        raise HTTPException(status_code=404, detail="schedule not found")
    if not sch.enabled:
        sch.enabled = True
        await db.flush()
    return ScheduleOut.model_validate(sch, from_attributes=True)

@router.put("/{schedule_id}/disable", response_model=ScheduleOut, dependencies=[Depends(require_admin)], summary="Disable schedule")
async def disable_schedule(schedule_id: int, db: AsyncSession = Depends(get_db)) -> ScheduleOut:
    sch = await db.get(Schedule, schedule_id)
    if not sch:
        raise HTTPException(status_code=404, detail="schedule not found")
    if sch.enabled:
        sch.enabled = False
        await db.flush()
    return ScheduleOut.model_validate(sch, from_attributes=True)

class RunNowRequest(BaseModel):
    align_to_now: bool = Field(
        default=True,
        description="Если true — сдвигает next_run_at на текущий момент (планировщик подхватит немедленно).",
    )

@router.post("/{schedule_id}/run-now", response_model=ScheduleOut, dependencies=[Depends(require_admin)], summary="Set next_run_at to now() to run ASAP")
async def run_now(schedule_id: int, req: RunNowRequest, db: AsyncSession = Depends(get_db)) -> ScheduleOut:
    sch = await db.get(Schedule, schedule_id)
    if not sch:
        raise HTTPException(status_code=404, detail="schedule not found")
    if not sch.enabled:
        raise HTTPException(status_code=409, detail="schedule is disabled")

    if req.align_to_now:
        sch.next_run_at = _utc_now()
        await db.flush()
    return ScheduleOut.model_validate(sch, from_attributes=True)

@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_admin)], summary="Delete schedule")
async def delete_schedule(schedule_id: int, db: AsyncSession = Depends(get_db)) -> None:
    sch = await db.get(Schedule, schedule_id)
    if not sch:
        raise HTTPException(status_code=404, detail="schedule not found")
    await db.delete(sch)
    # commit выполняется в session_scope()
    return None
