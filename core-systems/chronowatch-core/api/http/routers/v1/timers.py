from __future__ import annotations

import asyncio
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional, Sequence
from uuid import UUID

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    Header,
    HTTPException,
    Path,
    Query,
    Request,
    status,
)
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator
from enum import Enum
from zoneinfo import ZoneInfo

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# ------------------------------------------------------------------------------
# Конфигурация БД и сессии (async-only)
# ------------------------------------------------------------------------------
_DB_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://postgres:postgres@localhost:5432/chronowatch",
)

_engine = create_async_engine(_DB_URL, pool_size=10, max_overflow=20, pool_pre_ping=True)
_SessionLocal = async_sessionmaker(bind=_engine, expire_on_commit=False, class_=AsyncSession)


async def get_db() -> AsyncSession:
    async with _SessionLocal() as session:
        yield session


# ------------------------------------------------------------------------------
# Утилиты: TZ и CRON валидация/превью
# ------------------------------------------------------------------------------
_CRON_RE = re.compile(
    r"^([0-9A-Za-z\*\?LW#\/,\-]+)\s+([0-9A-Za-z\*\?LW#\/,\-]+)\s+([0-9A-Za-z\*\?LW#\/,\-]+)\s+([0-9A-Za-z\*\?LW#\/,\-]+)\s+([0-9A-Za-z\*\?LW#\/,\-]+)(?:\s+([0-9A-Za-z\*\?LW#\/,\-]+))?$"
)


def _validate_tz(tz: str) -> bool:
    try:
        ZoneInfo(tz)
        return True
    except Exception:
        return False


def _is_valid_cron(expr: str) -> bool:
    if not expr or not isinstance(expr, str):
        return False
    norm = re.sub(r"\s+", " ", expr.strip())
    if not _CRON_RE.match(norm):
        return False
    return True


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _require_croniter():
    try:
        import croniter  # type: ignore
        return croniter
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Cron preview requires 'croniter' package installed on the API service.",
        )


# ------------------------------------------------------------------------------
# Доменные типы/модели
# ------------------------------------------------------------------------------
class ScheduleKind(str, Enum):
    cron = "cron"
    interval = "interval"
    oneoff = "oneoff"


class ScheduleState(str, Enum):
    enabled = "enabled"
    paused = "paused"
    disabled = "disabled"


class ScheduleBase(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    description: Optional[str] = Field(default=None, max_length=4096)
    owner: Optional[str] = Field(default=None, max_length=256)

    state: ScheduleState = ScheduleState.enabled
    kind: ScheduleKind

    cron_expr: Optional[str] = None
    interval_ms: Optional[int] = Field(default=None, ge=1000, le=86_400_000 * 7)  # до недели
    at_time: Optional[datetime] = None
    timezone: str = Field(default="UTC", min_length=1, max_length=128)

    start_after: Optional[datetime] = None
    end_before: Optional[datetime] = None

    jitter_ms: int = Field(default=0, ge=0, le=86_400_000)
    max_drift_ms: int = Field(default=0, ge=0, le=86_400_000)
    backfill_limit: int = Field(default=0, ge=0, le=100_000)

    concurrency_limit: int = Field(default=1, ge=1, le=1024)
    dedup_key: Optional[str] = Field(default=None, max_length=256)

    payload: dict[str, Any] = Field(default_factory=dict)
    labels: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timezone")
    @classmethod
    def _tz_is_valid(cls, v: str) -> str:
        if not _validate_tz(v):
            raise ValueError("Invalid IANA timezone")
        return v

    @field_validator("cron_expr")
    @classmethod
    def _cron_is_valid(cls, v: Optional[str], info):
        kind = info.data.get("kind")
        if kind == ScheduleKind.cron:
            if not v or not _is_valid_cron(v):
                raise ValueError("Invalid cron expression")
        return v

    @model_validator(mode="after")
    def _kind_matrix(self):
        if self.kind == ScheduleKind.cron:
            if not self.cron_expr or self.interval_ms is not None or self.at_time is not None:
                raise ValueError("For kind=cron, only cron_expr must be set")
        elif self.kind == ScheduleKind.interval:
            if self.interval_ms is None or self.cron_expr is not None or self.at_time is not None:
                raise ValueError("For kind=interval, only interval_ms must be set")
        elif self.kind == ScheduleKind.oneoff:
            if self.at_time is None or self.cron_expr is not None or self.interval_ms is not None:
                raise ValueError("For kind=oneoff, only at_time must be set")
        if self.start_after and self.end_before and not (self.end_before > self.start_after):
            raise ValueError("end_before must be greater than start_after")
        return self


class ScheduleCreate(ScheduleBase):
    pass


class ScheduleUpdate(BaseModel):
    # Частичное обновление: все поля опциональны, но валидируются совместимостью
    name: Optional[str] = Field(default=None, min_length=1, max_length=256)
    description: Optional[str] = Field(default=None, max_length=4096)
    owner: Optional[str] = Field(default=None, max_length=256)

    state: Optional[ScheduleState] = None
    kind: Optional[ScheduleKind] = None

    cron_expr: Optional[str] = None
    interval_ms: Optional[int] = Field(default=None, ge=1000, le=86_400_000 * 7)
    at_time: Optional[datetime] = None
    timezone: Optional[str] = Field(default=None, min_length=1, max_length=128)

    start_after: Optional[datetime] = None
    end_before: Optional[datetime] = None

    jitter_ms: Optional[int] = Field(default=None, ge=0, le=86_400_000)
    max_drift_ms: Optional[int] = Field(default=None, ge=0, le=86_400_000)
    backfill_limit: Optional[int] = Field(default=None, ge=0, le=100_000)

    concurrency_limit: Optional[int] = Field(default=None, ge=1, le=1024)
    dedup_key: Optional[str] = Field(default=None, max_length=256)

    payload: Optional[dict[str, Any]] = None
    labels: Optional[dict[str, Any]] = None

    @field_validator("timezone")
    @classmethod
    def _tz_is_valid(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if not _validate_tz(v):
            raise ValueError("Invalid IANA timezone")
        return v

    @field_validator("cron_expr")
    @classmethod
    def _cron_is_valid(cls, v: Optional[str], info):
        kind = info.data.get("kind")
        # При частичном обновлении позволяем менять cron только если kind=cron
        if v is not None and not _is_valid_cron(v):
            raise ValueError("Invalid cron expression")
        return v

    @model_validator(mode="after")
    def _kind_cross_check(self):
        # Невозможно строго проверить без текущего состояния; сделаем базовую совместимость.
        # Полная проверка выполняется на уровне БД (CHECK) и в merge_existing().
        return self


class ScheduleOut(BaseModel):
    schedule_id: UUID
    tenant_id: UUID
    name: str
    description: Optional[str]
    owner: Optional[str]
    state: ScheduleState
    kind: ScheduleKind
    cron_expr: Optional[str]
    interval_ms: Optional[int]
    at_time: Optional[datetime]
    timezone: str
    start_after: Optional[datetime]
    end_before: Optional[datetime]
    jitter_ms: int
    max_drift_ms: int
    backfill_limit: int
    concurrency_limit: int
    dedup_key: Optional[str]
    payload: dict[str, Any]
    labels: dict[str, Any]
    revision: int
    created_at: datetime
    updated_at: datetime
    deleted_at: Optional[datetime]


class TimersList(BaseModel):
    items: list[ScheduleOut]
    total: int
    limit: int
    offset: int


class PreviewRequest(BaseModel):
    n: int = Field(default=5, ge=1, le=100)
    from_time: Optional[datetime] = None


class PreviewOut(BaseModel):
    schedule_id: UUID
    occurrences: list[datetime]


class ActionOut(BaseModel):
    schedule_id: UUID
    state: ScheduleState
    message: str


class RunNowOut(BaseModel):
    run_id: UUID
    schedule_id: UUID
    due_at: datetime
    status: Literal["scheduled", "running", "success", "failed", "canceled", "skipped", "timeout"]


# ------------------------------------------------------------------------------
# Роутер
# ------------------------------------------------------------------------------
router = APIRouter(prefix="/v1/timers", tags=["timers"])


# ------------------------------------------------------------------------------
# Хелперы: установка tenant в сессии и common execute
# ------------------------------------------------------------------------------
async def _set_tenant(session: AsyncSession, tenant_id: UUID) -> None:
    # RLS: каждая ТРАНЗАКЦИЯ должна иметь app.tenant_id
    await session.execute(text("SET LOCAL app.tenant_id = :tid").bindparams(tid=str(tenant_id)))


def _merge_existing(existing: dict[str, Any], patch: ScheduleUpdate) -> dict[str, Any]:
    merged = {**existing}
    data = patch.model_dump(exclude_unset=True)
    merged.update({k: v for k, v in data.items() if v is not None or k in data})
    # Проверка совместимости kind/полей
    k = ScheduleKind(merged["kind"])
    if k == ScheduleKind.cron:
        if not merged.get("cron_expr") or merged.get("interval_ms") is not None or merged.get("at_time") is not None:
            raise HTTPException(status_code=422, detail="For kind=cron, only cron_expr must be set")
    elif k == ScheduleKind.interval:
        if merged.get("interval_ms") is None or merged.get("cron_expr") is not None or merged.get("at_time") is not None:
            raise HTTPException(status_code=422, detail="For kind=interval, only interval_ms must be set")
    elif k == ScheduleKind.oneoff:
        if merged.get("at_time") is None or merged.get("cron_expr") is not None or merged.get("interval_ms") is not None:
            raise HTTPException(status_code=422, detail="For kind=oneoff, only at_time must be set")

    if merged.get("timezone") and not _validate_tz(merged["timezone"]):
        raise HTTPException(status_code=422, detail="Invalid timezone")

    if merged.get("cron_expr") and not _is_valid_cron(merged["cron_expr"]):
        raise HTTPException(status_code=422, detail="Invalid cron expression")

    sa = merged.get("start_after")
    eb = merged.get("end_before")
    if sa and eb and not (eb > sa):
        raise HTTPException(status_code=422, detail="end_before must be greater than start_after")

    return merged


# ------------------------------------------------------------------------------
# CRUD
# ------------------------------------------------------------------------------
@router.post(
    "",
    response_model=ScheduleOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_timer(
    payload: ScheduleCreate,
    db: AsyncSession = Depends(get_db),
    x_tenant_id: UUID = Header(..., alias="X-Tenant-Id"),
    x_actor: Optional[str] = Header(None, alias="X-Actor"),
    x_idem_key: Optional[str] = Header(None, alias="X-Idempotency-Key"),
):
    async with db.begin():
        await _set_tenant(db, x_tenant_id)

        # Идемпотентность по (tenant, idem_key, name) — опционально через labels
        if x_idem_key:
            row = (
                await db.execute(
                    text(
                        """
                        SELECT schedule_id FROM chronowatch.schedules
                        WHERE tenant_id = :tid AND labels ? :idem AND deleted_at IS NULL
                        """
                    ),
                    {"tid": str(x_tenant_id), "idem": f"idem:{x_idem_key}"},
                )
            ).first()
            if row:
                # Возвращаем существующую запись
                rec = (
                    await db.execute(
                        text("SELECT * FROM chronowatch.schedules WHERE schedule_id = :sid"),
                        {"sid": row[0]},
                    )
                ).mappings().first()
                return ScheduleOut(**rec)

        # Встраиваем idem_key в labels, если задан
        labels = {**payload.labels}
        if x_idem_key:
            labels[f"idem:{x_idem_key}"] = True

        rec = (
            await db.execute(
                text(
                    """
                    INSERT INTO chronowatch.schedules (
                      tenant_id, name, description, owner,
                      state, kind, cron_expr, interval_ms, at_time, timezone,
                      start_after, end_before, jitter_ms, max_drift_ms, backfill_limit,
                      concurrency_limit, dedup_key, payload, labels, created_by, updated_by
                    )
                    VALUES (
                      :tenant_id, :name, :description, :owner,
                      :state, :kind, :cron_expr, :interval_ms, :at_time, :timezone,
                      :start_after, :end_before, :jitter_ms, :max_drift_ms, :backfill_limit,
                      :concurrency_limit, :dedup_key, :payload::jsonb, :labels::jsonb, :actor, :actor
                    )
                    RETURNING *
                    """
                ),
                {
                    "tenant_id": str(x_tenant_id),
                    "name": payload.name,
                    "description": payload.description,
                    "owner": payload.owner,
                    "state": payload.state.value,
                    "kind": payload.kind.value,
                    "cron_expr": payload.cron_expr,
                    "interval_ms": payload.interval_ms,
                    "at_time": payload.at_time,
                    "timezone": payload.timezone,
                    "start_after": payload.start_after,
                    "end_before": payload.end_before,
                    "jitter_ms": payload.jitter_ms,
                    "max_drift_ms": payload.max_drift_ms,
                    "backfill_limit": payload.backfill_limit,
                    "concurrency_limit": payload.concurrency_limit,
                    "dedup_key": payload.dedup_key,
                    "payload": payload.payload,
                    "labels": labels,
                    "actor": x_actor or "api",
                },
            )
        ).mappings().first()

        return ScheduleOut(**rec)


@router.get(
    "/{schedule_id}",
    response_model=ScheduleOut,
    status_code=status.HTTP_200_OK,
)
async def get_timer(
    schedule_id: UUID = Path(...),
    db: AsyncSession = Depends(get_db),
    x_tenant_id: UUID = Header(..., alias="X-Tenant-Id"),
):
    async with db.begin():
        await _set_tenant(db, x_tenant_id)
        rec = (
            await db.execute(
                text(
                    """
                    SELECT * FROM chronowatch.schedules
                    WHERE schedule_id = :sid AND deleted_at IS NULL
                    """
                ),
                {"sid": str(schedule_id)},
            )
        ).mappings().first()
        if not rec:
            raise HTTPException(status_code=404, detail="Schedule not found")
        return ScheduleOut(**rec)


@router.get(
    "",
    response_model=TimersList,
    status_code=status.HTTP_200_OK,
)
async def list_timers(
    db: AsyncSession = Depends(get_db),
    x_tenant_id: UUID = Header(..., alias="X-Tenant-Id"),
    q: Optional[str] = Query(None, description="Поиск по name (ILIKE)"),
    state: Optional[ScheduleState] = Query(None),
    kind: Optional[ScheduleKind] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    sort: str = Query("created_at:desc", pattern=r"^(name|created_at|updated_at):(asc|desc)$"),
):
    field, direction = sort.split(":")
    async with db.begin():
        await _set_tenant(db, x_tenant_id)
        conds = ["tenant_id = :tid", "deleted_at IS NULL"]
        params: dict[str, Any] = {"tid": str(x_tenant_id)}
        if q:
            conds.append("name ILIKE :q")
            params["q"] = f"%{q}%"
        if state:
            conds.append("state = :state")
            params["state"] = state.value
        if kind:
            conds.append("kind = :kind")
            params["kind"] = kind.value
        where = " AND ".join(conds)

        total = (
            await db.execute(
                text(f"SELECT count(*) AS c FROM chronowatch.schedules WHERE {where}"), params
            )
        ).scalar_one()

        rows = (
            await db.execute(
                text(
                    f"""
                    SELECT * FROM chronowatch.schedules
                    WHERE {where}
                    ORDER BY {field} {direction.upper()}
                    LIMIT :limit OFFSET :offset
                    """
                ),
                {**params, "limit": limit, "offset": offset},
            )
        ).mappings().all()

        return TimersList(items=[ScheduleOut(**r) for r in rows], total=total, limit=limit, offset=offset)


@router.patch(
    "/{schedule_id}",
    response_model=ScheduleOut,
    status_code=status.HTTP_200_OK,
)
async def update_timer(
    schedule_id: UUID,
    patch: ScheduleUpdate,
    db: AsyncSession = Depends(get_db),
    x_tenant_id: UUID = Header(..., alias="X-Tenant-Id"),
    x_actor: Optional[str] = Header(None, alias="X-Actor"),
):
    async with db.begin():
        await _set_tenant(db, x_tenant_id)
        cur = (
            await db.execute(
                text(
                    """
                    SELECT * FROM chronowatch.schedules
                    WHERE schedule_id = :sid AND deleted_at IS NULL
                    """
                ),
                {"sid": str(schedule_id)},
            )
        ).mappings().first()
        if not cur:
            raise HTTPException(status_code=404, detail="Schedule not found")

        merged = _merge_existing(dict(cur), patch)

        rec = (
            await db.execute(
                text(
                    """
                    UPDATE chronowatch.schedules
                    SET
                      name = :name,
                      description = :description,
                      owner = :owner,
                      state = :state,
                      kind = :kind,
                      cron_expr = :cron_expr,
                      interval_ms = :interval_ms,
                      at_time = :at_time,
                      timezone = :timezone,
                      start_after = :start_after,
                      end_before = :end_before,
                      jitter_ms = :jitter_ms,
                      max_drift_ms = :max_drift_ms,
                      backfill_limit = :backfill_limit,
                      concurrency_limit = :concurrency_limit,
                      dedup_key = :dedup_key,
                      payload = :payload::jsonb,
                      labels = :labels::jsonb,
                      updated_by = :actor
                    WHERE schedule_id = :sid
                    RETURNING *
                    """
                ),
                {
                    **{k: merged.get(k) for k in [
                        "name", "description", "owner", "state", "kind", "cron_expr", "interval_ms",
                        "at_time", "timezone", "start_after", "end_before", "jitter_ms", "max_drift_ms",
                        "backfill_limit", "concurrency_limit", "dedup_key", "payload", "labels"
                    ]},
                    "sid": str(schedule_id),
                    "actor": x_actor or "api",
                },
            )
        ).mappings().first()

        return ScheduleOut(**rec)


@router.delete(
    "/{schedule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_timer(
    schedule_id: UUID,
    db: AsyncSession = Depends(get_db),
    x_tenant_id: UUID = Header(..., alias="X-Tenant-Id"),
    x_actor: Optional[str] = Header(None, alias="X-Actor"),
    hard: bool = Query(False, description="Жесткое удаление (только для тестовых окружений)"),
):
    async with db.begin():
        await _set_tenant(db, x_tenant_id)
        if hard:
            await db.execute(
                text("DELETE FROM chronowatch.schedules WHERE schedule_id = :sid"),
                {"sid": str(schedule_id)},
            )
        else:
            n = (
                await db.execute(
                    text(
                        """
                        UPDATE chronowatch.schedules
                        SET deleted_at = now(), updated_by = :actor
                        WHERE schedule_id = :sid AND deleted_at IS NULL
                        """
                    ),
                    {"sid": str(schedule_id), "actor": x_actor or "api"},
                )
            ).rowcount
            if n == 0:
                raise HTTPException(status_code=404, detail="Schedule not found")
    return None


# ------------------------------------------------------------------------------
# Действия: pause/resume
# ------------------------------------------------------------------------------
@router.post(
    "/{schedule_id}/pause",
    response_model=ActionOut,
    status_code=status.HTTP_200_OK,
)
async def pause_timer(
    schedule_id: UUID,
    db: AsyncSession = Depends(get_db),
    x_tenant_id: UUID = Header(..., alias="X-Tenant-Id"),
    x_actor: Optional[str] = Header(None, alias="X-Actor"),
):
    async with db.begin():
        await _set_tenant(db, x_tenant_id)
        rec = (
            await db.execute(
                text(
                    """
                    UPDATE chronowatch.schedules
                    SET state = 'paused', updated_by = :actor
                    WHERE schedule_id = :sid AND deleted_at IS NULL
                    RETURNING schedule_id, state
                    """
                ),
                {"sid": str(schedule_id), "actor": x_actor or "api"},
            )
        ).first()
        if not rec:
            raise HTTPException(status_code=404, detail="Schedule not found")
        return ActionOut(schedule_id=schedule_id, state=ScheduleState.paused, message="Paused")


@router.post(
    "/{schedule_id}/resume",
    response_model=ActionOut,
    status_code=status.HTTP_200_OK,
)
async def resume_timer(
    schedule_id: UUID,
    db: AsyncSession = Depends(get_db),
    x_tenant_id: UUID = Header(..., alias="X-Tenant-Id"),
    x_actor: Optional[str] = Header(None, alias="X-Actor"),
):
    async with db.begin():
        await _set_tenant(db, x_tenant_id)
        rec = (
            await db.execute(
                text(
                    """
                    UPDATE chronowatch.schedules
                    SET state = 'enabled', updated_by = :actor
                    WHERE schedule_id = :sid AND deleted_at IS NULL
                    RETURNING schedule_id, state
                    """
                ),
                {"sid": str(schedule_id), "actor": x_actor or "api"},
            )
        ).first()
        if not rec:
            raise HTTPException(status_code=404, detail="Schedule not found")
        return ActionOut(schedule_id=schedule_id, state=ScheduleState.enabled, message="Resumed")


# ------------------------------------------------------------------------------
# Preview next occurrences
# ------------------------------------------------------------------------------
@router.post(
    "/{schedule_id}/preview-next",
    response_model=PreviewOut,
    status_code=status.HTTP_200_OK,
)
async def preview_next(
    schedule_id: UUID,
    req: PreviewRequest,
    db: AsyncSession = Depends(get_db),
    x_tenant_id: UUID = Header(..., alias="X-Tenant-Id"),
):
    async with db.begin():
        await _set_tenant(db, x_tenant_id)
        rec = (
            await db.execute(
                text("SELECT * FROM chronowatch.schedules WHERE schedule_id = :sid AND deleted_at IS NULL"),
                {"sid": str(schedule_id)},
            )
        ).mappings().first()
        if not rec:
            raise HTTPException(status_code=404, detail="Schedule not found")

        tz = ZoneInfo(rec["timezone"])
        base = (req.from_time or _now_utc()).astimezone(tz)

        occurrences: list[datetime] = []

        kind = ScheduleKind(rec["kind"])
        if kind == ScheduleKind.oneoff:
            at = rec["at_time"]
            if at:
                at_tz = at.astimezone(tz)
                if at_tz > base:
                    occurrences.append(at_tz)
        elif kind == ScheduleKind.interval:
            interval_ms = int(rec["interval_ms"])
            # Найдём ближайшее кратное время после base
            # Допускаем использование start_after как нижней границы
            start = (rec["start_after"] or _now_utc()).astimezone(tz)
            if base < start:
                base = start
            # Округление вверх до следующего интервала
            step = timedelta(milliseconds=interval_ms)
            # Предотвращаем бесконечности при step=0 (не должно случиться из-за CHECK)
            next_time = base + (step - timedelta(microseconds=(base - start).microseconds % int(step.total_seconds() * 1_000_000)))
            # Генерация N штук
            cur = next_time
            for _ in range(req.n):
                occurrences.append(cur)
                cur = cur + step
        elif kind == ScheduleKind.cron:
            croniter = _require_croniter()
            expr = rec["cron_expr"]
            it = croniter.croniter(expr, base)
            for _ in range(req.n):
                occurrences.append(it.get_next(datetime))

        return PreviewOut(schedule_id=schedule_id, occurrences=[dt.astimezone(timezone.utc) for dt in occurrences])


# ------------------------------------------------------------------------------
# Ручной запуск (enqueue)
# ------------------------------------------------------------------------------
@router.post(
    "/{schedule_id}/run-now",
    response_model=RunNowOut,
    status_code=status.HTTP_202_ACCEPTED,
)
async def run_now(
    schedule_id: UUID,
    db: AsyncSession = Depends(get_db),
    x_tenant_id: UUID = Header(..., alias="X-Tenant-Id"),
    x_actor: Optional[str] = Header(None, alias="X-Actor"),
    x_idem_key: Optional[str] = Header(None, alias="X-Idempotency-Key"),
):
    async with db.begin():
        await _set_tenant(db, x_tenant_id)
        exists = (
            await db.execute(
                text("SELECT 1 FROM chronowatch.schedules WHERE schedule_id = :sid AND deleted_at IS NULL"),
                {"sid": str(schedule_id)},
            )
        ).first()
        if not exists:
            raise HTTPException(status_code=404, detail="Schedule not found")

        # Идемпотентность запуска: если есть recent scheduled с тем же idem_key в ближайшие 60с — вернём его
        if x_idem_key:
            existing = (
                await db.execute(
                    text(
                        """
                        SELECT run_id, schedule_id, due_at, status
                        FROM chronowatch.schedule_runs
                        WHERE schedule_id = :sid AND tenant_id = :tid
                          AND metrics ? :idem
                          AND created_at > now() - interval '60 seconds'
                        ORDER BY created_at DESC
                        LIMIT 1
                        """
                    ),
                    {"sid": str(schedule_id), "tid": str(x_tenant_id), "idem": f"idem:{x_idem_key}"},
                )
            ).mappings().first()
            if existing:
                return RunNowOut(**existing)

        due = _now_utc()
        metrics = {}
        if x_idem_key:
            metrics[f"idem:{x_idem_key}"] = True

        row = (
            await db.execute(
                text(
                    """
                    INSERT INTO chronowatch.schedule_runs
                      (schedule_id, tenant_id, due_at, status, attempt, worker_id, metrics)
                    VALUES
                      (:sid, :tid, :due_at, 'scheduled', 0, NULL, :metrics::jsonb)
                    RETURNING run_id, schedule_id, due_at, status
                    """
                ),
                {"sid": str(schedule_id), "tid": str(x_tenant_id), "due_at": due, "metrics": metrics},
            )
        ).mappings().first()

        return RunNowOut(**row)
