# chronowatch-core/api/http/routers/v1/sla.py
from __future__ import annotations

import os
import math
import typing as t
import datetime as dt
from contextlib import asynccontextmanager

from fastapi import APIRouter, Depends, HTTPException, Query, Path, Header, status
from pydantic import BaseModel, Field, conint, confloat, validator

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy import text

# --- Optional Observability (soft dependency) ---
try:
    from opentelemetry import trace  # type: ignore
    _tracer = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    class _NoopSpan:
        def __enter__(self): return self
        def __exit__(self, *a): return False
    class _NoopTracer:
        def start_as_current_span(self, *a, **k): return _NoopSpan()
    _tracer = _NoopTracer()

try:
    from prometheus_client import Counter, Gauge  # type: ignore
    _sla_requests = Counter("chronowatch_sla_requests_total", "Total SLA API requests", ["route", "method", "status"])
    _sla_calc_seconds = Gauge("chronowatch_sla_calc_seconds", "SLA calc wall time seconds", ["kind"])
except Exception:  # pragma: no cover
    class _NoopMetric:
        def labels(self, *a, **k): return self
        def inc(self, *a, **k): pass
        def set(self, *a, **k): pass
        def observe(self, *a, **k): pass
    _sla_requests = _NoopMetric()
    _sla_calc_seconds = _NoopMetric()

router = APIRouter(prefix="/v1/sla", tags=["sla"])

# --- Database bootstrap (async-only SQLAlchemy, PostgreSQL expected) ---

DATABASE_DSN = os.getenv("DATABASE_DSN")  # e.g. postgresql+asyncpg://user:pass@host:5432/db
if not DATABASE_DSN:
    # Явно сообщаем о необходимости конфигурации — без DSN сервис работать не должен
    # Это лучше fail-fast чем тихий переход к in-memory.
    DB_INIT_ERROR = "Missing DATABASE_DSN environment variable for SLA router"
else:
    DB_INIT_ERROR = None

_engine = create_async_engine(DATABASE_DSN, pool_pre_ping=True, pool_size=5, max_overflow=10) if not DB_INIT_ERROR else None
_Session = async_sessionmaker(_engine, expire_on_commit=False, class_=AsyncSession) if _engine else None
_initialized: bool = False

SLA_SCHEMA = "chronowatch"

DDL_INIT_SQL = text(f"""
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = '{SLA_SCHEMA}') THEN
    EXECUTE 'CREATE SCHEMA {SLA_SCHEMA}';
  END IF;
END$$;

CREATE TABLE IF NOT EXISTS {SLA_SCHEMA}.sla_objectives (
  slo_id           BIGSERIAL PRIMARY KEY,
  service          TEXT        NOT NULL,
  env              TEXT        NOT NULL DEFAULT 'production',
  indicator        TEXT        NOT NULL CHECK (indicator IN ('availability','latency','custom')),
  target           NUMERIC(5,4) NOT NULL CHECK (target > 0 AND target < 1), -- e.g. 0.999 for 99.9%
  window_days      INTEGER     NOT NULL CHECK (window_days >= 1 AND window_days <= 365),
  target_latency_ms INTEGER    NULL CHECK (target_latency_ms IS NULL OR target_latency_ms > 0),
  tags             JSONB       NOT NULL DEFAULT '{{}}'::jsonb,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (service, env, indicator)
);

COMMENT ON TABLE {SLA_SCHEMA}.sla_objectives IS 'SLO objectives per service/env/indicator';

-- Touch dependency table from migration 0003 for runtime calculations
-- We do not create it here; we assume migrations created chronowatch.heartbeats_hourly.

-- Update trigger for updated_at
CREATE OR REPLACE FUNCTION {SLA_SCHEMA}.fn_touch_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END $$;

DROP TRIGGER IF EXISTS trg_touch_updated_at ON {SLA_SCHEMA}.sla_objectives;
CREATE TRIGGER trg_touch_updated_at
BEFORE UPDATE ON {SLA_SCHEMA}.sla_objectives
FOR EACH ROW EXECUTE FUNCTION {SLA_SCHEMA}.fn_touch_updated_at();
""")

@asynccontextmanager
async def get_session() -> t.AsyncIterator[AsyncSession]:
    if DB_INIT_ERROR:
        raise HTTPException(status_code=500, detail=DB_INIT_ERROR)
    assert _Session is not None
    global _initialized
    async with _Session() as session:
        if not _initialized:
            async with session.begin():
                await session.execute(DDL_INIT_SQL)
            _initialized = True
        yield session

# --- Pydantic models ---

class SLOCreate(BaseModel):
    service: str = Field(..., min_length=1, max_length=200)
    env: str = Field(default="production", min_length=2, max_length=32)
    indicator: str = Field(..., pattern="^(availability|latency|custom)$")
    target: confloat(gt=0.0, lt=1.0) = Field(..., description="SLO target as fraction, e.g. 0.999")
    window_days: conint(ge=1, le=365) = 30
    target_latency_ms: t.Optional[conint(gt=0)] = None
    tags: t.Dict[str, t.Any] = Field(default_factory=dict)

    @validator("target_latency_ms")
    def latency_required_for_latency_indicator(cls, v, values):
        if values.get("indicator") == "latency" and v is None:
            raise ValueError("target_latency_ms is required when indicator=latency")
        return v

class SLOUpdate(BaseModel):
    target: t.Optional[confloat(gt=0.0, lt=1.0)] = None
    window_days: t.Optional[conint(ge=1, le=365)] = None
    target_latency_ms: t.Optional[conint(gt=0)] = None
    tags: t.Optional[t.Dict[str, t.Any]] = None

class SLOOut(BaseModel):
    slo_id: int
    service: str
    env: str
    indicator: str
    target: float
    window_days: int
    target_latency_ms: t.Optional[int]
    tags: t.Dict[str, t.Any]
    created_at: dt.datetime
    updated_at: dt.datetime

class SLOStatusOut(BaseModel):
    service: str
    env: str
    indicator: str
    window_days: int
    target: float
    total_events: int
    ok_events: int
    warn_events: int
    fail_events: int
    availability: float
    error_budget: float
    error_consumed: float
    error_budget_remaining: float
    sli_latency_ms: t.Optional[float] = None  # e.g. p95 if indicator=latency
    computed_at: dt.datetime

class BurnRateOut(BaseModel):
    service: str
    env: str
    indicator: str
    target: float
    windows: t.Dict[str, float]  # window label -> burn rate
    computed_at: dt.datetime

class BudgetForecastOut(BaseModel):
    service: str
    env: str
    indicator: str
    target: float
    window_days: int
    error_budget_remaining: float
    current_burn_rate_24h: float
    estimated_time_to_exhaustion_hours: t.Optional[float]
    computed_at: dt.datetime

# --- CRUD Endpoints ---

@router.post("/objectives", response_model=SLOOut, status_code=status.HTTP_201_CREATED)
async def create_slo(
    payload: SLOCreate,
    session: AsyncSession = Depends(get_session),
    x_request_id: t.Optional[str] = Header(None, alias="X-Request-ID"),
):
    with _tracer.start_as_current_span("sla.create"):
        q = text(f"""
            INSERT INTO {SLA_SCHEMA}.sla_objectives (service, env, indicator, target, window_days, target_latency_ms, tags)
            VALUES (:service, :env, :indicator, :target, :window_days, :target_latency_ms, COALESCE(:tags::jsonb, '{{}}'::jsonb))
            ON CONFLICT (service, env, indicator)
            DO UPDATE SET target=EXCLUDED.target, window_days=EXCLUDED.window_days,
                          target_latency_ms=EXCLUDED.target_latency_ms, tags=EXCLUDED.tags
            RETURNING slo_id, service, env, indicator, target, window_days, target_latency_ms, tags, created_at, updated_at
        """)
        res = await session.execute(q, {
            "service": payload.service,
            "env": payload.env,
            "indicator": payload.indicator,
            "target": float(payload.target),
            "window_days": int(payload.window_days),
            "target_latency_ms": payload.target_latency_ms,
            "tags": os.environ.get("SLA_TAGS_FORCE") or (payload.json(include={"tags"}, exclude_none=True) if payload.tags else "{}"),
        })
        row = res.first()
        if not row:
            raise HTTPException(status_code=500, detail="Failed to create SLO")
        await session.commit()
        _sla_requests.labels(route="/objectives", method="POST", status="201").inc()
        return SLOOut(**row._mapping)

@router.get("/objectives", response_model=t.List[SLOOut])
async def list_slos(
    service: t.Optional[str] = Query(None),
    env: t.Optional[str] = Query(None),
    limit: conint(gt=0, le=500) = 100,
    offset: conint(ge=0) = 0,
    session: AsyncSession = Depends(get_session),
):
    with _tracer.start_as_current_span("sla.list"):
        where = []
        params: dict[str, t.Any] = {"limit": int(limit), "offset": int(offset)}
        if service:
            where.append("service = :service")
            params["service"] = service
        if env:
            where.append("env = :env")
            params["env"] = env
        sql = f"""
            SELECT slo_id, service, env, indicator, target, window_days, target_latency_ms, tags, created_at, updated_at
            FROM {SLA_SCHEMA}.sla_objectives
            {"WHERE " + " AND ".join(where) if where else ""}
            ORDER BY service, env, indicator
            LIMIT :limit OFFSET :offset
        """
        res = await session.execute(text(sql), params)
        rows = res.fetchall()
        _sla_requests.labels(route="/objectives", method="GET", status="200").inc()
        return [SLOOut(**r._mapping) for r in rows]

@router.get("/objectives/{slo_id}", response_model=SLOOut)
async def get_slo(
    slo_id: int = Path(..., gt=0),
    session: AsyncSession = Depends(get_session),
):
    with _tracer.start_as_current_span("sla.get"):
        res = await session.execute(text(f"""
            SELECT slo_id, service, env, indicator, target, window_days, target_latency_ms, tags, created_at, updated_at
            FROM {SLA_SCHEMA}.sla_objectives WHERE slo_id=:slo_id
        """), {"slo_id": slo_id})
        row = res.first()
        if not row:
            raise HTTPException(status_code=404, detail="SLO not found")
        _sla_requests.labels(route="/objectives/{id}", method="GET", status="200").inc()
        return SLOOut(**row._mapping)

@router.patch("/objectives/{slo_id}", response_model=SLOOut)
async def update_slo(
    payload: SLOUpdate,
    slo_id: int = Path(..., gt=0),
    session: AsyncSession = Depends(get_session),
):
    with _tracer.start_as_current_span("sla.update"):
        fields, params = [], {"slo_id": slo_id}
        if payload.target is not None:
            fields.append("target=:target")
            params["target"] = float(payload.target)
        if payload.window_days is not None:
            fields.append("window_days=:window_days")
            params["window_days"] = int(payload.window_days)
        if payload.target_latency_ms is not None:
            fields.append("target_latency_ms=:target_latency_ms")
            params["target_latency_ms"] = int(payload.target_latency_ms)
        if payload.tags is not None:
            fields.append("tags=:tags::jsonb")
            params["tags"] = payload.json(include={"tags"})
        if not fields:
            raise HTTPException(status_code=400, detail="No fields to update")
        sql = f"""
            UPDATE {SLA_SCHEMA}.sla_objectives
            SET {", ".join(fields)}
            WHERE slo_id=:slo_id
            RETURNING slo_id, service, env, indicator, target, window_days, target_latency_ms, tags, created_at, updated_at
        """
        res = await session.execute(text(sql), params)
        row = res.first()
        if not row:
            raise HTTPException(status_code=404, detail="SLO not found")
        await session.commit()
        _sla_requests.labels(route="/objectives/{id}", method="PATCH", status="200").inc()
        return SLOOut(**row._mapping)

@router.delete("/objectives/{slo_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_slo(
    slo_id: int = Path(..., gt=0),
    session: AsyncSession = Depends(get_session),
):
    with _tracer.start_as_current_span("sla.delete"):
        res = await session.execute(text(f"DELETE FROM {SLA_SCHEMA}.sla_objectives WHERE slo_id=:slo_id"), {"slo_id": slo_id})
        if res.rowcount == 0:
            raise HTTPException(status_code=404, detail="SLO not found")
        await session.commit()
        _sla_requests.labels(route="/objectives/{id}", method="DELETE", status="204").inc()
        return None

# --- Computation helpers ---

async def _load_slo(session: AsyncSession, service: str, env: str, indicator: str) -> SLOOut:
    res = await session.execute(text(f"""
        SELECT slo_id, service, env, indicator, target, window_days, target_latency_ms, tags, created_at, updated_at
        FROM {SLA_SCHEMA}.sla_objectives
        WHERE service=:service AND env=:env AND indicator=:indicator
    """), {"service": service, "env": env, "indicator": indicator})
    row = res.first()
    if not row:
        raise HTTPException(status_code=404, detail="SLO objective not found for given service/env/indicator")
    return SLOOut(**row._mapping)

async def _calc_availability(
    session: AsyncSession,
    service: str,
    env: str,
    days: int,
) -> tuple[int, int, int, int]:
    # Считаем по hourly-агрегации (см. миграцию 0003_heartbeats.sql)
    sql = text("""
        SELECT
          COALESCE(SUM(total_count),0)  AS total,
          COALESCE(SUM(ok_count),0)     AS ok,
          COALESCE(SUM(warn_count),0)   AS warn,
          COALESCE(SUM(fail_count),0)   AS fail
        FROM chronowatch.heartbeats_hourly
        WHERE service = :service
          AND env = :env
          AND bucket_ts >= (now() AT TIME ZONE 'UTC') - (:days::text || ' days')::interval
    """)
    res = await session.execute(sql, {"service": service, "env": env, "days": days})
    row = res.first()
    total = int(row.total or 0)
    ok = int(row.ok or 0)
    warn = int(row.warn or 0)
    fail = int(row.fail or 0)
    return total, ok, warn, fail

async def _calc_latency_p95_ms(
    session: AsyncSession, service: str, env: str, days: int
) -> t.Optional[float]:
    # Приближенно считаем p95 по исходной таблице heartbeats (если latency_ms заполнен)
    # Можно заменить на materialized view mv_heartbeats_hourly_latency при наличии.
    sql = text("""
        SELECT PERCENTILE_DISC(0.95) WITHIN GROUP (ORDER BY latency_ms)::float AS p95
        FROM chronowatch.heartbeats
        WHERE service = :service
          AND env = :env
          AND ts_utc >= (now() AT TIME ZONE 'UTC') - (:days::text || ' days')::interval
          AND latency_ms IS NOT NULL
    """)
    res = await session.execute(sql, {"service": service, "env": env, "days": days})
    row = res.first()
    return float(row.p95) if row and row.p95 is not None else None

def _safe_div(n: float, d: float) -> float:
    return n / d if d > 0 else 0.0

# --- Status / Burn-rate / Budget endpoints ---

@router.get("/status", response_model=SLOStatusOut)
async def get_status(
    service: str = Query(..., min_length=1, max_length=200),
    env: str = Query("production", min_length=2, max_length=32),
    indicator: str = Query("availability", regex="^(availability|latency|custom)$"),
    window_days: t.Optional[int] = Query(None, ge=1, le=365),
    session: AsyncSession = Depends(get_session),
):
    t0 = dt.datetime.now(dt.timezone.utc)
    with _tracer.start_as_current_span("sla.status"):
        slo = await _load_slo(session, service, env, indicator)
        days = int(window_days or slo.window_days)

        total, ok, warn, fail = await _calc_availability(session, service, env, days)

        # Политика: считаем ошибкой только "fail"
        err_events = fail
        availability = _safe_div(total - err_events, total)
        error_budget = 1.0 - float(slo.target)
        error_consumed = 1.0 - availability
        remaining = max(0.0, error_budget - error_consumed)

        sli_latency_ms = None
        if indicator == "latency":
            sli_latency_ms = await _calc_latency_p95_ms(session, service, env, days)

        t1 = dt.datetime.now(dt.timezone.utc)
        _sla_calc_seconds.labels("status").set((t1 - t0).total_seconds())
        _sla_requests.labels(route="/status", method="GET", status="200").inc()

        return SLOStatusOut(
            service=service,
            env=env,
            indicator=indicator,
            window_days=days,
            target=float(slo.target),
            total_events=total,
            ok_events=ok,
            warn_events=warn,
            fail_events=fail,
            availability=availability,
            error_budget=error_budget,
            error_consumed=error_consumed,
            error_budget_remaining=remaining,
            sli_latency_ms=sli_latency_ms,
            computed_at=t1,
        )

@router.get("/burn-rate", response_model=BurnRateOut)
async def get_burn_rate(
    service: str = Query(..., min_length=1, max_length=200),
    env: str = Query("production", min_length=2, max_length=32),
    indicator: str = Query("availability", regex="^(availability|latency|custom)$"),
    session: AsyncSession = Depends(get_session),
):
    # Окна для оценки (часовые бакеты используются, поэтому разрешение ~1h)
    windows_hours = {
        "1h": 1,
        "6h": 6,
        "24h": 24,
        "7d": 24 * 7,
        "30d": 24 * 30,
    }
    slo = await _load_slo(session, service, env, indicator)
    error_budget = 1.0 - float(slo.target)

    def to_days(hours: int) -> int:
        return max(1, math.ceil(hours / 24))

    rates: dict[str, float] = {}
    with _tracer.start_as_current_span("sla.burn_rate"):
        for label, hours in windows_hours.items():
            total, ok, warn, fail = await _calc_availability(session, service, env, to_days(hours))
            # Приближение: берем последние N часов из дневного окна — для часов < 24 точность ограничена.
            # Если нужен точный расчет за 1h/6h, используйте исходную таблицу по минутам.
            err_frac = _safe_div(fail, total)
            rates[label] = _safe_div(err_frac, error_budget) if error_budget > 0 else 0.0

    now = dt.datetime.now(dt.timezone.utc)
    _sla_requests.labels(route="/burn-rate", method="GET", status="200").inc()
    return BurnRateOut(
        service=service,
        env=env,
        indicator=indicator,
        target=float(slo.target),
        windows=rates,
        computed_at=now,
    )

@router.get("/budget", response_model=BudgetForecastOut)
async def get_budget_forecast(
    service: str = Query(..., min_length=1, max_length=200),
    env: str = Query("production", min_length=2, max_length=32),
    indicator: str = Query("availability", regex="^(availability|latency|custom)$"),
    session: AsyncSession = Depends(get_session),
):
    with _tracer.start_as_current_span("sla.budget_forecast"):
        slo = await _load_slo(session, service, env, indicator)
        total, ok, warn, fail = await _calc_availability(session, service, env, slo.window_days)
        availability = _safe_div(total - fail, total)
        error_budget = 1.0 - float(slo.target)
        consumed = 1.0 - availability
        remaining = max(0.0, error_budget - consumed)

        # Берем burn-rate за ~24h как текущий темп (см. комментарий про точность)
        total24, _, _, fail24 = await _calc_availability(session, service, env, 2)  # ~приближение
        err_frac_24h = _safe_div(fail24, total24)
        burn_24h = _safe_div(err_frac_24h, error_budget) if error_budget > 0 else 0.0

        # Если burn_24h == 0, ресурс бесконечен в рамках модели
        etta_hours: t.Optional[float] = None
        if burn_24h > 0:
            # За 24 часа расходуется burn_24h * error_budget (доля окна)
            # Сколько часов до исчерпания оставшегося бюджета:
            etta_hours = (remaining / (burn_24h * error_budget)) * 24.0

        now = dt.datetime.now(dt.timezone.utc)
        _sla_requests.labels(route="/budget", method="GET", status="200").inc()
        return BudgetForecastOut(
            service=service,
            env=env,
            indicator=indicator,
            target=float(slo.target),
            window_days=int(slo.window_days),
            error_budget_remaining=remaining,
            current_burn_rate_24h=burn_24h,
            estimated_time_to_exhaustion_hours=etta_hours,
            computed_at=now,
        )
