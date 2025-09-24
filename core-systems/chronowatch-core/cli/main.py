# chronowatch-core/cli/main.py
from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
import typing as t
import datetime as dt
from dataclasses import dataclass

# -------- Soft deps (lazy import helpers) --------
def _require(module: str, hint: str):
    try:
        return __import__(module)
    except Exception as e:
        raise RuntimeError(f"Missing optional dependency '{module}'. {hint}") from e

def _maybe(module: str):
    try:
        return __import__(module)
    except Exception:
        return None

# Observability (soft)
_ot = _maybe("opentelemetry.trace")
_tracer = (_ot.trace.get_tracer(__name__) if _ot else None)

_prom = _maybe("prometheus_client")
if _prom:
    _cli_runs = _prom.Counter("chronowatch_cli_runs_total", "CLI runs", ["command"])
else:
    class _NoMetric:
        def labels(self, *a, **k): return self
        def inc(self, *a, **k): pass
    _cli_runs = _NoMetric()

# -------- Output formatting --------
class OutputFormat(str):
    JSON = "json"
    TEXT = "text"

def _print(data: t.Any, fmt: str):
    if fmt == OutputFormat.JSON:
        sys.stdout.write(json.dumps(data, ensure_ascii=False, separators=(",", ":"), default=str) + "\n")
    else:
        if isinstance(data, (dict, list, tuple)):
            sys.stdout.write(json.dumps(data, ensure_ascii=False, indent=2, default=str) + "\n")
        else:
            sys.stdout.write(str(data) + "\n")
    sys.stdout.flush()

# -------- Global config --------
APP_NAME = "chronowatch-core"
APP_VERSION = os.getenv("CHRONO_VERSION", "0.0.0")
BUILD_REF = os.getenv("CHRONO_BUILD_REF", "")
BUILD_DATE = os.getenv("CHRONO_BUILD_DATE", "")

DEFAULT_CONFIG_PATH = os.getenv("CHRONO_CONFIG", "configs/chronowatch.yaml")
DEFAULT_SCHEDULE_PATH = os.getenv("CHRONO_SCHEDULES", "configs/templates/schedule_rrule.example.yaml")
DATABASE_DSN = os.getenv("DATABASE_DSN")  # postgresql+asyncpg://...

# -------- Async DB helpers (soft SQLAlchemy) --------
async def _with_session() -> "typing.AsyncContextManager":
    sa = _require("sqlalchemy", "Install SQLAlchemy for DB commands (pip install sqlalchemy[asyncio])")
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession  # type: ignore

    if not DATABASE_DSN:
        raise RuntimeError("Missing DATABASE_DSN environment variable")
    engine = create_async_engine(DATABASE_DSN, pool_pre_ping=True, pool_size=5, max_overflow=10)
    Session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    class _Mgr:
        async def __aenter__(self):
            self.session = Session()
            return self.session
        async def __aexit__(self, exc_type, exc, tb):
            await self.session.close()
            await engine.dispose()
    return _Mgr()

# -------- Signal handling --------
def _install_signal_handlers():
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda s=sig: asyncio.ensure_future(_shutdown(s)))
        except NotImplementedError:
            pass

async def _shutdown(sig: signal.Signals):
    sys.stderr.write(f"Received {sig.name}, shutting down...\n")
    await asyncio.sleep(0.01)
    sys.exit(130 if sig == signal.SIGINT else 143)

# -------- Typer app --------
try:
    typer = _require("typer", "Install Typer (pip install typer[all])").typer
except RuntimeError as e:
    # Re-raise with clear message when CLI is invoked without Typer
    raise

app = typer.Typer(add_completion=False, no_args_is_help=True, help="ChronoWatch Core CLI")
config_app = typer.Typer(help="Configuration utilities")
maintenance_app = typer.Typer(help="Maintenance windows operations")
schedule_app = typer.Typer(help="RRULE schedule operations")
sla_app = typer.Typer(help="SLA/SLO calculations")
db_app = typer.Typer(help="Database utilities")

app.add_typer(config_app, name="config")
app.add_typer(maintenance_app, name="maintenance")
app.add_typer(schedule_app, name="schedule")
app.add_typer(sla_app, name="sla")
app.add_typer(db_app, name="db")

# =========================
# version
# =========================
@app.command("version")
def version(
    output: str = typer.Option(OutputFormat.TEXT, "--output", "-o", case_sensitive=False, help="Output format: json|text"),
):
    """Print version and build info."""
    _cli_runs.labels(command="version").inc()
    data = {
        "app": APP_NAME,
        "version": APP_VERSION,
        "build_ref": BUILD_REF,
        "build_date": BUILD_DATE,
        "python": sys.version.split()[0],
    }
    _print(data if output == OutputFormat.JSON else f"{APP_NAME} {APP_VERSION} ({BUILD_REF}) built {BUILD_DATE}", output)

# =========================
# config validate
# =========================
@config_app.command("validate")
def config_validate(
    path: str = typer.Option(DEFAULT_CONFIG_PATH, "--path", "-p", help="Path to chronowatch.yaml"),
    output: str = typer.Option(OutputFormat.TEXT, "--output", "-o", case_sensitive=False),
):
    """Validate chronowatch.yaml shape (light schema)."""
    yaml = _require("yaml", "Install PyYAML (pip install pyyaml)")
    data = None
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    # Minimal structural checks (intentionally light to avoid tight coupling)
    errors: list[str] = []
    if "version" not in data:
        errors.append("missing: version")
    if "server" not in data or "http" not in data["server"]:
        errors.append("missing: server.http")
    if "observability" not in data or "logging" not in data["observability"]:
        errors.append("missing: observability.logging")
    if "storage" not in data or "database" not in data["storage"]:
        errors.append("missing: storage.database")

    ok = len(errors) == 0
    result = {"ok": ok, "errors": errors, "path": path}
    _cli_runs.labels(command="config.validate").inc()
    _print(result if output == OutputFormat.JSON else ("OK" if ok else "INVALID:\n- " + "\n- ".join(errors)), output)
    sys.exit(0 if ok else 2)

# =========================
# maintenance {status,next,set-emergency}
# =========================
@maintenance_app.command("status")
def maintenance_status(
    output: str = typer.Option(OutputFormat.TEXT, "--output", "-o", case_sensitive=False),
):
    """Show if maintenance is in effect now."""
    from chronowatch.windows.maintenance import DEFAULT_MANAGER  # type: ignore
    async def _run():
        in_effect, start, end, rule_id = await DEFAULT_MANAGER.is_in_effect()
        res = {"in_effect": in_effect, "start": start, "end": end, "rule_id": rule_id}
        _print(res if output == OutputFormat.JSON else (f"in_effect={in_effect} rule={rule_id} start={start} end={end}"), output)
        return 0
    _cli_runs.labels(command="maintenance.status").inc()
    sys.exit(asyncio.run(_run()))

@maintenance_app.command("next")
def maintenance_next(
    output: str = typer.Option(OutputFormat.TEXT, "--output", "-o", case_sensitive=False),
):
    """Show the nearest upcoming maintenance window."""
    from chronowatch.windows.maintenance import DEFAULT_MANAGER  # type: ignore
    async def _run():
        s, e, rid = await DEFAULT_MANAGER.next_window()
        res = {"start": s, "end": e, "rule_id": rid}
        _print(res if output == OutputFormat.JSON else (f"start={s} end={e} rule={rid}"), output)
        return 0 if s else 3
    _cli_runs.labels(command="maintenance.next").inc()
    sys.exit(asyncio.run(_run()))

@maintenance_app.command("set-emergency")
def maintenance_set_emergency(
    enabled: bool = typer.Argument(..., help="true|false"),
    ttl: int = typer.Option(3600, "--ttl", help="TTL seconds for emergency flag"),
    output: str = typer.Option(OutputFormat.TEXT, "--output", "-o", case_sensitive=False),
):
    """Enable or disable emergency maintenance flag."""
    from chronowatch.windows.maintenance import DEFAULT_MANAGER  # type: ignore
    async def _run():
        await DEFAULT_MANAGER.set_emergency(enabled, ttl_seconds=ttl if enabled else None)
        res = {"emergency": enabled, "ttl_seconds": ttl if enabled else None}
        _print(res if output == OutputFormat.JSON else (f"emergency={enabled} ttl={ttl if enabled else 'none'}"), output)
        return 0
    _cli_runs.labels(command="maintenance.set-emergency").inc()
    sys.exit(asyncio.run(_run()))

# =========================
# schedule next
# =========================
@schedule_app.command("next")
def schedule_next(
    schedule_file: str = typer.Option(DEFAULT_SCHEDULE_PATH, "--file", "-f", help="Path to RRULE schedules YAML"),
    schedule_id: str = typer.Option(..., "--id", "-i", help="Schedule ID"),
    count: int = typer.Option(5, "--count", "-n", min=1, max=100, help="Occurrences to show"),
    after: t.Optional[str] = typer.Option(None, "--after", help="ISO datetime to start after"),
    output: str = typer.Option(OutputFormat.TEXT, "--output", "-o", case_sensitive=False),
):
    """Compute next N occurrences for a schedule ID."""
    yaml = _require("yaml", "Install PyYAML (pip install pyyaml)")
    du = _require("dateutil.rrule", "Install python-dateutil (pip install python-dateutil)")
    from zoneinfo import ZoneInfo

    data = None
    with open(schedule_file, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    schedules = {s["id"]: s for s in (data.get("schedules") or []) if "id" in s}
    if schedule_id not in schedules:
        _print({"error": f"schedule '{schedule_id}' not found", "file": schedule_file}, output)
        sys.exit(4)

    s = schedules[schedule_id]
    tz = ZoneInfo(s.get("timezone", "UTC"))
    rs = du.rruleset.rruleset()
    base = (dt.datetime.now(tz) - dt.timedelta(days=365*2))
    for r in (s.get("calendar", {}).get("rrule") or []):
        rs.rrule(du.rrulestr.rrulestr(r, dtstart=base))
    for d in (s.get("calendar", {}).get("rdate") or []):
        rs.rdate(dt.datetime.fromisoformat(d).astimezone(tz))
    for r in (s.get("calendar", {}).get("exrule") or []):
        rs.exrule(du.rrulestr.rrulestr(r, dtstart=base))
    for d in (s.get("calendar", {}).get("exdate") or []):
        rs.exdate(dt.datetime.fromisoformat(d).astimezone(tz))

    start_after = (dt.datetime.fromisoformat(after) if after else dt.datetime.now(dt.timezone.utc)).astimezone(tz)
    out: list[str] = []
    nxt = rs.after(start_after, inc=False)
    while nxt and len(out) < count:
        out.append(nxt.isoformat())
        nxt = rs.after(nxt, inc=False)

    _cli_runs.labels(command="schedule.next").inc()
    _print({"id": schedule_id, "timezone": str(tz), "next": out} if output == OutputFormat.JSON else f"{schedule_id} next: {out}", output)

# =========================
# SLA {status,burn-rate,budget}
# =========================
@dataclass
class _SLO:
    service: str
    env: str
    indicator: str
    target: float
    window_days: int
    target_latency_ms: int | None

async def _get_slo(session, service: str, env: str, indicator: str) -> _SLO:
    sql = """
        SELECT service, env, indicator, target::float, window_days, target_latency_ms
        FROM chronowatch.sla_objectives
        WHERE service=:service AND env=:env AND indicator=:indicator
    """
    res = await session.execute(_require("sqlalchemy", "").text(sql), {"service": service, "env": env, "indicator": indicator})
    row = res.first()
    if not row:
        raise RuntimeError("SLO not found")
    m = row._mapping
    return _SLO(m["service"], m["env"], m["indicator"], float(m["target"]), int(m["window_days"]), m["target_latency_ms"])

async def _agg_availability(session, service: str, env: str, days: int) -> tuple[int, int, int, int]:
    sql = """
        SELECT
          COALESCE(SUM(total_count),0)  AS total,
          COALESCE(SUM(ok_count),0)     AS ok,
          COALESCE(SUM(warn_count),0)   AS warn,
          COALESCE(SUM(fail_count),0)   AS fail
        FROM chronowatch.heartbeats_hourly
        WHERE service=:service AND env=:env
          AND bucket_ts >= (now() AT TIME ZONE 'UTC') - (:days::text || ' days')::interval
    """
    sa = _require("sqlalchemy", "")
    r = await session.execute(sa.text(sql), {"service": service, "env": env, "days": days})
    m = r.first()._mapping
    return int(m["total"]), int(m["ok"]), int(m["warn"]), int(m["fail"])

async def _latency_p95(session, service: str, env: str, days: int) -> float | None:
    sql = """
        SELECT PERCENTILE_DISC(0.95) WITHIN GROUP (ORDER BY latency_ms)::float AS p95
        FROM chronowatch.heartbeats
        WHERE service=:service AND env=:env
          AND ts_utc >= (now() AT TIME ZONE 'UTC') - (:days::text || ' days')::interval
          AND latency_ms IS NOT NULL
    """
    sa = _require("sqlalchemy", "")
    r = await session.execute(sa.text(sql), {"service": service, "env": env, "days": days})
    row = r.first()
    return float(row.p95) if row and row.p95 is not None else None

@sla_app.command("status")
def sla_status(
    service: str = typer.Option(..., "--service"),
    env: str = typer.Option("production", "--env"),
    indicator: str = typer.Option("availability", "--indicator", help="availability|latency|custom"),
    window_days: int | None = typer.Option(None, "--window-days"),
    output: str = typer.Option(OutputFormat.TEXT, "--output", "-o", case_sensitive=False),
):
    """Compute SLA/SLO status using DB aggregations."""
    async def _run():
        async with await _with_session() as s:
            slo = await _get_slo(s, service, env, indicator)
            days = int(window_days or slo.window_days)
            total, ok, warn, fail = await _agg_availability(s, service, env, days)
            err = fail
            availability = (total - err) / total if total > 0 else 0.0
            error_budget = 1.0 - float(slo.target)
            consumed = 1.0 - availability
            remaining = max(0.0, error_budget - consumed)
            res: dict[str, t.Any] = {
                "service": service, "env": env, "indicator": indicator, "window_days": days,
                "target": slo.target, "availability": availability,
                "error_budget": error_budget, "error_consumed": consumed, "error_budget_remaining": remaining,
                "total_events": total, "ok_events": ok, "warn_events": warn, "fail_events": fail,
                "computed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            }
            if indicator == "latency":
                res["sli_latency_ms"] = await _latency_p95(s, service, env, days)
            _print(res if output == OutputFormat.JSON else res, output)
            return 0
    _cli_runs.labels(command="sla.status").inc()
    sys.exit(asyncio.run(_run()))

@sla_app.command("burn-rate")
def sla_burn_rate(
    service: str = typer.Option(..., "--service"),
    env: str = typer.Option("production", "--env"),
    indicator: str = typer.Option("availability", "--indicator"),
    output: str = typer.Option(OutputFormat.TEXT, "--output", "-o", case_sensitive=False),
):
    """Compute simple multi-window burn-rate."""
    async def _run():
        async with await _with_session() as s:
            slo = await _get_slo(s, service, env, indicator)
            error_budget = 1.0 - float(slo.target)
            windows_hours = {"1h": 1, "6h": 6, "24h": 24, "7d": 24*7, "30d": 24*30}
            rates: dict[str, float] = {}
            for label, hours in windows_hours.items():
                days = max(1, (hours + 23) // 24)
                total, ok, warn, fail = await _agg_availability(s, service, env, days)
                err_frac = (fail / total) if total > 0 else 0.0
                rates[label] = (err_frac / error_budget) if error_budget > 0 else 0.0
            res = {"service": service, "env": env, "indicator": indicator,
                   "target": slo.target, "windows": rates,
                   "computed_at": dt.datetime.now(dt.timezone.utc).isoformat()}
            _print(res if output == OutputFormat.JSON else res, output)
            return 0
    _cli_runs.labels(command="sla.burn-rate").inc()
    sys.exit(asyncio.run(_run()))

@sla_app.command("budget")
def sla_budget(
    service: str = typer.Option(..., "--service"),
    env: str = typer.Option("production", "--env"),
    indicator: str = typer.Option("availability", "--indicator"),
    output: str = typer.Option(OutputFormat.TEXT, "--output", "-o", case_sensitive=False),
):
    """Forecast budget exhaustion using ~24h burn-rate."""
    async def _run():
        async with await _with_session() as s:
            slo = await _get_slo(s, service, env, indicator)
            total, ok, warn, fail = await _agg_availability(s, service, env, slo.window_days)
            availability = (total - fail) / total if total > 0 else 0.0
            error_budget = 1.0 - float(slo.target)
            consumed = 1.0 - availability
            remaining = max(0.0, error_budget - consumed)
            total24, ok24, warn24, fail24 = await _agg_availability(s, service, env, 2)
            err_frac_24h = (fail24 / total24) if total24 > 0 else 0.0
            burn_24h = (err_frac_24h / error_budget) if error_budget > 0 else 0.0
            etta_hours = None if burn_24h <= 0 else (remaining / (burn_24h * error_budget)) * 24.0
            res = {"service": service, "env": env, "indicator": indicator,
                   "target": slo.target, "window_days": int(slo.window_days),
                   "error_budget_remaining": remaining, "current_burn_rate_24h": burn_24h,
                   "estimated_time_to_exhaustion_hours": etta_hours,
                   "computed_at": dt.datetime.now(dt.timezone.utc).isoformat()}
            _print(res if output == OutputFormat.JSON else res, output)
            return 0
    _cli_runs.labels(command="sla.budget").inc()
    sys.exit(asyncio.run(_run()))

# =========================
# db ping
# =========================
@db_app.command("ping")
def db_ping(
    output: str = typer.Option(OutputFormat.TEXT, "--output", "-o", case_sensitive=False),
):
    """Check DB connectivity and basic heartbeat presence."""
    async def _run():
        try:
            async with await _with_session() as s:
                sa = _require("sqlalchemy", "")
                res = await s.execute(sa.text("SELECT now() AT TIME ZONE 'UTC' AS now_utc"))
                now = res.first().now_utc
                # Optional check: aggregated heartbeats existence
                r2 = await s.execute(sa.text("SELECT COUNT(*) AS c FROM chronowatch.heartbeats_hourly"))
                cnt = int(r2.first().c)
                _print({"ok": True, "now_utc": now, "heartbeats_hourly_rows": cnt} if output == OutputFormat.JSON
                       else f"OK now_utc={now} heartbeats_hourly_rows={cnt}", output)
                return 0
        except Exception as e:
            _print({"ok": False, "error": str(e)} if output == OutputFormat.JSON else f"ERROR: {e}", output)
            return 5
    _cli_runs.labels(command="db.ping").inc()
    sys.exit(asyncio.run(_run()))

# =========================
# main
# =========================
def _main():
    _install_signal_handlers()
    if _tracer:
        with _tracer.start_as_current_span("cli.run"):
            app()
    else:
        app()

if __name__ == "__main__":
    _main()
