# chronowatch-core/chronowatch/windows/maintenance.py
from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
import json
import os
import re
import typing as t
from contextlib import asynccontextmanager
from functools import lru_cache
from zoneinfo import ZoneInfo

# --- Soft deps (lazy) ---
# dateutil.rrule is used for RFC5545 parsing; imported lazily inside methods.
# YAML is optional for load_from_yaml.

# --- Optional Observability (soft dependency) ---
try:
    from opentelemetry import trace  # type: ignore
    _tracer = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    class _NoSpan:
        def __enter__(self): return self
        def __exit__(self, *a): return False
    class _NoTracer:
        def start_as_current_span(self, *a, **k): return _NoSpan()
    _tracer = _NoTracer()

try:
    from prometheus_client import Counter, Gauge  # type: ignore
    _mw_checks = Counter("chronowatch_maintenance_checks_total", "Total maintenance checks", ["result"])
    _mw_next_calc = Gauge("chronowatch_maintenance_next_seconds", "Seconds to next maintenance window", ["rule_id"])
except Exception:  # pragma: no cover
    class _NoMetric:
        def labels(self, *a, **k): return self
        def inc(self, *a, **k): pass
        def set(self, *a, **k): pass
    _mw_checks = _NoMetric()
    _mw_next_calc = _NoMetric()

__all__ = [
    "MaintenanceError",
    "MaintenanceInEffect",
    "FlagBackend",
    "InMemoryFlagBackend",
    "RedisFlagBackend",
    "MaintenanceRule",
    "MaintenanceManager",
    "maintenance_guard",
    "maintenance_block",
]

# =========================
# Exceptions
# =========================

class MaintenanceError(RuntimeError):
    """Base class for maintenance errors."""

class MaintenanceInEffect(MaintenanceError):
    """Raised when an operation is attempted during maintenance."""
    def __init__(self, message: str, start: dt.datetime | None, end: dt.datetime | None, rule_id: str | None = None):
        super().__init__(message)
        self.start = start
        self.end = end
        self.rule_id = rule_id


# =========================
# Flag backends
# =========================

class FlagBackend(t.Protocol):
    async def get(self, key: str) -> bool: ...
    async def set(self, key: str, value: bool, ttl_seconds: int | None = None) -> None: ...

class InMemoryFlagBackend:
    def __init__(self):
        self._data: dict[str, tuple[bool, float | None]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> bool:
        async with self._lock:
            val = self._data.get(key)
            if not val:
                return False
            value, expires = val
            if expires is not None and expires < dt.datetime.now(dt.timezone.utc).timestamp():
                self._data.pop(key, None)
                return False
            return bool(value)

    async def set(self, key: str, value: bool, ttl_seconds: int | None = None) -> None:
        async with self._lock:
            expires = None
            if ttl_seconds is not None:
                expires = dt.datetime.now(dt.timezone.utc).timestamp() + ttl_seconds
            self._data[key] = (bool(value), expires)

class RedisFlagBackend:
    """
    Optional Redis backend using redis.asyncio if available.
    Key is stored as string '1'/'0'. TTL handled by EXPIRE.
    """
    def __init__(self, url: str):
        try:
            import redis.asyncio as redis  # type: ignore
        except Exception as e:  # pragma: no cover
            raise RuntimeError("redis.asyncio is required for RedisFlagBackend") from e
        self._redis = redis.from_url(url, decode_responses=True)

    async def get(self, key: str) -> bool:
        val = await self._redis.get(key)
        return val == "1"

    async def set(self, key: str, value: bool, ttl_seconds: int | None = None) -> None:
        await self._redis.set(key, "1" if value else "0")
        if ttl_seconds is not None:
            await self._redis.expire(key, ttl_seconds)


# =========================
# Utilities
# =========================

_DURATION_RE = re.compile(
    r"^P(?:(?P<days>\d+)D)?"
    r"(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+)S)?)?$"
)

def parse_iso8601_duration(value: str) -> dt.timedelta:
    """
    Parse minimal ISO-8601 duration strings like PnDTnHnMnS, PnD, PTnH, PTnM, PTnS.
    """
    m = _DURATION_RE.match(value)
    if not m:
        raise ValueError(f"Invalid ISO-8601 duration: {value}")
    days = int(m.group("days") or 0)
    hours = int(m.group("hours") or 0)
    minutes = int(m.group("minutes") or 0)
    seconds = int(m.group("seconds") or 0)
    return dt.timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)

def ensure_aware(ts: dt.datetime, tz: ZoneInfo) -> dt.datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=tz)
    return ts.astimezone(tz)

@lru_cache(maxsize=128)
def _zone(name: str) -> ZoneInfo:
    return ZoneInfo(name)

def _now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


# =========================
# Maintenance rule
# =========================

@dataclasses.dataclass(slots=True)
class MaintenanceRule:
    """
    A single maintenance rule defined by RFC5545 strings and duration per occurrence.
    - timezone: IANA TZ name (e.g., "Europe/Stockholm")
    - rrule: list of RRULE strings
    - rdate: list of ISO-8601 datetimes (local to timezone) -> explicit starts
    - exrule: list of exclusion RRULE strings
    - exdate: list of ISO-8601 datetimes to exclude
    - duration: ISO-8601 duration string (PnDTnHnMnS)
    - id: rule identifier
    """
    id: str
    timezone: str = "UTC"
    rrule: list[str] = dataclasses.field(default_factory=list)
    rdate: list[str] = dataclasses.field(default_factory=list)
    exrule: list[str] = dataclasses.field(default_factory=list)
    exdate: list[str] = dataclasses.field(default_factory=list)
    duration: str = "PT30M"
    description: str = ""

    def _rruleset(self):
        try:
            from dateutil import rrule as du_rrule  # lazy import
        except Exception as e:  # pragma: no cover
            raise RuntimeError("python-dateutil is required for MaintenanceRule") from e

        tz = _zone(self.timezone)
        rs = du_rrule.rruleset()

        # RRULEs
        for r in self.rrule:
            # rrulestr respects DTSTART in the string; if not provided, we add a default dtstart
            # We set dtstart to now-2y by default to not miss near-term recurrences.
            base = _now_utc().astimezone(tz) - dt.timedelta(days=730)
            rs.rrule(du_rrule.rrulestr(r, dtstart=base))

        # RDATEs
        for d in self.rdate:
            start = ensure_aware(dt.datetime.fromisoformat(d), tz)
            rs.rdate(start)

        # EXRULEs
        for x in self.exrule:
            base = _now_utc().astimezone(tz) - dt.timedelta(days=730)
            rs.exrule(du_rrule.rrulestr(x, dtstart=base))

        # EXDATEs
        for x in self.exdate:
            exd = ensure_aware(dt.datetime.fromisoformat(x), tz)
            rs.exdate(exd)

        return rs, tz

    def _duration_td(self) -> dt.timedelta:
        return parse_iso8601_duration(self.duration)

    def is_in_effect(self, when: dt.datetime | None = None) -> tuple[bool, dt.datetime | None, dt.datetime | None]:
        """
        Return (in_effect, start, end) for the given moment (default now in rule tz).
        """
        rs, tz = self._rruleset()
        td = self._duration_td()
        now_loc = ensure_aware(when or _now_utc(), tz)

        # Find the last occurrence <= now and the next occurrence > now, then check span.
        prev_start = rs.before(now_loc, inc=True)
        if prev_start is not None:
            end = prev_start + td
            if prev_start <= now_loc < end:
                return True, prev_start, end

        return False, None, None

    def next_window(self, after: dt.datetime | None = None) -> tuple[dt.datetime | None, dt.datetime | None]:
        """
        Return the next (start, end) window strictly after 'after' (default now).
        """
        rs, tz = self._rruleset()
        td = self._duration_td()
        base = ensure_aware(after or _now_utc(), tz)
        nxt = rs.after(base, inc=False)
        if nxt is None:
            return None, None
        return nxt, nxt + td


# =========================
# Maintenance manager
# =========================

class MaintenanceManager:
    """
    Holds multiple rules and emergency flag backend.
    """
    def __init__(
        self,
        rules: list[MaintenanceRule] | None = None,
        flag_backend: FlagBackend | None = None,
        emergency_flag_key: str = "chronowatch:maintenance:emergency",
    ):
        self.rules = rules or []
        self.flags = flag_backend or InMemoryFlagBackend()
        self.emergency_flag_key = emergency_flag_key

    # --------- Configuration loaders ---------

    @classmethod
    def from_dict(cls, data: dict[str, t.Any], flag_backend: FlagBackend | None = None) -> "MaintenanceManager":
        """
        Expected schema:
        {
          "maintenance": {
            "emergency": false,
            "rules": [
              {
                "id": "ad-hoc",
                "timezone": "Europe/Stockholm",
                "duration": "PT15M",
                "rrule": ["FREQ=MINUTELY;INTERVAL=5"],
                "rdate": ["2025-10-10T23:00:00"],
                "exrule": [],
                "exdate": []
              }
            ]
          }
        }
        """
        maint = data.get("maintenance", {})
        rules_data = maint.get("rules", [])
        rules: list[MaintenanceRule] = []
        for r in rules_data:
            rules.append(MaintenanceRule(
                id=r["id"],
                timezone=r.get("timezone", "UTC"),
                rrule=list(r.get("rrule", []) or []),
                rdate=list(r.get("rdate", []) or []),
                exrule=list(r.get("exrule", []) or []),
                exdate=list(r.get("exdate", []) or []),
                duration=r.get("duration", "PT30M"),
                description=r.get("description", ""),
            ))
        mgr = cls(rules=rules, flag_backend=flag_backend)
        # Initialize emergency flag from config
        if isinstance(maint.get("emergency"), bool) and maint["emergency"]:
            # set with small TTL to avoid stale permanent state if backend evicts
            asyncio.get_event_loop().create_task(mgr.set_emergency(True, ttl_seconds=3600))
        return mgr

    @classmethod
    def load_from_yaml(cls, path: str, flag_backend: FlagBackend | None = None) -> "MaintenanceManager":
        try:
            import yaml  # type: ignore
        except Exception as e:  # pragma: no cover
            raise RuntimeError("PyYAML is required for load_from_yaml") from e
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls.from_dict(data, flag_backend=flag_backend)

    # --------- Emergency flag ---------

    async def is_emergency(self) -> bool:
        val = await self.flags.get(self.emergency_flag_key)
        return bool(val)

    async def set_emergency(self, value: bool, ttl_seconds: int | None = None) -> None:
        await self.flags.set(self.emergency_flag_key, bool(value), ttl_seconds)

    # --------- Core queries ---------

    async def is_in_effect(
        self, when: dt.datetime | None = None
    ) -> tuple[bool, dt.datetime | None, dt.datetime | None, str | None]:
        """
        Check if maintenance is in effect now or at provided time across all rules OR emergency flag.
        Returns: (in_effect, start, end, rule_id)
        """
        with _tracer.start_as_current_span("maintenance.is_in_effect"):
            if await self.is_emergency():
                _mw_checks.labels(result="emergency").inc()
                return True, None, None, "emergency"

            # Iterate rules, return first active window
            when_utc = when or _now_utc()
            for rule in self.rules:
                active, start, end = rule.is_in_effect(when_utc)
                if active:
                    _mw_checks.labels(result="in_effect").inc()
                    return True, start, end, rule.id

            _mw_checks.labels(result="not_in_effect").inc()
            return False, None, None, None

    async def next_window(self, after: dt.datetime | None = None) -> tuple[dt.datetime | None, dt.datetime | None, str | None]:
        """
        Compute nearest next window among rules (ignores emergency flag because it's immediate).
        Returns: (start, end, rule_id) or (None, None, None) if none.
        """
        with _tracer.start_as_current_span("maintenance.next_window"):
            best: tuple[dt.datetime, dt.datetime, str] | None = None
            for r in self.rules:
                s, e = r.next_window(after)
                if s and e:
                    if best is None or s < best[0]:
                        best = (s, e, r.id)
            if best:
                s, e, rid = best
                # Export seconds to next start if possible
                try:
                    _mw_next_calc.labels(rule_id=rid).set(max(0.0, (s - (after or _now_utc().astimezone(s.tzinfo))).total_seconds()))
                except Exception:
                    pass
                return s, e, rid
            return None, None, None


# =========================
# Guards and context managers
# =========================

def maintenance_guard(manager: MaintenanceManager, *, allow_during: bool = False):
    """
    Decorator to block function execution during maintenance windows unless allow_during=True.
    Works with sync and async callables.

    Example:
        @maintenance_guard(manager)
        async def critical_op(...):
            ...
    """
    def decorator(func: t.Callable[..., t.Awaitable[t.Any]] | t.Callable[..., t.Any]):
        if asyncio.iscoroutinefunction(func):
            async def wrapper(*args, **kwargs):
                in_effect, start, end, rid = await manager.is_in_effect()
                if in_effect and not allow_during:
                    raise MaintenanceInEffect(
                        f"Operation is blocked by maintenance (rule={rid})", start, end, rid
                    )
                return await func(*args, **kwargs)
            return wrapper
        else:
            def wrapper(*args, **kwargs):
                # For sync functions we run a blocking check using running loop or a new loop if absent.
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    loop = None
                if loop and loop.is_running():
                    in_effect, start, end, rid = loop.run_until_complete(manager.is_in_effect())  # type: ignore
                else:
                    in_effect, start, end, rid = asyncio.run(manager.is_in_effect())
                if in_effect and not allow_during:
                    raise MaintenanceInEffect(
                        f"Operation is blocked by maintenance (rule={rid})", start, end, rid
                    )
                return func(*args, **kwargs)
            return wrapper
    return decorator

@asynccontextmanager
async def maintenance_block(manager: MaintenanceManager):
    """
    Async context manager to assert no maintenance during wrapped block.
    """
    in_effect, start, end, rid = await manager.is_in_effect()
    if in_effect:
        raise MaintenanceInEffect(
            f"Execution blocked by maintenance (rule={rid})", start, end, rid
        )
    yield


# =========================
# Example env bootstrap
# =========================

def _load_manager_from_env() -> MaintenanceManager:
    """
    Optional helper to bootstrap from env:
      CHRONO_MAINTENANCE_JSON='{"maintenance":{"emergency":false,"rules":[...]}}'
      or CHRONO_MAINTENANCE_YAML_FILE='/path/to/maintenance.yaml'
      or CHRONO_MAINTENANCE_REDIS_URL='redis://...'
    """
    backend: FlagBackend | None = None
    redis_url = os.getenv("CHRONO_MAINTENANCE_REDIS_URL")
    if redis_url:
        backend = RedisFlagBackend(redis_url)

    yaml_path = os.getenv("CHRONO_MAINTENANCE_YAML_FILE")
    json_blob = os.getenv("CHRONO_MAINTENANCE_JSON")

    if yaml_path:
        return MaintenanceManager.load_from_yaml(yaml_path, flag_backend=backend)
    if json_blob:
        data = json.loads(json_blob)
        return MaintenanceManager.from_dict(data, flag_backend=backend)
    return MaintenanceManager(rules=[], flag_backend=backend)

# Singleton-style default manager (opt-in)
DEFAULT_MANAGER = _load_manager_from_env()
