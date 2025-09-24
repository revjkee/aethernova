# chronowatch-core/chronowatch/windows/freeze.py
# Industrial-grade maintenance freeze evaluator for ChronoWatch Core.
# Python 3.11+ (zoneinfo); optional dependencies:
# - PyYAML (yaml) for YAML parsing; otherwise JSON is supported
# - python-dateutil for RFC5545 RRULE support (optional)
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

try:
    import yaml  # type: ignore
    HAS_YAML = True
except Exception:
    HAS_YAML = False

try:
    from dateutil import rrule  # type: ignore
    HAS_DATEUTIL = True
except Exception:
    HAS_DATEUTIL = False

from zoneinfo import ZoneInfo

# -----------------------------
# Logging
# -----------------------------
LOG = logging.getLogger("chronowatch.freeze")
if not LOG.handlers:
    logging.basicConfig(
        level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
    )


# -----------------------------
# Data structures
# -----------------------------
@dataclass(slots=True, frozen=True)
class Scope:
    env: Optional[str] = None
    clusters: Optional[List[str]] = None
    namespaces: Optional[List[str]] = None
    services: Optional[List[str]] = None
    labels: Optional[Dict[str, str]] = None  # k8s matchLabels-like

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Scope":
        return Scope(
            env=d.get("env"),
            clusters=list(d.get("clusters") or []) or None,
            namespaces=list(d.get("namespaces") or []) or None,
            services=list(d.get("services") or []) or None,
            labels=(d.get("selector") or {}).get("matchLabels"),
        )

    def matches(self, candidate: Dict[str, str]) -> bool:
        """
        AND между полями Scope; внутри каждого поля — OR.
        Пустое поле => не фильтрует (т.е. match all).
        """
        def _in(field_vals: Optional[List[str]], key: str) -> bool:
            if not field_vals:
                return True
            v = candidate.get(key)
            return v in field_vals

        labels_ok = True
        if self.labels:
            for k, v in self.labels.items():
                if candidate.get(k) != v:
                    labels_ok = False
                    break

        return (
            _in(self.clusters, "cluster")
            and _in(self.namespaces, "namespace")
            and _in(self.services, "service")
            and (self.env is None or candidate.get("env") == self.env)
            and labels_ok
        )


@dataclass(slots=True, frozen=True)
class WindowSpec:
    name: str
    start: dt.time        # локальное время в timezone спецификации
    end: dt.time          # локальное время
    rrule_str: Optional[str] = None
    cron: Optional[str] = None  # зарезервировано; требуется croniter (не входит)
    freeze: bool = True
    blackout: bool = False
    severity: Optional[str] = None
    scope: Scope = field(default_factory=Scope)
    drain: Optional[Dict[str, Any]] = None
    db_policy: Optional[Dict[str, Any]] = None

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "WindowSpec":
        # start/end — локальные строки "YYYY-MM-DDTHH:MM:SS" или только "HH:MM[:SS]"
        def _parse_local_time(s: str) -> dt.time:
            # допускаем "2025-09-07T22:00:00" -> берём только время
            if "T" in s:
                s = s.split("T", 1)[1]
            parts = [int(x) for x in s.split(":")]
            while len(parts) < 3:
                parts.append(0)
            return dt.time(parts[0], parts[1], parts[2])

        rec = d.get("recurrence") or {}
        return WindowSpec(
            name=str(d.get("name") or "unnamed"),
            start=_parse_local_time(str(d["start"])),
            end=_parse_local_time(str(d["end"])),
            rrule_str=rec.get("rrule"),
            cron=rec.get("cron"),
            freeze=bool(d.get("freeze", True) or d.get("blackout", False)),
            blackout=bool(d.get("blackout", False)),
            severity=d.get("severity"),
            scope=Scope.from_dict(d.get("scope") or {}),
            drain=d.get("traffic_policy", {}),
            db_policy=d.get("db_policy", {}),
        )


@dataclass(slots=True, frozen=True)
class MaintenanceConfig:
    timezone: str
    windows: Tuple[WindowSpec, ...]
    # Глобальные «freeze windows» в формате ISO-интервалов "start/end" UTC или локальные?
    global_freeze_intervals: Tuple[Tuple[dt.datetime, dt.datetime], ...] = ()
    exceptions_by_date: Tuple[Tuple[dt.date, bool], ...] = ()  # date, allow_emergency_only

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "MaintenanceConfig":
        tz = str((d.get("schedule") or {}).get("timezone") or "UTC")
        windows_raw = (d.get("schedule") or {}).get("windows") or []
        windows = tuple(WindowSpec.from_dict(x) for x in windows_raw)

        # dependencies.freeze_windows: ["2025-12-20T00:00:00Z/2026-01-05T23:59:59Z", ...]
        gf: List[Tuple[dt.datetime, dt.datetime]] = []
        for s in ((d.get("dependencies") or {}).get("freeze_windows") or []):
            try:
                start_s, end_s = s.split("/", 1)
                gf.append((_parse_iso_dt(start_s), _parse_iso_dt(end_s)))
            except Exception:
                LOG.warning("Invalid freeze_windows interval: %s", s)

        # exceptions: [{date: "2025-10-31", allow_emergency_only: true}, ...]
        exc: List[Tuple[dt.date, bool]] = []
        for e in ((d.get("dependencies") or {}).get("exceptions") or []):
            try:
                exc.append((dt.date.fromisoformat(str(e["date"])), bool(e.get("allow_emergency_only", False))))
            except Exception:
                LOG.warning("Invalid exceptions entry: %s", e)

        return MaintenanceConfig(
            timezone=tz,
            windows=windows,
            global_freeze_intervals=tuple(gf),
            exceptions_by_date=tuple(exc),
        )


@dataclass(slots=True, frozen=True)
class FreezeDecision:
    frozen: bool
    reason: str
    window_name: Optional[str] = None
    blackout: bool = False
    severity: Optional[str] = None
    interval_utc: Optional[Tuple[dt.datetime, dt.datetime]] = None  # (start, end)
    scope_matched: Optional[Dict[str, str]] = None


# -----------------------------
# Utilities
# -----------------------------
def _parse_iso_dt(s: str) -> dt.datetime:
    """Parse ISO-8601 string. If tz-naive, assume UTC."""
    try:
        x = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        # Fallback to flexible parser unavailability; raise a clearer error
        raise ValueError(f"Invalid ISO datetime: {s}")
    if x.tzinfo is None:
        x = x.replace(tzinfo=dt.UTC)
    return x.astimezone(dt.UTC)


def _localize(date_local: dt.date, t_local: dt.time, tz: ZoneInfo) -> dt.datetime:
    """Combine local date and local time to aware datetime in given tz."""
    return dt.datetime.combine(date_local, t_local, tzinfo=tz)


def _to_utc(x: dt.datetime) -> dt.datetime:
    return x.astimezone(dt.UTC)


def _daterange(start_date: dt.date, end_date: dt.date) -> Iterator[dt.date]:
    d = start_date
    while d <= end_date:
        yield d
        d += dt.timedelta(days=1)


# -----------------------------
# Core evaluator
# -----------------------------
class FreezeManager:
    """
    Главный класс, который:
    - загружает YAML/JSON
    - кэширует по mtime
    - предоставляет API is_frozen() и next_window()
    """
    def __init__(self, path: Path, cache_ttl: int = 5):
        self._path = path
        self._cache_ttl = cache_ttl
        self._cache_expire = 0.0
        self._cfg: Optional[MaintenanceConfig] = None
        self._mtime = 0.0

    @property
    def config(self) -> MaintenanceConfig:
        cfg = self._maybe_reload()
        assert cfg is not None
        return cfg

    def _maybe_reload(self) -> MaintenanceConfig:
        now = time.time()
        if self._cfg and now < self._cache_expire:
            return self._cfg
        try:
            stat = self._path.stat()
        except FileNotFoundError:
            raise FileNotFoundError(f"Config file not found: {self._path}")
        if not self._cfg or stat.st_mtime > self._mtime or now >= self._cache_expire:
            self._cfg = self._load()
            self._mtime = stat.st_mtime
            self._cache_expire = now + self._cache_ttl
            LOG.debug("Config loaded: %s", self._path)
        return self._cfg

    def _load(self) -> MaintenanceConfig:
        text = self._path.read_text(encoding="utf-8")
        data: Dict[str, Any]
        suffix = self._path.suffix.lower()
        if suffix in (".yaml", ".yml"):
            if not HAS_YAML:
                raise RuntimeError("PyYAML is required to read YAML; install `pyyaml` or provide JSON")
            data = yaml.safe_load(text) or {}
        else:
            data = json.loads(text)
        return MaintenanceConfig.from_dict(data)

    # -------- Public API --------
    def is_frozen(
        self,
        at_utc: Optional[dt.datetime] = None,
        candidate_scope: Optional[Dict[str, str]] = None,
        emergency_change: bool = False,
        search_horizon_days: int = 35,
    ) -> FreezeDecision:
        """
        Возвращает FreezeDecision для момента времени (UTC).
        Если указана область (env/cluster/namespace/service/labels...), она учитывается.
        """
        cfg = self.config
        now_utc = at_utc or dt.datetime.now(dt.UTC)
        candidate_scope = candidate_scope or {}

        # 1) Глобальные freeze_windows (UTC интервалы)
        for s, e in cfg.global_freeze_intervals:
            if s <= now_utc <= e:
                # Исключения по дате (локальная TZ)
                if self._is_exception(now_utc, emergency_change):
                    return FreezeDecision(
                        frozen=False,
                        reason="exception-date-allows-change",
                        window_name=None,
                        blackout=False,
                        severity=None,
                        interval_utc=(s, e),
                        scope_matched=candidate_scope or None,
                    )
                return FreezeDecision(
                    frozen=True,
                    reason="global-freeze-window",
                    window_name="global-freeze",
                    blackout=True,
                    severity="high",
                    interval_utc=(s, e),
                    scope_matched=candidate_scope or None,
                )

        # 2) Окна расписания (по TZ)
        tz = ZoneInfo(cfg.timezone)
        horizon_start = (now_utc - dt.timedelta(days=1)).astimezone(tz)
        horizon_end = (now_utc + dt.timedelta(days=search_horizon_days)).astimezone(tz)

        for interval in self._iter_concrete_windows(cfg, horizon_start, horizon_end):
            (w, start_utc, end_utc) = interval
            if start_utc <= now_utc <= end_utc:
                # Сопоставление области
                if not w.scope.matches(candidate_scope):
                    continue
                # Исключения по дате (локальная дата)
                if self._is_exception(now_utc, emergency_change, tz=tz):
                    return FreezeDecision(
                        frozen=False,
                        reason="exception-date-allows-change",
                        window_name=w.name,
                        blackout=w.blackout,
                        severity=w.severity,
                        interval_utc=(start_utc, end_utc),
                        scope_matched=candidate_scope or None,
                    )
                return FreezeDecision(
                    frozen=True,
                    reason="scheduled-freeze" if w.freeze else "scheduled-blackout",
                    window_name=w.name,
                    blackout=w.blackout,
                    severity=w.severity,
                    interval_utc=(start_utc, end_utc),
                    scope_matched=candidate_scope or None,
                )

        return FreezeDecision(frozen=False, reason="no-freeze", scope_matched=candidate_scope or None)

    def next_window(
        self,
        after_utc: Optional[dt.datetime] = None,
        candidate_scope: Optional[Dict[str, str]] = None,
        search_horizon_days: int = 365,
    ) -> Optional[Tuple[str, dt.datetime, dt.datetime, bool]]:
        """
        Возвращает следующую подходящую фриз-интервальную тройку:
        (name, start_utc, end_utc, blackout)
        """
        cfg = self.config
        candidate_scope = candidate_scope or {}
        now_utc = after_utc or dt.datetime.now(dt.UTC)
        tz = ZoneInfo(cfg.timezone)

        horizon_start = now_utc.astimezone(tz)
        horizon_end = (now_utc + dt.timedelta(days=search_horizon_days)).astimezone(tz)

        best: Optional[Tuple[str, dt.datetime, dt.datetime, bool]] = None

        # Глобальные интервалы
        for s, e in cfg.global_freeze_intervals:
            if e <= now_utc:
                continue
            if s > now_utc and (best is None or s < best[1]):
                best = ("global-freeze", s, e, True)

        # Расписание
        for w, s_utc, e_utc in self._iter_concrete_windows(cfg, horizon_start, horizon_end):
            if not w.scope.matches(candidate_scope):
                continue
            if e_utc <= now_utc:
                continue
            if s_utc > now_utc:
                if best is None or s_utc < best[1]:
                    best = (w.name, s_utc, e_utc, w.blackout)

        return best

    # -------- Internals --------
    def _iter_concrete_windows(
        self,
        cfg: MaintenanceConfig,
        horizon_start_local: dt.datetime,
        horizon_end_local: dt.datetime,
    ) -> Iterator[Tuple[WindowSpec, dt.datetime, dt.datetime]]:
        """
        Разворачивает окна расписания в конкретные интервалы UTC в заданном горизонте.
        """
        tz = ZoneInfo(cfg.timezone)
        for w in cfg.windows:
            # Длительность локального окна
            # Если end < start по времени суток — это «через полночь».
            base_start = _localize(horizon_start_local.date(), w.start, tz)
            base_end = _localize(horizon_start_local.date(), w.end, tz)
            if base_end <= _localize(horizon_start_local.date(), w.start, tz):
                # через полночь
                # длительность = (время_конца завтра) - (время_старта сегодня)
                end_calc = _localize(horizon_start_local.date() + dt.timedelta(days=1), w.end, tz)
                duration = end_calc - _localize(horizon_start_local.date(), w.start, tz)
            else:
                duration = base_end - base_start

            if w.rrule_str:
                if not HAS_DATEUTIL:
                    raise RuntimeError("RRULE specified but python-dateutil is not installed")
                # dtstart возьмём как horizon_start.date() со временем w.start
                dtstart = _localize(horizon_start_local.date(), w.start, tz)
                # Ensure RRULE has DTSTART; если нет — зададим вручную через rrule.rrulestr
                rule = rrule.rrulestr(w.rrule_str, dtstart=dtstart)
                # Перечислим наступления в горизонте
                # dateutil >=2.8 поддерживает between; inc=True включает границы
                for occ in rule.between(horizon_start_local, horizon_end_local, inc=True):
                    occ_end = occ + duration
                    yield (w, _to_utc(occ), _to_utc(occ_end))
                continue

            # Без recurrence — конкретные календарные дни в горизонте
            for day in _daterange(horizon_start_local.date(), horizon_end_local.date()):
                start_local = _localize(day, w.start, tz)
                end_local = start_local + duration
                # отбросим интервалы полностью вне горизонта
                if end_local < horizon_start_local or start_local > horizon_end_local:
                    continue
                yield (w, _to_utc(start_local), _to_utc(end_local))

    def _is_exception(self, at_utc: dt.datetime, emergency: bool, tz: Optional[ZoneInfo] = None) -> bool:
        if not self.config.exceptions_by_date:
            return False
        tz = tz or ZoneInfo(self.config.timezone)
        local_date = at_utc.astimezone(tz).date()
        for d, allow_emergency_only in self.config.exceptions_by_date:
            if d == local_date:
                if allow_emergency_only:
                    return emergency
                return True
        return False


# -----------------------------
# CLI
# -----------------------------
def _parse_kv_list(items: Iterable[str]) -> Dict[str, str]:
    res: Dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise argparse.ArgumentTypeError(f"Invalid scope item: {item}, expected key=value")
        k, v = item.split("=", 1)
        res[k.strip()] = v.strip()
    return res


def cli(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="chronowatch-freeze",
        description="ChronoWatch maintenance freeze evaluator",
    )
    parser.add_argument("--file", "-f", required=False, default=os.getenv("CHRONO_MAINT_FILE", ""),
                        help="Path to maintenance_window.yaml (or JSON).")
    parser.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "INFO"))
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_check = sub.add_parser("check", help="Return whether we are in a freeze window.")
    p_check.add_argument("--at", help="ISO datetime; default now UTC.")
    p_check.add_argument("--scope", "-s", action="append", default=[],
                         help="Scope key=value; e.g. env=prod cluster=prod-eu1 service=api")
    p_check.add_argument("--emergency", action="store_true", help="Treat as emergency change.")
    p_check.add_argument("--exit-on-freeze", action="store_true",
                         help="Exit with code 2 if frozen, else 0.")

    p_next = sub.add_parser("next", help="Show next freeze window after time.")
    p_next.add_argument("--after", help="ISO datetime; default now UTC.")
    p_next.add_argument("--scope", "-s", action="append", default=[],
                        help="Scope key=value")

    args = parser.parse_args(argv)

    LOG.setLevel(getattr(logging, args.log_level.upper(), logging.INFO))

    cfg_file = args.file or os.getenv("CHRONOWATCH_MAINTENANCE_FILE")
    if not cfg_file:
        print("Missing --file or CHRONOWATCH_MAINTENANCE_FILE", file=sys.stderr)
        return 64
    manager = FreezeManager(Path(cfg_file))

    if args.cmd == "check":
        at = _parse_iso_dt(args.at) if args.at else dt.datetime.now(dt.UTC)
        scope = _parse_kv_list(args.scope)
        decision = manager.is_frozen(at_utc=at, candidate_scope=scope, emergency_change=args.emergency)
        out = {
            "frozen": decision.frozen,
            "reason": decision.reason,
            "window_name": decision.window_name,
            "blackout": decision.blackout,
            "severity": decision.severity,
            "interval_utc": [
                decision.interval_utc[0].isoformat() if decision.interval_utc else None,
                decision.interval_utc[1].isoformat() if decision.interval_utc else None,
            ] if decision.interval_utc else None,
            "scope": decision.scope_matched,
        }
        print(json.dumps(out, ensure_ascii=False))
        if args.exit_on_freeze and decision.frozen:
            return 2
        return 0

    if args.cmd == "next":
        after = _parse_iso_dt(args.after) if args.after else dt.datetime.now(dt.UTC)
        scope = _parse_kv_list(args.scope)
        nxt = manager.next_window(after_utc=after, candidate_scope=scope)
        if not nxt:
            print(json.dumps({"next": None}, ensure_ascii=False))
            return 0
        name, s, e, blackout = nxt
        print(json.dumps(
            {"next": {"name": name, "start_utc": s.isoformat(), "end_utc": e.isoformat(), "blackout": blackout}},
            ensure_ascii=False)
        )
        return 0

    return 0


# -----------------------------
# Public helpers (library API)
# -----------------------------
def load_manager(path: str | Path) -> FreezeManager:
    return FreezeManager(Path(path))


__all__ = [
    "FreezeManager",
    "MaintenanceConfig",
    "WindowSpec",
    "Scope",
    "FreezeDecision",
    "load_manager",
    "cli",
]


if __name__ == "__main__":
    sys.exit(cli())
