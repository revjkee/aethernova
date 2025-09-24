# chronowatch-core/chronowatch/calendars/holiday_loader.py
from __future__ import annotations

"""
Industrial holiday calendar loader for ChronoWatch.

Features:
- Pluggable providers (python-holidays, workalendar, JSON/YAML, ICS).
- Graceful degradation if optional deps are missing.
- Thread-safe in-memory caching with TTL.
- Timezone-aware normalization (ZoneInfo).
- Business-day rules: custom weekends, manual overrides.
- Deterministic fingerprint (SHA-256) over merged calendar.
- Convenience API: is_holiday, is_business_day, next_business_day, range.
- Minimal ICS fallback parser (VEVENT DTSTART/SUMMARY, no RRULE).
"""

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Iterable, Optional, Protocol, Sequence, Dict, List, Tuple, Any
from zoneinfo import ZoneInfo
import hashlib
import json
import logging
import os
import threading
import time

# Optional imports (graceful if absent)
try:
    import holidays as py_holidays  # type: ignore
except Exception:  # pragma: no cover
    py_holidays = None  # I cannot verify this.

try:
    # Workalendar family
    from workalendar.registry import registry as workalendar_registry  # type: ignore
except Exception:  # pragma: no cover
    workalendar_registry = None  # I cannot verify this.

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # I cannot verify this.

# ------------------------------------------------------------------------------
# Public data types
# ------------------------------------------------------------------------------

@dataclass(frozen=True)
class Holiday:
    day: date
    name: str
    source: str = "unknown"

    def as_dict(self) -> Dict[str, Any]:
        return {"date": self.day.isoformat(), "name": self.name, "source": self.source}


@dataclass
class HolidayCalendar:
    country: Optional[str]
    region: Optional[str]
    tz: str
    holidays: List[Holiday] = field(default_factory=list)
    weekend: Tuple[int, ...] = (5, 6)  # Saturday/Sunday by Python weekday() (Mon=0)
    extra_working_days: set[date] = field(default_factory=set)
    extra_holidays: set[date] = field(default_factory=set)

    def to_set(self) -> set[date]:
        base = {h.day for h in self.holidays}
        base |= self.extra_holidays
        base -= self.extra_working_days
        return base

    def fingerprint(self) -> str:
        payload = {
            "country": self.country,
            "region": self.region,
            "tz": self.tz,
            "weekend": list(self.weekend),
            "extra_working_days": sorted([d.isoformat() for d in self.extra_working_days]),
            "extra_holidays": sorted([d.isoformat() for d in self.extra_holidays]),
            "holidays": sorted([h.as_dict() for h in self.holidays], key=lambda x: (x["date"], x["name"], x["source"])),
        }
        ser = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(ser).hexdigest()


# ------------------------------------------------------------------------------
# Provider interface
# ------------------------------------------------------------------------------

class HolidayProvider(Protocol):
    name: str

    def load(
        self,
        years: Iterable[int],
        country: Optional[str],
        region: Optional[str],
        tz: str,
    ) -> List[Holiday]:
        ...


# ------------------------------------------------------------------------------
# Providers
# ------------------------------------------------------------------------------

class HolidaysLibProvider:
    """Adapter for python-holidays (https://pypi.org/project/holidays/)"""

    name = "python-holidays"

    def load(self, years: Iterable[int], country: Optional[str], region: Optional[str], tz: str) -> List[Holiday]:
        if py_holidays is None:
            logging.debug("HolidaysLibProvider unavailable: python-holidays not installed")
            return []
        if not country:
            return []
        try:
            # Many countries are by ISO 3166 alpha-2; region is subdiv code
            hol = py_holidays.CountryHoliday(country=country, subdiv=region, years=list(years))  # type: ignore
        except Exception as e:  # pragma: no cover
            logging.warning("HolidaysLibProvider failed for country=%s region=%s: %s", country, region, e)
            return []
        out: List[Holiday] = []
        for d, name in hol.items():
            if isinstance(d, datetime):
                d = d.date()
            out.append(Holiday(day=d, name=str(name), source=self.name))
        return out


class WorkalendarProvider:
    """Adapter for workalendar (https://workalendar.github.io/)."""

    name = "workalendar"

    def load(self, years: Iterable[int], country: Optional[str], region: Optional[str], tz: str) -> List[Holiday]:
        if workalendar_registry is None:
            logging.debug("WorkalendarProvider unavailable: workalendar not installed")
            return []
        if not country:
            return []
        key = country
        if region:
            key = f"{country}.{region}"
        # Resolve calendar class
        cal_cls = None
        try:
            # Workalendar keys vary; attempt best-effort lookup
            if key in workalendar_registry.region_registry:
                cal_cls = workalendar_registry.region_registry[key]
            elif country in workalendar_registry.region_registry:
                cal_cls = workalendar_registry.region_registry[country]
            else:
                cal_cls = workalendar_registry.get(country)  # type: ignore
        except Exception:  # pragma: no cover
            cal_cls = None
        if cal_cls is None:
            logging.debug("WorkalendarProvider: no calendar for key=%s", key)
            return []
        try:
            cal = cal_cls()
            out: List[Holiday] = []
            for y in years:
                for d, name in cal.holidays(y):  # type: ignore
                    out.append(Holiday(day=d, name=str(name), source=self.name))
            return out
        except Exception as e:  # pragma: no cover
            logging.warning("WorkalendarProvider failed for key=%s: %s", key, e)
            return []


class FileProvider:
    """
    Loads holidays from JSON or YAML file. Schema:
      {
        "holidays": [
          {"date": "YYYY-MM-DD", "name": "New Year"},
          ...
        ]
      }
    """

    name = "file"

    def __init__(self, path: str) -> None:
        self.path = path

    def load(self, years: Iterable[int], country: Optional[str], region: Optional[str], tz: str) -> List[Holiday]:
        if not os.path.isfile(self.path):
            logging.debug("FileProvider: file not found: %s", self.path)
            return []
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                text = f.read()
            data = None
            if self.path.lower().endswith((".yaml", ".yml")) and yaml is not None:
                data = yaml.safe_load(text)  # I cannot verify this.
            else:
                data = json.loads(text)
        except Exception as e:  # pragma: no cover
            logging.warning("FileProvider: failed to read %s: %s", self.path, e)
            return []
        items = (data or {}).get("holidays", [])
        ys = set(int(y) for y in years)
        out: List[Holiday] = []
        for it in items:
            try:
                d = date.fromisoformat(str(it["date"]))
                if d.year in ys:
                    out.append(Holiday(day=d, name=str(it.get("name", "Holiday")), source=self.name))
            except Exception:  # pragma: no cover
                continue
        return out


class ICSProvider:
    """
    Loads all-day holidays from an .ics file (VEVENT DTSTART, SUMMARY).
    Uses a minimal parser when 'icalendar' is not available. RRULE is ignored in minimal mode.
    """

    name = "ics"

    def __init__(self, path: str) -> None:
        self.path = path

    def load(self, years: Iterable[int], country: Optional[str], region: Optional[str], tz: str) -> List[Holiday]:
        if not os.path.isfile(self.path):
            logging.debug("ICSProvider: file not found: %s", self.path)
            return []
        ys = set(int(y) for y in years)
        try:
            # Try icalendar first
            try:
                import icalendar  # type: ignore
            except Exception:
                icalendar = None  # type: ignore

            if icalendar is not None:  # pragma: no cover (depends on env)
                cal = icalendar.Calendar.from_ical(open(self.path, "rb").read())
                out: List[Holiday] = []
                for comp in cal.walk("VEVENT"):
                    dtstart = comp.get("DTSTART")
                    summary = str(comp.get("SUMMARY", "Holiday"))
                    if not dtstart:
                        continue
                    v = dtstart.dt
                    if isinstance(v, datetime):
                        v = v.date()
                    if v.year in ys:
                        out.append(Holiday(day=v, name=summary, source=self.name))
                return out

            # Minimal fallback parser
            out: List[Holiday] = []
            with open(self.path, "r", encoding="utf-8", errors="ignore") as f:
                vevent = False
                dt: Optional[date] = None
                summary: Optional[str] = None
                for raw in f:
                    line = raw.strip()
                    if line == "BEGIN:VEVENT":
                        vevent = True
                        dt, summary = None, None
                        continue
                    if line == "END:VEVENT":
                        if vevent and dt and summary and dt.year in ys:
                            out.append(Holiday(day=dt, name=summary, source=self.name))
                        vevent = False
                        dt, summary = None, None
                        continue
                    if not vevent:
                        continue
                    if line.startswith("DTSTART"):
                        # DTSTART;VALUE=DATE:YYYYMMDD or DTSTART:YYYYMMDD
                        try:
                            _, val = line.split(":", 1)
                            if len(val) >= 8:
                                y, m, d = int(val[0:4]), int(val[4:6]), int(val[6:8])
                                dt = date(y, m, d)
                        except Exception:  # pragma: no cover
                            pass
                    elif line.startswith("SUMMARY"):
                        try:
                            _, val = line.split(":", 1)
                            summary = val.strip()
                        except Exception:  # pragma: no cover
                            pass
            if out and any(True for _ in out):
                logging.debug("ICSProvider: loaded %d entries (minimal mode, no RRULE)", len(out))
            return out
        except Exception as e:  # pragma: no cover
            logging.warning("ICSProvider: failed to parse %s: %s", self.path, e)
            return []


# ------------------------------------------------------------------------------
# Aggregation / Loader
# ------------------------------------------------------------------------------

@dataclass
class LoaderConfig:
    tz: str = "UTC"
    weekend: Tuple[int, ...] = (5, 6)
    providers: Tuple[HolidayProvider, ...] = field(default_factory=tuple)
    extra_working_days: Sequence[date] = field(default_factory=tuple)
    extra_holidays: Sequence[date] = field(default_factory=tuple)
    ttl_seconds: int = 3600  # cache TTL


class HolidayLoader:
    """
    Aggregate loader with caching and business-day helpers.
    Thread-safe for concurrent reads.
    """

    def __init__(self, config: LoaderConfig) -> None:
        self._tz = config.tz
        self._weekend = tuple(sorted(set(config.weekend)))
        self._providers = list(config.providers)
        self._extra_working_days = set(config.extra_working_days)
        self._extra_holidays = set(config.extra_holidays)
        self._ttl = max(0, int(config.ttl_seconds))
        self._cache: Dict[str, Tuple[float, HolidayCalendar]] = {}
        self._lock = threading.RLock()

    # ------------- public API -------------

    def load_calendar(
        self,
        years: Iterable[int],
        country: Optional[str] = None,
        region: Optional[str] = None,
    ) -> HolidayCalendar:
        """
        Load and merge calendars from configured providers with caching.
        """
        years_key = ",".join(str(int(y)) for y in sorted(set(years)))
        key = self._cache_key(years_key, country, region)
        now = time.time()
        with self._lock:
            if key in self._cache and (self._ttl == 0 or now - self._cache[key][0] < self._ttl):
                return self._cache[key][1]

        tz = self._tz
        merged = self._merge(years=sorted(set(int(y) for y in years)), country=country, region=region, tz=tz)
        cal = HolidayCalendar(
            country=country,
            region=region,
            tz=tz,
            holidays=merged,
            weekend=self._weekend,
            extra_working_days=set(self._extra_working_days),
            extra_holidays=set(self._extra_holidays),
        )
        with self._lock:
            self._cache[key] = (now, cal)
        return cal

    def is_holiday(self, day: date, years_hint: Optional[Iterable[int]] = None, country: Optional[str] = None, region: Optional[str] = None) -> bool:
        cal = self._calendar_for_date(day, years_hint, country, region)
        return day in cal.to_set()

    def is_business_day(self, day: date, years_hint: Optional[Iterable[int]] = None, country: Optional[str] = None, region: Optional[str] = None) -> bool:
        cal = self._calendar_for_date(day, years_hint, country, region)
        if day in cal.to_set():
            return False
        if day.weekday() in cal.weekend:
            # Weekend can be overridden by explicit extra working day
            return day in cal.extra_working_days
        return True

    def next_business_day(
        self,
        day: date,
        direction: int = 1,
        years_hint: Optional[Iterable[int]] = None,
        country: Optional[str] = None,
        region: Optional[str] = None,
        max_days: int = 365,
    ) -> date:
        """
        Find the next business day in 'direction' (1 forward, -1 backward).
        """
        if direction == 0:
            direction = 1
        step = timedelta(days=1 if direction > 0 else -1)
        current = day
        for _ in range(max_days):
            current = current + step
            if self.is_business_day(current, years_hint=years_hint, country=country, region=region):
                return current
        raise RuntimeError("Exceeded max_days during search for next business day")

    def range(
        self,
        start: date,
        end: date,
        include_start: bool = True,
        include_end: bool = True,
        years_hint: Optional[Iterable[int]] = None,
        country: Optional[str] = None,
        region: Optional[str] = None,
        business_days_only: bool = False,
    ) -> List[date]:
        """
        Enumerate dates in [start, end] with optional business-day filter.
        """
        if end < start:
            start, end = end, start
        days = (end - start).days
        out: List[date] = []
        for i in range(days + 1):
            d = start + timedelta(days=i)
            if (i == 0 and not include_start) or (i == days and not include_end):
                continue
            if business_days_only:
                if self.is_business_day(d, years_hint=years_hint, country=country, region=region):
                    out.append(d)
            else:
                out.append(d)
        return out

    def clear_cache(self) -> None:
        with self._lock:
            self._cache.clear()

    # ------------- internals -------------

    def _calendar_for_date(
        self, day: date, years_hint: Optional[Iterable[int]], country: Optional[str], region: Optional[str]
    ) -> HolidayCalendar:
        years = years_hint if years_hint else {day.year - 1, day.year, day.year + 1}
        return self.load_calendar(years=years, country=country, region=region)

    def _merge(
        self, years: Iterable[int], country: Optional[str], region: Optional[str], tz: str
    ) -> List[Holiday]:
        collected: List[Holiday] = []
        for p in self._providers:
            try:
                items = p.load(years=years, country=country, region=region, tz=tz)
                if items:
                    collected.extend(items)
            except Exception as e:  # pragma: no cover
                logging.warning("Provider %s failed: %s", getattr(p, "name", str(p)), e)

        # Normalize TZ (if ever we had datetimes — store as date only) and deduplicate
        by_key: Dict[Tuple[date, str], Holiday] = {}
        for h in collected:
            d = h.day
            if isinstance(d, datetime):
                if d.tzinfo is None:
                    d = d.replace(tzinfo=timezone.utc)
                d = d.astimezone(ZoneInfo(tz)).date()
            key = (d, h.name.strip())
            # Keep the first occurrence by provider priority
            by_key.setdefault(key, Holiday(day=d, name=h.name.strip(), source=h.source))

        # Also dedup by date irrespective of name: if multiple names on same day, keep the first (highest priority)
        by_day: Dict[date, Holiday] = {}
        for (d, _), hol in by_key.items():
            if d not in by_day:
                by_day[d] = hol

        return sorted(by_day.values(), key=lambda x: x.day)

    def _cache_key(self, years_key: str, country: Optional[str], region: Optional[str]) -> str:
        base = f"{years_key}|{country or '-'}|{region or '-'}|{self._tz}|{','.join(map(str, self._weekend))}"
        if self._extra_holidays or self._extra_working_days:
            ex = "|".join(sorted([d.isoformat() for d in self._extra_holidays]))
            ew = "|".join(sorted([d.isoformat() for d in self._extra_working_days]))
            base += f"|EH:{ex}|EW:{ew}"
        return hashlib.sha256(base.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------------------
# Factory helpers
# ------------------------------------------------------------------------------

def default_loader(
    tz: str = "UTC",
    weekend: Tuple[int, ...] = (5, 6),
    providers: Optional[Sequence[HolidayProvider]] = None,
    file_paths: Optional[Sequence[str]] = None,
    ics_paths: Optional[Sequence[str]] = None,
    ttl_seconds: int = 3600,
    extra_working_days: Optional[Sequence[date]] = None,
    extra_holidays: Optional[Sequence[date]] = None,
) -> HolidayLoader:
    """
    Build a sensible default loader:
     1) python-holidays (if installed),
     2) workalendar (if installed),
     3) file providers (JSON/YAML),
     4) ICS providers.
    Custom 'providers' overrides the entire list.
    """
    provs: List[HolidayProvider] = []
    if providers is not None:
        provs = list(providers)
    else:
        provs.append(HolidaysLibProvider())
        provs.append(WorkalendarProvider())
        for p in file_paths or []:
            provs.append(FileProvider(p))
        for p in ics_paths or []:
            provs.append(ICSProvider(p))

    cfg = LoaderConfig(
        tz=tz,
        weekend=tuple(sorted(set(weekend))),
        providers=tuple(provs),
        ttl_seconds=ttl_seconds,
        extra_working_days=tuple(extra_working_days or ()),
        extra_holidays=tuple(extra_holidays or ()),
    )
    return HolidayLoader(cfg)


# ------------------------------------------------------------------------------
# Example (docstring only; do not execute on import)
# ------------------------------------------------------------------------------
"""
Example usage:

from datetime import date
from chronowatch.calendars.holiday_loader import default_loader, FileProvider

loader = default_loader(
    tz="Europe/Stockholm",
    file_paths=["/etc/calendars/se_public_holidays.json"],
)

cal = loader.load_calendar(years=[2025], country="SE")
assert loader.is_holiday(date(2025, 1, 1), country="SE")
d = loader.next_business_day(date(2025, 1, 1), direction=1, country="SE")
print(cal.fingerprint())
"""
