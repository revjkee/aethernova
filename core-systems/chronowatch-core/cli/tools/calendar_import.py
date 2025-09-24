# path: chronowatch-core/cli/tools/calendar_import.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ChronoWatch — Calendar Import Tool
Industrial-grade ICS/URL importer with recurrence expansion, exceptions handling,
ETag/Last-Modified caching, deterministic IDs, deduplication, and optional API batching.

Dependencies (install in your environment):
  - icalendar>=5.0
  - python-dateutil>=2.8
  - httpx>=0.27

Python: 3.10+

Usage examples:
  # Import single .ics to JSONL (stdout)
  python calendar_import.py --ics ./cal.ics --dry-run

  # Import by URL with caching to local file and send to backend
  python calendar_import.py --url https://example.com/calendar.ics \
      --api-url https://api.example.com/v1/chronowatch/events/import \
      --api-token $CHRONO_API_TOKEN

  # Import directory of .ics, expand 1y back and 2y forward, text logs
  python calendar_import.py --dir ./calendars --window-back 365 --window-forward 730 --log-format text
"""
from __future__ import annotations

import argparse
import asyncio
import dataclasses
import hashlib
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, date
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union
from urllib.parse import urlparse

# Third-party deps
try:
    import httpx
except Exception as e:  # pragma: no cover
    raise SystemExit("Missing dependency 'httpx'. Install with: pip install httpx") from e

try:
    from icalendar import Calendar, Event, vText, vDDDTypes
except Exception as e:  # pragma: no cover
    raise SystemExit("Missing dependency 'icalendar'. Install with: pip install icalendar") from e

try:
    from dateutil.rrule import rruleset, rrulestr
    from dateutil.tz import gettz
except Exception as e:  # pragma: no cover
    raise SystemExit("Missing dependency 'python-dateutil'. Install with: pip install python-dateutil") from e

# TZ handling: prefer stdlib zoneinfo if available
try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore

ISO_FMT = "%Y-%m-%dT%H:%M:%S%z"
CACHE_DEFAULT = ".calendar_import_cache.json"

# ---------------------------- Logging --------------------------------------- #

def configure_logging(level: str = "INFO", fmt: str = "json") -> None:
    log = logging.getLogger()
    log.setLevel(getattr(logging, level.upper(), logging.INFO))
    handler = logging.StreamHandler(sys.stdout)
    if fmt == "json":
        handler.setFormatter(JsonLogFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.handlers.clear()
    log.addHandler(handler)


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": int(time.time()),
            "level": record.levelname.lower(),
            "msg": record.getMessage(),
            "logger": record.name,
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        # Attach extra fields if present
        for key, val in record.__dict__.items():
            if key not in ("args", "msg", "levelname", "levelno", "pathname", "filename",
                           "module", "exc_info", "exc_text", "stack_info", "lineno",
                           "funcName", "created", "msecs", "relativeCreated", "thread",
                           "threadName", "processName", "process"):
                payload[key] = val
        return json.dumps(payload, ensure_ascii=False)


logger = logging.getLogger("chronowatch.calendar_import")

# ---------------------------- Models --------------------------------------- #

@dataclass(frozen=True)
class EventRecord:
    event_id: str
    uid: str
    title: str
    description: str
    location: str
    start: str          # ISO 8601 with tz
    end: str            # ISO 8601 with tz
    allday: bool
    status: str
    organizer: Optional[str]
    attendees: List[str]
    categories: List[str]
    source: str         # file path or URL
    last_modified: Optional[str]
    created: Optional[str]
    recurrence_id: Optional[str] = None
    sequence: Optional[int] = None
    tz: Optional[str] = None
    raw_hash: Optional[str] = None


# ------------------------- Cache for URLs ---------------------------------- #

class UrlCache:
    def __init__(self, path: Union[str, Path]):
        self.path = Path(path)
        self.data: Dict[str, Dict[str, Any]] = {}
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                self.data = {}

    def get_headers(self, url: str) -> Dict[str, str]:
        entry = self.data.get(url, {})
        headers: Dict[str, str] = {}
        if etag := entry.get("etag"):
            headers["If-None-Match"] = etag
        if lm := entry.get("last_modified"):
            headers["If-Modified-Since"] = lm
        return headers

    def update(self, url: str, etag: Optional[str], last_modified: Optional[str]) -> None:
        self.data[url] = {"etag": etag, "last_modified": last_modified}
        try:
            self.path.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as e:
            logger.warning("cache_write_failed", error=str(e), cache=str(self.path))


# ------------------------- Utilities --------------------------------------- #

def normalize_email(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    v = value.strip()
    v = re.sub(r"^mailto:\s*", "", v, flags=re.IGNORECASE)
    return v or None


def isoformat_dt(dt: datetime) -> str:
    # Normalize to aware datetime
    if dt.tzinfo is None:
        # Default to UTC if timezone-less
        return dt.replace(tzinfo=gettz("UTC")).strftime(ISO_FMT)
    return dt.strftime(ISO_FMT)


def to_zoneinfo(tzid: Optional[str]):
    if not tzid:
        return None
    if ZoneInfo:
        try:
            return ZoneInfo(tzid)
        except Exception:
            pass
    return gettz(tzid)


def ensure_aware(dtval: Union[datetime, date], fallback_tz: Optional[str]) -> Tuple[datetime, bool]:
    """Return (aware_datetime, is_allday)."""
    if isinstance(dtval, date) and not isinstance(dtval, datetime):
        # All-day date (no time), set midnight in TZ (or UTC)
        tz = to_zoneinfo(fallback_tz) or gettz("UTC")
        return datetime(dtval.year, dtval.month, dtval.day, 0, 0, 0, tzinfo=tz), True
    dt = dtval if isinstance(dtval, datetime) else datetime.combine(dtval, datetime.min.time())
    if dt.tzinfo is None:
        tz = to_zoneinfo(fallback_tz) or gettz("UTC")
        dt = dt.replace(tzinfo=tz)
    return dt, False


def sha256_hexdigest(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def make_event_id(uid: str, start: datetime, end: datetime, title: str, recurrence_id: Optional[datetime]) -> str:
    # Deterministic ID that changes on reschedule/rename
    rid = recurrence_id.strftime(ISO_FMT) if recurrence_id else ""
    basis = f"{uid}|{start.strftime(ISO_FMT)}|{end.strftime(ISO_FMT)}|{title.strip()}|{rid}"
    return sha256_hexdigest(basis)


def raw_component_hash(component: Event) -> str:
    # Stable-ish hash for change detection
    # Use selected fields to avoid drift from insignificant ordering differences.
    fields = []
    for key in ("UID", "SUMMARY", "DESCRIPTION", "LOCATION", "DTSTART", "DTEND", "DURATION",
                "RRULE", "RDATE", "EXDATE", "RECURRENCE-ID", "SEQUENCE", "STATUS", "LAST-MODIFIED"):
        if key in component:
            fields.append(f"{key}={component.get(key).to_ical()!r}")
    return sha256_hexdigest("|".join(fields))


def as_text(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, vText):
        return str(val)
    return str(val)


def collect_attendees(component: Event) -> List[str]:
    vals = component.getall("attendee", [])
    result: List[str] = []
    for v in vals:
        email = normalize_email(str(v))
        if email:
            result.append(email)
    return sorted(set(result))


def collect_categories(component: Event) -> List[str]:
    cats = component.get("categories")
    if not cats:
        return []
    if isinstance(cats, list):
        return sorted({str(c) for c in cats})
    # icalendar may return vText or list-like
    try:
        return sorted({str(x) for x in cats.cats})
    except Exception:
        return [str(cats)]


# ------------------------- ICS Parsing & Expansion -------------------------- #

@dataclass
class MasterEvent:
    uid: str
    component: Event
    tzid: Optional[str]
    dtstart: datetime
    dtend: Optional[datetime]
    duration: Optional[timedelta]
    allday: bool
    raw_hash: str


@dataclass
class OverrideEvent:
    uid: str
    recurrence_id: datetime
    component: Event
    cancelled: bool
    raw_hash: str


def parse_ics_calendar(content: bytes, source_label: str, default_tz: Optional[str]) -> Tuple[List[MasterEvent], List[OverrideEvent]]:
    cal = Calendar.from_ical(content)
    masters: List[MasterEvent] = []
    overrides: List[OverrideEvent] = []

    for component in cal.walk():
        if component.name != "VEVENT":
            continue

        uid = as_text(component.get("uid")).strip()
        if not uid:
            logger.warning("skip_without_uid", source=source_label)
            continue

        # DTSTART
        dtstart_prop = component.get("dtstart")
        if not dtstart_prop:
            logger.warning("skip_without_dtstart", uid=uid, source=source_label)
            continue
        dtstart_val = dtstart_prop.dt  # type: ignore[attr-defined]
        tzid = None
        try:
            tzid = dtstart_prop.params.get("TZID")  # type: ignore[attr-defined]
        except Exception:
            pass
        dtstart, allday = ensure_aware(dtstart_val, tzid or default_tz)

        # DTEND or DURATION
        dtend_prop = component.get("dtend")
        duration_prop = component.get("duration")
        dtend: Optional[datetime] = None
        duration: Optional[timedelta] = None

        if dtend_prop:
            dtend_val = dtend_prop.dt  # type: ignore[attr-defined]
            tzid_end = None
            try:
                tzid_end = dtend_prop.params.get("TZID")  # type: ignore[attr-defined]
            except Exception:
                pass
            dtend, _ = ensure_aware(dtend_val, tzid_end or tzid or default_tz)
        elif duration_prop:
            try:
                duration = duration_prop.dt  # type: ignore[attr-defined]
            except Exception:
                # last resort: parse ISO 8601 duration string if present
                duration = None

        raw_hash = raw_component_hash(component)

        # RECURRENCE-ID indicates an override instance, not a master
        rec_id_prop = component.get("recurrence-id")
        if rec_id_prop:
            rec_dt, _ = ensure_aware(rec_id_prop.dt, tzid or default_tz)  # type: ignore[attr-defined]
            status = as_text(component.get("status")).upper()
            cancelled = status == "CANCELLED"
            overrides.append(OverrideEvent(
                uid=uid,
                recurrence_id=rec_dt,
                component=component,
                cancelled=cancelled,
                raw_hash=raw_hash,
            ))
            continue

        masters.append(MasterEvent(
            uid=uid,
            component=component,
            tzid=tzid,
            dtstart=dtstart,
            dtend=dtend,
            duration=duration,
            allday=allday,
            raw_hash=raw_hash,
        ))

    return masters, overrides


def build_rruleset(master: MasterEvent) -> Optional[rruleset]:
    rs = rruleset()
    comp = master.component

    # DTSTART base
    dtstart = master.dtstart

    # RRULE
    rrule = comp.get("rrule")
    if rrule:
        # icalendar returns dict-like; serialize to RFC string
        try:
            # Convert RRULE dict to a semicolon-joined string (e.g., FREQ=...;BYDAY=...)
            parts = []
            for k, v in rrule.items():
                if isinstance(v, list):
                    vstr = ",".join(map(str, v))
                else:
                    vstr = str(v)
                parts.append(f"{k}={vstr}")
            rrule_str = ";".join(parts)
            rs.rrule(rrulestr(rrule_str, dtstart=dtstart))
        except Exception as e:
            logger.warning("rrule_parse_failed", uid=master.uid, error=str(e))

    # RDATE
    for rdate_prop in comp.getall("rdate", []):
        try:
            # rdate can contain one or multiple dates/datetimes
            vals = rdate_prop.dts  # type: ignore[attr-defined]
            for v in vals:
                occ_dt, _ = ensure_aware(v.dt, master.tzid)  # type: ignore[attr-defined]
                rs.rdate(occ_dt)
        except Exception as e:
            logger.warning("rdate_parse_failed", uid=master.uid, error=str(e))

    # EXDATE
    for exdate_prop in comp.getall("exdate", []):
        try:
            vals = exdate_prop.dts  # type: ignore[attr-defined]
            for v in vals:
                ex_dt, _ = ensure_aware(v.dt, master.tzid)  # type: ignore[attr-defined]
                rs.exdate(ex_dt)
        except Exception as e:
            logger.warning("exdate_parse_failed", uid=master.uid, error=str(e))

    # If neither RRULE nor RDATE present, no recurrence set needed
    if not comp.get("rrule") and not comp.get("rdate"):
        return None
    return rs


def expand_master(master: MasterEvent,
                  overrides_idx: Dict[Tuple[str, str], OverrideEvent],
                  window_start: datetime,
                  window_end: datetime,
                  source_label: str,
                  default_tz: Optional[str]) -> Iterable[EventRecord]:
    comp = master.component

    # Base fields
    title = as_text(comp.get("summary")).strip()
    description = as_text(comp.get("description"))
    location = as_text(comp.get("location"))
    status = as_text(comp.get("status")).upper() or "CONFIRMED"
    organizer = normalize_email(as_text(comp.get("organizer")))
    attendees = collect_attendees(comp)
    categories = collect_categories(comp)
    sequence = None
    try:
        sequence = int(as_text(comp.get("sequence"))) if comp.get("sequence") else None
    except Exception:
        sequence = None

    created = comp.get("created")
    created_iso = isoformat_dt(created.dt) if created else None  # type: ignore[attr-defined]
    lm = comp.get("last-modified") or comp.get("dtstamp")
    last_modified_iso = isoformat_dt(lm.dt) if lm else None  # type: ignore[attr-defined]

    # Determine duration or dtend
    base_start = master.dtstart
    base_end: Optional[datetime] = master.dtend
    duration: Optional[timedelta] = master.duration
    if not base_end and not duration:
        # Default 1 hour for events without end/duration (common in some feeds)
        base_end = base_start + timedelta(hours=1)

    rs = build_rruleset(master)
    if rs is None:
        # Non-recurring
        start = base_start
        end = base_end if base_end else (base_start + (duration or timedelta(hours=1)))
        eid = make_event_id(master.uid, start, end, title, None)
        yield EventRecord(
            event_id=eid,
            uid=master.uid,
            title=title or "(No title)",
            description=description,
            location=location,
            start=isoformat_dt(start),
            end=isoformat_dt(end),
            allday=master.allday,
            status=status,
            organizer=organizer,
            attendees=attendees,
            categories=categories,
            source=source_label,
            last_modified=last_modified_iso,
            created=created_iso,
            recurrence_id=None,
            sequence=sequence,
            tz=master.tzid,
            raw_hash=master.raw_hash,
        )
        return

    # Recurring: expand within window
    try:
        occurrences = list(rs.between(window_start, window_end, inc=True))
    except Exception as e:
        logger.error("rruleset_between_failed", uid=master.uid, error=str(e))
        occurrences = []

    # Duration for instances
    inst_duration: timedelta
    if duration:
        inst_duration = duration
    else:
        inst_duration = (base_end - base_start) if base_end else timedelta(hours=1)

    for occ in occurrences:
        # Apply override if present
        key = (master.uid, occ.strftime(ISO_FMT))
        override = overrides_idx.get(key)
        if override and override.cancelled:
            continue  # explicit cancellation

        # Start/end for instance
        inst_start = occ
        inst_end = inst_start + inst_duration

        inst_title, inst_desc, inst_loc = title, description, location
        inst_status, inst_organizer, inst_attendees, inst_cats = status, organizer, attendees, categories
        inst_sequence = sequence
        inst_created = created_iso
        inst_last_modified = last_modified_iso
        inst_tz = master.tzid
        inst_raw_hash = master.raw_hash

        if override and not override.cancelled:
            oc = override.component
            inst_title = as_text(oc.get("summary")).strip() or inst_title
            inst_desc = as_text(oc.get("description")) or inst_desc
            inst_loc = as_text(oc.get("location")) or inst_loc
            ov_status = as_text(oc.get("status")).upper()
            inst_status = ov_status or inst_status
            inst_organizer = normalize_email(as_text(oc.get("organizer"))) or inst_organizer
            inst_attendees = collect_attendees(oc) or inst_attendees
            inst_cats = collect_categories(oc) or inst_cats

            # If override has own DTSTART/DTEND/DURATION, respect it
            if oc.get("dtstart"):
                inst_start, _ = ensure_aware(oc.get("dtstart").dt, inst_tz or default_tz)  # type: ignore
            if oc.get("dtend"):
                inst_end, _ = ensure_aware(oc.get("dtend").dt, inst_tz or default_tz)  # type: ignore
            elif oc.get("duration"):
                try:
                    inst_end = inst_start + oc.get("duration").dt  # type: ignore
                except Exception:
                    pass

            # Sequence/created/last-modified from override if present
            try:
                inst_sequence = int(as_text(oc.get("sequence"))) if oc.get("sequence") else inst_sequence
            except Exception:
                pass

            ov_created = oc.get("created")
            if ov_created:
                inst_created = isoformat_dt(ov_created.dt)  # type: ignore
            ov_lm = oc.get("last-modified") or oc.get("dtstamp")
            if ov_lm:
                inst_last_modified = isoformat_dt(ov_lm.dt)  # type: ignore

            inst_raw_hash = override.raw_hash

        recurrence_id_str = occ.strftime(ISO_FMT)
        eid = make_event_id(master.uid, inst_start, inst_end, inst_title, occ)
        yield EventRecord(
            event_id=eid,
            uid=master.uid,
            title=inst_title or "(No title)",
            description=inst_desc,
            location=inst_loc,
            start=isoformat_dt(inst_start),
            end=isoformat_dt(inst_end),
            allday=master.allday,
            status=inst_status,
            organizer=inst_organizer,
            attendees=inst_attendees,
            categories=inst_cats,
            source=source_label,
            last_modified=inst_last_modified,
            created=inst_created,
            recurrence_id=recurrence_id_str,
            sequence=inst_sequence,
            tz=inst_tz,
            raw_hash=inst_raw_hash,
        )


def index_overrides(overrides: List[OverrideEvent]) -> Dict[Tuple[str, str], OverrideEvent]:
    idx: Dict[Tuple[str, str], OverrideEvent] = {}
    for ov in overrides:
        key = (ov.uid, ov.recurrence_id.strftime(ISO_FMT))
        idx[key] = ov
    return idx


# ------------------------- I/O: File & HTTP -------------------------------- #

async def fetch_url(url: str, cache: UrlCache, timeout_s: int = 20) -> Optional[bytes]:
    headers = cache.get_headers(url)
    async with httpx.AsyncClient(timeout=timeout_s, follow_redirects=True) as client:
        resp = await client.get(url, headers=headers)
        if resp.status_code == 304:
            logger.info("not_modified", url=url)
            return None
        if resp.status_code >= 400:
            logger.error("fetch_failed", url=url, status=resp.status_code)
            raise SystemExit(1)
        etag = resp.headers.get("ETag")
        last_modified = resp.headers.get("Last-Modified")
        cache.update(url, etag, last_modified)
        return resp.content


def is_url(path_or_url: str) -> bool:
    p = urlparse(path_or_url)
    return p.scheme in ("http", "https")


def load_local(path: Union[str, Path]) -> bytes:
    p = Path(path)
    return p.read_bytes()


# ------------------------- Sender (optional) -------------------------------- #

async def send_batches(api_url: str,
                       api_token: Optional[str],
                       events: List[EventRecord],
                       batch_size: int = 500,
                       timeout_s: int = 20,
                       max_retries: int = 3) -> None:
    if not events:
        logger.info("no_events_to_send")
        return
    headers = {"Content-Type": "application/json"}
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"

    async with httpx.AsyncClient(timeout=timeout_s, follow_redirects=True) as client:
        for i in range(0, len(events), batch_size):
            chunk = events[i:i + batch_size]
            payload = [dataclasses.asdict(e) for e in chunk]
            attempt = 0
            while True:
                attempt += 1
                try:
                    resp = await client.post(api_url, headers=headers, json={"events": payload})
                    if resp.status_code >= 500 and attempt <= max_retries:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    if resp.status_code >= 400:
                        logger.error("post_failed", status=resp.status_code, body=resp.text[:4000])
                        raise SystemExit(1)
                    logger.info("batch_sent", count=len(chunk), status=resp.status_code)
                    break
                except httpx.RequestError as e:
                    if attempt <= max_retries:
                        logger.warning("post_retry", error=str(e), attempt=attempt)
                        await asyncio.sleep(2 ** attempt)
                        continue
                    logger.error("post_gave_up", error=str(e))
                    raise SystemExit(1)


# ------------------------- Main pipeline ----------------------------------- #

async def process_sources(args: argparse.Namespace) -> int:
    default_tz = args.default_tz
    window_start = datetime.now(tz=gettz(default_tz) if default_tz else gettz("UTC")) - timedelta(days=args.window_back)
    window_end = datetime.now(tz=gettz(default_tz) if default_tz else gettz("UTC")) + timedelta(days=args.window_forward)

    cache = UrlCache(args.cache_file)
    sources: List[str] = []

    if args.ics:
        sources.append(args.ics)
    if args.url:
        sources.append(args.url)
    if args.dir:
        for p in Path(args.dir).glob("**/*.ics"):
            sources.append(str(p))

    if not sources:
        logger.error("no_sources_provided")
        return 1

    all_events: List[EventRecord] = []
    seen_ids: set[str] = set()

    for src in sources:
        try:
            if is_url(src):
                content = await fetch_url(src, cache)
                if content is None:  # Not modified
                    continue
                source_label = src
            else:
                content = load_local(src)
                source_label = str(Path(src).resolve())
        except Exception as e:
            logger.error("source_load_failed", source=src, error=str(e))
            if args.strict:
                return 1
            else:
                continue

        try:
            masters, overrides = parse_ics_calendar(content, source_label, default_tz)
            ov_idx = index_overrides(overrides)

            for m in masters:
                for ev in expand_master(m, ov_idx, window_start, window_end, source_label, default_tz):
                    if ev.event_id in seen_ids:
                        continue
                    seen_ids.add(ev.event_id)
                    all_events.append(ev)
        except Exception as e:
            logger.error("parse_failed", source=src, error=str(e))
            if args.strict:
                return 1
            else:
                continue

    # Output or send
    if args.dry_run or not args.api_url:
        # JSONL to stdout
        for ev in all_events:
            print(json.dumps(dataclasses.asdict(ev), ensure_ascii=False))
        logger.info("dry_run_done", count=len(all_events))
    else:
        await send_batches(args.api_url, args.api_token, all_events, batch_size=args.batch_size,
                           timeout_s=args.http_timeout, max_retries=args.max_retries)
        logger.info("sent_all", count=len(all_events))

    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="ChronoWatch Calendar Import Tool")
    src = p.add_mutually_exclusive_group(required=False)
    src.add_argument("--ics", type=str, help="Path to a single .ics file")
    src.add_argument("--url", type=str, help="HTTP(S) URL of .ics")
    p.add_argument("--dir", type=str, help="Directory to search for .ics files recursively")

    p.add_argument("--default-tz", type=str, default="UTC", help="Default TZID if missing (e.g., Europe/Stockholm)")
    p.add_argument("--window-back", type=int, default=365, help="Days back for recurrence expansion")
    p.add_argument("--window-forward", type=int, default=730, help="Days forward for recurrence expansion")

    p.add_argument("--api-url", type=str, help="Backend endpoint to POST {'events': [...]}")
    p.add_argument("--api-token", type=str, help="Bearer token for API requests")
    p.add_argument("--batch-size", type=int, default=500, help="Batch size for POST")
    p.add_argument("--http-timeout", type=int, default=20, help="HTTP timeout seconds")
    p.add_argument("--max-retries", type=int, default=3, help="Max retries for POST 5xx/network errors")

    p.add_argument("--dry-run", action="store_true", help="Print JSONL to stdout instead of POST")
    p.add_argument("--strict", action="store_true", help="Fail on source/parse errors instead of skipping")

    p.add_argument("--cache-file", type=str, default=CACHE_DEFAULT, help="URL cache file (ETag/Last-Modified)")
    p.add_argument("--log-level", type=str, default="INFO", help="Logging level")
    p.add_argument("--log-format", type=str, choices=["json", "text"], default="json", help="Logging format")
    return p


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    configure_logging(args.log_level, args.log_format)
    try:
        code = asyncio.run(process_sources(args))
    except KeyboardInterrupt:
        code = 130
    sys.exit(code)


if __name__ == "__main__":
    main()
