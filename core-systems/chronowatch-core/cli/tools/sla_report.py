#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SLA/SLO Reporting Tool for chronowatch-core

Features:
- Input: CSV/JSON files or directories with incidents.
- Optional planned maintenance windows to exclude from downtime.
- Time window selection (--from, --to) with timezone control (--tz).
- Grouping by fields (service, env, region, ...).
- Metrics per group: uptime%, downtime (min), incidents, MTTR, MTBF,
  error budget (allowed vs. consumed), burn rate, SLO target, pass/fail.
- Output formats: table, json, csv, md (Markdown).
- Exit codes: 0 (all SLO met), 2 (some SLO failed), 1 (error).
- No external dependencies (stdlib only).

Input schemas (incidents):
CSV/JSON fields (minimum): service, started_at, resolved_at
Optional: severity, env, region, description, planned (true/false)
Dates must be ISO-8601. 'Z' and offsets supported. Examples:
  2025-08-01T10:15:00Z
  2025-08-01T12:00:00+02:00

Maintenance windows:
Same schema as incidents but planned=true. Or provide a separate file via --maintenance.

Examples:
  python sla_report.py --input incidents.csv --from 2025-08-01 --to 2025-08-31 \
    --slo 99.9 --group-by service,env --format table

  python sla_report.py --input data_dir --maintenance maint.json --format md \
    --slo 99.95 --from 2025-07-01T00:00:00Z --to 2025-07-31T23:59:59Z

  python sla_report.py --input a.json --input b.csv --format json --out report.json

Author: chronowatch-core
License: MIT
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import math
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Any, Union
from zoneinfo import ZoneInfo

# -------------------------- Logging -----------------------------------------

def setup_logging(verbosity: int, json_logs: bool) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG

    if json_logs:
        handler = logging.StreamHandler()
        formatter = JsonLogFormatter()
        handler.setFormatter(formatter)
        root = logging.getLogger()
        root.setLevel(level)
        root.handlers = [handler]
    else:
        logging.basicConfig(
            level=level,
            format="%(asctime)s %(levelname)s %(message)s",
        )


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.utcnow().replace(tzinfo=timezone.utc).isoformat(),
            "level": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


# -------------------------- Time utils --------------------------------------

def parse_iso8601(dt: str) -> datetime:
    """
    Parse ISO-8601 datetime with 'Z' or offset into aware datetime (UTC normalized).
    """
    s = dt.strip()
    if s.endswith("Z"):
        s = s.replace("Z", "+00:00")
    try:
        d = datetime.fromisoformat(s)
    except ValueError as e:
        raise ValueError(f"Invalid datetime: {dt}") from e
    if d.tzinfo is None:
        # treat naive as UTC
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc)


def clamp_interval(
    start: datetime, end: datetime, window_start: datetime, window_end: datetime
) -> Optional[Tuple[datetime, datetime]]:
    """
    Clip [start,end) to window [window_start,window_end). Return None if outside.
    """
    if end <= window_start or start >= window_end:
        return None
    s = max(start, window_start)
    e = min(end, window_end)
    if s >= e:
        return None
    return s, e


# -------------------------- Data models -------------------------------------

@dataclass(frozen=True)
class Incident:
    service: str
    started_at: datetime
    resolved_at: datetime
    severity: Optional[str] = None
    env: Optional[str] = None
    region: Optional[str] = None
    description: Optional[str] = None
    planned: bool = False

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Incident":
        try:
            service = str(d["service"]).strip()
            # allow alternative keys
            started = d.get("started_at") or d.get("start") or d.get("started")
            resolved = d.get("resolved_at") or d.get("end") or d.get("resolved")
            if not started or not resolved:
                raise KeyError("started_at/resolved_at is required")
            started_at = parse_iso8601(str(started))
            resolved_at = parse_iso8601(str(resolved))
            if resolved_at <= started_at:
                raise ValueError("resolved_at must be after started_at")
            severity = (str(d["severity"]).strip() if "severity" in d and d["severity"] is not None else None)
            env = (str(d["env"]).strip() if "env" in d and d["env"] is not None else None)
            region = (str(d["region"]).strip() if "region" in d and d["region"] is not None else None)
            description = (str(d["description"]).strip() if "description" in d and d["description"] is not None else None)
            planned_val = d.get("planned", False)
            if isinstance(planned_val, str):
                planned = planned_val.strip().lower() in {"1", "true", "yes", "y"}
            else:
                planned = bool(planned_val)
            return Incident(
                service=service,
                started_at=started_at,
                resolved_at=resolved_at,
                severity=severity,
                env=env,
                region=region,
                description=description,
                planned=planned,
            )
        except Exception as e:
            raise ValueError(f"Invalid incident record: {d}") from e

    def group_key(self, keys: Tuple[str, ...]) -> Tuple[str, ...]:
        mapping = {
            "service": self.service,
            "env": self.env or "",
            "region": self.region or "",
            "severity": self.severity or "",
            "planned": "planned" if self.planned else "unplanned",
        }
        return tuple(mapping.get(k, "") for k in keys)


# -------------------------- IO Parsers --------------------------------------

def load_incidents_from_csv(path: Path) -> List[Incident]:
    logging.debug(f"Loading CSV incidents: {path}")
    incidents: List[Incident] = []
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row:
                continue
            inc = Incident.from_dict(row)
            incidents.append(inc)
    return incidents


def load_incidents_from_json(path: Path) -> List[Incident]:
    logging.debug(f"Loading JSON incidents: {path}")
    with path.open("r", encoding="utf-8") as f:
        payload = json.load(f)
    # Allow list or {"incidents":[...]}
    if isinstance(payload, dict) and "incidents" in payload and isinstance(payload["incidents"], list):
        items = payload["incidents"]
    elif isinstance(payload, list):
        items = payload
    else:
        raise ValueError(f"Unsupported JSON schema in {path}")
    return [Incident.from_dict(x) for x in items]


def discover_files(path: Path) -> List[Path]:
    if path.is_file():
        return [path]
    files: List[Path] = []
    for p in path.rglob("*"):
        if p.is_file() and p.suffix.lower() in (".csv", ".json"):
            files.append(p)
    return files


def load_many(paths: List[Path]) -> List[Incident]:
    incidents: List[Incident] = []
    futures = []
    with ThreadPoolExecutor(max_workers=min(8, max(1, os.cpu_count() or 2))) as ex:
        for p in paths:
            if p.suffix.lower() == ".csv":
                futures.append(ex.submit(load_incidents_from_csv, p))
            elif p.suffix.lower() == ".json":
                futures.append(ex.submit(load_incidents_from_json, p))
            else:
                logging.info(f"Skipping unsupported file: {p}")
        for fut in as_completed(futures):
            incidents.extend(fut.result())
    return incidents


# -------------------------- Interval Math -----------------------------------

@dataclass(frozen=True)
class Interval:
    start: datetime
    end: datetime

    @property
    def seconds(self) -> float:
        return (self.end - self.start).total_seconds()


def merge_overlaps(intervals: List[Interval]) -> List[Interval]:
    """
    Merge overlapping [start,end) intervals. Input must be within window and start < end.
    """
    if not intervals:
        return []
    sorted_ints = sorted(intervals, key=lambda x: (x.start, x.end))
    merged: List[Interval] = []
    cur = sorted_ints[0]
    for it in sorted_ints[1:]:
        if it.start <= cur.end:
            # overlapping or touching
            cur = Interval(start=cur.start, end=max(cur.end, it.end))
        else:
            merged.append(cur)
            cur = it
    merged.append(cur)
    return merged


def subtract_intervals(base: List[Interval], subtract: List[Interval]) -> List[Interval]:
    """
    Subtract 'subtract' from 'base'. All intervals assumed within the same window.
    """
    if not base or not subtract:
        return base
    sub_sorted = merge_overlaps(subtract)
    result: List[Interval] = []
    for b in base:
        cur_parts = [b]
        for s in sub_sorted:
            new_parts: List[Interval] = []
            for part in cur_parts:
                if s.end <= part.start or s.start >= part.end:
                    new_parts.append(part)
                else:
                    # overlap exists
                    if s.start > part.start:
                        new_parts.append(Interval(part.start, s.start))
                    if s.end < part.end:
                        new_parts.append(Interval(s.end, part.end))
            cur_parts = new_parts
            if not cur_parts:
                break
        result.extend(cur_parts)
    return result


# -------------------------- Metrics Engine ----------------------------------

@dataclass
class GroupStats:
    key: Tuple[str, ...]
    total_seconds: float
    allowed_downtime_seconds: float
    actual_downtime_seconds: float
    incidents_count: int
    mttr_seconds: Optional[float]
    mtbf_seconds: Optional[float]
    slo_target: float

    @property
    def uptime_pct(self) -> float:
        if self.total_seconds <= 0:
            return 100.0
        up = max(0.0, self.total_seconds - self.actual_downtime_seconds)
        return (up / self.total_seconds) * 100.0

    @property
    def error_budget_seconds_remaining(self) -> float:
        return max(0.0, self.allowed_downtime_seconds - self.actual_downtime_seconds)

    @property
    def burn_rate(self) -> Optional[float]:
        if self.allowed_downtime_seconds <= 0:
            return None
        return self.actual_downtime_seconds / self.allowed_downtime_seconds

    @property
    def sla_met(self) -> bool:
        return self.uptime_pct + 1e-9 >= self.slo_target


def to_minutes(seconds: Optional[float]) -> Optional[float]:
    if seconds is None:
        return None
    return seconds / 60.0


def compute_metrics(
    incidents: List[Incident],
    maintenance: List[Incident],
    window_start: datetime,
    window_end: datetime,
    slo_target: float,
    group_keys: Tuple[str, ...],
    filter_planned: bool,
) -> List[GroupStats]:
    """
    Compute metrics per group. Planned incidents are excluded from downtime by default.
    If filter_planned=False, planned incidents are counted as downtime unless explicitly
    subtracted via 'maintenance' input.
    """
    # prepare intervals per group
    per_group_intervals: Dict[Tuple[str, ...], List[Interval]] = {}
    per_group_incidents: Dict[Tuple[str, ...], List[Incident]] = {}

    for inc in incidents:
        if filter_planned and inc.planned:
            continue
        clipped = clamp_interval(inc.started_at, inc.resolved_at, window_start, window_end)
        if not clipped:
            continue
        key = inc.group_key(group_keys)
        per_group_intervals.setdefault(key, []).append(Interval(*clipped))
        per_group_incidents.setdefault(key, []).append(inc)

    # maintenance intervals (to subtract)
    maint_intervals_by_group: Dict[Tuple[str, ...], List[Interval]] = {}
    if maintenance:
        for m in maintenance:
            clipped = clamp_interval(m.started_at, m.resolved_at, window_start, window_end)
            if not clipped:
                continue
            key = m.group_key(group_keys)
            maint_intervals_by_group.setdefault(key, []).append(Interval(*clipped))

    total_seconds = (window_end - window_start).total_seconds()
    allowed_downtime_seconds = total_seconds * (1.0 - (slo_target / 100.0))

    results: List[GroupStats] = []
    all_keys = set(per_group_intervals.keys()) | set(maint_intervals_by_group.keys())
    for key in sorted(all_keys):
        downtime_intervals = merge_overlaps(per_group_intervals.get(key, []))
        maint_intervals = merge_overlaps(maint_intervals_by_group.get(key, []))
        if maint_intervals:
            downtime_intervals = subtract_intervals(downtime_intervals, maint_intervals)
        actual_downtime_seconds = sum(iv.seconds for iv in downtime_intervals)
        incs = per_group_incidents.get(key, [])

        # MTTR: mean duration of incidents overlapping window (unplanned considered)
        durations = []
        # For MTBF: intervals between resolved and next started (within the group)
        ordered = sorted(incs, key=lambda x: (x.started_at, x.resolved_at))
        for i in ordered:
            clip = clamp_interval(i.started_at, i.resolved_at, window_start, window_end)
            if clip:
                durations.append((clip[1] - clip[0]).total_seconds())
        mttr_seconds = (sum(durations) / len(durations)) if durations else None

        mtbf_seconds = None
        if len(ordered) >= 2:
            gaps = []
            for a, b in zip(ordered, ordered[1:]):
                # if overlap, gap = 0
                gap = (b.started_at - a.resolved_at).total_seconds()
                gaps.append(max(0.0, gap))
            if gaps:
                mtbf_seconds = sum(gaps) / len(gaps)

        stats = GroupStats(
            key=key,
            total_seconds=total_seconds,
            allowed_downtime_seconds=allowed_downtime_seconds,
            actual_downtime_seconds=actual_downtime_seconds,
            incidents_count=len(incs),
            mttr_seconds=mttr_seconds,
            mtbf_seconds=mtbf_seconds,
            slo_target=slo_target,
        )
        results.append(stats)
    return results


# -------------------------- Output Formatters --------------------------------

def fmt_pct(x: float) -> str:
    return f"{x:.5f}".rstrip("0").rstrip(".")


def fmt_minutes(x: Optional[float]) -> str:
    if x is None:
        return "-"
    # Show up to 4 decimals for small windows
    return f"{x:.4f}" if x < 1 else f"{x:.2f}"


def fmt_num(x: Optional[float]) -> str:
    if x is None:
        return "-0-"
    return f"{x:.4f}" if x < 1 else f"{x:.2f}"


def render_table(stats: List[GroupStats], group_keys: Tuple[str, ...]) -> str:
    headers = list(group_keys) + [
        "uptime_pct",
        "downtime_min",
        "allowed_min",
        "err_budget_left_min",
        "burn_rate",
        "incidents",
        "mttr_min",
        "mtbf_min",
        "slo",
        "sla_met",
    ]
    rows: List[List[str]] = []
    for s in stats:
        row_key = list(s.key)
        uptime = fmt_pct(s.uptime_pct)
        downtime_min = fmt_minutes(to_minutes(s.actual_downtime_seconds))
        allowed_min = fmt_minutes(to_minutes(s.allowed_downtime_seconds))
        left_min = fmt_minutes(to_minutes(s.error_budget_seconds_remaining))
        br = fmt_num(s.burn_rate) if s.burn_rate is not None else "n/a"
        mttr = fmt_minutes(to_minutes(s.mttr_seconds))
        mtbf = fmt_minutes(to_minutes(s.mtbf_seconds))
        row = row_key + [
            uptime,
            downtime_min,
            allowed_min,
            left_min,
            br,
            str(s.incidents_count),
            mttr,
            mtbf,
            fmt_pct(s.slo_target),
            "yes" if s.sla_met else "no",
        ]
        rows.append(row)

    # column widths
    widths = [len(h) for h in headers]
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(cell))

    def line(sep_left="+", sep_mid="+", sep_right="+", fill="-") -> str:
        parts = [fill * (w + 2) for w in widths]
        return sep_left + sep_mid.join(parts) + sep_right

    out = []
    out.append(line())
    out.append(
        "| " + " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers)) + " |"
    )
    out.append(line(sep_left="+", sep_mid="+", sep_right="+", fill="="))
    for r in rows:
        out.append("| " + " | ".join(str(r[i]).ljust(widths[i]) for i in range(len(headers))) + " |")
    out.append(line())
    return "\n".join(out)


def render_json(stats: List[GroupStats], group_keys: Tuple[str, ...]) -> str:
    data = []
    for s in stats:
        item = {
            "group": {k: v for k, v in zip(group_keys, s.key)},
            "metrics": {
                "uptime_pct": s.uptime_pct,
                "downtime_minutes": to_minutes(s.actual_downtime_seconds),
                "allowed_minutes": to_minutes(s.allowed_downtime_seconds),
                "error_budget_left_minutes": to_minutes(s.error_budget_seconds_remaining),
                "burn_rate": s.burn_rate,
                "incidents": s.incidents_count,
                "mttr_minutes": to_minutes(s.mttr_seconds),
                "mtbf_minutes": to_minutes(s.mtbf_seconds),
                "slo_target": s.slo_target,
                "sla_met": s.sla_met,
            },
        }
        data.append(item)
    return json.dumps({"results": data}, ensure_ascii=False, indent=2)


def render_csv(stats: List[GroupStats], group_keys: Tuple[str, ...]) -> str:
    headers = list(group_keys) + [
        "uptime_pct",
        "downtime_minutes",
        "allowed_minutes",
        "error_budget_left_minutes",
        "burn_rate",
        "incidents",
        "mttr_minutes",
        "mtbf_minutes",
        "slo_target",
        "sla_met",
    ]
    out_lines = []
    out_lines.append(",".join(headers))
    for s in stats:
        row = list(s.key) + [
            f"{s.uptime_pct:.10f}",
            f"{to_minutes(s.actual_downtime_seconds) or 0:.10f}",
            f"{to_minutes(s.allowed_downtime_seconds) or 0:.10f}",
            f"{to_minutes(s.error_budget_seconds_remaining) or 0:.10f}",
            "" if s.burn_rate is None else f"{s.burn_rate:.10f}",
            str(s.incidents_count),
            "" if s.mttr_seconds is None else f"{to_minutes(s.mttr_seconds):.10f}",
            "" if s.mtbf_seconds is None else f"{to_minutes(s.mtbf_seconds):.10f}",
            f"{s.slo_target:.10f}",
            "true" if s.sla_met else "false",
        ]
        out_lines.append(",".join(row))
    return "\n".join(out_lines)


def render_md(stats: List[GroupStats], group_keys: Tuple[str, ...]) -> str:
    # Markdown table
    headers = list(group_keys) + [
        "uptime%",
        "downtime (min)",
        "allowed (min)",
        "budget left (min)",
        "burn rate",
        "incidents",
        "MTTR (min)",
        "MTBF (min)",
        "SLO",
        "met",
    ]
    out = []
    out.append("| " + " | ".join(headers) + " |")
    out.append("|" + "|".join("---" for _ in headers) + "|")
    for s in stats:
        row = list(s.key) + [
            fmt_pct(s.uptime_pct),
            fmt_minutes(to_minutes(s.actual_downtime_seconds)),
            fmt_minutes(to_minutes(s.allowed_downtime_seconds)),
            fmt_minutes(to_minutes(s.error_budget_seconds_remaining)),
            ("n/a" if s.burn_rate is None else fmt_num(s.burn_rate)),
            str(s.incidents_count),
            fmt_minutes(to_minutes(s.mttr_seconds)),
            fmt_minutes(to_minutes(s.mtbf_seconds)),
            fmt_pct(s.slo_target),
            ("yes" if s.sla_met else "no"),
        ]
        out.append("| " + " | ".join(row) + " |")
    return "\n".join(out)


# -------------------------- CLI ---------------------------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="sla_report",
        description="SLA/SLO reporting tool for chronowatch-core (incidents-based).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--input", "-i", action="append", required=True,
                   help="Path to CSV/JSON file or directory (repeatable).")
    p.add_argument("--maintenance", "-m", action="append",
                   help="CSV/JSON file(s) with planned maintenance windows.")
    p.add_argument("--from", dest="t_from", required=True,
                   help="Window start (ISO-8601). Naive treated as UTC.")
    p.add_argument("--to", dest="t_to", required=True,
                   help="Window end (ISO-8601), exclusive.")
    p.add_argument("--tz", default="UTC",
                   help="Output timezone for printed window (does not affect calculations).")
    p.add_argument("--slo", type=float, default=99.9,
                   help="Target SLO (percentage).")
    p.add_argument("--group-by", default="service",
                   help="Comma-separated fields to group by (e.g., service,env,region).")
    p.add_argument("--include-planned", action="store_true",
                   help="Include planned incidents as downtime (by default: excluded).")
    p.add_argument("--format", choices=("table", "json", "csv", "md"), default="table",
                   help="Output format.")
    p.add_argument("--out", help="Output file path. If omitted, print to stdout.")
    p.add_argument("--verbosity", "-v", action="count", default=0,
                   help="Increase verbosity (-v, -vv).")
    p.add_argument("--log-json", action="store_true",
                   help="Log in JSON to stdout.")
    return p.parse_args(argv)


def ensure_timezone(tz_name: str) -> ZoneInfo:
    try:
        return ZoneInfo(tz_name)
    except Exception as e:
        raise ValueError(f"Invalid timezone: {tz_name}") from e


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbosity, args.log_json)

    try:
        window_start = parse_iso8601(args.t_from)
        window_end = parse_iso8601(args.t_to)
        if window_end <= window_start:
            raise ValueError("--to must be after --from")
        tz_out = ensure_timezone(args.tz)
        slo_target = float(args.slo)
        if not (0.0 < slo_target <= 100.0):
            raise ValueError("--slo must be in (0, 100]")

        group_keys = tuple(x.strip() for x in args.group_by.split(",") if x.strip())
        if not group_keys:
            raise ValueError("--group-by must yield at least one key")

        # Discover and load incidents
        input_paths: List[Path] = []
        for p in args.input or []:
            input_paths.extend(discover_files(Path(p)))
        if not input_paths:
            raise ValueError("No input files discovered.")

        incidents = load_many(input_paths)
        logging.info(f"Loaded incidents: {len(incidents)}")

        # Maintenance
        maint: List[Incident] = []
        if args.maintenance:
            maint_paths: List[Path] = []
            for m in args.maintenance:
                maint_paths.extend(discover_files(Path(m)))
            if maint_paths:
                maint = load_many(maint_paths)
                # If 'planned' not set in maintenance file, treat all as planned
                maint = [
                    Incident(
                        service=i.service,
                        started_at=i.started_at,
                        resolved_at=i.resolved_at,
                        severity=i.severity,
                        env=i.env,
                        region=i.region,
                        description=i.description,
                        planned=True,
                    )
                    for i in maint
                ]
            logging.info(f"Loaded maintenance windows: {len(maint)}")

        stats = compute_metrics(
            incidents=incidents,
            maintenance=maint,
            window_start=window_start,
            window_end=window_end,
            slo_target=slo_target,
            group_keys=group_keys,
            filter_planned=(not args.include_planned),
        )

        # Render
        if args.format == "table":
            rendered = render_table(stats, group_keys)
        elif args.format == "json":
            rendered = render_json(stats, group_keys)
        elif args.format == "csv":
            rendered = render_csv(stats, group_keys)
        else:
            rendered = render_md(stats, group_keys)

        header = (
            f"# chronowatch SLA report\n"
            f"Window: {window_start.astimezone(tz_out).isoformat()} → {window_end.astimezone(tz_out).isoformat()}\n"
            f"SLO target: {slo_target:.5f}%\n"
            f"Groups: {', '.join(group_keys)}\n"
        )

        output = f"{header}\n{rendered}\n"

        if args.out:
            out_path = Path(args.out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(output, encoding="utf-8")
        else:
            print(output)

        # Exit code: 0 if all met or no stats; 2 if any failed
        if stats and any(not s.sla_met for s in stats):
            return 2
        return 0
    except Exception as e:
        logging.exception("Failed to generate SLA report")
        # Print minimal error to stderr; detailed in logs
        print(f"ERROR: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
