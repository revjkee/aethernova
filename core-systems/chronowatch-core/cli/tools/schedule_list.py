#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ChronoWatch Core — CLI: schedule_list

Подкоманды:
  list         — распечатать все расписания (агрегированные поля)
  next         — сгенерировать ближайшие наступления (occurrences)
  validate     — валидация входного файла расписаний
  export-ics   — экспорт выборки в iCalendar (VEVENT)

Источник данных:
  - Файл JSON/YAML через --file / -f (или CHRONOWATCH_SCHEDULE_FILE)
  - STDIN (-f -)
  - Форматы вывода: table (по умолчанию), json, yaml, csv, ndjson

Поддерживаемые типы расписаний (job.schedule.kind):
  - "interval": ISO-8601 длительность (например, "PT15M") или секунды (int/float)
  - "at": список локальных времён "HH:MM[:SS]" (ежедневно)
  - "cron": cron-выражение (требуется croniter)   [опционально]
  - "rrule": RRULE-строка (требуется python-dateutil) [опционально]

Полезные ENV (I cannot verify this):
  CHRONOWATCH_SCHEDULE_FILE=/etc/chronowatch/schedules.yaml
  TZ, or per-job timezone

Схема входа (минимум):
{
  "jobs": [
    {
      "id": "string (unique)",
      "name": "string",
      "enabled": true,
      "timezone": "Europe/Stockholm",
      "tags": ["reporting","prod"],
      "schedule": {
        "kind": "interval|at|cron|rrule",
        "value": "PT15M" | 900 | ["09:00","18:00"] | "0 5 * * *" | "FREQ=DAILY;BYHOUR=9",
        "start": "2025-01-01T00:00:00Z",        # опционально
        "end":   "2025-12-31T23:59:59Z"         # опционально
      },
      "metadata": { "owner": "sre", "description": "..." }
    }
  ]
}
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import datetime as dt
import io
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

# ---------- Опциональные зависимости (graceful degrade) ----------
try:
    import yaml  # type: ignore
    _HAS_YAML = True
except Exception:
    yaml = None
    _HAS_YAML = False

try:
    from croniter import croniter  # type: ignore
    _HAS_CRON = True
except Exception:
    croniter = None
    _HAS_CRON = False

try:
    from dateutil.rrule import rrulestr  # type: ignore
    from dateutil.tz import gettz  # type: ignore
    _HAS_RRULE = True
except Exception:
    rrulestr = None
    gettz = None
    _HAS_RRULE = False

try:
    # Python 3.9+
    from zoneinfo import ZoneInfo
    _HAS_ZONEINFO = True
except Exception:
    ZoneInfo = None  # type: ignore
    _HAS_ZONEINFO = False


ISO8601_DATE_FMT = "%Y-%m-%dT%H:%M:%S%z"  # гибко парсим вручную, см. _parse_dt


# ---------- Модель данных ----------
@dataclass(frozen=True)
class Schedule:
    kind: str
    value: Any
    start: Optional[dt.datetime] = None
    end: Optional[dt.datetime] = None


@dataclass(frozen=True)
class Job:
    id: str
    name: str
    enabled: bool = True
    timezone: Optional[str] = None
    tags: Tuple[str, ...] = field(default_factory=tuple)
    schedule: Schedule = field(default_factory=lambda: Schedule(kind="interval", value="PT1H"))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def tzinfo(self) -> dt.tzinfo:
        if self.timezone:
            if _HAS_ZONEINFO:
                try:
                    return ZoneInfo(self.timezone)
                except Exception:
                    pass
            if _HAS_RRULE and gettz is not None:
                tz = gettz(self.timezone)
                if tz:
                    return tz  # type: ignore
        # Fallback: локальная зона или UTC
        return dt.timezone.utc


@dataclass(frozen=True)
class Occurrence:
    job_id: str
    job_name: str
    when: dt.datetime
    source: str  # вид расписания: interval/cron/rrule/at
    tz: str


# ---------- Парсинг ISO-8601 длительности (простой) ----------
def parse_iso_duration(value: str) -> dt.timedelta:
    """
    Простой парсер ISO-8601 длительности: PnDTnHnMnS / PTnH / PTnM / PTnS.
    Без недель и месяц/год (умышленно).
    """
    if not isinstance(value, str):
        raise ValueError("duration must be a string")
    s = value.upper().strip()
    if not s.startswith("P"):
        raise ValueError("duration must start with 'P'")
    # PnDTnHnMnS | PTnHnMnS
    date_part, time_part = "", ""
    if "T" in s:
        date_part, time_part = s[1:].split("T", 1)
    else:
        date_part, time_part = s[1:], ""
    days = hours = minutes = seconds = 0
    # дни
    num = ""
    for ch in date_part:
        if ch.isdigit():
            num += ch
        elif ch == "D":
            if not num:
                raise ValueError("invalid days in duration")
            days = int(num)
            num = ""
        else:
            raise ValueError("unsupported duration component in date part")
    # время
    num = ""
    for ch in time_part:
        if ch.isdigit() or ch == ".":
            num += ch
        elif ch == "H":
            hours = int(float(num)); num = ""
        elif ch == "M":
            minutes = int(float(num)); num = ""
        elif ch == "S":
            seconds = int(float(num)); num = ""
        else:
            raise ValueError("unsupported duration component in time part")
    return dt.timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)


# ---------- Универсальные парсеры времени ----------
def _parse_dt(s: str) -> dt.datetime:
    """Парсинг дат в ISO-8601: поддержка 'Z' и смещений."""
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # пробуем несколько форматов
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S%z"):
        try:
            return dt.datetime.strptime(s, fmt)
        except Exception:
            continue
    # без tz — считаем UTC
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return dt.datetime.strptime(s, fmt).replace(tzinfo=dt.timezone.utc)
        except Exception:
            continue
    raise ValueError(f"cannot parse datetime: {s}")


def _parse_time_of_day(s: str) -> Tuple[int, int, int]:
    parts = s.split(":")
    if len(parts) not in (2, 3):
        raise ValueError(f"invalid time of day: {s}")
    h = int(parts[0]); m = int(parts[1]); sec = int(parts[2]) if len(parts) == 3 else 0
    if not (0 <= h <= 23 and 0 <= m <= 59 and 0 <= sec <= 59):
        raise ValueError(f"invalid time of day: {s}")
    return h, m, sec


# ---------- Загрузка и валидация ----------
def _load_stream(stream: io.TextIOBase) -> Dict[str, Any]:
    data_txt = stream.read()
    data_txt_stripped = data_txt.strip()
    if not data_txt_stripped:
        return {"jobs": []}
    # если начинается с { или [ — трактуем как JSON
    if data_txt_stripped[0] in "{[":
        try:
            return json.loads(data_txt)
        except Exception as e:
            raise SystemExit(f"Invalid JSON: {e}")
    # иначе пытаемся YAML (если доступен)
    if _HAS_YAML:
        try:
            return yaml.safe_load(data_txt)  # type: ignore
        except Exception as e:
            raise SystemExit(f"Invalid YAML: {e}")
    raise SystemExit("YAML parser not available; provide JSON")

def _load_file(path: str) -> Dict[str, Any]:
    if path == "-":
        return _load_stream(sys.stdin)
    with open(path, "r", encoding="utf-8") as fh:
        return _load_stream(fh)

def load_input(file_arg: Optional[str]) -> Dict[str, Any]:
    path = file_arg or os.getenv("CHRONOWATCH_SCHEDULE_FILE")
    if not path:
        raise SystemExit("No input provided: use --file or CHRONOWATCH_SCHEDULE_FILE")
    return _load_file(path)

def _as_jobs(obj: Dict[str, Any]) -> List[Job]:
    if not isinstance(obj, dict) or "jobs" not in obj or not isinstance(obj["jobs"], list):
        raise SystemExit("Invalid schema: root must be an object with 'jobs' array")
    out: List[Job] = []
    ids = set()
    for i, row in enumerate(obj["jobs"]):
        if not isinstance(row, dict):
            raise SystemExit(f"Invalid job at index {i}: not an object")
        jid = str(row.get("id") or "").strip()
        if not jid:
            raise SystemExit(f"Invalid job at index {i}: missing id")
        if jid in ids:
            raise SystemExit(f"Duplicate job id: {jid}")
        ids.add(jid)
        name = str(row.get("name") or jid)
        enabled = bool(row.get("enabled", True))
        tz = row.get("timezone")
        tags = tuple(map(str, row.get("tags", [])))
        sched = row.get("schedule") or {}
        if not isinstance(sched, dict):
            raise SystemExit(f"Invalid schedule for job {jid}: not an object")
        kind = str(sched.get("kind") or "interval").lower()
        value = sched.get("value")
        start = _parse_dt(sched["start"]) if "start" in sched and sched["start"] else None
        end = _parse_dt(sched["end"]) if "end" in sched and sched["end"] else None
        if start and start.tzinfo is None:
            start = start.replace(tzinfo=dt.timezone.utc)
        if end and end.tzinfo is None:
            end = end.replace(tzinfo=dt.timezone.utc)
        # базовые проверки
        if kind not in ("interval", "at", "cron", "rrule"):
            raise SystemExit(f"Unsupported schedule kind for {jid}: {kind}")
        if kind == "interval":
            if isinstance(value, (int, float)):
                pass
            elif isinstance(value, str):
                try:
                    parse_iso_duration(value)  # validate only
                except Exception as e:
                    raise SystemExit(f"Invalid interval for {jid}: {e}")
            else:
                raise SystemExit(f"Invalid interval value for {jid}")
        elif kind == "at":
            if not isinstance(value, (list, tuple)) or not value:
                raise SystemExit(f"'at' requires non-empty list of times for {jid}")
            for t in value:
                _ = _parse_time_of_day(str(t))
        elif kind == "cron":
            if not _HAS_CRON:
                raise SystemExit(f"croniter not available to handle cron for {jid}")
            if not isinstance(value, str):
                raise SystemExit(f"cron value must be a string for {jid}")
            try:
                croniter(value, dt.datetime.now(dt.timezone.utc))
            except Exception as e:
                raise SystemExit(f"Invalid cron for {jid}: {e}")
        elif kind == "rrule":
            if not _HAS_RRULE:
                raise SystemExit(f"python-dateutil not available to handle rrule for {jid}")
            if not isinstance(value, str):
                raise SystemExit(f"rrule value must be a string for {jid}")
            try:
                rrulestr(value)
            except Exception as e:
                raise SystemExit(f"Invalid rrule for {jid}: {e}")
        sched_obj = Schedule(kind=kind, value=value, start=start, end=end)
        job = Job(id=jid, name=name, enabled=enabled, timezone=tz, tags=tags, schedule=sched_obj, metadata=row.get("metadata") or {})
        out.append(job)
    # детерминированная сортировка
    out.sort(key=lambda j: (not j.enabled, j.name.lower(), j.id))
    return out


# ---------- Генераторы наступлений ----------
def _ceil_to_midnight(d: dt.datetime, tz: dt.tzinfo) -> dt.datetime:
    local = d.astimezone(tz)
    ceiled = local.replace(hour=0, minute=0, second=0, microsecond=0)
    return ceiled.astimezone(dt.timezone.utc)

def _iter_at(job: Job, start: dt.datetime, end: dt.datetime) -> Iterator[dt.datetime]:
    tz = job.tzinfo()
    cursor = _ceil_to_midnight(start, tz)
    while cursor < end:
        for t in job.schedule.value:
            h, m, s = _parse_time_of_day(str(t))
            local = cursor.astimezone(tz).replace(hour=h, minute=m, second=s, microsecond=0)
            utc = local.astimezone(dt.timezone.utc)
            if start <= utc < end:
                yield utc
        cursor += dt.timedelta(days=1)

def _iter_interval(job: Job, start: dt.datetime, end: dt.datetime) -> Iterator[dt.datetime]:
    val = job.schedule.value
    if isinstance(val, (int, float)):
        delta = dt.timedelta(seconds=float(val))
    else:
        delta = parse_iso_duration(str(val))
    # опорная точка — start или schedule.start, округляем вверх к кратности delta
    anchor = job.schedule.start or start
    if anchor.tzinfo is None:
        anchor = anchor.replace(tzinfo=dt.timezone.utc)
    # найдём ближайшее t>=start: anchor + ceil((start-anchor)/delta)*delta
    if start <= anchor:
        t = anchor
    else:
        diff = (start - anchor).total_seconds()
        steps = int(diff // delta.total_seconds())
        t = anchor + dt.timedelta(seconds=(steps * delta.total_seconds()))
        if t < start:
            t += delta
    while t < end:
        if (job.schedule.start and t < job.schedule.start) or (job.schedule.end and t > job.schedule.end):
            pass
        else:
            if t >= start:
                yield t
        t += delta

def _iter_cron(job: Job, start: dt.datetime, end: dt.datetime) -> Iterator[dt.datetime]:
    assert _HAS_CRON and croniter is not None
    base = start
    itr = croniter(job.schedule.value, base)
    while True:
        t = itr.get_next(dt.datetime).replace(tzinfo=None)
        # croniter возвращает naive — считаем UTC
        t = t.replace(tzinfo=dt.timezone.utc)
        if t >= end:
            break
        if job.schedule.start and t < job.schedule.start:
            continue
        if job.schedule.end and t > job.schedule.end:
            break
        yield t

def _iter_rrule(job: Job, start: dt.datetime, end: dt.datetime) -> Iterator[dt.datetime]:
    assert _HAS_RRULE and rrulestr is not None
    rule = rrulestr(job.schedule.value, dtstart=(job.schedule.start or start))
    for t in rule.between(start, end, inc=False):
        if t.tzinfo is None:
            t = t.replace(tzinfo=dt.timezone.utc)
        yield t

def iter_occurrences(job: Job, window_from: dt.datetime, window_to: dt.datetime, limit: int) -> Iterator[dt.datetime]:
    if not job.enabled:
        return iter(())
    start = max(window_from, job.schedule.start) if job.schedule.start else window_from
    end = min(window_to, job.schedule.end) if job.schedule.end else window_to
    if start >= end:
        return iter(())
    if job.schedule.kind == "at":
        it = _iter_at(job, start, end)
    elif job.schedule.kind == "interval":
        it = _iter_interval(job, start, end)
    elif job.schedule.kind == "cron":
        it = _iter_cron(job, start, end)
    elif job.schedule.kind == "rrule":
        it = _iter_rrule(job, start, end)
    else:
        it = iter(())
    # обрезаем лимитом
    def _limited() -> Iterator[dt.datetime]:
        n = 0
        for d in it:
            yield d
            n += 1
            if n >= limit:
                break
    return _limited()


# ---------- Вывод ----------
def _fmt_dt(d: dt.datetime, tzname: Optional[str]) -> str:
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    if tzname and _HAS_ZONEINFO:
        try:
            d = d.astimezone(ZoneInfo(tzname))
        except Exception:
            pass
    return d.isoformat()

def _print_table(rows: List[Dict[str, Any]], columns: List[str]) -> None:
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in columns}
    line = " | ".join(c.ljust(widths[c]) for c in columns)
    sep = "-+-".join("-" * widths[c] for c in columns)
    print(line)
    print(sep)
    for r in rows:
        print(" | ".join(str(r.get(c, "")).ljust(widths[c]) for c in columns))

def _dump_yaml(obj: Any) -> str:
    if not _HAS_YAML:
        raise SystemExit("YAML output requested but PyYAML not available")
    return yaml.safe_dump(obj, sort_keys=False, allow_unicode=True)  # type: ignore

def _dump_rows(rows: List[Dict[str, Any]], fmt: str, columns: Optional[List[str]] = None) -> None:
    fmt = fmt.lower()
    if fmt == "table":
        if not rows:
            print("(no rows)")
            return
        _print_table(rows, columns or list(rows[0].keys()))
    elif fmt == "json":
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    elif fmt == "ndjson":
        for r in rows:
            print(json.dumps(r, ensure_ascii=False))
    elif fmt == "yaml":
        print(_dump_yaml(rows))
    elif fmt == "csv":
        if not rows:
            return
        colz = columns or list(rows[0].keys())
        w = csv.DictWriter(sys.stdout, fieldnames=colz)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in colz})
    else:
        raise SystemExit(f"Unknown output format: {fmt}")


# ---------- iCalendar экспорт ----------
def _ics_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace(",", "\\,").replace(";", "\\;").replace("\n", "\\n")

def build_ics(occurs: List[Occurrence]) -> str:
    """
    Минимальный iCalendar (RFC 5545) экспорт.
    Для каждого Occurrence — VEVENT с DTSTART/DTEND=+duration(минуту), UID=job_id+ts.
    """
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//chronowatch-core//schedule_list//EN",
        "CALSCALE:GREGORIAN",
    ]
    for oc in occurs:
        start = oc.when.astimezone(dt.timezone.utc)
        end = start + dt.timedelta(minutes=1)
        dtstart = start.strftime("%Y%m%dT%H%M%SZ")
        dtend = end.strftime("%Y%m%dT%H%M%SZ")
        uid = f"{oc.job_id}-{int(start.timestamp())}@chronowatch"
        summary = _ics_escape(f"{oc.job_name} ({oc.source})")
        lines += [
            "BEGIN:VEVENT",
            f"UID:{uid}",
            f"SUMMARY:{summary}",
            f"DTSTART:{dtstart}",
            f"DTEND:{dtend}",
            f"DESCRIPTION:{_ics_escape(oc.job_id)}",
            "END:VEVENT",
        ]
    lines.append("END:VCALENDAR")
    return "\n".join(lines)


# ---------- Фильтры и утилиты ----------
def _filter_jobs(jobs: List[Job], ids: Optional[List[str]], tags_all: Optional[List[str]], enabled_only: bool) -> List[Job]:
    out = []
    ids_set = set(ids or [])
    tags_all = [t.lower() for t in (tags_all or [])]
    for j in jobs:
        if ids_set and j.id not in ids_set:
            continue
        if enabled_only and not j.enabled:
            continue
        if tags_all:
            low = set(t.lower() for t in j.tags)
            if not set(tags_all).issubset(low):
                continue
        out.append(j)
    return out


# ---------- Команды ----------
def cmd_list(args: argparse.Namespace) -> int:
    data = load_input(args.file)
    jobs = _as_jobs(data)
    jobs = _filter_jobs(jobs, args.id, args.tag, args.enabled_only)
    rows: List[Dict[str, Any]] = []
    for j in jobs:
        rows.append({
            "id": j.id,
            "name": j.name,
            "enabled": "yes" if j.enabled else "no",
            "kind": j.schedule.kind,
            "value": json.dumps(j.schedule.value) if isinstance(j.schedule.value, (dict, list)) else str(j.schedule.value),
            "timezone": j.timezone or "",
            "start": j.schedule.start.isoformat() if j.schedule.start else "",
            "end": j.schedule.end.isoformat() if j.schedule.end else "",
            "tags": ",".join(j.tags),
        })
    cols = ["id","name","enabled","kind","value","timezone","start","end","tags"]
    _dump_rows(rows, args.format, cols)
    return 0

def _window(args: argparse.Namespace, default_hours: int = 24) -> Tuple[dt.datetime, dt.datetime]:
    now = dt.datetime.now(dt.timezone.utc)
    win_from = _parse_dt(args.from_) if args.from_ else now
    win_to = _parse_dt(args.to) if args.to else (win_from + dt.timedelta(hours=args.hours or default_hours))
    if win_from.tzinfo is None:
        win_from = win_from.replace(tzinfo=dt.timezone.utc)
    if win_to.tzinfo is None:
        win_to = win_to.replace(tzinfo=dt.timezone.utc)
    if win_to <= win_from:
        raise SystemExit("--to must be > --from")
    return win_from, win_to

def cmd_next(args: argparse.Namespace) -> int:
    data = load_input(args.file)
    jobs = _as_jobs(data)
    jobs = _filter_jobs(jobs, args.id, args.tag, args.enabled_only)
    win_from, win_to = _window(args)
    rows: List[Dict[str, Any]] = []
    occs: List[Occurrence] = []
    for j in jobs:
        for d in iter_occurrences(j, win_from, win_to, args.limit):
            rows.append({
                "job_id": j.id,
                "job_name": j.name,
                "when_utc": d.isoformat(),
                "when_local": _fmt_dt(d, j.timezone),
                "kind": j.schedule.kind,
                "tz": j.timezone or "UTC",
            })
            occs.append(Occurrence(job_id=j.id, job_name=j.name, when=d, source=j.schedule.kind, tz=j.timezone or "UTC"))
    # детерминированная сортировка по времени, затем job_id
    rows.sort(key=lambda r: (r["when_utc"], r["job_id"]))
    _dump_rows(rows, args.format, ["when_utc","when_local","job_id","job_name","kind","tz"])
    # экспорт ICS в файл, если указан
    if args.ics:
        ics = build_ics(occs)
        with (sys.stdout if args.ics == "-" else open(args.ics, "w", encoding="utf-8")) as fh:
            fh.write(ics)
    return 0

def cmd_validate(args: argparse.Namespace) -> int:
    try:
        data = load_input(args.file)
        _ = _as_jobs(data)
        print("OK")
        return 0
    except SystemExit as e:
        # пробрасываем диагностическое сообщение
        print(str(e), file=sys.stderr)
        return 2

def cmd_export_ics(args: argparse.Namespace) -> int:
    # Сокращённый путь: next с экспортом ICS, но без табличного вывода
    data = load_input(args.file)
    jobs = _as_jobs(data)
    jobs = _filter_jobs(jobs, args.id, args.tag, args.enabled_only)
    win_from, win_to = _window(args)
    occs: List[Occurrence] = []
    for j in jobs:
        for d in iter_occurrences(j, win_from, win_to, args.limit):
            occs.append(Occurrence(job_id=j.id, job_name=j.name, when=d, source=j.schedule.kind, tz=j.timezone or "UTC"))
    ics = build_ics(occs)
    with (sys.stdout if args.output == "-" else open(args.output, "w", encoding="utf-8")) as fh:
        fh.write(ics)
    return 0


# ---------- Аргументы CLI ----------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="schedule_list",
        description="ChronoWatch Core — инспекция расписаний",
    )
    p.add_argument("--file", "-f", default=None, help="Путь к JSON/YAML файлу расписаний (или '-' для STDIN)")
    p.add_argument("--format", "-o", default="table", choices=["table","json","yaml","csv","ndjson"], help="Формат вывода (для list/next)")
    p.add_argument("--enabled-only", action="store_true", help="Только enabled задания")
    p.add_argument("--id", action="append", help="Фильтр по id (можно несколько)", dest="id")
    p.add_argument("--tag", action="append", help="Фильтр: все указанные теги должны присутствовать", dest="tag")
    sub = p.add_subparsers(dest="cmd", required=True)

    s1 = sub.add_parser("list", help="Показать все задания")
    s1.set_defaults(func=cmd_list)

    s2 = sub.add_parser("next", help="Показать наступления в окне")
    s2.add_argument("--from", dest="from_", default=None, help="Начало окна ISO-8601 (по умолчанию: сейчас, UTC)")
    s2.add_argument("--to", dest="to", default=None, help="Конец окна ISO-8601")
    s2.add_argument("--hours", type=int, default=None, help="Размер окна в часах (если --to не указан)")
    s2.add_argument("--limit", type=int, default=10, help="Лимит наступлений на одно задание")
    s2.add_argument("--ics", default=None, help="Путь для сохранения .ics (или '-' для STDOUT)")
    s2.set_defaults(func=cmd_next)

    s3 = sub.add_parser("validate", help="Проверить файл на соответствие схеме и поддержанным видам расписаний")
    s3.set_defaults(func=cmd_validate)

    s4 = sub.add_parser("export-ics", help="Сгенерировать iCalendar (VEVENT) для окна наступлений")
    s4.add_argument("--from", dest="from_", default=None, help="Начало окна ISO-8601")
    s4.add_argument("--to", dest="to", default=None, help="Конец окна ISO-8601")
    s4.add_argument("--hours", type=int, default=24, help="Размер окна (часов), если --to не указан")
    s4.add_argument("--limit", type=int, default=10, help="Лимит наступлений на одно задание")
    s4.add_argument("--output", "-O", default="-", help="Куда писать .ics (файл или '-')")
    s4.set_defaults(func=cmd_export_ics)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
