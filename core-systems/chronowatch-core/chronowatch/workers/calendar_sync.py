from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, AsyncIterator, Iterable, Optional

import httpx
from redis.asyncio import from_url as redis_from_url
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from chronowatch.config import settings
from chronowatch.db import session_scope
from chronowatch.models import Job, Schedule
from chronowatch.calendars import tzdb

log = logging.getLogger("chronowatch.calendar_sync")

# -----------------------------
# Конфигурация из ENV
# -----------------------------
# CALSYNC_SOURCES — JSON-массив объектов:
# [
#   {"url":"https://example.com/maintenance.ics","type":"ics","name":"maint","default_tz":"UTC"},
#   {"url":"https://example.com/jobs.ics","type":"ics","name":"jobs","default_tz":"Europe/Stockholm"}
# ]
#
# Доп. ENV:
# CALSYNC_INTERVAL_SEC=300
# CALSYNC_TIMEOUT_SEC=15
# CALSYNC_MAX_BODY_BYTES=1048576
# CALSYNC_CONCURRENCY=2
# CALSYNC_DRY_RUN=false
# CALSYNC_REQUIRE_JOB_PREFIX=false  # если true, брать задания только у SUMMARY, начинающихся с "job:"
#
def _env_bool(v: Optional[str], default: bool) -> bool:
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}

CALSYNC_SOURCES: list[dict[str, Any]] = []
try:
    if s := (getattr(settings, "calsync_sources", None) or None):
        CALSYNC_SOURCES = json.loads(s)  # через pydantic-settings можно пробросить
except Exception:
    pass

if not CALSYNC_SOURCES:
    # Фолбэк на системную переменную
    import os
    s = os.environ.get("CALSYNC_SOURCES", "[]")
    try:
        CALSYNC_SOURCES = json.loads(s)
    except Exception:
        CALSYNC_SOURCES = []

import os

CALSYNC_INTERVAL_SEC = int(os.environ.get("CALSYNC_INTERVAL_SEC", "300"))
CALSYNC_TIMEOUT_SEC = int(os.environ.get("CALSYNC_TIMEOUT_SEC", "15"))
CALSYNC_MAX_BODY_BYTES = int(os.environ.get("CALSYNC_MAX_BODY_BYTES", str(1 * 1024 * 1024)))
CALSYNC_CONCURRENCY = int(os.environ.get("CALSYNC_CONCURRENCY", "2"))
CALSYNC_DRY_RUN = _env_bool(os.environ.get("CALSYNC_DRY_RUN"), False)
CALSYNC_REQUIRE_JOB_PREFIX = _env_bool(os.environ.get("CALSYNC_REQUIRE_JOB_PREFIX"), False)

REDIS = redis_from_url(settings.redis_url, decode_responses=True)

# -----------------------------
# Модель нормализованного события
# -----------------------------
@dataclass(frozen=True)
class CalendarEvent:
    uid: str
    start_utc: datetime
    end_utc: Optional[datetime]
    summary: str
    description: Optional[str]
    source: str  # имя источника
    raw_props: dict[str, Any]

# -----------------------------
# ICS парсер (минимально достаточный, без сторонних пакетов)
# Поддержка:
# - line unfolding (RFC5545)
# - VEVENT c полями: UID, DTSTART[, DTEND], SUMMARY, DESCRIPTION, CATEGORIES, X-CHRONOWATCH-*
# -TZID=Area/City и значения в Z / локальные без TZID (тогда default_tz)
# RRULE/EXDATE не поддерживаем — можно пометить каждого повтором отдельной записью на стороне источника.
# -----------------------------
_ICAL_LINE = re.compile(r"^([A-Z0-9-]+)(;[^:]+)?:([\s\S]*)$")

def _unfold_lines(text: str) -> Iterable[str]:
    # Склеиваем строки, начинающиеся с пробела/табуляции
    lines = text.splitlines()
    buf: list[str] = []
    for ln in lines:
        if ln.startswith((" ", "\t")) and buf:
            buf[-1] += ln[1:]
        else:
            buf.append(ln)
    return buf

def _parse_params(param_str: str) -> dict[str, str]:
    # ;TZID=Europe/Stockholm;FMTTYPE=text/plain
    params: dict[str, str] = {}
    if not param_str:
        return params
    for piece in param_str.split(";"):
        if not piece:
            continue
        if "=" in piece:
            k, v = piece.split("=", 1)
            params[k.upper()] = v
    return params

def _parse_dt(value: str, params: dict[str, str], default_tz: str | None) -> datetime:
    # Варианты:
    # 1) 20250901T100000Z — UTC
    # 2) 20250901T100000   — naive, применим default_tz
    # 3) TZID=Europe/Stockholm:20250901T120000 — локально + TZID
    v = value.strip()
    tzid = params.get("TZID")
    if v.endswith("Z"):
        dt = tzdb.parse_iso8601(v)
        return dt.astimezone(timezone.utc)
    # без Z
    if tzid:
        tz = tzdb.get_tz(tzid)
        naive = datetime.strptime(v, "%Y%m%dT%H%M%S")
        aware = tzdb.localize(naive, tz, policy=tzdb.SAFE_EARLIER_STRICT)
        return aware.astimezone(timezone.utc)
    # без TZID: используем default_tz
    tz = tzdb.get_tz(default_tz or "UTC")
    naive = datetime.strptime(v, "%Y%m%dT%H%M%S")
    aware = tzdb.localize(naive, tz, policy=tzdb.SAFE_EARLIER_STRICT)
    return aware.astimezone(timezone.utc)

def _parse_ics_vevents(body: str, source_name: str, default_tz: str | None) -> list[CalendarEvent]:
    events: list[CalendarEvent] = []
    in_event = False
    cur: dict[str, Any] = {}
    for raw in _unfold_lines(body):
        if raw.strip() == "BEGIN:VEVENT":
            in_event = True
            cur = {"_props": {}}
            continue
        if raw.strip() == "END:VEVENT":
            if not in_event:
                continue
            # собрать событие
            uid = cur.get("UID")
            dtstart = cur.get("DTSTART")
            if not uid or not dtstart:
                in_event = False
                cur = {}
                continue
            start_utc = dtstart
            end_utc = cur.get("DTEND")
            summary = cur.get("SUMMARY", "") or ""
            description = cur.get("DESCRIPTION")
            events.append(
                CalendarEvent(
                    uid=uid,
                    start_utc=start_utc,
                    end_utc=end_utc,
                    summary=summary,
                    description=description,
                    source=source_name,
                    raw_props=cur["_props"],
                )
            )
            in_event = False
            cur = {}
            continue

        if not in_event:
            continue

        m = _ICAL_LINE.match(raw)
        if not m:
            continue
        key = m.group(1).upper()
        params = _parse_params(m.group(2) or "")
        val = m.group(3)

        if key in {"DTSTART", "DTEND"}:
            try:
                cur[key] = _parse_dt(val, params, default_tz=default_tz)
            except Exception as e:
                log.warning("Failed to parse %s: %s", key, e)
        elif key in {"UID", "SUMMARY", "DESCRIPTION", "CATEGORIES"}:
            cur[key] = val
        else:
            # сохраняем «как есть» полезные X-ключи
            if key.startswith("X-CHRONOWATCH-"):
                cur["_props"][key] = val
            else:
                # и любые другие для диагностики
                cur["_props"].setdefault(key, val)
    return events

# -----------------------------
# HTTP клиент с ограничениями
# -----------------------------
class ICSClient:
    def __init__(self, timeout_sec: int, max_body: int):
        limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)
        self._client = httpx.AsyncClient(timeout=timeout_sec, limits=limits, follow_redirects=True)
        self._max = max_body

    async def fetch(self, url: str, etag: Optional[str], last_modified: Optional[str]) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Возвращает (body, etag, last_modified) или (None, etag, last_modified) при 304.
        """
        headers = {}
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified

        resp = await self._client.get(url, headers=headers)
        if resp.status_code == 304:
            return None, resp.headers.get("ETag"), resp.headers.get("Last-Modified")

        resp.raise_for_status()
        ctype = resp.headers.get("Content-Type", "")
        if "text/calendar" not in ctype and "text/plain" not in ctype:
            log.warning("Unexpected content-type for %s: %s", url, ctype)
        body = resp.text
        if len(body.encode("utf-8", errors="ignore")) > self._max:
            raise ValueError(f"ICS too large (> {self._max} bytes)")
        return body, resp.headers.get("ETag"), resp.headers.get("Last-Modified")

    async def aclose(self):
        await self._client.aclose()

# -----------------------------
# Утилиты БД: апсерты по UID
# -----------------------------
async def _get_job_by_name(db: AsyncSession, name: str) -> Optional[Job]:
    res = await db.execute(select(Job).where(Job.name == name))
    return res.scalar_one_or_none()

async def _ensure_job(db: AsyncSession, name: str, handler: str, description: Optional[str]) -> Job:
    job = await _get_job_by_name(db, name)
    if job:
        # можно обновить handler/description при расхождениях
        updated = False
        if job.handler != handler:
            job.handler = handler
            updated = True
        if description and job.description != description:
            job.description = description
            updated = True
        if updated:
            await db.flush()
        return job
    job = Job(name=name, handler=handler, description=description or f"synced from calendar: {name}", enabled=True)
    db.add(job)
    await db.flush()
    return job

async def _find_schedule_by_uid(db: AsyncSession, uid: str) -> Optional[Schedule]:
    # Поиск по JSON args -> {"calsync_uid": uid}
    res = await db.execute(
        select(Schedule).where(Schedule.args.contains({"calsync_uid": uid}))
    )
    return res.scalar_one_or_none()

async def _upsert_schedule_for_event(
    db: AsyncSession,
    ev: CalendarEvent,
    job: Job,
    interval_sec: Optional[int],
    args: dict[str, Any],
) -> Schedule:
    """
    Идемпотентный апсерт расписания по UID события.
    Интервал:
      - если указан, используется как есть;
      - если None (one-off), ставим большой интервал, чтобы после первого выполнения следующий запуск ушёл «далеко».
    """
    sch = await _find_schedule_by_uid(db, ev.uid)
    BIG_SEC = 365 * 24 * 3600  # 1y
    interval = interval_sec if interval_sec and interval_sec > 0 else BIG_SEC

    # next_run_at: если прошёл — двигаем к будущему ближайшему (для one-off оставим сейчас+1m)
    first_run = ev.start_utc
    now = datetime.now(timezone.utc)
    if first_run < now:
        # если периодическое — сдвиг на кратный интервал вперед
        delta = (now - first_run).total_seconds()
        if interval_sec and interval_sec > 0:
            k = int(delta // interval) + 1
            first_run = first_run + timedelta(seconds=interval * k)
        else:
            first_run = now + timedelta(minutes=1)

    if sch:
        # обновляем
        sch.job_id = job.id
        sch.interval_sec = interval
        sch.next_run_at = first_run
        # слить args (UID неизменяем)
        new_args = dict(sch.args or {})
        new_args.update(args)
        new_args["calsync_uid"] = ev.uid
        sch.args = new_args
        sch.enabled = True
        await db.flush()
        return sch

    sch = Schedule(
        job_id=job.id,
        cron=None,
        interval_sec=interval,
        next_run_at=first_run,
        args=dict(args, calsync_uid=ev.uid),
        enabled=True,
    )
    db.add(sch)
    await db.flush()
    return sch

# -----------------------------
# Преобразование событий → действие
# -----------------------------
def _extract_job_info(ev: CalendarEvent) -> Optional[dict[str, Any]]:
    """
    Извлекает информацию о задании из X-CHRONOWATCH-* или из SUMMARY.
    При отсутствии — вернуть None (событие не для планировщика).
    Поддерживаемые ключи:
      X-CHRONOWATCH-JOB           — имя job (handler registry key)
      X-CHRONOWATCH-HANDLER       — имя handler (если отличается от job.name)
      X-CHRONOWATCH-ARGS          — JSON-строка аргументов
      X-CHRONOWATCH-INTERVAL-SEC  — число секунд (если нет — считаем one-off)
    """
    props = {k.upper(): v for k, v in (ev.raw_props or {}).items()}
    job_name = props.get("X-CHRONOWATCH-JOB")
    handler = props.get("X-CHRONOWATCH-HANDLER") or (job_name or "")
    args_raw = props.get("X-CHRONOWATCH-ARGS")
    interval_raw = props.get("X-CHRONOWATCH-INTERVAL-SEC")

    if not job_name and not handler:
        # Альтернатива: SUMMARY начинается с "job:NAME"
        if CALSYNC_REQUIRE_JOB_PREFIX:
            return None
        m = re.match(r"(?i)^\s*job\s*:\s*([A-Za-z0-9_\-\.]+)", ev.summary or "")
        if not m:
            return None
        job_name = m.group(1)
        handler = job_name

    args: dict[str, Any] = {}
    if args_raw:
        try:
            args = json.loads(args_raw)
        except Exception:
            log.warning("Invalid X-CHRONOWATCH-ARGS for uid=%s", ev.uid)

    interval_sec: Optional[int] = None
    if interval_raw:
        try:
            interval_sec = int(interval_raw)
        except Exception:
            log.warning("Invalid X-CHRONOWATCH-INTERVAL-SEC for uid=%s", ev.uid)

    return {
        "job_name": job_name or handler,
        "handler": handler or job_name,
        "args": args,
        "interval_sec": interval_sec,
    }

def _is_maintenance(ev: CalendarEvent) -> Optional[dict[str, Any]]:
    """
    Если событие — окно обслуживания: CATEGORIES содержит MAINTENANCE
    Доп.параметры:
      X-CHRONOWATCH-MODE: read-only|deny-writes|full-freeze
      X-CHRONOWATCH-EXEMPT-ROLES: csv
      X-CHRONOWATCH-EXEMPT-PATHS: csv
    """
    cats = (ev.raw_props.get("CATEGORIES") or ev.raw_props.get("Category") or "")
    if not cats:
        return None
    if "MAINTENANCE" not in cats.upper():
        return None
    mode = (ev.raw_props.get("X-CHRONOWATCH-MODE") or "deny-writes").strip()
    roles = (ev.raw_props.get("X-CHRONOWATCH-EXEMPT-ROLES") or "").strip()
    paths = (ev.raw_props.get("X-CHRONOWATCH-EXEMPT-PATHS") or "").strip()
    # окно only fixed (start/end в UTC). weekly не пытаемся реконструировать из ICS
    if not ev.end_utc:
        # по контракту для окна нужен end
        return None
    return {
        "type": "fixed",
        "mode": mode,
        "description": ev.summary or ev.description or "",
        "tags": ["calendar", ev.source],
        "start": ev.start_utc.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
        "end": ev.end_utc.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
        "exempt_roles": [r.strip() for r in roles.split(",") if r.strip()],
        "exempt_paths": [p.strip() for p in paths.split(",") if p.strip()],
    }

# -----------------------------
# Состояние по источнику в Redis
# -----------------------------
def _redis_keys(source_name: str) -> dict[str, str]:
    base = f"chronowatch:calsync:{source_name}"
    return {
        "etag": f"{base}:etag",
        "lm": f"{base}:last_modified",
        "windows": "chronowatch:maintenance:windows",  # общий ключ с массивом окон
    }

# -----------------------------
# Основной воркер
# -----------------------------
class CalendarSyncWorker:
    def __init__(self, sources: list[dict[str, Any]]):
        self.sources = sources
        self.http = ICSClient(timeout_sec=CALSYNC_TIMEOUT_SEC, max_body=CALSYNC_MAX_BODY_BYTES)
        self._stop = asyncio.Event()
        self._sem = asyncio.Semaphore(CALSYNC_CONCURRENCY)

    async def start(self):
        log.info("CalendarSyncWorker started: %d sources, interval=%ss dry_run=%s",
                 len(self.sources), CALSYNC_INTERVAL_SEC, CALSYNC_DRY_RUN)
        while not self._stop.is_set():
            try:
                await self.sync_once_all()
            except Exception as e:
                log.exception("sync cycle error: %s", e)
            await asyncio.wait_for(self._stop.wait(), timeout=CALSYNC_INTERVAL_SEC)

    async def stop(self):
        self._stop.set()
        await self.http.aclose()

    async def sync_once_all(self):
        tasks = [self._sync_source(src) for src in self.sources]
        await asyncio.gather(*tasks)

    async def _sync_source(self, src: dict[str, Any]):
        async with self._sem:
            name = src.get("name") or "unnamed"
            url = src.get("url")
            if not url:
                log.warning("Source without URL skipped: %s", name)
                return
            if (src.get("type") or "ics") != "ics":
                log.warning("Unsupported source type for %s: %s", name, src.get("type"))
                return
            default_tz = src.get("default_tz") or "UTC"

            keys = _redis_keys(name)
            etag, lm = await REDIS.get(keys["etag"]), await REDIS.get(keys["lm"])
            try:
                body, new_etag, new_lm = await self.http.fetch(url, etag, lm)
            except httpx.HTTPStatusError as he:
                log.error("HTTP error for %s: %s", url, he)
                return
            except Exception as e:
                log.error("Fetch error for %s: %s", url, e)
                return

            if new_etag:
                await REDIS.set(keys["etag"], new_etag)
            if new_lm:
                await REDIS.set(keys["lm"], new_lm)

            if body is None:
                log.info("Not modified: %s", name)
                return

            events = _parse_ics_vevents(body, source_name=name, default_tz=default_tz)
            if not events:
                log.info("No events parsed for %s", name)

            maint_windows: list[dict[str, Any]] = []

            # Транзакционно апдейтить БД
            async with session_scope() as db:
                for ev in events:
                    # 1) maintenance windows в Redis
                    mw = _is_maintenance(ev)
                    if mw:
                        maint_windows.append(mw)

                    # 2) job/schedule
                    job_info = _extract_job_info(ev)
                    if not job_info:
                        continue
                    if CALSYNC_DRY_RUN:
                        log.info("DRY-RUN job %s at %s (uid=%s)", job_info["job_name"], ev.start_utc, ev.uid)
                        continue
                    job = await _ensure_job(
                        db,
                        name=job_info["job_name"],
                        handler=job_info["handler"],
                        description=ev.summary or ev.description,
                    )
                    args = dict(job_info["args"] or {})
                    # enrich служебными атрибутами
                    args.setdefault("_calsync_source", ev.source)
                    args.setdefault("_calsync_summary", ev.summary)
                    args.setdefault("_calsync_start", ev.start_utc.isoformat().replace("+00:00", "Z"))
                    await _upsert_schedule_for_event(
                        db,
                        ev=ev,
                        job=job,
                        interval_sec=job_info["interval_sec"],
                        args=args,
                    )

            # Слить/сохранить maintenance окна в общий ключ (merge по start/end/mode)
            if maint_windows and not CALSYNC_DRY_RUN:
                try:
                    existing_raw = await REDIS.get(keys["windows"])
                    existing = json.loads(existing_raw) if existing_raw else []
                except Exception:
                    existing = []

                # простая идемпотентность: ключ = (start,end,mode,description)
                def key(w: dict[str, Any]) -> str:
                    return json.dumps([w.get("start"), w.get("end"), w.get("mode"), w.get("description")], sort_keys=True)

                merged = {key(w): w for w in existing}
                for w in maint_windows:
                    merged[key(w)] = w
                await REDIS.set(keys["windows"], json.dumps(list(merged.values()), ensure_ascii=False))

            log.info("Synced source=%s events=%d jobs_scheduled=%d windows=%d",
                     name, len(events),
                     sum(1 for e in events if _extract_job_info(e)),
                     len(maint_windows))

# -----------------------------
# CLI
# -----------------------------
async def _run_once():
    worker = CalendarSyncWorker(sources=CALSYNC_SOURCES)
    try:
        await worker.sync_once_all()
    finally:
        await worker.stop()

def _main():
    import argparse
    parser = argparse.ArgumentParser(description="Chronowatch Calendar Sync")
    parser.add_argument("--once", action="store_true", help="Run single sync iteration and exit")
    args = parser.parse_args()
    if args.once:
        asyncio.run(_run_once())
    else:
        # фоновой цикл
        worker = CalendarSyncWorker(sources=CALSYNC_SOURCES)
        async def _loop():
            try:
                await worker.start()
            finally:
                await worker.stop()
        asyncio.run(_loop())

if __name__ == "__main__":
    _main()
