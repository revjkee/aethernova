from __future__ import annotations

import asyncio
import contextlib
import fnmatch
import json
import logging
import logging.handlers
import os
import queue
import re
import signal
import socket
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union


# =========================
# Exceptions
# =========================
class LogActionError(Exception):
    """Base class for log obligation errors."""


# =========================
# Enums & Config
# =========================
class Destination(Enum):
    STDOUT = "stdout"
    STDERR = "stderr"
    FILE = "file"
    SYSLOG = "syslog"
    UDP = "udp"          # fire-and-forget to host:port (for local forwarder)


class Backpressure(Enum):
    BLOCK = "block"      # await while queue is full
    DROP = "drop"        # drop newest
    COALESCE = "coalesce"  # merge duplicates by (subject, action, resource, rule_id/effect)


@dataclass
class RedactionRule:
    # redact by key name (exact or glob) and/or regex applied to stringified values
    key_globs: List[str] = field(default_factory=list)
    patterns: List[str] = field(default_factory=list)
    replacement: str = "***"

    def should_redact_key(self, key: str) -> bool:
        return any(fnmatch.fnmatchcase(key, g) for g in self.key_globs)

    def redact_str(self, text: str) -> str:
        out = text
        for pat in self.patterns:
            out = re.sub(pat, self.replacement, out)
        return out


@dataclass
class Projection:
    include: List[str] = field(default_factory=list)   # dotted paths (e.g. "ip", "device.id")
    exclude: List[str] = field(default_factory=list)   # dotted paths to drop
    max_bytes: int = 1_000_000                         # guard rail for payload truncation


@dataclass
class Rotation:
    max_bytes: int = 100 * 1024 * 1024  # 100 MiB
    backups: int = 10
    when: Optional[str] = None          # e.g., "D", "H"; if set -> TimedRotatingFileHandler
    interval: int = 1
    utc: bool = True


@dataclass
class LogActionSettings:
    destination: Destination = Destination.STDOUT
    level: str = "INFO"
    fmt: str = "json"  # "json" | "text"
    file_path: Optional[str] = None
    syslog_address: Optional[str] = None     # e.g., "/dev/log" or "127.0.0.1:514"
    udp_address: Optional[str] = None        # "host:port"
    queue_size: int = 10_000
    workers: int = 1
    flush_interval_ms: int = 250
    backpressure: Backpressure = Backpressure.BLOCK
    redact: RedactionRule = field(default_factory=RedactionRule)
    projection: Projection = field(default_factory=Projection)
    static_fields: Dict[str, Any] = field(default_factory=dict)  # always included in record
    rotation: Rotation = field(default_factory=Rotation)
    name: str = "policy_core.obligations.log"


# =========================
# JSON Formatter
# =========================
class _JsonFormatter(logging.Formatter):
    def __init__(self, static_fields: Optional[Mapping[str, Any]] = None):
        super().__init__()
        self.static_fields = dict(static_fields or {})

    def format(self, record: logging.LogRecord) -> str:
        base: Dict[str, Any] = {
            "ts": int(time.time() * 1000),
            "lvl": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            base["exc"] = self.formatException(record.exc_info)
        base.update(getattr(record, "_extra_json", {}) or {})
        base.update(self.static_fields)
        # canonical JSON (no spaces)
        return json.dumps(base, ensure_ascii=False, separators=(",", ":"))


# =========================
# Utilities
# =========================
def _ensure_logger(settings: LogActionSettings) -> logging.Logger:
    log = logging.getLogger(settings.name)
    log.setLevel(getattr(logging, settings.level.upper(), logging.INFO))
    log.propagate = False
    # reset handlers for idempotent re-init
    log.handlers.clear()

    if settings.destination == Destination.STDOUT:
        h: logging.Handler = logging.StreamHandler(sys.stdout)
    elif settings.destination == Destination.STDERR:
        h = logging.StreamHandler(sys.stderr)
    elif settings.destination == Destination.FILE:
        if not settings.file_path:
            raise LogActionError("file_path must be set for FILE destination")
        Path(settings.file_path).parent.mkdir(parents=True, exist_ok=True)
        if settings.rotation.when:
            h = logging.handlers.TimedRotatingFileHandler(
                settings.file_path,
                when=settings.rotation.when,
                interval=settings.rotation.interval,
                backupCount=settings.rotation.backups,
                utc=settings.rotation.utc,
                encoding="utf-8",
                delay=True,
            )
        else:
            h = logging.handlers.RotatingFileHandler(
                settings.file_path,
                maxBytes=settings.rotation.max_bytes,
                backupCount=settings.rotation.backups,
                encoding="utf-8",
                delay=True,
            )
    elif settings.destination == Destination.SYSLOG:
        addr: Union[str, Tuple[str, int]]
        default_unix = "/dev/log"
        if settings.syslog_address:
            if ":" in settings.syslog_address and not settings.syslog_address.startswith("/"):
                host, port = settings.syslog_address.rsplit(":", 1)
                addr = (host, int(port))
            else:
                addr = settings.syslog_address
        else:
            addr = default_unix if os.name != "nt" else ("127.0.0.1", 514)
        h = logging.handlers.SysLogHandler(address=addr)
    elif settings.destination == Destination.UDP:
        if not settings.udp_address or ":" not in settings.udp_address:
            raise LogActionError("udp_address must be host:port for UDP destination")
        host, port = settings.udp_address.rsplit(":", 1)
        h = logging.handlers.DatagramHandler(host, int(port))
    else:
        raise LogActionError(f"Unsupported destination: {settings.destination}")

    if settings.fmt == "json":
        h.setFormatter(_JsonFormatter(settings.static_fields))
    else:
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))

    log.addHandler(h)
    return log


def _get_in(d: Mapping[str, Any], dotted: str) -> Any:
    cur: Any = d
    for part in dotted.split("."):
        if isinstance(cur, Mapping) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _set_in(d: MutableMapping[str, Any], dotted: str, value: Any) -> None:
    cur: MutableMapping[str, Any] = d
    parts = dotted.split(".")
    for p in parts[:-1]:
        nxt = cur.get(p)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[p] = nxt
        cur = nxt
    cur[parts[-1]] = value


def _del_in(d: MutableMapping[str, Any], dotted: str) -> None:
    cur: MutableMapping[str, Any] = d
    parts = dotted.split(".")
    for p in parts[:-1]:
        nxt = cur.get(p)
        if not isinstance(nxt, dict):
            return
        cur = nxt
    cur.pop(parts[-1], None)


def _stable_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _truncate_bytes(s: str, max_bytes: int) -> str:
    raw = s.encode("utf-8")
    if len(raw) <= max_bytes:
        return s
    # truncate preserving utf-8 boundary
    cut = max_bytes
    while cut > 0 and (raw[cut - 1] & 0xC0) == 0x80:
        cut -= 1
    return raw[:cut].decode("utf-8", errors="ignore") + "...TRUNCATED"


# =========================
# Metrics (in-memory)
# =========================
@dataclass
class LogMetrics:
    accepted: int = 0
    dropped: int = 0
    flushed: int = 0
    errors: int = 0

    def snapshot(self) -> Dict[str, int]:
        return asdict(self)


# =========================
# Log Action
# =========================
@dataclass
class ObligationEvent:
    subject: str
    action: str
    resource: str
    effect: str                # "allow"|"deny"
    rule_id: Optional[str] = None
    reason: Optional[str] = None
    used_conditions: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    # free-form add-ons
    extras: Dict[str, Any] = field(default_factory=dict)


class LogObligation:
    """
    Асинхронное действие-обязательство логирования.
    Безопасно вызывать из sync/async кода: use apply().

    Запись:
    - JSON (по умолчанию) или text
    - stdout/stderr/file/syslog/udp
    - Очередь с ограничением, бэкпрешер BLOCK/DROP/COALESCE
    - Редакция ключей и regex
    - Проекция/фильтрация контекста, ограничение размера
    - Reopen файлов по SIGHUP (логротейт)
    """

    def __init__(self, settings: Optional[LogActionSettings] = None):
        self.settings = settings or LogActionSettings()
        self.logger = _ensure_logger(self.settings)
        self.metrics = LogMetrics()
        self._queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(self.settings.queue_size)
        self._workers: List[asyncio.Task] = []
        self._coalesce_key = "subject,action,resource,rule_id,effect"
        self._coalesced: Dict[str, Dict[str, Any]] = {}
        self._stop = asyncio.Event()
        self._started = False

        # SIGHUP -> reopen handlers (UNIX)
        with contextlib.suppress(Exception):
            loop = asyncio.get_event_loop()
            loop.add_signal_handler(signal.SIGHUP, self._reopen_handlers)

    # ---------- lifecycle ----------
    async def start(self) -> None:
        if self._started:
            return
        self._started = True
        self._stop.clear()
        for _ in range(max(1, self.settings.workers)):
            self._workers.append(asyncio.create_task(self._worker()))
        # background flusher for COALESCE
        if self.settings.backpressure == Backpressure.COALESCE:
            self._workers.append(asyncio.create_task(self._coalesce_flusher()))
        self.logger.info("LogObligation started")

    async def stop(self) -> None:
        if not self._started:
            return
        self._stop.set()
        for t in self._workers:
            t.cancel()
        for t in self._workers:
            with contextlib.suppress(asyncio.CancelledError):
                await t
        self._workers.clear()
        self._started = False
        self.logger.info("LogObligation stopped")

    def _reopen_handlers(self) -> None:
        for h in list(self.logger.handlers):
            with contextlib.suppress(Exception):
                if hasattr(h, "close"):
                    h.close()
            # Recreate handler stack
        self.logger.handlers.clear()
        self.logger = _ensure_logger(self.settings)
        self.logger.info("Log handlers reopened")

    # ---------- public API ----------
    def apply(self, event: Mapping[str, Any]) -> None:
        """
        Безопасный вход из синхронного кода.
        Если событийный цикл не запущен, выполняем best-effort через asyncio.run_coroutine_threadsafe.
        """
        payload = self._prepare_payload(event)
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._enqueue(payload))
        except RuntimeError:
            # Нет активного event loop: fallback — временный цикл
            asyncio.run(self._enqueue(payload))

    async def apply_async(self, event: Mapping[str, Any]) -> None:
        payload = self._prepare_payload(event)
        await self._enqueue(payload)

    # ---------- core ----------
    def _prepare_payload(self, event: Mapping[str, Any]) -> Dict[str, Any]:
        # validate/normalize
        required = ("subject", "action", "resource", "effect")
        for k in required:
            if k not in event or event[k] is None:
                raise LogActionError(f"missing required field '{k}' in event")
        # base envelope
        base: Dict[str, Any] = {
            "ts": int(time.time() * 1000),
            "id": str(uuid.uuid4()),
            "subject": str(event["subject"]),
            "action": str(event["action"]),
            "resource": str(event["resource"]),
            "effect": str(event["effect"]),
        }
        # optional
        if "rule_id" in event and event["rule_id"] is not None:
            base["rule_id"] = str(event["rule_id"])
        if "reason" in event and event["reason"] is not None:
            base["reason"] = str(event["reason"])
        if "used_conditions" in event and isinstance(event["used_conditions"], list):
            base["used_conditions"] = [str(x) for x in event["used_conditions"]]

        # context projection
        ctx = dict(event.get("context", {}) or {})
        projected = self._project_context(ctx)

        # redact
        redacted = self._redact(projected)

        # extras
        extras = event.get("extras", {}) or {}
        if isinstance(extras, Mapping):
            for k, v in extras.items():
                base[str(k)] = v

        base["ctx"] = redacted
        # size guard
        payload = {
            "event": "obligation.log",
            "decision": base,
        }
        # truncate if necessary
        s = _stable_json(payload)
        if len(s.encode("utf-8")) > self.settings.projection.max_bytes:
            # Попытаемся урезать контекст
            payload["decision"]["ctx"] = {"_truncated": True}
        return payload

    def _project_context(self, ctx: Mapping[str, Any]) -> Dict[str, Any]:
        if not self.settings.projection.include and not self.settings.projection.exclude:
            return dict(ctx)
        # include takes precedence
        out: Dict[str, Any] = {}
        if self.settings.projection.include:
            for dotted in self.settings.projection.include:
                val = _get_in(ctx, dotted)
                if val is not None:
                    _set_in(out, dotted, val)
        else:
            out = dict(ctx)
        for dotted in self.settings.projection.exclude:
            _del_in(out, dotted)
        return out

    def _redact(self, data: Any) -> Any:
        # recursive traversal
        if isinstance(data, dict):
            out: Dict[str, Any] = {}
            for k, v in data.items():
                if self.settings.redact.should_redact_key(k):
                    out[k] = self.settings.redact.replacement
                    continue
                out[k] = self._redact(v)
            return out
        if isinstance(data, list):
            return [self._redact(x) for x in data]
        if isinstance(data, (str, bytes, int, float, bool)) or data is None:
            s = str(data) if not isinstance(data, str) else data
            return self.settings.redact.redact_str(s) if isinstance(s, str) else data
        # fallback to string
        return self.settings.redact.redact_str(str(data))

    async def _enqueue(self, payload: Dict[str, Any]) -> None:
        # backpressure policies
        if self.settings.backpressure == Backpressure.BLOCK:
            await self._queue.put(payload)
            self.metrics.accepted += 1
            return
        if self.settings.backpressure == Backpressure.DROP:
            if self._queue.full():
                self.metrics.dropped += 1
                return
            await self._queue.put(payload)
            self.metrics.accepted += 1
            return
        # COALESCE
        key = self._make_coalesce_key(payload)
        self._coalesced[key] = payload
        self.metrics.accepted += 1

    def _make_coalesce_key(self, payload: Mapping[str, Any]) -> str:
        d = payload.get("decision", {})
        parts = []
        for k in self._coalesce_key.split(","):
            parts.append(str(d.get(k, "")))
        return "|".join(parts)

    async def _worker(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    item = await asyncio.wait_for(self._queue.get(), timeout=self.settings.flush_interval_ms / 1000)
                except asyncio.TimeoutError:
                    continue
                self._emit(item)
                self.metrics.flushed += 1
        except asyncio.CancelledError:
            # drain quickly
            with contextlib.suppress(asyncio.TimeoutError):
                while True:
                    item = self._queue.get_nowait()
                    self._emit(item)
                    self.metrics.flushed += 1
        except Exception as e:
            self.metrics.errors += 1
            self.logger.exception(f"log worker error: {e}")

    async def _coalesce_flusher(self) -> None:
        tick = self.settings.flush_interval_ms / 1000
        try:
            while not self._stop.is_set():
                await asyncio.sleep(tick)
                if not self._coalesced:
                    continue
                batch = list(self._coalesced.values())
                self._coalesced.clear()
                for item in batch:
                    self._emit(item)
                    self.metrics.flushed += 1
        except asyncio.CancelledError:
            # flush remaining
            for item in list(self._coalesced.values()):
                self._emit(item)
                self.metrics.flushed += 1
            self._coalesced.clear()

    def _emit(self, payload: Mapping[str, Any]) -> None:
        if self.settings.fmt == "json":
            msg = _stable_json(payload)
            # Attach parsed JSON as extra (for JSON formatter)
            self.logger.info(msg, extra={"_extra_json": payload})
        else:
            # text format
            d = payload.get("decision", {})
            line = f"[{d.get('effect')}] {d.get('subject')} {d.get('action')} -> {d.get('resource')} rule={d.get('rule_id')} ctx={d.get('ctx')}"
            self.logger.info(line)

    # ---------- Introspection ----------
    def get_metrics(self) -> Dict[str, int]:
        return self.metrics.snapshot()


# =========================
# Factory
# =========================
def build_log_obligation(settings_dict: Optional[Mapping[str, Any]] = None) -> LogObligation:
    """
    Конструктор из словаря (например, из YAML/JSON конфигурации).
    """
    settings_dict = dict(settings_dict or {})
    # Destination
    dest = Destination(settings_dict.get("destination", "stdout"))
    bp = Backpressure(settings_dict.get("backpressure", "block"))

    # Redaction
    red = settings_dict.get("redact", {}) or {}
    redact = RedactionRule(
        key_globs=list(red.get("key_globs", [])),
        patterns=list(red.get("patterns", [])),
        replacement=str(red.get("replacement", "***")),
    )

    # Projection
    proj = settings_dict.get("projection", {}) or {}
    projection = Projection(
        include=list(proj.get("include", [])),
        exclude=list(proj.get("exclude", [])),
        max_bytes=int(proj.get("max_bytes", 1_000_000)),
    )

    # Rotation
    rot = settings_dict.get("rotation", {}) or {}
    rotation = Rotation(
        max_bytes=int(rot.get("max_bytes", 100 * 1024 * 1024)),
        backups=int(rot.get("backups", 10)),
        when=rot.get("when"),
        interval=int(rot.get("interval", 1)),
        utc=bool(rot.get("utc", True)),
    )

    settings = LogActionSettings(
        destination=dest,
        level=str(settings_dict.get("level", "INFO")),
        fmt=str(settings_dict.get("fmt", "json")),
        file_path=settings_dict.get("file_path"),
        syslog_address=settings_dict.get("syslog_address"),
        udp_address=settings_dict.get("udp_address"),
        queue_size=int(settings_dict.get("queue_size", 10_000)),
        workers=int(settings_dict.get("workers", 1)),
        flush_interval_ms=int(settings_dict.get("flush_interval_ms", 250)),
        backpressure=bp,
        redact=redact,
        projection=projection,
        static_fields=dict(settings_dict.get("static_fields", {})),
        rotation=rotation,
        name=str(settings_dict.get("name", "policy_core.obligations.log")),
    )
    return LogObligation(settings)


# =========================
# Minimal self-check (optional)
# =========================
if __name__ == "__main__":
    # Пример автономного запуска: лог в stdout, с редакцией поля "ip"
    obl = build_log_obligation({
        "destination": "stdout",
        "fmt": "json",
        "redact": {"key_globs": ["ip"]},
        "projection": {"include": ["ip", "device.id"]},
        "backpressure": "coalesce",
        "flush_interval_ms": 200,
        "static_fields": {"app": "policy-core", "component": "obligations.log"},
    })

    async def demo():
        await obl.start()
        ev = {
            "subject": "user:42",
            "action": "doc.read",
            "resource": "doc:123",
            "effect": "allow",
            "rule_id": "allow-doc",
            "used_conditions": ["ip_in_cidr"],
            "context": {"ip": "10.1.2.3", "device": {"id": "A1"}},
        }
        for _ in range(3):
            await obl.apply_async(ev)
        await asyncio.sleep(0.5)
        print("metrics:", obl.get_metrics(), file=sys.stderr)
        await obl.stop()

    asyncio.run(demo())
