# cybersecurity-core/cybersecurity/edr/process_monitor.py
from __future__ import annotations

import asyncio
import base64
import dataclasses
import fnmatch
import hashlib
import json
import logging
import os
import platform
import re
import socket
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, Iterable, List, Optional, Set, Tuple

try:
    import psutil  # type: ignore
except Exception as e:  # pragma: no cover
    raise RuntimeError("psutil is required for process monitoring") from e


LOG = logging.getLogger("cybersecurity.edr.process_monitor")
LOG.setLevel(logging.INFO)


# ------------------------------- Utilities -----------------------------------

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}


def safe_b64(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode("utf-8")).decode("ascii")


def sha256_file(path: Path, chunk: int = 1024 * 1024) -> Optional[str]:
    try:
        if not path.exists() or not path.is_file():
            return None
        h = hashlib.sha256()
        with path.open("rb") as f:
            while True:
                b = f.read(chunk)
                if not b:
                    break
                h.update(b)
        return h.hexdigest()
    except Exception:
        return None


def limit_str(value: Optional[str], max_len: int) -> Optional[str]:
    if value is None:
        return None
    if len(value) <= max_len:
        return value
    return value[: max_len - 3] + "..."


def host_fingerprint() -> str:
    # Стабильный идентификатор сенсора
    sensor_env = os.getenv("SENSOR_ID")
    if sensor_env:
        return sensor_env
    mid_paths = ["/etc/machine-id", "/var/lib/dbus/machine-id"]
    for p in mid_paths:
        try:
            if os.path.exists(p):
                with open(p, "r", encoding="utf-8") as fh:
                    return fh.read().strip()
        except Exception:
            pass
    raw = f"{socket.gethostname()}|{platform.system()}|{platform.version()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


# ------------------------------- Config --------------------------------------

@dataclass(slots=True)
class MonitorConfig:
    poll_interval_sec: float = float(os.getenv("EDR_POLL_INTERVAL_SEC", "1.0"))
    queue_max: int = int(os.getenv("EDR_QUEUE_MAX", "4096"))
    cmdline_max_len: int = int(os.getenv("EDR_CMDLINE_MAX", "2048"))
    exe_hash_max_mb: int = int(os.getenv("EDR_EXE_HASH_MAX_MB", "64"))  # не хэшируем >64MB
    enrichment_connections: bool = env_bool("EDR_ENRICH_CONNECTIONS", True)
    connections_limit: int = int(os.getenv("EDR_CONNECTIONS_LIMIT", "5"))
    open_files: bool = env_bool("EDR_ENRICH_OPEN_FILES", False)
    emit_info_events: bool = env_bool("EDR_EMIT_INFO_EVENTS", True)
    dedup_ttl_sec: int = int(os.getenv("EDR_DEDUP_TTL_SEC", "300"))
    rules_enabled: bool = env_bool("EDR_RULES_ENABLED", True)
    environment: str = os.getenv("ENVIRONMENT", "prod")  # dev/staging/prod/...
    tenant_id: Optional[str] = os.getenv("TENANT_ID")  # UUID or None
    hostname: str = socket.gethostname()
    # Жесткие ограничения
    max_events_per_cycle: int = int(os.getenv("EDR_MAX_EVENTS_PER_CYCLE", "1024"))
    # Пути, которые считаем "временными"/подозрительными для исполнения
    suspicious_paths: Tuple[str, ...] = (
        "/tmp/", "/var/tmp/", "/dev/shm/", "\\AppData\\Local\\Temp\\", "\\Windows\\Temp\\"
    )


# ------------------------------- Rule Engine ---------------------------------

@dataclass(slots=True)
class Rule:
    name: str
    description: str
    severity: str  # info/low/medium/high/critical
    confidence: int  # 0..100
    cmd_regex: Optional[re.Pattern] = None
    exe_globs: Tuple[str, ...] = ()
    parent_name_globs: Tuple[str, ...] = ()
    path_contains: Tuple[str, ...] = ()
    mitre: Tuple[str, ...] = ()  # e.g., ("T1059",)
    kill_chain: Optional[str] = None  # reconnaissance..actions-on-objective

    def matches(self, ctx: "ProcContext") -> bool:
        if self.cmd_regex and not self.cmd_regex.search(ctx.cmdline or ""):
            return False
        if self.exe_globs:
            if not any(fnmatch.fnmatch((ctx.exe or "").lower(), g.lower()) for g in self.exe_globs):
                return False
        if self.parent_name_globs:
            pname = (ctx.parent_name or "").lower()
            if not any(fnmatch.fnmatch(pname, g.lower()) for g in self.parent_name_globs):
                return False
        if self.path_contains:
            p = (ctx.exe or "") + " " + (ctx.cwd or "")
            if not any(substr.lower() in p.lower() for substr in self.path_contains):
                return False
        return True


def default_rules() -> List[Rule]:
    rules: List[Rule] = []
    # PowerShell encoded / download cradle (Windows)
    rules.append(Rule(
        name="powershell_encoded",
        description="PowerShell с -enc/-encodedCommand",
        severity="high",
        confidence=85,
        cmd_regex=re.compile(r"powershell(\.exe)?\s+.*-(enc|encodedcommand)\s+", re.I),
        mitre=("T1059.001",),  # Command and Scripting Interpreter: PowerShell
        kill_chain="execution",
    ))
    # curl|bash / wget|sh (Linux/Unix)
    rules.append(Rule(
        name="curl_pipe_sh",
        description="Скачивание и немедленный запуск через pipe (curl|wget -> sh/bash)",
        severity="high",
        confidence=80,
        cmd_regex=re.compile(r"(curl|wget).*(\||\|&)\s*(/bin/)?(ba)?sh\b", re.I),
        mitre=("T1059.004", "T1105"),  # Unix shell + Ingress Tool Transfer
        kill_chain="execution",
    ))
    # mshta/http (Windows)
    rules.append(Rule(
        name="mshta_remote",
        description="mshta.exe запускает удалённый HTA",
        severity="high",
        confidence=80,
        cmd_regex=re.compile(r"mshta(\.exe)?\s+https?://", re.I),
        mitre=("T1218.005",),  # Signed Binary Proxy Execution: Mshta
        kill_chain="execution",
    ))
    # rundll32 with URL or javascript
    rules.append(Rule(
        name="rundll32_suspicious",
        description="rundll32 с URL/Javascript",
        severity="high",
        confidence=75,
        cmd_regex=re.compile(r"rundll32(\.exe)?\s+.*(url|javascript|shell32\.dll,control_rundll)", re.I),
        mitre=("T1218.011",),
        kill_chain="execution",
    ))
    # certutil -urlcache -split -f http
    rules.append(Rule(
        name="certutil_download",
        description="certutil используется для скачивания",
        severity="medium",
        confidence=70,
        cmd_regex=re.compile(r"certutil(\.exe)?\s+.*-urlcache.*https?://", re.I),
        mitre=("T1105",),
        kill_chain="delivery",
    ))
    # Execution from temp directories
    rules.append(Rule(
        name="execute_from_temp",
        description="Запуск исполняемого файла из временной директории",
        severity="medium",
        confidence=70,
        path_contains=("/tmp/", "/var/tmp/", "/dev/shm/", "\\AppData\\Local\\Temp\\", "\\Windows\\Temp\\"),
        mitre=("T1204",),
        kill_chain="execution",
    ))
    # Python -c / Perl -e one-liners
    rules.append(Rule(
        name="scripting_one_liner",
        description="Однострочный запуск интерпретатора (-c/-e)",
        severity="low",
        confidence=60,
        cmd_regex=re.compile(r"\b(python|perl|ruby|node)\b.*\s(-c|-e)\s", re.I),
        mitre=("T1059",),
        kill_chain="execution",
    ))
    return rules


# ------------------------------- TTL Cache -----------------------------------

class TTLCache:
    """Простой TTL-кэш для подавления одинаковых событий (dedup)."""
    __slots__ = ("_data", "ttl")

    def __init__(self, ttl_sec: int) -> None:
        self._data: Dict[str, float] = {}
        self.ttl = float(ttl_sec)

    def _purge(self) -> None:
        now = time.monotonic()
        expired = [k for k, t in self._data.items() if t <= now]
        for k in expired:
            self._data.pop(k, None)

    def seen(self, key: str) -> bool:
        now = time.monotonic()
        self._purge()
        if key in self._data:
            return True
        self._data[key] = now + self.ttl
        return False


# ------------------------------- Models --------------------------------------

@dataclass(slots=True)
class ProcContext:
    pid: int
    ppid: Optional[int]
    name: Optional[str]
    exe: Optional[str]
    cmdline: Optional[str]
    username: Optional[str]
    create_time: Optional[datetime]
    cwd: Optional[str]
    parent_name: Optional[str]
    exe_sha256: Optional[str]
    connections: List[Tuple[str, str, int]] = field(default_factory=list)  # [(laddr, raddr, rport)]
    open_files: List[str] = field(default_factory=list)


# ------------------------------- Sinks ---------------------------------------

class EventSink:
    async def emit(self, event: Dict[str, Any]) -> None:  # pragma: no cover
        raise NotImplementedError

class LoggingSink(EventSink):
    def __init__(self, level: int = logging.INFO) -> None:
        self.level = level

    async def emit(self, event: Dict[str, Any]) -> None:
        LOG.log(self.level, json.dumps(event, ensure_ascii=False))

class JsonlFileSink(EventSink):
    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()

    async def emit(self, event: Dict[str, Any]) -> None:
        line = json.dumps(event, ensure_ascii=False) + "\n"
        async with self._lock:
            # простой безопасный append (без aiofiles)
            await asyncio.to_thread(self._path.open("a", encoding="utf-8").write, line)

class CallbackSink(EventSink):
    def __init__(self, cb: Callable[[Dict[str, Any]], Awaitable[None]]) -> None:
        self._cb = cb

    async def emit(self, event: Dict[str, Any]) -> None:
        await self._cb(event)


# ------------------------------- Monitor -------------------------------------

class ProcessMonitor:
    """
    Асинхронный монитор процессов.
    Использует снапшоты psutil для выявления стартов/завершений, обогащает контекстом,
    прогоняет через набор правил и отправляет в EventSink'и.
    """

    def __init__(
        self,
        config: Optional[MonitorConfig] = None,
        sinks: Optional[List[EventSink]] = None,
        rules: Optional[List[Rule]] = None,
    ) -> None:
        self.cfg = config or MonitorConfig()
        self.sinks = sinks or [LoggingSink()]
        self.rules = rules if rules is not None else default_rules()
        self._queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=self.cfg.queue_max)
        self._tasks: List[asyncio.Task] = []
        self._stop = asyncio.Event()
        self._seen: Set[int] = set()
        self._hash_cache: Dict[str, Optional[str]] = {}
        self._dedup = TTLCache(self.cfg.dedup_ttl_sec)
        self._sensor_id = host_fingerprint()
        self._host_meta = self._collect_host_meta()

    def _collect_host_meta(self) -> Dict[str, Any]:
        return {
            "hostname": self.cfg.hostname,
            "os": {
                "type": platform.system().lower(),
                "name": platform.platform(),
                "version": platform.version(),
                "kernel": platform.release(),
                "arch": platform.machine(),
            },
        }

    async def __aenter__(self) -> "ProcessMonitor":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.stop()

    async def start(self) -> None:
        self._stop.clear()
        # Инициализируем исходный список процессов
        try:
            self._seen = {p.pid for p in psutil.process_iter(attrs=[])}
        except Exception:
            self._seen = set()
        self._tasks = [
            asyncio.create_task(self._producer(), name="edr-producer"),
            asyncio.create_task(self._consumer(), name="edr-consumer"),
        ]
        LOG.info("ProcessMonitor started on host=%s sensor=%s", self.cfg.hostname, self._sensor_id)

    async def stop(self) -> None:
        self._stop.set()
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        LOG.info("ProcessMonitor stopped")

    # --------------------------- Producer ------------------------------------

    async def _producer(self) -> None:
        while not self._stop.is_set():
            try:
                await self._scan_cycle()
            except Exception as e:  # noqa: BLE001
                LOG.exception("producer error: %s", e)
            await asyncio.sleep(self.cfg.poll_interval_sec)

    async def _scan_cycle(self) -> None:
        current: Set[int] = set()
        events_emitted = 0

        for p in psutil.process_iter(attrs=["pid"]):
            current.add(p.pid)

        started = current - self._seen
        exited = self._seen - current
        self._seen = current

        # Стартовавшие процессы
        for pid in list(started)[: self.cfg.max_events_per_cycle]:
            ctx = await self._gather_context(pid)
            if ctx is None:
                continue
            evt = self._build_event(ctx, action="start")
            if not self.cfg.emit_info_events and evt["severity"] == "info":
                continue
            if await self._maybe_put(evt):
                events_emitted += 1

        # Завершившиеся процессы (минимальный контекст)
        for pid in list(exited)[: self.cfg.max_events_per_cycle]:
            evt = self._build_exit_event(pid)
            if await self._maybe_put(evt):
                events_emitted += 1

        if events_emitted:
            LOG.debug("producer emitted events=%d", events_emitted)

    async def _maybe_put(self, evt: Dict[str, Any]) -> bool:
        key = self._dedup_key(evt)
        if self._dedup.seen(key):
            return False
        try:
            self._queue.put_nowait(evt)
            return True
        except asyncio.QueueFull:
            LOG.warning("drop event due to full queue")
            return False

    def _dedup_key(self, evt: Dict[str, Any]) -> str:
        # Упрощённый ключ: тип действия + exe_hash + cmdline(signature) + parent
        proc = evt.get("process", {})
        part = json.dumps(
            {
                "a": evt.get("alert", {}).get("signature", {}).get("name"),
                "exe": proc.get("exe"),
                "sha": proc.get("hashes", {}).get("sha256"),
                "pp": proc.get("ppid"),
                "pname": proc.get("name"),
                "cl": (proc.get("cmdline") or "")[:128],
                "act": evt.get("alert", {}).get("category"),
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(part.encode("utf-8")).hexdigest()

    # --------------------------- Consumer ------------------------------------

    async def _consumer(self) -> None:
        while not self._stop.is_set():
            try:
                evt = await asyncio.wait_for(self._queue.get(), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            await self._fanout(evt)

    async def _fanout(self, evt: Dict[str, Any]) -> None:
        for sink in self.sinks:
            try:
                await sink.emit(evt)
            except Exception as e:  # noqa: BLE001
                LOG.warning("sink error: %s", e)

    # --------------------------- Context -------------------------------------

    async def _gather_context(self, pid: int) -> Optional[ProcContext]:
        try:
            p = psutil.Process(pid)
        except psutil.Error:
            return None

        try:
            with p.oneshot():
                ppid = p.ppid()
                name = p.name()
                exe = p.exe() if p.exe() else None
                cmdline_list = p.cmdline() or []
                cmdline = " ".join(cmdline_list) if cmdline_list else None
                username = p.username() if hasattr(p, "username") else None
                create_time = datetime.fromtimestamp(p.create_time(), tz=timezone.utc) if p.create_time() else None
                cwd = p.cwd() if hasattr(p, "cwd") else None
                parent_name = None
                if ppid:
                    try:
                        parent_name = psutil.Process(ppid).name()
                    except psutil.Error:
                        parent_name = None

                exe_sha = await self._exe_sha256_cached(exe)

                conns: List[Tuple[str, str, int]] = []
                if self.cfg.enrichment_connections:
                    try:
                        for c in p.connections(kind="inet")[: self.cfg.connections_limit]:
                            laddr = f"{getattr(c.laddr, 'ip', None)}:{getattr(c.laddr, 'port', None)}" if c.laddr else None
                            raddr = None
                            if c.raddr:
                                raddr = getattr(c.raddr, "ip", None)
                                rport = getattr(c.raddr, "port", None)
                                conns.append((laddr or "", raddr or "", int(rport)))
                    except Exception:
                        pass

                open_files: List[str] = []
                if self.cfg.open_files:
                    try:
                        open_files = [f.path for f in p.open_files()[:50]]
                    except Exception:
                        open_files = []

                return ProcContext(
                    pid=pid,
                    ppid=ppid,
                    name=name,
                    exe=exe,
                    cmdline=limit_str(cmdline, self.cfg.cmdline_max_len),
                    username=username,
                    create_time=create_time,
                    cwd=cwd,
                    parent_name=parent_name,
                    exe_sha256=exe_sha,
                    connections=conns,
                    open_files=open_files,
                )
        except psutil.Error:
            return None

    async def _exe_sha256_cached(self, exe: Optional[str]) -> Optional[str]:
        if not exe:
            return None
        exe = os.path.abspath(exe)
        if exe in self._hash_cache:
            return self._hash_cache[exe]
        size_ok = True
        try:
            sz = os.path.getsize(exe)
            if sz > self.cfg.exe_hash_max_mb * 1024 * 1024:
                size_ok = False
        except Exception:
            pass
        if not size_ok:
            self._hash_cache[exe] = None
            return None
        h = await asyncio.to_thread(sha256_file, Path(exe))
        self._hash_cache[exe] = h
        return h

    # --------------------------- Event building -------------------------------

    def _build_base(self) -> Dict[str, Any]:
        event_id = str(uuid.uuid4())
        tz = os.getenv("TZ") or "UTC"
        tenant = self.cfg.tenant_id
        return {
            "schema_version": "1.0.0",
            "event": {
                "id": event_id,
                "occurred_at": iso(utcnow()),
                "timezone": tz,
            },
            "source": {
                "environment": self.cfg.environment,
                "sensor": {
                    "id": self._sensor_id,
                    "hostname": self.cfg.hostname,
                    "ipv4": [],  # можно обогатить в агенте
                    "mac": [],
                    "location": "",
                },
                "engine": {
                    "vendor": "Aethernova",
                    "product": "EDR-ProcessMonitor",
                    "version": "1.0.0",
                    "profile": "balanced",
                    "rule_source": "builtin",
                },
                "tenant": tenant or "",
            },
            "labels": ["edr", "process"],
            "host": self._host_meta,
        }

    def _score_from_rules(self, ctx: ProcContext) -> Tuple[str, int, Optional[Rule]]:
        if not self.cfg.rules_enabled:
            return "info", 60, None
        for r in self.rules:
            if r.matches(ctx):
                return r.severity, r.confidence, r
        # эвристика по пути
        if ctx.exe and any(s in ctx.exe for s in self.cfg.suspicious_paths):
            return "medium", 65, next((x for x in self.rules if x.name == "execute_from_temp"), None)
        return "info", 60, None

    def _process_block(self, ctx: ProcContext) -> Dict[str, Any]:
        return {
            "pid": ctx.pid,
            "ppid": ctx.ppid,
            "name": ctx.name,
            "exe": ctx.exe,
            "cmdline": ctx.cmdline,
            "user": ctx.username,
            "start_time": iso(ctx.create_time) if ctx.create_time else None,
            "integrity_level": "unknown",
            "hashes": {"sha256": ctx.exe_sha256} if ctx.exe_sha256 else {},
            "cwd": ctx.cwd,
            "parent_name": ctx.parent_name,
            "connections": [
                {"laddr": la, "raddr": ra, "rport": rp} for (la, ra, rp) in ctx.connections
            ],
            "open_files": ctx.open_files,
        }

    def _build_event(self, ctx: ProcContext, action: str) -> Dict[str, Any]:
        base = self._build_base()
        sev, conf, rule = self._score_from_rules(ctx)

        alert_msg = f"process {action}: {ctx.name or ctx.exe or ctx.pid}"
        alert = {
            "signature": {
                "id": f"edr:{rule.name if rule else 'process_event'}",
                "name": rule.description if rule else "Process event",
                "rev": 1,
                "gid": 1001,
                "sid": 500000 + (abs(hash(rule.name)) % 100000 if rule else 1),
                "references": [],
            },
            "category": f"process_{action}",
            "action": "alert",
            "message": alert_msg,
            "labels": ["process", action] + ([rule.name] if rule else []),
        }

        classification: Dict[str, Any] = {}
        if rule and rule.mitre:
            classification["mitre_attack"] = list(rule.mitre)
        if rule and rule.kill_chain:
            classification["kill_chain"] = rule.kill_chain

        event = {
            **base,
            "alert": alert,
            "severity": sev,
            "confidence": conf,
            "classification": classification,
            "process": self._process_block(ctx),
        }
        return event

    def _build_exit_event(self, pid: int) -> Dict[str, Any]:
        base = self._build_base()
        alert = {
            "signature": {
                "id": "edr:process_exit",
                "name": "Process exit",
                "rev": 1,
                "gid": 1001,
                "sid": 500001,
                "references": [],
            },
            "category": "process_exit",
            "action": "alert",
            "message": f"process exit: pid={pid}",
            "labels": ["process", "exit"],
        }
        event = {
            **base,
            "alert": alert,
            "severity": "info",
            "confidence": 60,
            "classification": {},
            "process": {"pid": pid},
        }
        return event


# ------------------------------- Example bootstrap ---------------------------

async def _example_callback(event: Dict[str, Any]) -> None:
    # Здесь можно интегрировать ваш брокер (например, websockets broker.publish)
    # В демо просто логируем другой меткой
    LOG.info("[CALLBACK] %s", json.dumps(event, ensure_ascii=False))


async def main() -> None:  # pragma: no cover
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    cfg = MonitorConfig()
    sinks: List[EventSink] = [
        LoggingSink(level=logging.INFO),
        JsonlFileSink(path=os.getenv("EDR_JSONL", "./logs/edr-process.jsonl")),
        CallbackSink(_example_callback),
    ]
    async with ProcessMonitor(config=cfg, sinks=sinks) as mon:
        # Работаем пока не прервут (Ctrl+C)
        try:
            while True:
                await asyncio.sleep(3600)
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass


if __name__ == "__main__":  # pragma: no cover
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
