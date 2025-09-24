# cybersecurity-core/cybersecurity/ids/host_ids.py
from __future__ import annotations

import asyncio
import base64
import dataclasses
import fnmatch
import hashlib
import hmac
import json
import logging
import os
import random
import re
import socket
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Iterable, List, Literal, Optional, Tuple

try:
    import psutil  # optional
except Exception:  # pragma: no cover
    psutil = None  # type: ignore

try:
    import aiohttp  # optional
except Exception:  # pragma: no cover
    aiohttp = None  # type: ignore

from pydantic import BaseModel, Field, conint, constr, validator

# ------------------------------------------------------------------------------
# Логирование
# ------------------------------------------------------------------------------
logger = logging.getLogger("host_ids")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# ------------------------------------------------------------------------------
# Константы и утилиты
# ------------------------------------------------------------------------------
ISO8601 = "%Y-%m-%dT%H:%M:%S.%fZ"

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def to_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(ISO8601)

def stable_uid(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8"))
    return h.hexdigest()

# ------------------------------------------------------------------------------
# Модели событий (выравнены под EDR BulkIngestRequest -> EdrEvent)
# ------------------------------------------------------------------------------
class HostEvent(BaseModel):
    event_time: datetime
    agent_id: uuid.UUID
    hostname: constr(strip_whitespace=True, min_length=1, max_length=255)
    username: Optional[str] = None
    severity: conint(ge=0, le=10) = 3
    category: Literal[
        "malware", "ransomware", "lateral_movement", "persistence", "exfil", "policy", "other"
    ] = "other"
    action: Literal["alert", "block", "quarantine", "allow"] = "alert"

    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process_name: Optional[str] = None
    parent_process_id: Optional[int] = None

    file_path: Optional[str] = None
    file_hash: Optional[str] = None  # sha256
    change_type: Optional[Literal["created", "modified", "deleted", "renamed"]] = None

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[Literal["tcp", "udp", "icmp", "other"]] = None

    signature: Optional[str] = None
    rule_ref: Optional[str] = None

    payload_size: Optional[int] = None
    extra: Dict[str, Any] = Field(default_factory=dict)

    @validator("event_time", pre=True)
    def _ensure_tz(cls, v: Any) -> datetime:
        if isinstance(v, datetime):
            return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        return datetime.fromisoformat(v).replace(tzinfo=timezone.utc)

# ------------------------------------------------------------------------------
# Движок правил
# ------------------------------------------------------------------------------
class RuleCondition(BaseModel):
    field: str
    op: Literal["eq", "neq", "regex", "in", "contains", "gte", "lte"]
    value: Any

class Threshold(BaseModel):
    window_sec: conint(ge=1, le=3600) = 60
    count_gte: conint(ge=1, le=100000) = 5
    key_fields: List[str] = Field(default_factory=list)

class Rule(BaseModel):
    rule_id: str
    name: str
    severity: conint(ge=0, le=10) = 5
    category: str = "other"
    conditions_all: List[RuleCondition] = Field(default_factory=list)
    conditions_any: List[RuleCondition] = Field(default_factory=list)
    threshold: Optional[Threshold] = None
    action: Literal["alert", "block", "quarantine", "allow"] = "alert"
    enabled: bool = True
    description: Optional[str] = None
    references: List[str] = Field(default_factory=list)

class _Counter:
    __slots__ = ("ts", "n")
    def __init__(self, ts: float) -> None:
        self.ts = ts
        self.n = 0

class RuleEngine:
    """
    Простая, быстрая, детерминированная система правил:
    - условия all/any (eq, neq, regex, in, contains, gte, lte)
    - пороговые окна (threshold) по наборам ключей
    """
    def __init__(self, rules: List[Rule]) -> None:
        self.rules = [r for r in rules if r.enabled]
        self._counters: Dict[str, _Counter] = {}

    def _get_value(self, ev: HostEvent, field: str) -> Any:
        cur: Any = ev.dict()
        for part in field.split("."):
            if isinstance(cur, dict):
                cur = cur.get(part)
            else:
                cur = getattr(ev, part, None)
        return cur

    def _match_cond(self, ev: HostEvent, c: RuleCondition) -> bool:
        v = self._get_value(ev, c.field)
        if c.op == "eq":
            return v == c.value
        if c.op == "neq":
            return v != c.value
        if c.op == "regex":
            try:
                return bool(re.search(str(c.value), str(v or "")))
            except re.error:
                return False
        if c.op == "in":
            return v in (c.value or [])
        if c.op == "contains":
            return (str(c.value) in str(v or ""))
        if c.op == "gte":
            try:
                return float(v) >= float(c.value)
            except Exception:
                return False
        if c.op == "lte":
            try:
                return float(v) <= float(c.value)
            except Exception:
                return False
        return False

    def _th_key(self, ev: HostEvent, th: Threshold) -> str:
        parts = [str(self._get_value(ev, f) or "") for f in th.key_fields]
        return stable_uid(*parts) if parts else stable_uid("global")

    def _threshold_ok(self, ev: HostEvent, th: Threshold, now_ts: float) -> bool:
        key = self._th_key(ev, th)
        ctr = self._counters.get(key)
        if ctr is None or (now_ts - ctr.ts) > th.window_sec:
            ctr = _Counter(now_ts)
            self._counters[key] = ctr
        ctr.n += 1
        return ctr.n >= th.count_gte

    def evaluate(self, ev: HostEvent) -> Optional[Tuple[Rule, HostEvent]]:
        for r in self.rules:
            if r.conditions_all and not all(self._match_cond(ev, c) for c in r.conditions_all):
                continue
            if r.conditions_any and not any(self._match_cond(ev, c) for c in r.conditions_any):
                continue
            if r.threshold:
                if not self._threshold_ok(ev, r.threshold, time.time()):
                    continue
            ev2 = ev.copy(deep=True)
            ev2.severity = r.severity
            ev2.category = r.category or ev.category
            ev2.action = r.action
            ev2.signature = r.name
            ev2.rule_ref = r.rule_id
            return r, ev2
        return None

# ------------------------------------------------------------------------------
# Дедупликация и rate-limit
# ------------------------------------------------------------------------------
class Deduplicator:
    def __init__(self, ttl_sec: int = 300, max_keys: int = 100_000) -> None:
        self.ttl = ttl_sec
        self.max_keys = max_keys
        self._cache: Dict[str, float] = {}

    def check_and_remember(self, key: str) -> bool:
        now = time.time()
        # очистка по мере роста
        if len(self._cache) > self.max_keys:
            to_del = [k for k, ts in self._cache.items() if now - ts > self.ttl]
            for k in to_del[: self.max_keys // 10]:
                self._cache.pop(k, None)
        ts = self._cache.get(key)
        if ts and (now - ts) <= self.ttl:
            return False
        self._cache[key] = now
        return True

class TokenBucket:
    def __init__(self, rate_per_minute: int) -> None:
        self.rate = max(1, rate_per_minute)
        self.tokens = self.rate
        self.updated = time.time()

    def allow(self) -> bool:
        now = time.time()
        if now - self.updated >= 60:
            self.tokens = self.rate
            self.updated = now
        if self.tokens <= 0:
            return False
        self.tokens -= 1
        return True

# ------------------------------------------------------------------------------
# Collectors
# ------------------------------------------------------------------------------
class Collector:
    name: str = "collector"
    async def run(self, q: "asyncio.Queue[HostEvent]") -> None:  # pragma: no cover
        raise NotImplementedError

class FIMCollector(Collector):
    """
    Периодический хэш-скан путей: улавливает created/modified/deleted.
    Без внешних зависимостей, кроссплатформенно.
    """
    name = "fim"
    def __init__(self, agent_id: uuid.UUID, hostname: str, paths: List[str], include: List[str] | None = None,
                 exclude: List[str] | None = None, interval_sec: int = 15, max_files: int = 100_000) -> None:
        self.agent_id = agent_id
        self.hostname = hostname
        self.paths = [Path(p) for p in paths]
        self.include = include or ["*"]
        self.exclude = exclude or []
        self.interval = max(1, interval_sec)
        self.max_files = max_files
        self._state: Dict[str, str] = {}
        self._stop = asyncio.Event()

    def _match(self, p: Path) -> bool:
        s = str(p)
        if any(fnmatch.fnmatch(s, pat) for pat in self.exclude):
            return False
        return any(fnmatch.fnmatch(s, pat) for pat in self.include)

    def _sha256(self, p: Path) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(p, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    async def run(self, q: "asyncio.Queue[HostEvent]") -> None:
        logger.info("FIMCollector started")
        try:
            while not self._stop.is_set():
                count = 0
                seen: set[str] = set()
                for root in self.paths:
                    if not root.exists():
                        continue
                    for p in root.rglob("*"):
                        if not p.is_file():
                            continue
                        if not self._match(p):
                            continue
                        s = str(p)
                        seen.add(s)
                        count += 1
                        if count > self.max_files:
                            break
                        new_hash = await asyncio.to_thread(self._sha256, p)
                        old_hash = self._state.get(s)
                        if new_hash is None:
                            continue
                        if old_hash is None:
                            self._state[s] = new_hash
                            ev = HostEvent(
                                event_time=utcnow(),
                                agent_id=self.agent_id,
                                hostname=self.hostname,
                                severity=3,
                                category="policy",
                                action="alert",
                                file_path=s,
                                file_hash=new_hash,
                                change_type="created",
                                extra={"collector": self.name},
                            )
                            await q.put(ev)
                        elif old_hash != new_hash:
                            self._state[s] = new_hash
                            ev = HostEvent(
                                event_time=utcnow(),
                                agent_id=self.agent_id,
                                hostname=self.hostname,
                                severity=4,
                                category="persistence",
                                action="alert",
                                file_path=s,
                                file_hash=new_hash,
                                change_type="modified",
                                extra={"collector": self.name},
                            )
                            await q.put(ev)
                    # break outer loop if max_files exceeded
                    if count > self.max_files:
                        break

                # удаленные файлы
                deleted = [path for path in list(self._state.keys()) if path not in seen]
                for s in deleted:
                    self._state.pop(s, None)
                    ev = HostEvent(
                        event_time=utcnow(),
                        agent_id=self.agent_id,
                        hostname=self.hostname,
                        severity=3,
                        category="policy",
                        action="alert",
                        file_path=s,
                        change_type="deleted",
                        extra={"collector": self.name},
                    )
                    await q.put(ev)

                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
        except asyncio.TimeoutError:
            # нормальный цикл
            self._stop.clear()
            await self.run(q)
        except asyncio.CancelledError:  # pragma: no cover
            pass
        except Exception as ex:  # pragma: no cover
            logger.exception("FIMCollector error: %s", ex)

    def stop(self) -> None:
        self._stop.set()

class SyslogTailCollector(Collector):
    """
    Простое асинхронное чтение лога (tail -f) без внешних зависимостей.
    Подходит для локальных агентских логов/аудита.
    """
    name = "syslog"
    def __init__(self, agent_id: uuid.UUID, hostname: str, path: str, regex: str | None = None) -> None:
        self.agent_id = agent_id
        self.hostname = hostname
        self.path = Path(path)
        self.regex = re.compile(regex) if regex else None
        self._stop = asyncio.Event()

    async def run(self, q: "asyncio.Queue[HostEvent]") -> None:
        logger.info("SyslogTailCollector started: %s", self.path)
        if not self.path.exists():
            logger.warning("Syslog path does not exist: %s", self.path)
            return
        # позиция в конце файла
        with self.path.open("r", encoding="utf-8", errors="ignore") as f:
            f.seek(0, os.SEEK_END)
            while not self._stop.is_set():
                where = f.tell()
                line = f.readline()
                if not line:
                    await asyncio.sleep(0.5)
                    f.seek(where)
                    continue
                if self.regex and not self.regex.search(line):
                    continue
                ev = HostEvent(
                    event_time=utcnow(),
                    agent_id=self.agent_id,
                    hostname=self.hostname,
                    severity=3,
                    category="other",
                    action="alert",
                    signature="syslog",
                    extra={"collector": self.name, "line": line.strip()[:4096]},
                )
                await q.put(ev)

    def stop(self) -> None:
        self._stop.set()

class ProcessCollector(Collector):
    """
    Опциональный мониторинг процессов: поднимает события при совпадении по regex имени
    или при аномальном потреблении CPU/RSS. Требует psutil.
    """
    name = "proc"
    def __init__(self, agent_id: uuid.UUID, hostname: str, pattern: str = r".*(mimikatz|procdump|nc).*",
                 cpu_pct_gte: float = 85.0, rss_mb_gte: int = 2048, interval_sec: int = 10) -> None:
        self.agent_id = agent_id
        self.hostname = hostname
        self.regex = re.compile(pattern, re.IGNORECASE)
        self.cpu = cpu_pct_gte
        self.rss = rss_mb_gte
        self.interval = max(1, interval_sec)
        self._stop = asyncio.Event()

    async def run(self, q: "asyncio.Queue[HostEvent]") -> None:
        if psutil is None:
            logger.warning("ProcessCollector disabled: psutil not installed")
            return
        logger.info("ProcessCollector started")
        while not self._stop.is_set():
            try:
                for p in psutil.process_iter(["name", "pid", "ppid", "username", "cpu_percent", "memory_info"]):
                    name = p.info.get("name") or ""
                    pid = int(p.info.get("pid") or 0)
                    ppid = int(p.info.get("ppid") or 0)
                    usr = p.info.get("username")
                    cpu = float(p.info.get("cpu_percent") or 0.0)
                    rss = int(getattr(p.info.get("memory_info"), "rss", 0) or 0) // (1024 * 1024)
                    if self.regex.search(name) or cpu >= self.cpu or rss >= self.rss:
                        ev = HostEvent(
                            event_time=utcnow(),
                            agent_id=self.agent_id,
                            hostname=self.hostname,
                            username=usr,
                            severity=6 if self.regex.search(name) else 4,
                            category="persistence" if self.regex.search(name) else "policy",
                            action="alert",
                            process_name=name,
                            process_id=pid,
                            parent_process_id=ppid,
                            extra={"collector": self.name, "cpu_pct": cpu, "rss_mb": rss},
                        )
                        await q.put(ev)
                await asyncio.sleep(self.interval)
            except asyncio.CancelledError:  # pragma: no cover
                break
            except Exception as ex:  # pragma: no cover
                logger.exception("ProcessCollector error: %s", ex)
                await asyncio.sleep(self.interval)

    def stop(self) -> None:
        self._stop.set()

# ------------------------------------------------------------------------------
# Sinks
# ------------------------------------------------------------------------------
class Sink:
    async def send(self, events: List[HostEvent]) -> None:  # pragma: no cover
        raise NotImplementedError

class FileSink(Sink):
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    async def send(self, events: List[HostEvent]) -> None:
        recs = [{"event": e.dict(), "ts": to_iso(utcnow())} for e in events]
        line = json.dumps(recs, ensure_ascii=False)
        await asyncio.to_thread(self.path.open("a", encoding="utf-8").write, line + "\n")

class HttpSink(Sink):
    """
    Отправка в EDR API /api/v1/edr/events батчами с HMAC-подписью и Idempotency-Key.
    """
    def __init__(self, base_url: str, bearer_token: str, hmac_secret: str,
                 max_retries: int = 5, timeout_sec: int = 10) -> None:
        self.base_url = base_url.rstrip("/")
        self.url = f"{self.base_url}/api/v1/edr/events"
        self.token = bearer_token
        self.secret = hmac_secret.encode("utf-8")
        self.max_retries = max_retries
        self.timeout = timeout_sec

    def _idempotency_key(self, events: List[HostEvent]) -> str:
        h = hashlib.sha256()
        for e in events:
            h.update(str(e.agent_id).encode())
            h.update(e.event_time.isoformat().encode())
            if e.file_hash:
                h.update(e.file_hash.encode())
            if e.signature:
                h.update(e.signature.encode())
        return base64.urlsafe_b64encode(h.digest()).decode("ascii").rstrip("=")

    def _payload(self, events: List[HostEvent]) -> Dict[str, Any]:
        # Выравнивание под BulkIngestRequest
        edr_events = []
        for e in events:
            edr_events.append({
                "event_time": e.event_time.isoformat(),
                "agent_id": str(e.agent_id),
                "hostname": e.hostname,
                "username": e.username,
                "severity": e.severity,
                "category": e.category,
                "action": e.action,
                "process_name": e.process_name,
                "process_id": e.process_id,
                "parent_process_name": e.parent_process_name,
                "parent_process_id": e.parent_process_id,
                "file_path": e.file_path,
                "file_hash": e.file_hash,
                "src_ip": e.src_ip,
                "dst_ip": e.dst_ip,
                "src_port": e.src_port,
                "dst_port": e.dst_port,
                "protocol": e.protocol,
                "signature": e.signature,
                "rule_ref": e.rule_ref,
                "payload_size": e.payload_size,
                "extra": e.extra or {},
            })
        return {"events": edr_events}

    def _sign(self, body: bytes) -> str:
        return hmac.new(self.secret, body, hashlib.sha256).hexdigest()

    async def send(self, events: List[HostEvent]) -> None:
        if not events:
            return
        body = json.dumps(self._payload(events), separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "X-Signature": self._sign(body),
            "Idempotency-Key": self._idempotency_key(events),
        }

        # Вариант с aiohttp (если доступен), иначе синхронный fallback
        delay = 0.5
        for attempt in range(1, self.max_retries + 1):
            try:
                if aiohttp is not None:
                    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as sess:
                        async with sess.post(self.url, data=body, headers=headers) as resp:
                            if resp.status // 100 == 2:
                                return
                            text = await resp.text()
                            raise RuntimeError(f"http {resp.status}: {text[:512]}")
                else:
                    # синхронный fallback через стандартную библиотеку
                    import urllib.request
                    req = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
                    def _do():
                        with urllib.request.urlopen(req, timeout=self.timeout) as r:
                            if r.status // 100 != 2:
                                raise RuntimeError(f"http {r.status}")
                    await asyncio.to_thread(_do)
                    return
            except Exception as ex:
                if attempt >= self.max_retries:
                    logger.error("HttpSink failed after %d attempts: %s", attempt, ex)
                    raise
                jitter = random.uniform(0, 0.25)
                await asyncio.sleep(delay + jitter)
                delay = min(delay * 2, 8.0)

# ------------------------------------------------------------------------------
# Конфигурация агента
# ------------------------------------------------------------------------------
class AgentConfig(BaseModel):
    edr_base_url: str
    bearer_token: str  # формат 'agent:<agent_id>:<hmac>'
    hmac_secret: str   # тот же, что на сервере, для X-Signature
    batch_max: conint(ge=1, le=5000) = 500
    batch_interval_sec: conint(ge=1, le=30) = 3
    queue_max: conint(ge=100, le=200000) = 20000
    dedup_ttl_sec: conint(ge=1, le=3600) = 300
    rate_per_minute: conint(ge=1, le=200000) = 600
    file_sink_path: Optional[str] = None

    fim_paths: List[str] = Field(default_factory=list)
    fim_include: List[str] = Field(default_factory=lambda: ["*"])
    fim_exclude: List[str] = Field(default_factory=list)
    fim_interval_sec: conint(ge=1, le=3600) = 15

    syslog_path: Optional[str] = None
    syslog_regex: Optional[str] = None

    proc_enable: bool = False
    proc_regex: str = r".*(mimikatz|procdump|nc).*"
    proc_cpu_pct_gte: float = 85.0
    proc_rss_mb_gte: int = 2048
    proc_interval_sec: int = 10

    rules: List[Rule] = Field(default_factory=list)

# ------------------------------------------------------------------------------
# HostIDS оркестратор
# ------------------------------------------------------------------------------
@dataclass
class Metrics:
    produced: int = 0
    sent: int = 0
    dropped: int = 0
    deduped: int = 0
    throttled: int = 0
    last_send_error: Optional[str] = None

class HostIDS:
    """
    Асинхронный Host-IDS агент:
    - собирает события из коллектора(ов)
    - нормализует и обогащает
    - прогоняет через RuleEngine
    - дедуп/лимит
    - пакетирует и отправляет в sinks
    """
    def __init__(self, config: AgentConfig, agent_id: Optional[uuid.UUID] = None, hostname: Optional[str] = None) -> None:
        self.cfg = config
        self.agent_id = agent_id or uuid.uuid4()
        self.hostname = hostname or socket.gethostname()
        self.queue: "asyncio.Queue[HostEvent]" = asyncio.Queue(maxsize=self.cfg.queue_max)
        self.metrics = Metrics()
        self.dedup = Deduplicator(self.cfg.dedup_ttl_sec)
        self.bucket = TokenBucket(self.cfg.rate_per_minute)
        self.rules = RuleEngine(self.cfg.rules or [])

        # sinks
        self.sinks: List[Sink] = []
        self.sinks.append(HttpSink(self.cfg.edr_base_url, self.cfg.bearer_token, self.cfg.hmac_secret))
        if self.cfg.file_sink_path:
            self.sinks.append(FileSink(self.cfg.file_sink_path))

        # collectors
        self.collectors: List[Collector] = []
        if self.cfg.fim_paths:
            self.collectors.append(FIMCollector(self.agent_id, self.hostname, self.cfg.fim_paths,
                                               include=self.cfg.fim_include, exclude=self.cfg.fim_exclude,
                                               interval_sec=self.cfg.fim_interval_sec))
        if self.cfg.syslog_path:
            self.collectors.append(SyslogTailCollector(self.agent_id, self.hostname, self.cfg.syslog_path, self.cfg.syslog_regex))
        if self.cfg.proc_enable:
            self.collectors.append(ProcessCollector(self.agent_id, self.hostname, self.cfg.proc_regex,
                                                    self.cfg.proc_cpu_pct_gte, self.cfg.proc_rss_mb_gte,
                                                    self.cfg.proc_interval_sec))
        self._tasks: List[asyncio.Task] = []
        self._stop = asyncio.Event()

    # ----------------------------- публичные методы ----------------------------
    async def start(self) -> None:
        logger.info("HostIDS starting. agent_id=%s host=%s", self.agent_id, self.hostname)
        # запускаем сборщиков
        for col in self.collectors:
            self._tasks.append(asyncio.create_task(col.run(self.queue), name=f"collector:{col.name}"))

        # запуск пачкера/отправителя
        self._tasks.append(asyncio.create_task(self._batch_sender(), name="batch_sender"))
        # запуск нормализатора/правил
        self._tasks.append(asyncio.create_task(self._normalize_and_route(), name="normalize"))

    async def stop(self) -> None:
        self._stop.set()
        for col in self.collectors:
            try:
                col.stop()  # type: ignore[attr-defined]
            except Exception:
                pass
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        logger.info("HostIDS stopped. metrics=%s", dataclasses.asdict(self.metrics))

    # ---------------------------- внутренние пайплайны -------------------------
    async def _normalize_and_route(self) -> None:
        """
        Читает из очереди, нормализует, применяет правила, выполняет дедуп/лимит,
        прокидывает дальше в буфер отправки.
        """
        # внутренний буфер до sender
        self._buf: List[HostEvent] = []
        self._buf_lock = asyncio.Lock()

        while not self._stop.is_set():
            try:
                ev: HostEvent = await self.queue.get()
                self.metrics.produced += 1

                # нормализация
                ev.hostname = self.hostname
                ev.agent_id = self.agent_id
                if ev.event_time is None:
                    ev.event_time = utcnow()
                # размер полезной нагрузки (если есть файл/линия лога)
                if ev.extra:
                    size = len(json.dumps(ev.extra, ensure_ascii=False))
                    ev.payload_size = min(size, 10_000_000)

                # движок правил
                decision = self.rules.evaluate(ev)
                if decision:
                    _, ev = decision

                # дедуп и rate-limit
                key = stable_uid(
                    str(ev.agent_id), ev.event_time.isoformat(), ev.signature or "",
                    ev.file_hash or "", ev.process_name or "", ev.file_path or ""
                )
                if not self.dedup.check_and_remember(key):
                    self.metrics.deduped += 1
                    continue
                if not self.bucket.allow():
                    self.metrics.throttled += 1
                    continue

                async with self._buf_lock:
                    self._buf.append(ev)

                self.queue.task_done()
            except asyncio.CancelledError:  # pragma: no cover
                break
            except Exception as ex:  # pragma: no cover
                logger.exception("normalize_and_route error: %s", ex)
                await asyncio.sleep(0.1)

    async def _batch_sender(self) -> None:
        """
        Пакетная отправка в sinks по времени/размеру.
        """
        last_flush = time.time()
        while not self._stop.is_set():
            try:
                await asyncio.sleep(0.1)
                to_send: List[HostEvent] = []
                async with getattr(self, "_buf_lock", asyncio.Lock()):
                    buf: List[HostEvent] = getattr(self, "_buf", [])
                    flush_time = (time.time() - last_flush) >= self.cfg.batch_interval_sec
                    flush_size = len(buf) >= self.cfg.batch_max
                    if buf and (flush_time or flush_size):
                        to_send = buf[: self.cfg.batch_max]
                        del buf[: self.cfg.batch_max]
                        last_flush = time.time()

                if not to_send:
                    continue

                # отправка во все sinks с ретраями по каждому
                for sink in self.sinks:
                    try:
                        await sink.send(to_send)
                        self.metrics.sent += len(to_send)
                    except Exception as ex:  # pragma: no cover
                        msg = f"{sink.__class__.__name__}: {ex}"
                        logger.error("send failed: %s", msg)
                        self.metrics.last_send_error = msg
                        # не прерываем; другой sink может принять
            except asyncio.CancelledError:  # pragma: no cover
                break
            except Exception as ex:  # pragma: no cover
                logger.exception("batch_sender error: %s", ex)
                await asyncio.sleep(0.2)

# ------------------------------------------------------------------------------
# Утилита сборки конфигурации из env/файла
# ------------------------------------------------------------------------------
def load_config_from_env(env: Dict[str, str] | None = None) -> AgentConfig:
    e = env or os.environ
    rules_json = e.get("HIDS_RULES_JSON", "[]")
    try:
        rules = [Rule(**r) for r in json.loads(rules_json)]
    except Exception:
        rules = []
    return AgentConfig(
        edr_base_url=e.get("EDR_BASE_URL", "http://127.0.0.1:8000").strip(),
        bearer_token=e.get("EDR_BEARER", "agent:00000000-0000-0000-0000-000000000000:deadbeef"),
        hmac_secret=e.get("EDR_HMAC_SECRET", "change-me"),
        batch_max=int(e.get("HIDS_BATCH_MAX", "500")),
        batch_interval_sec=int(e.get("HIDS_BATCH_INTERVAL", "3")),
        queue_max=int(e.get("HIDS_QUEUE_MAX", "20000")),
        dedup_ttl_sec=int(e.get("HIDS_DEDUP_TTL", "300")),
        rate_per_minute=int(e.get("HIDS_RATE_PER_MIN", "600")),
        file_sink_path=e.get("HIDS_FILE_SINK_PATH") or None,
        fim_paths=[p for p in (e.get("HIDS_FIM_PATHS", "")).split(",") if p.strip()],
        fim_include=[p for p in (e.get("HIDS_FIM_INCLUDE", "*")).split(",") if p.strip()],
        fim_exclude=[p for p in (e.get("HIDS_FIM_EXCLUDE", "")).split(",") if p.strip()],
        fim_interval_sec=int(e.get("HIDS_FIM_INTERVAL", "15")),
        syslog_path=e.get("HIDS_SYSLOG_PATH") or None,
        syslog_regex=e.get("HIDS_SYSLOG_REGEX") or None,
        proc_enable=e.get("HIDS_PROC_ENABLE", "false").lower() == "true",
        proc_regex=e.get("HIDS_PROC_REGEX", r".*(mimikatz|procdump|nc).*"),
        proc_cpu_pct_gte=float(e.get("HIDS_PROC_CPU", "85")),
        proc_rss_mb_gte=int(e.get("HIDS_PROC_RSS", "2048")),
        proc_interval_sec=int(e.get("HIDS_PROC_INTERVAL", "10")),
        rules=rules,
    )

# ------------------------------------------------------------------------------
# Пример программного запуска (использовать из сервиса/демона)
# ------------------------------------------------------------------------------
async def run_agent(config: AgentConfig) -> HostIDS:
    agent = HostIDS(config)
    await agent.start()
    return agent

# Если файл запускают напрямую, поднимем минимальный агент с FileSink
if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    cfg = load_config_from_env()
    if not cfg.file_sink_path:
        cfg.file_sink_path = str(Path("./host_ids_events.log").absolute())
    async def main():
        agent = await run_agent(cfg)
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            await agent.stop()
    asyncio.run(main())
