# cybersecurity-core/cybersecurity/audit/trail.py
from __future__ import annotations

import asyncio
import contextvars
import dataclasses
import hashlib
import hmac
import json
import logging
import os
import re
import socket
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Literal, Optional, Tuple, Union

# -----------------------------------------------------------------------------
# Логирование
# -----------------------------------------------------------------------------
LOG = logging.getLogger("cybersecurity.audit.trail")
if not LOG.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

# -----------------------------------------------------------------------------
# Конфигурация из ENV
# -----------------------------------------------------------------------------
AUDIT_JSONL_PATH = os.getenv("AUDIT_JSONL_PATH", "./logs/audit/%Y-%m-%d.jsonl")  # strftime-шаблон
AUDIT_QUEUE_MAX = int(os.getenv("AUDIT_QUEUE_MAX", "10000"))
AUDIT_FLUSH_INTERVAL_SEC = float(os.getenv("AUDIT_FLUSH_INTERVAL_SEC", "0.50"))
AUDIT_MAX_ATTR_BYTES = int(os.getenv("AUDIT_MAX_ATTR_BYTES", "131072"))  # 128 KiB
AUDIT_HMAC_KEY = os.getenv("AUDIT_HMAC_KEY")  # если задан, включается подпись
HOSTNAME = os.getenv("HOSTNAME") or socket.gethostname()
ENVIRONMENT = os.getenv("ENVIRONMENT", "prod")

# -----------------------------------------------------------------------------
# Контекст (actor/tenant/correlation)
# -----------------------------------------------------------------------------
cv_actor_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("actor_id", default=None)
cv_actor_display: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("actor_display", default=None)
cv_actor_scopes: contextvars.ContextVar[List[str]] = contextvars.ContextVar("actor_scopes", default=[])
cv_tenant_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("tenant_id", default=None)
cv_correlation_id: contextvars.ContextVar[str] = contextvars.ContextVar("correlation_id", default=str(uuid.uuid4()))
cv_client_ip: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("client_ip", default=None)
cv_user_agent: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("user_agent", default=None)

def set_audit_context(
    *,
    actor_id: Optional[str] = None,
    actor_display: Optional[str] = None,
    actor_scopes: Optional[Iterable[str]] = None,
    tenant_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> None:
    if actor_id is not None:
        cv_actor_id.set(actor_id)
    if actor_display is not None:
        cv_actor_display.set(actor_display)
    if actor_scopes is not None:
        cv_actor_scopes.set([s for s in actor_scopes if s])
    if tenant_id is not None:
        cv_tenant_id.set(tenant_id)
    if correlation_id is not None:
        cv_correlation_id.set(correlation_id)
    if client_ip is not None:
        cv_client_ip.set(client_ip)
    if user_agent is not None:
        cv_user_agent.set(user_agent)

# -----------------------------------------------------------------------------
# Утилиты
# -----------------------------------------------------------------------------
JSON_SEPARATORS = (",", ":")
def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

SECRET_PATTERNS = [
    re.compile(r"(?i)\b(authorization)\s*:\s*bearer\s+[A-Za-z0-9\-._~+/=]+"),
    re.compile(r"(?i)\b(api[_-]?key|access[_-]?key|secret|password|passwd|pwd|token)\b\s*[:=]\s*[^\s,;]+"),
]

def redact(text: str) -> str:
    if not text:
        return text
    s = text
    for p in SECRET_PATTERNS:
        s = p.sub(lambda m: m.group(0).split(":")[0] + ": ***REDACTED***", s)
    return s

def clamp_bytes(d: Any, max_bytes: int) -> Any:
    # Ограничивает сериализуемые атрибуты по размеру
    try:
        raw = json.dumps(d, ensure_ascii=False, separators=JSON_SEPARATORS).encode("utf-8")
        if len(raw) <= max_bytes:
            return d
        return {"_truncated": True, "_approx_size": len(raw)}
    except Exception:
        return {"_error": "unserializable"}

def stable_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=JSON_SEPARATORS, sort_keys=True)

# -----------------------------------------------------------------------------
# Модель события аудита
# -----------------------------------------------------------------------------
Outcome = Literal["success", "failure"]
Severity = Literal["info", "low", "medium", "high", "critical"]

@dataclass(slots=True)
class ResourceRef:
    type: str
    id: str
    display: Optional[str] = None

@dataclass(slots=True)
class DiffEntry:
    path: str
    before: Any = None
    after: Any = None
    redacted: bool = False

def compute_diff(before: Optional[Dict[str, Any]], after: Optional[Dict[str, Any]], sensitive_keys: Iterable[str] = ()) -> List[DiffEntry]:
    before = before or {}
    after = after or {}
    sens = {k.lower() for k in sensitive_keys}
    keys = sorted(set(before.keys()) | set(after.keys()))
    out: List[DiffEntry] = []
    for k in keys:
        b = before.get(k)
        a = after.get(k)
        red = k.lower() in sens
        if b != a:
            out.append(DiffEntry(path=k, before="***REDACTED***" if red else b, after="***REDACTED***" if red else a, redacted=red))
    return out

@dataclass(slots=True)
class AuditEvent:
    # Метаданные
    id: str
    ts: str
    env: str
    host: str
    tenant_id: Optional[str]
    correlation_id: str

    # Субъект и действие
    actor_id: Optional[str]
    actor_display: Optional[str]
    actor_scopes: List[str]
    action: str                # e.g., "policy.update"
    category: str              # e.g., "access","change","security","config","data"
    severity: Severity

    # Контекст
    client_ip: Optional[str]
    user_agent: Optional[str]
    resource: Optional[ResourceRef]
    related: List[ResourceRef]
    outcome: Outcome
    http: Optional[Dict[str, Any]]      # method/path/status/latency_ms
    attributes: Dict[str, Any]          # произвольные данные (ограничены по размеру)
    diff: List[DiffEntry]               # ключевые изменения

    # Тампер-стойкость
    chain_id: str
    seq: int
    prev_hash: Optional[str]
    record_hash: Optional[str]
    hmac_sha256: Optional[str]

# -----------------------------------------------------------------------------
# Синки
# -----------------------------------------------------------------------------
class EventSink:
    async def emit(self, events: List[AuditEvent]) -> None:  # pragma: no cover
        raise NotImplementedError

class JsonlFileSink(EventSink):
    def __init__(self, path_template: str) -> None:
        self.path_template = path_template
        self._path: Optional[Path] = None
        self._fh: Optional[Any] = None
        self._lock = asyncio.Lock()

    def _current_path(self) -> Path:
        return Path(datetime.now().strftime(self.path_template)).resolve()

    async def _ensure_open(self) -> None:
        p = self._current_path()
        if self._path != p or self._fh is None:
            if self._fh:
                try:
                    self._fh.close()
                except Exception:
                    pass
            p.parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(p, "a", encoding="utf-8")
            self._path = p

    async def emit(self, events: List[AuditEvent]) -> None:
        async with self._lock:
            await self._ensure_open()
            assert self._fh is not None
            for ev in events:
                line = stable_json(asdict(ev)) + "\n"
                self._fh.write(line)
            self._fh.flush()

class SyslogSink(EventSink):
    def __init__(self, address: Union[str, Tuple[str, int]] = "/dev/log", facility: int = 1) -> None:
        import logging.handlers as h
        self._logger = logging.getLogger("audit.syslog")
        self._logger.setLevel(logging.INFO)
        handler = h.SysLogHandler(address=address, facility=facility)
        formatter = logging.Formatter("%(message)s")
        handler.setFormatter(formatter)
        self._logger.handlers = [handler]

    async def emit(self, events: List[AuditEvent]) -> None:
        for ev in events:
            self._logger.info(stable_json(asdict(ev)))

class PostgresSink(EventSink):
    """
    Опциональный sink (asyncpg). Таблица создаётся отдельно:
      CREATE SCHEMA IF NOT EXISTS cybersecurity;
      CREATE TABLE IF NOT EXISTS cybersecurity.audit_trail_jsonl(
        id UUID PRIMARY KEY,
        ts TIMESTAMPTZ NOT NULL,
        payload JSONB NOT NULL
      );
    """
    def __init__(self, dsn: str) -> None:
        try:
            import asyncpg  # type: ignore
        except Exception as e:  # noqa: BLE001
            raise RuntimeError("asyncpg is required for PostgresSink") from e
        self._dsn = dsn
        self._pool: Optional[Any] = None
        self._asyncpg = asyncpg  # type: ignore

    async def _ensure_pool(self) -> None:
        if self._pool is None:
            self._pool = await self._asyncpg.create_pool(dsn=self._dsn, min_size=1, max_size=4)

    async def emit(self, events: List[AuditEvent]) -> None:
        await self._ensure_pool()
        assert self._pool is not None
        payloads = [(uuid.UUID(ev.id), datetime.fromisoformat(ev.ts), json.loads(stable_json(asdict(ev)))) for ev in events]
        async with self._pool.acquire() as conn:
            await conn.executemany(
                "INSERT INTO cybersecurity.audit_trail_jsonl(id, ts, payload) VALUES($1,$2,$3) ON CONFLICT (id) DO NOTHING",
                payloads,
            )

# -----------------------------------------------------------------------------
# Основной класс AuditTrail
# -----------------------------------------------------------------------------
class AuditTrail:
    def __init__(
        self,
        sinks: Optional[List[EventSink]] = None,
        queue_max: int = AUDIT_QUEUE_MAX,
        flush_interval_sec: float = AUDIT_FLUSH_INTERVAL_SEC,
        hmac_key: Optional[str] = AUDIT_HMAC_KEY,
        chain_id: Optional[str] = None,
    ) -> None:
        self.sinks = sinks or [JsonlFileSink(AUDIT_JSONL_PATH)]
        self.queue: asyncio.Queue[AuditEvent] = asyncio.Queue(maxsize=queue_max)
        self.flush_interval = flush_interval_sec
        self._hmac_key = hmac_key.encode("utf-8") if hmac_key else None
        self._chain_id = chain_id or str(uuid.uuid4())
        self._seq = 0
        self._prev_hash: Optional[str] = None
        self._stop = asyncio.Event()
        self._consumer_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        self._stop.clear()
        self._consumer_task = asyncio.create_task(self._consumer(), name="audit-consumer")
        LOG.info("AuditTrail started chain_id=%s", self._chain_id)

    async def stop(self) -> None:
        self._stop.set()
        if self._consumer_task:
            self._consumer_task.cancel()
            with contextlib.suppress(Exception):
                await self._consumer_task
        # финальный флаш
        await self._flush([])

    async def _consumer(self) -> None:
        buf: List[AuditEvent] = []
        last_flush = time.monotonic()
        try:
            while not self._stop.is_set():
                timeout = self.flush_interval - (time.monotonic() - last_flush)
                try:
                    ev = await asyncio.wait_for(self.queue.get(), timeout=max(0.0, timeout))
                    self._attach_chain(ev)
                    buf.append(ev)
                except asyncio.TimeoutError:
                    pass

                if buf and (time.monotonic() - last_flush >= self.flush_interval or len(buf) >= 256):
                    await self._flush(buf)
                    buf = []
                    last_flush = time.monotonic()
        except asyncio.CancelledError:  # pragma: no cover
            pass
        finally:
            if buf:
                await self._flush(buf)

    def _attach_chain(self, ev: AuditEvent) -> None:
        self._seq += 1
        ev.chain_id = self._chain_id
        ev.seq = self._seq
        ev.prev_hash = self._prev_hash
        canon = stable_json({
            "id": ev.id,
            "ts": ev.ts,
            "actor_id": ev.actor_id,
            "action": ev.action,
            "category": ev.category,
            "severity": ev.severity,
            "tenant_id": ev.tenant_id,
            "correlation_id": ev.correlation_id,
            "resource": asdict(ev.resource) if ev.resource else None,
            "outcome": ev.outcome,
            "attributes": ev.attributes,
            "diff": [asdict(d) for d in ev.diff],
            "prev_hash": ev.prev_hash,
            "seq": ev.seq,
            "chain_id": ev.chain_id,
        })
        rh = hashlib.sha256(canon.encode("utf-8")).hexdigest()
        ev.record_hash = rh
        self._prev_hash = rh
        if self._hmac_key:
            ev.hmac_sha256 = hmac.new(self._hmac_key, canon.encode("utf-8"), hashlib.sha256).hexdigest()

    async def _flush(self, events: List[AuditEvent]) -> None:
        if not events:
            return
        for s in self.sinks:
            try:
                await s.emit(events)
            except Exception as e:  # noqa: BLE001
                LOG.warning("sink emit error: %s", e)

    # -- Публичное API --------------------------------------------------------

    async def log_event(
        self,
        *,
        action: str,
        category: str,
        severity: Severity = "info",
        outcome: Outcome = "success",
        resource: Optional[ResourceRef] = None,
        related: Optional[List[ResourceRef]] = None,
        http: Optional[Dict[str, Any]] = None,
        attributes: Optional[Dict[str, Any]] = None,
        before: Optional[Dict[str, Any]] = None,
        after: Optional[Dict[str, Any]] = None,
        sensitive_keys: Iterable[str] = (),
    ) -> str:
        ev = AuditEvent(
            id=str(uuid.uuid4()),
            ts=iso(utcnow()),
            env=ENVIRONMENT,
            host=HOSTNAME,
            tenant_id=cv_tenant_id.get(),
            correlation_id=cv_correlation_id.get(),
            actor_id=cv_actor_id.get(),
            actor_display=cv_actor_display.get(),
            actor_scopes=list(cv_actor_scopes.get() or []),
            action=action,
            category=category,
            severity=severity,
            client_ip=cv_client_ip.get(),
            user_agent=cv_user_agent.get(),
            resource=resource,
            related=related or [],
            outcome=outcome,
            http=http,
            attributes=clamp_bytes(attributes or {}, AUDIT_MAX_ATTR_BYTES),
            diff=compute_diff(before, after, sensitive_keys=sensitive_keys),
            chain_id="",
            seq=0,
            prev_hash=None,
            record_hash=None,
            hmac_sha256=None,
        )
        try:
            self.queue.put_nowait(ev)
        except asyncio.QueueFull:
            LOG.warning("audit queue full, dropping event action=%s", action)
        return ev.id

    # Контекст-менеджер спана (измерение и автологирование исключения)
    def span(
        self,
        *,
        action: str,
        category: str,
        severity: Severity = "info",
        resource: Optional[ResourceRef] = None,
        attributes: Optional[Dict[str, Any]] = None,
        sensitive_keys: Iterable[str] = (),
    ):
        return _AuditSpan(self, action, category, severity, resource, attributes or {}, sensitive_keys)

# -----------------------------------------------------------------------------
# Контекст-менеджер спана
# -----------------------------------------------------------------------------
class _AuditSpan:
    def __init__(
        self,
        at: AuditTrail,
        action: str,
        category: str,
        severity: Severity,
        resource: Optional[ResourceRef],
        attributes: Dict[str, Any],
        sensitive_keys: Iterable[str],
    ) -> None:
        self.at = at
        self.action = action
        self.category = category
        self.severity = severity
        self.resource = resource
        self.attributes = attributes
        self.sensitive_keys = sensitive_keys
        self._start = time.perf_counter()
        self._attrs: Dict[str, Any] = dict(attributes)

    async def __aenter__(self):
        self._start = time.perf_counter()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        latency_ms = int((time.perf_counter() - self._start) * 1000)
        http = None
        self._attrs["latency_ms"] = latency_ms
        if exc is None:
            await self.at.log_event(
                action=self.action,
                category=self.category,
                severity=self.severity,
                outcome="success",
                resource=self.resource,
                attributes=self._attrs,
                sensitive_keys=self.sensitive_keys,
            )
        else:
            await self.at.log_event(
                action=self.action,
                category=self.category,
                severity="high",
                outcome="failure",
                resource=self.resource,
                attributes={**self._attrs, "error": str(exc.__class__.__name__)},
                sensitive_keys=self.sensitive_keys,
            )

# -----------------------------------------------------------------------------
# ASGI middleware (совместимо с FastAPI/Starlette)
# -----------------------------------------------------------------------------
class AuditMiddleware:
    def __init__(self, app, audit: AuditTrail) -> None:
        self.app = app
        self.audit = audit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        method = scope.get("method")
        path = scope.get("path")
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        client = scope.get("client") or ("", 0)
        client_ip = client[0]
        user_agent = headers.get("user-agent")
        corr = headers.get("x-correlation-id") or str(uuid.uuid4())

        set_audit_context(
            correlation_id=corr,
            client_ip=client_ip,
            user_agent=user_agent,
            tenant_id=headers.get("x-tenant-id"),
            actor_id=headers.get("x-actor"),
            actor_display=headers.get("x-actor-name"),
            actor_scopes=(headers.get("x-scopes", "") or "").split(","),
        )

        status_code_holder = {"status": 0}
        start_ts = time.perf_counter()

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status_code_holder["status"] = int(message["status"])
            return await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
            latency_ms = int((time.perf_counter() - start_ts) * 1000)
            await self.audit.log_event(
                action=f"http.{method.lower()}",
                category="access",
                severity="info",
                outcome="success" if 200 <= status_code_holder["status"] < 400 else "failure",
                resource=ResourceRef(type="http", id=path),
                http={"method": method, "path": path, "status": status_code_holder["status"], "latency_ms": latency_ms},
                attributes={"headers": {k: redact(v) for k, v in headers.items() if k in ("x-request-id", "referer")}},
            )
        except Exception as e:
            latency_ms = int((time.perf_counter() - start_ts) * 1000)
            await self.audit.log_event(
                action=f"http.{method.lower()}",
                category="access",
                severity="high",
                outcome="failure",
                resource=ResourceRef(type="http", id=path),
                http={"method": method, "path": path, "status": status_code_holder["status"] or 500, "latency_ms": latency_ms},
                attributes={"error": str(e)},
            )
            raise

# -----------------------------------------------------------------------------
# Верификация цепочки JSONL
# -----------------------------------------------------------------------------
def verify_jsonl_chain(path: Union[str, Path], hmac_key: Optional[str] = None) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(str(p))
    prev: Optional[str] = None
    seq_prev = 0
    ok = True
    bad_lines: List[int] = []
    with p.open("r", encoding="utf-8") as fh:
        for i, line in enumerate(fh, start=1):
            try:
                ev = json.loads(line)
            except Exception:
                ok = False
                bad_lines.append(i)
                continue
            canon = json.dumps({
                "id": ev["id"],
                "ts": ev["ts"],
                "actor_id": ev.get("actor_id"),
                "action": ev["action"],
                "category": ev["category"],
                "severity": ev["severity"],
                "tenant_id": ev.get("tenant_id"),
                "correlation_id": ev["correlation_id"],
                "resource": ev.get("resource"),
                "outcome": ev["outcome"],
                "attributes": ev.get("attributes"),
                "diff": ev.get("diff"),
                "prev_hash": ev.get("prev_hash"),
                "seq": ev.get("seq"),
                "chain_id": ev.get("chain_id"),
            }, ensure_ascii=False, separators=JSON_SEPARATORS, sort_keys=True)
            rh = hashlib.sha256(canon.encode("utf-8")).hexdigest()
            if ev.get("prev_hash") != prev or ev.get("record_hash") != rh:
                ok = False
                bad_lines.append(i)
            if hmac_key and ev.get("hmac_sha256"):
                sig = hmac.new(hmac_key.encode("utf-8"), canon.encode("utf-8"), hashlib.sha256).hexdigest()
                if sig != ev["hmac_sha256"]:
                    ok = False
                    bad_lines.append(i)
            prev = ev.get("record_hash")
            seq_prev = ev.get("seq", 0)
    return {"ok": ok, "bad_lines": sorted(set(bad_lines))}

# -----------------------------------------------------------------------------
# Пример использования (CLI)
# -----------------------------------------------------------------------------
async def _demo() -> None:  # pragma: no cover
    at = AuditTrail()
    await at.start()
    set_audit_context(actor_id="user-123", actor_display="Alice", actor_scopes=["policies:write"], tenant_id="11111111-1111-1111-1111-111111111111")
    await at.log_event(
        action="policy.create",
        category="change",
        severity="medium",
        outcome="success",
        resource=ResourceRef(type="policy", id="p-42", display="Block Dangerous Powershell"),
        attributes={"version": "1.0.0", "note": "initial"},
        after={"name": "Block PS", "status": "active"},
        sensitive_keys=("secret",),
    )
    # span пример
    async with at.span(action="job.reconcile", category="operations", severity="info", resource=ResourceRef(type="job", id="sync-1")):
        await asyncio.sleep(0.1)
    await asyncio.sleep(1.0)

def main() -> None:  # pragma: no cover
    import argparse
    parser = argparse.ArgumentParser(description="Audit trail demo/verify")
    parser.add_argument("--verify", help="Verify a JSONL chain")
    args = parser.parse_args()
    if args.verify:
        print(json.dumps(verify_jsonl_chain(args.verify, AUDIT_HMAC_KEY), ensure_ascii=False, indent=2))
        return
    try:
        asyncio.run(_demo())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":  # pragma: no cover
    main()
