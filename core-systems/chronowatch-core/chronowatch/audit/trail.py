# chronowatch/ audit/ trail.py
from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import hmac
import json
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Protocol, Sequence, Tuple

# -------- Optional deps (graceful degradation) --------
try:
    import asyncpg  # type: ignore
except Exception:  # pragma: no cover
    asyncpg = None  # type: ignore

try:
    from aiokafka import AIOKafkaProducer  # type: ignore
except Exception:  # pragma: no cover
    AIOKafkaProducer = None  # type: ignore

try:
    from opentelemetry.trace import get_current_span  # type: ignore
except Exception:  # pragma: no cover
    def get_current_span():  # type: ignore
        class _Noop:
            def get_span_context(self):  # type: ignore
                class _Ctx:
                    trace_id = 0
                    span_id = 0
                return _Ctx()
        return _Noop()

# ----------------------------- Logging -----------------------------
logger = logging.getLogger("chronowatch.audit")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(_h)
logger.setLevel(os.getenv("AUDIT_LOG_LEVEL", "INFO").upper())

# ----------------------------- Config ------------------------------
def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "y", "on")

def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    try:
        return int(v) if v is not None else default
    except Exception:
        return default

def _env_list(name: str, default: str) -> List[str]:
    raw = os.getenv(name, default)
    return [s.strip() for s in raw.split(",") if s.strip()]

AUDIT_ENABLED = _env_bool("AUDIT_ENABLED", True)
AUDIT_BATCH_SIZE = _env_int("AUDIT_BATCH_SIZE", 200)
AUDIT_BATCH_INTERVAL_MS = _env_int("AUDIT_BATCH_INTERVAL_MS", 500)
AUDIT_QUEUE_MAX = _env_int("AUDIT_QUEUE_MAX", 10_000)
AUDIT_DROP_OLDEST = _env_bool("AUDIT_DROP_OLDEST", True)
AUDIT_HMAC_SECRET = os.getenv("AUDIT_HMAC_SECRET")  # strongly recommended in prod
AUDIT_PII_KEYS = set(_env_list("AUDIT_PII_KEYS", "password,token,authorization,set-cookie,secret,api_key"))
AUDIT_PII_PATTERNS = [
    re.compile(r"([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})"),  # emails
    re.compile(r"\b(\d{4}[-\s]?){3}\d{4}\b"),  # naive CC number pattern
]
AUDIT_REDACTION = os.getenv("AUDIT_REDACTION", "[REDACTED]")
AUDIT_DEDUP_TTL_SEC = _env_int("AUDIT_DEDUP_TTL_SEC", 60)
AUDIT_STREAM_KEY = os.getenv("AUDIT_STREAM_KEY", "org_id")  # chain key dimension

# Sinks
AUDIT_SINK = os.getenv("AUDIT_SINK", "file").lower()  # file|postgres|kafka|multi
AUDIT_FILE_PATH = os.getenv("AUDIT_FILE_PATH", "./audit.log.jsonl")
AUDIT_PG_DSN = os.getenv("AUDIT_PG_DSN")  # e.g., postgresql://user:pass@host:5432/db
AUDIT_KAFKA_BOOTSTRAP = os.getenv("AUDIT_KAFKA_BOOTSTRAP")  # host:port
AUDIT_KAFKA_TOPIC = os.getenv("AUDIT_KAFKA_TOPIC", "chronowatch.audit")

# ----------------------------- Types -------------------------------
class Severity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"

class Outcome(str, Enum):
    SUCCESS = "SUCCESS"
    DENY = "DENY"
    ERROR = "ERROR"

# Core event (canonical schema)
@dataclass
class AuditEvent:
    # Identity and request context
    event_id: str
    ts: str
    category: str
    action: str
    actor_id: Optional[str] = None
    actor_org_id: Optional[str] = None
    actor_roles: Tuple[str, ...] = field(default_factory=tuple)
    request_id: Optional[str] = None
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None

    # Domain object (subject) and outcome
    subject_type: Optional[str] = None
    subject_id: Optional[str] = None
    resource: Optional[str] = None
    outcome: Outcome = Outcome.SUCCESS
    severity: Severity = Severity.INFO
    reason: Optional[str] = None

    # Arbitrary structured metadata (will be sanitized)
    meta: Dict[str, Any] = field(default_factory=dict)

    # Tamper-evident fields
    stream_key: Optional[str] = None          # e.g., org_id for per-tenant chain
    chain_prev_hash: Optional[str] = None     # previous chain hash (hex)
    content_hash: Optional[str] = None        # sha256 over sanitized content
    chain_hash: Optional[str] = None          # sha256(prev_hash + content_hash)
    signature: Optional[str] = None           # HMAC(secret, chain_hash)

# ----------------------------- Redaction ---------------------------
def _redact_value(val: Any) -> Any:
    if isinstance(val, str):
        red = val
        for pat in AUDIT_PII_PATTERNS:
            red = pat.sub(AUDIT_REDACTION, red)
        return red
    if isinstance(val, (dict, list, tuple)):
        return _redact(val)
    return val

def _redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            lk = str(k).lower()
            if lk in AUDIT_PII_KEYS:
                out[k] = AUDIT_REDACTION
            else:
                out[k] = _redact_value(v)
        return out
    if isinstance(obj, list):
        return [_redact_value(x) for x in obj]
    if isinstance(obj, tuple):
        return tuple(_redact_value(x) for x in obj)
    return obj

# ------------------------ Canonical serialization -------------------
def _canonical_json(payload: Mapping[str, Any]) -> str:
    # Sorted keys, stable separators, no gap spaces, ensure_ascii False
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

# -------------------------- Chain state store -----------------------
class ChainState(Protocol):
    async def get_prev(self, stream_key: str) -> Optional[str]: ...
    async def set_prev(self, stream_key: str, chain_hash: str) -> None: ...

class InMemoryChainState:
    def __init__(self) -> None:
        self._state: Dict[str, str] = {}

    async def get_prev(self, stream_key: str) -> Optional[str]:
        return self._state.get(stream_key)

    async def set_prev(self, stream_key: str, chain_hash: str) -> None:
        self._state[stream_key] = chain_hash

# ----------------------------- Dedup cache --------------------------
class DedupCache:
    def __init__(self, ttl_sec: int) -> None:
        self.ttl = ttl_sec
        self._store: Dict[str, float] = {}

    def seen_recently(self, key: str) -> bool:
        now = time.time()
        ts = self._store.get(key)
        if ts and (now - ts) < self.ttl:
            return True
        self._store[key] = now
        # GC occasionally
        if len(self._store) > 10000:
            for k, v in list(self._store.items())[:5000]:
                if (now - v) >= self.ttl:
                    self._store.pop(k, None)
        return False

# ------------------------------- Sinks --------------------------------
class AuditSink(Protocol):
    async def write(self, batch: Sequence[AuditEvent]) -> None: ...
    async def close(self) -> None: ...

class JsonlFileSink:
    def __init__(self, path: str) -> None:
        self.path = path
        self._fp = open(self.path, "a", encoding="utf-8", buffering=1)

    async def write(self, batch: Sequence[AuditEvent]) -> None:
        for ev in batch:
            self._fp.write(_canonical_json(dataclasses.asdict(ev)) + "\n")
        self._fp.flush()

    async def close(self) -> None:
        try:
            self._fp.close()
        except Exception:
            pass

PG_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS audit_trail (
  event_id TEXT PRIMARY KEY,
  ts TIMESTAMPTZ NOT NULL,
  category TEXT NOT NULL,
  action TEXT NOT NULL,
  actor_id TEXT,
  actor_org_id TEXT,
  actor_roles TEXT[],
  request_id TEXT,
  client_ip TEXT,
  user_agent TEXT,
  trace_id TEXT,
  span_id TEXT,
  subject_type TEXT,
  subject_id TEXT,
  resource TEXT,
  outcome TEXT NOT NULL,
  severity TEXT NOT NULL,
  reason TEXT,
  meta JSONB,
  stream_key TEXT,
  chain_prev_hash TEXT,
  content_hash TEXT NOT NULL,
  chain_hash TEXT NOT NULL,
  signature TEXT
);
"""

class PostgresSink:
    def __init__(self, dsn: str) -> None:
        if asyncpg is None:
            raise RuntimeError("asyncpg is required for Postgres sink")
        self.dsn = dsn
        self._pool: Optional[Any] = None

    async def _ensure(self) -> None:
        if self._pool is None:
            self._pool = await asyncpg.create_pool(self.dsn, min_size=1, max_size=5)
            async with self._pool.acquire() as conn:
                await conn.execute(PG_CREATE_SQL)

    async def write(self, batch: Sequence[AuditEvent]) -> None:
        await self._ensure()
        assert self._pool is not None
        rows = [
            (
                ev.event_id, ev.ts, ev.category, ev.action, ev.actor_id, ev.actor_org_id,
                list(ev.actor_roles) if ev.actor_roles else None, ev.request_id, ev.client_ip, ev.user_agent,
                ev.trace_id, ev.span_id, ev.subject_type, ev.subject_id, ev.resource,
                ev.outcome.value, ev.severity.value, ev.reason, json.dumps(ev.meta, ensure_ascii=False),
                ev.stream_key, ev.chain_prev_hash, ev.content_hash, ev.chain_hash, ev.signature
            )
            for ev in batch
        ]
        sql = """
        INSERT INTO audit_trail (event_id, ts, category, action, actor_id, actor_org_id, actor_roles,
                                 request_id, client_ip, user_agent, trace_id, span_id, subject_type,
                                 subject_id, resource, outcome, severity, reason, meta, stream_key,
                                 chain_prev_hash, content_hash, chain_hash, signature)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19::jsonb,$20,$21,$22,$23,$24)
        ON CONFLICT (event_id) DO NOTHING
        """
        async with self._pool.acquire() as conn:
            await conn.executemany(sql, rows)

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()
            self._pool = None

class KafkaSink:
    def __init__(self, bootstrap: str, topic: str) -> None:
        if AIOKafkaProducer is None:
            raise RuntimeError("aiokafka is required for Kafka sink")
        self.topic = topic
        self._producer = AIOKafkaProducer(bootstrap_servers=bootstrap)
        self._started = False

    async def _ensure(self) -> None:
        if not self._started:
            await self._producer.start()
            self._started = True

    async def write(self, batch: Sequence[AuditEvent]) -> None:
        await self._ensure()
        for ev in batch:
            payload = _canonical_json(dataclasses.asdict(ev)).encode("utf-8")
            await self._producer.send_and_wait(self.topic, payload)

    async def close(self) -> None:
        if self._started:
            await self._producer.stop()
            self._started = False

class MultiSink:
    def __init__(self, sinks: Sequence[AuditSink]) -> None:
        self.sinks = list(sinks)

    async def write(self, batch: Sequence[AuditEvent]) -> None:
        errors: List[str] = []
        for s in self.sinks:
            try:
                await s.write(batch)
            except Exception as e:
                errors.append(f"{s.__class__.__name__}: {e!r}")
        if errors:
            raise RuntimeError("; ".join(errors))

    async def close(self) -> None:
        for s in self.sinks:
            try:
                await s.close()
            except Exception:
                pass

# --------------------------- Audit Manager ---------------------------
class AuditTrail:
    def __init__(
        self,
        sink: AuditSink,
        chain_state: Optional[ChainState] = None,
        enabled: bool = True,
        batch_size: int = 200,
        batch_interval_ms: int = 500,
        queue_max: int = 10_000,
        drop_oldest: bool = True,
        hmac_secret: Optional[str] = None,
        dedup_ttl_sec: int = 60,
    ) -> None:
        self.enabled = enabled
        self.sink = sink
        self.chain = chain_state or InMemoryChainState()
        self.batch_size = batch_size
        self.batch_interval_ms = batch_interval_ms
        self.queue: "asyncio.Queue[AuditEvent]" = asyncio.Queue(maxsize=queue_max)
        self.drop_oldest = drop_oldest
        self.hmac_secret = hmac_secret.encode() if hmac_secret else None
        self._task: Optional[asyncio.Task] = None
        self._stopped = asyncio.Event()
        self._dedup = DedupCache(dedup_ttl_sec)

    @staticmethod
    def from_env() -> "AuditTrail":
        # Build sink
        sink: AuditSink
        if AUDIT_SINK == "postgres" and AUDIT_PG_DSN:
            sink = PostgresSink(AUDIT_PG_DSN)
        elif AUDIT_SINK == "kafka" and AUDIT_KAFKA_BOOTSTRAP:
            sink = KafkaSink(AUDIT_KAFKA_BOOTSTRAP, AUDIT_KAFKA_TOPIC)
        elif AUDIT_SINK == "multi":
            sinks: List[AuditSink] = []
            if AUDIT_PG_DSN:
                sinks.append(PostgresSink(AUDIT_PG_DSN))
            if AUDIT_KAFKA_BOOTSTRAP:
                sinks.append(KafkaSink(AUDIT_KAFKA_BOOTSTRAP, AUDIT_KAFKA_TOPIC))
            sinks.append(JsonlFileSink(AUDIT_FILE_PATH))
            sink = MultiSink(sinks)
        else:
            sink = JsonlFileSink(AUDIT_FILE_PATH)

        at = AuditTrail(
            sink=sink,
            enabled=AUDIT_ENABLED,
            batch_size=AUDIT_BATCH_SIZE,
            batch_interval_ms=AUDIT_BATCH_INTERVAL_MS,
            queue_max=AUDIT_QUEUE_MAX,
            drop_oldest=AUDIT_DROP_OLDEST,
            hmac_secret=AUDIT_HMAC_SECRET,
            dedup_ttl_sec=AUDIT_DEDUP_TTL_SEC,
        )
        at.start()
        if not AUDIT_HMAC_SECRET:
            logger.warning("AUDIT_HMAC_SECRET is not set; signatures will be empty")
        return at

    def start(self) -> None:
        if self._task is None:
            self._stopped.clear()
            self._task = asyncio.create_task(self._worker(), name="audit-worker")

    async def stop(self) -> None:
        self._stopped.set()
        if self._task:
            await self._task
        await self.sink.close()

    async def _worker(self) -> None:
        batch: List[AuditEvent] = []
        last_flush = time.time()
        while not self._stopped.is_set():
            timeout = self.batch_interval_ms / 1000.0
            try:
                ev = await asyncio.wait_for(self.queue.get(), timeout=timeout)
                batch.append(ev)
                if len(batch) >= self.batch_size:
                    await self._flush(batch)
                    batch.clear()
                    last_flush = time.time()
            except asyncio.TimeoutError:
                if batch and (time.time() - last_flush) >= timeout:
                    await self._flush(batch)
                    batch.clear()
                    last_flush = time.time()
            except Exception as e:
                logger.exception("Audit worker error: %r", e)

        # Drain on stop
        try:
            drain: List[AuditEvent] = []
            while not self.queue.empty():
                drain.append(self.queue.get_nowait())
                if len(drain) >= self.batch_size:
                    await self._flush(drain)
                    drain.clear()
            if drain:
                await self._flush(drain)
        except Exception as e:
            logger.exception("Audit drain error: %r", e)

    async def _flush(self, batch: List[AuditEvent]) -> None:
        if not batch:
            return
        try:
            await self.sink.write(batch)
        except Exception as e:
            logger.exception("Audit sink write failed; will retry once: %r", e)
            await asyncio.sleep(0.5)
            await self.sink.write(batch)

    async def emit(self, ev: AuditEvent) -> None:
        if not self.enabled:
            return

        # Dedup (best-effort)
        dedup_key = f"{ev.category}:{ev.action}:{ev.actor_id}:{ev.subject_type}:{ev.subject_id}:{ev.request_id}"
        if self._dedup.seen_recently(dedup_key):
            return

        # Sanitize/prepare
        self._prepare_event(ev)

        # Backpressure policy
        try:
            self.queue.put_nowait(ev)
        except asyncio.QueueFull:
            if self.drop_oldest:
                try:
                    _ = self.queue.get_nowait()
                except Exception:
                    pass
                self.queue.put_nowait(ev)
            else:
                # Block until there is space
                await self.queue.put(ev)

    def _prepare_event(self, ev: AuditEvent) -> None:
        # Normalize timestamps
        if not ev.ts:
            ev.ts = datetime.utcnow().replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        # Stream key for chaining
        if not ev.stream_key:
            ev.stream_key = getattr(ev, AUDIT_STREAM_KEY, None) or ev.actor_org_id or "global"

        # Sanitize meta
        ev.meta = _sanitize_meta(ev.meta)

        # Attach OTel if present
        try:
            ctx = get_current_span().get_span_context()
            if getattr(ctx, "trace_id", 0):
                ev.trace_id = f"{ctx.trace_id:032x}"
                ev.span_id = f"{ctx.span_id:016x}"
        except Exception:
            pass

        # Compute content hash over sanitized, canonical payload (without chain/signature fields)
        content = _canonical_json(_event_content_for_hash(ev)).encode("utf-8")
        ev.content_hash = _sha256_hex(content)

        # Chain
        # NOTE: synchronous wait; acceptable as in-process state
        prev = asyncio.get_event_loop().run_until_complete(self.chain.get_prev(ev.stream_key)) if asyncio.get_event_loop().is_running() is False else None
        # If loop is running, do it in a slightly hacky way
        async def _get_prev_async() -> Optional[str]:
            return await self.chain.get_prev(ev.stream_key or "global")
        if prev is None:
            # running loop path
            prev = asyncio.get_event_loop().create_task(_get_prev_async())
            # we cannot await here synchronously; instead, set prev later in emit if needed
        # handle both path variants
        if isinstance(prev, asyncio.Task):
            # schedule set later when available
            def _set_chain(task: asyncio.Task) -> None:
                try:
                    p = task.result()
                except Exception:
                    p = None
                self._finalize_chain(ev, p)
            prev.add_done_callback(_set_chain)
        else:
            self._finalize_chain(ev, prev)

    def _finalize_chain(self, ev: AuditEvent, prev_hash: Optional[str]) -> None:
        ev.chain_prev_hash = prev_hash
        basis = ((prev_hash or "").encode("utf-8")) + (ev.content_hash or "").encode("utf-8")
        ev.chain_hash = _sha256_hex(basis)
        if self.hmac_secret:
            ev.signature = hmac.new(self.hmac_secret, ev.chain_hash.encode("utf-8"), hashlib.sha256).hexdigest()

        # Update chain state asynchronously (fire and forget)
        async def _save_chain() -> None:
            await self.chain.set_prev(ev.stream_key or "global", ev.chain_hash or "")
        try:
            asyncio.create_task(_save_chain())
        except RuntimeError:
            # If no running loop (sync context), create new loop just for this (rare)
            loop = asyncio.new_event_loop()
            loop.run_until_complete(_save_chain())
            loop.close()

# ------------------------- Sanitization helpers ---------------------
def _sanitize_meta(meta: Mapping[str, Any]) -> Dict[str, Any]:
    # Enforce limits to prevent abuse
    MAX_KEYS = 128
    MAX_LEN = 4096  # per string
    if not isinstance(meta, Mapping):
        return {}
    # Shallow copy
    cleaned: Dict[str, Any] = {}
    for idx, (k, v) in enumerate(meta.items()):
        if idx >= MAX_KEYS:
            break
        if isinstance(v, str) and len(v) > MAX_LEN:
            v = v[:MAX_LEN] + "…"
        cleaned[str(k)] = v
    return _redact(cleaned)  # deep redact

def _event_content_for_hash(ev: AuditEvent) -> Dict[str, Any]:
    # Exclude chain/signature fields to avoid self-reference
    data = dataclasses.asdict(ev).copy()
    for k in ("chain_prev_hash", "content_hash", "chain_hash", "signature"):
        data.pop(k, None)
    return data

# --------------------------- Convenience API ------------------------
def _now_iso() -> str:
    return datetime.utcnow().replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")

def new_event(
    *,
    category: str,
    action: str,
    actor_id: Optional[str] = None,
    actor_org_id: Optional[str] = None,
    actor_roles: Optional[Iterable[str]] = None,
    request_id: Optional[str] = None,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    subject_type: Optional[str] = None,
    subject_id: Optional[str] = None,
    resource: Optional[str] = None,
    outcome: Outcome = Outcome.SUCCESS,
    severity: Severity = Severity.INFO,
    reason: Optional[str] = None,
    meta: Optional[Mapping[str, Any]] = None,
) -> AuditEvent:
    return AuditEvent(
        event_id=str(uuid.uuid4()),
        ts=_now_iso(),
        category=category,
        action=action,
        actor_id=actor_id,
        actor_org_id=actor_org_id,
        actor_roles=tuple(actor_roles) if actor_roles else tuple(),
        request_id=request_id,
        client_ip=client_ip,
        user_agent=user_agent,
        subject_type=subject_type,
        subject_id=subject_id,
        resource=resource,
        outcome=outcome,
        severity=severity,
        reason=reason,
        meta=dict(meta or {}),
    )

# --------------- FastAPI/Starlette integration (optional) -----------
try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import Response
    from starlette import status as http_status

    class AuditMiddleware(BaseHTTPMiddleware):
        """
        Logs one audit entry per HTTP request (success/deny/error).
        Expects request.state.auth (from your auth middleware) with fields:
          subject (user id), org_id, roles
        """

        def __init__(self, app, trail: Optional[AuditTrail] = None) -> None:
            super().__init__(app)
            self.trail = trail or AuditTrail.from_env()

        async def dispatch(self, request: Request, call_next):
            if not AUDIT_ENABLED:
                return await call_next(request)

            t0 = time.perf_counter()
            rid = getattr(request.state, "request_id", None) or request.headers.get("X-Request-ID")
            auth = getattr(request.state, "auth", None)
            actor_id = getattr(auth, "subject", None)
            actor_org_id = getattr(auth, "org_id", None)
            actor_roles = tuple(getattr(auth, "roles", ()) or ())

            try:
                response: Response = await call_next(request)
                outcome = Outcome.SUCCESS if response.status_code < 400 else Outcome.DENY
                reason = None
            except Exception as e:
                response = Response(status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR)
                outcome = Outcome.ERROR
                reason = str(e)

            dur_ms = int((time.perf_counter() - t0) * 1000)
            meta = {
                "method": request.method,
                "path": request.url.path,
                "query": str(request.url.query)[:1024],
                "status": response.status_code,
                "duration_ms": dur_ms,
            }
            ev = new_event(
                category="http",
                action="request",
                actor_id=actor_id,
                actor_org_id=actor_org_id,
                actor_roles=actor_roles,
                request_id=rid,
                client_ip=_client_ip(request),
                user_agent=request.headers.get("user-agent"),
                subject_type="route",
                subject_id=request.url.path,
                resource=str(request.url),
                outcome=outcome,
                severity=Severity.INFO if outcome is Outcome.SUCCESS else Severity.WARNING,
                reason=reason,
                meta=meta,
            )
            await self.trail.emit(ev)
            return response

    def _client_ip(request: "Request") -> Optional[str]:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
        return request.client.host if request.client else None

except Exception:
    AuditMiddleware = None  # type: ignore

# ------------------------- Global instance (opt) ---------------------
# Сразу создаём singleton при импорте, если это удобно приложению.
# Иначе создайте вручную: audit = AuditTrail.from_env()
audit: AuditTrail = AuditTrail.from_env()

# ------------------------------ Usage notes -------------------------
# Пример ручной записи события:
#   await audit.emit(new_event(
#       category="user",
#       action="login",
#       actor_id="u_123",
#       actor_org_id="org_1",
#       subject_type="session",
#       subject_id="sess_456",
#       outcome=Outcome.SUCCESS,
#       meta={"ip": "1.2.3.4"},
#   ))
#
# FastAPI:
#   app = FastAPI()
#   from chronowatch.audit.trail import AuditMiddleware, audit
#   app.add_middleware(AuditMiddleware, trail=audit)
