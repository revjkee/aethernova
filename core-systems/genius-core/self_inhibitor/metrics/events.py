# path: core-systems/genius_core/security/self_inhibitor/metrics/events.py
# License: MIT
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import hashlib
import io
import json
import os
import re
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Protocol, Sequence, Tuple

# ---------- Optional integrations (fail-safe) ----------
try:
    from opentelemetry import metrics as _otel_metrics  # type: ignore
except Exception:
    _otel_metrics = None  # type: ignore

try:
    # prometheus_client is optional; if absent, we expose manual export()
    from prometheus_client import Counter as _PCounter, Histogram as _PHistogram  # type: ignore
except Exception:
    _PCounter = None  # type: ignore
    _PHistogram = None  # type: ignore

try:
    from observability_core.logging.latency.latency_tracker import track_latency  # type: ignore
except Exception:
    @contextlib.asynccontextmanager
    async def track_latency(*args, **kwargs):
        yield

# ---------- ID & time helpers ----------
def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _utc_iso() -> str:
    return _utcnow().isoformat()

def _gen_id() -> str:
    # ULID if available in project, otherwise uuid4
    try:
        from omnimind.utils.idgen import new_ulid  # type: ignore
        return new_ulid()
    except Exception:
        return uuid.uuid4().hex

def _now_mono() -> float:
    return time.monotonic()

# ---------- Token bucket ----------
@dataclass
class _Bucket:
    capacity: int
    fill_rate: float
    tokens: float = field(init=False)
    ts: float = field(init=False)

    def __post_init__(self) -> None:
        self.tokens = float(self.capacity)
        self.ts = _now_mono()

    def take(self, n: int = 1) -> bool:
        now = _now_mono()
        dt = now - self.ts
        self.ts = now
        self.tokens = min(self.capacity, self.tokens + dt * self.fill_rate)
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False

# ---------- PII sanitizer ----------
_RE_EMAIL = re.compile(r"\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b", re.I)
_RE_PHONE = re.compile(r"(?:\+?\d{1,3}[\s\-\.]?)?(?:\(?\d{2,4}\)?[\s\-\.]?){2,4}\d{2,4}")
_RE_CC = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_URL = re.compile(r"\bhttps?://[^\s<>{}|\^`\\\[\]]+\b", re.I)

def _luhn_ok(s: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", s)]
    if len(digits) < 13:
        return False
    sm = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        sm += d
    return sm % 10 == 0

def _hash_stable(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()

def _sanitize_scalar(v: Any, placeholder: str) -> Any:
    if not isinstance(v, str):
        return v
    s = v
    s = _RE_EMAIL.sub(placeholder, s)
    s = _RE_PHONE.sub(placeholder, s)
    s = _RE_IP.sub(placeholder, s)
    s = _RE_URL.sub(placeholder, s)
    chunks = []
    last = 0
    for m in _RE_CC.finditer(s):
        if _luhn_ok(m.group(0)):
            chunks.append(s[last:m.start()] + placeholder)
            last = m.end()
    chunks.append(s[last:])
    return "".join(chunks)

def sanitize_obj(obj: Any, placeholder: str = "[REDACTED]") -> Any:
    """Recursively sanitize strings in dict/list/tuple; leaves non-strings untouched."""
    try:
        if isinstance(obj, dict):
            return {k: sanitize_obj(v, placeholder) for k, v in obj.items()}
        if isinstance(obj, list):
            return [sanitize_obj(x, placeholder) for x in obj]
        if isinstance(obj, tuple):
            return tuple(sanitize_obj(x, placeholder) for x in obj)
        return _sanitize_scalar(obj, placeholder)
    except Exception:
        return obj

# ---------- Event types ----------
class Severity:
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Action:
    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"

@dataclass
class Event:
    # Schema v1
    event_id: str
    ts: str
    kind: str                    # e.g., "decision", "redaction", "block", "policy_denied", "circuit_change"
    severity: str                # Severity.*
    action: Optional[str] = None # Action.* or None
    score: Optional[float] = None
    labels: Dict[str, str] = field(default_factory=dict)  # small cardinality labels (tenant, app, route, model, ...)
    data: Dict[str, Any] = field(default_factory=dict)    # detail payload; sanitized before emit if enabled
    traceparent: Optional[str] = None
    request_id: Optional[str] = None
    user_hash: Optional[str] = None                       # privacy-preserving hash of user id if provided
    schema: str = "genius.self_inhibitor.event.v1"

    @staticmethod
    def make(kind: str, *, severity: str, action: Optional[str] = None, score: Optional[float] = None,
             labels: Optional[Dict[str, str]] = None, data: Optional[Dict[str, Any]] = None,
             traceparent: Optional[str] = None, request_id: Optional[str] = None, user_id: Optional[str] = None) -> "Event":
        return Event(
            event_id=_gen_id(),
            ts=_utc_iso(),
            kind=kind,
            severity=severity,
            action=action,
            score=score,
            labels=dict(labels or {}),
            data=dict(data or {}),
            traceparent=traceparent,
            request_id=request_id,
            user_hash=_hash_stable(user_id) if user_id else None,
        )

# ---------- Config ----------
@dataclass
class BusConfig:
    queue_size: int = 4096
    flush_interval_sec: float = 0.1
    dedupe_window_sec: float = 2.0
    sanitize: bool = True
    sanitize_placeholder: str = "[REDACTED]"
    # sampling per kind: probability 0..1; default applies if kind not present
    default_sample: float = 1.0
    sample_by_kind: Dict[str, float] = field(default_factory=dict)
    # per-kind rate-limit tokens per second, capacity = 2x rps
    rps_by_kind: Dict[str, float] = field(default_factory=lambda: {"decision": 200.0, "redaction": 200.0, "block": 200.0})
    # sinks config
    jsonl_path: Optional[str] = None
    jsonl_rotate_bytes: int = 64 * 1024 * 1024
    enable_stdout: bool = True
    enable_prometheus: bool = True
    enable_opentelemetry: bool = True
    prometheus_namespace: str = "self_inhibitor"

# ---------- Sinks ----------
class Sink(Protocol):
    async def handle(self, ev: Event) -> None: ...
    async def start(self) -> None: ...
    async def stop(self) -> None: ...

class StdoutSink:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        return

    async def stop(self) -> None:
        return

    async def handle(self, ev: Event) -> None:
        async with self._lock:
            sys.stdout.write(json.dumps(asdict(ev), ensure_ascii=False) + "\n")
            sys.stdout.flush()

class JsonlSink:
    def __init__(self, path: str, rotate_bytes: int = 64 * 1024 * 1024) -> None:
        self.path = path
        self.rotate = int(rotate_bytes)
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)

    async def stop(self) -> None:
        return

    def _rotate_if_needed(self) -> None:
        try:
            if self.rotate > 0 and os.path.exists(self.path) and os.path.getsize(self.path) >= self.rotate:
                ts = datetime.now().strftime("%Y%m%d-%H%M%S")
                os.replace(self.path, f"{self.path}.{ts}.log")
        except Exception:
            pass

    async def handle(self, ev: Event) -> None:
        line = json.dumps(asdict(ev), ensure_ascii=False)
        async with self._lock:
            self._rotate_if_needed()
            # Use blocking write in thread to avoid event loop blocking on slow disks
            def _write():
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            await asyncio.to_thread(_write)

class PrometheusSink:
    """
    If prometheus_client is available, update real metrics.
    Otherwise, keep an in-memory dict and expose export() for manual scraping (optional).
    """
    def __init__(self, namespace: str = "self_inhibitor") -> None:
        self.ns = namespace
        self._inmem_counts: Dict[Tuple[str, str, str], int] = {}
        self._inmem_hist: List[Tuple[str, float]] = []
        self._pcounter = None
        self._phist = None

        if _PCounter and _PHistogram:
            self._pcounter = _PCounter(f"{self.ns}_events_total", "Total events", ["kind", "action", "severity"])
            self._phist = _PHistogram(f"{self.ns}_scores", "Decision score histogram", buckets=(0.0, 0.1, 0.25, 0.4, 0.6, 0.8, 1.0))

    async def start(self) -> None:
        return

    async def stop(self) -> None:
        return

    async def handle(self, ev: Event) -> None:
        kind = ev.kind
        action = ev.action or "none"
        sev = ev.severity
        if self._pcounter:
            try:
                self._pcounter.labels(kind=kind, action=action, severity=sev).inc()
                if ev.score is not None and self._phist:
                    self._phist.observe(float(ev.score))
                return
            except Exception:
                pass
        # fallback in-memory
        key = (kind, action, sev)
        self._inmem_counts[key] = self._inmem_counts.get(key, 0) + 1
        if ev.score is not None:
            self._inmem_hist.append((kind, float(ev.score)))

    def export_text(self) -> str:
        """Prometheus text format (only for fallback mode)."""
        lines = [f"# HELP {self.ns}_events_total Total events", f"# TYPE {self.ns}_events_total counter"]
        for (k, a, s), v in self._inmem_counts.items():
            lines.append(f'{self.ns}_events_total{{kind="{k}",action="{a}",severity="{s}"}} {v}')
        lines.append(f"# HELP {self.ns}_scores Decision score histogram (summary)")
        if self._inmem_hist:
            avg_by_kind: Dict[str, Tuple[float, int]] = {}
            for k, val in self._inmem_hist:
                sm, n = avg_by_kind.get(k, (0.0, 0))
                avg_by_kind[k] = (sm + val, n + 1)
            for k, (sm, n) in avg_by_kind.items():
                lines.append(f'{self.ns}_scores_avg{{kind="{k}"}} {sm / max(1, n)}')
        return "\n".join(lines) + "\n"

class OpenTelemetrySink:
    def __init__(self) -> None:
        self._meter = None
        self._ctr = None
        self._hist = None

    async def start(self) -> None:
        if _otel_metrics:
            try:
                self._meter = _otel_metrics.get_meter(__name__)
                self._ctr = self._meter.create_counter("self_inhibitor.events", unit="1")
                self._hist = self._meter.create_histogram("self_inhibitor.score", unit="1")
            except Exception:
                self._meter = None

    async def stop(self) -> None:
        return

    async def handle(self, ev: Event) -> None:
        if not self._meter:
            return
        try:
            attrs = {"kind": ev.kind, "action": ev.action or "none", "severity": ev.severity}
            self._ctr.add(1, attrs)  # type: ignore
            if ev.score is not None:
                self._hist.record(float(ev.score), attrs)  # type: ignore
        except Exception:
            pass

# ---------- Bus ----------
@dataclass
class _DedupeEntry:
    ts: float
    count: int

class EventsBus:
    def __init__(self, cfg: Optional[BusConfig] = None) -> None:
        self.cfg = cfg or BusConfig()
        self._queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=self.cfg.queue_size)
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._sinks: List[Sink] = []
        self._dedupe: Dict[str, _DedupeEntry] = {}
        self._buckets: Dict[str, _Bucket] = {}
        self.dropped_full = 0
        self.dropped_sample = 0
        self.dropped_rate = 0
        self.dropped_dedupe = 0

        # build sinks
        if self.cfg.enable_stdout:
            self._sinks.append(StdoutSink())
        if self.cfg.jsonl_path:
            self._sinks.append(JsonlSink(self.cfg.jsonl_path, self.cfg.jsonl_rotate_bytes))
        if self.cfg.enable_prometheus:
            self._sinks.append(PrometheusSink(self.cfg.prometheus_namespace))
        if self.cfg.enable_opentelemetry:
            self._sinks.append(OpenTelemetrySink())

    # ----- lifecycle -----
    async def start(self) -> None:
        if self._running:
            return
        for s in self._sinks:
            with contextlib.suppress(Exception):
                await s.start()
        self._running = True
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._task:
            self._task.cancel()
            with contextlib.suppress(Exception):
                await self._task
        for s in self._sinks:
            with contextlib.suppress(Exception):
                await s.stop()

    # ----- emit API -----
    def emit(self, ev: Event) -> bool:
        """
        Non-blocking best-effort emit from sync code.
        Returns True if queued, False if dropped (and increments counters).
        """
        return self._enqueue(ev, block=False)

    async def aemit(self, ev: Event) -> bool:
        """Async emit; may block briefly if queue has slack."""
        return self._enqueue(ev, block=True)

    # ----- helpers -----
    def _enqueue(self, ev: Event, *, block: bool) -> bool:
        if not self._should_keep(ev):
            return False
        if self.cfg.sanitize:
            ev.data = sanitize_obj(ev.data, self.cfg.sanitize_placeholder)
        try:
            if block:
                self._queue.put_nowait(ev)
            else:
                self._queue.put_nowait(ev)
            return True
        except asyncio.QueueFull:
            self.dropped_full += 1
            return False

    def _should_keep(self, ev: Event) -> bool:
        # sampling
        p = self.cfg.sample_by_kind.get(ev.kind, self.cfg.default_sample)
        if p < 1.0:
            import random
            if random.random() > max(0.0, min(1.0, p)):
                self.dropped_sample += 1
                return False
        # rate limit per kind
        rps = float(self.cfg.rps_by_kind.get(ev.kind, 0.0))
        if rps > 0.0:
            b = self._buckets.get(ev.kind)
            if b is None:
                b = _Bucket(capacity=max(1, int(rps * 2)), fill_rate=rps)
                self._buckets[ev.kind] = b
            if not b.take(1):
                self.dropped_rate += 1
                return False
        # dedupe within small window
        key = self._dedupe_key(ev)
        now = _now_mono()
        ent = self._dedupe.get(key)
        if ent and now - ent.ts < self.cfg.dedupe_window_sec:
            ent.count += 1
            self.dropped_dedupe += 1
            return False
        self._dedupe[key] = _DedupeEntry(ts=now, count=1)
        return True

    def _dedupe_key(self, ev: Event) -> str:
        # minimal stable signature: kind + action + severity + selected labels + hash of data keys
        lbl = ev.labels
        core = f"{ev.kind}|{ev.action or 'none'}|{ev.severity}|{lbl.get('tenant','')}|{lbl.get('app','')}|{lbl.get('route','')}"
        data_fingerprint = _hash_stable(json.dumps(sorted(list(ev.data.keys())), ensure_ascii=False))
        return core + "|" + data_fingerprint

    async def _run(self) -> None:
        while self._running:
            try:
                ev = await asyncio.wait_for(self._queue.get(), timeout=self.cfg.flush_interval_sec)
            except asyncio.TimeoutError:
                # periodic cleanup of dedupe map
                self._gc_dedupe()
                continue
            # fan-out
            async with track_latency("events_dispatch_ms", {"kind": ev.kind}):
                for s in self._sinks:
                    with contextlib.suppress(Exception):
                        await s.handle(ev)
            self._queue.task_done()

    def _gc_dedupe(self) -> None:
        if not self._dedupe:
            return
        cutoff = _now_mono() - self.cfg.dedupe_window_sec
        dead = [k for k, v in self._dedupe.items() if v.ts < cutoff]
        for k in dead[:4096]:
            self._dedupe.pop(k, None)

# ---------- Singleton & helpers ----------
_default_bus: Optional[EventsBus] = None

async def get_bus() -> EventsBus:
    global _default_bus
    if _default_bus is None:
        cfg = BusConfig(
            jsonl_path=os.getenv("SELF_INHIBITOR_EVENTS_JSONL") or None,
            enable_stdout=os.getenv("SELF_INHIBITOR_EVENTS_STDOUT", "1") == "1",
            enable_prometheus=os.getenv("SELF_INHIBITOR_EVENTS_PROM", "1") == "1",
            enable_opentelemetry=os.getenv("SELF_INHIBITOR_EVENTS_OTEL", "1") == "1",
        )
        _default_bus = EventsBus(cfg)
        await _default_bus.start()
    return _default_bus

def emit_event(kind: str, *, severity: str, action: Optional[str] = None, score: Optional[float] = None,
               labels: Optional[Dict[str, str]] = None, data: Optional[Dict[str, Any]] = None,
               traceparent: Optional[str] = None, request_id: Optional[str] = None, user_id: Optional[str] = None) -> bool:
    """
    Synchronous best-effort emit via singleton bus. Returns False if event was dropped locally.
    """
    ev = Event.make(kind, severity=severity, action=action, score=score, labels=labels, data=data,
                    traceparent=traceparent, request_id=request_id, user_id=user_id)
    bus = _default_bus
    if bus is None:
        # lazy, non-awaited init for sync contexts
        loop = None
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            pass
        if loop and not loop.is_closed():
            # schedule async init, but do not await
            asyncio.create_task(get_bus())
        else:
            # best-effort immediate bus
            _tmp = EventsBus()
            _tmp.emit(ev)
            return True
    return (_default_bus.emit(ev) if _default_bus else True)

async def aemit_event(kind: str, *, severity: str, action: Optional[str] = None, score: Optional[float] = None,
                      labels: Optional[Dict[str, str]] = None, data: Optional[Dict[str, Any]] = None,
                      traceparent: Optional[str] = None, request_id: Optional[str] = None, user_id: Optional[str] = None) -> bool:
    ev = Event.make(kind, severity=severity, action=action, score=score, labels=labels, data=data,
                    traceparent=traceparent, request_id=request_id, user_id=user_id)
    bus = await get_bus()
    return await bus.aemit(ev)

# ---------- High-level adapters ----------
def emit_decision(*, action: str, score: float, categories: Dict[str, float], reason: str,
                  severity: str, labels: Optional[Dict[str, str]] = None,
                  traceparent: Optional[str] = None, request_id: Optional[str] = None,
                  user_id: Optional[str] = None) -> bool:
    data = {"categories": categories, "reason": reason}
    return emit_event("decision", severity=severity, action=action, score=score,
                      labels=labels, data=data, traceparent=traceparent, request_id=request_id, user_id=user_id)

def emit_redaction(*, count: int, labels: Optional[Dict[str, str]] = None,
                   traceparent: Optional[str] = None, request_id: Optional[str] = None) -> bool:
    return emit_event("redaction", severity=Severity.LOW, action=Action.REDACT, score=None,
                      labels=labels, data={"count": int(count)}, traceparent=traceparent, request_id=request_id)

def emit_block(*, reason: str, labels: Optional[Dict[str, str]] = None,
               traceparent: Optional[str] = None, request_id: Optional[str] = None) -> bool:
    return emit_event("block", severity=Severity.HIGH, action=Action.BLOCK, score=1.0,
                      labels=labels, data={"reason": reason}, traceparent=traceparent, request_id=request_id)

def emit_policy_denied(*, policy: str, why: str, labels: Optional[Dict[str, str]] = None,
                       traceparent: Optional[str] = None, request_id: Optional[str] = None) -> bool:
    return emit_event("policy_denied", severity=Severity.MEDIUM, action="deny", score=None,
                      labels=labels, data={"policy": policy, "why": why}, traceparent=traceparent, request_id=request_id)

def emit_circuit_change(*, name: str, old: str, new: str, labels: Optional[Dict[str, str]] = None) -> bool:
    return emit_event("circuit_change", severity=Severity.MEDIUM, action="state",
                      score=None, labels={**(labels or {}), "circuit": name}, data={"old": old, "new": new})

# ---------- Example run ----------
if __name__ == "__main__":
    async def demo():
        bus = await get_bus()
        emit_decision(action=Action.REDACT, score=0.62, categories={"PII": 0.8, "TOXICITY": 0.2},
                      reason="PII detected", severity=Severity.MEDIUM,
                      labels={"tenant": "acme", "app": "genius", "model": "guard-v1"})
        emit_redaction(count=3, labels={"tenant": "acme"})
        emit_block(reason="self_harm_high", labels={"tenant": "acme"})
        await asyncio.sleep(0.2)
        await bus.stop()
    asyncio.run(demo())
