# agent_mash/core/escalation.py
# -*- coding: utf-8 -*-
"""
Industrial escalation core for agent_mash.

Design goals:
- Async-first, safe defaults
- Deterministic idempotency key (stable hashing)
- Deduplication + TTL
- Rate limiting to prevent alert storms
- Pluggable policy engine, state store, and sinks
- Backoff on transient sink failures
- Minimal dependencies (standard library only)

Note:
This module intentionally avoids depending on other internal modules to keep it
portable. Integrate via sinks and stores from your infrastructure.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import enum
import hashlib
import json
import logging
import random
import time
from collections import deque
from dataclasses import dataclass
from typing import (
    Any,
    Awaitable,
    Deque,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    Union,
)

logger = logging.getLogger(__name__)


class EscalationError(Exception):
    """Base exception for escalation subsystem."""


class PolicyError(EscalationError):
    """Raised when policy cannot evaluate."""


class SinkError(EscalationError):
    """Raised when a sink cannot deliver."""


class StoreError(EscalationError):
    """Raised when store operation fails."""


class Severity(enum.IntEnum):
    """
    Severity scale (ascending).
    """
    DEBUG = 10
    INFO = 20
    LOW = 30
    MEDIUM = 40
    HIGH = 50
    CRITICAL = 60


class Decision(enum.Enum):
    """
    Policy decision outcome.
    """
    DROP = "drop"            # discard silently
    LOG_ONLY = "log_only"    # record but do not notify
    NOTIFY = "notify"        # notify sinks
    ESCALATE = "escalate"    # notify sinks + increase urgency / widen audience


@dataclass(frozen=True)
class EscalationTarget:
    """
    A logical target for escalation routing. Your sinks can interpret this.
    """
    kind: str  # e.g. "team", "user", "channel", "oncall", "webhook"
    address: str  # e.g. "@alice", "sec-oncall", "#alerts", "https://..."
    meta: Dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclass(frozen=True)
class EscalationEvent:
    """
    Canonical escalation event.
    """
    name: str
    severity: Severity
    domain: str  # e.g. "identity-access-core", "observability-core"
    message: str

    actor: str = "system"
    correlation_id: Optional[str] = None
    trace_id: Optional[str] = None

    tags: Tuple[str, ...] = ()
    payload: Dict[str, Any] = dataclasses.field(default_factory=dict)

    created_at_epoch: float = dataclasses.field(default_factory=lambda: time.time())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "severity": int(self.severity),
            "severity_name": self.severity.name,
            "domain": self.domain,
            "message": self.message,
            "actor": self.actor,
            "correlation_id": self.correlation_id,
            "trace_id": self.trace_id,
            "tags": list(self.tags),
            "payload": self.payload,
            "created_at_epoch": self.created_at_epoch,
        }


@dataclass(frozen=True)
class EscalationDecision:
    decision: Decision
    targets: Tuple[EscalationTarget, ...] = ()
    reason: str = ""
    ttl_seconds: int = 300  # dedup TTL window for same key
    max_notifications: int = 1  # per TTL window
    escalate_by: int = 0  # e.g. widen severity by n steps (optional)
    extra: Dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclass(frozen=True)
class DeliveryAttempt:
    sink_name: str
    ok: bool
    error: Optional[str] = None
    latency_ms: Optional[int] = None


@dataclass(frozen=True)
class EscalationResult:
    key: str
    decision: EscalationDecision
    stored: bool
    delivered: Tuple[DeliveryAttempt, ...]
    suppressed: bool
    suppressed_reason: Optional[str] = None


class EscalationPolicy(Protocol):
    async def evaluate(self, event: EscalationEvent) -> EscalationDecision:
        ...


class EscalationSink(Protocol):
    """
    A sink is responsible for delivering notifications.

    `deliver()` should raise SinkError for known delivery failures.
    It may raise other exceptions; manager will treat as SinkError.
    """
    @property
    def name(self) -> str:
        ...

    async def deliver(
        self,
        event: EscalationEvent,
        decision: EscalationDecision,
        key: str,
    ) -> None:
        ...


class EscalationStore(Protocol):
    """
    Store persists dedup counters and optionally full audit record.
    """

    async def get_window(
        self,
        key: str,
    ) -> Optional[Dict[str, Any]]:
        ...

    async def put_window(
        self,
        key: str,
        value: Dict[str, Any],
        ttl_seconds: int,
    ) -> None:
        ...

    async def increment_window(
        self,
        key: str,
        ttl_seconds: int,
    ) -> int:
        """
        Atomically increments a counter for given key within TTL window.
        Returns the new counter value.
        """
        ...

    async def append_audit(
        self,
        record: Dict[str, Any],
    ) -> None:
        ...


@dataclass(frozen=True)
class RateLimitConfig:
    """
    Simple leaky-bucket rate limit.
    """
    max_events: int = 50
    per_seconds: int = 60


@dataclass(frozen=True)
class BackoffConfig:
    """
    Exponential backoff with jitter for sink delivery retries.
    """
    max_retries: int = 3
    base_delay_ms: int = 150
    max_delay_ms: int = 5_000
    jitter_ratio: float = 0.2


@dataclass(frozen=True)
class EscalationManagerConfig:
    """
    Manager configuration.
    """
    dedup_default_ttl_seconds: int = 300
    audit_enabled: bool = True
    rate_limit: RateLimitConfig = RateLimitConfig()
    backoff: BackoffConfig = BackoffConfig()
    delivery_timeout_seconds: int = 8
    strict_policy: bool = False  # if True: policy errors raise
    strict_store: bool = False   # if True: store errors raise
    strict_sink: bool = False    # if True: sink errors raise
    stable_hash_salt: str = "agent_mash.escalation.v1"


class InMemoryEscalationStore(EscalationStore):
    """
    In-memory store for local/dev and tests.
    Not suitable for multi-process deployments.
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._windows: Dict[str, Dict[str, Any]] = {}
        self._exp: Dict[str, float] = {}
        self._audit: List[Dict[str, Any]] = []

    async def _gc(self) -> None:
        now = time.time()
        expired = [k for k, t in self._exp.items() if t <= now]
        for k in expired:
            self._exp.pop(k, None)
            self._windows.pop(k, None)

    async def get_window(self, key: str) -> Optional[Dict[str, Any]]:
        async with self._lock:
            await self._gc()
            v = self._windows.get(key)
            if v is None:
                return None
            return dict(v)

    async def put_window(self, key: str, value: Dict[str, Any], ttl_seconds: int) -> None:
        async with self._lock:
            await self._gc()
            self._windows[key] = dict(value)
            self._exp[key] = time.time() + max(1, int(ttl_seconds))

    async def increment_window(self, key: str, ttl_seconds: int) -> int:
        async with self._lock:
            await self._gc()
            now = time.time()
            if key not in self._windows:
                self._windows[key] = {"count": 0, "first_seen": now}
                self._exp[key] = now + max(1, int(ttl_seconds))
            self._windows[key]["count"] = int(self._windows[key].get("count", 0)) + 1
            return int(self._windows[key]["count"])

    async def append_audit(self, record: Dict[str, Any]) -> None:
        async with self._lock:
            self._audit.append(dict(record))


class DefaultEscalationPolicy(EscalationPolicy):
    """
    A conservative default policy:
    - CRITICAL/HIGH -> ESCALATE to oncall + alerts channel
    - MEDIUM -> NOTIFY to alerts channel
    - LOW/INFO -> LOG_ONLY
    - DEBUG -> DROP
    """

    def __init__(
        self,
        alerts_channel: str = "#alerts",
        oncall: str = "oncall",
        domain_overrides: Optional[Mapping[str, Mapping[str, Any]]] = None,
    ) -> None:
        self._alerts_channel = alerts_channel
        self._oncall = oncall
        self._domain_overrides = dict(domain_overrides or {})

    async def evaluate(self, event: EscalationEvent) -> EscalationDecision:
        # Apply domain overrides if present
        ov = self._domain_overrides.get(event.domain, {})
        min_sev = ov.get("min_severity")
        if min_sev is not None:
            try:
                min_sev_int = int(min_sev)
            except Exception as e:
                raise PolicyError(f"Invalid min_severity override for domain={event.domain}: {e}") from e
            if int(event.severity) < min_sev_int:
                return EscalationDecision(decision=Decision.DROP, reason="below_domain_min_severity")

        if event.severity >= Severity.CRITICAL:
            return EscalationDecision(
                decision=Decision.ESCALATE,
                targets=(
                    EscalationTarget(kind="oncall", address=self._oncall),
                    EscalationTarget(kind="channel", address=self._alerts_channel),
                ),
                reason="critical",
                ttl_seconds=300,
                max_notifications=1,
            )
        if event.severity >= Severity.HIGH:
            return EscalationDecision(
                decision=Decision.ESCALATE,
                targets=(
                    EscalationTarget(kind="oncall", address=self._oncall),
                    EscalationTarget(kind="channel", address=self._alerts_channel),
                ),
                reason="high",
                ttl_seconds=300,
                max_notifications=1,
            )
        if event.severity >= Severity.MEDIUM:
            return EscalationDecision(
                decision=Decision.NOTIFY,
                targets=(EscalationTarget(kind="channel", address=self._alerts_channel),),
                reason="medium",
                ttl_seconds=300,
                max_notifications=2,
            )
        if event.severity >= Severity.LOW:
            return EscalationDecision(decision=Decision.LOG_ONLY, reason="low")
        if event.severity >= Severity.INFO:
            return EscalationDecision(decision=Decision.LOG_ONLY, reason="info")
        return EscalationDecision(decision=Decision.DROP, reason="debug")


class _LeakyBucket:
    """
    A minimal leaky bucket rate limiter for async contexts.
    """

    def __init__(self, cfg: RateLimitConfig) -> None:
        self._cfg = cfg
        self._lock = asyncio.Lock()
        self._events: Deque[float] = deque()

    async def allow(self) -> bool:
        async with self._lock:
            now = time.time()
            window = float(max(1, int(self._cfg.per_seconds)))
            cutoff = now - window
            while self._events and self._events[0] < cutoff:
                self._events.popleft()
            if len(self._events) >= int(self._cfg.max_events):
                return False
            self._events.append(now)
            return True


def _stable_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def compute_escalation_key(event: EscalationEvent, salt: str) -> str:
    """
    Compute a stable idempotency key for an event.

    The key must not include volatile fields like created_at_epoch.
    """
    base = {
        "salt": salt,
        "name": event.name,
        "severity": int(event.severity),
        "domain": event.domain,
        "message": event.message,
        "actor": event.actor,
        "correlation_id": event.correlation_id,
        "trace_id": event.trace_id,
        "tags": list(event.tags),
        "payload": event.payload,
    }
    raw = _stable_json(base).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


async def _with_timeout(coro: Awaitable[None], timeout_s: int) -> None:
    await asyncio.wait_for(coro, timeout=max(1, int(timeout_s)))


def _next_backoff_ms(attempt: int, cfg: BackoffConfig) -> int:
    # attempt starts at 1
    base = min(cfg.max_delay_ms, cfg.base_delay_ms * (2 ** max(0, attempt - 1)))
    jitter = int(base * cfg.jitter_ratio * random.random())
    return min(cfg.max_delay_ms, base + jitter)


class EscalationManager:
    """
    Orchestrates escalation flow: policy evaluation, suppression, delivery, audit.

    Thread safety:
    - safe for concurrent async calls within one event loop
    - store must provide atomic increment if shared across processes
    """

    def __init__(
        self,
        policy: EscalationPolicy,
        sinks: Sequence[EscalationSink],
        store: Optional[EscalationStore] = None,
        config: Optional[EscalationManagerConfig] = None,
    ) -> None:
        self._policy = policy
        self._sinks = list(sinks)
        self._store = store or InMemoryEscalationStore()
        self._cfg = config or EscalationManagerConfig()
        self._rate = _LeakyBucket(self._cfg.rate_limit)
        self._op_lock = asyncio.Lock()

    @property
    def config(self) -> EscalationManagerConfig:
        return self._cfg

    async def raise_event(self, event: EscalationEvent) -> EscalationResult:
        """
        Main entry point. Returns decision and delivery outcomes.
        """
        key = compute_escalation_key(event, self._cfg.stable_hash_salt)

        if not await self._rate.allow():
            # Rate limit global storm
            suppressed_reason = "rate_limited"
            await self._safe_audit(
                key=key,
                event=event,
                decision=EscalationDecision(decision=Decision.LOG_ONLY, reason=suppressed_reason),
                delivered=(),
                suppressed=True,
                suppressed_reason=suppressed_reason,
            )
            return EscalationResult(
                key=key,
                decision=EscalationDecision(decision=Decision.LOG_ONLY, reason=suppressed_reason),
                stored=False,
                delivered=(),
                suppressed=True,
                suppressed_reason=suppressed_reason,
            )

        # Evaluate policy
        try:
            decision = await self._policy.evaluate(event)
        except Exception as e:
            if self._cfg.strict_policy:
                raise PolicyError(str(e)) from e
            decision = EscalationDecision(decision=Decision.LOG_ONLY, reason=f"policy_error:{type(e).__name__}")
            logger.exception("Escalation policy error; fallback to LOG_ONLY. key=%s", key)

        # Normalize TTL and limits
        ttl = int(decision.ttl_seconds or self._cfg.dedup_default_ttl_seconds)
        ttl = max(1, ttl)
        max_notifs = max(0, int(decision.max_notifications))

        # Suppression via dedup / counter
        suppressed = False
        suppressed_reason: Optional[str] = None
        stored = False

        # Serialize window updates to reduce races for in-memory store.
        # For distributed stores, atomic increment is expected anyway.
        async with self._op_lock:
            try:
                count = await self._store.increment_window(key, ttl_seconds=ttl)
                stored = True
            except Exception as e:
                if self._cfg.strict_store:
                    raise StoreError(str(e)) from e
                count = 1
                stored = False
                logger.exception("Escalation store increment failed; continuing without dedup. key=%s", key)

        if max_notifs == 0 and decision.decision in (Decision.NOTIFY, Decision.ESCALATE):
            suppressed = True
            suppressed_reason = "policy_max_notifications_zero"

        if decision.decision in (Decision.NOTIFY, Decision.ESCALATE):
            if count > max_notifs > 0:
                suppressed = True
                suppressed_reason = f"dedup_suppressed_count={count}_limit={max_notifs}"

        # Perform delivery if needed and not suppressed
        delivered: List[DeliveryAttempt] = []
        if not suppressed and decision.decision in (Decision.NOTIFY, Decision.ESCALATE):
            delivered = await self._deliver_to_sinks(event=event, decision=decision, key=key)

        # Audit
        await self._safe_audit(
            key=key,
            event=event,
            decision=decision,
            delivered=tuple(delivered),
            suppressed=suppressed,
            suppressed_reason=suppressed_reason,
        )

        return EscalationResult(
            key=key,
            decision=decision,
            stored=stored,
            delivered=tuple(delivered),
            suppressed=suppressed,
            suppressed_reason=suppressed_reason,
        )

    async def _deliver_to_sinks(
        self,
        event: EscalationEvent,
        decision: EscalationDecision,
        key: str,
    ) -> List[DeliveryAttempt]:
        attempts: List[DeliveryAttempt] = []

        for sink in self._sinks:
            ok = False
            err: Optional[str] = None
            latency_ms: Optional[int] = None

            start = time.time()
            try:
                await self._deliver_with_retries(sink=sink, event=event, decision=decision, key=key)
                ok = True
            except Exception as e:
                err = f"{type(e).__name__}:{e}"
                logger.exception("Escalation sink delivery failed. sink=%s key=%s", getattr(sink, "name", "unknown"), key)
                if self._cfg.strict_sink:
                    raise SinkError(err) from e
            finally:
                latency_ms = int((time.time() - start) * 1000)

            attempts.append(DeliveryAttempt(sink_name=getattr(sink, "name", "unknown"), ok=ok, error=err, latency_ms=latency_ms))

        return attempts

    async def _deliver_with_retries(
        self,
        sink: EscalationSink,
        event: EscalationEvent,
        decision: EscalationDecision,
        key: str,
    ) -> None:
        cfg = self._cfg.backoff
        last_err: Optional[BaseException] = None

        for attempt in range(1, max(1, int(cfg.max_retries)) + 1):
            try:
                await _with_timeout(
                    sink.deliver(event=event, decision=decision, key=key),
                    timeout_s=self._cfg.delivery_timeout_seconds,
                )
                return
            except asyncio.TimeoutError as e:
                last_err = e
            except Exception as e:
                last_err = e

            if attempt < int(cfg.max_retries):
                delay_ms = _next_backoff_ms(attempt, cfg)
                await asyncio.sleep(delay_ms / 1000.0)

        raise SinkError(f"delivery_failed_after_retries:{getattr(sink, 'name', 'unknown')}") from last_err

    async def _safe_audit(
        self,
        key: str,
        event: EscalationEvent,
        decision: EscalationDecision,
        delivered: Tuple[DeliveryAttempt, ...],
        suppressed: bool,
        suppressed_reason: Optional[str],
    ) -> None:
        if not self._cfg.audit_enabled:
            return

        record = {
            "key": key,
            "ts_epoch": time.time(),
            "event": event.to_dict(),
            "decision": {
                "decision": decision.decision.value,
                "targets": [dataclasses.asdict(t) for t in decision.targets],
                "reason": decision.reason,
                "ttl_seconds": int(decision.ttl_seconds),
                "max_notifications": int(decision.max_notifications),
                "escalate_by": int(decision.escalate_by),
                "extra": dict(decision.extra or {}),
            },
            "suppressed": bool(suppressed),
            "suppressed_reason": suppressed_reason,
            "delivered": [dataclasses.asdict(a) for a in delivered],
        }

        try:
            await self._store.append_audit(record)
        except Exception as e:
            if self._cfg.strict_store:
                raise StoreError(str(e)) from e
            logger.exception("Escalation audit append failed; ignoring. key=%s", key)


__all__ = [
    "Severity",
    "Decision",
    "EscalationTarget",
    "EscalationEvent",
    "EscalationDecision",
    "DeliveryAttempt",
    "EscalationResult",
    "EscalationPolicy",
    "EscalationSink",
    "EscalationStore",
    "RateLimitConfig",
    "BackoffConfig",
    "EscalationManagerConfig",
    "InMemoryEscalationStore",
    "DefaultEscalationPolicy",
    "compute_escalation_key",
    "EscalationManager",
    "EscalationError",
    "PolicyError",
    "SinkError",
    "StoreError",
]
