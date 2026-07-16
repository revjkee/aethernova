# agent_mash/core/routing.py
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import functools
import hashlib
import inspect
import json
import logging
import os
import time
import uuid
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional, TypeAlias, TypedDict

logger = logging.getLogger(__name__)

JsonValue: TypeAlias = str | int | float | bool | None | dict[str, "JsonValue"] | list["JsonValue"]
Headers: TypeAlias = dict[str, str]
Tags: TypeAlias = dict[str, str]


class RoutingError(RuntimeError):
    pass


class NoRouteFound(RoutingError):
    pass


class HandlerNotFound(RoutingError):
    pass


class RateLimitExceeded(RoutingError):
    pass


class WorkRejected(RoutingError):
    pass


class RouteTargetType(str, Enum):
    AGENT = "agent"
    QUEUE = "queue"
    TOPIC = "topic"
    SERVICE = "service"


class DispatchStatus(str, Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    RETRYING = "retrying"
    FAILED = "failed"
    SUCCEEDED = "succeeded"
    DEADLETTER = "deadletter"


class AuditEventType(str, Enum):
    WORK_RECEIVED = "work_received"
    ROUTE_DECIDED = "route_decided"
    DISPATCH_STARTED = "dispatch_started"
    DISPATCH_FINISHED = "dispatch_finished"
    DISPATCH_RETRY = "dispatch_retry"
    DISPATCH_DEADLETTER = "dispatch_deadletter"
    DISPATCH_ERROR = "dispatch_error"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _stable_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class WorkId:
    value: str

    @staticmethod
    def new() -> "WorkId":
        return WorkId(value=str(uuid.uuid4()))

    @staticmethod
    def from_deterministic(parts: Mapping[str, Any]) -> "WorkId":
        return WorkId(value=_sha256_hex(_stable_json(parts)))


@dataclass(frozen=True, slots=True)
class TraceContext:
    trace_id: str
    span_id: str
    parent_span_id: Optional[str] = None

    @staticmethod
    def new() -> "TraceContext":
        tid = uuid.uuid4().hex
        sid = uuid.uuid4().hex[:16]
        return TraceContext(trace_id=tid, span_id=sid)

    def child(self) -> "TraceContext":
        return TraceContext(
            trace_id=self.trace_id,
            span_id=uuid.uuid4().hex[:16],
            parent_span_id=self.span_id,
        )


@dataclass(frozen=True, slots=True)
class WorkMeta:
    created_at: datetime
    source: str
    correlation_id: Optional[str] = None
    trace: Optional[TraceContext] = None
    headers: Headers = dataclasses.field(default_factory=dict)
    tags: Tags = dataclasses.field(default_factory=dict)

    @staticmethod
    def default(source: str = "unknown") -> "WorkMeta":
        return WorkMeta(created_at=utc_now(), source=source, trace=TraceContext.new())


@dataclass(frozen=True, slots=True)
class WorkItem:
    id: WorkId
    kind: str
    payload: dict[str, JsonValue]
    meta: WorkMeta
    priority: int = 100
    deadline: Optional[datetime] = None
    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    dedupe_key: Optional[str] = None

    def is_expired(self, at: Optional[datetime] = None) -> bool:
        if self.deadline is None:
            return False
        now = at or utc_now()
        return now >= self.deadline

    def as_log_dict(self) -> dict[str, Any]:
        return {
            "work_id": self.id.value,
            "kind": self.kind,
            "priority": self.priority,
            "deadline": self.deadline.isoformat() if self.deadline else None,
            "tenant_id": self.tenant_id,
            "user_id": self.user_id,
            "source": self.meta.source,
            "correlation_id": self.meta.correlation_id,
            "trace_id": self.meta.trace.trace_id if self.meta.trace else None,
            "span_id": self.meta.trace.span_id if self.meta.trace else None,
            "tags": dict(self.meta.tags),
            "dedupe_key": self.dedupe_key,
        }


@dataclass(frozen=True, slots=True)
class RouteTarget:
    type: RouteTargetType
    name: str
    shard: Optional[str] = None

    def as_key(self) -> str:
        if self.shard:
            return f"{self.type.value}:{self.name}:{self.shard}"
        return f"{self.type.value}:{self.name}"


@dataclass(frozen=True, slots=True)
class RouteDecision:
    target: RouteTarget
    reason: str
    policy_id: Optional[str] = None
    handler: Optional[str] = None
    tags: Tags = dataclasses.field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 5
    base_delay_ms: int = 200
    max_delay_ms: int = 15_000
    jitter_ratio: float = 0.2
    retry_on: tuple[type[BaseException], ...] = (Exception,)

    def compute_delay_ms(self, attempt: int) -> int:
        attempt = max(1, attempt)
        delay = min(self.max_delay_ms, int(self.base_delay_ms * (2 ** (attempt - 1))))
        if self.jitter_ratio > 0:
            jitter = int(delay * self.jitter_ratio)
            delay = delay + (hash(delay) % (2 * jitter + 1) - jitter)
            delay = max(0, delay)
        return delay


@dataclass(frozen=True, slots=True)
class RateLimit:
    per_key_rps: float = 50.0
    burst: int = 100

    def key(self, decision: RouteDecision, work: WorkItem) -> str:
        tenant = work.tenant_id or "public"
        return f"{tenant}:{decision.target.as_key()}"


class TokenBucket:
    __slots__ = ("rate", "capacity", "tokens", "updated_at")

    def __init__(self, rate: float, capacity: int) -> None:
        self.rate = float(rate)
        self.capacity = int(capacity)
        self.tokens = float(capacity)
        self.updated_at = time.monotonic()

    def allow(self, amount: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self.updated_at
        self.updated_at = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False


class AuditSink:
    async def emit(self, event: "AuditEvent") -> None:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class AuditEvent:
    at: datetime
    type: AuditEventType
    work_id: str
    data: dict[str, JsonValue]

    def to_json(self) -> str:
        return _stable_json(
            {
                "at": self.at.isoformat(),
                "type": self.type.value,
                "work_id": self.work_id,
                "data": self.data,
            }
        )


class StdoutAuditSink(AuditSink):
    async def emit(self, event: AuditEvent) -> None:
        logger.info("audit=%s", event.to_json())


Predicate: TypeAlias = Callable[[WorkItem], bool]
HandlerFn: TypeAlias = Callable[[WorkItem, RouteDecision], Awaitable["DispatchResult"]] | Callable[
    [WorkItem, RouteDecision], "DispatchResult"
]


@dataclass(frozen=True, slots=True)
class RouteRule:
    id: str
    when: Predicate
    target: RouteTarget
    reason: str
    handler: Optional[str] = None
    tags: Tags = dataclasses.field(default_factory=dict)
    enabled: bool = True
    priority: int = 100

    def matches(self, work: WorkItem) -> bool:
        if not self.enabled:
            return False
        try:
            return bool(self.when(work))
        except Exception as e:
            logger.exception("route_rule_match_error rule_id=%s err=%s", self.id, e)
            return False


@dataclass(frozen=True, slots=True)
class DispatchResult:
    status: DispatchStatus
    message: str = ""
    output: Optional[dict[str, JsonValue]] = None
    metrics: Optional[dict[str, JsonValue]] = None


class DedupeStore:
    async def seen(self, key: str, ttl: timedelta) -> bool:
        raise NotImplementedError

    async def mark(self, key: str, ttl: timedelta) -> None:
        raise NotImplementedError


class InMemoryDedupeStore(DedupeStore):
    def __init__(self) -> None:
        self._items: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def seen(self, key: str, ttl: timedelta) -> bool:
        await self._gc()
        async with self._lock:
            exp = self._items.get(key)
            if exp is None:
                return False
            return exp >= time.time()

    async def mark(self, key: str, ttl: timedelta) -> None:
        await self._gc()
        async with self._lock:
            self._items[key] = time.time() + ttl.total_seconds()

    async def _gc(self) -> None:
        now = time.time()
        async with self._lock:
            dead = [k for k, exp in self._items.items() if exp < now]
            for k in dead:
                self._items.pop(k, None)


class RoutingEngine:
    def __init__(self, rules: Iterable[RouteRule]) -> None:
        self._rules = sorted(list(rules), key=lambda r: (r.priority, r.id))

    def decide(self, work: WorkItem) -> RouteDecision:
        for rule in self._rules:
            if rule.matches(work):
                return RouteDecision(
                    target=rule.target,
                    reason=rule.reason,
                    policy_id=rule.id,
                    handler=rule.handler,
                    tags=dict(rule.tags),
                )
        raise NoRouteFound(f"No route for kind={work.kind}")

    def with_rule(self, rule: RouteRule) -> "RoutingEngine":
        return RoutingEngine([*self._rules, rule])

    def snapshot(self) -> list[RouteRule]:
        return list(self._rules)


class HandlerRegistry:
    def __init__(self) -> None:
        self._handlers: dict[str, HandlerFn] = {}

    def register(self, name: str, fn: HandlerFn) -> None:
        if not name or not isinstance(name, str):
            raise ValueError("Handler name must be non-empty string")
        if name in self._handlers:
            raise ValueError(f"Handler already registered: {name}")
        self._handlers[name] = fn

    def get(self, name: str) -> HandlerFn:
        fn = self._handlers.get(name)
        if fn is None:
            raise HandlerNotFound(f"Handler not found: {name}")
        return fn

    def has(self, name: str) -> bool:
        return name in self._handlers

    def list(self) -> list[str]:
        return sorted(self._handlers.keys())


class RouterConfig(TypedDict, total=False):
    default_handler: str
    deadletter_handler: str
    max_concurrency: int
    rate_limit_per_key_rps: float
    rate_limit_burst: int
    retry_max_attempts: int
    retry_base_delay_ms: int
    retry_max_delay_ms: int
    retry_jitter_ratio: float
    dedupe_ttl_seconds: int


class WorkforceRouter:
    def __init__(
        self,
        engine: RoutingEngine,
        registry: HandlerRegistry,
        *,
        audit: Optional[AuditSink] = None,
        dedupe: Optional[DedupeStore] = None,
        config: Optional[RouterConfig] = None,
    ) -> None:
        cfg = dict(config or {})
        self._engine = engine
        self._registry = registry
        self._audit = audit or StdoutAuditSink()
        self._dedupe = dedupe or InMemoryDedupeStore()

        self._default_handler = cfg.get("default_handler", "workforce.default")
        self._deadletter_handler = cfg.get("deadletter_handler", "workforce.deadletter")

        self._max_concurrency = int(cfg.get("max_concurrency", 200))
        self._sem = asyncio.Semaphore(self._max_concurrency)

        self._rate_limit = RateLimit(
            per_key_rps=float(cfg.get("rate_limit_per_key_rps", 50.0)),
            burst=int(cfg.get("rate_limit_burst", 100)),
        )
        self._buckets: dict[str, TokenBucket] = {}
        self._bucket_lock = asyncio.Lock()

        self._retry = RetryPolicy(
            max_attempts=int(cfg.get("retry_max_attempts", 5)),
            base_delay_ms=int(cfg.get("retry_base_delay_ms", 200)),
            max_delay_ms=int(cfg.get("retry_max_delay_ms", 15_000)),
            jitter_ratio=float(cfg.get("retry_jitter_ratio", 0.2)),
            retry_on=(Exception,),
        )

        self._dedupe_ttl = timedelta(seconds=int(cfg.get("dedupe_ttl_seconds", 300)))

    def snapshot_rules(self) -> list[RouteRule]:
        return self._engine.snapshot()

    async def handle(self, work: WorkItem) -> DispatchResult:
        if work.is_expired():
            return DispatchResult(status=DispatchStatus.REJECTED, message="deadline_expired")

        await self._emit(AuditEventType.WORK_RECEIVED, work, {"kind": work.kind})

        if work.dedupe_key:
            if await self._dedupe.seen(work.dedupe_key, self._dedupe_ttl):
                return DispatchResult(status=DispatchStatus.ACCEPTED, message="deduped")
            await self._dedupe.mark(work.dedupe_key, self._dedupe_ttl)

        decision = self._engine.decide(work)
        await self._emit(
            AuditEventType.ROUTE_DECIDED,
            work,
            {
                "target": decision.target.as_key(),
                "reason": decision.reason,
                "policy_id": decision.policy_id,
                "handler": decision.handler or self._default_handler,
                "tags": dict(decision.tags),
            },
        )

        handler_name = decision.handler or self._default_handler
        if not self._registry.has(handler_name):
            raise HandlerNotFound(f"Missing handler={handler_name}")

        await self._check_rate_limit(decision, work)

        async with self._sem:
            return await self._dispatch_with_retries(work, decision, handler_name)

    async def _dispatch_with_retries(self, work: WorkItem, decision: RouteDecision, handler_name: str) -> DispatchResult:
        trace = work.meta.trace.child() if work.meta.trace else None
        start = time.monotonic()

        await self._emit(
            AuditEventType.DISPATCH_STARTED,
            work,
            {"handler": handler_name, "trace_id": trace.trace_id if trace else None, "span_id": trace.span_id if trace else None},
        )

        last_err: Optional[BaseException] = None
        for attempt in range(1, self._retry.max_attempts + 1):
            try:
                result = await self._call_handler(handler_name, work, decision)
                dur_ms = int((time.monotonic() - start) * 1000)

                await self._emit(
                    AuditEventType.DISPATCH_FINISHED,
                    work,
                    {
                        "handler": handler_name,
                        "status": result.status.value,
                        "duration_ms": dur_ms,
                        "attempt": attempt,
                        "message": result.message,
                    },
                )
                return result
            except self._retry.retry_on as e:
                last_err = e
                if attempt >= self._retry.max_attempts:
                    break
                delay_ms = self._retry.compute_delay_ms(attempt)
                await self._emit(
                    AuditEventType.DISPATCH_RETRY,
                    work,
                    {"handler": handler_name, "attempt": attempt, "delay_ms": delay_ms, "error": type(e).__name__},
                )
                await asyncio.sleep(delay_ms / 1000.0)
            except BaseException as e:
                last_err = e
                break

        await self._emit(
            AuditEventType.DISPATCH_ERROR,
            work,
            {"handler": handler_name, "error": type(last_err).__name__ if last_err else "unknown"},
        )

        if self._registry.has(self._deadletter_handler):
            with contextlib.suppress(Exception):
                dlq_decision = RouteDecision(
                    target=RouteTarget(type=RouteTargetType.QUEUE, name="deadletter"),
                    reason="deadletter",
                    policy_id=decision.policy_id,
                    handler=self._deadletter_handler,
                    tags=dict(decision.tags),
                )
                await self._emit(
                    AuditEventType.DISPATCH_DEADLETTER,
                    work,
                    {"handler": self._deadletter_handler, "original_handler": handler_name},
                )
                return await self._call_handler(self._deadletter_handler, work, dlq_decision)

        return DispatchResult(status=DispatchStatus.FAILED, message="dispatch_failed")

    async def _call_handler(self, handler_name: str, work: WorkItem, decision: RouteDecision) -> DispatchResult:
        fn = self._registry.get(handler_name)

        extra = work.as_log_dict()
        extra.update(
            {
                "handler": handler_name,
                "target": decision.target.as_key(),
                "policy_id": decision.policy_id,
            }
        )

        try:
            if inspect.iscoroutinefunction(fn):
                result = await fn(work, decision)  # type: ignore[misc]
            else:
                res = fn(work, decision)  # type: ignore[misc]
                result = await res if asyncio.isfuture(res) or inspect.isawaitable(res) else res  # type: ignore[assignment]
            if not isinstance(result, DispatchResult):
                raise TypeError("Handler must return DispatchResult")
            logger.info("dispatch_ok %s", _stable_json(extra))
            return result
        except Exception as e:
            logger.exception("dispatch_err %s err=%s", _stable_json(extra), e)
            raise

    async def _check_rate_limit(self, decision: RouteDecision, work: WorkItem) -> None:
        key = self._rate_limit.key(decision, work)
        async with self._bucket_lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = TokenBucket(rate=self._rate_limit.per_key_rps, capacity=self._rate_limit.burst)
                self._buckets[key] = bucket
        if not bucket.allow(1.0):
            raise RateLimitExceeded(f"Rate limit exceeded for key={key}")

    async def _emit(self, etype: AuditEventType, work: WorkItem, data: dict[str, JsonValue]) -> None:
        try:
            ev = AuditEvent(at=utc_now(), type=etype, work_id=work.id.value, data=data)
            await self._audit.emit(ev)
        except Exception:
            logger.exception("audit_emit_failed type=%s work_id=%s", etype.value, work.id.value)


def rule_kind_is(kind: str) -> Predicate:
    def _p(w: WorkItem) -> bool:
        return w.kind == kind

    return _p


def rule_kind_prefix(prefix: str) -> Predicate:
    def _p(w: WorkItem) -> bool:
        return w.kind.startswith(prefix)

    return _p


def rule_tag_equals(key: str, value: str) -> Predicate:
    def _p(w: WorkItem) -> bool:
        return w.meta.tags.get(key) == value

    return _p


def rule_tenant_in(tenants: set[str]) -> Predicate:
    def _p(w: WorkItem) -> bool:
        return (w.tenant_id or "") in tenants

    return _p


def compose_all(*preds: Predicate) -> Predicate:
    def _p(w: WorkItem) -> bool:
        for p in preds:
            if not p(w):
                return False
        return True

    return _p


def compose_any(*preds: Predicate) -> Predicate:
    def _p(w: WorkItem) -> bool:
        for p in preds:
            if p(w):
                return True
        return False

    return _p


def default_work_item(
    *,
    kind: str,
    payload: dict[str, JsonValue],
    source: str,
    priority: int = 100,
    deadline_seconds: Optional[int] = None,
    tenant_id: Optional[str] = None,
    user_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    tags: Optional[Tags] = None,
    dedupe_parts: Optional[Mapping[str, Any]] = None,
) -> WorkItem:
    meta = WorkMeta.default(source=source)
    if correlation_id:
        meta = dataclasses.replace(meta, correlation_id=correlation_id)
    if tags:
        meta = dataclasses.replace(meta, tags=dict(tags))

    deadline = utc_now() + timedelta(seconds=int(deadline_seconds)) if deadline_seconds else None

    wid = WorkId.new() if dedupe_parts is None else WorkId.from_deterministic(dedupe_parts)
    dedupe_key = _sha256_hex(_stable_json(dedupe_parts)) if dedupe_parts is not None else None

    return WorkItem(
        id=wid,
        kind=kind,
        payload=payload,
        meta=meta,
        priority=int(priority),
        deadline=deadline,
        tenant_id=tenant_id,
        user_id=user_id,
        dedupe_key=dedupe_key,
    )


def env_router_config(prefix: str = "AETHERNOVA_ROUTER_") -> RouterConfig:
    def _get_int(name: str, default: int) -> int:
        v = os.getenv(prefix + name)
        return default if v is None or v == "" else int(v)

    def _get_float(name: str, default: float) -> float:
        v = os.getenv(prefix + name)
        return default if v is None or v == "" else float(v)

    def _get_str(name: str, default: str) -> str:
        v = os.getenv(prefix + name)
        return default if v is None or v == "" else str(v)

    return {
        "default_handler": _get_str("DEFAULT_HANDLER", "workforce.default"),
        "deadletter_handler": _get_str("DEADLETTER_HANDLER", "workforce.deadletter"),
        "max_concurrency": _get_int("MAX_CONCURRENCY", 200),
        "rate_limit_per_key_rps": _get_float("RATE_LIMIT_RPS", 50.0),
        "rate_limit_burst": _get_int("RATE_LIMIT_BURST", 100),
        "retry_max_attempts": _get_int("RETRY_MAX_ATTEMPTS", 5),
        "retry_base_delay_ms": _get_int("RETRY_BASE_DELAY_MS", 200),
        "retry_max_delay_ms": _get_int("RETRY_MAX_DELAY_MS", 15000),
        "retry_jitter_ratio": _get_float("RETRY_JITTER_RATIO", 0.2),
        "dedupe_ttl_seconds": _get_int("DEDUPE_TTL_SECONDS", 300),
    }


def make_router(
    *,
    rules: Iterable[RouteRule],
    registry: Optional[HandlerRegistry] = None,
    audit: Optional[AuditSink] = None,
    dedupe: Optional[DedupeStore] = None,
    config: Optional[RouterConfig] = None,
) -> WorkforceRouter:
    reg = registry or HandlerRegistry()
    engine = RoutingEngine(rules=rules)
    cfg = config or env_router_config()
    return WorkforceRouter(engine=engine, registry=reg, audit=audit, dedupe=dedupe, config=cfg)
