# human-sovereignty-core/execution/limits.py
# Industrial-grade execution limits, budgets, and guardrails.
# No external dependencies. Python 3.11+ recommended.

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from threading import RLock
from typing import Any, Dict, Mapping, Optional, Tuple

# Local dependency for risk levels (expected to exist in project)
try:
    from human_sovereignty_core.domain.risk_levels import RiskLevel  # type: ignore
except Exception as _e:  # pragma: no cover
    raise ImportError("limits.py requires human_sovereignty_core.domain.risk_levels") from _e


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class LimitError(RuntimeError):
    """Base error for execution limits."""


class LimitViolationError(LimitError):
    """Raised when an execution request violates limits."""


class BudgetExhaustedError(LimitError):
    """Raised when a budget cannot be consumed."""


class DegradationMode(str, Enum):
    """
    How to degrade behavior when near limits.
    """

    DENY = "DENY"
    QUEUE = "QUEUE"
    THROTTLE = "THROTTLE"
    SAFE_MODE = "SAFE_MODE"


@dataclass(frozen=True, slots=True)
class ExecutionLimits:
    """
    Limits governing execution of actions.

    time_budget_seconds: maximum wall-clock time per action execution.
    max_payload_bytes: maximum size of payload/context accepted for execution.
    max_result_bytes: maximum allowed result size.
    max_parallelism: maximum concurrent executions for this scope/actor.
    max_subtasks: maximum number of internal subtasks spawned.
    max_external_calls: maximum number of external calls (network/db/agents).
    rate_tokens_per_minute: token bucket refill rate.
    rate_burst: max burst tokens.
    degradation_mode: behavior when limit pressure is high.
    """

    time_budget_seconds: int
    max_payload_bytes: int
    max_result_bytes: int
    max_parallelism: int
    max_subtasks: int
    max_external_calls: int
    rate_tokens_per_minute: int
    rate_burst: int
    degradation_mode: DegradationMode = DegradationMode.DENY

    def __post_init__(self) -> None:
        _assert_int_range("time_budget_seconds", self.time_budget_seconds, 1, 86_400)
        _assert_int_range("max_payload_bytes", self.max_payload_bytes, 1, 200 * 1024 * 1024)
        _assert_int_range("max_result_bytes", self.max_result_bytes, 1, 200 * 1024 * 1024)
        _assert_int_range("max_parallelism", self.max_parallelism, 1, 10_000)
        _assert_int_range("max_subtasks", self.max_subtasks, 0, 1_000_000)
        _assert_int_range("max_external_calls", self.max_external_calls, 0, 1_000_000)
        _assert_int_range("rate_tokens_per_minute", self.rate_tokens_per_minute, 0, 10_000_000)
        _assert_int_range("rate_burst", self.rate_burst, 0, 10_000_000)
        if not isinstance(self.degradation_mode, DegradationMode):
            raise TypeError("degradation_mode must be DegradationMode")


def _assert_int_range(name: str, value: int, lo: int, hi: int) -> None:
    if not isinstance(value, int):
        raise TypeError(f"{name} must be int")
    if value < lo or value > hi:
        raise ValueError(f"{name} must be in [{lo}, {hi}]")


DEFAULT_LIMITS_BY_RISK: Dict[RiskLevel, ExecutionLimits] = {
    RiskLevel.LOW: ExecutionLimits(
        time_budget_seconds=30,
        max_payload_bytes=256 * 1024,
        max_result_bytes=256 * 1024,
        max_parallelism=50,
        max_subtasks=200,
        max_external_calls=50,
        rate_tokens_per_minute=5_000,
        rate_burst=2_000,
        degradation_mode=DegradationMode.THROTTLE,
    ),
    RiskLevel.MEDIUM: ExecutionLimits(
        time_budget_seconds=20,
        max_payload_bytes=192 * 1024,
        max_result_bytes=192 * 1024,
        max_parallelism=20,
        max_subtasks=120,
        max_external_calls=30,
        rate_tokens_per_minute=2_000,
        rate_burst=800,
        degradation_mode=DegradationMode.QUEUE,
    ),
    RiskLevel.HIGH: ExecutionLimits(
        time_budget_seconds=12,
        max_payload_bytes=128 * 1024,
        max_result_bytes=128 * 1024,
        max_parallelism=10,
        max_subtasks=80,
        max_external_calls=20,
        rate_tokens_per_minute=800,
        rate_burst=300,
        degradation_mode=DegradationMode.SAFE_MODE,
    ),
    RiskLevel.CRITICAL: ExecutionLimits(
        time_budget_seconds=8,
        max_payload_bytes=96 * 1024,
        max_result_bytes=96 * 1024,
        max_parallelism=3,
        max_subtasks=40,
        max_external_calls=10,
        rate_tokens_per_minute=200,
        rate_burst=80,
        degradation_mode=DegradationMode.DENY,
    ),
}


@dataclass(slots=True)
class TokenBucket:
    """
    Thread-safe token bucket limiter.

    tokens refill continuously at rate_tokens_per_second.
    """

    rate_tokens_per_minute: int
    burst: int

    _lock: RLock = field(default_factory=RLock, init=False, repr=False)
    _tokens: float = field(default=0.0, init=False)
    _updated_at: datetime = field(default_factory=_utc_now, init=False)

    def __post_init__(self) -> None:
        _assert_int_range("rate_tokens_per_minute", self.rate_tokens_per_minute, 0, 10_000_000)
        _assert_int_range("burst", self.burst, 0, 10_000_000)
        with self._lock:
            self._tokens = float(self.burst)
            self._updated_at = _utc_now()

    def _refill(self, now: datetime) -> None:
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        elapsed = (now - self._updated_at).total_seconds()
        if elapsed <= 0:
            return

        rate_per_sec = float(self.rate_tokens_per_minute) / 60.0
        add = elapsed * rate_per_sec
        self._tokens = min(float(self.burst), self._tokens + add)
        self._updated_at = now

    def try_consume(self, tokens: int, *, now: Optional[datetime] = None) -> bool:
        if not isinstance(tokens, int) or tokens < 0:
            raise ValueError("tokens must be non-negative int")

        n = now or _utc_now()
        with self._lock:
            self._refill(n)
            if tokens == 0:
                return True
            if self._tokens >= float(tokens):
                self._tokens -= float(tokens)
                return True
            return False

    def consume_or_raise(self, tokens: int, *, now: Optional[datetime] = None) -> None:
        ok = self.try_consume(tokens, now=now)
        if not ok:
            raise BudgetExhaustedError("Rate budget exhausted")

    def snapshot(self, *, now: Optional[datetime] = None) -> Dict[str, Any]:
        n = now or _utc_now()
        with self._lock:
            self._refill(n)
            return {
                "tokens": float(self._tokens),
                "burst": int(self.burst),
                "rate_tokens_per_minute": int(self.rate_tokens_per_minute),
                "updated_at": self._updated_at.isoformat(),
            }


@dataclass(slots=True)
class ConcurrencyGate:
    """
    Thread-safe concurrency limiter per key (actor, tenant, scope, etc).

    This is an in-memory guard; production systems typically back this with Redis,
    but this module defines the domain contract.
    """

    max_parallelism: int

    _lock: RLock = field(default_factory=RLock, init=False, repr=False)
    _in_flight: Dict[str, int] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        _assert_int_range("max_parallelism", self.max_parallelism, 1, 10_000)

    def try_acquire(self, key: str) -> bool:
        k = (key or "").strip()
        if not k:
            raise ValueError("key must be non-empty")
        with self._lock:
            cur = self._in_flight.get(k, 0)
            if cur >= self.max_parallelism:
                return False
            self._in_flight[k] = cur + 1
            return True

    def release(self, key: str) -> None:
        k = (key or "").strip()
        if not k:
            raise ValueError("key must be non-empty")
        with self._lock:
            cur = self._in_flight.get(k, 0)
            if cur <= 0:
                self._in_flight.pop(k, None)
                return
            nxt = cur - 1
            if nxt <= 0:
                self._in_flight.pop(k, None)
            else:
                self._in_flight[k] = nxt

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {"max_parallelism": self.max_parallelism, "in_flight": dict(self._in_flight)}


def limits_for_risk(level: RiskLevel, overrides: Optional[Mapping[RiskLevel, ExecutionLimits]] = None) -> ExecutionLimits:
    if not isinstance(level, RiskLevel):
        raise TypeError("level must be RiskLevel")
    if overrides is None:
        return DEFAULT_LIMITS_BY_RISK[level]
    merged = dict(DEFAULT_LIMITS_BY_RISK)
    merged.update(dict(overrides))
    return merged[level]


def validate_execution_request(
    *,
    level: RiskLevel,
    payload_bytes: int,
    expected_result_bytes: int,
    planned_subtasks: int,
    planned_external_calls: int,
    time_budget_seconds: Optional[int] = None,
    overrides: Optional[Mapping[RiskLevel, ExecutionLimits]] = None,
) -> ExecutionLimits:
    """
    Validates a request against execution limits for given risk level.

    Returns resolved ExecutionLimits that should be enforced at runtime.
    """
    lim = limits_for_risk(level, overrides=overrides)

    _assert_int_range("payload_bytes", payload_bytes, 0, 2_000_000_000)
    _assert_int_range("expected_result_bytes", expected_result_bytes, 0, 2_000_000_000)
    _assert_int_range("planned_subtasks", planned_subtasks, 0, 2_000_000_000)
    _assert_int_range("planned_external_calls", planned_external_calls, 0, 2_000_000_000)

    if payload_bytes > lim.max_payload_bytes:
        raise LimitViolationError(f"payload too large: {payload_bytes} > {lim.max_payload_bytes}")
    if expected_result_bytes > lim.max_result_bytes:
        raise LimitViolationError(
            f"expected result too large: {expected_result_bytes} > {lim.max_result_bytes}"
        )
    if planned_subtasks > lim.max_subtasks:
        raise LimitViolationError(f"too many subtasks: {planned_subtasks} > {lim.max_subtasks}")
    if planned_external_calls > lim.max_external_calls:
        raise LimitViolationError(
            f"too many external calls: {planned_external_calls} > {lim.max_external_calls}"
        )

    if time_budget_seconds is not None:
        _assert_int_range("time_budget_seconds", time_budget_seconds, 1, 86_400)
        if time_budget_seconds > lim.time_budget_seconds:
            raise LimitViolationError(
                f"time budget too high: {time_budget_seconds} > {lim.time_budget_seconds}"
            )

    return lim


@dataclass(frozen=True, slots=True)
class RuntimeBudget:
    """
    A runtime budget for wall-clock time.
    """

    started_at: datetime
    budget_seconds: int

    def __post_init__(self) -> None:
        if self.started_at.tzinfo is None:
            object.__setattr__(self, "started_at", self.started_at.replace(tzinfo=timezone.utc))
        _assert_int_range("budget_seconds", self.budget_seconds, 1, 86_400)

    def deadline(self) -> datetime:
        return self.started_at + timedelta(seconds=self.budget_seconds)

    def remaining_seconds(self, *, now: Optional[datetime] = None) -> int:
        n = now or _utc_now()
        if n.tzinfo is None:
            n = n.replace(tzinfo=timezone.utc)
        rem = (self.deadline() - n).total_seconds()
        if rem <= 0:
            return 0
        return int(rem)

    def ensure_not_expired(self, *, now: Optional[datetime] = None) -> None:
        if self.remaining_seconds(now=now) <= 0:
            raise BudgetExhaustedError("time budget expired")
