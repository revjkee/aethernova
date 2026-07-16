# human-sovereignty-core/execution/rollback/rollback_executor.py
from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
)

__all__ = [
    "RollbackError",
    "RollbackValidationError",
    "RollbackConcurrencyError",
    "RollbackTimeoutError",
    "RollbackStepError",
    "RollbackStatus",
    "RollbackPolicy",
    "RollbackContext",
    "RollbackStep",
    "RollbackPlan",
    "RollbackAttempt",
    "RollbackResult",
    "AuditEvent",
    "AuditSink",
    "IdempotencyStore",
    "LockManager",
    "RollbackExecutor",
    "InMemoryAuditSink",
    "InMemoryIdempotencyStore",
    "InMemoryLockManager",
]


class RollbackError(Exception):
    """Base error for rollback execution."""


class RollbackValidationError(RollbackError):
    """Raised when a rollback plan or context is invalid."""


class RollbackConcurrencyError(RollbackError):
    """Raised when rollback cannot acquire required lock(s)."""


class RollbackTimeoutError(RollbackError):
    """Raised when rollback times out."""


class RollbackStepError(RollbackError):
    """Raised when a rollback step fails."""


class RollbackStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class RollbackPolicy:
    """
    Execution policy for rollback.

    Notes:
    - fail_closed: if True, any validation or external failure leads to hard stop.
    - stop_on_first_failure: if True, stop at first step failure. Otherwise attempt remaining steps.
    - max_attempts_per_step includes the first attempt.
    """

    fail_closed: bool = True
    stop_on_first_failure: bool = True

    timeout_seconds_total: int = 900
    timeout_seconds_per_step: int = 120

    max_attempts_per_step: int = 3
    backoff_initial_seconds: float = 0.5
    backoff_max_seconds: float = 10.0
    backoff_multiplier: float = 2.0
    jitter_ratio: float = 0.1  # 10% jitter

    dry_run: bool = False

    # Concurrency
    lock_ttl_seconds: int = 600
    lock_wait_seconds: int = 10

    # Safety limits
    max_steps: int = 200
    max_payload_bytes: int = 256_000

    def validate(self) -> None:
        if self.timeout_seconds_total <= 0:
            raise RollbackValidationError("timeout_seconds_total must be positive")
        if self.timeout_seconds_per_step <= 0:
            raise RollbackValidationError("timeout_seconds_per_step must be positive")
        if self.max_attempts_per_step <= 0:
            raise RollbackValidationError("max_attempts_per_step must be positive")
        if self.backoff_initial_seconds < 0:
            raise RollbackValidationError("backoff_initial_seconds must be >= 0")
        if self.backoff_max_seconds <= 0:
            raise RollbackValidationError("backoff_max_seconds must be positive")
        if self.backoff_multiplier < 1.0:
            raise RollbackValidationError("backoff_multiplier must be >= 1.0")
        if not (0.0 <= self.jitter_ratio <= 1.0):
            raise RollbackValidationError("jitter_ratio must be in [0, 1]")
        if self.lock_ttl_seconds <= 0:
            raise RollbackValidationError("lock_ttl_seconds must be positive")
        if self.lock_wait_seconds < 0:
            raise RollbackValidationError("lock_wait_seconds must be >= 0")
        if self.max_steps <= 0:
            raise RollbackValidationError("max_steps must be positive")
        if self.max_payload_bytes <= 0:
            raise RollbackValidationError("max_payload_bytes must be positive")


@dataclass(frozen=True, slots=True)
class RollbackContext:
    """
    Execution context for rollback.

    request_id: approval request ID
    packet_id: decision packet ID that triggered execution/rollback
    execution_id: idempotency scope for a rollback run
    actor: human or system principal performing rollback
    environment: dev/staging/prod
    domain: subsystem domain for routing/audit
    """

    request_id: str
    packet_id: str
    execution_id: str
    actor: str
    environment: str
    domain: str
    reason: str = ""
    metadata: Mapping[str, str] = field(default_factory=dict)

    def validate(self) -> None:
        for name, v in (
            ("request_id", self.request_id),
            ("packet_id", self.packet_id),
            ("execution_id", self.execution_id),
            ("actor", self.actor),
            ("environment", self.environment),
            ("domain", self.domain),
        ):
            if not isinstance(v, str) or not v.strip():
                raise RollbackValidationError(f"{name} must be a non-empty string")


@dataclass(frozen=True, slots=True)
class AuditEvent:
    ts_unix: int
    type: str
    request_id: str
    packet_id: str
    execution_id: str
    actor: str
    environment: str
    domain: str
    status: str
    message: str
    fields: Mapping[str, Any] = field(default_factory=dict)


class AuditSink(Protocol):
    async def emit(self, event: AuditEvent) -> None: ...


class IdempotencyStore(Protocol):
    async def get(self, key: str) -> Optional[Mapping[str, Any]]: ...
    async def put_if_absent(self, key: str, value: Mapping[str, Any], ttl_seconds: int) -> bool: ...
    async def put(self, key: str, value: Mapping[str, Any], ttl_seconds: int) -> None: ...


class LockManager(Protocol):
    async def acquire(self, lock_key: str, owner: str, ttl_seconds: int, wait_seconds: int) -> bool: ...
    async def release(self, lock_key: str, owner: str) -> None: ...


RollbackCallable = Callable[[RollbackContext, Mapping[str, Any]], Awaitable[None]]


class StepSemantics(str, Enum):
    """
    Semantics hints for executor.

    - REVERSIBLE: safe to retry; repeated execution should be idempotent.
    - BEST_EFFORT: failures are non-fatal if policy allows continuing.
    """

    REVERSIBLE = "reversible"
    BEST_EFFORT = "best_effort"


@dataclass(frozen=True, slots=True)
class RollbackStep:
    """
    One rollback step, intended to compensate an earlier forward step.

    id: stable unique id within plan.
    title: human readable.
    handler: async callable performing rollback side-effect.
    payload: step-specific data, must be JSON-serializable (enforced by executor size check).
    semantics: hints for retry and failure behavior.
    """

    id: str
    title: str
    handler: RollbackCallable
    payload: Mapping[str, Any] = field(default_factory=dict)
    semantics: StepSemantics = StepSemantics.REVERSIBLE
    # Optional explicit per-step timeout override
    timeout_seconds: Optional[int] = None

    def validate(self) -> None:
        if not self.id or not isinstance(self.id, str):
            raise RollbackValidationError("step.id must be non-empty string")
        if not self.title or not isinstance(self.title, str):
            raise RollbackValidationError("step.title must be non-empty string")
        if not callable(self.handler):
            raise RollbackValidationError("step.handler must be callable")
        # payload must be JSON-serializable; checked in executor with size limit


@dataclass(frozen=True, slots=True)
class RollbackPlan:
    """
    Rollback plan.

    id: plan identifier (stable).
    steps: ordered forward steps compensation list. Executor will run in reverse order by default.
    """

    id: str
    steps: Tuple[RollbackStep, ...]
    created_at_unix: int
    metadata: Mapping[str, str] = field(default_factory=dict)

    def validate(self, policy: RollbackPolicy) -> None:
        if not self.id or not isinstance(self.id, str):
            raise RollbackValidationError("plan.id must be non-empty string")
        if len(self.steps) == 0:
            raise RollbackValidationError("plan.steps must not be empty")
        if len(self.steps) > policy.max_steps:
            raise RollbackValidationError("plan.steps exceeds policy.max_steps")
        seen: set[str] = set()
        for s in self.steps:
            s.validate()
            if s.id in seen:
                raise RollbackValidationError(f"duplicate step id: {s.id}")
            seen.add(s.id)


@dataclass(frozen=True, slots=True)
class RollbackAttempt:
    step_id: str
    attempt_no: int
    started_unix: int
    finished_unix: int
    status: RollbackStatus
    error: Optional[str] = None


@dataclass(frozen=True, slots=True)
class RollbackResult:
    status: RollbackStatus
    started_unix: int
    finished_unix: int
    plan_id: str
    idempotency_key: str
    attempts: Tuple[RollbackAttempt, ...]
    error: Optional[str] = None
    summary: Mapping[str, Any] = field(default_factory=dict)


def _now_unix() -> int:
    return int(time.time())


def _safe_json_size(obj: Any, max_bytes: int) -> int:
    try:
        raw = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8", errors="strict")
    except Exception as exc:
        raise RollbackValidationError(f"payload is not JSON-serializable: {exc}") from exc
    size = len(raw)
    if size > max_bytes:
        raise RollbackValidationError("payload exceeds max_payload_bytes")
    return size


def _stable_hash(obj: Any) -> str:
    raw = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8", errors="strict")
    return hashlib.sha256(raw).hexdigest()


def _idempotency_key(ctx: RollbackContext, plan: RollbackPlan) -> str:
    # Idempotency scoped to execution_id + plan_id + packet_id
    material = {
        "execution_id": ctx.execution_id,
        "packet_id": ctx.packet_id,
        "plan_id": plan.id,
    }
    return "rb:" + _stable_hash(material)


async def _sleep_backoff(seconds: float) -> None:
    if seconds <= 0:
        await asyncio.sleep(0)
    else:
        await asyncio.sleep(seconds)


def _compute_backoff(policy: RollbackPolicy, attempt_no: int) -> float:
    # attempt_no starts at 1; backoff applies for attempt_no > 1
    if attempt_no <= 1:
        return 0.0
    base = policy.backoff_initial_seconds * (policy.backoff_multiplier ** (attempt_no - 2))
    base = min(base, policy.backoff_max_seconds)
    # jitter using deterministic pseudo-random from time would be non-deterministic;
    # here we keep it simple and bounded without external randomness.
    jitter = base * policy.jitter_ratio
    return base + jitter


class InMemoryAuditSink:
    __slots__ = ("events",)

    def __init__(self) -> None:
        self.events: List[AuditEvent] = []

    async def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


class InMemoryIdempotencyStore:
    __slots__ = ("_data",)

    def __init__(self) -> None:
        self._data: Dict[str, Tuple[Mapping[str, Any], int]] = {}

    async def get(self, key: str) -> Optional[Mapping[str, Any]]:
        item = self._data.get(key)
        if item is None:
            return None
        value, expires_unix = item
        if expires_unix != 0 and _now_unix() > expires_unix:
            self._data.pop(key, None)
            return None
        return value

    async def put_if_absent(self, key: str, value: Mapping[str, Any], ttl_seconds: int) -> bool:
        existing = await self.get(key)
        if existing is not None:
            return False
        expires = 0 if ttl_seconds <= 0 else _now_unix() + ttl_seconds
        self._data[key] = (dict(value), expires)
        return True

    async def put(self, key: str, value: Mapping[str, Any], ttl_seconds: int) -> None:
        expires = 0 if ttl_seconds <= 0 else _now_unix() + ttl_seconds
        self._data[key] = (dict(value), expires)


class InMemoryLockManager:
    __slots__ = ("_locks", "_lock")

    def __init__(self) -> None:
        self._locks: Dict[str, Tuple[str, int]] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, lock_key: str, owner: str, ttl_seconds: int, wait_seconds: int) -> bool:
        deadline = time.time() + max(0.0, float(wait_seconds))
        while True:
            async with self._lock:
                cur = self._locks.get(lock_key)
                now = _now_unix()
                if cur is None:
                    self._locks[lock_key] = (owner, now + ttl_seconds)
                    return True
                cur_owner, exp = cur
                if now >= exp:
                    self._locks[lock_key] = (owner, now + ttl_seconds)
                    return True
                if cur_owner == owner:
                    # Renew
                    self._locks[lock_key] = (owner, now + ttl_seconds)
                    return True
            if time.time() >= deadline:
                return False
            await asyncio.sleep(0.05)

    async def release(self, lock_key: str, owner: str) -> None:
        async with self._lock:
            cur = self._locks.get(lock_key)
            if cur is None:
                return
            cur_owner, _exp = cur
            if cur_owner == owner:
                self._locks.pop(lock_key, None)


class RollbackExecutor:
    """
    Industrial rollback executor.

    Guarantees:
    - Idempotency via IdempotencyStore: repeated call returns stored result if already finalized.
    - Concurrency safety via LockManager: only one rollback per (packet_id, plan_id) per environment by lock key.
    - Deterministic audit trail via AuditSink events.
    """

    __slots__ = ("_audit", "_idem", "_locks", "_policy")

    def __init__(
        self,
        *,
        audit_sink: AuditSink,
        idempotency_store: IdempotencyStore,
        lock_manager: LockManager,
        policy: Optional[RollbackPolicy] = None,
    ) -> None:
        self._audit = audit_sink
        self._idem = idempotency_store
        self._locks = lock_manager
        self._policy = policy or RollbackPolicy()
        self._policy.validate()

    async def execute(self, ctx: RollbackContext, plan: RollbackPlan) -> RollbackResult:
        ctx.validate()
        plan.validate(self._policy)

        # Pre-check payload sizes for all steps to fail fast (fail-closed).
        for s in plan.steps:
            _safe_json_size(s.payload, self._policy.max_payload_bytes)

        idem_key = _idempotency_key(ctx, plan)
        lock_key = f"rb-lock:{ctx.environment}:{ctx.domain}:{ctx.packet_id}:{plan.id}"

        # If already executed, return stored result.
        existing = await self._idem.get(idem_key)
        if existing is not None:
            return _result_from_mapping(existing)

        started = _now_unix()

        await self._audit.emit(
            AuditEvent(
                ts_unix=started,
                type="rollback.started",
                request_id=ctx.request_id,
                packet_id=ctx.packet_id,
                execution_id=ctx.execution_id,
                actor=ctx.actor,
                environment=ctx.environment,
                domain=ctx.domain,
                status=RollbackStatus.RUNNING.value,
                message="rollback execution started",
                fields={"plan_id": plan.id, "idempotency_key": idem_key, "dry_run": self._policy.dry_run},
            )
        )

        acquired = await self._locks.acquire(
            lock_key=lock_key,
            owner=ctx.execution_id,
            ttl_seconds=self._policy.lock_ttl_seconds,
            wait_seconds=self._policy.lock_wait_seconds,
        )
        if not acquired:
            finished = _now_unix()
            err = "rollback lock acquisition failed"
            await self._audit.emit(
                AuditEvent(
                    ts_unix=finished,
                    type="rollback.lock_failed",
                    request_id=ctx.request_id,
                    packet_id=ctx.packet_id,
                    execution_id=ctx.execution_id,
                    actor=ctx.actor,
                    environment=ctx.environment,
                    domain=ctx.domain,
                    status=RollbackStatus.FAILED.value,
                    message=err,
                    fields={"plan_id": plan.id, "lock_key": lock_key, "idempotency_key": idem_key},
                )
            )
            raise RollbackConcurrencyError(err)

        # Reserve idempotency record early to prevent thundering duplicates.
        reserved = await self._idem.put_if_absent(
            idem_key,
            {
                "status": RollbackStatus.RUNNING.value,
                "started_unix": started,
                "finished_unix": 0,
                "plan_id": plan.id,
                "idempotency_key": idem_key,
                "attempts": [],
                "error": None,
                "summary": {"note": "reserved"},
            },
            ttl_seconds=max(self._policy.timeout_seconds_total, 60),
        )
        if not reserved:
            # Another executor reserved while we were acquiring lock; return stored.
            try:
                existing2 = await self._idem.get(idem_key)
                if existing2 is not None:
                    return _result_from_mapping(existing2)
            finally:
                await self._locks.release(lock_key, ctx.execution_id)
            # If cannot read, fail closed.
            raise RollbackConcurrencyError("idempotency reservation race detected")

        attempts: List[RollbackAttempt] = []
        overall_error: Optional[str] = None
        status: RollbackStatus = RollbackStatus.SUCCEEDED

        try:
            await asyncio.wait_for(
                self._execute_steps(ctx, plan, attempts),
                timeout=float(self._policy.timeout_seconds_total),
            )
        except asyncio.TimeoutError as exc:
            status = RollbackStatus.FAILED
            overall_error = "rollback total timeout exceeded"
            await self._audit.emit(
                AuditEvent(
                    ts_unix=_now_unix(),
                    type="rollback.timeout",
                    request_id=ctx.request_id,
                    packet_id=ctx.packet_id,
                    execution_id=ctx.execution_id,
                    actor=ctx.actor,
                    environment=ctx.environment,
                    domain=ctx.domain,
                    status=status.value,
                    message=overall_error,
                    fields={"plan_id": plan.id, "idempotency_key": idem_key},
                )
            )
            raise RollbackTimeoutError(overall_error) from exc
        except RollbackError as exc:
            status = RollbackStatus.FAILED
            overall_error = str(exc)
            await self._audit.emit(
                AuditEvent(
                    ts_unix=_now_unix(),
                    type="rollback.failed",
                    request_id=ctx.request_id,
                    packet_id=ctx.packet_id,
                    execution_id=ctx.execution_id,
                    actor=ctx.actor,
                    environment=ctx.environment,
                    domain=ctx.domain,
                    status=status.value,
                    message=overall_error,
                    fields={"plan_id": plan.id, "idempotency_key": idem_key},
                )
            )
            raise
        except Exception as exc:
            status = RollbackStatus.FAILED
            overall_error = f"unexpected rollback error: {exc}"
            await self._audit.emit(
                AuditEvent(
                    ts_unix=_now_unix(),
                    type="rollback.failed_unexpected",
                    request_id=ctx.request_id,
                    packet_id=ctx.packet_id,
                    execution_id=ctx.execution_id,
                    actor=ctx.actor,
                    environment=ctx.environment,
                    domain=ctx.domain,
                    status=status.value,
                    message=overall_error,
                    fields={"plan_id": plan.id, "idempotency_key": idem_key},
                )
            )
            raise RollbackError(overall_error) from exc
        finally:
            await self._locks.release(lock_key, ctx.execution_id)

        # Determine final status if any partial failures were recorded but not thrown (best-effort mode).
        if any(a.status == RollbackStatus.FAILED for a in attempts):
            status = RollbackStatus.PARTIAL if not self._policy.stop_on_first_failure else RollbackStatus.FAILED
            if status == RollbackStatus.FAILED and overall_error is None:
                overall_error = "one or more rollback steps failed"

        finished = _now_unix()
        result = RollbackResult(
            status=status,
            started_unix=started,
            finished_unix=finished,
            plan_id=plan.id,
            idempotency_key=idem_key,
            attempts=tuple(attempts),
            error=overall_error,
            summary={
                "steps_total": len(plan.steps),
                "attempts_total": len(attempts),
                "dry_run": self._policy.dry_run,
            },
        )

        # Persist final result
        await self._idem.put(
            idem_key,
            _result_to_mapping(result),
            ttl_seconds=max(24 * 3600, self._policy.timeout_seconds_total),
        )

        await self._audit.emit(
            AuditEvent(
                ts_unix=finished,
                type="rollback.finished",
                request_id=ctx.request_id,
                packet_id=ctx.packet_id,
                execution_id=ctx.execution_id,
                actor=ctx.actor,
                environment=ctx.environment,
                domain=ctx.domain,
                status=result.status.value,
                message="rollback execution finished",
                fields={
                    "plan_id": plan.id,
                    "idempotency_key": idem_key,
                    "attempts_total": len(attempts),
                    "steps_total": len(plan.steps),
                    "dry_run": self._policy.dry_run,
                    "error": overall_error,
                },
            )
        )

        return result

    async def _execute_steps(self, ctx: RollbackContext, plan: RollbackPlan, attempts: List[RollbackAttempt]) -> None:
        # Execute in reverse order (rollback semantics)
        steps = list(plan.steps)[::-1]

        for step in steps:
            step_timeout = step.timeout_seconds or self._policy.timeout_seconds_per_step
            await self._audit.emit(
                AuditEvent(
                    ts_unix=_now_unix(),
                    type="rollback.step_started",
                    request_id=ctx.request_id,
                    packet_id=ctx.packet_id,
                    execution_id=ctx.execution_id,
                    actor=ctx.actor,
                    environment=ctx.environment,
                    domain=ctx.domain,
                    status=RollbackStatus.RUNNING.value,
                    message=f"step started: {step.id}",
                    fields={"plan_id": plan.id, "step_id": step.id, "title": step.title, "dry_run": self._policy.dry_run},
                )
            )

            ok = await self._run_step_with_retries(ctx, plan, step, step_timeout, attempts)

            if not ok:
                if self._policy.stop_on_first_failure:
                    raise RollbackStepError(f"rollback step failed: {step.id}")

    async def _run_step_with_retries(
        self,
        ctx: RollbackContext,
        plan: RollbackPlan,
        step: RollbackStep,
        step_timeout: int,
        attempts: List[RollbackAttempt],
    ) -> bool:
        last_error: Optional[str] = None

        for attempt_no in range(1, self._policy.max_attempts_per_step + 1):
            backoff = _compute_backoff(self._policy, attempt_no)
            if backoff > 0:
                await _sleep_backoff(backoff)

            started = _now_unix()
            try:
                if self._policy.dry_run:
                    # Dry-run never calls handler; still validates payload size and produces audit.
                    await asyncio.sleep(0)
                else:
                    await asyncio.wait_for(step.handler(ctx, step.payload), timeout=float(step_timeout))

                finished = _now_unix()
                attempts.append(
                    RollbackAttempt(
                        step_id=step.id,
                        attempt_no=attempt_no,
                        started_unix=started,
                        finished_unix=finished,
                        status=RollbackStatus.SUCCEEDED,
                        error=None,
                    )
                )
                await self._audit.emit(
                    AuditEvent(
                        ts_unix=finished,
                        type="rollback.step_succeeded",
                        request_id=ctx.request_id,
                        packet_id=ctx.packet_id,
                        execution_id=ctx.execution_id,
                        actor=ctx.actor,
                        environment=ctx.environment,
                        domain=ctx.domain,
                        status=RollbackStatus.SUCCEEDED.value,
                        message=f"step succeeded: {step.id}",
                        fields={"plan_id": plan.id, "step_id": step.id, "attempt_no": attempt_no},
                    )
                )
                return True

            except asyncio.TimeoutError:
                finished = _now_unix()
                last_error = f"step timeout exceeded: {step_timeout}s"
                attempts.append(
                    RollbackAttempt(
                        step_id=step.id,
                        attempt_no=attempt_no,
                        started_unix=started,
                        finished_unix=finished,
                        status=RollbackStatus.FAILED,
                        error=last_error,
                    )
                )
                await self._audit.emit(
                    AuditEvent(
                        ts_unix=finished,
                        type="rollback.step_failed",
                        request_id=ctx.request_id,
                        packet_id=ctx.packet_id,
                        execution_id=ctx.execution_id,
                        actor=ctx.actor,
                        environment=ctx.environment,
                        domain=ctx.domain,
                        status=RollbackStatus.FAILED.value,
                        message=f"step failed: {step.id}",
                        fields={
                            "plan_id": plan.id,
                            "step_id": step.id,
                            "attempt_no": attempt_no,
                            "error": last_error,
                            "semantics": step.semantics.value,
                        },
                    )
                )

            except Exception as exc:
                finished = _now_unix()
                last_error = str(exc)
                attempts.append(
                    RollbackAttempt(
                        step_id=step.id,
                        attempt_no=attempt_no,
                        started_unix=started,
                        finished_unix=finished,
                        status=RollbackStatus.FAILED,
                        error=last_error,
                    )
                )
                await self._audit.emit(
                    AuditEvent(
                        ts_unix=finished,
                        type="rollback.step_failed",
                        request_id=ctx.request_id,
                        packet_id=ctx.packet_id,
                        execution_id=ctx.execution_id,
                        actor=ctx.actor,
                        environment=ctx.environment,
                        domain=ctx.domain,
                        status=RollbackStatus.FAILED.value,
                        message=f"step failed: {step.id}",
                        fields={
                            "plan_id": plan.id,
                            "step_id": step.id,
                            "attempt_no": attempt_no,
                            "error": last_error,
                            "semantics": step.semantics.value,
                        },
                    )
                )

            # Retry decision
            if attempt_no < self._policy.max_attempts_per_step:
                continue

        # If all attempts failed:
        if step.semantics == StepSemantics.BEST_EFFORT and not self._policy.stop_on_first_failure:
            # Non-fatal in best-effort mode.
            await self._audit.emit(
                AuditEvent(
                    ts_unix=_now_unix(),
                    type="rollback.step_best_effort_exhausted",
                    request_id=ctx.request_id,
                    packet_id=ctx.packet_id,
                    execution_id=ctx.execution_id,
                    actor=ctx.actor,
                    environment=ctx.environment,
                    domain=ctx.domain,
                    status=RollbackStatus.PARTIAL.value,
                    message=f"best-effort step exhausted attempts: {step.id}",
                    fields={"plan_id": plan.id, "step_id": step.id, "error": last_error},
                )
            )
            return False

        # Fail closed by default
        raise RollbackStepError(f"step {step.id} failed after retries: {last_error}")


def _result_to_mapping(result: RollbackResult) -> Mapping[str, Any]:
    return {
        "status": result.status.value,
        "started_unix": result.started_unix,
        "finished_unix": result.finished_unix,
        "plan_id": result.plan_id,
        "idempotency_key": result.idempotency_key,
        "attempts": [
            {
                "step_id": a.step_id,
                "attempt_no": a.attempt_no,
                "started_unix": a.started_unix,
                "finished_unix": a.finished_unix,
                "status": a.status.value,
                "error": a.error,
            }
            for a in result.attempts
        ],
        "error": result.error,
        "summary": dict(result.summary),
    }


def _result_from_mapping(data: Mapping[str, Any]) -> RollbackResult:
    try:
        attempts_raw = data.get("attempts", [])
        attempts: List[RollbackAttempt] = []
        for a in attempts_raw:
            attempts.append(
                RollbackAttempt(
                    step_id=str(a["step_id"]),
                    attempt_no=int(a["attempt_no"]),
                    started_unix=int(a["started_unix"]),
                    finished_unix=int(a["finished_unix"]),
                    status=RollbackStatus(str(a["status"])),
                    error=a.get("error"),
                )
            )
        return RollbackResult(
            status=RollbackStatus(str(data["status"])),
            started_unix=int(data["started_unix"]),
            finished_unix=int(data["finished_unix"]),
            plan_id=str(data["plan_id"]),
            idempotency_key=str(data["idempotency_key"]),
            attempts=tuple(attempts),
            error=data.get("error"),
            summary=data.get("summary", {}) if isinstance(data.get("summary", {}), Mapping) else {},
        )
    except Exception as exc:
        raise RollbackValidationError(f"invalid stored rollback result: {exc}") from exc
