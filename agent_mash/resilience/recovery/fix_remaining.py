# agent_mash/resilience/recovery/fix_remaining.py
from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Set, Tuple


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Outcome(str, Enum):
    FIXED = "fixed"
    UNCHANGED = "unchanged"
    SKIPPED = "skipped"
    FAILED = "failed"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class TaskSpec:
    """
    A recovery task specification.

    - id: stable identifier (used for idempotency and dedupe)
    - name: human label
    - severity: governs priority ordering (higher first)
    - depends_on: task ids that must be succeeded before this can run
    - timeout_seconds: per-attempt wall clock budget (soft; cooperative)
    - max_attempts: hard cap for retry attempts
    - retry_backoff_base_seconds: base backoff used with exponential growth
    """
    id: str
    name: str
    severity: Severity = Severity.MEDIUM
    depends_on: Tuple[str, ...] = ()
    timeout_seconds: int = 60
    max_attempts: int = 3
    retry_backoff_base_seconds: float = 1.0

    def validate(self) -> None:
        _validate_id(self.id, "TaskSpec.id")
        _validate_nonempty(self.name, "TaskSpec.name")
        if self.timeout_seconds <= 0:
            raise ValueError("TaskSpec.timeout_seconds must be > 0")
        if self.max_attempts <= 0:
            raise ValueError("TaskSpec.max_attempts must be > 0")
        _validate_finite(self.retry_backoff_base_seconds, "TaskSpec.retry_backoff_base_seconds")
        if self.retry_backoff_base_seconds <= 0:
            raise ValueError("TaskSpec.retry_backoff_base_seconds must be > 0")
        for d in self.depends_on:
            _validate_id(d, "TaskSpec.depends_on")


@dataclass(frozen=True)
class TaskState:
    """
    Persisted state for a task across recovery runs.
    """
    task_id: str
    status: TaskStatus
    attempts: int = 0
    last_error: str = ""
    updated_at_unix: float = field(default_factory=lambda: time.time())

    def validate(self) -> None:
        _validate_id(self.task_id, "TaskState.task_id")
        if not isinstance(self.status, TaskStatus):
            raise TypeError("TaskState.status must be TaskStatus")
        if not isinstance(self.attempts, int) or self.attempts < 0:
            raise ValueError("TaskState.attempts must be int >= 0")
        _validate_finite(self.updated_at_unix, "TaskState.updated_at_unix")


@dataclass(frozen=True)
class TaskExecutionContext:
    """
    Execution context injected into task handlers.
    """
    now_unix: float
    run_id: str
    attempt: int
    deadline_unix: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    def remaining_seconds(self) -> float:
        return max(0.0, float(self.deadline_unix) - float(self.now_unix))


@dataclass(frozen=True)
class TaskResult:
    """
    Returned by task handlers. Must be deterministic and serializable.
    """
    outcome: Outcome
    message: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not isinstance(self.outcome, Outcome):
            raise TypeError("TaskResult.outcome must be Outcome")
        if not isinstance(self.message, str):
            raise TypeError("TaskResult.message must be str")
        if not isinstance(self.evidence, dict):
            raise TypeError("TaskResult.evidence must be dict")


@dataclass(frozen=True)
class TaskRecord:
    """
    Execution record for reporting.
    """
    task_id: str
    name: str
    severity: str
    outcome: str
    attempts: int
    started_at_unix: float
    finished_at_unix: float
    message: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class RecoveryReport:
    """
    Final report of a fix_remaining run.
    """
    run_id: str
    started_at_unix: float
    finished_at_unix: float
    totals: Dict[str, int]
    records: Tuple[TaskRecord, ...]
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "started_at_unix": self.started_at_unix,
            "finished_at_unix": self.finished_at_unix,
            "totals": dict(self.totals),
            "records": [r.to_dict() for r in self.records],
            "meta": dict(self.meta),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)


class StateStore(Protocol):
    """
    Storage interface for recovery task states.
    Implementations may persist to DB/Redis/files; this module stays I/O free.
    """
    def get(self, task_id: str) -> Optional[TaskState]:
        ...

    def set(self, state: TaskState) -> None:
        ...

    def list(self) -> Sequence[TaskState]:
        ...


class TaskRegistry(Protocol):
    """
    Registry for task specs and handlers.
    """
    def specs(self) -> Sequence[TaskSpec]:
        ...

    def handler(self, task_id: str) -> Callable[[TaskExecutionContext], TaskResult]:
        ...


class Clock(Protocol):
    def now(self) -> float:
        ...


@dataclass(frozen=True)
class SystemClock:
    def now(self) -> float:
        return time.time()


@dataclass(frozen=True)
class FixRemainingConfig:
    """
    Controls how fix_remaining executes.

    - stop_on_first_failure: if True, abort after first FAILED outcome
    - include_severities: optional allowlist; if empty -> all
    - max_total_seconds: hard cap for entire run (soft; cooperative)
    - max_tasks: optional cap of how many tasks to execute this run
    - allow_rerun_succeeded: if True, can rerun succeeded tasks (default False)
    """
    stop_on_first_failure: bool = False
    include_severities: Tuple[Severity, ...] = ()
    max_total_seconds: int = 600
    max_tasks: Optional[int] = None
    allow_rerun_succeeded: bool = False

    def validate(self) -> None:
        if self.max_total_seconds <= 0:
            raise ValueError("FixRemainingConfig.max_total_seconds must be > 0")
        if self.max_tasks is not None and (not isinstance(self.max_tasks, int) or self.max_tasks <= 0):
            raise ValueError("FixRemainingConfig.max_tasks must be None or int > 0")
        for s in self.include_severities:
            if not isinstance(s, Severity):
                raise TypeError("FixRemainingConfig.include_severities must contain Severity")


def fix_remaining(
    store: StateStore,
    registry: TaskRegistry,
    *,
    config: Optional[FixRemainingConfig] = None,
    clock: Optional[Clock] = None,
    run_id: Optional[str] = None,
) -> RecoveryReport:
    """
    Execute remaining recovery tasks.

    "Remaining" is defined as tasks that are:
    - missing in store, or
    - status in {PENDING, FAILED, BLOCKED}, or
    - RUNNING but stale (not managed here; left to store policies), or
    - SKIPPED (optional: rerun not default)

    This function:
    - validates registry specs
    - filters by severity
    - topologically orders by dependencies
    - executes with deterministic exponential backoff retries
    - persists TaskState transitions
    - returns a structured RecoveryReport
    """
    cfg = config or FixRemainingConfig()
    cfg.validate()
    clk = clock or SystemClock()

    started = float(clk.now())
    deadline = started + float(cfg.max_total_seconds)

    rid = run_id.strip() if isinstance(run_id, str) and run_id.strip() else _make_run_id(started)

    specs = list(registry.specs())
    if not specs:
        finished = float(clk.now())
        return RecoveryReport(
            run_id=rid,
            started_at_unix=started,
            finished_at_unix=finished,
            totals=_totals_from_records([]),
            records=(),
            meta={"note": "no_specs"},
        )

    # Validate and build spec map
    spec_by_id: Dict[str, TaskSpec] = {}
    for s in specs:
        s.validate()
        if s.id in spec_by_id:
            raise ValueError(f"Duplicate TaskSpec.id: {s.id}")
        spec_by_id[s.id] = s

    # Validate dependency references
    for s in specs:
        for d in s.depends_on:
            if d not in spec_by_id:
                raise ValueError(f"TaskSpec {s.id} depends on unknown task id: {d}")

    # Filter severities
    if cfg.include_severities:
        allowed = set(cfg.include_severities)
        specs = [s for s in specs if s.severity in allowed]

    # Build current states
    state_by_id: Dict[str, TaskState] = {st.task_id: st for st in store.list()}

    # Determine remaining
    remaining = _select_remaining(specs, state_by_id, allow_rerun_succeeded=cfg.allow_rerun_succeeded)

    # Order by dependencies + severity + stable id
    ordered = _topo_sort_with_priority(remaining, spec_by_id)

    # Enforce max_tasks
    if cfg.max_tasks is not None:
        ordered = ordered[: cfg.max_tasks]

    records: List[TaskRecord] = []
    executed: Set[str] = set()

    for task_id in ordered:
        now = float(clk.now())
        if now >= deadline:
            break

        spec = spec_by_id[task_id]

        # Dependencies gate
        dep_ok, blocked_by = _deps_satisfied(spec, store, spec_by_id)
        if not dep_ok:
            st = TaskState(task_id=task_id, status=TaskStatus.BLOCKED, attempts=state_by_id.get(task_id, TaskState(task_id, TaskStatus.PENDING)).attempts, last_error=f"blocked_by={blocked_by}", updated_at_unix=now)
            store.set(st)
            records.append(
                TaskRecord(
                    task_id=task_id,
                    name=spec.name,
                    severity=spec.severity.value,
                    outcome=Outcome.BLOCKED.value,
                    attempts=st.attempts,
                    started_at_unix=now,
                    finished_at_unix=now,
                    message="dependencies_not_satisfied",
                    evidence={"blocked_by": blocked_by},
                    error="",
                )
            )
            continue

        # Execute with retries
        rec = _execute_task_with_retries(
            store=store,
            registry=registry,
            spec=spec,
            run_id=rid,
            clock=clk,
            run_deadline_unix=deadline,
        )
        records.append(rec)
        executed.add(task_id)

        if cfg.stop_on_first_failure and rec.outcome in (Outcome.FAILED.value,):
            break

    finished = float(clk.now())
    totals = _totals_from_records(records)
    meta = {
        "executed": len(executed),
        "remaining_initial": len(remaining),
        "ordered": len(ordered),
        "deadline_unix": deadline,
    }

    return RecoveryReport(
        run_id=rid,
        started_at_unix=started,
        finished_at_unix=finished,
        totals=totals,
        records=tuple(records),
        meta=meta,
    )


# ----------------------------
# Execution internals
# ----------------------------

def _execute_task_with_retries(
    *,
    store: StateStore,
    registry: TaskRegistry,
    spec: TaskSpec,
    run_id: str,
    clock: Clock,
    run_deadline_unix: float,
) -> TaskRecord:
    started = float(clock.now())
    attempts0 = store.get(spec.id).attempts if store.get(spec.id) is not None else 0

    # Mark running (idempotent)
    store.set(TaskState(task_id=spec.id, status=TaskStatus.RUNNING, attempts=attempts0, last_error="", updated_at_unix=started))

    handler = registry.handler(spec.id)
    if not callable(handler):
        err = "handler_not_callable"
        now = float(clock.now())
        store.set(TaskState(task_id=spec.id, status=TaskStatus.FAILED, attempts=attempts0, last_error=err, updated_at_unix=now))
        return TaskRecord(
            task_id=spec.id,
            name=spec.name,
            severity=spec.severity.value,
            outcome=Outcome.FAILED.value,
            attempts=attempts0,
            started_at_unix=started,
            finished_at_unix=now,
            message="",
            evidence={},
            error=err,
        )

    last_error = ""
    last_result: Optional[TaskResult] = None

    for attempt in range(1, spec.max_attempts + 1):
        now = float(clock.now())
        if now >= run_deadline_unix:
            last_error = "run_deadline_exceeded"
            break

        # Per-attempt deadline
        attempt_deadline = min(run_deadline_unix, now + float(spec.timeout_seconds))
        ctx = TaskExecutionContext(
            now_unix=now,
            run_id=run_id,
            attempt=attempt,
            deadline_unix=attempt_deadline,
            metadata={"task_id": spec.id, "task_name": spec.name, "severity": spec.severity.value},
        )

        # Update attempts count in store before execution (so crashes still record attempt)
        store.set(TaskState(task_id=spec.id, status=TaskStatus.RUNNING, attempts=attempts0 + attempt, last_error="", updated_at_unix=now))

        try:
            res = handler(ctx)
            if not isinstance(res, TaskResult):
                raise TypeError("task handler must return TaskResult")
            res.validate()
            last_result = res

            if res.outcome == Outcome.FIXED:
                end = float(clock.now())
                store.set(TaskState(task_id=spec.id, status=TaskStatus.SUCCEEDED, attempts=attempts0 + attempt, last_error="", updated_at_unix=end))
                return TaskRecord(
                    task_id=spec.id,
                    name=spec.name,
                    severity=spec.severity.value,
                    outcome=Outcome.FIXED.value,
                    attempts=attempts0 + attempt,
                    started_at_unix=started,
                    finished_at_unix=end,
                    message=res.message,
                    evidence=dict(res.evidence),
                    error="",
                )

            if res.outcome == Outcome.UNCHANGED:
                # Treat unchanged as success from recovery standpoint, but preserve semantics
                end = float(clock.now())
                store.set(TaskState(task_id=spec.id, status=TaskStatus.SUCCEEDED, attempts=attempts0 + attempt, last_error="", updated_at_unix=end))
                return TaskRecord(
                    task_id=spec.id,
                    name=spec.name,
                    severity=spec.severity.value,
                    outcome=Outcome.UNCHANGED.value,
                    attempts=attempts0 + attempt,
                    started_at_unix=started,
                    finished_at_unix=end,
                    message=res.message,
                    evidence=dict(res.evidence),
                    error="",
                )

            if res.outcome in (Outcome.SKIPPED, Outcome.BLOCKED):
                end = float(clock.now())
                st_status = TaskStatus.SKIPPED if res.outcome == Outcome.SKIPPED else TaskStatus.BLOCKED
                store.set(TaskState(task_id=spec.id, status=st_status, attempts=attempts0 + attempt, last_error="", updated_at_unix=end))
                return TaskRecord(
                    task_id=spec.id,
                    name=spec.name,
                    severity=spec.severity.value,
                    outcome=res.outcome.value,
                    attempts=attempts0 + attempt,
                    started_at_unix=started,
                    finished_at_unix=end,
                    message=res.message,
                    evidence=dict(res.evidence),
                    error="",
                )

            if res.outcome == Outcome.FAILED:
                last_error = res.message or "task_failed"
                # retry if attempts remain
        except Exception as e:
            last_error = _safe_exc_str(e)

        # If we are here, attempt failed (logical or exception)
        now2 = float(clock.now())
        store.set(TaskState(task_id=spec.id, status=TaskStatus.FAILED, attempts=attempts0 + attempt, last_error=last_error, updated_at_unix=now2))

        if attempt >= spec.max_attempts:
            break

        # Backoff sleep (cooperative; no actual sleep here to keep module I/O free)
        # We compute and expose backoff in evidence; caller/orchestrator may sleep if desired.
        _ = _backoff_seconds(spec, attempt)

    end = float(clock.now())
    store.set(TaskState(task_id=spec.id, status=TaskStatus.FAILED, attempts=attempts0 + min(spec.max_attempts, max(1, attempt)), last_error=last_error, updated_at_unix=end))

    evidence: Dict[str, Any] = {
        "max_attempts": spec.max_attempts,
        "timeout_seconds": spec.timeout_seconds,
        "retry_backoff_base_seconds": spec.retry_backoff_base_seconds,
        "last_result": dataclasses.asdict(last_result) if last_result is not None else None,
        "suggested_backoff_seconds_next": _backoff_seconds(spec, min(spec.max_attempts, max(1, attempt))),
    }

    return TaskRecord(
        task_id=spec.id,
        name=spec.name,
        severity=spec.severity.value,
        outcome=Outcome.FAILED.value,
        attempts=attempts0 + min(spec.max_attempts, max(1, attempt)),
        started_at_unix=started,
        finished_at_unix=end,
        message="",
        evidence=evidence,
        error=last_error,
    )


def _backoff_seconds(spec: TaskSpec, attempt: int) -> float:
    """
    Deterministic exponential backoff with bounded jitter derived from task id and attempt.

    backoff = base * 2^(attempt-1) * (1 + jitter)
    jitter in [0..0.2]
    """
    base = float(spec.retry_backoff_base_seconds)
    exp = 2.0 ** float(max(0, attempt - 1))
    jitter = _deterministic_jitter_0_02(spec.id, attempt)
    return base * exp * (1.0 + jitter)


def _deterministic_jitter_0_02(task_id: str, attempt: int) -> float:
    h = hashlib.sha256(f"{task_id}:{attempt}".encode("utf-8")).digest()
    # Use first 4 bytes as uint32
    u = int.from_bytes(h[:4], "big", signed=False)
    # Map to [0..1)
    x = (u % 10_000_000) / 10_000_000.0
    return 0.2 * x


def _select_remaining(
    specs: Sequence[TaskSpec],
    state_by_id: Mapping[str, TaskState],
    *,
    allow_rerun_succeeded: bool,
) -> List[str]:
    out: List[str] = []
    for s in specs:
        st = state_by_id.get(s.id)
        if st is None:
            out.append(s.id)
            continue
        st.validate()
        if st.status in (TaskStatus.PENDING, TaskStatus.FAILED, TaskStatus.BLOCKED):
            out.append(s.id)
            continue
        if st.status == TaskStatus.SKIPPED:
            out.append(s.id)
            continue
        if st.status == TaskStatus.SUCCEEDED and allow_rerun_succeeded:
            out.append(s.id)
            continue
    return out


def _deps_satisfied(spec: TaskSpec, store: StateStore, spec_by_id: Mapping[str, TaskSpec]) -> Tuple[bool, List[str]]:
    blocked_by: List[str] = []
    for dep in spec.depends_on:
        # dependency must exist in registry
        if dep not in spec_by_id:
            blocked_by.append(dep)
            continue
        st = store.get(dep)
        if st is None or st.status != TaskStatus.SUCCEEDED:
            blocked_by.append(dep)
    return (len(blocked_by) == 0), blocked_by


def _topo_sort_with_priority(task_ids: Sequence[str], spec_by_id: Mapping[str, TaskSpec]) -> List[str]:
    """
    Topological sort over the induced subgraph of task_ids.
    Priority tie-break:
    - higher severity first
    - then stable task_id lexicographic
    """
    wanted = set(task_ids)
    deps: Dict[str, Set[str]] = {}
    rdeps: Dict[str, Set[str]] = {}

    for tid in wanted:
        spec = spec_by_id[tid]
        dset = set(d for d in spec.depends_on if d in wanted)
        deps[tid] = dset
        for d in dset:
            rdeps.setdefault(d, set()).add(tid)

    def pri(tid: str) -> Tuple[int, str]:
        sev = spec_by_id[tid].severity
        rank = _severity_rank(sev)
        return (-rank, tid)

    ready = sorted([tid for tid, ds in deps.items() if not ds], key=pri)
    out: List[str] = []

    while ready:
        tid = ready.pop(0)
        out.append(tid)
        for child in sorted(rdeps.get(tid, set())):
            if tid in deps.get(child, set()):
                deps[child].remove(tid)
            if not deps[child] and child not in out and child not in ready:
                ready.append(child)
        ready.sort(key=pri)

    # If cycle exists, append remaining in priority order (deterministic) and mark as blocked at execution stage
    remaining = [tid for tid in wanted if tid not in out]
    remaining.sort(key=pri)
    out.extend(remaining)
    return out


def _severity_rank(s: Severity) -> int:
    return {
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }[s]


def _totals_from_records(records: Sequence[TaskRecord]) -> Dict[str, int]:
    totals: Dict[str, int] = {
        Outcome.FIXED.value: 0,
        Outcome.UNCHANGED.value: 0,
        Outcome.SKIPPED.value: 0,
        Outcome.BLOCKED.value: 0,
        Outcome.FAILED.value: 0,
        "total": 0,
    }
    for r in records:
        totals["total"] += 1
        if r.outcome in totals:
            totals[r.outcome] += 1
        else:
            totals[r.outcome] = totals.get(r.outcome, 0) + 1
    return totals


def _make_run_id(started_unix: float) -> str:
    # Deterministic-ish run id based on timestamp and monotonic hash
    raw = f"{started_unix:.6f}"
    h = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"fixrem-{int(started_unix)}-{h}"


def _safe_exc_str(e: Exception) -> str:
    try:
        s = str(e)
        return s if s else e.__class__.__name__
    except Exception:
        return "exception"


def _validate_nonempty(s: str, name: str) -> None:
    if not isinstance(s, str):
        raise TypeError(f"{name} must be str")
    if not s.strip():
        raise ValueError(f"{name} must be non-empty")


def _validate_id(s: str, name: str) -> None:
    _validate_nonempty(s, name)
    if len(s) < 3 or len(s) > 128:
        raise ValueError(f"{name} length must be 3..128")
    for ch in s:
        if ch.isalnum():
            continue
        if ch in "._-":
            continue
        raise ValueError(f"{name} has invalid character: {ch!r}")


def _validate_finite(x: float, name: str) -> None:
    if not isinstance(x, (int, float)):
        raise TypeError(f"{name} must be numeric")
    fx = float(x)
    if math.isnan(fx) or math.isinf(fx):
        raise ValueError(f"{name} must be finite")


def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return float(x)
