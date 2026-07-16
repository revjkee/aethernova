from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


class RollbackError(ValueError):
    pass


class RollbackState(str, Enum):
    DRAFT = "draft"
    READY = "ready"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    ABORTED = "aborted"


class RollbackMode(str, Enum):
    DRY_RUN = "dry_run"
    ENFORCE = "enforce"


class StepKind(str, Enum):
    CONFIG_CHANGE = "config_change"
    DEPLOYMENT = "deployment"
    TRAFFIC_SHIFT = "traffic_shift"
    FEATURE_FLAG = "feature_flag"
    DATA_MIGRATION = "data_migration"
    EXTERNAL_ACTION = "external_action"
    CUSTOM = "custom"


class StepDecision(str, Enum):
    CONTINUE = "continue"
    STOP = "stop"
    ABORT = "abort"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApprovalKind(str, Enum):
    HUMAN = "human"
    AUTOMATED = "automated"


def _now_epoch_seconds() -> int:
    return int(time.time())


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RollbackError(f"{name} must be a non-empty string")
    return value.strip()


def _require_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RollbackError(f"{name} must be an integer")
    return value


def _require_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RollbackError(f"{name} must be a mapping")
    return value


def _require_sequence(value: Any, name: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise RollbackError(f"{name} must be a sequence")
    return value


def _canonical_json_bytes(data: Any) -> bytes:
    try:
        return json.dumps(
            data,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except Exception as exc:
        raise RollbackError("failed to canonicalize json") from exc


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _clamp_int(v: int, min_v: int, max_v: int, name: str) -> int:
    if v < min_v or v > max_v:
        raise RollbackError(f"{name} must be between {min_v} and {max_v}")
    return v


@dataclass(frozen=True, slots=True)
class Approval:
    kind: ApprovalKind
    approver: str
    approved_at: int
    reason: str
    signature_ref: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", ApprovalKind(self.kind))
        object.__setattr__(self, "approver", _require_str(self.approver, "approver"))
        object.__setattr__(self, "approved_at", _require_int(self.approved_at, "approved_at"))
        object.__setattr__(self, "reason", _require_str(self.reason, "reason"))
        if self.signature_ref is not None:
            object.__setattr__(self, "signature_ref", _require_str(self.signature_ref, "signature_ref"))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind.value,
            "approver": self.approver,
            "approved_at": self.approved_at,
            "reason": self.reason,
            "signature_ref": self.signature_ref,
        }

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "Approval":
        d = _require_mapping(data, "approval")
        return Approval(
            kind=ApprovalKind(str(d.get("kind"))),
            approver=str(d.get("approver", "")),
            approved_at=int(d.get("approved_at")),
            reason=str(d.get("reason", "")),
            signature_ref=(str(d.get("signature_ref")) if d.get("signature_ref") is not None else None),
        )


@dataclass(frozen=True, slots=True)
class TimeWindow:
    start_epoch: int
    end_epoch: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "start_epoch", _require_int(self.start_epoch, "start_epoch"))
        object.__setattr__(self, "end_epoch", _require_int(self.end_epoch, "end_epoch"))
        if self.end_epoch <= self.start_epoch:
            raise RollbackError("time window end must be greater than start")

    def contains(self, now_epoch: int) -> bool:
        n = _require_int(now_epoch, "now_epoch")
        return self.start_epoch <= n <= self.end_epoch

    def to_dict(self) -> Dict[str, Any]:
        return {"start_epoch": self.start_epoch, "end_epoch": self.end_epoch}

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "TimeWindow":
        d = _require_mapping(data, "time_window")
        return TimeWindow(start_epoch=int(d.get("start_epoch")), end_epoch=int(d.get("end_epoch")))


@dataclass(frozen=True, slots=True)
class SafetyRails:
    fail_closed: bool = True
    require_approvals: bool = True
    min_approvals: int = 1
    require_break_glass_for_critical: bool = True
    max_step_duration_seconds: int = 900
    max_total_duration_seconds: int = 7200
    allow_irreversible_steps_in_enforce: bool = False
    block_if_environment: Tuple[str, ...] = field(default_factory=tuple)
    require_change_ticket: bool = True
    allow_data_migration_in_enforce: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.fail_closed, bool):
            raise RollbackError("fail_closed must be bool")
        if not isinstance(self.require_approvals, bool):
            raise RollbackError("require_approvals must be bool")
        object.__setattr__(self, "min_approvals", _require_int(self.min_approvals, "min_approvals"))
        if self.min_approvals < 0:
            raise RollbackError("min_approvals must be >= 0")
        if not isinstance(self.require_break_glass_for_critical, bool):
            raise RollbackError("require_break_glass_for_critical must be bool")

        object.__setattr__(self, "max_step_duration_seconds", _require_int(self.max_step_duration_seconds, "max_step_duration_seconds"))
        object.__setattr__(self, "max_total_duration_seconds", _require_int(self.max_total_duration_seconds, "max_total_duration_seconds"))

        _clamp_int(self.max_step_duration_seconds, 1, 86400, "max_step_duration_seconds")
        _clamp_int(self.max_total_duration_seconds, 1, 604800, "max_total_duration_seconds")

        if not isinstance(self.allow_irreversible_steps_in_enforce, bool):
            raise RollbackError("allow_irreversible_steps_in_enforce must be bool")
        if not isinstance(self.require_change_ticket, bool):
            raise RollbackError("require_change_ticket must be bool")
        if not isinstance(self.allow_data_migration_in_enforce, bool):
            raise RollbackError("allow_data_migration_in_enforce must be bool")

        if not isinstance(self.block_if_environment, tuple):
            object.__setattr__(self, "block_if_environment", tuple(self.block_if_environment))
        for e in self.block_if_environment:
            _require_str(e, "blocked environment")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fail_closed": self.fail_closed,
            "require_approvals": self.require_approvals,
            "min_approvals": self.min_approvals,
            "require_break_glass_for_critical": self.require_break_glass_for_critical,
            "max_step_duration_seconds": self.max_step_duration_seconds,
            "max_total_duration_seconds": self.max_total_duration_seconds,
            "allow_irreversible_steps_in_enforce": self.allow_irreversible_steps_in_enforce,
            "block_if_environment": list(self.block_if_environment),
            "require_change_ticket": self.require_change_ticket,
            "allow_data_migration_in_enforce": self.allow_data_migration_in_enforce,
        }

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "SafetyRails":
        d = _require_mapping(data, "safety_rails")
        return SafetyRails(
            fail_closed=bool(d.get("fail_closed", True)),
            require_approvals=bool(d.get("require_approvals", True)),
            min_approvals=int(d.get("min_approvals", 1)),
            require_break_glass_for_critical=bool(d.get("require_break_glass_for_critical", True)),
            max_step_duration_seconds=int(d.get("max_step_duration_seconds", 900)),
            max_total_duration_seconds=int(d.get("max_total_duration_seconds", 7200)),
            allow_irreversible_steps_in_enforce=bool(d.get("allow_irreversible_steps_in_enforce", False)),
            block_if_environment=tuple(str(x) for x in d.get("block_if_environment", []) or []),
            require_change_ticket=bool(d.get("require_change_ticket", True)),
            allow_data_migration_in_enforce=bool(d.get("allow_data_migration_in_enforce", False)),
        )


@dataclass(frozen=True, slots=True)
class RollbackStep:
    id: str
    kind: StepKind
    title: str
    description: str
    target: str
    params: Mapping[str, Any] = field(default_factory=dict)

    idempotency_key: Optional[str] = None
    reversible: bool = True
    risk: RiskLevel = RiskLevel.MEDIUM
    timeout_seconds: int = 300
    depends_on: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _require_str(self.id, "step id"))
        object.__setattr__(self, "kind", StepKind(self.kind))
        object.__setattr__(self, "title", _require_str(self.title, "title"))
        object.__setattr__(self, "description", _require_str(self.description, "description"))
        object.__setattr__(self, "target", _require_str(self.target, "target"))
        if self.params is None:
            object.__setattr__(self, "params", {})
        _require_mapping(self.params, "params")

        if self.idempotency_key is not None:
            object.__setattr__(self, "idempotency_key", _require_str(self.idempotency_key, "idempotency_key"))

        if not isinstance(self.reversible, bool):
            raise RollbackError("reversible must be bool")

        object.__setattr__(self, "risk", RiskLevel(self.risk))
        object.__setattr__(self, "timeout_seconds", _require_int(self.timeout_seconds, "timeout_seconds"))
        _clamp_int(self.timeout_seconds, 1, 86400, "timeout_seconds")

        if not isinstance(self.depends_on, tuple):
            object.__setattr__(self, "depends_on", tuple(self.depends_on))
        for dep in self.depends_on:
            _require_str(dep, "depends_on")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "title": self.title,
            "description": self.description,
            "target": self.target,
            "params": dict(self.params),
            "idempotency_key": self.idempotency_key,
            "reversible": self.reversible,
            "risk": self.risk.value,
            "timeout_seconds": self.timeout_seconds,
            "depends_on": list(self.depends_on),
        }

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "RollbackStep":
        d = _require_mapping(data, "rollback_step")
        return RollbackStep(
            id=str(d.get("id", "")),
            kind=StepKind(str(d.get("kind"))),
            title=str(d.get("title", "")),
            description=str(d.get("description", "")),
            target=str(d.get("target", "")),
            params=(d.get("params") or {}),
            idempotency_key=(str(d.get("idempotency_key")) if d.get("idempotency_key") is not None else None),
            reversible=bool(d.get("reversible", True)),
            risk=RiskLevel(str(d.get("risk", RiskLevel.MEDIUM.value))),
            timeout_seconds=int(d.get("timeout_seconds", 300)),
            depends_on=tuple(str(x) for x in (d.get("depends_on") or [])),
        )


@dataclass(frozen=True, slots=True)
class RollbackPlan:
    plan_id: str
    created_at: int
    created_by: str

    service: str
    environment: str
    incident_id: Optional[str]
    change_ticket: Optional[str]

    objective: str
    rationale: str

    mode: RollbackMode = RollbackMode.ENFORCE
    state: RollbackState = RollbackState.DRAFT
    risk: RiskLevel = RiskLevel.MEDIUM

    steps: Tuple[RollbackStep, ...] = field(default_factory=tuple)
    approvals: Tuple[Approval, ...] = field(default_factory=tuple)
    allowed_window: Optional[TimeWindow] = None
    safety: SafetyRails = field(default_factory=SafetyRails)

    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "plan_id", _require_str(self.plan_id, "plan_id"))
        object.__setattr__(self, "created_at", _require_int(self.created_at, "created_at"))
        object.__setattr__(self, "created_by", _require_str(self.created_by, "created_by"))

        object.__setattr__(self, "service", _require_str(self.service, "service"))
        object.__setattr__(self, "environment", _require_str(self.environment, "environment"))

        if self.incident_id is not None:
            object.__setattr__(self, "incident_id", _require_str(self.incident_id, "incident_id"))
        if self.change_ticket is not None:
            object.__setattr__(self, "change_ticket", _require_str(self.change_ticket, "change_ticket"))

        object.__setattr__(self, "objective", _require_str(self.objective, "objective"))
        object.__setattr__(self, "rationale", _require_str(self.rationale, "rationale"))

        object.__setattr__(self, "mode", RollbackMode(self.mode))
        object.__setattr__(self, "state", RollbackState(self.state))
        object.__setattr__(self, "risk", RiskLevel(self.risk))

        if not isinstance(self.steps, tuple):
            object.__setattr__(self, "steps", tuple(self.steps))
        if not self.steps:
            raise RollbackError("rollback plan must contain at least one step")
        for s in self.steps:
            if not isinstance(s, RollbackStep):
                raise RollbackError("steps must be RollbackStep")

        ids = [s.id for s in self.steps]
        if len(set(ids)) != len(ids):
            raise RollbackError("duplicate step id in plan")

        if not isinstance(self.approvals, tuple):
            object.__setattr__(self, "approvals", tuple(self.approvals))
        for a in self.approvals:
            if not isinstance(a, Approval):
                raise RollbackError("approvals must be Approval")

        if self.allowed_window is not None and not isinstance(self.allowed_window, TimeWindow):
            raise RollbackError("allowed_window must be TimeWindow")

        if not isinstance(self.safety, SafetyRails):
            raise RollbackError("safety must be SafetyRails")

        if self.metadata is None:
            object.__setattr__(self, "metadata", {})
        _require_mapping(self.metadata, "metadata")

    def fingerprint(self) -> str:
        payload = self.to_dict(include_fingerprint=False)
        return _sha256_hex(_canonical_json_bytes(payload))

    def to_dict(self, include_fingerprint: bool = True) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "plan_id": self.plan_id,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "service": self.service,
            "environment": self.environment,
            "incident_id": self.incident_id,
            "change_ticket": self.change_ticket,
            "objective": self.objective,
            "rationale": self.rationale,
            "mode": self.mode.value,
            "state": self.state.value,
            "risk": self.risk.value,
            "steps": [s.to_dict() for s in self.steps],
            "approvals": [a.to_dict() for a in self.approvals],
            "allowed_window": (self.allowed_window.to_dict() if self.allowed_window is not None else None),
            "safety": self.safety.to_dict(),
            "metadata": dict(self.metadata),
        }
        if include_fingerprint:
            d["fingerprint_sha256"] = self.fingerprint()
        return d

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "RollbackPlan":
        d = _require_mapping(data, "rollback_plan")
        steps_data = _require_sequence(d.get("steps") or [], "steps")
        approvals_data = _require_sequence(d.get("approvals") or [], "approvals")

        allowed_window = d.get("allowed_window")
        tw = TimeWindow.from_dict(allowed_window) if isinstance(allowed_window, Mapping) else None

        safety = d.get("safety")
        sr = SafetyRails.from_dict(safety) if isinstance(safety, Mapping) else SafetyRails()

        return RollbackPlan(
            plan_id=str(d.get("plan_id", "")),
            created_at=int(d.get("created_at")),
            created_by=str(d.get("created_by", "")),
            service=str(d.get("service", "")),
            environment=str(d.get("environment", "")),
            incident_id=(str(d.get("incident_id")) if d.get("incident_id") is not None else None),
            change_ticket=(str(d.get("change_ticket")) if d.get("change_ticket") is not None else None),
            objective=str(d.get("objective", "")),
            rationale=str(d.get("rationale", "")),
            mode=RollbackMode(str(d.get("mode", RollbackMode.ENFORCE.value))),
            state=RollbackState(str(d.get("state", RollbackState.DRAFT.value))),
            risk=RiskLevel(str(d.get("risk", RiskLevel.MEDIUM.value))),
            steps=tuple(RollbackStep.from_dict(x) for x in steps_data),
            approvals=tuple(Approval.from_dict(x) for x in approvals_data),
            allowed_window=tw,
            safety=sr,
            metadata=(d.get("metadata") or {}),
        )


@dataclass(frozen=True, slots=True)
class PlanValidationResult:
    ok: bool
    errors: Tuple[str, ...] = field(default_factory=tuple)
    warnings: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.ok, bool):
            raise RollbackError("ok must be bool")
        if not isinstance(self.errors, tuple):
            object.__setattr__(self, "errors", tuple(self.errors))
        if not isinstance(self.warnings, tuple):
            object.__setattr__(self, "warnings", tuple(self.warnings))


class RollbackPlanValidator:
    def validate(self, plan: RollbackPlan, now_epoch: Optional[int] = None) -> PlanValidationResult:
        if not isinstance(plan, RollbackPlan):
            raise RollbackError("plan must be RollbackPlan")

        now = _now_epoch_seconds() if now_epoch is None else _require_int(now_epoch, "now_epoch")

        errors: List[str] = []
        warnings: List[str] = []

        if plan.environment in plan.safety.block_if_environment:
            errors.append("environment is blocked by safety rails")

        if plan.safety.require_change_ticket and not plan.change_ticket:
            errors.append("change_ticket is required by safety rails")

        if plan.allowed_window is not None and not plan.allowed_window.contains(now):
            errors.append("execution not allowed outside allowed_window")

        if plan.safety.require_approvals:
            if plan.safety.min_approvals > 0 and len(plan.approvals) < plan.safety.min_approvals:
                errors.append("insufficient approvals")
            if plan.risk == RiskLevel.CRITICAL and plan.safety.require_break_glass_for_critical:
                if not any(a.signature_ref for a in plan.approvals):
                    errors.append("critical risk requires break-glass approval with signature_ref")

        total_timeout = 0
        for s in plan.steps:
            total_timeout += s.timeout_seconds
            if s.timeout_seconds > plan.safety.max_step_duration_seconds:
                errors.append(f"step {s.id} timeout exceeds max_step_duration_seconds")

            if plan.mode == RollbackMode.ENFORCE:
                if not s.reversible and not plan.safety.allow_irreversible_steps_in_enforce:
                    errors.append(f"step {s.id} is irreversible and not allowed in enforce mode")

                if s.kind == StepKind.DATA_MIGRATION and not plan.safety.allow_data_migration_in_enforce:
                    errors.append(f"step {s.id} is data_migration and blocked in enforce mode by safety rails")

            if not s.idempotency_key:
                warnings.append(f"step {s.id} has no idempotency_key")

        if total_timeout > plan.safety.max_total_duration_seconds:
            errors.append("plan total step time exceeds max_total_duration_seconds")

        # Dependency checks
        step_ids = {s.id for s in plan.steps}
        for s in plan.steps:
            for dep in s.depends_on:
                if dep not in step_ids:
                    errors.append(f"step {s.id} depends on unknown step {dep}")

        ok = len(errors) == 0
        return PlanValidationResult(ok=ok, errors=tuple(errors), warnings=tuple(warnings))


@dataclass(frozen=True, slots=True)
class StepOutcome:
    step_id: str
    ok: bool
    decision: StepDecision
    started_at: int
    finished_at: int
    message: str
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "step_id", _require_str(self.step_id, "step_id"))
        if not isinstance(self.ok, bool):
            raise RollbackError("ok must be bool")
        object.__setattr__(self, "decision", StepDecision(self.decision))
        object.__setattr__(self, "started_at", _require_int(self.started_at, "started_at"))
        object.__setattr__(self, "finished_at", _require_int(self.finished_at, "finished_at"))
        object.__setattr__(self, "message", _require_str(self.message, "message"))
        if self.details is None:
            object.__setattr__(self, "details", {})
        _require_mapping(self.details, "details")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "ok": self.ok,
            "decision": self.decision.value,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "message": self.message,
            "details": dict(self.details),
        }


@dataclass(frozen=True, slots=True)
class PlanExecutionReport:
    plan_id: str
    fingerprint_sha256: str
    mode: RollbackMode
    state: RollbackState
    started_at: int
    finished_at: int
    outcomes: Tuple[StepOutcome, ...]
    error: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "plan_id", _require_str(self.plan_id, "plan_id"))
        object.__setattr__(self, "fingerprint_sha256", _require_str(self.fingerprint_sha256, "fingerprint_sha256"))
        object.__setattr__(self, "mode", RollbackMode(self.mode))
        object.__setattr__(self, "state", RollbackState(self.state))
        object.__setattr__(self, "started_at", _require_int(self.started_at, "started_at"))
        object.__setattr__(self, "finished_at", _require_int(self.finished_at, "finished_at"))
        if not isinstance(self.outcomes, tuple):
            object.__setattr__(self, "outcomes", tuple(self.outcomes))
        for o in self.outcomes:
            if not isinstance(o, StepOutcome):
                raise RollbackError("outcomes must be StepOutcome")
        if self.error is not None:
            object.__setattr__(self, "error", _require_str(self.error, "error"))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "fingerprint_sha256": self.fingerprint_sha256,
            "mode": self.mode.value,
            "state": self.state.value,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "outcomes": [o.to_dict() for o in self.outcomes],
            "error": self.error,
        }


class StepExecutor:
    """
    Integration point.
    Implement execute_step to call your real orchestrator, deploy system, feature-flag service, etc.
    """

    def execute_step(self, step: RollbackStep, plan: RollbackPlan, mode: RollbackMode) -> StepOutcome:
        raise NotImplementedError


class RollbackPlanner:
    def __init__(self, validator: Optional[RollbackPlanValidator] = None) -> None:
        self._validator = validator or RollbackPlanValidator()

    def validate(self, plan: RollbackPlan, now_epoch: Optional[int] = None) -> PlanValidationResult:
        return self._validator.validate(plan, now_epoch=now_epoch)

    def execute(self, plan: RollbackPlan, executor: StepExecutor, now_epoch: Optional[int] = None) -> PlanExecutionReport:
        if not isinstance(executor, StepExecutor):
            raise RollbackError("executor must be StepExecutor")

        start = _now_epoch_seconds() if now_epoch is None else _require_int(now_epoch, "now_epoch")

        v = self.validate(plan, now_epoch=start)
        if not v.ok:
            state = RollbackState.FAILED if plan.safety.fail_closed else RollbackState.ABORTED
            return PlanExecutionReport(
                plan_id=plan.plan_id,
                fingerprint_sha256=plan.fingerprint(),
                mode=plan.mode,
                state=state,
                started_at=start,
                finished_at=start,
                outcomes=tuple(),
                error="; ".join(v.errors),
            )

        outcomes: List[StepOutcome] = []
        state = RollbackState.SUCCEEDED
        error: Optional[str] = None

        # Simple dependency enforcement: execute in plan order, ensure dependencies already succeeded
        succeeded = set()
        for step in plan.steps:
            if any(dep not in succeeded for dep in step.depends_on):
                state = RollbackState.FAILED if plan.safety.fail_closed else RollbackState.ABORTED
                error = f"dependency not satisfied for step {step.id}"
                break

            try:
                outcome = executor.execute_step(step, plan, plan.mode)
            except Exception as exc:
                state = RollbackState.FAILED if plan.safety.fail_closed else RollbackState.ABORTED
                error = f"executor error on step {step.id}: {exc}"
                break

            outcomes.append(outcome)

            if outcome.ok:
                succeeded.add(step.id)

            if outcome.decision == StepDecision.CONTINUE and outcome.ok:
                continue

            if outcome.decision == StepDecision.STOP:
                state = RollbackState.SUCCEEDED if outcome.ok else (RollbackState.FAILED if plan.safety.fail_closed else RollbackState.ABORTED)
                if not outcome.ok and error is None:
                    error = f"step {step.id} returned STOP with failure"
                break

            if outcome.decision == StepDecision.ABORT:
                state = RollbackState.ABORTED
                if error is None and not outcome.ok:
                    error = f"step {step.id} requested ABORT"
                break

        finish = _now_epoch_seconds()
        if state == RollbackState.SUCCEEDED and error is not None:
            state = RollbackState.FAILED

        return PlanExecutionReport(
            plan_id=plan.plan_id,
            fingerprint_sha256=plan.fingerprint(),
            mode=plan.mode,
            state=state,
            started_at=start,
            finished_at=finish,
            outcomes=tuple(outcomes),
            error=error,
        )
