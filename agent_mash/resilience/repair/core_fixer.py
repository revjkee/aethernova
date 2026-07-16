# agent_mash/resilience/repair/core_fixer.py
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple


class RepairActionType(str, Enum):
    INVESTIGATE = "investigate"
    RETRY = "retry"
    RESTART = "restart"
    ROLLBACK = "rollback"
    SCALE = "scale"
    THROTTLE = "throttle"
    RELOAD_CONFIG = "reload_config"
    CLEAR_CACHE = "clear_cache"
    ROTATE_CREDENTIALS = "rotate_credentials"
    NOOP = "noop"


class RepairOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApprovalMode(str, Enum):
    REQUIRED = "required"
    OPTIONAL = "optional"
    FORBIDDEN = "forbidden"


@dataclass(frozen=True)
class RepairEvidence:
    source: str
    payload: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RepairAction:
    action_id: str
    action_type: RepairActionType
    target: str
    risk: RiskLevel
    title: str
    rationale: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    prerequisites: List[str] = field(default_factory=list)
    evidence: List[RepairEvidence] = field(default_factory=list)
    requires_approval: bool = True
    timeout_s: int = 120
    retry: int = 0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["action_type"] = self.action_type.value
        d["risk"] = self.risk.value
        return d


@dataclass(frozen=True)
class RepairPlan:
    plan_id: str
    created_at: str
    snapshot_fingerprint: str
    summary: str
    risk: RiskLevel
    actions: List[RepairAction]
    constraints: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "created_at": self.created_at,
            "snapshot_fingerprint": self.snapshot_fingerprint,
            "summary": self.summary,
            "risk": self.risk.value,
            "actions": [a.to_dict() for a in self.actions],
            "constraints": self.constraints,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class ActionExecutionRecord:
    action_id: str
    outcome: RepairOutcome
    started_at: str
    finished_at: str
    message: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["outcome"] = self.outcome.value
        return d


@dataclass(frozen=True)
class ApplyResult:
    plan_id: str
    dry_run: bool
    approved: bool
    outcome: RepairOutcome
    message: str
    records: List[ActionExecutionRecord]
    started_at: str
    finished_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "dry_run": self.dry_run,
            "approved": self.approved,
            "outcome": self.outcome.value,
            "message": self.message,
            "records": [r.to_dict() for r in self.records],
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


class RepairExecutor(Protocol):
    """
    Executor is the only place where real side-effects may occur.
    This module intentionally does not implement side-effects.
    """

    def execute(self, action: RepairAction, *, dry_run: bool) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Return tuple:
          ok: bool
          message: str
          details: dict (optional structured diagnostics)
        """
        ...


@dataclass(frozen=True)
class CoreFixerPolicy:
    """
    Safety and approval policy.
    Defaults are conservative: no risky writes without explicit approval.
    """

    approval_mode: ApprovalMode = ApprovalMode.REQUIRED
    allow_critical_actions: bool = False
    allow_high_actions: bool = False
    max_actions_per_plan: int = 25
    default_action_timeout_s: int = 120
    max_total_timeout_s: int = 900
    enforce_prerequisites: bool = True

    # If True, apply() will refuse to run when dry_run is False unless approved flag is True.
    strict_approval: bool = True

    # If True, plan generation will include only low/medium actions unless allow_high_actions/allow_critical_actions enabled.
    conservative_plan: bool = True


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stable_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _fingerprint_snapshot(snapshot: Mapping[str, Any]) -> str:
    try:
        raw = _stable_json(snapshot)
    except Exception:
        raw = str(snapshot)
    h = hashlib.sha256()
    h.update(raw.encode("utf-8", errors="replace"))
    return h.hexdigest()


def _validate_snapshot_minimal(snapshot: Any) -> Tuple[bool, str]:
    if not isinstance(snapshot, Mapping):
        return False, "snapshot must be a mapping"
    if "components" not in snapshot:
        return False, "snapshot missing key: components"
    comps = snapshot.get("components")
    if not isinstance(comps, (list, tuple)):
        return False, "snapshot.components must be a list"
    return True, "ok"


def _component_name(comp: Any, idx: int) -> str:
    if isinstance(comp, Mapping):
        name = str(comp.get("name", "")).strip()
        if name:
            return name
    return f"component_{idx}"


def _component_state(comp: Any) -> str:
    if not isinstance(comp, Mapping):
        return "unknown"
    return str(comp.get("state", "unknown")).strip().lower()


def _component_reason(comp: Any) -> str:
    if not isinstance(comp, Mapping):
        return ""
    return str(comp.get("reason", "") or comp.get("message", "") or "").strip()


def _risk_max(a: RiskLevel, b: RiskLevel) -> RiskLevel:
    order = {
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3,
        RiskLevel.CRITICAL: 4,
    }
    return a if order[a] >= order[b] else b


def _action_id(plan_seed: str, action_type: RepairActionType, target: str) -> str:
    h = hashlib.sha256()
    h.update(f"{plan_seed}:{action_type.value}:{target}".encode("utf-8", errors="replace"))
    return h.hexdigest()[:16]


def _default_constraints() -> Dict[str, Any]:
    return {
        "no_direct_mutation_without_approval": True,
        "executor_required": True,
        "max_parallelism": 1,
    }


def _is_write_action(t: RepairActionType) -> bool:
    return t in {
        RepairActionType.RESTART,
        RepairActionType.ROLLBACK,
        RepairActionType.SCALE,
        RepairActionType.THROTTLE,
        RepairActionType.RELOAD_CONFIG,
        RepairActionType.CLEAR_CACHE,
        RepairActionType.ROTATE_CREDENTIALS,
        RepairActionType.RETRY,
    }


class CoreFixer:
    """
    Industrial core fixer:
      - generates deterministic repair plans from a snapshot (plan())
      - applies plans only through an injected executor (apply())
      - enforces approval rules and safety constraints
    """

    def __init__(self, *, policy: Optional[CoreFixerPolicy] = None) -> None:
        self._policy = policy or CoreFixerPolicy()

    @property
    def policy(self) -> CoreFixerPolicy:
        return self._policy

    def plan(self, snapshot: Mapping[str, Any]) -> RepairPlan:
        ok, msg = _validate_snapshot_minimal(snapshot)
        fp = _fingerprint_snapshot(snapshot)
        created = _utc_now_iso()

        if not ok:
            plan_id = _action_id(fp, RepairActionType.NOOP, "snapshot")
            action = RepairAction(
                action_id=_action_id(plan_id, RepairActionType.INVESTIGATE, "telemetry"),
                action_type=RepairActionType.INVESTIGATE,
                target="telemetry.pipeline",
                risk=RiskLevel.HIGH,
                title="Invalid snapshot: investigate telemetry pipeline",
                rationale=msg,
                parameters={"validation_error": msg},
                requires_approval=False,
                timeout_s=min(self._policy.default_action_timeout_s, 120),
                evidence=[RepairEvidence(source="snapshot.validation", payload={"message": msg})],
            )
            return RepairPlan(
                plan_id=plan_id,
                created_at=created,
                snapshot_fingerprint=fp,
                summary="Snapshot invalid; only investigation plan produced.",
                risk=RiskLevel.HIGH,
                actions=[action],
                constraints=_default_constraints(),
                metadata={"validation_ok": False, "validation_message": msg},
            )

        components = snapshot.get("components", [])
        degraded: List[Tuple[str, str]] = []
        unhealthy: List[Tuple[str, str]] = []
        unknown: List[Tuple[str, str]] = []

        for i, comp in enumerate(components):
            name = _component_name(comp, i)
            st = _component_state(comp)
            reason = _component_reason(comp)
            if st == "degraded":
                degraded.append((name, reason))
            elif st == "unhealthy":
                unhealthy.append((name, reason))
            elif st == "unknown":
                unknown.append((name, reason))

        plan_seed = fp
        plan_id = hashlib.sha256(f"plan:{plan_seed}".encode("utf-8", errors="replace")).hexdigest()[:16]

        actions: List[RepairAction] = []
        overall_risk = RiskLevel.LOW

        # Always include investigation if unknown is large or unhealthy exists.
        if unhealthy or (len(unknown) >= max(1, int(0.2 * max(1, len(components))))):
            a = RepairAction(
                action_id=_action_id(plan_id, RepairActionType.INVESTIGATE, "monitoring.inspection"),
                action_type=RepairActionType.INVESTIGATE,
                target="monitoring.inspection",
                risk=RiskLevel.MEDIUM if not unhealthy else RiskLevel.HIGH,
                title="Run detailed inspection",
                rationale="Unhealthy/unknown components detected; collect deeper diagnostics before any mutation.",
                parameters={
                    "unhealthy": [n for n, _ in unhealthy][:200],
                    "degraded": [n for n, _ in degraded][:200],
                    "unknown": [n for n, _ in unknown][:200],
                },
                requires_approval=False,
                timeout_s=min(self._policy.default_action_timeout_s, 180),
                evidence=[RepairEvidence(source="snapshot.components", payload={"counts": {
                    "degraded": len(degraded),
                    "unhealthy": len(unhealthy),
                    "unknown": len(unknown),
                    "total": len(components),
                }})],
            )
            actions.append(a)
            overall_risk = _risk_max(overall_risk, a.risk)

        # For degraded components propose non-invasive first: retry/reload_config.
        for name, reason in degraded[: self._policy.max_actions_per_plan]:
            # Conservative plan prefers RETRY/RELOAD_CONFIG; RESTART only with relaxed policy.
            if self._policy.conservative_plan:
                t = RepairActionType.RETRY
                risk = RiskLevel.MEDIUM
                title = f"Retry transient operations for {name}"
                rationale = "Degraded state often caused by transient failures; retry is safer than restart."
                params = {"component": name, "reason": reason}
            else:
                t = RepairActionType.RELOAD_CONFIG
                risk = RiskLevel.MEDIUM
                title = f"Reload configuration for {name}"
                rationale = "Config reload can restore functionality with lower risk than restart."
                params = {"component": name, "reason": reason}

            a = RepairAction(
                action_id=_action_id(plan_id, t, name),
                action_type=t,
                target=name,
                risk=risk,
                title=title,
                rationale=rationale,
                parameters=params,
                requires_approval=self._policy.approval_mode == ApprovalMode.REQUIRED,
                timeout_s=self._policy.default_action_timeout_s,
                evidence=[RepairEvidence(source="snapshot.component", payload={"name": name, "state": "degraded", "reason": reason})],
            )
            actions.append(a)
            overall_risk = _risk_max(overall_risk, a.risk)

        # For unhealthy components propose investigation first; potentially restart only if policy allows.
        for name, reason in unhealthy[: self._policy.max_actions_per_plan]:
            inv = RepairAction(
                action_id=_action_id(plan_id, RepairActionType.INVESTIGATE, name),
                action_type=RepairActionType.INVESTIGATE,
                target=name,
                risk=RiskLevel.HIGH,
                title=f"Investigate unhealthy component {name}",
                rationale="Unhealthy state requires triage; mutation is blocked until evidence is collected.",
                parameters={"component": name, "reason": reason},
                requires_approval=False,
                timeout_s=min(self._policy.default_action_timeout_s, 180),
                evidence=[RepairEvidence(source="snapshot.component", payload={"name": name, "state": "unhealthy", "reason": reason})],
            )
            actions.append(inv)
            overall_risk = _risk_max(overall_risk, inv.risk)

            if self._policy.allow_high_actions:
                restart = RepairAction(
                    action_id=_action_id(plan_id, RepairActionType.RESTART, name),
                    action_type=RepairActionType.RESTART,
                    target=name,
                    risk=RiskLevel.HIGH,
                    title=f"Restart {name}",
                    rationale="Restart may restore a stuck component; requires explicit approval.",
                    parameters={"component": name, "reason": reason},
                    prerequisites=[inv.action_id] if self._policy.enforce_prerequisites else [],
                    requires_approval=True,
                    timeout_s=max(self._policy.default_action_timeout_s, 180),
                    evidence=[RepairEvidence(source="policy", payload={"allow_high_actions": True})],
                )
                actions.append(restart)
                overall_risk = _risk_max(overall_risk, restart.risk)

        # If nothing to do, emit NOOP
        if not actions:
            noop = RepairAction(
                action_id=_action_id(plan_id, RepairActionType.NOOP, "system"),
                action_type=RepairActionType.NOOP,
                target="system",
                risk=RiskLevel.LOW,
                title="No repair actions required",
                rationale="Snapshot indicates no degraded or unhealthy components.",
                parameters={"components_total": len(components)},
                requires_approval=False,
                timeout_s=1,
            )
            actions.append(noop)

        # Enforce max actions
        if len(actions) > self._policy.max_actions_per_plan:
            actions = actions[: self._policy.max_actions_per_plan]

        # Compute plan summary
        summary = snapshot.get("summary")
        summary_text = ""
        if isinstance(summary, Mapping):
            summary_text = str(summary.get("message") or "").strip()
        if not summary_text:
            summary_text = "Repair plan generated from current snapshot."

        return RepairPlan(
            plan_id=plan_id,
            created_at=created,
            snapshot_fingerprint=fp,
            summary=summary_text,
            risk=overall_risk,
            actions=actions,
            constraints=_default_constraints(),
            metadata={
                "validation_ok": True,
                "counts": {
                    "degraded": len(degraded),
                    "unhealthy": len(unhealthy),
                    "unknown": len(unknown),
                    "total": len(components),
                },
                "policy": asdict(self._policy),
            },
        )

    def apply(
        self,
        plan: RepairPlan,
        *,
        executor: RepairExecutor,
        approved: bool = False,
        dry_run: bool = True,
        idempotency_key: Optional[str] = None,
    ) -> ApplyResult:
        started = _utc_now_iso()

        if self._policy.approval_mode == ApprovalMode.FORBIDDEN and not dry_run:
            finished = _utc_now_iso()
            return ApplyResult(
                plan_id=plan.plan_id,
                dry_run=dry_run,
                approved=False,
                outcome=RepairOutcome.BLOCKED,
                message="Write actions are forbidden by policy.",
                records=[],
                started_at=started,
                finished_at=finished,
            )

        if self._policy.strict_approval and not dry_run and not approved:
            finished = _utc_now_iso()
            return ApplyResult(
                plan_id=plan.plan_id,
                dry_run=dry_run,
                approved=False,
                outcome=RepairOutcome.BLOCKED,
                message="Approval is required for non-dry-run execution.",
                records=[],
                started_at=started,
                finished_at=finished,
            )

        # Idempotency key is not persisted here; upstream must persist it (governance/audit).
        # We only incorporate it into execution context for deterministic logging.
        exec_ctx = {
            "plan_id": plan.plan_id,
            "snapshot_fingerprint": plan.snapshot_fingerprint,
            "dry_run": dry_run,
            "approved": approved,
            "idempotency_key": idempotency_key or "",
        }

        total_timeout = 0
        records: List[ActionExecutionRecord] = []
        seen: Dict[str, RepairOutcome] = {}

        # Map action_id to action for prerequisite checks
        action_index: Dict[str, RepairAction] = {a.action_id: a for a in plan.actions}

        for action in plan.actions:
            a_started = _utc_now_iso()

            # Hard guard on risk
            if action.risk == RiskLevel.CRITICAL and not self._policy.allow_critical_actions and _is_write_action(action.action_type):
                a_finished = _utc_now_iso()
                records.append(
                    ActionExecutionRecord(
                        action_id=action.action_id,
                        outcome=RepairOutcome.BLOCKED,
                        started_at=a_started,
                        finished_at=a_finished,
                        message="Critical write action blocked by policy.",
                        details={"exec_ctx": exec_ctx, "risk": action.risk.value},
                    )
                )
                seen[action.action_id] = RepairOutcome.BLOCKED
                continue

            if action.risk == RiskLevel.HIGH and not self._policy.allow_high_actions and _is_write_action(action.action_type):
                a_finished = _utc_now_iso()
                records.append(
                    ActionExecutionRecord(
                        action_id=action.action_id,
                        outcome=RepairOutcome.BLOCKED,
                        started_at=a_started,
                        finished_at=a_finished,
                        message="High-risk write action blocked by policy.",
                        details={"exec_ctx": exec_ctx, "risk": action.risk.value},
                    )
                )
                seen[action.action_id] = RepairOutcome.BLOCKED
                continue

            # Approval per-action
            if action.requires_approval and not dry_run and not approved:
                a_finished = _utc_now_iso()
                records.append(
                    ActionExecutionRecord(
                        action_id=action.action_id,
                        outcome=RepairOutcome.BLOCKED,
                        started_at=a_started,
                        finished_at=a_finished,
                        message="Action requires approval; execution blocked.",
                        details={"exec_ctx": exec_ctx, "requires_approval": True},
                    )
                )
                seen[action.action_id] = RepairOutcome.BLOCKED
                continue

            # Prerequisites
            if self._policy.enforce_prerequisites and action.prerequisites:
                prereq_ok = True
                blocked_by: List[str] = []
                for pre_id in action.prerequisites:
                    pre_out = seen.get(pre_id)
                    if pre_out not in (RepairOutcome.SUCCESS, RepairOutcome.SKIPPED):
                        prereq_ok = False
                        blocked_by.append(pre_id)
                if not prereq_ok:
                    a_finished = _utc_now_iso()
                    records.append(
                        ActionExecutionRecord(
                            action_id=action.action_id,
                            outcome=RepairOutcome.BLOCKED,
                            started_at=a_started,
                            finished_at=a_finished,
                            message="Prerequisites not satisfied; execution blocked.",
                            details={"blocked_by": blocked_by, "exec_ctx": exec_ctx},
                        )
                    )
                    seen[action.action_id] = RepairOutcome.BLOCKED
                    continue

            # Timeout budgeting
            total_timeout += max(0, int(action.timeout_s))
            if total_timeout > self._policy.max_total_timeout_s and not dry_run:
                a_finished = _utc_now_iso()
                records.append(
                    ActionExecutionRecord(
                        action_id=action.action_id,
                        outcome=RepairOutcome.BLOCKED,
                        started_at=a_started,
                        finished_at=a_finished,
                        message="Execution blocked by total timeout budget.",
                        details={"budget_s": self._policy.max_total_timeout_s, "total_timeout_s": total_timeout, "exec_ctx": exec_ctx},
                    )
                )
                seen[action.action_id] = RepairOutcome.BLOCKED
                continue

            # Execute with retries
            attempts = 0
            max_attempts = 1 + max(0, int(action.retry))
            last_msg = ""
            last_details: Dict[str, Any] = {}

            while attempts < max_attempts:
                attempts += 1
                ok, msg, details = executor.execute(action, dry_run=dry_run)
                last_msg = msg
                last_details = details or {}
                if ok:
                    break
                if attempts < max_attempts:
                    time.sleep(0.05)

            a_finished = _utc_now_iso()
            if last_msg == "":
                last_msg = "Executor returned empty message."

            outcome = RepairOutcome.SUCCESS if ok else RepairOutcome.FAILURE
            records.append(
                ActionExecutionRecord(
                    action_id=action.action_id,
                    outcome=outcome,
                    started_at=a_started,
                    finished_at=a_finished,
                    message=last_msg,
                    details={
                        "attempts": attempts,
                        "exec_ctx": exec_ctx,
                        "action": action.to_dict(),
                        "executor_details": last_details,
                    },
                )
            )
            seen[action.action_id] = outcome

        # Compute overall outcome
        finished = _utc_now_iso()
        if not records:
            overall = RepairOutcome.SKIPPED
            msg = "No actions executed."
        else:
            any_failure = any(r.outcome == RepairOutcome.FAILURE for r in records)
            any_blocked = any(r.outcome == RepairOutcome.BLOCKED for r in records)
            any_success = any(r.outcome == RepairOutcome.SUCCESS for r in records)

            if any_failure:
                overall = RepairOutcome.FAILURE
                msg = "One or more actions failed."
            elif any_blocked and any_success:
                overall = RepairOutcome.SUCCESS
                msg = "Some actions were blocked; executed actions succeeded."
            elif any_blocked and not any_success:
                overall = RepairOutcome.BLOCKED
                msg = "All actions were blocked."
            else:
                overall = RepairOutcome.SUCCESS
                msg = "All actions succeeded."

        return ApplyResult(
            plan_id=plan.plan_id,
            dry_run=dry_run,
            approved=approved,
            outcome=overall,
            message=msg,
            records=records,
            started_at=started,
            finished_at=finished,
        )


__all__ = [
    "RepairActionType",
    "RepairOutcome",
    "RiskLevel",
    "ApprovalMode",
    "RepairEvidence",
    "RepairAction",
    "RepairPlan",
    "ActionExecutionRecord",
    "ApplyResult",
    "CoreFixerPolicy",
    "RepairExecutor",
    "CoreFixer",
]
