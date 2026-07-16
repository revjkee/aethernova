# human-sovereignty-core/decision_packets/states.py
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Final, FrozenSet, Iterable, Mapping, MutableMapping, Sequence


class StateMachineError(RuntimeError):
    pass


class InvalidStateError(StateMachineError):
    pass


class InvalidEventError(StateMachineError):
    pass


class InvalidTransitionError(StateMachineError):
    pass


class DecisionPacketState(str, Enum):
    """
    Canonical lifecycle states for a decision packet.

    Design goals:
    - deterministic, explicit transitions
    - no ambiguous "implicit" moves
    - safe terminal states
    - audit-friendly reasons for outcomes
    """

    # Pre-ingest
    CREATED = "created"

    # Intake and validation
    INTAKE = "intake"
    VALIDATING = "validating"
    REJECTED = "rejected"

    # Policy evaluation / risk
    POLICY_EVALUATING = "policy_evaluating"
    POLICY_BLOCKED = "policy_blocked"

    # Approval workflow
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    DENIED = "denied"
    ESCALATED = "escalated"
    VETOED = "vetoed"

    # Execution
    SCHEDULED = "scheduled"
    EXECUTING = "executing"
    EXECUTED = "executed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"

    # TTL / lifecycle control
    EXPIRED = "expired"
    CANCELLED = "cancelled"

    # Final archival
    ARCHIVED = "archived"


class DecisionPacketEvent(str, Enum):
    """
    Events are the only way to move between states.
    """

    # Intake / validation
    SUBMIT = "submit"
    START_VALIDATION = "start_validation"
    VALIDATION_PASSED = "validation_passed"
    VALIDATION_FAILED = "validation_failed"

    # Policy evaluation
    START_POLICY_EVALUATION = "start_policy_evaluation"
    POLICY_PASSED = "policy_passed"
    POLICY_BLOCK = "policy_block"

    # Approval workflow
    REQUEST_APPROVAL = "request_approval"
    APPROVE = "approve"
    DENY = "deny"
    ESCALATE = "escalate"
    VETO = "veto"

    # Scheduling/execution
    SCHEDULE = "schedule"
    START_EXECUTION = "start_execution"
    EXECUTION_SUCCEEDED = "execution_succeeded"
    EXECUTION_FAILED = "execution_failed"
    ROLLBACK = "rollback"
    ROLLBACK_SUCCEEDED = "rollback_succeeded"
    ROLLBACK_FAILED = "rollback_failed"

    # Lifecycle control
    EXPIRE = "expire"
    CANCEL = "cancel"

    # Archive
    ARCHIVE = "archive"


class TerminalReason(str, Enum):
    """
    Reasons (high-level) for terminal outcomes.

    Not every reason is applicable to every terminal state; enforcement is done by callers.
    """

    # Validation / format / schema issues
    INVALID_SCHEMA = "invalid_schema"
    INVALID_SIGNATURE = "invalid_signature"
    INVALID_ORIGIN = "invalid_origin"
    INVALID_TTL = "invalid_ttl"

    # Policy and governance
    RED_DOMAIN = "red_domain"
    POLICY_VIOLATION = "policy_violation"
    LIMITS_EXCEEDED = "limits_exceeded"

    # Approval outcomes
    APPROVAL_DENIED = "approval_denied"
    VETO_APPLIED = "veto_applied"
    ESCALATION_TIMEOUT = "escalation_timeout"

    # Execution outcomes
    EXECUTION_ERROR = "execution_error"
    ROLLBACK_ERROR = "rollback_error"

    # Lifecycle outcomes
    EXPIRED_TTL = "expired_ttl"
    CANCELLED_BY_USER = "cancelled_by_user"
    CANCELLED_BY_SYSTEM = "cancelled_by_system"

    # Administrative
    ARCHIVED = "archived"


@dataclass(frozen=True, slots=True)
class Transition:
    """
    A transition rule: (from_state, event) -> to_state.

    Guards/conditions are not embedded here to keep the state machine pure and deterministic.
    Higher-level services should evaluate guards and then fire events accordingly.
    """

    from_state: DecisionPacketState
    event: DecisionPacketEvent
    to_state: DecisionPacketState


def _enum_contains(enum_cls: Any, value: Any) -> bool:
    try:
        enum_cls(value)
        return True
    except Exception:
        return False


# Single source of truth: explicit transitions.
_TRANSITIONS: Final[tuple[Transition, ...]] = (
    # CREATED -> intake path
    Transition(DecisionPacketState.CREATED, DecisionPacketEvent.SUBMIT, DecisionPacketState.INTAKE),
    Transition(DecisionPacketState.INTAKE, DecisionPacketEvent.START_VALIDATION, DecisionPacketState.VALIDATING),
    Transition(DecisionPacketState.VALIDATING, DecisionPacketEvent.VALIDATION_PASSED, DecisionPacketState.POLICY_EVALUATING),
    Transition(DecisionPacketState.VALIDATING, DecisionPacketEvent.VALIDATION_FAILED, DecisionPacketState.REJECTED),

    # Policy evaluation
    Transition(DecisionPacketState.POLICY_EVALUATING, DecisionPacketEvent.POLICY_PASSED, DecisionPacketState.PENDING_APPROVAL),
    Transition(DecisionPacketState.POLICY_EVALUATING, DecisionPacketEvent.POLICY_BLOCK, DecisionPacketState.POLICY_BLOCKED),

    # Approval workflow
    Transition(DecisionPacketState.PENDING_APPROVAL, DecisionPacketEvent.APPROVE, DecisionPacketState.APPROVED),
    Transition(DecisionPacketState.PENDING_APPROVAL, DecisionPacketEvent.DENY, DecisionPacketState.DENIED),
    Transition(DecisionPacketState.PENDING_APPROVAL, DecisionPacketEvent.ESCALATE, DecisionPacketState.ESCALATED),
    Transition(DecisionPacketState.PENDING_APPROVAL, DecisionPacketEvent.VETO, DecisionPacketState.VETOED),

    # Escalation may lead to final decision
    Transition(DecisionPacketState.ESCALATED, DecisionPacketEvent.APPROVE, DecisionPacketState.APPROVED),
    Transition(DecisionPacketState.ESCALATED, DecisionPacketEvent.DENY, DecisionPacketState.DENIED),
    Transition(DecisionPacketState.ESCALATED, DecisionPacketEvent.VETO, DecisionPacketState.VETOED),

    # After approval -> scheduling/execution
    Transition(DecisionPacketState.APPROVED, DecisionPacketEvent.SCHEDULE, DecisionPacketState.SCHEDULED),
    Transition(DecisionPacketState.SCHEDULED, DecisionPacketEvent.START_EXECUTION, DecisionPacketState.EXECUTING),
    Transition(DecisionPacketState.EXECUTING, DecisionPacketEvent.EXECUTION_SUCCEEDED, DecisionPacketState.EXECUTED),
    Transition(DecisionPacketState.EXECUTING, DecisionPacketEvent.EXECUTION_FAILED, DecisionPacketState.FAILED),

    # Rollback flow
    Transition(DecisionPacketState.FAILED, DecisionPacketEvent.ROLLBACK, DecisionPacketState.ROLLED_BACK),
    Transition(DecisionPacketState.EXECUTED, DecisionPacketEvent.ROLLBACK, DecisionPacketState.ROLLED_BACK),

    # Optional explicit rollback outcomes (if you model rollback as a process outside this state machine,
    # keep these events unused; they are here for completeness)
    Transition(DecisionPacketState.ROLLED_BACK, DecisionPacketEvent.ROLLBACK_SUCCEEDED, DecisionPacketState.ROLLED_BACK),
    Transition(DecisionPacketState.ROLLED_BACK, DecisionPacketEvent.ROLLBACK_FAILED, DecisionPacketState.FAILED),

    # Lifecycle controls: expire/cancel are allowed from most non-terminal states
    Transition(DecisionPacketState.CREATED, DecisionPacketEvent.CANCEL, DecisionPacketState.CANCELLED),
    Transition(DecisionPacketState.INTAKE, DecisionPacketEvent.CANCEL, DecisionPacketState.CANCELLED),
    Transition(DecisionPacketState.VALIDATING, DecisionPacketEvent.CANCEL, DecisionPacketState.CANCELLED),
    Transition(DecisionPacketState.POLICY_EVALUATING, DecisionPacketEvent.CANCEL, DecisionPacketState.CANCELLED),
    Transition(DecisionPacketState.PENDING_APPROVAL, DecisionPacketEvent.CANCEL, DecisionPacketState.CANCELLED),
    Transition(DecisionPacketState.ESCALATED, DecisionPacketEvent.CANCEL, DecisionPacketState.CANCELLED),
    Transition(DecisionPacketState.SCHEDULED, DecisionPacketEvent.CANCEL, DecisionPacketState.CANCELLED),

    Transition(DecisionPacketState.CREATED, DecisionPacketEvent.EXPIRE, DecisionPacketState.EXPIRED),
    Transition(DecisionPacketState.INTAKE, DecisionPacketEvent.EXPIRE, DecisionPacketState.EXPIRED),
    Transition(DecisionPacketState.VALIDATING, DecisionPacketEvent.EXPIRE, DecisionPacketState.EXPIRED),
    Transition(DecisionPacketState.POLICY_EVALUATING, DecisionPacketEvent.EXPIRE, DecisionPacketState.EXPIRED),
    Transition(DecisionPacketState.PENDING_APPROVAL, DecisionPacketEvent.EXPIRE, DecisionPacketState.EXPIRED),
    Transition(DecisionPacketState.ESCALATED, DecisionPacketEvent.EXPIRE, DecisionPacketState.EXPIRED),
    Transition(DecisionPacketState.SCHEDULED, DecisionPacketEvent.EXPIRE, DecisionPacketState.EXPIRED),

    # Archive terminal-ish states (and allow archiving of executed/rolled_back/cancelled/expired/denied/vetoed/rejected/blocked)
    Transition(DecisionPacketState.REJECTED, DecisionPacketEvent.ARCHIVE, DecisionPacketState.ARCHIVED),
    Transition(DecisionPacketState.POLICY_BLOCKED, DecisionPacketEvent.ARCHIVE, DecisionPacketState.ARCHIVED),
    Transition(DecisionPacketState.DENIED, DecisionPacketEvent.ARCHIVE, DecisionPacketState.ARCHIVED),
    Transition(DecisionPacketState.VETOED, DecisionPacketEvent.ARCHIVE, DecisionPacketState.ARCHIVED),
    Transition(DecisionPacketState.CANCELLED, DecisionPacketEvent.ARCHIVE, DecisionPacketState.ARCHIVED),
    Transition(DecisionPacketState.EXPIRED, DecisionPacketEvent.ARCHIVE, DecisionPacketState.ARCHIVED),
    Transition(DecisionPacketState.EXECUTED, DecisionPacketEvent.ARCHIVE, DecisionPacketState.ARCHIVED),
    Transition(DecisionPacketState.FAILED, DecisionPacketEvent.ARCHIVE, DecisionPacketState.ARCHIVED),
    Transition(DecisionPacketState.ROLLED_BACK, DecisionPacketEvent.ARCHIVE, DecisionPacketState.ARCHIVED),
)


# Build a lookup for fast validation and transition.
_TRANSITION_MAP: Final[dict[tuple[DecisionPacketState, DecisionPacketEvent], DecisionPacketState]] = {
    (t.from_state, t.event): t.to_state for t in _TRANSITIONS
}

# States that should be treated as "no further processing".
_TERMINAL_STATES: Final[FrozenSet[DecisionPacketState]] = frozenset(
    {
        DecisionPacketState.REJECTED,
        DecisionPacketState.POLICY_BLOCKED,
        DecisionPacketState.DENIED,
        DecisionPacketState.VETOED,
        DecisionPacketState.EXECUTED,
        DecisionPacketState.FAILED,
        DecisionPacketState.ROLLED_BACK,
        DecisionPacketState.EXPIRED,
        DecisionPacketState.CANCELLED,
        DecisionPacketState.ARCHIVED,
    }
)

# States that may be archived.
_ARCHIVABLE_STATES: Final[FrozenSet[DecisionPacketState]] = frozenset(
    {
        DecisionPacketState.REJECTED,
        DecisionPacketState.POLICY_BLOCKED,
        DecisionPacketState.DENIED,
        DecisionPacketState.VETOED,
        DecisionPacketState.EXECUTED,
        DecisionPacketState.FAILED,
        DecisionPacketState.ROLLED_BACK,
        DecisionPacketState.EXPIRED,
        DecisionPacketState.CANCELLED,
    }
)


def normalize_state(value: Any) -> DecisionPacketState:
    if isinstance(value, DecisionPacketState):
        return value
    if isinstance(value, str):
        try:
            return DecisionPacketState(value)
        except Exception as exc:
            raise InvalidStateError(f"Unknown DecisionPacketState: {value!r}") from exc
    raise InvalidStateError(f"Cannot normalize state from: {type(value).__name__}")


def normalize_event(value: Any) -> DecisionPacketEvent:
    if isinstance(value, DecisionPacketEvent):
        return value
    if isinstance(value, str):
        try:
            return DecisionPacketEvent(value)
        except Exception as exc:
            raise InvalidEventError(f"Unknown DecisionPacketEvent: {value!r}") from exc
    raise InvalidEventError(f"Cannot normalize event from: {type(value).__name__}")


def is_terminal(state: DecisionPacketState) -> bool:
    return normalize_state(state) in _TERMINAL_STATES


def is_archivable(state: DecisionPacketState) -> bool:
    return normalize_state(state) in _ARCHIVABLE_STATES


def allowed_events(state: DecisionPacketState) -> FrozenSet[DecisionPacketEvent]:
    st = normalize_state(state)
    out: set[DecisionPacketEvent] = set()
    for (from_state, ev), _to_state in _TRANSITION_MAP.items():
        if from_state == st:
            out.add(ev)
    return frozenset(out)


def can_transition(state: DecisionPacketState, event: DecisionPacketEvent) -> bool:
    st = normalize_state(state)
    ev = normalize_event(event)
    return (st, ev) in _TRANSITION_MAP


def transition(state: DecisionPacketState, event: DecisionPacketEvent) -> DecisionPacketState:
    st = normalize_state(state)
    ev = normalize_event(event)
    try:
        return _TRANSITION_MAP[(st, ev)]
    except KeyError as exc:
        raise InvalidTransitionError(
            f"Invalid transition: state={st.value!r} event={ev.value!r} allowed={[e.value for e in allowed_events(st)]}"
        ) from exc


def validate_transitions_strict() -> None:
    """
    Consistency checks for the state machine definition.
    Call from bootstrap/self_check to fail-fast on malformed config.
    """
    # 1) Ensure unique mappings for each (state,event)
    seen: set[tuple[str, str]] = set()
    for t in _TRANSITIONS:
        key = (t.from_state.value, t.event.value)
        if key in seen:
            raise StateMachineError(f"Duplicate transition mapping: {key}")
        seen.add(key)

    # 2) Ensure all enum values are used correctly
    for t in _TRANSITIONS:
        if not _enum_contains(DecisionPacketState, t.from_state.value):
            raise StateMachineError(f"Transition has invalid from_state: {t.from_state}")
        if not _enum_contains(DecisionPacketEvent, t.event.value):
            raise StateMachineError(f"Transition has invalid event: {t.event}")
        if not _enum_contains(DecisionPacketState, t.to_state.value):
            raise StateMachineError(f"Transition has invalid to_state: {t.to_state}")

    # 3) Ensure ARCHIVED is terminal and has no outgoing transitions
    if DecisionPacketState.ARCHIVED not in _TERMINAL_STATES:
        raise StateMachineError("ARCHIVED must be terminal")
    if allowed_events(DecisionPacketState.ARCHIVED):
        raise StateMachineError("ARCHIVED must not have outgoing transitions")

    # 4) Ensure archivable states can be archived (policy: explicit archive transition exists)
    for st in _ARCHIVABLE_STATES:
        if not can_transition(st, DecisionPacketEvent.ARCHIVE):
            raise StateMachineError(f"Archivable state must support ARCHIVE event: {st.value}")

    # 5) Ensure terminal states (except ARCHIVED) can be archived if they are archivable
    for st in _TERMINAL_STATES:
        if st == DecisionPacketState.ARCHIVED:
            continue
        if st in _ARCHIVABLE_STATES and not can_transition(st, DecisionPacketEvent.ARCHIVE):
            raise StateMachineError(f"Terminal state should be archivable but missing ARCHIVE transition: {st.value}")


def explain_transition_matrix() -> Mapping[str, Mapping[str, str]]:
    """
    Returns a serializable transition matrix: state -> event -> next_state.
    Useful for docs, UI, and audits.
    """
    matrix: dict[str, dict[str, str]] = {}
    for (st, ev), to_st in _TRANSITION_MAP.items():
        matrix.setdefault(st.value, {})[ev.value] = to_st.value
    return matrix


__all__ = [
    "DecisionPacketState",
    "DecisionPacketEvent",
    "TerminalReason",
    "Transition",
    "StateMachineError",
    "InvalidStateError",
    "InvalidEventError",
    "InvalidTransitionError",
    "normalize_state",
    "normalize_event",
    "is_terminal",
    "is_archivable",
    "allowed_events",
    "can_transition",
    "transition",
    "validate_transitions_strict",
    "explain_transition_matrix",
]
