# path: human-sovereignty-core/bootstrap/invariants.py
from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import json
import logging
import os
import re
import threading
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence, Tuple, Union

logger = logging.getLogger(__name__)


class SovereigntyViolation(RuntimeError):
    """Raised when a human-sovereignty invariant is violated."""


class InvalidMandate(ValueError):
    """Raised when a human mandate is missing or malformed."""


class InvariantCheckError(RuntimeError):
    """Raised when invariant checking fails unexpectedly."""


class Criticality(Enum):
    """Risk/impact classification used to derive approval requirements."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApprovalMode(Enum):
    """Defines whether human approval is required."""
    NONE = "none"
    REQUIRED = "required"


class DecisionKind(Enum):
    """High-level category of a decision/action request."""
    READ = "read"
    PLAN = "plan"
    WRITE = "write"
    EXECUTE = "execute"
    ESCALATE_PRIVILEGE = "escalate_privilege"
    CHANGE_POLICY = "change_policy"
    CHANGE_GOAL = "change_goal"
    DELETE = "delete"
    TRANSFER_VALUE = "transfer_value"


@dataclass(frozen=True)
class HumanMandate:
    """
    Human mandate is the explicit authorization that binds a decision/action
    to a specific human sovereign.
    """
    human_id: str
    session_id: str
    issued_at_utc: _dt.datetime
    expires_at_utc: _dt.datetime
    reason: str
    nonce: str
    signature: Optional[str] = None  # optional to support external signature systems
    attestation_ref: Optional[str] = None  # optional pointer to external evidence (ticket, approval record)

    def is_expired(self, now_utc: Optional[_dt.datetime] = None) -> bool:
        now = now_utc or _dt.datetime.now(tz=_dt.timezone.utc)
        return now >= self.expires_at_utc

    def validate(self, now_utc: Optional[_dt.datetime] = None) -> None:
        if not self.human_id or not self.human_id.strip():
            raise InvalidMandate("human_id is required")
        if not self.session_id or not self.session_id.strip():
            raise InvalidMandate("session_id is required")
        if not isinstance(self.issued_at_utc, _dt.datetime) or self.issued_at_utc.tzinfo is None:
            raise InvalidMandate("issued_at_utc must be timezone-aware datetime")
        if not isinstance(self.expires_at_utc, _dt.datetime) or self.expires_at_utc.tzinfo is None:
            raise InvalidMandate("expires_at_utc must be timezone-aware datetime")
        if self.expires_at_utc <= self.issued_at_utc:
            raise InvalidMandate("expires_at_utc must be after issued_at_utc")
        if self.is_expired(now_utc=now_utc):
            raise InvalidMandate("mandate is expired")
        if not self.reason or not self.reason.strip():
            raise InvalidMandate("reason is required")
        if not self.nonce or not self.nonce.strip():
            raise InvalidMandate("nonce is required")


@dataclass(frozen=True)
class DecisionContext:
    """
    Full context used to enforce sovereignty invariants before any action is executed.
    """
    request_id: str
    kind: DecisionKind
    criticality: Criticality
    actor: str  # agent/service id that proposes/requests the action
    target: str  # system/resource that will be affected
    goal: str  # human-provided or system-provided goal reference
    proposed_action: str  # short description for audit and explainability
    inputs: Mapping[str, Any]
    mandate: Optional[HumanMandate]
    created_at_utc: _dt.datetime
    allow_autonomy: bool = False  # explicit opt-in for non-critical safe automation

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "kind": self.kind.value,
            "criticality": self.criticality.value,
            "actor": self.actor,
            "target": self.target,
            "goal": self.goal,
            "proposed_action": self.proposed_action,
            "inputs": _canonicalize(self.inputs),
            "mandate": _canonicalize(_mandate_to_dict(self.mandate)),
            "created_at_utc": _iso_utc(self.created_at_utc),
            "allow_autonomy": bool(self.allow_autonomy),
        }

    def fingerprint(self) -> str:
        payload = _json_dumps_canonical(self.to_canonical_dict())
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class InvariantResult:
    ok: bool
    approval_mode: ApprovalMode
    violations: Tuple[str, ...]
    context_fingerprint: str
    checked_at_utc: str  # ISO-8601 UTC
    policy_id: str

    def raise_if_failed(self) -> None:
        if not self.ok:
            raise SovereigntyViolation(
                "human sovereignty invariant violation: "
                + "; ".join(self.violations)
                + f" | policy={self.policy_id} | fp={self.context_fingerprint}"
            )


@dataclass(frozen=True)
class SovereigntyPolicy:
    """
    Policy determining when a human mandate is required.
    """
    policy_id: str = "human-sovereignty-default-v1"
    require_mandate_for_kinds: Tuple[DecisionKind, ...] = (
        DecisionKind.EXECUTE,
        DecisionKind.WRITE,
        DecisionKind.DELETE,
        DecisionKind.ESCALATE_PRIVILEGE,
        DecisionKind.CHANGE_POLICY,
        DecisionKind.CHANGE_GOAL,
        DecisionKind.TRANSFER_VALUE,
    )
    require_mandate_at_or_above: Criticality = Criticality.HIGH
    fail_closed: bool = True
    max_inputs_bytes: int = 256_000
    max_string_len: int = 16_384
    allowed_actor_pattern: str = r"^[a-zA-Z0-9][a-zA-Z0-9_\-.:]{1,127}$"
    allowed_target_pattern: str = r"^[a-zA-Z0-9][a-zA-Z0-9_\-.:/]{1,255}$"

    def requires_mandate(self, ctx: DecisionContext) -> bool:
        if ctx.kind in self.require_mandate_for_kinds:
            return True
        return _criticality_ge(ctx.criticality, self.require_mandate_at_or_above)


_DEFAULT_POLICY = SovereigntyPolicy()


def get_default_policy() -> SovereigntyPolicy:
    return _DEFAULT_POLICY


def set_default_policy(policy: SovereigntyPolicy) -> None:
    global _DEFAULT_POLICY
    _DEFAULT_POLICY = policy


def build_context(
    *,
    kind: DecisionKind,
    criticality: Criticality,
    actor: str,
    target: str,
    goal: str,
    proposed_action: str,
    inputs: Optional[Mapping[str, Any]] = None,
    mandate: Optional[HumanMandate] = None,
    request_id: Optional[str] = None,
    created_at_utc: Optional[_dt.datetime] = None,
    allow_autonomy: bool = False,
) -> DecisionContext:
    rid = request_id or str(uuid.uuid4())
    created = created_at_utc or _dt.datetime.now(tz=_dt.timezone.utc)
    return DecisionContext(
        request_id=rid,
        kind=kind,
        criticality=criticality,
        actor=actor,
        target=target,
        goal=goal,
        proposed_action=proposed_action,
        inputs=dict(inputs or {}),
        mandate=mandate,
        created_at_utc=created,
        allow_autonomy=bool(allow_autonomy),
    )


def check_invariants(
    ctx: DecisionContext,
    *,
    policy: Optional[SovereigntyPolicy] = None,
    now_utc: Optional[_dt.datetime] = None,
    extra_checks: Optional[Sequence[Callable[[DecisionContext, SovereigntyPolicy], Optional[str]]]] = None,
) -> InvariantResult:
    pol = policy or _DEFAULT_POLICY
    now = now_utc or _dt.datetime.now(tz=_dt.timezone.utc)

    violations: list[str] = []
    try:
        _validate_context_shape(ctx, pol, violations)
        _validate_inputs_limits(ctx, pol, violations)
        _validate_mandate_rules(ctx, pol, now, violations)

        if extra_checks:
            for fn in extra_checks:
                try:
                    msg = fn(ctx, pol)
                except Exception as e:
                    if pol.fail_closed:
                        violations.append(f"extra_check_error:{_safe_exc_name(e)}")
                        continue
                    logger.exception("extra check failed but fail_closed is false")
                    continue
                if msg:
                    violations.append(f"extra_check:{msg}")

    except Exception as e:
        if pol.fail_closed:
            violations.append(f"invariant_check_error:{_safe_exc_name(e)}")
        else:
            raise InvariantCheckError(str(e)) from e

    fp = ctx.fingerprint()
    requires = pol.requires_mandate(ctx)
    approval_mode = ApprovalMode.REQUIRED if requires else ApprovalMode.NONE

    ok = len(violations) == 0
    checked_iso = _iso_utc(now)

    result = InvariantResult(
        ok=ok,
        approval_mode=approval_mode,
        violations=tuple(violations),
        context_fingerprint=fp,
        checked_at_utc=checked_iso,
        policy_id=pol.policy_id,
    )
    return result


def enforce(
    ctx: DecisionContext,
    *,
    policy: Optional[SovereigntyPolicy] = None,
    now_utc: Optional[_dt.datetime] = None,
    extra_checks: Optional[Sequence[Callable[[DecisionContext, SovereigntyPolicy], Optional[str]]]] = None,
) -> InvariantResult:
    """
    Enforce invariants and raise if any violation exists.
    Returns InvariantResult for auditing.
    """
    res = check_invariants(ctx, policy=policy, now_utc=now_utc, extra_checks=extra_checks)
    res.raise_if_failed()
    return res


def env_fail_closed_enabled(default: bool = True) -> bool:
    """
    Reads environment toggle for fail-closed mode.
    Values: 1, true, yes enable; 0, false, no disable.
    """
    val = os.environ.get("HUMAN_SOVEREIGNTY_FAIL_CLOSED")
    if val is None:
        return default
    v = val.strip().lower()
    if v in ("1", "true", "yes", "y", "on"):
        return True
    if v in ("0", "false", "no", "n", "off"):
        return False
    return default


def make_mandate(
    *,
    human_id: str,
    session_id: str,
    ttl_seconds: int,
    reason: str,
    signature: Optional[str] = None,
    attestation_ref: Optional[str] = None,
    issued_at_utc: Optional[_dt.datetime] = None,
    nonce: Optional[str] = None,
) -> HumanMandate:
    issued = issued_at_utc or _dt.datetime.now(tz=_dt.timezone.utc)
    exp = issued + _dt.timedelta(seconds=int(ttl_seconds))
    n = nonce or _new_nonce()
    mandate = HumanMandate(
        human_id=human_id,
        session_id=session_id,
        issued_at_utc=issued,
        expires_at_utc=exp,
        reason=reason,
        nonce=n,
        signature=signature,
        attestation_ref=attestation_ref,
    )
    mandate.validate(now_utc=_dt.datetime.now(tz=_dt.timezone.utc))
    return mandate


def mandate_from_dict(data: Mapping[str, Any]) -> HumanMandate:
    """
    Strict parsing to avoid silent acceptance of malformed mandates.
    """
    def _req(k: str) -> Any:
        if k not in data:
            raise InvalidMandate(f"missing field: {k}")
        return data[k]

    issued = _parse_dt_utc(_req("issued_at_utc"))
    exp = _parse_dt_utc(_req("expires_at_utc"))

    mandate = HumanMandate(
        human_id=str(_req("human_id")),
        session_id=str(_req("session_id")),
        issued_at_utc=issued,
        expires_at_utc=exp,
        reason=str(_req("reason")),
        nonce=str(_req("nonce")),
        signature=(str(data["signature"]) if "signature" in data and data["signature"] is not None else None),
        attestation_ref=(str(data["attestation_ref"]) if "attestation_ref" in data and data["attestation_ref"] is not None else None),
    )
    mandate.validate(now_utc=_dt.datetime.now(tz=_dt.timezone.utc))
    return mandate


def mandate_to_dict(mandate: HumanMandate) -> Dict[str, Any]:
    return _mandate_to_dict(mandate)


def _mandate_to_dict(mandate: Optional[HumanMandate]) -> Optional[Dict[str, Any]]:
    if mandate is None:
        return None
    return {
        "human_id": mandate.human_id,
        "session_id": mandate.session_id,
        "issued_at_utc": _iso_utc(mandate.issued_at_utc),
        "expires_at_utc": _iso_utc(mandate.expires_at_utc),
        "reason": mandate.reason,
        "nonce": mandate.nonce,
        "signature": mandate.signature,
        "attestation_ref": mandate.attestation_ref,
    }


def _validate_context_shape(ctx: DecisionContext, pol: SovereigntyPolicy, violations: list[str]) -> None:
    if not ctx.request_id or not str(ctx.request_id).strip():
        violations.append("missing_request_id")
    if not isinstance(ctx.kind, DecisionKind):
        violations.append("invalid_kind")
    if not isinstance(ctx.criticality, Criticality):
        violations.append("invalid_criticality")
    if not ctx.actor or not str(ctx.actor).strip():
        violations.append("missing_actor")
    if not ctx.target or not str(ctx.target).strip():
        violations.append("missing_target")
    if not ctx.goal or not str(ctx.goal).strip():
        violations.append("missing_goal")
    if not ctx.proposed_action or not str(ctx.proposed_action).strip():
        violations.append("missing_proposed_action")

    if not isinstance(ctx.created_at_utc, _dt.datetime) or ctx.created_at_utc.tzinfo is None:
        violations.append("created_at_utc_not_timezone_aware")

    if ctx.actor and not re.match(pol.allowed_actor_pattern, str(ctx.actor)):
        violations.append("actor_pattern_rejected")
    if ctx.target and not re.match(pol.allowed_target_pattern, str(ctx.target)):
        violations.append("target_pattern_rejected")

    if len(str(ctx.goal)) > pol.max_string_len:
        violations.append("goal_too_long")
    if len(str(ctx.proposed_action)) > pol.max_string_len:
        violations.append("proposed_action_too_long")


def _validate_inputs_limits(ctx: DecisionContext, pol: SovereigntyPolicy, violations: list[str]) -> None:
    try:
        canon = _json_dumps_canonical(_canonicalize(ctx.inputs))
        size = len(canon.encode("utf-8"))
        if size > pol.max_inputs_bytes:
            violations.append("inputs_too_large")
    except Exception:
        if pol.fail_closed:
            violations.append("inputs_canonicalization_failed")


def _validate_mandate_rules(
    ctx: DecisionContext,
    pol: SovereigntyPolicy,
    now_utc: _dt.datetime,
    violations: list[str],
) -> None:
    requires = pol.requires_mandate(ctx)

    if requires:
        if ctx.mandate is None:
            violations.append("missing_human_mandate")
            return
        try:
            ctx.mandate.validate(now_utc=now_utc)
        except InvalidMandate as e:
            violations.append(f"invalid_mandate:{_safe_exc_name(e)}")
            return

        if not ctx.mandate.reason.strip():
            violations.append("mandate_reason_empty")

    else:
        if not ctx.allow_autonomy and ctx.kind in (DecisionKind.EXECUTE, DecisionKind.WRITE, DecisionKind.DELETE):
            violations.append("autonomy_not_explicitly_allowed_for_mutation")


def _criticality_ge(a: Criticality, b: Criticality) -> bool:
    order = {
        Criticality.LOW: 0,
        Criticality.MEDIUM: 1,
        Criticality.HIGH: 2,
        Criticality.CRITICAL: 3,
    }
    return order[a] >= order[b]


def _iso_utc(dt: _dt.datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    return dt.astimezone(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_dt_utc(value: Any) -> _dt.datetime:
    if isinstance(value, _dt.datetime):
        if value.tzinfo is None:
            raise InvalidMandate("datetime must be timezone-aware")
        return value.astimezone(_dt.timezone.utc)
    if not isinstance(value, str):
        raise InvalidMandate("datetime must be ISO-8601 string or datetime")
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = _dt.datetime.fromisoformat(s)
    except ValueError as e:
        raise InvalidMandate("invalid datetime format") from e
    if dt.tzinfo is None:
        raise InvalidMandate("datetime must include timezone")
    return dt.astimezone(_dt.timezone.utc)


def _json_dumps_canonical(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _canonicalize(obj: Any) -> Any:
    """
    Canonicalize inputs for stable hashing and deterministic audit.
    """
    if obj is None:
        return None
    if isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, bytes):
        return {"__bytes__": hashlib.sha256(obj).hexdigest(), "len": len(obj)}
    if isinstance(obj, _dt.datetime):
        if obj.tzinfo is None:
            return {"__datetime__": "naive"}
        return {"__datetime__": _iso_utc(obj)}
    if dataclasses.is_dataclass(obj):
        return _canonicalize(dataclasses.asdict(obj))
    if isinstance(obj, Mapping):
        items = {}
        for k in sorted(obj.keys(), key=lambda x: str(x)):
            items[str(k)] = _canonicalize(obj[k])
        return items
    if isinstance(obj, (list, tuple, set
