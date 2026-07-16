# human-sovereignty-core/decision_packets/classifier.py
#
# Industrial-grade Decision Packet Classifier for Human Sovereignty Core.
#
# Responsibilities:
# - Validate and normalize incoming "decision packets"
# - Compute risk tier and sovereignty domain impact
# - Select enforcement action deterministically via policy rules
# - Produce explainable, audit-friendly classification output
#
# Non-goals:
# - No network calls
# - No framework-specific assumptions
# - No persistence
#
# This module contains no external factual claims; it is pure logic.

from __future__ import annotations

import dataclasses
import datetime as _dt
import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from human_sovereignty_core.domain.enums import (
    AuditEventType,
    DecisionAuthority,
    EnforcementAction,
    HumanConsentState,
    PolicyScope,
    RiskLevel,
    SovereigntyDomain,
    SovereigntyViolationType,
)

_ALLOWED_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-:.]{0,127}$")
_ALLOWED_KEY_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-:.]{0,255}$")


class DecisionPacketError(ValueError):
    pass


def _utc_now_iso() -> str:
    return _dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _as_str(x: Any, *, field_name: str, allow_empty: bool = False) -> str:
    if not isinstance(x, str):
        raise DecisionPacketError(f"{field_name} must be a string")
    s = x.strip()
    if not allow_empty and not s:
        raise DecisionPacketError(f"{field_name} must be a non-empty string")
    return s


def _as_bool(x: Any, *, field_name: str) -> bool:
    if isinstance(x, bool):
        return x
    raise DecisionPacketError(f"{field_name} must be a boolean")


def _as_dict(x: Any, *, field_name: str) -> Dict[str, Any]:
    if x is None:
        return {}
    if isinstance(x, dict):
        return x
    raise DecisionPacketError(f"{field_name} must be an object/dict")


def _as_list(x: Any, *, field_name: str) -> List[Any]:
    if x is None:
        return []
    if isinstance(x, list):
        return x
    raise DecisionPacketError(f"{field_name} must be an array/list")


def _validate_id(value: str, *, field_name: str) -> str:
    s = _as_str(value, field_name=field_name)
    if not _ALLOWED_ID_RE.match(s):
        raise DecisionPacketError(f"{field_name} has invalid format")
    return s


def _validate_kv_map(meta: Mapping[str, Any], *, field_name: str, max_items: int = 64) -> Dict[str, Any]:
    if not isinstance(meta, Mapping):
        raise DecisionPacketError(f"{field_name} must be a mapping")
    if len(meta) > max_items:
        raise DecisionPacketError(f"{field_name} too many keys (max {max_items})")
    out: Dict[str, Any] = {}
    for k, v in meta.items():
        if not isinstance(k, str):
            raise DecisionPacketError(f"{field_name} keys must be strings")
        kk = k.strip()
        if not kk or not _ALLOWED_KEY_RE.match(kk):
            raise DecisionPacketError(f"{field_name} has invalid key: {k!r}")
        out[kk] = v
    return out


def _safe_json_preview(obj: Any, max_len: int = 600) -> str:
    try:
        s = json.dumps(obj, ensure_ascii=False, sort_keys=True)
    except Exception:
        s = str(obj)
    if len(s) > max_len:
        return s[:max_len] + "..."
    return s


def _coerce_enum(enum_cls: Any, value: Any, *, field_name: str):
    if isinstance(value, enum_cls):
        return value
    s = _as_str(value, field_name=field_name)
    try:
        return enum_cls(s)
    except Exception as e:
        raise DecisionPacketError(f"{field_name} invalid value: {s}") from e


@dataclass(frozen=True)
class DecisionPacket:
    packet_id: str
    occurred_at_utc: str
    actor_id: str
    authority: DecisionAuthority
    consent: HumanConsentState
    scope: PolicyScope

    resource_type: str
    resource_id: str
    operation: str

    domain: SovereigntyDomain
    intent: str

    # Optional classifiers
    declared_risk: Optional[RiskLevel] = None
    declared_violation: Optional[SovereigntyViolationType] = None

    # Context for explainability/audit
    context: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ClassificationReason:
    code: str
    message: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {"code": self.code, "message": self.message, "evidence": self.evidence}


@dataclass(frozen=True)
class ClassificationResult:
    classification_id: str
    packet_id: str
    generated_at_utc: str

    risk: RiskLevel
    enforcement: EnforcementAction
    violation: Optional[SovereigntyViolationType]

    audit_event: AuditEventType
    reasons: Tuple[ClassificationReason, ...]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "classification_id": self.classification_id,
            "packet_id": self.packet_id,
            "generated_at_utc": self.generated_at_utc,
            "risk": str(self.risk),
            "enforcement": str(self.enforcement),
            "violation": str(self.violation) if self.violation else None,
            "audit_event": str(self.audit_event),
            "reasons": [r.as_dict() for r in self.reasons],
        }


@dataclass(frozen=True)
class Rule:
    """
    Deterministic matching rule.

    If all specified matchers match, the rule applies.

    Matchers supported:
    - domain: SovereigntyDomain
    - operation: exact string
    - resource_type: exact string
    - authority: DecisionAuthority
    - consent: HumanConsentState
    - scope: PolicyScope
    - intent_regex: regex against packet.intent
    - metadata_any: list of keys that must exist in packet.metadata
    - context_any: list of keys that must exist in packet.context
    - context_kv: dict of key->exact value match in context

    Actions:
    - risk: RiskLevel
    - enforcement: EnforcementAction
    - violation: Optional[SovereigntyViolationType]
    - audit_event: AuditEventType
    """

    id: str
    description: str

    domain: Optional[SovereigntyDomain] = None
    operation: Optional[str] = None
    resource_type: Optional[str] = None
    authority: Optional[DecisionAuthority] = None
    consent: Optional[HumanConsentState] = None
    scope: Optional[PolicyScope] = None
    intent_regex: Optional[str] = None

    metadata_any: Tuple[str, ...] = ()
    context_any: Tuple[str, ...] = ()
    context_kv: Tuple[Tuple[str, Any], ...] = ()

    risk: RiskLevel = RiskLevel.LOW
    enforcement: EnforcementAction = EnforcementAction.WARN
    violation: Optional[SovereigntyViolationType] = None
    audit_event: AuditEventType = AuditEventType.POLICY_EVALUATED

    def matches(self, p: DecisionPacket) -> bool:
        if self.domain is not None and p.domain != self.domain:
            return False
        if self.operation is not None and p.operation != self.operation:
            return False
        if self.resource_type is not None and p.resource_type != self.resource_type:
            return False
        if self.authority is not None and p.authority != self.authority:
            return False
        if self.consent is not None and p.consent != self.consent:
            return False
        if self.scope is not None and p.scope != self.scope:
            return False
        if self.intent_regex is not None:
            try:
                if re.search(self.intent_regex, p.intent, flags=re.IGNORECASE) is None:
                    return False
            except re.error:
                return False
        for k in self.metadata_any:
            if k not in p.metadata:
                return False
        for k in self.context_any:
            if k not in p.context:
                return False
        for k, v in self.context_kv:
            if p.context.get(k) != v:
                return False
        return True


@dataclass(frozen=True)
class Policy:
    """
    Policy is an ordered set of rules.
    The first matching rule wins.
    """

    rules: Tuple[Rule, ...] = ()

    def evaluate(self, p: DecisionPacket) -> Optional[Rule]:
        for r in self.rules:
            if r.matches(p):
                return r
        return None


def default_policy() -> Policy:
    """
    Conservative baseline policy.
    Safe defaults: unknown or denied consent and sensitive domains escalate risk.

    This policy is intentionally generic. Extend in your repo-level governance configs.
    """
    rules: List[Rule] = []

    # Hard blocks for explicit denial/revocation with non-human authority
    rules.append(
        Rule(
            id="deny_revoked_or_denied_non_human",
            description="Block if consent is denied/revoked and decision is not purely human",
            consent=HumanConsentState.DENIED,
            authority=DecisionAuthority.AI_AUTONOMOUS,
            risk=RiskLevel.CRITICAL,
            enforcement=EnforcementAction.BLOCK,
            violation=SovereigntyViolationType.CONSENT_BYPASS,
            audit_event=AuditEventType.ACCESS_DENIED,
        )
    )
    rules.append(
        Rule(
            id="revoked_non_human",
            description="Block if consent is revoked and decision is not purely human",
            consent=HumanConsentState.REVOKED,
            authority=DecisionAuthority.AI_AUTONOMOUS,
            risk=RiskLevel.CRITICAL,
            enforcement=EnforcementAction.BLOCK,
            violation=SovereigntyViolationType.CONSENT_BYPASS,
            audit_event=AuditEventType.ACCESS_DENIED,
        )
    )

    # High risk for sensitive domains when consent is unknown
    for dom in (SovereigntyDomain.IDENTITY, SovereigntyDomain.MIND, SovereigntyDomain.BODY):
        rules.append(
            Rule(
                id=f"unknown_consent_sensitive_domain_{dom.value}",
                description="Escalate when consent is unknown in sensitive domains",
                domain=dom,
                consent=HumanConsentState.UNKNOWN,
                risk=RiskLevel.HIGH,
                enforcement=EnforcementAction.ESCALATE,
                violation=None,
                audit_event=AuditEventType.POLICY_EVALUATED,
            )
        )

    # Default: if consent is denied, block access requests
    rules.append(
        Rule(
            id="consent_denied_block_access",
            description="Block access operation when consent is denied",
            consent=HumanConsentState.DENIED,
            operation="access",
            risk=RiskLevel.HIGH,
            enforcement=EnforcementAction.BLOCK,
            violation=SovereigntyViolationType.UNAUTHORIZED_ACCESS,
            audit_event=AuditEventType.ACCESS_DENIED,
        )
    )

    # If consent is granted, allow typical access on data/digital with moderate checks
    for dom in (SovereigntyDomain.DATA, SovereigntyDomain.DIGITAL, SovereigntyDomain.ECONOMIC):
        rules.append(
            Rule(
                id=f"granted_consent_allow_{dom.value}",
                description="Allow when consent is granted for common domains",
                domain=dom,
                consent=HumanConsentState.GRANTED,
                operation="access",
                risk=RiskLevel.LOW,
                enforcement=EnforcementAction.ALLOW,
                violation=None,
                audit_event=AuditEventType.ACCESS_GRANTED,
            )
        )

    # Detect suspicious intents (generic)
    rules.append(
        Rule(
            id="suspicious_intent_extract",
            description="Escalate if intent indicates extraction",
            intent_regex=r"\b(extract|exfiltrate|dump|harvest|scrape)\b",
            risk=RiskLevel.HIGH,
            enforcement=EnforcementAction.ESCALATE,
            violation=SovereigntyViolationType.DATA_EXTRACTION,
            audit_event=AuditEventType.POLICY_EVALUATED,
        )
    )
    rules.append(
        Rule(
            id="suspicious_intent_surveillance",
            description="Escalate if intent indicates surveillance/monitoring",
            intent_regex=r"\b(surveil|surveillance|monitor|track|profil(e|ing))\b",
            risk=RiskLevel.HIGH,
            enforcement=EnforcementAction.ESCALATE,
            violation=SovereigntyViolationType.SURVEILLANCE,
            audit_event=AuditEventType.POLICY_EVALUATED,
        )
    )

    return Policy(rules=tuple(rules))


class DecisionPacketClassifier:
    """
    Main classifier.

    Step-by-step behavior:
    1) validate and normalize packet
    2) compute baseline risk from packet fields
    3) apply policy rules (first match)
    4) reconcile declared risk/violation with computed (never lower computed risk)
    5) output explainable result
    """

    def __init__(self, policy: Optional[Policy] = None) -> None:
        self._policy = policy or default_policy()

    def parse(self, raw: Mapping[str, Any]) -> DecisionPacket:
        d = _as_dict(raw, field_name="decision_packet")

        packet_id = d.get("packet_id") or f"dp_{uuid.uuid4().hex}"
        packet_id = _validate_id(str(packet_id), field_name="packet_id")

        occurred_at_utc = d.get("occurred_at_utc") or _utc_now_iso()
        occurred_at_utc = _as_str(occurred_at_utc, field_name="occurred_at_utc")

        actor_id = _validate_id(_as_str(d.get("actor_id"), field_name="actor_id"), field_name="actor_id")

        authority = _coerce_enum(DecisionAuthority, d.get("authority"), field_name="authority")
        consent = _coerce_enum(HumanConsentState, d.get("consent"), field_name="consent")
        scope = _coerce_enum(PolicyScope, d.get("scope"), field_name="scope")

        resource_type = _validate_id(_as_str(d.get("resource_type"), field_name="resource_type"), field_name="resource_type")
        resource_id = _validate_id(_as_str(d.get("resource_id"), field_name="resource_id"), field_name="resource_id")
        operation = _validate_id(_as_str(d.get("operation"), field_name="operation"), field_name="operation")

        domain = _coerce_enum(SovereigntyDomain, d.get("domain"), field_name="domain")
        intent = _as_str(d.get("intent"), field_name="intent")

        declared_risk = d.get("declared_risk")
        if declared_risk is not None:
            declared_risk = _coerce_enum(RiskLevel, declared_risk, field_name="declared_risk")

        declared_violation = d.get("declared_violation")
        if declared_violation is not None:
            declared_violation = _coerce_enum(SovereigntyViolationType, declared_violation, field_name="declared_violation")

        context = _validate_kv_map(_as_dict(d.get("context"), field_name="context"), field_name="context", max_items=128)
        metadata = _validate_kv_map(_as_dict(d.get("metadata"), field_name="metadata"), field_name="metadata", max_items=128)

        return DecisionPacket(
            packet_id=packet_id,
            occurred_at_utc=occurred_at_utc,
            actor_id=actor_id,
            authority=authority,
            consent=consent,
            scope=scope,
            resource_type=resource_type,
            resource_id=resource_id,
            operation=operation,
            domain=domain,
            intent=intent,
            declared_risk=declared_risk,
            declared_violation=declared_violation,
            context=context,
            metadata=metadata,
        )

    def classify(self, packet: DecisionPacket) -> ClassificationResult:
        reasons: List[ClassificationReason] = []

        baseline_risk = self._baseline_risk(packet, reasons=reasons)
        rule = self._policy.evaluate(packet)

        if rule is None:
            reasons.append(
                ClassificationReason(
                    code="policy.no_match",
                    message="No policy rule matched; defaults applied",
                    evidence={"baseline_risk": str(baseline_risk)},
                )
            )
            computed_risk = baseline_risk
            enforcement = self._default_enforcement(packet, computed_risk, reasons=reasons)
            violation = packet.declared_violation
            audit_event = AuditEventType.POLICY_EVALUATED
        else:
            reasons.append(
                ClassificationReason(
                    code="policy.matched",
                    message="Policy rule matched and applied",
                    evidence={
                        "rule_id": rule.id,
                        "rule_description": rule.description,
                        "rule_risk": str(rule.risk),
                        "rule_enforcement": str(rule.enforcement),
                        "rule_violation": str(rule.violation) if rule.violation else None,
                    },
                )
            )
            computed_risk = self._max_risk(baseline_risk, rule.risk)
            if computed_risk != rule.risk:
                reasons.append(
                    ClassificationReason(
                        code="risk.escalated_by_baseline",
                        message="Baseline risk was higher than rule risk; using higher risk",
                        evidence={
                            "baseline_risk": str(baseline_risk),
                            "rule_risk": str(rule.risk),
                        },
                    )
                )
            enforcement = rule.enforcement
            violation = rule.violation or packet.declared_violation
            audit_event = rule.audit_event

        if packet.declared_risk is not None:
            declared = self._max_risk(computed_risk, packet.declared_risk)
            if declared != computed_risk:
                reasons.append(
                    ClassificationReason(
                        code="risk.escalated_by_declaration",
                        message="Declared risk raised the computed risk",
                        evidence={"declared_risk": str(packet.declared_risk)},
                    )
                )
                computed_risk = declared

        return ClassificationResult(
            classification_id=f"cls_{uuid.uuid4().hex}",
            packet_id=packet.packet_id,
            generated_at_utc=_utc_now_iso(),
            risk=computed_risk,
            enforcement=enforcement,
            violation=violation,
            audit_event=audit_event,
            reasons=tuple(reasons),
        )

    def _baseline_risk(
        self,
        packet: DecisionPacket,
        *,
        reasons: List[ClassificationReason],
    ) -> RiskLevel:
        risk = packet.declared_risk or RiskLevel.NONE
        if packet.consent in {HumanConsentState.DENIED, HumanConsentState.REVOKED}:
            risk = self._max_risk(risk, RiskLevel.CRITICAL)
            reasons.append(
                ClassificationReason(
                    code="consent.denied",
                    message="Denied or revoked consent requires critical handling",
                )
            )
        elif packet.consent in {HumanConsentState.UNKNOWN, HumanConsentState.EXPIRED}:
            risk = self._max_risk(risk, RiskLevel.MEDIUM)
            reasons.append(
                ClassificationReason(
                    code="consent.unconfirmed",
                    message="Consent is not currently confirmed",
                )
            )
        if packet.authority is DecisionAuthority.AI_AUTONOMOUS:
            risk = self._max_risk(risk, RiskLevel.HIGH)
            reasons.append(
                ClassificationReason(
                    code="authority.autonomous_ai",
                    message="Autonomous AI decisions require elevated review",
                )
            )
        return risk

    def _default_enforcement(
        self,
        packet: DecisionPacket,
        risk: RiskLevel,
        *,
        reasons: List[ClassificationReason],
    ) -> EnforcementAction:
        if risk in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            action = EnforcementAction.BLOCK
        elif risk is RiskLevel.MEDIUM:
            action = EnforcementAction.ESCALATE
        elif packet.consent is HumanConsentState.GRANTED:
            action = EnforcementAction.ALLOW
        else:
            action = EnforcementAction.WARN
        reasons.append(
            ClassificationReason(
                code="policy.default_enforcement",
                message="Default fail-closed enforcement selected",
                evidence={"action": str(action), "risk": str(risk)},
            )
        )
        return action

    @staticmethod
    def _max_risk(left: RiskLevel, right: RiskLevel) -> RiskLevel:
        order = {
            RiskLevel.NONE: 0,
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4,
        }
        return left if order[left] >= order[right] else right
