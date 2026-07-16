# human-sovereignty-core/domain/risk_levels.py
# Industrial-grade domain model for risk levels and mandatory verification rules.
# No external dependencies. Python 3.11+ recommended.

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple


class RiskLevel(str, Enum):
    """
    Risk levels for actions/decisions within Human Sovereignty Core.

    Contract:
      - LOW: routine, low impact, low irreversibility
      - MEDIUM: moderate impact or uncertainty
      - HIGH: high impact, elevated uncertainty, or sensitive context
      - CRITICAL: catastrophic potential or strong indicators of abuse
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class VerificationMethod(str, Enum):
    """
    Verification methods that can be required based on risk.
    """

    HUMAN_REVIEW = "HUMAN_REVIEW"
    TWO_PERSON_RULE = "TWO_PERSON_RULE"
    OUT_OF_BAND_CONFIRMATION = "OUT_OF_BAND_CONFIRMATION"
    CRYPTO_SIGNATURE = "CRYPTO_SIGNATURE"
    DEVICE_ATTESTATION = "DEVICE_ATTESTATION"
    RATE_LIMIT_ESCALATION = "RATE_LIMIT_ESCALATION"
    SAFE_MODE_EXECUTION = "SAFE_MODE_EXECUTION"
    CHANGE_FREEZE_WINDOW = "CHANGE_FREEZE_WINDOW"


class RiskModelError(RuntimeError):
    """Base exception for risk model failures."""


class InvalidRiskInputError(RiskModelError):
    """Raised when risk inputs are malformed or inconsistent."""


@dataclass(frozen=True, slots=True)
class RiskFactor:
    """
    A single risk factor used to compute a risk score.

    name: stable identifier used in logs and analytics.
    weight: positive integer weight (0..100 recommended).
    value: normalized [0.0..1.0] by the caller, or computed by a detector.
    rationale: short explanation for audit/explainability.
    """

    name: str
    weight: int
    value: float
    rationale: str = ""

    def __post_init__(self) -> None:
        n = (self.name or "").strip()
        if not n:
            raise InvalidRiskInputError("RiskFactor.name must be non-empty")
        if not isinstance(self.weight, int):
            raise InvalidRiskInputError("RiskFactor.weight must be int")
        if self.weight < 0:
            raise InvalidRiskInputError("RiskFactor.weight must be >= 0")
        if not isinstance(self.value, (int, float)):
            raise InvalidRiskInputError("RiskFactor.value must be numeric")
        v = float(self.value)
        if v < 0.0 or v > 1.0:
            raise InvalidRiskInputError("RiskFactor.value must be in [0.0, 1.0]")
        r = (self.rationale or "").strip()
        object.__setattr__(self, "name", n)
        object.__setattr__(self, "value", v)
        object.__setattr__(self, "rationale", r)


@dataclass(frozen=True, slots=True)
class VerificationPolicy:
    """
    Policy describing what verifications are mandatory for a given risk level.

    methods: required verification methods (order matters for UX flows).
    require_reason: if true, caller must provide a human-entered reason.
    require_ticket: if true, caller must provide an external change ticket id.
    require_audit_tags: if true, caller must provide structured audit tags.
    """

    methods: Tuple[VerificationMethod, ...] = field(default_factory=tuple)
    require_reason: bool = False
    require_ticket: bool = False
    require_audit_tags: bool = False


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """
    Result of risk evaluation.

    score: 0..100 integer score.
    level: mapped RiskLevel.
    factors: normalized factors used.
    reasons: explainable reasons derived from factors (non-empty if level != LOW).
    required_verifications: verification policy for this level.
    """

    score: int
    level: RiskLevel
    factors: Tuple[RiskFactor, ...]
    reasons: Tuple[str, ...]
    required_verifications: VerificationPolicy

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level.value,
            "factors": [
                {
                    "name": f.name,
                    "weight": f.weight,
                    "value": f.value,
                    "rationale": f.rationale,
                }
                for f in self.factors
            ],
            "reasons": list(self.reasons),
            "required_verifications": {
                "methods": [m.value for m in self.required_verifications.methods],
                "require_reason": self.required_verifications.require_reason,
                "require_ticket": self.required_verifications.require_ticket,
                "require_audit_tags": self.required_verifications.require_audit_tags,
            },
        }


@dataclass(frozen=True, slots=True)
class RiskThresholds:
    """
    Thresholds map score to RiskLevel.

    Interpretation:
      - score < medium_min => LOW
      - medium_min <= score < high_min => MEDIUM
      - high_min <= score < critical_min => HIGH
      - score >= critical_min => CRITICAL
    """

    medium_min: int = 25
    high_min: int = 50
    critical_min: int = 75

    def __post_init__(self) -> None:
        for name, v in (
            ("medium_min", self.medium_min),
            ("high_min", self.high_min),
            ("critical_min", self.critical_min),
        ):
            if not isinstance(v, int):
                raise InvalidRiskInputError(f"{name} must be int")
            if v < 0 or v > 100:
                raise InvalidRiskInputError(f"{name} must be in [0, 100]")
        if not (self.medium_min <= self.high_min <= self.critical_min):
            raise InvalidRiskInputError("Thresholds must satisfy medium <= high <= critical")


DEFAULT_THRESHOLDS = RiskThresholds()

DEFAULT_VERIFICATION_POLICIES: Dict[RiskLevel, VerificationPolicy] = {
    RiskLevel.LOW: VerificationPolicy(
        methods=tuple(),
        require_reason=False,
        require_ticket=False,
        require_audit_tags=False,
    ),
    RiskLevel.MEDIUM: VerificationPolicy(
        methods=(VerificationMethod.OUT_OF_BAND_CONFIRMATION,),
        require_reason=True,
        require_ticket=False,
        require_audit_tags=True,
    ),
    RiskLevel.HIGH: VerificationPolicy(
        methods=(
            VerificationMethod.HUMAN_REVIEW,
            VerificationMethod.CRYPTO_SIGNATURE,
            VerificationMethod.RATE_LIMIT_ESCALATION,
        ),
        require_reason=True,
        require_ticket=True,
        require_audit_tags=True,
    ),
    RiskLevel.CRITICAL: VerificationPolicy(
        methods=(
            VerificationMethod.TWO_PERSON_RULE,
            VerificationMethod.HUMAN_REVIEW,
            VerificationMethod.CRYPTO_SIGNATURE,
            VerificationMethod.DEVICE_ATTESTATION,
            VerificationMethod.SAFE_MODE_EXECUTION,
            VerificationMethod.CHANGE_FREEZE_WINDOW,
        ),
        require_reason=True,
        require_ticket=True,
        require_audit_tags=True,
    ),
}


def compute_risk_score(factors: Sequence[RiskFactor]) -> int:
    """
    Computes integer risk score in range [0..100].

    Scoring:
      - weighted average of factor values
      - weights sum to W; score = round(100 * sum(w_i * v_i) / W)
      - if all weights are 0 => score 0
    """
    if factors is None:
        raise InvalidRiskInputError("factors must not be None")
    if not isinstance(factors, Sequence):
        raise InvalidRiskInputError("factors must be a sequence")

    total_w = 0
    accum = 0.0

    for f in factors:
        if not isinstance(f, RiskFactor):
            raise InvalidRiskInputError("all factors must be RiskFactor")
        if f.weight == 0:
            continue
        total_w += f.weight
        accum += float(f.weight) * float(f.value)

    if total_w <= 0:
        return 0

    raw = 100.0 * (accum / float(total_w))
    # Clamp and round to nearest int
    if raw < 0.0:
        raw = 0.0
    if raw > 100.0:
        raw = 100.0
    return int(round(raw))


def map_score_to_level(score: int, thresholds: RiskThresholds = DEFAULT_THRESHOLDS) -> RiskLevel:
    """
    Maps score to a RiskLevel using thresholds.
    """
    if not isinstance(score, int):
        raise InvalidRiskInputError("score must be int")
    if score < 0 or score > 100:
        raise InvalidRiskInputError("score must be in [0, 100]")

    if score < thresholds.medium_min:
        return RiskLevel.LOW
    if score < thresholds.high_min:
        return RiskLevel.MEDIUM
    if score < thresholds.critical_min:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def derive_reasons(factors: Sequence[RiskFactor], *, top_k: int = 5, min_contribution: float = 0.10) -> Tuple[str, ...]:
    """
    Produces explainable reasons from the highest contributing factors.

    Contribution:
      contribution = (weight * value) / max(1, sum(weight * value))
    Only factors with value > 0 and contribution >= min_contribution are included.
    """
    if not isinstance(top_k, int) or top_k <= 0:
        raise InvalidRiskInputError("top_k must be a positive int")
    if not isinstance(min_contribution, (int, float)):
        raise InvalidRiskInputError("min_contribution must be numeric")
    mc = float(min_contribution)
    if mc < 0.0 or mc > 1.0:
        raise InvalidRiskInputError("min_contribution must be in [0.0, 1.0]")

    weighted_values: list[Tuple[float, RiskFactor]] = []
    denom = 0.0
    for f in factors:
        wv = float(f.weight) * float(f.value)
        if wv > 0.0:
            weighted_values.append((wv, f))
            denom += wv

    if denom <= 0.0:
        return tuple()

    weighted_values.sort(key=lambda x: x[0], reverse=True)

    reasons: list[str] = []
    for wv, f in weighted_values[:top_k]:
        contrib = wv / denom
        if contrib < mc:
            continue
        if f.rationale:
            reasons.append(f"{f.name}: {f.rationale}")
        else:
            reasons.append(f"{f.name}: contribution={contrib:.2f}, value={f.value:.2f}, weight={f.weight}")
    return tuple(reasons)


def evaluate_risk(
    *,
    factors: Sequence[RiskFactor],
    thresholds: RiskThresholds = DEFAULT_THRESHOLDS,
    policies: Optional[Mapping[RiskLevel, VerificationPolicy]] = None,
) -> RiskAssessment:
    """
    High-level evaluation: score -> level -> required verifications + reasons.
    """
    score = compute_risk_score(factors)
    level = map_score_to_level(score, thresholds=thresholds)

    policy_map = dict(DEFAULT_VERIFICATION_POLICIES) if policies is None else dict(policies)
    if level not in policy_map:
        raise InvalidRiskInputError(f"Missing verification policy for level {level.value}")

    reasons = derive_reasons(factors)
    return RiskAssessment(
        score=score,
        level=level,
        factors=tuple(factors),
        reasons=reasons,
        required_verifications=policy_map[level],
    )


def mandatory_verification_required(level: RiskLevel) -> bool:
    """
    Convenience: returns True if any verification method is required for this level.
    """
    if not isinstance(level, RiskLevel):
        raise InvalidRiskInputError("level must be RiskLevel")
    pol = DEFAULT_VERIFICATION_POLICIES.get(level)
    if pol is None:
        raise InvalidRiskInputError(f"Missing default policy for {level.value}")
    return len(pol.methods) > 0


def validate_verification_payload(
    *,
    level: RiskLevel,
    provided_methods: Iterable[VerificationMethod],
    reason: Optional[str],
    ticket_id: Optional[str],
    audit_tags: Optional[Mapping[str, Any]],
    policies: Optional[Mapping[RiskLevel, VerificationPolicy]] = None,
) -> None:
    """
    Validates that the provided verification payload satisfies mandatory requirements.

    This is a pure domain validator; it does not perform the verifications.
    """
    if not isinstance(level, RiskLevel):
        raise InvalidRiskInputError("level must be RiskLevel")

    policy_map = dict(DEFAULT_VERIFICATION_POLICIES) if policies is None else dict(policies)
    pol = policy_map.get(level)
    if pol is None:
        raise InvalidRiskInputError(f"Missing verification policy for level {level.value}")

    provided = set()
    for m in provided_methods:
        if not isinstance(m, VerificationMethod):
            raise InvalidRiskInputError("provided_methods must contain VerificationMethod")
        provided.add(m)

    missing = [m for m in pol.methods if m not in provided]
    if missing:
        raise InvalidRiskInputError(
            f"Missing required verification methods for {level.value}: {[m.value for m in missing]}"
        )

    if pol.require_reason:
        rr = (reason or "").strip()
        if not rr:
            raise InvalidRiskInputError(f"Missing required reason for {level.value}")

    if pol.require_ticket:
        tid = (ticket_id or "").strip()
        if not tid:
            raise InvalidRiskInputError(f"Missing required ticket_id for {level.value}")

    if pol.require_audit_tags:
        if audit_tags is None or not isinstance(audit_tags, Mapping) or not audit_tags:
            raise InvalidRiskInputError(f"Missing required audit_tags for {level.value}")
