# agent_mash/governance/risk_matrix.py
from __future__ import annotations

import dataclasses
import json
import math
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskTreatment(str, Enum):
    ACCEPT = "accept"
    MONITOR = "monitor"
    MITIGATE = "mitigate"
    AVOID = "avoid"


class ControlType(str, Enum):
    PREVENTIVE = "preventive"
    DETECTIVE = "detective"
    CORRECTIVE = "corrective"
    COMPENSATING = "compensating"


class LikelihoodBand(str, Enum):
    RARE = "rare"
    UNLIKELY = "unlikely"
    POSSIBLE = "possible"
    LIKELY = "likely"
    ALMOST_CERTAIN = "almost_certain"


class ImpactBand(str, Enum):
    NEGLIGIBLE = "negligible"
    MINOR = "minor"
    MODERATE = "moderate"
    MAJOR = "major"
    SEVERE = "severe"


# ----------------------------
# Core configuration
# ----------------------------

@dataclass(frozen=True)
class RiskScaleConfig:
    """
    Defines how Likelihood/Impact map to numeric scores.

    Scores MUST be integers within [1..5] to fit a classic 5x5 matrix.
    """
    likelihood_map: Mapping[LikelihoodBand, int] = field(default_factory=lambda: {
        LikelihoodBand.RARE: 1,
        LikelihoodBand.UNLIKELY: 2,
        LikelihoodBand.POSSIBLE: 3,
        LikelihoodBand.LIKELY: 4,
        LikelihoodBand.ALMOST_CERTAIN: 5,
    })
    impact_map: Mapping[ImpactBand, int] = field(default_factory=lambda: {
        ImpactBand.NEGLIGIBLE: 1,
        ImpactBand.MINOR: 2,
        ImpactBand.MODERATE: 3,
        ImpactBand.MAJOR: 4,
        ImpactBand.SEVERE: 5,
    })
    # Optional weights for multi-dimensional impact/likelihood components
    # Example: {"confidentiality": 0.4, "integrity": 0.3, "availability": 0.3}
    likelihood_weights: Optional[Mapping[str, float]] = None
    impact_weights: Optional[Mapping[str, float]] = None

    def validate(self) -> None:
        _validate_band_map(self.likelihood_map, "likelihood_map")
        _validate_band_map(self.impact_map, "impact_map")
        if self.likelihood_weights is not None:
            _validate_weights(self.likelihood_weights, "likelihood_weights")
        if self.impact_weights is not None:
            _validate_weights(self.impact_weights, "impact_weights")


@dataclass(frozen=True)
class RiskAppetite:
    """
    Defines thresholds for risk levels and treatment decisions.

    - score is in [1..25]
    - Default thresholds are commonly used but can be adjusted.
    """
    low_max: int = 6
    medium_max: int = 12
    high_max: int = 19
    critical_max: int = 25

    # Treatment cutoffs (by level)
    treat_low: RiskTreatment = RiskTreatment.ACCEPT
    treat_medium: RiskTreatment = RiskTreatment.MONITOR
    treat_high: RiskTreatment = RiskTreatment.MITIGATE
    treat_critical: RiskTreatment = RiskTreatment.AVOID

    def validate(self) -> None:
        for name, v in (
            ("low_max", self.low_max),
            ("medium_max", self.medium_max),
            ("high_max", self.high_max),
            ("critical_max", self.critical_max),
        ):
            if not isinstance(v, int):
                raise TypeError(f"{name} must be int")
            if v < 1 or v > 25:
                raise ValueError(f"{name} must be within 1..25")
        if not (self.low_max <= self.medium_max <= self.high_max <= self.critical_max):
            raise ValueError("RiskAppetite thresholds must be non-decreasing")


# ----------------------------
# Risk objects
# ----------------------------

@dataclass(frozen=True)
class Control:
    """
    Security/Process control that reduces likelihood and/or impact.

    effectiveness is in [0.0..1.0] where 0=no effect, 1=perfect control.
    coverage is in [0.0..1.0] how much of the risk surface it applies to.
    maturity is in [0.0..1.0] quality/operationalization of the control.
    """
    id: str
    name: str
    control_type: ControlType
    effectiveness: float
    coverage: float = 1.0
    maturity: float = 1.0
    affects_likelihood: bool = True
    affects_impact: bool = False
    notes: str = ""

    def validate(self) -> None:
        _validate_id(self.id, "control.id")
        _validate_nonempty(self.name, "control.name")
        _validate_unit_float(self.effectiveness, "control.effectiveness")
        _validate_unit_float(self.coverage, "control.coverage")
        _validate_unit_float(self.maturity, "control.maturity")


@dataclass(frozen=True)
class RiskFactors:
    """
    Optional structured factors for more detailed scoring.

    If provided, the system computes a weighted mean and then maps it to 1..5.
    Values are expected in [0..1] per factor (normalized).
    """
    likelihood: Optional[Mapping[str, float]] = None
    impact: Optional[Mapping[str, float]] = None

    def validate(self) -> None:
        if self.likelihood is not None:
            _validate_unit_map(self.likelihood, "factors.likelihood")
        if self.impact is not None:
            _validate_unit_map(self.impact, "factors.impact")


@dataclass(frozen=True)
class Risk:
    """
    A single risk entry in the register.

    You can specify:
    - categorical bands (LikelihoodBand/ImpactBand), or
    - normalized multi-dimensional factors with optional weights in RiskScaleConfig.

    If both are provided, factors take precedence because they are more granular.
    """
    id: str
    title: str
    description: str
    owner: str

    likelihood_band: Optional[LikelihoodBand] = None
    impact_band: Optional[ImpactBand] = None
    factors: Optional[RiskFactors] = None

    controls: Tuple[Control, ...] = ()
    tags: Tuple[str, ...] = ()
    created_at_unix: float = field(default_factory=lambda: time.time())

    def validate(self, scale: RiskScaleConfig) -> None:
        _validate_id(self.id, "risk.id")
        _validate_nonempty(self.title, "risk.title")
        _validate_nonempty(self.description, "risk.description")
        _validate_nonempty(self.owner, "risk.owner")
        scale.validate()

        if self.factors is not None:
            self.factors.validate()
        else:
            if self.likelihood_band is None or self.impact_band is None:
                raise ValueError("risk must have either factors or both likelihood_band and impact_band")

        for c in self.controls:
            c.validate()

        for t in self.tags:
            if not isinstance(t, str) or not t.strip():
                raise ValueError("risk.tags must be non-empty strings")


@dataclass(frozen=True)
class RiskScore:
    likelihood: int  # 1..5
    impact: int      # 1..5
    score: int       # 1..25
    level: RiskLevel
    treatment: RiskTreatment


@dataclass(frozen=True)
class RiskAssessment:
    """
    Computed view of a risk, including inherent and residual scoring.
    """
    risk: Risk
    inherent: RiskScore
    residual: RiskScore
    controls_effect_summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk": _risk_to_dict(self.risk),
            "inherent": dataclasses.asdict(self.inherent),
            "residual": dataclasses.asdict(self.residual),
            "controls_effect_summary": self.controls_effect_summary,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)


# ----------------------------
# Public API
# ----------------------------

def assess_risk(
    risk: Risk,
    *,
    scale: Optional[RiskScaleConfig] = None,
    appetite: Optional[RiskAppetite] = None,
) -> RiskAssessment:
    scale = scale or RiskScaleConfig()
    appetite = appetite or RiskAppetite()
    scale.validate()
    appetite.validate()
    risk.validate(scale)

    inherent_l, inherent_i = _compute_base_li(risk, scale)
    inherent = _score(inherent_l, inherent_i, appetite)

    residual_l, residual_i, summary = _apply_controls(inherent_l, inherent_i, risk.controls)
    residual = _score(residual_l, residual_i, appetite)

    return RiskAssessment(
        risk=risk,
        inherent=inherent,
        residual=residual,
        controls_effect_summary=summary,
    )


def build_matrix(
    *,
    appetite: Optional[RiskAppetite] = None,
) -> List[List[RiskLevel]]:
    """
    Returns a 5x5 matrix where rows=likelihood (1..5), cols=impact (1..5).
    Cell value is RiskLevel.
    """
    appetite = appetite or RiskAppetite()
    appetite.validate()
    matrix: List[List[RiskLevel]] = []
    for l in range(1, 6):
        row: List[RiskLevel] = []
        for i in range(1, 6):
            row.append(_level(l * i, appetite))
        matrix.append(row)
    return matrix


def render_matrix_text(
    *,
    appetite: Optional[RiskAppetite] = None,
) -> str:
    appetite = appetite or RiskAppetite()
    m = build_matrix(appetite=appetite)
    # Header impact 1..5
    lines: List[str] = []
    lines.append("Risk Matrix 5x5 (rows=likelihood 1..5, cols=impact 1..5)")
    lines.append("      I1   I2   I3   I4   I5")
    for idx, row in enumerate(m, start=1):
        cells = " ".join(_lvl_abbr(x).rjust(4) for x in row)
        lines.append(f"L{idx} {cells}")
    return "\n".join(lines)


# ----------------------------
# Scoring internals
# ----------------------------

def _compute_base_li(risk: Risk, scale: RiskScaleConfig) -> Tuple[int, int]:
    if risk.factors is not None:
        l = _factors_to_band_score(risk.factors.likelihood, scale.likelihood_weights, "likelihood")
        i = _factors_to_band_score(risk.factors.impact, scale.impact_weights, "impact")
        return l, i

    assert risk.likelihood_band is not None and risk.impact_band is not None
    try:
        l = int(scale.likelihood_map[risk.likelihood_band])
    except KeyError as e:
        raise ValueError(f"likelihood_band not mapped: {risk.likelihood_band}") from e
    try:
        i = int(scale.impact_map[risk.impact_band])
    except KeyError as e:
        raise ValueError(f"impact_band not mapped: {risk.impact_band}") from e

    _validate_score_1_5(l, "likelihood_score")
    _validate_score_1_5(i, "impact_score")
    return l, i


def _apply_controls(
    base_l: int,
    base_i: int,
    controls: Sequence[Control],
) -> Tuple[int, int, Dict[str, Any]]:
    """
    Apply controls to compute residual likelihood/impact.

    Model:
    - Effective reduction factor = effectiveness * coverage * maturity
    - For likelihood controls: l' = l * (1 - k_l) aggregated as 1 - Π(1 - k_i)
    - For impact controls:    i' = i * (1 - k_i) aggregated similarly
    - Scores are clamped to [1..5] and rounded to nearest integer with deterministic ties.
    """
    if not controls:
        return base_l, base_i, {"controls": 0, "likelihood_reduction": 0.0, "impact_reduction": 0.0}

    k_l_parts: List[float] = []
    k_i_parts: List[float] = []

    for c in controls:
        c.validate()
        k = _clamp01(c.effectiveness * c.coverage * c.maturity)
        if c.affects_likelihood:
            k_l_parts.append(k)
        if c.affects_impact:
            k_i_parts.append(k)

    agg_l = _aggregate_reduction(k_l_parts)
    agg_i = _aggregate_reduction(k_i_parts)

    new_l = _round_score(base_l * (1.0 - agg_l))
    new_i = _round_score(base_i * (1.0 - agg_i))

    new_l = _clamp_int(new_l, 1, 5)
    new_i = _clamp_int(new_i, 1, 5)

    return new_l, new_i, {
        "controls": len(controls),
        "likelihood_reduction": agg_l,
        "impact_reduction": agg_i,
        "base": {"likelihood": base_l, "impact": base_i},
        "residual": {"likelihood": new_l, "impact": new_i},
    }


def _aggregate_reduction(parts: Sequence[float]) -> float:
    if not parts:
        return 0.0
    # 1 - Π(1 - k_i)
    prod = 1.0
    for k in parts:
        prod *= (1.0 - _clamp01(k))
    return _clamp01(1.0 - prod)


def _score(likelihood: int, impact: int, appetite: RiskAppetite) -> RiskScore:
    _validate_score_1_5(likelihood, "likelihood")
    _validate_score_1_5(impact, "impact")
    s = likelihood * impact
    lvl = _level(s, appetite)
    tr = _treatment(lvl, appetite)
    return RiskScore(likelihood=likelihood, impact=impact, score=s, level=lvl, treatment=tr)


def _level(score: int, appetite: RiskAppetite) -> RiskLevel:
    if score <= appetite.low_max:
        return RiskLevel.LOW
    if score <= appetite.medium_max:
        return RiskLevel.MEDIUM
    if score <= appetite.high_max:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def _treatment(level: RiskLevel, appetite: RiskAppetite) -> RiskTreatment:
    if level == RiskLevel.LOW:
        return appetite.treat_low
    if level == RiskLevel.MEDIUM:
        return appetite.treat_medium
    if level == RiskLevel.HIGH:
        return appetite.treat_high
    return appetite.treat_critical


def _lvl_abbr(level: RiskLevel) -> str:
    return {
        RiskLevel.LOW: "LOW",
        RiskLevel.MEDIUM: "MED",
        RiskLevel.HIGH: "HIGH",
        RiskLevel.CRITICAL: "CRIT",
    }[level]


def _factors_to_band_score(
    factors: Optional[Mapping[str, float]],
    weights: Optional[Mapping[str, float]],
    name: str,
) -> int:
    """
    Convert normalized factor map [0..1] to a band score 1..5.
    Uses weighted mean if weights are provided; otherwise simple mean.
    """
    if not factors:
        raise ValueError(f"{name} factors missing")

    _validate_unit_map(factors, f"{name}_factors")

    if weights is not None:
        _validate_weights(weights, f"{name}_weights")
        common = [k for k in factors.keys() if k in weights]
        if not common:
            raise ValueError(f"{name}: no overlap between factors and weights keys")
        num = 0.0
        den = 0.0
        for k in common:
            w = float(weights[k])
            num += float(factors[k]) * w
            den += w
        mean = num / den if den > 0 else 0.0
    else:
        mean = sum(float(v) for v in factors.values()) / float(len(factors))

    mean = _clamp01(mean)
    # Map [0..1] -> 1..5 using bins:
    # [0..0.2)=1, [0.2..0.4)=2, [0.4..0.6)=3, [0.6..0.8)=4, [0.8..1]=5
    if mean < 0.2:
        return 1
    if mean < 0.4:
        return 2
    if mean < 0.6:
        return 3
    if mean < 0.8:
        return 4
    return 5


def _round_score(x: float) -> int:
    """
    Deterministic rounding:
    - standard rounding to nearest int
    - ties (0.5) are rounded up
    """
    if x <= 1.0:
        return 1
    if x >= 5.0:
        return 5
    frac, whole = math.modf(x)
    whole_i = int(whole)
    if frac > 0.5:
        return whole_i + 1
    if frac < 0.5:
        return whole_i
    return whole_i + 1


# ----------------------------
# Serialization helpers
# ----------------------------

def _risk_to_dict(risk: Risk) -> Dict[str, Any]:
    return {
        "id": risk.id,
        "title": risk.title,
        "description": risk.description,
        "owner": risk.owner,
        "likelihood_band": risk.likelihood_band.value if risk.likelihood_band else None,
        "impact_band": risk.impact_band.value if risk.impact_band else None,
        "factors": {
            "likelihood": dict(risk.factors.likelihood) if (risk.factors and risk.factors.likelihood) else None,
            "impact": dict(risk.factors.impact) if (risk.factors and risk.factors.impact) else None,
        } if risk.factors else None,
        "controls": [dataclasses.asdict(c) for c in risk.controls],
        "tags": list(risk.tags),
        "created_at_unix": risk.created_at_unix,
    }


# ----------------------------
# Validation utilities
# ----------------------------

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{2,127}$")


def _validate_id(value: str, field_name: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be str")
    if not _ID_RE.fullmatch(value):
        raise ValueError(f"{field_name} must match {_ID_RE.pattern}")


def _validate_nonempty(value: str, field_name: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be str")
    if not value.strip():
        raise ValueError(f"{field_name} must be non-empty")


def _validate_unit_float(value: float, field_name: str) -> None:
    if not isinstance(value, (int, float)):
        raise TypeError(f"{field_name} must be float")
    v = float(value)
    if v < 0.0 or v > 1.0:
        raise ValueError(f"{field_name} must be within 0..1")


def _validate_unit_map(m: Mapping[str, float], field_name: str) -> None:
    if not isinstance(m, Mapping):
        raise TypeError(f"{field_name} must be a mapping")
    if not m:
        raise ValueError(f"{field_name} must not be empty")
    for k, v in m.items():
        if not isinstance(k, str) or not k.strip():
            raise ValueError(f"{field_name}: keys must be non-empty strings")
        _validate_unit_float(float(v), f"{field_name}[{k}]")


def _validate_weights(w: Mapping[str, float], field_name: str) -> None:
    if not isinstance(w, Mapping):
        raise TypeError(f"{field_name} must be a mapping")
    if not w:
        raise ValueError(f"{field_name} must not be empty")
    total = 0.0
    for k, v in w.items():
        if not isinstance(k, str) or not k.strip():
            raise ValueError(f"{field_name}: keys must be non-empty strings")
        if not isinstance(v, (int, float)):
            raise TypeError(f"{field_name}[{k}] must be float")
        fv = float(v)
        if fv <= 0.0:
            raise ValueError(f"{field_name}[{k}] must be > 0")
        total += fv
    if total <= 0.0:
        raise ValueError(f"{field_name}: sum of weights must be > 0")


def _validate_band_map(m: Mapping[Enum, int], field_name: str) -> None:
    if not isinstance(m, Mapping):
        raise TypeError(f"{field_name} must be a mapping")
    if not m:
        raise ValueError(f"{field_name} must not be empty")
    for k, v in m.items():
        if not isinstance(v, int):
            raise TypeError(f"{field_name}[{k}] must be int")
        _validate_score_1_5(v, f"{field_name}[{k}]")


def _validate_score_1_5(v: int, field_name: str) -> None:
    if not isinstance(v, int):
        raise TypeError(f"{field_name} must be int")
    if v < 1 or v > 5:
        raise ValueError(f"{field_name} must be within 1..5")


def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return float(x)


def _clamp_int(x: int, lo: int, hi: int) -> int:
    if x < lo:
        return lo
    if x > hi:
        return hi
    return x
