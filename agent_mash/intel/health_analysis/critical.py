# agent_mash/intel/health_analysis/critical.py
from __future__ import annotations

import dataclasses
import json
import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


class CriticalLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    SEVERE = "severe"


class SignalKind(str, Enum):
    METRIC = "metric"
    LOG = "log"
    TRACE = "trace"
    EVENT = "event"
    HEARTBEAT = "heartbeat"


class Comparator(str, Enum):
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    EQ = "eq"
    NEQ = "neq"


class WindowAgg(str, Enum):
    LAST = "last"
    MIN = "min"
    MAX = "max"
    MEAN = "mean"
    SUM = "sum"
    COUNT = "count"


@dataclass(frozen=True)
class Evidence:
    """
    One piece of evidence supporting a criticality decision.
    """
    key: str
    value: Any
    ts_unix: float
    source: str = ""
    meta: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        _validate_nonempty(self.key, "evidence.key")
        _validate_finite(self.ts_unix, "evidence.ts_unix")


@dataclass(frozen=True)
class HealthSignal:
    """
    Canonical health signal.

    - name: stable metric/event identifier (e.g., "http_5xx_rate", "db_conn_errors")
    - kind: metric/log/trace/event/heartbeat
    - value: numeric representation used by rules; non-numeric signals should be converted upstream.
    - ts_unix: timestamp
    - labels: dimensions (service, region, instance, tenant, etc.)
    """
    name: str
    kind: SignalKind
    value: float
    ts_unix: float
    labels: Dict[str, str] = field(default_factory=dict)
    message: str = ""

    def validate(self) -> None:
        _validate_nonempty(self.name, "signal.name")
        _validate_finite(self.value, "signal.value")
        _validate_finite(self.ts_unix, "signal.ts_unix")
        if not isinstance(self.labels, dict):
            raise TypeError("signal.labels must be dict[str,str]")
        for k, v in self.labels.items():
            _validate_nonempty(str(k), "signal.labels.key")
            _validate_nonempty(str(v), "signal.labels.value")


@dataclass(frozen=True)
class Rule:
    """
    Criticality rule.

    - weight: contribution to overall criticality score (0..1 recommended, but not enforced)
    - hard_fail: if True and rule matches, force level at least 'hard_fail_level'
    - dedupe_key: used to suppress duplicates across very similar rules/signals
    """
    id: str
    name: str
    signal_name: str
    kind: SignalKind

    comparator: Comparator
    threshold: float

    window_seconds: int = 300
    aggregation: WindowAgg = WindowAgg.LAST

    weight: float = 1.0
    hard_fail: bool = False
    hard_fail_level: CriticalLevel = CriticalLevel.HIGH

    cooldown_seconds: int = 120
    dedupe_key: str = ""

    details: str = ""

    def validate(self) -> None:
        _validate_id(self.id, "rule.id")
        _validate_nonempty(self.name, "rule.name")
        _validate_nonempty(self.signal_name, "rule.signal_name")
        _validate_finite(self.threshold, "rule.threshold")
        if self.window_seconds <= 0:
            raise ValueError("rule.window_seconds must be > 0")
        if self.cooldown_seconds < 0:
            raise ValueError("rule.cooldown_seconds must be >= 0")
        _validate_finite(self.weight, "rule.weight")
        if self.weight < 0:
            raise ValueError("rule.weight must be >= 0")


@dataclass(frozen=True)
class CriticalPolicy:
    """
    Policy thresholds mapping score -> CriticalLevel.

    Score is an internal normalized value in [0..1].
    """
    low_at: float = 0.15
    medium_at: float = 0.35
    high_at: float = 0.6
    severe_at: float = 0.85

    # Flapping suppression: require sustained criticality for some time
    sustain_seconds: int = 60

    # If no signals within freshness window, treat as unknown->medium (configurable)
    freshness_seconds: int = 600
    stale_level: CriticalLevel = CriticalLevel.MEDIUM

    def validate(self) -> None:
        for name, v in (
            ("low_at", self.low_at),
            ("medium_at", self.medium_at),
            ("high_at", self.high_at),
            ("severe_at", self.severe_at),
        ):
            _validate_unit_float(v, f"policy.{name}")
        if not (self.low_at <= self.medium_at <= self.high_at <= self.severe_at):
            raise ValueError("policy thresholds must be non-decreasing")
        if self.sustain_seconds < 0:
            raise ValueError("policy.sustain_seconds must be >= 0")
        if self.freshness_seconds <= 0:
            raise ValueError("policy.freshness_seconds must be > 0")


@dataclass(frozen=True)
class CriticalAssessment:
    """
    Output of criticality analysis.
    """
    level: CriticalLevel
    score: float  # 0..1 normalized
    confidence: float  # 0..1
    reasons: Tuple[str, ...]
    matched_rules: Tuple[str, ...]
    evidences: Tuple[Evidence, ...]
    meta: Dict[str, Any] = field(default_factory=dict)
    created_at_unix: float = field(default_factory=lambda: time.time())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level.value,
            "score": self.score,
            "confidence": self.confidence,
            "reasons": list(self.reasons),
            "matched_rules": list(self.matched_rules),
            "evidences": [dataclasses.asdict(e) for e in self.evidences],
            "meta": dict(self.meta),
            "created_at_unix": self.created_at_unix,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)


# ----------------------------
# Public API
# ----------------------------

def assess_criticality(
    signals: Sequence[HealthSignal],
    rules: Sequence[Rule],
    *,
    policy: Optional[CriticalPolicy] = None,
    now_unix: Optional[float] = None,
    last_level: Optional[CriticalLevel] = None,
    last_level_since_unix: Optional[float] = None,
) -> CriticalAssessment:
    """
    Determine criticality from raw signals and rules.

    Inputs are assumed to be already collected upstream (metrics/logs/traces).
    This function is pure (no I/O).
    """
    policy = policy or CriticalPolicy()
    policy.validate()

    now = float(now_unix) if now_unix is not None else time.time()
    _validate_finite(now, "now_unix")

    sigs = _normalize_signals(signals)
    for r in rules:
        r.validate()

    # Freshness gate
    freshness_ok = _freshness_ok(sigs, now, policy.freshness_seconds)
    if not freshness_ok:
        return CriticalAssessment(
            level=policy.stale_level,
            score=0.5,
            confidence=0.25,
            reasons=("signals_stale_or_missing",),
            matched_rules=(),
            evidences=(),
            meta={
                "freshness_seconds": policy.freshness_seconds,
                "signal_count": len(sigs),
                "now_unix": now,
            },
        )

    # Evaluate rules
    matched, evidences, score_raw, hard_floor = _evaluate_rules(sigs, rules, now)

    # Normalize score to [0..1]
    score = _clamp01(score_raw)

    # Convert to level
    level = _score_to_level(score, policy)
    if hard_floor is not None:
        level = _max_level(level, hard_floor)

    # Apply sustain logic to suppress flapping
    if policy.sustain_seconds > 0 and last_level is not None and last_level_since_unix is not None:
        _validate_finite(last_level_since_unix, "last_level_since_unix")
        level = _apply_sustain(level, last_level, last_level_since_unix, now, policy.sustain_seconds)

    confidence = _estimate_confidence(sigs, matched, evidences, policy)

    reasons = _build_reasons(level, matched, hard_floor, score, confidence)
    meta = {
        "now_unix": now,
        "signal_count": len(sigs),
        "matched_rules_count": len(matched),
        "hard_floor": hard_floor.value if hard_floor is not None else None,
        "score_raw": score_raw,
        "score": score,
        "freshness_seconds": policy.freshness_seconds,
        "sustain_seconds": policy.sustain_seconds,
        "last_level": last_level.value if last_level is not None else None,
        "last_level_since_unix": last_level_since_unix,
    }

    return CriticalAssessment(
        level=level,
        score=round(score, 6),
        confidence=round(confidence, 6),
        reasons=tuple(reasons),
        matched_rules=tuple(matched),
        evidences=tuple(evidences),
        meta=meta,
    )


# ----------------------------
# Rule evaluation
# ----------------------------

def _evaluate_rules(
    signals: Sequence[HealthSignal],
    rules: Sequence[Rule],
    now_unix: float,
) -> Tuple[List[str], List[Evidence], float, Optional[CriticalLevel]]:
    """
    Returns:
    - matched rule ids
    - evidences
    - score_raw (pre-clamp)
    - hard_floor level if any hard-fail rule matched
    """
    matched: List[str] = []
    evidences: List[Evidence] = []
    hard_floor: Optional[CriticalLevel] = None

    # Build per-signal-name windows
    by_name_kind: Dict[Tuple[str, SignalKind], List[HealthSignal]] = {}
    for s in signals:
        by_name_kind.setdefault((s.name, s.kind), []).append(s)

    # Sort per bucket by time asc for deterministic aggregations
    for k in by_name_kind.keys():
        by_name_kind[k].sort(key=lambda x: x.ts_unix)

    score_acc = 0.0
    weight_acc = 0.0

    # Dedupe: rule id or dedupe_key can be used to suppress repeats
    last_triggered_by_key: Dict[str, float] = {}

    for r in rules:
        bucket = by_name_kind.get((r.signal_name, r.kind), [])
        if not bucket:
            continue

        window = _slice_window(bucket, now_unix, r.window_seconds)
        if not window:
            continue

        agg = _aggregate(window, r.aggregation)
        ok = _compare(agg, r.comparator, r.threshold)

        # cooldown / dedupe check
        dedupe_key = (r.dedupe_key.strip() if r.dedupe_key else r.id)
        last_ts = last_triggered_by_key.get(dedupe_key)
        if ok:
            if last_ts is not None and r.cooldown_seconds > 0 and (now_unix - last_ts) < r.cooldown_seconds:
                # Suppress duplicate trigger
                continue
            last_triggered_by_key[dedupe_key] = now_unix

            matched.append(r.id)

            # Contribution: use weight with saturation
            # contribution in [0..1] derived from how far beyond threshold we are
            contribution = _contribution(agg, r.comparator, r.threshold)
            score_acc += contribution * max(0.0, r.weight)
            weight_acc += max(0.0, r.weight)

            evidences.append(
                Evidence(
                    key=f"rule:{r.id}",
                    value={
                        "signal_name": r.signal_name,
                        "kind": r.kind.value,
                        "aggregation": r.aggregation.value,
                        "window_seconds": r.window_seconds,
                        "agg_value": agg,
                        "comparator": r.comparator.value,
                        "threshold": r.threshold,
                        "contribution": contribution,
                        "weight": r.weight,
                        "hard_fail": r.hard_fail,
                        "hard_fail_level": r.hard_fail_level.value,
                    },
                    ts_unix=now_unix,
                    source="criticality_engine",
                    meta={"rule_name": r.name, "details": r.details},
                )
            )

            if r.hard_fail:
                hard_floor = r.hard_fail_level if hard_floor is None else _max_level(hard_floor, r.hard_fail_level)

    # Normalize score
    # If no matched rules, score is 0.
    if weight_acc <= 0:
        score_raw = 0.0
    else:
        # Weighted mean of contributions, then apply mild amplification for multiple independent matches
        mean = score_acc / weight_acc
        diversity_boost = _diversity_boost(len(matched))
        score_raw = _clamp01(mean * diversity_boost)

    return matched, evidences, score_raw, hard_floor


def _slice_window(bucket: Sequence[HealthSignal], now_unix: float, window_seconds: int) -> List[HealthSignal]:
    start = now_unix - float(window_seconds)
    out = [s for s in bucket if s.ts_unix >= start and s.ts_unix <= now_unix]
    return out


def _aggregate(window: Sequence[HealthSignal], agg: WindowAgg) -> float:
    vals = [float(s.value) for s in window]
    if agg == WindowAgg.LAST:
        return vals[-1]
    if agg == WindowAgg.MIN:
        return min(vals)
    if agg == WindowAgg.MAX:
        return max(vals)
    if agg == WindowAgg.MEAN:
        return sum(vals) / len(vals)
    if agg == WindowAgg.SUM:
        return sum(vals)
    if agg == WindowAgg.COUNT:
        return float(len(vals))
    raise ValueError(f"Unknown aggregation: {agg}")


def _compare(value: float, comp: Comparator, threshold: float) -> bool:
    if comp == Comparator.GT:
        return value > threshold
    if comp == Comparator.GTE:
        return value >= threshold
    if comp == Comparator.LT:
        return value < threshold
    if comp == Comparator.LTE:
        return value <= threshold
    if comp == Comparator.EQ:
        return value == threshold
    if comp == Comparator.NEQ:
        return value != threshold
    raise ValueError(f"Unknown comparator: {comp}")


def _contribution(value: float, comp: Comparator, threshold: float) -> float:
    """
    Convert (value vs threshold) into [0..1] contribution.
    This is a heuristic scoring function, deterministic and monotonic.

    - For GT/GTE: contribution grows with (value-threshold)/max(|threshold|, eps)
    - For LT/LTE: contribution grows with (threshold-value)/max(|threshold|, eps)
    - For EQ/NEQ: treat match as medium signal
    """
    eps = 1e-9
    base = max(abs(threshold), eps)
    if comp in (Comparator.GT, Comparator.GTE):
        d = max(0.0, (value - threshold) / base)
        return _clamp01(d)
    if comp in (Comparator.LT, Comparator.LTE):
        d = max(0.0, (threshold - value) / base)
        return _clamp01(d)
    if comp == Comparator.EQ:
        return 0.5
    if comp == Comparator.NEQ:
        return 0.35
    return 0.0


def _diversity_boost(matched_count: int) -> float:
    """
    Mild boost for multiple independent matches.
    - 1 -> 1.00
    - 2 -> ~1.10
    - 3 -> ~1.18
    - 4 -> ~1.24
    - 5+ -> capped ~1.30
    """
    if matched_count <= 1:
        return 1.0
    boost = 1.0 + 0.12 * math.log(1.0 + matched_count)
    return min(1.30, max(1.0, boost))


# ----------------------------
# Level mapping and stability
# ----------------------------

def _score_to_level(score: float, policy: CriticalPolicy) -> CriticalLevel:
    score = _clamp01(score)
    if score >= policy.severe_at:
        return CriticalLevel.SEVERE
    if score >= policy.high_at:
        return CriticalLevel.HIGH
    if score >= policy.medium_at:
        return CriticalLevel.MEDIUM
    if score >= policy.low_at:
        return CriticalLevel.LOW
    return CriticalLevel.NONE


def _apply_sustain(
    new_level: CriticalLevel,
    last_level: CriticalLevel,
    last_since: float,
    now: float,
    sustain_seconds: int,
) -> CriticalLevel:
    # If escalates, allow immediately.
    if _level_rank(new_level) > _level_rank(last_level):
        return new_level

    # If de-escalates, require sustain time.
    if _level_rank(new_level) < _level_rank(last_level):
        if (now - last_since) < float(sustain_seconds):
            return last_level
        return new_level

    return new_level


def _max_level(a: CriticalLevel, b: CriticalLevel) -> CriticalLevel:
    return a if _level_rank(a) >= _level_rank(b) else b


def _level_rank(lvl: CriticalLevel) -> int:
    return {
        CriticalLevel.NONE: 0,
        CriticalLevel.LOW: 1,
        CriticalLevel.MEDIUM: 2,
        CriticalLevel.HIGH: 3,
        CriticalLevel.SEVERE: 4,
    }[lvl]


# ----------------------------
# Confidence and reasons
# ----------------------------

def _estimate_confidence(
    signals: Sequence[HealthSignal],
    matched_rules: Sequence[str],
    evidences: Sequence[Evidence],
    policy: CriticalPolicy,
) -> float:
    # Deterministic heuristic:
    # - more fresh signals -> higher
    # - more matched rules -> higher
    # - more evidence -> higher
    base = 0.25
    s_count = len(signals)
    r_count = len(matched_rules)
    e_count = len(evidences)

    c = base
    c += min(0.35, 0.05 * math.log1p(s_count))
    c += min(0.30, 0.10 * math.log1p(r_count))
    c += min(0.10, 0.03 * math.log1p(e_count))
    return _clamp01(c)


def _build_reasons(
    level: CriticalLevel,
    matched_rules: Sequence[str],
    hard_floor: Optional[CriticalLevel],
    score: float,
    confidence: float,
) -> List[str]:
    reasons: List[str] = []
    reasons.append(f"level={level.value}")
    reasons.append(f"score={round(score, 6)}")
    reasons.append(f"confidence={round(confidence, 6)}")
    if hard_floor is not None:
        reasons.append(f"hard_fail_floor={hard_floor.value}")
    if matched_rules:
        reasons.append("matched_rules=" + ",".join(matched_rules))
    else:
        reasons.append("no_rules_matched")
    return reasons


# ----------------------------
# Normalization and freshness
# ----------------------------

def _normalize_signals(signals: Sequence[HealthSignal]) -> List[HealthSignal]:
    out: List[HealthSignal] = []
    for s in signals:
        s.validate()
        out.append(s)
    # Deterministic sort: ts then name then kind
    out.sort(key=lambda x: (x.ts_unix, x.name, x.kind.value))
    return out


def _freshness_ok(signals: Sequence[HealthSignal], now: float, freshness_seconds: int) -> bool:
    if not signals:
        return False
    latest = signals[-1].ts_unix
    return (now - latest) <= float(freshness_seconds)


# ----------------------------
# Validation utilities
# ----------------------------

def _validate_nonempty(s: str, name: str) -> None:
    if not isinstance(s, str):
        raise TypeError(f"{name} must be str")
    if not s.strip():
        raise ValueError(f"{name} must be non-empty")


def _validate_id(s: str, name: str) -> None:
    _validate_nonempty(s, name)
    # conservative identifier: 3..128 chars, alnum/._-
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


def _validate_unit_float(x: float, name: str) -> None:
    _validate_finite(x, name)
    fx = float(x)
    if fx < 0.0 or fx > 1.0:
        raise ValueError(f"{name} must be in 0..1")


def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return float(x)
