# agent_mash/intel/health_analysis/partial.py
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HealthState(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class ActionType(str, Enum):
    OBSERVE = "observe"
    RETRY = "retry"
    ROLLBACK = "rollback"
    THROTTLE = "throttle"
    SCALE = "scale"
    RESTART = "restart"
    INVESTIGATE = "investigate"
    ESCALATE = "escalate"
    BLOCK = "block"


@dataclass(frozen=True)
class Finding:
    key: str
    title: str
    severity: Severity
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    affected_components: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Recommendation:
    action: ActionType
    severity: Severity
    title: str
    rationale: str
    target: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    requires_approval: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RiskAssessment:
    overall_severity: Severity
    risk_score: int
    state: HealthState
    summary: str
    findings: List[Finding]
    recommendations: List[Recommendation]
    signals: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_severity": self.overall_severity.value,
            "risk_score": self.risk_score,
            "state": self.state.value,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "recommendations": [r.to_dict() for r in self.recommendations],
            "signals": self.signals,
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class PartialAnalysisConfig:
    degraded_ratio_warn: float = 0.10
    degraded_ratio_high: float = 0.25

    unhealthy_ratio_warn: float = 0.02
    unhealthy_ratio_high: float = 0.08

    error_rate_warn: float = 0.01
    error_rate_high: float = 0.03

    latency_p95_warn_ms: int = 600
    latency_p95_high_ms: int = 1200

    saturation_warn: float = 0.75
    saturation_high: float = 0.90

    stale_heartbeat_warn_s: int = 60
    stale_heartbeat_high_s: int = 180

    risk_score_cap: int = 100

    # If an action can cause mutation, we require approval by default.
    require_approval_by_default: bool = True


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_float(x: Any) -> Optional[float]:
    try:
        if x is None:
            return None
        return float(x)
    except Exception:
        return None


def _safe_int(x: Any) -> Optional[int]:
    try:
        if x is None:
            return None
        return int(x)
    except Exception:
        return None


def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


def _severity_from_score(score: int) -> Severity:
    if score >= 90:
        return Severity.CRITICAL
    if score >= 70:
        return Severity.HIGH
    if score >= 45:
        return Severity.MEDIUM
    if score >= 20:
        return Severity.LOW
    return Severity.INFO


def _validate_snapshot(snapshot: Mapping[str, Any]) -> Tuple[bool, str]:
    if not isinstance(snapshot, Mapping):
        return False, "snapshot must be a mapping"
    # Minimal expected fields; everything else is optional signals.
    # We keep this tolerant to avoid breaking producers.
    required_any = ["components", "summary", "timestamp"]
    missing = [k for k in required_any if k not in snapshot]
    if missing:
        return False, f"snapshot missing required keys: {missing}"
    if not isinstance(snapshot.get("components"), (list, tuple)):
        return False, "snapshot.components must be a list"
    if not isinstance(snapshot.get("summary"), Mapping):
        return False, "snapshot.summary must be a mapping"
    return True, "ok"


def _component_state(comp: Mapping[str, Any]) -> HealthState:
    raw = str(comp.get("state", HealthState.UNKNOWN.value)).lower().strip()
    if raw in (HealthState.HEALTHY.value, HealthState.DEGRADED.value, HealthState.UNHEALTHY.value, HealthState.UNKNOWN.value):
        return HealthState(raw)
    return HealthState.UNKNOWN


def _extract_ratios(snapshot: Mapping[str, Any]) -> Dict[str, float]:
    components = snapshot.get("components", [])
    total = len(components) if isinstance(components, (list, tuple)) else 0
    if total <= 0:
        return {"total": 0.0, "healthy_ratio": 0.0, "degraded_ratio": 0.0, "unhealthy_ratio": 0.0, "unknown_ratio": 0.0}

    counts = {
        HealthState.HEALTHY: 0,
        HealthState.DEGRADED: 0,
        HealthState.UNHEALTHY: 0,
        HealthState.UNKNOWN: 0,
    }
    for c in components:
        if not isinstance(c, Mapping):
            counts[HealthState.UNKNOWN] += 1
            continue
        counts[_component_state(c)] += 1

    return {
        "total": float(total),
        "healthy_ratio": counts[HealthState.HEALTHY] / float(total),
        "degraded_ratio": counts[HealthState.DEGRADED] / float(total),
        "unhealthy_ratio": counts[HealthState.UNHEALTHY] / float(total),
        "unknown_ratio": counts[HealthState.UNKNOWN] / float(total),
    }


def _signal(snapshot: Mapping[str, Any], path: Iterable[str]) -> Any:
    cur: Any = snapshot
    for k in path:
        if not isinstance(cur, Mapping):
            return None
        cur = cur.get(k)
    return cur


def _ms(x: Any) -> Optional[int]:
    v = _safe_float(x)
    if v is None:
        return None
    # if producer gives seconds, they should standardize; we keep raw numeric as ms only if plausible.
    return int(round(v))


def analyze_partial(snapshot: Mapping[str, Any], *, config: Optional[PartialAnalysisConfig] = None) -> RiskAssessment:
    """
    Analyze a snapshot for "partially healthy" conditions.
    This is a read-only intelligence function: it produces risk assessment and recommendations.
    """
    cfg = config or PartialAnalysisConfig()
    ok, msg = _validate_snapshot(snapshot)
    if not ok:
        f = Finding(
            key="snapshot.invalid",
            title="Invalid health snapshot",
            severity=Severity.HIGH,
            description=msg,
            evidence={"received_type": str(type(snapshot))},
            affected_components=[],
        )
        rec = Recommendation(
            action=ActionType.BLOCK,
            severity=Severity.HIGH,
            title="Block automated actions",
            rationale="Snapshot validation failed; any automated decision would be unsafe.",
            target=None,
            parameters={"reason": msg},
            requires_approval=True,
        )
        return RiskAssessment(
            overall_severity=Severity.HIGH,
            risk_score=75,
            state=HealthState.UNKNOWN,
            summary="Invalid snapshot; analysis blocked.",
            findings=[f],
            recommendations=[rec],
            signals={"validation": {"ok": False, "message": msg}},
        )

    ratios = _extract_ratios(snapshot)
    total = int(ratios["total"]) if ratios["total"] else 0

    # Optional signals commonly emitted by monitoring:
    error_rate = _safe_float(_signal(snapshot, ["summary", "error_rate"]))  # 0..1
    latency_p95_ms = _safe_int(_signal(snapshot, ["summary", "latency_p95_ms"]))
    saturation = _safe_float(_signal(snapshot, ["summary", "saturation"]))  # 0..1
    stale_heartbeat_s = _safe_int(_signal(snapshot, ["summary", "stale_heartbeat_s"]))

    # Normalize missing values:
    er = _clamp01(error_rate) if error_rate is not None else None
    sat = _clamp01(saturation) if saturation is not None else None

    findings: List[Finding] = []
    recs: List[Recommendation] = []
    score = 0
    signals: Dict[str, Any] = {
        "ratios": ratios,
        "summary_signals": {
            "error_rate": er,
            "latency_p95_ms": latency_p95_ms,
            "saturation": sat,
            "stale_heartbeat_s": stale_heartbeat_s,
        },
        "timestamp": snapshot.get("timestamp"),
        "analyzed_at": _now_iso(),
    }

    # Component-level evidence
    degraded_components: List[str] = []
    unhealthy_components: List[str] = []
    unknown_components: List[str] = []
    components = snapshot.get("components", [])
    if isinstance(components, (list, tuple)):
        for c in components:
            if not isinstance(c, Mapping):
                unknown_components.append("unknown_component")
                continue
            name = str(c.get("name", "unknown")).strip() or "unknown"
            st = _component_state(c)
            if st == HealthState.DEGRADED:
                degraded_components.append(name)
            elif st == HealthState.UNHEALTHY:
                unhealthy_components.append(name)
            elif st == HealthState.UNKNOWN:
                unknown_components.append(name)

    # Ratio-based scoring and findings
    degraded_ratio = ratios["degraded_ratio"]
    unhealthy_ratio = ratios["unhealthy_ratio"]
    unknown_ratio = ratios["unknown_ratio"]

    if total == 0:
        findings.append(
            Finding(
                key="components.empty",
                title="No component data",
                severity=Severity.HIGH,
                description="Snapshot contains zero components; cannot establish partial health reliably.",
                evidence={"components_count": 0},
                affected_components=[],
            )
        )
        recs.append(
            Recommendation(
                action=ActionType.INVESTIGATE,
                severity=Severity.HIGH,
                title="Investigate health data pipeline",
                rationale="No components were reported; monitoring ingestion or registry may be broken.",
                parameters={"focus": ["registry", "monitoring", "exporters"]},
                requires_approval=False,
            )
        )
        score += 70

    # Degraded ratio thresholds
    if degraded_ratio >= cfg.degraded_ratio_high:
        score += 25
        findings.append(
            Finding(
                key="health.degraded_ratio.high",
                title="High degraded component ratio",
                severity=Severity.HIGH,
                description="A high share of components is degraded, indicating systemic stress or partial outage.",
                evidence={"degraded_ratio": degraded_ratio, "threshold": cfg.degraded_ratio_high, "count": len(degraded_components)},
                affected_components=degraded_components[:200],
            )
        )
        recs.append(
            Recommendation(
                action=ActionType.ESCALATE,
                severity=Severity.HIGH,
                title="Escalate to COO/PMO for mitigation",
                rationale="High degraded ratio increases delivery risk; PMO should re-plan and reduce blast radius.",
                target="coo.pmo",
                parameters={"degraded_components": degraded_components[:200]},
                requires_approval=cfg.require_approval_by_default,
            )
        )
        recs.append(
            Recommendation(
                action=ActionType.THROTTLE,
                severity=Severity.MEDIUM,
                title="Throttle non-critical workloads",
                rationale="Reducing load can restore degraded components without disruptive actions.",
                target="platform_ops",
                parameters={"mode": "non_critical_only"},
                requires_approval=cfg.require_approval_by_default,
            )
        )
    elif degraded_ratio >= cfg.degraded_ratio_warn:
        score += 12
        findings.append(
            Finding(
                key="health.degraded_ratio.warn",
                title="Elevated degraded component ratio",
                severity=Severity.MEDIUM,
                description="Some components are degraded; monitoring and prioritization are required.",
                evidence={"degraded_ratio": degraded_ratio, "threshold": cfg.degraded_ratio_warn, "count": len(degraded_components)},
                affected_components=degraded_components[:200],
            )
        )
        recs.append(
            Recommendation(
                action=ActionType.OBSERVE,
                severity=Severity.MEDIUM,
                title="Increase monitoring and tighten sprint scope",
                rationale="Partial degradation should trigger tighter scope control and enhanced observation.",
                target="coo.pmo",
                parameters={"watch": ["latency", "errors", "saturation"], "window_minutes": 30},
                requires_approval=False,
            )
        )

    # Unhealthy ratio thresholds
    if unhealthy_ratio >= cfg.unhealthy_ratio_high:
        score += 35
        findings.append(
            Finding(
                key="health.unhealthy_ratio.high",
                title="High unhealthy component ratio",
                severity=Severity.CRITICAL,
                description="A significant share of components is unhealthy, indicating a partial outage.",
                evidence={"unhealthy_ratio": unhealthy_ratio, "threshold": cfg.unhealthy_ratio_high, "count": len(unhealthy_components)},
                affected_components=unhealthy_components[:200],
            )
        )
        recs.append(
            Recommendation(
                action=ActionType.ESCALATE,
                severity=Severity.CRITICAL,
                title="Trigger incident escalation",
                rationale="High unhealthy ratio requires incident process and explicit approvals for recovery actions.",
                target="resilience.incident",
                parameters={"unhealthy_components": unhealthy_components[:200]},
                requires_approval=True,
            )
        )
        recs.append(
            Recommendation(
                action=ActionType.INVESTIGATE,
                severity=Severity.HIGH,
                title="Run detailed inspection",
                rationale="Identify root cause before any restart/rollback actions.",
                target="monitoring.inspection",
                parameters={"components": unhealthy_components[:200]},
                requires_approval=False,
            )
        )
    elif unhealthy_ratio >= cfg.unhealthy_ratio_warn:
        score += 18
        findings.append(
            Finding(
                key="health.unhealthy_ratio.warn",
                title="Non-trivial unhealthy component ratio",
                severity=Severity.HIGH,
                description="Some components are unhealthy; this can impact user experience and deadlines.",
                evidence={"unhealthy_ratio": unhealthy_ratio, "threshold": cfg.unhealthy_ratio_warn, "count": len(unhealthy_components)},
                affected_components=unhealthy_components[:200],
            )
        )
        recs.append(
            Recommendation(
                action=ActionType.INVESTIGATE,
                severity=Severity.HIGH,
                title="Investigate unhealthy components",
                rationale="Unhealthy components should be triaged quickly to prevent cascade failures.",
                target="monitoring.inspection",
                parameters={"components": unhealthy_components[:200]},
                requires_approval=False,
            )
        )

    # Unknown ratio as data quality risk
    if unknown_ratio >= 0.20 and total > 0:
        score += 10
        findings.append(
            Finding(
                key="health.unknown_ratio.high",
                title="High unknown state ratio",
                severity=Severity.MEDIUM,
                description="Many components report unknown state; health visibility is degraded.",
                evidence={"unknown_ratio": unknown_ratio, "count": len(unknown_components)},
                affected_components=unknown_components[:200],
            )
        )
        recs.append(
            Recommendation(
                action=ActionType.INVESTIGATE,
                severity=Severity.MEDIUM,
                title="Validate telemetry and registry mappings",
                rationale="Unknown states often come from missing telemetry, mismatched names, or exporter failures.",
                target="monitoring.metrics",
                parameters={"suspects": ["exporters", "registry", "name_mapping"]},
                requires_approval=False,
            )
        )

    # Error rate signal scoring
    if er is not None:
        if er >= cfg.error_rate_high:
            score += 20
            findings.append(
                Finding(
                    key="summary.error_rate.high",
                    title="High error rate",
                    severity=Severity.HIGH,
                    description="Error rate exceeds the high threshold; indicates reliability degradation.",
                    evidence={"error_rate": er, "threshold": cfg.error_rate_high},
                    affected_components=unhealthy_components[:200] or degraded_components[:200],
                )
            )
            recs.append(
                Recommendation(
                    action=ActionType.THROTTLE,
                    severity=Severity.HIGH,
                    title="Throttle or shed load",
                    rationale="High error rates can often be reduced by lowering load until stabilization.",
                    target="platform_ops",
                    parameters={"strategy": "load_shed", "max_drop_ratio": 0.15},
                    requires_approval=cfg.require_approval_by_default,
                )
            )
        elif er >= cfg.error_rate_warn:
            score += 10
            findings.append(
                Finding(
                    key="summary.error_rate.warn",
                    title="Elevated error rate",
                    severity=Severity.MEDIUM,
                    description="Error rate is elevated; monitor and prepare mitigation.",
                    evidence={"error_rate": er, "threshold": cfg.error_rate_warn},
                    affected_components=degraded_components[:200],
                )
            )

    # Latency p95 signal scoring
    if latency_p95_ms is not None:
        if latency_p95_ms >= cfg.latency_p95_high_ms:
            score += 20
            findings.append(
                Finding(
                    key="summary.latency_p95.high",
                    title="High p95 latency",
                    severity=Severity.HIGH,
                    description="High p95 latency can indicate saturation, downstream slowness, or queue buildup.",
                    evidence={"latency_p95_ms": latency_p95_ms, "threshold": cfg.latency_p95_high_ms},
                    affected_components=degraded_components[:200] or unhealthy_components[:200],
                )
            )
            recs.append(
                Recommendation(
                    action=ActionType.SCALE,
                    severity=Severity.MEDIUM,
                    title="Consider scaling critical services",
                    rationale="Scaling can reduce latency if bottleneck is resource saturation.",
                    target="platform_ops",
                    parameters={"scope": "critical_services_only"},
                    requires_approval=cfg.require_approval_by_default,
                )
            )
        elif latency_p95_ms >= cfg.latency_p95_warn_ms:
            score += 10
            findings.append(
                Finding(
                    key="summary.latency_p95.warn",
                    title="Elevated p95 latency",
                    severity=Severity.MEDIUM,
                    description="Latency is elevated; monitor saturation and downstream dependencies.",
                    evidence={"latency_p95_ms": latency_p95_ms, "threshold": cfg.latency_p95_warn_ms},
                    affected_components=degraded_components[:200],
                )
            )

    # Saturation scoring
    if sat is not None:
        if sat >= cfg.saturation_high:
            score += 20
            findings.append(
                Finding(
                    key="summary.saturation.high",
                    title="High saturation",
                    severity=Severity.HIGH,
                    description="Saturation is high; capacity is near limits, increasing risk of timeouts and errors.",
                    evidence={"saturation": sat, "threshold": cfg.saturation_high},
                    affected_components=degraded_components[:200] or unhealthy_components[:200],
                )
            )
            recs.append(
                Recommendation(
                    action=ActionType.SCALE,
                    severity=Severity.HIGH,
                    title="Scale capacity or reduce load",
                    rationale="High saturation requires capacity action or load shedding to prevent outages.",
                    target="platform_ops",
                    parameters={"priority": "urgent"},
                    requires_approval=True,
                )
            )
        elif sat >= cfg.saturation_warn:
            score += 8
            findings.append(
                Finding(
                    key="summary.saturation.warn",
                    title="Elevated saturation",
                    severity=Severity.MEDIUM,
                    description="Saturation is elevated; watch for early warning signs of cascading failures.",
                    evidence={"saturation": sat, "threshold": cfg.saturation_warn},
                    affected_components=degraded_components[:200],
                )
            )

    # Heartbeat staleness
    if stale_heartbeat_s is not None:
        if stale_heartbeat_s >= cfg.stale_heartbeat_high_s:
            score += 15
            findings.append(
                Finding(
                    key="summary.heartbeat.stale.high",
                    title="Telemetry heartbeat is stale",
                    severity=Severity.HIGH,
                    description="Telemetry appears stale; visibility and auto-decisions are unreliable.",
                    evidence={"stale_heartbeat_s": stale_heartbeat_s, "threshold": cfg.stale_heartbeat_high_s},
                    affected_components=[],
                )
            )
            recs.append(
                Recommendation(
                    action=ActionType.BLOCK,
                    severity=Severity.HIGH,
                    title="Block automated recovery actions",
                    rationale="Stale telemetry can cause incorrect remediation. Require human confirmation.",
                    target="governance",
                    parameters={"reason": "stale_telemetry"},
                    requires_approval=True,
                )
            )
        elif stale_heartbeat_s >= cfg.stale_heartbeat_warn_s:
            score += 7
            findings.append(
                Finding(
                    key="summary.heartbeat.stale.warn",
                    title="Telemetry heartbeat is somewhat stale",
                    severity=Severity.MEDIUM,
                    description="Telemetry staleness may reduce confidence in analysis; verify collectors/exporters.",
                    evidence={"stale_heartbeat_s": stale_heartbeat_s, "threshold": cfg.stale_heartbeat_warn_s},
                    affected_components=[],
                )
            )

    # Cap and finalize
    if score > cfg.risk_score_cap:
        score = cfg.risk_score_cap

    state = HealthState.DEGRADED if (degraded_ratio > 0.0 or unhealthy_ratio > 0.0) else HealthState.HEALTHY
    overall = _severity_from_score(score)

    # If there are no findings but state is degraded due to ratios rounding, keep a minimal finding.
    if not findings and state != HealthState.HEALTHY:
        findings.append(
            Finding(
                key="health.partial",
                title="Partial health degradation detected",
                severity=Severity.LOW,
                description="Minor degradation detected; continue observation.",
                evidence={"degraded_ratio": degraded_ratio, "unhealthy_ratio": unhealthy_ratio},
                affected_components=degraded_components[:50],
            )
        )

    # Ensure at least one recommendation when risk is non-trivial
    if score >= 20 and not recs:
        recs.append(
            Recommendation(
                action=ActionType.OBSERVE,
                severity=Severity.MEDIUM,
                title="Increase observation window",
                rationale="Risk score suggests non-trivial degradation; observe and prepare mitigation.",
                target="monitoring",
                parameters={"window_minutes": 30},
                requires_approval=False,
            )
        )

    summary = snapshot.get("summary", {})
    summary_text = str(summary.get("message") or "").strip()
    if not summary_text:
        summary_text = "Partial health analysis completed."

    return RiskAssessment(
        overall_severity=overall,
        risk_score=score,
        state=state,
        summary=summary_text,
        findings=findings,
        recommendations=recs,
        signals=signals,
    )


__all__ = [
    "Severity",
    "HealthState",
    "ActionType",
    "Finding",
    "Recommendation",
    "RiskAssessment",
    "PartialAnalysisConfig",
    "analyze_partial",
]
