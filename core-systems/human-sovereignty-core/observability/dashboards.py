# human-sovereignty-core/observability/dashboards.py
# Industrial-grade dashboard registry (domain-level) for Human Sovereignty Core.
# No external dependencies. Python 3.11+ recommended.

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DashboardError(RuntimeError):
    """Base error for dashboard registry."""


class DashboardValidationError(DashboardError):
    """Raised when dashboard specs are invalid."""


class PanelType(str, Enum):
    TIMESERIES = "timeseries"
    STAT = "stat"
    TABLE = "table"
    HEATMAP = "heatmap"
    TEXT = "text"


class DataSourceType(str, Enum):
    PROMETHEUS = "prometheus"
    OTEL = "otel"
    LOGS = "logs"
    INTERNAL = "internal"


@dataclass(frozen=True, slots=True)
class QuerySpec:
    """
    A query spec is intentionally generic.

    expr: query expression (PromQL / OTEL metrics / log query / internal DSL).
    legend: human-readable label.
    datasource: datasource type for routing.
    unit: unit for displaying (seconds, bytes, percent, etc).
    """

    expr: str
    legend: str = ""
    datasource: DataSourceType = DataSourceType.PROMETHEUS
    unit: str = ""

    def __post_init__(self) -> None:
        e = (self.expr or "").strip()
        if not e:
            raise DashboardValidationError("QuerySpec.expr must be non-empty")
        object.__setattr__(self, "expr", e)
        object.__setattr__(self, "legend", (self.legend or "").strip())
        if not isinstance(self.datasource, DataSourceType):
            raise TypeError("QuerySpec.datasource must be DataSourceType")
        object.__setattr__(self, "unit", (self.unit or "").strip())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "expr": self.expr,
            "legend": self.legend,
            "datasource": self.datasource.value,
            "unit": self.unit,
        }


@dataclass(frozen=True, slots=True)
class PanelSpec:
    """
    Declarative panel spec.

    id: stable panel id inside a dashboard.
    title: display title.
    panel_type: one of PanelType.
    queries: one or more QuerySpec.
    description: optional.
    tags: optional.
    """

    id: str
    title: str
    panel_type: PanelType
    queries: Tuple[QuerySpec, ...] = field(default_factory=tuple)
    description: str = ""
    tags: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        pid = (self.id or "").strip()
        if not pid:
            raise DashboardValidationError("PanelSpec.id must be non-empty")
        ttl = (self.title or "").strip()
        if not ttl:
            raise DashboardValidationError("PanelSpec.title must be non-empty")
        if not isinstance(self.panel_type, PanelType):
            raise TypeError("PanelSpec.panel_type must be PanelType")

        if not isinstance(self.queries, tuple):
            object.__setattr__(self, "queries", tuple(self.queries))

        if self.panel_type != PanelType.TEXT and len(self.queries) == 0:
            raise DashboardValidationError("Non-TEXT panel must have at least one query")

        desc = (self.description or "").strip()
        tgs = tuple(_norm_tag(x) for x in self.tags if _norm_tag(x))
        object.__setattr__(self, "id", pid)
        object.__setattr__(self, "title", ttl)
        object.__setattr__(self, "description", desc)
        object.__setattr__(self, "tags", tgs)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "type": self.panel_type.value,
            "description": self.description,
            "tags": list(self.tags),
            "queries": [q.to_dict() for q in self.queries],
        }


@dataclass(frozen=True, slots=True)
class DashboardSpec:
    """
    Dashboard spec.

    dashboard_id: stable unique id (namespace/name).
    title: display title.
    version: spec version.
    scopes: RBAC scopes required to view this dashboard.
    tags: for filtering in UI.
    panels: ordered panels.
    """

    dashboard_id: str
    title: str
    version: int
    scopes: Tuple[str, ...] = field(default_factory=tuple)
    tags: Tuple[str, ...] = field(default_factory=tuple)
    panels: Tuple[PanelSpec, ...] = field(default_factory=tuple)
    description: str = ""

    def __post_init__(self) -> None:
        did = (self.dashboard_id or "").strip()
        if not did or "/" not in did:
            raise DashboardValidationError("DashboardSpec.dashboard_id must be non-empty and contain '/'")
        ttl = (self.title or "").strip()
        if not ttl:
            raise DashboardValidationError("DashboardSpec.title must be non-empty")
        if not isinstance(self.version, int) or self.version <= 0:
            raise DashboardValidationError("DashboardSpec.version must be positive int")

        if not isinstance(self.panels, tuple):
            object.__setattr__(self, "panels", tuple(self.panels))

        # validate unique panel ids
        seen = set()
        for p in self.panels:
            if not isinstance(p, PanelSpec):
                raise DashboardValidationError("panels must contain PanelSpec")
            if p.id in seen:
                raise DashboardValidationError(f"duplicate panel id: {p.id}")
            seen.add(p.id)

        sc = tuple(_norm_scope(s) for s in self.scopes if _norm_scope(s))
        tg = tuple(_norm_tag(t) for t in self.tags if _norm_tag(t))
        desc = (self.description or "").strip()

        object.__setattr__(self, "dashboard_id", did)
        object.__setattr__(self, "title", ttl)
        object.__setattr__(self, "scopes", sc)
        object.__setattr__(self, "tags", tg)
        object.__setattr__(self, "description", desc)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dashboard_id": self.dashboard_id,
            "title": self.title,
            "version": self.version,
            "description": self.description,
            "scopes": list(self.scopes),
            "tags": list(self.tags),
            "generated_at": _utc_now().isoformat(),
            "panels": [p.to_dict() for p in self.panels],
        }


def _norm_scope(s: Any) -> str:
    if s is None:
        return ""
    v = str(s).strip()
    if not v:
        return ""
    # Keep it strict but non-prescriptive: "observability:read", "approval:read", etc.
    return v


def _norm_tag(t: Any) -> str:
    if t is None:
        return ""
    v = str(t).strip().lower()
    if not v:
        return ""
    return v


@dataclass(slots=True)
class DashboardRegistry:
    """
    Registry for dashboard specs.

    Responsibilities:
      - register immutable dashboard specs
      - validate uniqueness and schema
      - provide query/filter access
      - export for WebUI or adapters (Grafana/JSON/etc)
    """

    _specs: Dict[str, DashboardSpec] = field(default_factory=dict, init=False)

    def register(self, spec: DashboardSpec) -> None:
        if not isinstance(spec, DashboardSpec):
            raise DashboardValidationError("spec must be DashboardSpec")
        did = spec.dashboard_id
        if did in self._specs:
            # Prevent silent overrides in governance-critical system.
            raise DashboardValidationError(f"dashboard already registered: {did}")
        self._specs[did] = spec

    def get(self, dashboard_id: str) -> DashboardSpec:
        did = (dashboard_id or "").strip()
        if not did:
            raise DashboardValidationError("dashboard_id must be non-empty")
        spec = self._specs.get(did)
        if spec is None:
            raise DashboardValidationError(f"dashboard not found: {did}")
        return spec

    def list_ids(self) -> Tuple[str, ...]:
        return tuple(sorted(self._specs.keys()))

    def filter(
        self,
        *,
        tag: Optional[str] = None,
        scope: Optional[str] = None,
        prefix: Optional[str] = None,
    ) -> Tuple[DashboardSpec, ...]:
        t = _norm_tag(tag) if tag else ""
        s = _norm_scope(scope) if scope else ""
        pfx = (prefix or "").strip()

        out: list[DashboardSpec] = []
        for did, spec in self._specs.items():
            if pfx and not did.startswith(pfx):
                continue
            if t and t not in spec.tags:
                continue
            if s and s not in spec.scopes:
                continue
            out.append(spec)
        out.sort(key=lambda x: x.dashboard_id)
        return tuple(out)

    def export_all(self) -> Dict[str, Any]:
        return {
            "generated_at": _utc_now().isoformat(),
            "dashboards": [self._specs[k].to_dict() for k in sorted(self._specs.keys())],
        }


def build_default_registry() -> DashboardRegistry:
    """
    Builds the default registry for Human Sovereignty Core.
    """
    reg = DashboardRegistry()

    # Core overview
    reg.register(
        DashboardSpec(
            dashboard_id="hsc/core_overview",
            title="Human Sovereignty Core Overview",
            version=1,
            scopes=("observability:read",),
            tags=("core", "overview"),
            description="High-level SLO/SLA indicators for HSC subsystems.",
            panels=(
                PanelSpec(
                    id="req_rate",
                    title="Request rate",
                    panel_type=PanelType.TIMESERIES,
                    tags=("traffic",),
                    queries=(
                        QuerySpec(
                            expr='sum(rate(hsc_http_requests_total[5m]))',
                            legend="req/s",
                            datasource=DataSourceType.PROMETHEUS,
                            unit="req/s",
                        ),
                    ),
                ),
                PanelSpec(
                    id="error_rate",
                    title="Error rate",
                    panel_type=PanelType.TIMESERIES,
                    tags=("errors",),
                    queries=(
                        QuerySpec(
                            expr='sum(rate(hsc_http_requests_total{code=~"5.."}[5m])) / '
                                 'clamp_min(sum(rate(hsc_http_requests_total[5m])), 1)',
                            legend="5xx ratio",
                            datasource=DataSourceType.PROMETHEUS,
                            unit="ratio",
                        ),
                    ),
                ),
                PanelSpec(
                    id="p95_latency",
                    title="Latency p95",
                    panel_type=PanelType.TIMESERIES,
                    tags=("latency",),
                    queries=(
                        QuerySpec(
                            expr='histogram_quantile(0.95, sum(rate(hsc_http_request_duration_seconds_bucket[5m])) by (le))',
                            legend="p95",
                            datasource=DataSourceType.PROMETHEUS,
                            unit="s",
                        ),
                    ),
                ),
            ),
        )
    )

    # Approval flow
    reg.register(
        DashboardSpec(
            dashboard_id="hsc/approval_flow",
            title="Approvals and Governance Flow",
            version=1,
            scopes=("observability:read", "approval:read"),
            tags=("approval", "governance"),
            description="Approval pipeline health, backlog, and decision outcomes.",
            panels=(
                PanelSpec(
                    id="approvals_created",
                    title="Approvals created",
                    panel_type=PanelType.TIMESERIES,
                    tags=("approval",),
                    queries=(
                        QuerySpec(
                            expr='sum(rate(hsc_approvals_created_total[5m]))',
                            legend="created/s",
                            datasource=DataSourceType.PROMETHEUS,
                            unit="req/s",
                        ),
                    ),
                ),
                PanelSpec(
                    id="approval_state",
                    title="Approvals by state",
                    panel_type=PanelType.TIMESERIES,
                    tags=("approval",),
                    queries=(
                        QuerySpec(
                            expr='sum(hsc_approvals_in_state) by (state)',
                            legend="{{state}}",
                            datasource=DataSourceType.PROMETHEUS,
                            unit="count",
                        ),
                    ),
                ),
                PanelSpec(
                    id="approval_outcomes",
                    title="Approval outcomes",
                    panel_type=PanelType.TIMESERIES,
                    tags=("approval",),
                    queries=(
                        QuerySpec(
                            expr='sum(rate(hsc_approvals_decisions_total[5m])) by (decision)',
                            legend="{{decision}}",
                            datasource=DataSourceType.PROMETHEUS,
                            unit="req/s",
                        ),
                    ),
                ),
            ),
        )
    )

    # Risk assessment
    reg.register(
        DashboardSpec(
            dashboard_id="hsc/risk_assessment",
            title="Risk Assessment",
            version=1,
            scopes=("observability:read", "risk:read"),
            tags=("risk", "security"),
            description="Risk level distribution and mandatory verification compliance.",
            panels=(
                PanelSpec(
                    id="risk_level_dist",
                    title="Risk levels distribution",
                    panel_type=PanelType.TIMESERIES,
                    tags=("risk",),
                    queries=(
                        QuerySpec(
                            expr='sum(rate(hsc_risk_assessments_total[5m])) by (level)',
                            legend="{{level}}",
                            datasource=DataSourceType.PROMETHEUS,
                            unit="req/s",
                        ),
                    ),
                ),
                PanelSpec(
                    id="verification_failures",
                    title="Verification validation failures",
                    panel_type=PanelType.TIMESERIES,
                    tags=("risk", "verification"),
                    queries=(
                        QuerySpec(
                            expr='sum(rate(hsc_verification_validation_failures_total[5m])) by (level)',
                            legend="{{level}}",
                            datasource=DataSourceType.PROMETHEUS,
                            unit="req/s",
                        ),
                    ),
                ),
            ),
        )
    )

    # Execution limits
    reg.register(
        DashboardSpec(
            dashboard_id="hsc/execution_limits",
            title="Execution Limits and Guardrails",
            version=1,
            scopes=("observability:read", "execution:read"),
            tags=("execution", "limits"),
            description="Limit violations, throttling, and safe-mode triggers.",
            panels=(
                PanelSpec(
                    id="limit_violations",
                    title="Limit violations",
                    panel_type=PanelType.TIMESERIES,
                    tags=("limits",),
                    queries=(
                        QuerySpec(
                            expr='sum(rate(hsc_limit_violations_total[5m])) by (risk_level, limit)',
                            legend="{{risk_level}}/{{limit}}",
                            datasource=DataSourceType.PROMETHEUS,
                            unit="req/s",
                        ),
                    ),
                ),
                PanelSpec(
                    id="safe_mode_triggers",
                    title="Safe-mode triggers",
                    panel_type=PanelType.TIMESERIES,
                    tags=("safety",),
                    queries=(
                        QuerySpec(
                            expr='sum(rate(hsc_safe_mode_triggers_total[5m])) by (risk_level)',
                            legend="{{risk_level}}",
                            datasource=DataSourceType.PROMETHEUS,
                            unit="req/s",
                        ),
                    ),
                ),
                PanelSpec(
                    id="rate_budget_exhausted",
                    title="Rate budget exhausted",
                    panel_type=PanelType.TIMESERIES,
                    tags=("rate_limit",),
                    queries=(
                        QuerySpec(
                            expr='sum(rate(hsc_rate_budget_exhausted_total[5m])) by (risk_level)',
                            legend="{{risk_level}}",
                            datasource=DataSourceType.PROMETHEUS,
                            unit="req/s",
                        ),
                    ),
                ),
            ),
        )
    )

    return reg
