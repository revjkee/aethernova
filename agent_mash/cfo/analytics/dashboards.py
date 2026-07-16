# agent_mash/cfo/analytics/dashboards.py
from __future__ import annotations

import dataclasses
import datetime as dt
import json
import logging
from collections.abc import Iterable, Mapping, Sequence
from decimal import Decimal
from typing import Any, Optional, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


class DashboardError(RuntimeError):
    """Base error for CFO analytics dashboards."""


class ProviderError(DashboardError):
    """Raised when provider cannot fetch data."""


class ValidationError(DashboardError):
    """Raised when inputs or computed outputs violate invariants."""


class MetricComputationError(DashboardError):
    """Raised when a metric computation fails."""


@dataclasses.dataclass(frozen=True, slots=True)
class TimeRange:
    """
    Inclusive-exclusive time range: [start, end)
    Use timezone-aware datetimes only.
    """
    start: dt.datetime
    end: dt.datetime

    def __post_init__(self) -> None:
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise ValidationError("TimeRange datetimes must be timezone-aware")
        if self.end <= self.start:
            raise ValidationError("TimeRange.end must be greater than TimeRange.start")

    @property
    def seconds(self) -> float:
        return (self.end - self.start).total_seconds()

    @property
    def days(self) -> float:
        return self.seconds / 86400.0

    def clamp(self, min_start: dt.datetime, max_end: dt.datetime) -> "TimeRange":
        if min_start.tzinfo is None or max_end.tzinfo is None:
            raise ValidationError("clamp boundaries must be timezone-aware")
        s = max(self.start, min_start)
        e = min(self.end, max_end)
        if e <= s:
            raise ValidationError("clamp produced empty/negative range")
        return TimeRange(start=s, end=e)


@dataclasses.dataclass(frozen=True, slots=True)
class DimensionFilter:
    """
    Dimension filter for slicing analytics.
    Example dimensions: tenant_id, workspace_id, agent_id, route, model, currency.
    """
    key: str
    values: tuple[str, ...]
    mode: str = "include"  # "include" | "exclude"

    def __post_init__(self) -> None:
        if not self.key:
            raise ValidationError("DimensionFilter.key must be non-empty")
        if self.mode not in ("include", "exclude"):
            raise ValidationError("DimensionFilter.mode must be 'include' or 'exclude'")
        if not self.values:
            raise ValidationError("DimensionFilter.values must be non-empty")


@dataclasses.dataclass(frozen=True, slots=True)
class QuerySpec:
    """
    Provider query specification.
    """
    time_range: TimeRange
    dimensions: tuple[DimensionFilter, ...] = ()
    group_by: tuple[str, ...] = ()
    limit: int = 10_000

    def __post_init__(self) -> None:
        if self.limit <= 0:
            raise ValidationError("QuerySpec.limit must be > 0")


@dataclasses.dataclass(frozen=True, slots=True)
class SeriesPoint:
    ts: dt.datetime  # timezone-aware
    value: Decimal
    labels: Mapping[str, str] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.ts.tzinfo is None:
            raise ValidationError("SeriesPoint.ts must be timezone-aware")


@dataclasses.dataclass(frozen=True, slots=True)
class Series:
    """
    Named numeric time-series, optionally labeled.
    """
    name: str
    points: tuple[SeriesPoint, ...]
    unit: str = ""
    description: str = ""
    labels: Mapping[str, str] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name:
            raise ValidationError("Series.name must be non-empty")


@dataclasses.dataclass(frozen=True, slots=True)
class MetricValue:
    """
    Computed metric output: scalar + optional breakdowns.
    """
    name: str
    value: Decimal
    unit: str = ""
    description: str = ""
    breakdown: Mapping[str, Decimal] = dataclasses.field(default_factory=dict)
    metadata: Mapping[str, Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name:
            raise ValidationError("MetricValue.name must be non-empty")


@dataclasses.dataclass(frozen=True, slots=True)
class Panel:
    """
    A panel groups metrics and/or series for a given CFO dashboard section.
    """
    title: str
    metrics: tuple[MetricValue, ...] = ()
    series: tuple[Series, ...] = ()
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.title:
            raise ValidationError("Panel.title must be non-empty")


@dataclasses.dataclass(frozen=True, slots=True)
class Dashboard:
    """
    Full dashboard response.
    """
    name: str
    generated_at: dt.datetime
    time_range: TimeRange
    panels: tuple[Panel, ...]
    metadata: Mapping[str, Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name:
            raise ValidationError("Dashboard.name must be non-empty")
        if self.generated_at.tzinfo is None:
            raise ValidationError("Dashboard.generated_at must be timezone-aware")


@runtime_checkable
class MetricsProvider(Protocol):
    """
    Data provider contract.
    Implementations may fetch from DB, OLAP, Prometheus, OTEL, files, etc.
    All returned timestamps must be timezone-aware.
    """

    async def fetch_series(self, spec: QuerySpec, *, metric: str) -> Series:
        """
        Fetch a time series for a metric name.
        """
        raise NotImplementedError

    async def fetch_table(
        self,
        spec: QuerySpec,
        *,
        table: str,
        fields: Sequence[str],
    ) -> Sequence[Mapping[str, Any]]:
        """
        Fetch tabular records for breakdown KPIs.
        """
        raise NotImplementedError


class Metric(Protocol):
    """
    Metric computation contract.
    """

    @property
    def name(self) -> str: ...

    @property
    def unit(self) -> str: ...

    @property
    def description(self) -> str: ...

    async def compute(self, provider: MetricsProvider, spec: QuerySpec) -> MetricValue:
        raise NotImplementedError


def _now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _d(value: Any) -> Decimal:
    try:
        if isinstance(value, Decimal):
            return value
        if isinstance(value, (int, float, str)):
            return Decimal(str(value))
    except Exception as e:
        raise ValidationError(f"cannot convert to Decimal: {value!r}") from e
    raise ValidationError(f"unsupported decimal input type: {type(value).__name__}")


def _safe_div(n: Decimal, d: Decimal, *, default: Decimal = Decimal("0")) -> Decimal:
    if d == 0:
        return default
    return n / d


def _sum_points(points: Iterable[SeriesPoint]) -> Decimal:
    total = Decimal("0")
    for p in points:
        total += p.value
    return total


def _validate_monotonic(points: Sequence[SeriesPoint]) -> None:
    for i in range(1, len(points)):
        if points[i].ts < points[i - 1].ts:
            raise ValidationError("series points are not monotonic by ts")


class TotalRevenueMetric:
    name = "total_revenue"
    unit = "currency"
    description = "Total revenue in selected time range."

    async def compute(self, provider: MetricsProvider, spec: QuerySpec) -> MetricValue:
        try:
            series = await provider.fetch_series(spec, metric="revenue")
            _validate_monotonic(series.points)
            total = _sum_points(series.points)
            return MetricValue(
                name=self.name,
                value=total,
                unit=self.unit,
                description=self.description,
                metadata={"source_metric": "revenue", "points": len(series.points)},
            )
        except Exception as e:
            raise MetricComputationError(f"{self.name} failed: {type(e).__name__}: {e}") from e


class TotalCostMetric:
    name = "total_cost"
    unit = "currency"
    description = "Total costs in selected time range."

    async def compute(self, provider: MetricsProvider, spec: QuerySpec) -> MetricValue:
        try:
            series = await provider.fetch_series(spec, metric="cost")
            _validate_monotonic(series.points)
            total = _sum_points(series.points)
            return MetricValue(
                name=self.name,
                value=total,
                unit=self.unit,
                description=self.description,
                metadata={"source_metric": "cost", "points": len(series.points)},
            )
        except Exception as e:
            raise MetricComputationError(f"{self.name} failed: {type(e).__name__}: {e}") from e


class GrossMarginMetric:
    name = "gross_margin"
    unit = "ratio"
    description = "Gross margin (revenue - cost) / revenue."

    async def compute(self, provider: MetricsProvider, spec: QuerySpec) -> MetricValue:
        try:
            rev = await provider.fetch_series(spec, metric="revenue")
            cost = await provider.fetch_series(spec, metric="cost")
            _validate_monotonic(rev.points)
            _validate_monotonic(cost.points)
            total_rev = _sum_points(rev.points)
            total_cost = _sum_points(cost.points)
            margin = _safe_div(total_rev - total_cost, total_rev, default=Decimal("0"))
            return MetricValue(
                name=self.name,
                value=margin,
                unit=self.unit,
                description=self.description,
                metadata={
                    "total_revenue": str(total_rev),
                    "total_cost": str(total_cost),
                },
            )
        except Exception as e:
            raise MetricComputationError(f"{self.name} failed: {type(e).__name__}: {e}") from e


class BurnRateMetric:
    name = "burn_rate"
    unit = "currency_per_day"
    description = "Average daily burn rate: cost / days."

    async def compute(self, provider: MetricsProvider, spec: QuerySpec) -> MetricValue:
        try:
            cost = await provider.fetch_series(spec, metric="cost")
            _validate_monotonic(cost.points)
            total_cost = _sum_points(cost.points)
            days = Decimal(str(max(spec.time_range.days, 1e-9)))
            burn = _safe_div(total_cost, days, default=Decimal("0"))
            return MetricValue(
                name=self.name,
                value=burn,
                unit=self.unit,
                description=self.description,
                metadata={"days": float(spec.time_range.days)},
            )
        except Exception as e:
            raise MetricComputationError(f"{self.name} failed: {type(e).__name__}: {e}") from e


class DashboardService:
    """
    CFO Dashboards composer.

    This service does not assume any specific DB schema.
    It composes dashboards from provider series/table and metric computations.
    """

    def __init__(self, provider: MetricsProvider) -> None:
        self._provider = provider

        # Default KPI set; extend/replace via method parameters if needed.
        self._default_metrics: tuple[Metric, ...] = (
            TotalRevenueMetric(),
            TotalCostMetric(),
            GrossMarginMetric(),
            BurnRateMetric(),
        )

    async def build_cfo_overview(
        self,
        *,
        spec: QuerySpec,
        dashboard_name: str = "cfo_overview",
        metrics: Optional[Sequence[Metric]] = None,
        include_series: bool = True,
    ) -> Dashboard:
        if not isinstance(spec, QuerySpec):
            raise ValidationError("spec must be a QuerySpec")

        used_metrics = tuple(metrics) if metrics is not None else self._default_metrics

        computed: list[MetricValue] = []
        for m in used_metrics:
            computed.append(await m.compute(self._provider, spec))

        series_list: list[Series] = []
        if include_series:
            # Revenue and cost series for charting.
            # Provider decides resolution and aggregation.
            try:
                series_list.append(await self._provider.fetch_series(spec, metric="revenue"))
                series_list.append(await self._provider.fetch_series(spec, metric="cost"))
            except Exception as e:
                raise ProviderError(f"fetch_series failed: {type(e).__name__}: {e}") from e

        panels = (
            Panel(
                title="Key KPIs",
                metrics=tuple(computed),
                series=tuple(series_list),
                notes="Computed KPIs for the selected time range.",
            ),
        )

        return Dashboard(
            name=dashboard_name,
            generated_at=_now_utc(),
            time_range=spec.time_range,
            panels=panels,
            metadata={
                "dimensions": [
                    {"key": f.key, "values": list(f.values), "mode": f.mode} for f in spec.dimensions
                ],
                "group_by": list(spec.group_by),
                "limit": spec.limit,
            },
        )

    @staticmethod
    def to_json(dashboard: Dashboard) -> str:
        """
        JSON export with stable schema.
        """
        def _encode(obj: Any) -> Any:
            if isinstance(obj, Decimal):
                return str(obj)
            if isinstance(obj, dt.datetime):
                return obj.isoformat()
            if dataclasses.is_dataclass(obj):
                return dataclasses.asdict(obj)
            return obj

        payload = _encode(dashboard)
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=_encode)
