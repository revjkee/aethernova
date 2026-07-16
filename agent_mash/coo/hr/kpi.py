# agent_mash/hr/kpi.py
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


class KPIError(Exception):
    pass


class KPIValidationError(KPIError):
    pass


class KPIComputationError(KPIError):
    pass


class KPIStatus(str, Enum):
    excellent = "excellent"
    good = "good"
    ok = "ok"
    warning = "warning"
    critical = "critical"
    unknown = "unknown"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_aware_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        raise KPIValidationError("datetime must be timezone-aware")
    return dt.astimezone(timezone.utc)


def _to_decimal(value: Any, *, field_name: str) -> Decimal:
    try:
        if isinstance(value, Decimal):
            d = value
        elif isinstance(value, (int, str)):
            d = Decimal(str(value))
        elif isinstance(value, float):
            if value != value:  # NaN
                raise KPIValidationError(f"{field_name} must not be NaN")
            d = Decimal(repr(value))
        else:
            raise KPIValidationError(f"{field_name} has unsupported type: {type(value).__name__}")
    except (InvalidOperation, ValueError) as exc:
        raise KPIValidationError(f"{field_name} must be numeric-convertible") from exc
    return d


def _quantize_2(d: Decimal) -> Decimal:
    return d.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def _clamp(d: Decimal, lo: Decimal, hi: Decimal) -> Decimal:
    if d < lo:
        return lo
    if d > hi:
        return hi
    return d


@dataclass(frozen=True)
class KPIId:
    namespace: str
    name: str
    version: str = "1"

    def __post_init__(self) -> None:
        if not self.namespace or not self.namespace.strip():
            raise KPIValidationError("KPIId.namespace must be non-empty")
        if not self.name or not self.name.strip():
            raise KPIValidationError("KPIId.name must be non-empty")
        if not self.version or not self.version.strip():
            raise KPIValidationError("KPIId.version must be non-empty")

    @property
    def fqdn(self) -> str:
        return f"{self.namespace}.{self.name}.v{self.version}"


@dataclass(frozen=True)
class TimeWindow:
    start_utc: datetime
    end_utc: datetime

    def __post_init__(self) -> None:
        s = _ensure_aware_utc(self.start_utc)
        e = _ensure_aware_utc(self.end_utc)
        if e <= s:
            raise KPIValidationError("TimeWindow.end_utc must be greater than start_utc")
        object.__setattr__(self, "start_utc", s)
        object.__setattr__(self, "end_utc", e)

    @property
    def duration_seconds(self) -> int:
        return int((self.end_utc - self.start_utc).total_seconds())


@dataclass(frozen=True)
class Measurement:
    key: str
    value: Decimal
    observed_at_utc: datetime
    meta: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.key or not self.key.strip():
            raise KPIValidationError("Measurement.key must be non-empty")
        v = _to_decimal(self.value, field_name="Measurement.value")
        t = _ensure_aware_utc(self.observed_at_utc)
        object.__setattr__(self, "value", v)
        object.__setattr__(self, "observed_at_utc", t)
        if self.meta is None:
            object.__setattr__(self, "meta", {})


@dataclass(frozen=True)
class KPIThresholds:
    excellent_min: Decimal = Decimal("90")
    good_min: Decimal = Decimal("75")
    ok_min: Decimal = Decimal("60")
    warning_min: Decimal = Decimal("40")

    def __post_init__(self) -> None:
        ex = _to_decimal(self.excellent_min, field_name="excellent_min")
        gd = _to_decimal(self.good_min, field_name="good_min")
        ok = _to_decimal(self.ok_min, field_name="ok_min")
        wn = _to_decimal(self.warning_min, field_name="warning_min")
        if not (Decimal("0") <= wn <= ok <= gd <= ex <= Decimal("100")):
            raise KPIValidationError("Thresholds must satisfy 0 <= warning <= ok <= good <= excellent <= 100")
        object.__setattr__(self, "excellent_min", ex)
        object.__setattr__(self, "good_min", gd)
        object.__setattr__(self, "ok_min", ok)
        object.__setattr__(self, "warning_min", wn)

    def classify(self, score_0_100: Decimal) -> KPIStatus:
        s = _clamp(score_0_100, Decimal("0"), Decimal("100"))
        if s >= self.excellent_min:
            return KPIStatus.excellent
        if s >= self.good_min:
            return KPIStatus.good
        if s >= self.ok_min:
            return KPIStatus.ok
        if s >= self.warning_min:
            return KPIStatus.warning
        return KPIStatus.critical


@dataclass(frozen=True)
class KPIWeighting:
    weights: Dict[str, Decimal]

    def __post_init__(self) -> None:
        if not self.weights:
            raise KPIValidationError("KPIWeighting.weights must be non-empty")
        normalized: Dict[str, Decimal] = {}
        total = Decimal("0")
        for k, w in self.weights.items():
            if not k or not str(k).strip():
                raise KPIValidationError("KPIWeighting key must be non-empty")
            dw = _to_decimal(w, field_name=f"weight[{k}]")
            if dw < 0:
                raise KPIValidationError(f"weight[{k}] must be >= 0")
            normalized[str(k)] = dw
            total += dw
        if total <= 0:
            raise KPIValidationError("Sum of weights must be > 0")
        object.__setattr__(self, "weights", normalized)

    def normalized(self) -> Dict[str, Decimal]:
        total = sum(self.weights.values(), Decimal("0"))
        if total <= 0:
            raise KPIValidationError("Sum of weights must be > 0")
        return {k: (v / total) for k, v in self.weights.items()}


@dataclass(frozen=True)
class KPIProfile:
    kpi_id: KPIId
    title: str
    description: str
    thresholds: KPIThresholds = field(default_factory=KPIThresholds)
    weighting: Optional[KPIWeighting] = None
    min_samples: int = 1
    score_min: Decimal = Decimal("0")
    score_max: Decimal = Decimal("100")
    clamp_score: bool = True

    def __post_init__(self) -> None:
        if not self.title or not self.title.strip():
            raise KPIValidationError("KPIProfile.title must be non-empty")
        if self.min_samples <= 0:
            raise KPIValidationError("KPIProfile.min_samples must be > 0")
        mn = _to_decimal(self.score_min, field_name="score_min")
        mx = _to_decimal(self.score_max, field_name="score_max")
        if mx <= mn:
            raise KPIValidationError("KPIProfile.score_max must be greater than score_min")
        object.__setattr__(self, "score_min", mn)
        object.__setattr__(self, "score_max", mx)


@dataclass(frozen=True)
class TraceStep:
    step: str
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class KPIResult:
    kpi_id: KPIId
    window: TimeWindow
    score_0_100: Decimal
    status: KPIStatus
    computed_at_utc: datetime
    samples: int
    components: Dict[str, Decimal] = field(default_factory=dict)
    trace: List[TraceStep] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kpi_id": self.kpi_id.fqdn,
            "window": {
                "start_utc": self.window.start_utc.isoformat(),
                "end_utc": self.window.end_utc.isoformat(),
                "duration_seconds": self.window.duration_seconds,
            },
            "score_0_100": str(_quantize_2(self.score_0_100)),
            "status": self.status.value,
            "computed_at_utc": _ensure_aware_utc(self.computed_at_utc).isoformat(),
            "samples": int(self.samples),
            "components": {k: str(_quantize_2(v)) for k, v in self.components.items()},
            "trace": [{"step": t.step, "data": t.data} for t in self.trace],
        }


class KPIComputer:
    def compute(
        self,
        profile: KPIProfile,
        measurements: Sequence[Measurement],
        window: TimeWindow,
    ) -> KPIResult:
        raise NotImplementedError


class WeightedScoreComputer(KPIComputer):
    """
    Default industrial KPI computer:
    - Each component key gets a 0..100 component score.
    - Final KPI is weighted average of components (weights normalized).
    - If no weighting provided, equal weights by unique keys.
    """

    def compute(
        self,
        profile: KPIProfile,
        measurements: Sequence[Measurement],
        window: TimeWindow,
    ) -> KPIResult:
        if profile is None:
            raise KPIValidationError("profile is required")
        if window is None:
            raise KPIValidationError("window is required")
        if measurements is None:
            raise KPIValidationError("measurements is required")

        s_utc = window.start_utc
        e_utc = window.end_utc

        in_window: List[Measurement] = []
        for m in measurements:
            t = m.observed_at_utc
            if s_utc <= t < e_utc:
                in_window.append(m)

        trace: List[TraceStep] = [
            TraceStep("filter_window", {"total": len(measurements), "in_window": len(in_window)}),
            TraceStep("window", {"start_utc": s_utc.isoformat(), "end_utc": e_utc.isoformat()}),
        ]

        if len(in_window) < profile.min_samples:
            trace.append(
                TraceStep(
                    "insufficient_samples",
                    {"min_samples": profile.min_samples, "samples": len(in_window)},
                )
            )
            score = Decimal("0")
            status = KPIStatus.unknown
            return KPIResult(
                kpi_id=profile.kpi_id,
                window=window,
                score_0_100=score,
                status=status,
                computed_at_utc=_utcnow(),
                samples=len(in_window),
                components={},
                trace=trace,
            )

        by_key: Dict[str, List[Decimal]] = {}
        for m in in_window:
            by_key.setdefault(m.key, []).append(m.value)

        components_raw: Dict[str, Decimal] = {}
        for key, values in by_key.items():
            if not values:
                continue
            avg = sum(values, Decimal("0")) / Decimal(len(values))
            components_raw[key] = avg

        trace.append(
            TraceStep(
                "components_raw",
                {k: str(_quantize_2(v)) for k, v in components_raw.items()},
            )
        )

        components_score: Dict[str, Decimal] = {}
        for key, raw in components_raw.items():
            if profile.clamp_score:
                sc = _clamp(raw, profile.score_min, profile.score_max)
            else:
                sc = raw
            score_0_100 = (sc - profile.score_min) / (profile.score_max - profile.score_min) * Decimal("100")
            score_0_100 = _clamp(score_0_100, Decimal("0"), Decimal("100"))
            components_score[key] = score_0_100

        trace.append(
            TraceStep(
                "components_score_0_100",
                {k: str(_quantize_2(v)) for k, v in components_score.items()},
            )
        )

        if profile.weighting is not None:
            weights = profile.weighting.normalized()
            trace.append(
                TraceStep(
                    "weights_normalized",
                    {k: str(_quantize_2(v * Decimal("100"))) for k, v in weights.items()},
                )
            )
        else:
            keys = sorted(components_score.keys())
            if not keys:
                raise KPIComputationError("No KPI components after processing")
            w = Decimal("1") / Decimal(len(keys))
            weights = {k: w for k in keys}
            trace.append(
                TraceStep(
                    "weights_equal",
                    {"keys": keys, "each": str(_quantize_2(w * Decimal("100")))},
                )
            )

        numerator = Decimal("0")
        denom = Decimal("0")
        for k, sc in components_score.items():
            w = weights.get(k)
            if w is None:
                continue
            if w <= 0:
                continue
            numerator += sc * w
            denom += w

        if denom <= 0:
            raise KPIComputationError("Effective weight sum is <= 0")

        final_score = numerator / denom
        final_score = _clamp(final_score, Decimal("0"), Decimal("100"))
        status = profile.thresholds.classify(final_score)

        trace.append(
            TraceStep(
                "final",
                {
                    "numerator": str(_quantize_2(numerator)),
                    "denom": str(_quantize_2(denom)),
                    "final_score_0_100": str(_quantize_2(final_score)),
                    "status": status.value,
                },
            )
        )

        return KPIResult(
            kpi_id=profile.kpi_id,
            window=window,
            score_0_100=final_score,
            status=status,
            computed_at_utc=_utcnow(),
            samples=len(in_window),
            components=components_score,
            trace=trace,
        )


@dataclass
class KPIRegistry:
    """
    Registry binds KPI profiles to compute strategies.
    This keeps KPI-as-code scalable and testable.
    """

    profiles: Dict[str, KPIProfile] = field(default_factory=dict)
    computers: Dict[str, KPIComputer] = field(default_factory=dict)
    default_computer: KPIComputer = field(default_factory=WeightedScoreComputer)

    def register_profile(self, profile: KPIProfile) -> None:
        if profile is None:
            raise KPIValidationError("profile is required")
        self.profiles[profile.kpi_id.fqdn] = profile

    def register_computer(self, kpi_fqdn: str, computer: KPIComputer) -> None:
        if not kpi_fqdn or not str(kpi_fqdn).strip():
            raise KPIValidationError("kpi_fqdn must be non-empty")
        if computer is None:
            raise KPIValidationError("computer is required")
        self.computers[str(kpi_fqdn)] = computer

    def get_profile(self, kpi_fqdn: str) -> KPIProfile:
        try:
            return self.profiles[kpi_fqdn]
        except KeyError as exc:
            raise KPIValidationError(f"Unknown KPI profile: {kpi_fqdn}") from exc

    def get_computer(self, kpi_fqdn: str) -> KPIComputer:
        return self.computers.get(kpi_fqdn, self.default_computer)

    def compute(
        self,
        kpi_fqdn: str,
        measurements: Sequence[Measurement],
        window: TimeWindow,
    ) -> KPIResult:
        profile = self.get_profile(kpi_fqdn)
        computer = self.get_computer(kpi_fqdn)
        return computer.compute(profile=profile, measurements=measurements, window=window)


def make_window(*, start_utc: datetime, end_utc: datetime) -> TimeWindow:
    return TimeWindow(start_utc=start_utc, end_utc=end_utc)


def make_measurement(
    *,
    key: str,
    value: Any,
    observed_at_utc: Optional[datetime] = None,
    meta: Optional[Dict[str, Any]] = None,
) -> Measurement:
    ts = observed_at_utc if observed_at_utc is not None else _utcnow()
    return Measurement(key=key, value=_to_decimal(value, field_name="value"), observed_at_utc=ts, meta=meta or {})


def make_profile(
    *,
    namespace: str,
    name: str,
    version: str = "1",
    title: str,
    description: str,
    thresholds: Optional[KPIThresholds] = None,
    weighting: Optional[Mapping[str, Any]] = None,
    min_samples: int = 1,
    score_min: Any = Decimal("0"),
    score_max: Any = Decimal("100"),
    clamp_score: bool = True,
) -> KPIProfile:
    kpi_id = KPIId(namespace=namespace, name=name, version=version)
    w_obj: Optional[KPIWeighting] = None
    if weighting is not None:
        w_obj = KPIWeighting(weights={str(k): _to_decimal(v, field_name=f"weight[{k}]") for k, v in weighting.items()})
    return KPIProfile(
        kpi_id=kpi_id,
        title=title,
        description=description,
        thresholds=thresholds or KPIThresholds(),
        weighting=w_obj,
        min_samples=min_samples,
        score_min=_to_decimal(score_min, field_name="score_min"),
        score_max=_to_decimal(score_max, field_name="score_max"),
        clamp_score=clamp_score,
    )
