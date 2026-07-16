# agent_mash/monitoring/metrics/collectors.py
# Industrial-grade metrics collectors & registry for agent_mash.
#
# Goals:
# - No external deps
# - Async-safe updates
# - Deterministic export
# - Prometheus text exposition format
# - Cardinality guardrails to prevent label explosion
# - Useful primitives: Counter, Gauge, Histogram, Summary, Timer
#
# This module does NOT start servers; it provides core building blocks.

from __future__ import annotations

import asyncio
import math
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple

__all__ = [
    "MetricsError",
    "MetricsValidationError",
    "CardinalityExceededError",
    "MetricType",
    "MetricSample",
    "MetricFamily",
    "Collector",
    "CollectorRegistry",
    "Counter",
    "Gauge",
    "Histogram",
    "Summary",
    "Timer",
    "MetricsPoller",
    "prometheus_text_format",
]

# -----------------------------
# Errors
# -----------------------------


class MetricsError(RuntimeError):
    pass


class MetricsValidationError(MetricsError):
    pass


class CardinalityExceededError(MetricsError):
    pass


# -----------------------------
# Core types
# -----------------------------


def _now() -> float:
    return time.time()


def _now_ms() -> int:
    return int(time.time() * 1000)


def _is_finite_number(x: float) -> bool:
    return isinstance(x, (int, float)) and math.isfinite(float(x))


def _validate_metric_name(name: str) -> None:
    # Prometheus metric naming: [a-zA-Z_:][a-zA-Z0-9_:]*
    # We validate minimally to avoid exporting invalid lines.
    if not name or not isinstance(name, str):
        raise MetricsValidationError("metric name must be non-empty string")
    first = name[0]
    if not (first.isalpha() or first in "_:"):
        raise MetricsValidationError(f"invalid metric name: {name}")
    for ch in name:
        if not (ch.isalnum() or ch in "_:"):
            raise MetricsValidationError(f"invalid metric name: {name}")


def _validate_label_name(name: str) -> None:
    # Prometheus label: [a-zA-Z_][a-zA-Z0-9_]*
    if not name or not isinstance(name, str):
        raise MetricsValidationError("label name must be non-empty string")
    first = name[0]
    if not (first.isalpha() or first == "_"):
        raise MetricsValidationError(f"invalid label name: {name}")
    for ch in name:
        if not (ch.isalnum() or ch == "_"):
            raise MetricsValidationError(f"invalid label name: {name}")


def _escape_label_value(v: str) -> str:
    # Prometheus text format escaping for label values
    return v.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _normalize_labels(labels: Optional[Mapping[str, str]]) -> Tuple[Tuple[str, str], ...]:
    if not labels:
        return tuple()
    items: List[Tuple[str, str]] = []
    for k, v in labels.items():
        _validate_label_name(k)
        if v is None:
            raise MetricsValidationError(f"label value for {k} is None")
        items.append((k, str(v)))
    items.sort(key=lambda kv: kv[0])
    return tuple(items)


class MetricType(str):
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


@dataclass(frozen=True, slots=True)
class MetricSample:
    name: str
    value: float
    labels: Tuple[Tuple[str, str], ...] = ()
    timestamp_ms: Optional[int] = None


@dataclass(frozen=True, slots=True)
class MetricFamily:
    name: str
    mtype: str
    help: str
    samples: Tuple[MetricSample, ...]


@staticmethod
def _ensure_help(help_text: str) -> str:
    if help_text is None:
        return ""
    return str(help_text).replace("\n", " ").replace("\r", " ")


@staticmethod
def _labels_to_text(labels: Tuple[Tuple[str, str], ...]) -> str:
    if not labels:
        return ""
    inner = ",".join(f'{k}="{_escape_label_value(v)}"' for k, v in labels)
    return "{" + inner + "}"


# -----------------------------
# Collector protocol
# -----------------------------


class Collector(Protocol):
    """
    Collectors produce metric families.
    Should be side-effect free: do not mutate global state during collect().
    """

    async def collect(self) -> Sequence[MetricFamily]:
        ...


# -----------------------------
# Registry with guardrails
# -----------------------------


@dataclass(slots=True)
class _SeriesKey:
    metric: str
    labels: Tuple[Tuple[str, str], ...]

    def as_tuple(self) -> Tuple[str, Tuple[Tuple[str, str], ...]]:
        return (self.metric, self.labels)


class CollectorRegistry:
    """
    Central registry for metrics primitives.

    Guardrails:
    - max_series_per_metric limits label cardinality per metric name
    - max_total_series limits total series across registry
    """

    def __init__(
        self,
        *,
        max_series_per_metric: int = 2000,
        max_total_series: int = 20000,
        default_labels: Optional[Mapping[str, str]] = None,
    ) -> None:
        if max_series_per_metric <= 0 or max_total_series <= 0:
            raise MetricsValidationError("series limits must be positive integers")
        self._max_series_per_metric = int(max_series_per_metric)
        self._max_total_series = int(max_total_series)
        self._default_labels = _normalize_labels(default_labels)

        self._lock = asyncio.Lock()
        self._series_index: Dict[str, set[Tuple[Tuple[str, str], ...]]] = {}
        self._total_series: int = 0

        self._metrics: Dict[str, "_MetricBase"] = {}
        self._collectors: List[Collector] = []

    def register_collector(self, collector: Collector) -> None:
        if collector is None:
            raise MetricsValidationError("collector is None")
        self._collectors.append(collector)

    def get_collectors(self) -> Tuple[Collector, ...]:
        return tuple(self._collectors)

    async def collect_all(self) -> List[MetricFamily]:
        families: List[MetricFamily] = []
        for c in self._collectors:
            part = await c.collect()
            for f in part:
                families.append(f)
        # add primitives exported from registry itself
        primitives = await self._collect_primitives()
        families.extend(primitives)
        # deterministic order
        families.sort(key=lambda x: x.name)
        return families

    async def _collect_primitives(self) -> List[MetricFamily]:
        async with self._lock:
            metrics = list(self._metrics.values())
        out: List[MetricFamily] = []
        for m in metrics:
            out.extend(await m.collect())
        return out

    async def _guard_series(self, metric_name: str, labels: Tuple[Tuple[str, str], ...]) -> None:
        # Enforces per-metric and total series caps.
        async with self._lock:
            s = self._series_index.get(metric_name)
            if s is None:
                s = set()
                self._series_index[metric_name] = s

            if labels in s:
                return

            if len(s) + 1 > self._max_series_per_metric:
                raise CardinalityExceededError(
                    f"cardinality exceeded for metric={metric_name}: "
                    f"{len(s)} >= {self._max_series_per_metric}"
                )
            if self._total_series + 1 > self._max_total_series:
                raise CardinalityExceededError(
                    f"total series exceeded: {self._total_series} >= {self._max_total_series}"
                )

            s.add(labels)
            self._total_series += 1

    async def counter(self, name: str, *, help: str = "", unit: str = "") -> "Counter":
        return await self._create_metric(Counter, name, help=help, unit=unit)

    async def gauge(self, name: str, *, help: str = "", unit: str = "") -> "Gauge":
        return await self._create_metric(Gauge, name, help=help, unit=unit)

    async def histogram(
        self,
        name: str,
        *,
        help: str = "",
        unit: str = "",
        buckets: Optional[Sequence[float]] = None,
    ) -> "Histogram":
        return await self._create_metric(Histogram, name, help=help, unit=unit, buckets=buckets)

    async def summary(
        self,
        name: str,
        *,
        help: str = "",
        unit: str = "",
        max_observations: int = 2048,
    ) -> "Summary":
        return await self._create_metric(Summary, name, help=help, unit=unit, max_observations=max_observations)

    async def _create_metric(self, cls: Any, name: str, **kwargs: Any) -> Any:
        _validate_metric_name(name)
        async with self._lock:
            existing = self._metrics.get(name)
            if existing is not None:
                if not isinstance(existing, cls):
                    raise MetricsValidationError(f"metric name already used with different type: {name}")
                return existing
            metric = cls(name=name, registry=self, **kwargs)
            self._metrics[name] = metric
            return metric

    def apply_default_labels(self, labels: Optional[Mapping[str, str]]) -> Tuple[Tuple[str, str], ...]:
        base = list(self._default_labels)
        if labels:
            user = _normalize_labels(labels)
            # merge with override semantics: user overwrites same keys
            m = {k: v for k, v in base}
            for k, v in user:
                m[k] = v
            merged = sorted(m.items(), key=lambda kv: kv[0])
            return tuple((k, v) for k, v in merged)
        return tuple(base)


# -----------------------------
# Metrics primitives
# -----------------------------


class _MetricBase:
    def __init__(self, *, name: str, registry: CollectorRegistry, help: str = "", unit: str = "") -> None:
        _validate_metric_name(name)
        self._name = name
        self._help = _ensure_help(help)
        self._unit = str(unit) if unit is not None else ""
        self._registry = registry
        self._lock = asyncio.Lock()

    @property
    def name(self) -> str:
        return self._name

    async def collect(self) -> Sequence[MetricFamily]:
        raise NotImplementedError


class Counter(_MetricBase):
    def __init__(self, *, name: str, registry: CollectorRegistry, help: str = "", unit: str = "") -> None:
        super().__init__(name=name, registry=registry, help=help, unit=unit)
        self._values: Dict[Tuple[Tuple[str, str], ...], float] = {}

    async def inc(self, value: float = 1.0, *, labels: Optional[Mapping[str, str]] = None) -> None:
        if not _is_finite_number(value) or float(value) < 0.0:
            raise MetricsValidationError("counter increment must be finite and non-negative")
        lbs = self._registry.apply_default_labels(labels)
        await self._registry._guard_series(self._name, lbs)
        async with self._lock:
            self._values[lbs] = float(self._values.get(lbs, 0.0)) + float(value)

    async def collect(self) -> Sequence[MetricFamily]:
        async with self._lock:
            items = list(self._values.items())
        samples = tuple(MetricSample(name=self._name, value=v, labels=lbs) for lbs, v in items)
        return (MetricFamily(name=self._name, mtype=MetricType.COUNTER, help=self._help, samples=samples),)


class Gauge(_MetricBase):
    def __init__(self, *, name: str, registry: CollectorRegistry, help: str = "", unit: str = "") -> None:
        super().__init__(name=name, registry=registry, help=help, unit=unit)
        self._values: Dict[Tuple[Tuple[str, str], ...], float] = {}

    async def set(self, value: float, *, labels: Optional[Mapping[str, str]] = None) -> None:
        if not _is_finite_number(value):
            raise MetricsValidationError("gauge value must be finite number")
        lbs = self._registry.apply_default_labels(labels)
        await self._registry._guard_series(self._name, lbs)
        async with self._lock:
            self._values[lbs] = float(value)

    async def inc(self, value: float = 1.0, *, labels: Optional[Mapping[str, str]] = None) -> None:
        if not _is_finite_number(value):
            raise MetricsValidationError("gauge increment must be finite")
        lbs = self._registry.apply_default_labels(labels)
        await self._registry._guard_series(self._name, lbs)
        async with self._lock:
            self._values[lbs] = float(self._values.get(lbs, 0.0)) + float(value)

    async def dec(self, value: float = 1.0, *, labels: Optional[Mapping[str, str]] = None) -> None:
        if not _is_finite_number(value):
            raise MetricsValidationError("gauge decrement must be finite")
        await self.inc(-float(value), labels=labels)

    async def collect(self) -> Sequence[MetricFamily]:
        async with self._lock:
            items = list(self._values.items())
        samples = tuple(MetricSample(name=self._name, value=v, labels=lbs) for lbs, v in items)
        return (MetricFamily(name=self._name, mtype=MetricType.GAUGE, help=self._help, samples=samples),)


class Histogram(_MetricBase):
    """
    Prometheus histogram exports:
    - <name>_bucket{le="..."} count
    - <name>_count total
    - <name>_sum total sum
    """
    def __init__(
        self,
        *,
        name: str,
        registry: CollectorRegistry,
        help: str = "",
        unit: str = "",
        buckets: Optional[Sequence[float]] = None,
    ) -> None:
        super().__init__(name=name, registry=registry, help=help, unit=unit)
        if buckets is None:
            buckets = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
        b = sorted(float(x) for x in buckets)
        if not b or any(not _is_finite_number(x) or x <= 0.0 for x in b):
            raise MetricsValidationError("histogram buckets must be finite positive numbers")
        self._buckets = tuple(b)
        self._counts: Dict[Tuple[Tuple[str, str], ...], List[int]] = {}
        self._sum: Dict[Tuple[Tuple[str, str], ...], float] = {}
        self._total: Dict[Tuple[Tuple[str, str], ...], int] = {}

    async def observe(self, value: float, *, labels: Optional[Mapping[str, str]] = None) -> None:
        if not _is_finite_number(value) or float(value) < 0.0:
            raise MetricsValidationError("histogram observe value must be finite and non-negative")
        lbs = self._registry.apply_default_labels(labels)
        # +1 for each bucket series le label is handled at export time; guard base labels series here
        await self._registry._guard_series(self._name, lbs)
        async with self._lock:
            cnts = self._counts.get(lbs)
            if cnts is None:
                cnts = [0 for _ in self._buckets]
                self._counts[lbs] = cnts
                self._sum[lbs] = 0.0
                self._total[lbs] = 0
            v = float(value)
            for i, b in enumerate(self._buckets):
                if v <= b:
                    cnts[i] += 1
            self._sum[lbs] = float(self._sum[lbs]) + v
            self._total[lbs] = int(self._total[lbs]) + 1

    async def collect(self) -> Sequence[MetricFamily]:
        async with self._lock:
            counts = {k: list(v) for k, v in self._counts.items()}
            sums = dict(self._sum)
            totals = dict(self._total)

        samples: List[MetricSample] = []
        # buckets
        for lbs, cnts in counts.items():
            running = 0
            for i, b in enumerate(self._buckets):
                running = cnts[i]
                labels = tuple(list(lbs) + [("le", str(b))])
                samples.append(MetricSample(name=f"{self._name}_bucket", value=float(running), labels=labels))
            labels_inf = tuple(list(lbs) + [("le", "+Inf")])
            samples.append(MetricSample(name=f"{self._name}_bucket", value=float(totals.get(lbs, 0)), labels=labels_inf))
            samples.append(MetricSample(name=f"{self._name}_count", value=float(totals.get(lbs, 0)), labels=lbs))
            samples.append(MetricSample(name=f"{self._name}_sum", value=float(sums.get(lbs, 0.0)), labels=lbs))

        fam = MetricFamily(name=self._name, mtype=MetricType.HISTOGRAM, help=self._help, samples=tuple(samples))
        return (fam,)


class Summary(_MetricBase):
    """
    Lightweight summary:
    - <name>_count
    - <name>_sum
    - optional quantiles computed on recent window (approx by storing last N observations)
    """
    def __init__(
        self,
        *,
        name: str,
        registry: CollectorRegistry,
        help: str = "",
        unit: str = "",
        max_observations: int = 2048,
    ) -> None:
        super().__init__(name=name, registry=registry, help=help, unit=unit)
        if max_observations <= 0:
            raise MetricsValidationError("max_observations must be positive")
        self._max = int(max_observations)
        self._obs: Dict[Tuple[Tuple[str, str], ...], List[float]] = {}
        self._sum: Dict[Tuple[Tuple[str, str], ...], float] = {}
        self._count: Dict[Tuple[Tuple[str, str], ...], int] = {}

    async def observe(self, value: float, *, labels: Optional[Mapping[str, str]] = None) -> None:
        if not _is_finite_number(value) or float(value) < 0.0:
            raise MetricsValidationError("summary observe value must be finite and non-negative")
        lbs = self._registry.apply_default_labels(labels)
        await self._registry._guard_series(self._name, lbs)
        async with self._lock:
            arr = self._obs.get(lbs)
            if arr is None:
                arr = []
                self._obs[lbs] = arr
                self._sum[lbs] = 0.0
                self._count[lbs] = 0
            arr.append(float(value))
            if len(arr) > self._max:
                arr.pop(0)
            self._sum[lbs] = float(self._sum[lbs]) + float(value)
            self._count[lbs] = int(self._count[lbs]) + 1

    async def collect(self) -> Sequence[MetricFamily]:
        async with self._lock:
            obs = {k: list(v) for k, v in self._obs.items()}
            sums = dict(self._sum)
            counts = dict(self._count)

        samples: List[MetricSample] = []
        for lbs, n in counts.items():
            samples.append(MetricSample(name=f"{self._name}_count", value=float(n), labels=lbs))
            samples.append(MetricSample(name=f"{self._name}_sum", value=float(sums.get(lbs, 0.0)), labels=lbs))

            # quantiles (approx by full sort of window)
            window = obs.get(lbs, [])
            if window:
                w = sorted(window)
                for q in (0.5, 0.9, 0.99):
                    idx = int(round(q * (len(w) - 1)))
                    val = float(w[idx])
                    labels = tuple(list(lbs) + [("quantile", str(q))])
                    samples.append(MetricSample(name=self._name, value=val, labels=labels))

        fam = MetricFamily(name=self._name, mtype=MetricType.SUMMARY, help=self._help, samples=tuple(samples))
        return (fam,)


class Timer:
    """
    Async-friendly timer helper that records durations into a Histogram or Summary.

    Usage:
      t = Timer(metric)
      async with t.time(labels={...}):
          ...
    """

    def __init__(self, metric: Any) -> None:
        self._metric = metric

    class _Ctx:
        def __init__(self, metric: Any, labels: Optional[Mapping[str, str]]) -> None:
            self._metric = metric
            self._labels = labels
            self._start: Optional[float] = None

        async def __aenter__(self) -> "Timer._Ctx":
            self._start = _now()
            return self

        async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
            if self._start is None:
                return
            dur = _now() - self._start
            # store seconds as value
            if hasattr(self._metric, "observe"):
                await self._metric.observe(dur, labels=self._labels)

    def time(self, *, labels: Optional[Mapping[str, str]] = None) -> "Timer._Ctx":
        return Timer._Ctx(self._metric, labels)


# -----------------------------
# Poller
# -----------------------------


class MetricsPoller:
    """
    Periodically invokes collectors and stores the last successful scrape payload.
    Useful when you want to decouple expensive collection from /metrics endpoint.
    """

    def __init__(
        self,
        registry: CollectorRegistry,
        *,
        interval_sec: float = 5.0,
        on_error: Optional[Callable[[Exception], Awaitable[None]]] = None,
    ) -> None:
        if interval_sec <= 0:
            raise MetricsValidationError("interval_sec must be positive")
        self._registry = registry
        self._interval = float(interval_sec)
        self._on_error = on_error
        self._task: Optional[asyncio.Task[None]] = None
        self._stop = asyncio.Event()
        self._lock = asyncio.Lock()
        self._last_text: str = ""
        self._last_ok_ms: Optional[int] = None

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run(), name="metrics_poller")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stop.set()
        try:
            await self._task
        finally:
            self._task = None

    async def last_scrape(self) -> Tuple[str, Optional[int]]:
        async with self._lock:
            return self._last_text, self._last_ok_ms

    async def _run(self) -> None:
        while not self._stop.is_set():
            started = _now()
            try:
                families = await self._registry.collect_all()
                text = prometheus_text_format(families)
                async with self._lock:
                    self._last_text = text
                    self._last_ok_ms = _now_ms()
            except Exception as e:
                if self._on_error is not None:
                    await self._on_error(e)
            elapsed = _now() - started
            sleep_for = max(0.0, self._interval - elapsed)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=sleep_for)
            except asyncio.TimeoutError:
                pass


# -----------------------------
# Prometheus export
# -----------------------------


def prometheus_text_format(families: Sequence[MetricFamily]) -> str:
    """
    Prometheus text exposition format.
    Deterministic output:
    - families sorted by name by caller or here defensively
    - samples sorted by (name, labels)
    """
    fams = sorted(list(families), key=lambda f: f.name)
    lines: List[str] = []
    for fam in fams:
        _validate_metric_name(fam.name)
        help_txt = str(fam.help or "").replace("\\", "\\\\").replace("\n", " ").replace("\r", " ")
        lines.append(f"# HELP {fam.name} {help_txt}")
        lines.append(f"# TYPE {fam.name} {fam.mtype}")

        samples = sorted(
            list(fam.samples),
            key=lambda s: (s.name, s.labels),
        )
        for s in samples:
            _validate_metric_name(s.name)
            if not _is_finite_number(s.value):
                continue
            lbls = _labels_to_text(s.labels)
            if s.timestamp_ms is None:
                lines.append(f"{s.name}{lbls} {float(s.value)}")
            else:
                lines.append(f"{s.name}{lbls} {float(s.value)} {int(s.timestamp_ms)}")
    lines.append("")
    return "\n".join(lines)
