# -*- coding: utf-8 -*-
"""
Unified metrics facade for Neuroforge services.

Unverified: окружение/версии библиотек/экспортёров зависят от вашей платформы. I cannot verify this.

Возможности:
- Единый интерфейс эмиттера (increment, observe, gauge_set/inc/dec).
- Реализации:
  * PrometheusEmitter — совместим с multiprocess (PROMETHEUS_MULTIPROC_DIR), Gauge в режиме livesum.
  * OpenTelemetryEmitter — использует opentelemetry.metrics Meter API.
  * CompositeEmitter — мультикаст на несколько бэкендов.
  * NoopEmitter — по умолчанию, если ничего не настроено.
- Потокобезопасный кэш инструментов по (name, type, label_names).
- Ограничение кардинальности: санитизация имён/значений лейблов, хэширование подозрительных/слишком длинных.
- Таймеры/декораторы для sync/async, учёт ошибок и latency-бакеты.
- Мягкие ошибки: эмиттер никогда не роняет бизнес-логику.

Использование:
    from neuroforge.observability.metrics import (
        init_default_emitter, increment, observe, gauge_set, timer, track_operation
    )

    # 1) Инициализация (например, в точке входа сервиса)
    init_default_emitter(backend="prometheus", namespace="nf", subsystem="core")

    # 2) Инструментирование
    increment("requests_total", method="GET", handler="/api/v1/items", status="200")
    with timer("db_query_seconds", op="select"):
        run_query()

    @track_operation("inference_seconds", labels=lambda *a, **k: {"model":"mA"})
    async def infer(x): ...

Замечание:
- Экспорт /metrics для Prometheus реализуйте через HTTP-роутер (см. ваш модуль api/http/routers/v1/metrics.py).
"""

from __future__ import annotations

import os
import re
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence, Tuple

# ------------------------------
# Optional deps (guarded import)
# ------------------------------
try:
    from prometheus_client import Counter as _P_Counter, Histogram as _P_Histogram, Gauge as _P_Gauge
    from prometheus_client import CollectorRegistry as _P_CollectorRegistry  # noqa: F401 (для type hints/будущего)
    _HAVE_PROM = True
except Exception:  # pragma: no cover
    _HAVE_PROM = False
    _P_Counter = _P_Histogram = _P_Gauge = object  # type: ignore

try:
    from opentelemetry import metrics as _otel_metrics
    _HAVE_OTEL = True
except Exception:  # pragma: no cover
    _HAVE_OTEL = False
    _otel_metrics = None  # type: ignore

# ------------------------------
# Константы/настройки по умолчанию
# ------------------------------

_DEFAULT_LATENCY_BUCKETS = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10
)

_SAN_LABEL_NAME = re.compile(r"[^a-zA-Z0-9_:]")
_SAN_LABEL_VALUE = re.compile(r"[^a-zA-Z0-9_\-\.@:/]")

_MAX_LABEL_VALUE_LEN = 128
_HASH_PREFIX = "h_"

# ------------------------------
# API эмиттера
# ------------------------------

class MetricsEmitter:
    """
    Абстрактный эмиттер. Все методы должны быть «безопасными» к исключениям.
    """
    def increment(self, name: str, value: float = 1.0, **labels: str) -> None: ...
    def observe(self, name: str, value: float, buckets: Optional[Sequence[float]] = None, **labels: str) -> None: ...
    def gauge_set(self, name: str, value: float, **labels: str) -> None: ...
    def gauge_inc(self, name: str, value: float = 1.0, **labels: str) -> None: ...
    def gauge_dec(self, name: str, value: float = 1.0, **labels: str) -> None: ...


# ------------------------------
# Утилиты санитизации/кардинальности
# ------------------------------

def _sanitize_name(n: str) -> str:
    """
    Преобразует имя в формат совместимый с Prometheus/OpenMetrics.
    """
    n = _SAN_LABEL_NAME.sub("_", n.strip())
    if not n:
        return "metric"
    if n[0].isdigit():
        n = "_" + n
    return n

def _sanitize_label_key(k: str) -> str:
    k = _SAN_LABEL_NAME.sub("_", k.strip())
    if not k:
        return "label"
    if k[0].isdigit():
        k = "_" + k
    return k

def _hash_value(v: str) -> str:
    # Простое стабильное 64-бит FNV-1a
    h = 0xcbf29ce484222325
    for b in v.encode("utf-8", "ignore"):
        h ^= b
        h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return f"{_HASH_PREFIX}{h:016x}"

def _looks_high_cardinality(v: str) -> bool:
    # Эвристики: слишком длинно, выглядит как UUID/хеш, содержит многие уникальные сегменты
    if len(v) > _MAX_LABEL_VALUE_LEN:
        return True
    if re.match(r"(?i)\b[0-9a-f]{8}\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\b[0-9a-f]{12}\b", v):
        return True
    if re.match(r"(?i)^[0-9a-f]{20,64}$", v.replace("-", "")):
        return True
    return False

def _sanitize_label_value(v: str, allow_raw: bool = False) -> str:
    if allow_raw:
        vv = v.strip()
        return vv[:_MAX_LABEL_VALUE_LEN]
    v = v.strip()
    if _looks_high_cardinality(v):
        return _hash_value(v)
    v = _SAN_LABEL_VALUE.sub("_", v)
    return v[:_MAX_LABEL_VALUE_LEN]


# ------------------------------
# Prometheus реализация
# ------------------------------

class PrometheusEmitter(MetricsEmitter):
    """
    Потокобезопасный эмиттер метрик Prometheus. Поддерживает multiprocess (Gauge — livesum).
    """
    def __init__(
        self,
        *,
        namespace: Optional[str] = None,
        subsystem: Optional[str] = None,
        label_allow_raw: Sequence[str] = (),
        default_buckets: Sequence[float] = _DEFAULT_LATENCY_BUCKETS,
    ) -> None:
        if not _HAVE_PROM:  # pragma: no cover
            raise RuntimeError("prometheus_client is not available")
        self.ns = _sanitize_name(namespace) if namespace else None
        self.ss = _sanitize_name(subsystem) if subsystem else None
        self.allow_raw = {lk.lower() for lk in label_allow_raw}
        self.default_buckets = tuple(default_buckets)
        self._lock = threading.RLock()
        self._counters: Dict[Tuple[str, Tuple[str, ...]], Any] = {}
        self._hists: Dict[Tuple[str, Tuple[str, ...], Tuple[float, ...]], Any] = {}
        self._gauges: Dict[Tuple[str, Tuple[str, ...]], Any] = {}
        self._multiproc = os.environ.get("PROMETHEUS_MULTIPROC_DIR") not in (None, "")

    # --- API ---
    def increment(self, name: str, value: float = 1.0, **labels: str) -> None:
        metric, label_values = self._counter(name, labels)
        try:
            metric.labels(*label_values).inc(value)
        except Exception:
            pass

    def observe(self, name: str, value: float, buckets: Optional[Sequence[float]] = None, **labels: str) -> None:
        metric, label_values = self._histogram(name, labels, buckets=buckets)
        try:
            metric.labels(*label_values).observe(value)
        except Exception:
            pass

    def gauge_set(self, name: str, value: float, **labels: str) -> None:
        metric, label_values = self._gauge(name, labels)
        try:
            metric.labels(*label_values).set(value)
        except Exception:
            pass

    def gauge_inc(self, name: str, value: float = 1.0, **labels: str) -> None:
        metric, label_values = self._gauge(name, labels)
        try:
            metric.labels(*label_values).inc(value)
        except Exception:
            pass

    def gauge_dec(self, name: str, value: float = 1.0, **labels: str) -> None:
        metric, label_values = self._gauge(name, labels)
        try:
            metric.labels(*label_values).dec(value)
        except Exception:
            pass

    # --- Internals ---
    def _metric_base(self, name: str) -> str:
        parts = []
        if self.ns: parts.append(self.ns)
        if self.ss: parts.append(self.ss)
        parts.append(_sanitize_name(name))
        return "_".join(parts)

    def _canon_labels(self, labels: Mapping[str, str]) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
        if not labels:
            return tuple(), tuple()
        items = []
        for k, v in labels.items():
            kk = _sanitize_label_key(k)
            vv = _sanitize_label_value(str(v), allow_raw=(kk.lower() in self.allow_raw))
            items.append((kk, vv))
        items.sort(key=lambda kv: kv[0])
        keys = tuple(k for k, _ in items)
        vals = tuple(v for _, v in items)
        return keys, vals

    def _counter(self, name: str, labels: Mapping[str, str]):
        mname = self._metric_base(name)
        keys, vals = self._canon_labels(labels)
        cache_key = (mname, keys)
        with self._lock:
            metric = self._counters.get(cache_key)
            if metric is None:
                metric = _P_Counter(mname, f"{mname} counter", labelnames=keys or ())
                self._counters[cache_key] = metric
        return metric, vals

    def _histogram(self, name: str, labels: Mapping[str, str], buckets: Optional[Sequence[float]] = None):
        mname = self._metric_base(name)
        keys, vals = self._canon_labels(labels)
        bkts = tuple(buckets or self.default_buckets)
        cache_key = (mname, keys, bkts)
        with self._lock:
            metric = self._hists.get(cache_key)
            if metric is None:
                metric = _P_Histogram(mname, f"{mname} histogram", labelnames=keys or (), buckets=bkts)
                self._hists[cache_key] = metric
        return metric, vals

    def _gauge(self, name: str, labels: Mapping[str, str]):
        mname = self._metric_base(name)
        keys, vals = self._canon_labels(labels)
        cache_key = (mname, keys)
        with self._lock:
            metric = self._gauges.get(cache_key)
            if metric is None:
                if self._multiproc:
                    metric = _P_Gauge(mname, f"{mname} gauge", labelnames=keys or (), multiprocess_mode="livesum")
                else:
                    metric = _P_Gauge(mname, f"{mname} gauge", labelnames=keys or ())
                self._gauges[cache_key] = metric
        return metric, vals


# ------------------------------
# OpenTelemetry реализация
# ------------------------------

class OpenTelemetryEmitter(MetricsEmitter):
    """
    Эмиттер на базе OpenTelemetry Metrics API.
    Предполагает, что SDK/Exporter и MeterProvider настроены в вашем приложении.
    """
    def __init__(self, *, meter_name: str = "neuroforge-core", label_allow_raw: Sequence[str] = ()) -> None:
        if not _HAVE_OTEL:  # pragma: no cover
            raise RuntimeError("opentelemetry.metrics is not available")
        self._meter = _otel_metrics.get_meter(meter_name)
        self.allow_raw = {lk.lower() for lk in label_allow_raw}
        self._lock = threading.RLock()
        self._counters: Dict[Tuple[str, Tuple[str, ...]], Any] = {}
        self._hists: Dict[Tuple[str, Tuple[str, ...]], Any] = {}
        self._updowns: Dict[Tuple[str, Tuple[str, ...]], Any] = {}

    def increment(self, name: str, value: float = 1.0, **labels: str) -> None:
        instr, attrs = self._counter(name, labels)
        try:
            instr.add(value, attributes=attrs)
        except Exception:
            pass

    def observe(self, name: str, value: float, buckets: Optional[Sequence[float]] = None, **labels: str) -> None:
        instr, attrs = self._histogram(name, labels)
        try:
            instr.record(value, attributes=attrs)
        except Exception:
            pass

    def gauge_set(self, name: str, value: float, **labels: str) -> None:
        # В OTel нет "settable gauge"; используем UpDownCounter и pseudo-set через дельту.
        instr, attrs = self._updown(name, labels)
        try:
            # В простом варианте — add абсолютную величину в отдельном атрибуте "value".
            # Если нужен настоящий set, рекомендуется использовать ObservableGauge на сборщике.
            instr.add(value, attributes={**attrs, "_mode": "set"})
        except Exception:
            pass

    def gauge_inc(self, name: str, value: float = 1.0, **labels: str) -> None:
        instr, attrs = self._updown(name, labels)
        try:
            instr.add(value, attributes=attrs)
        except Exception:
            pass

    def gauge_dec(self, name: str, value: float = 1.0, **labels: str) -> None:
        instr, attrs = self._updown(name, labels)
        try:
            instr.add(-value, attributes=attrs)
        except Exception:
            pass

    # --- internals ---
    def _canon_labels(self, labels: Mapping[str, str]) -> Tuple[Tuple[str, ...], Mapping[str, str]]:
        if not labels:
            return tuple(), {}
        items = []
        for k, v in labels.items():
            kk = _sanitize_label_key(k)
            vv = _sanitize_label_value(str(v), allow_raw=(kk.lower() in self.allow_raw))
            items.append((kk, vv))
        items.sort(key=lambda kv: kv[0])
        keys = tuple(k for k, _ in items)
        attrs = {k: v for k, v in items}
        return keys, attrs

    def _counter(self, name: str, labels: Mapping[str, str]):
        mname = _sanitize_name(name)
        keys, attrs = self._canon_labels(labels)
        cache_key = (mname, keys)
        with self._lock:
            instr = self._counters.get(cache_key)
            if instr is None:
                instr = self._meter.create_counter(mname)
                self._counters[cache_key] = instr
        return instr, attrs

    def _histogram(self, name: str, labels: Mapping[str, str]):
        mname = _sanitize_name(name)
        keys, attrs = self._canon_labels(labels)
        cache_key = (mname, keys)
        with self._lock:
            instr = self._hists.get(cache_key)
            if instr is None:
                instr = self._meter.create_histogram(mname)
                self._hists[cache_key] = instr
        return instr, attrs

    def _updown(self, name: str, labels: Mapping[str, str]):
        mname = _sanitize_name(name)
        keys, attrs = self._canon_labels(labels)
        cache_key = (mname, keys)
        with self._lock:
            instr = self._updowns.get(cache_key)
            if instr is None:
                instr = self._meter.create_up_down_counter(mname)
                self._updowns[cache_key] = instr
        return instr, attrs


# ------------------------------
# Композитный и No-op эмиттеры
# ------------------------------

class CompositeEmitter(MetricsEmitter):
    def __init__(self, *emitters: MetricsEmitter) -> None:
        self._emitters = emitters

    def increment(self, name: str, value: float = 1.0, **labels: str) -> None:
        for e in self._emitters:
            try: e.increment(name, value, **labels)
            except Exception: pass

    def observe(self, name: str, value: float, buckets: Optional[Sequence[float]] = None, **labels: str) -> None:
        for e in self._emitters:
            try: e.observe(name, value, buckets=buckets, **labels)
            except Exception: pass

    def gauge_set(self, name: str, value: float, **labels: str) -> None:
        for e in self._emitters:
            try: e.gauge_set(name, value, **labels)
            except Exception: pass

    def gauge_inc(self, name: str, value: float = 1.0, **labels: str) -> None:
        for e in self._emitters:
            try: e.gauge_inc(name, value, **labels)
            except Exception: pass

    def gauge_dec(self, name: str, value: float = 1.0, **labels: str) -> None:
        for e in self._emitters:
            try: e.gauge_dec(name, value, **labels)
            except Exception: pass


class NoopEmitter(MetricsEmitter):
    def increment(self, name: str, value: float = 1.0, **labels: str) -> None:  # pragma: no cover
        return
    def observe(self, name: str, value: float, buckets: Optional[Sequence[float]] = None, **labels: str) -> None:  # pragma: no cover
        return
    def gauge_set(self, name: str, value: float, **labels: str) -> None:  # pragma: no cover
        return
    def gauge_inc(self, name: str, value: float = 1.0, **labels: str) -> None:  # pragma: no cover
        return
    def gauge_dec(self, name: str, value: float = 1.0, **labels: str) -> None:  # pragma: no cover
        return


# ------------------------------
# Глобальный по умолчанию эмиттер + init
# ------------------------------

_default_emitter: MetricsEmitter = NoopEmitter()
_default_lock = threading.RLock()

def set_default_emitter(emitter: MetricsEmitter) -> None:
    global _default_emitter
    with _default_lock:
        _default_emitter = emitter

def get_default_emitter() -> MetricsEmitter:
    return _default_emitter

def init_default_emitter(
    *,
    backend: Optional[str] = None,
    namespace: Optional[str] = None,
    subsystem: Optional[str] = None,
    label_allow_raw: Sequence[str] = (),
    default_buckets: Sequence[float] = _DEFAULT_LATENCY_BUCKETS,
) -> MetricsEmitter:
    """
    Автоинициализация из кода/окружения.
    Параметры также читаются из:
        NEUROFORGE_METRICS_BACKEND = "prometheus"|"otel"|"composite"|"none"
        PROMETHEUS_NAMESPACE, PROMETHEUS_SUBSYSTEM
    """
    be = (backend or os.environ.get("NEUROFORGE_METRICS_BACKEND") or "prometheus").lower()
    ns = namespace or os.environ.get("PROMETHEUS_NAMESPACE") or None
    ss = subsystem or os.environ.get("PROMETHEUS_SUBSYSTEM") or None

    emitter: MetricsEmitter
    try:
        if be == "prometheus":
            emitter = PrometheusEmitter(namespace=ns, subsystem=ss, label_allow_raw=label_allow_raw, default_buckets=default_buckets)
        elif be == "otel":
            emitter = OpenTelemetryEmitter(meter_name=(ns or "neuroforge-core"), label_allow_raw=label_allow_raw)
        elif be == "composite":
            # Пробуем оба, что доступно
            parts = []
            if _HAVE_PROM:
                parts.append(PrometheusEmitter(namespace=ns, subsystem=ss, label_allow_raw=label_allow_raw, default_buckets=default_buckets))
            if _HAVE_OTEL:
                parts.append(OpenTelemetryEmitter(meter_name=(ns or "neuroforge-core"), label_allow_raw=label_allow_raw))
            emitter = CompositeEmitter(*parts) if parts else NoopEmitter()
        else:
            emitter = NoopEmitter()
    except Exception:
        emitter = NoopEmitter()

    set_default_emitter(emitter)
    return emitter


# ------------------------------
# Удобные фасады
# ------------------------------

def increment(name: str, value: float = 1.0, **labels: str) -> None:
    get_default_emitter().increment(name, value, **labels)

def observe(name: str, value: float, buckets: Optional[Sequence[float]] = None, **labels: str) -> None:
    get_default_emitter().observe(name, value, buckets=buckets, **labels)

def gauge_set(name: str, value: float, **labels: str) -> None:
    get_default_emitter().gauge_set(name, value, **labels)

def gauge_inc(name: str, value: float = 1.0, **labels: str) -> None:
    get_default_emitter().gauge_inc(name, value, **labels)

def gauge_dec(name: str, value: float = 1.0, **labels: str) -> None:
    get_default_emitter().gauge_dec(name, value, **labels)


# ------------------------------
# Таймеры/декораторы
# ------------------------------

@dataclass
class _TimerOptions:
    metric_name: str
    labels: Mapping[str, str]
    buckets: Optional[Sequence[float]]
    count_errors: bool
    error_metric: Optional[str]
    error_labels: Mapping[str, str]

@contextmanager
def timer(metric_name: str,
          *,
          labels: Optional[Mapping[str, str]] = None,
          buckets: Optional[Sequence[float]] = None,
          count_errors: bool = True,
          error_metric: Optional[str] = None,
          error_labels: Optional[Mapping[str, str]] = None):
    """
    Контекст-таймер: измеряет длительность блока и пишет в histogram.
    При исключении, если count_errors=True, инкрементит error_metric (или <metric_name>_errors_total).
    """
    opts = _TimerOptions(
        metric_name=metric_name,
        labels=labels or {},
        buckets=buckets,
        count_errors=count_errors,
        error_metric=error_metric or f"{_sanitize_name(metric_name)}_errors_total",
        error_labels=error_labels or {},
    )
    t0 = time.perf_counter()
    try:
        yield
    except Exception as e:
        if opts.count_errors:
            increment(opts.error_metric, 1.0, **{**opts.error_labels, "exc": type(e).__name__})
        raise
    finally:
        dt = time.perf_counter() - t0
        observe(opts.metric_name, dt, buckets=opts.buckets, **opts.labels)

def track_operation(metric_name: str,
                    *,
                    labels: Optional[Callable[..., Mapping[str, str]]] = None,
                    buckets: Optional[Sequence[float]] = None,
                    count_errors: bool = True,
                    error_metric: Optional[str] = None,
                    error_labels: Optional[Callable[..., Mapping[str, str]]] = None):
    """
    Декоратор для функций/корутин: измеряет длительность вызова.
    labels / error_labels — функции, принимающие (args, kwargs) и возвращающие словарь лейблов.
    """
    def deco(fn: Callable):
        is_async = hasattr(fn, "__call__") and hasattr(fn, "__await__") or hasattr(fn, "__anext__")

        @wraps(fn)
        def _sync(*args, **kwargs):
            lbs = (labels(*args, **kwargs) if labels else {})  # type: ignore
            errs = (error_labels(*args, **kwargs) if error_labels else {})  # type: ignore
            with timer(metric_name, labels=lbs, buckets=buckets, count_errors=count_errors,
                       error_metric=error_metric, error_labels=errs):
                return fn(*args, **kwargs)

        @wraps(fn)
        async def _async(*args, **kwargs):
            lbs = (labels(*args, **kwargs) if labels else {})  # type: ignore
            errs = (error_labels(*args, **kwargs) if error_labels else {})  # type: ignore
            t0 = time.perf_counter()
            try:
                return await fn(*args, **kwargs)
            except Exception as e:
                if count_errors:
                    increment(error_metric or f"{_sanitize_name(metric_name)}_errors_total",
                              1.0, **{**errs, "exc": type(e).__name__})
                raise
            finally:
                dt = time.perf_counter() - t0
                observe(metric_name, dt, buckets=buckets, **lbs)

        return _async if _is_coro(fn) else _sync
    return deco

def _is_coro(fn: Callable) -> bool:
    import inspect
    return inspect.iscoroutinefunction(fn)


# ------------------------------
# Готовые пресеты бакетов
# ------------------------------

LATENCY_BUCKETS_DEFAULT = _DEFAULT_LATENCY_BUCKETS
LATENCY_BUCKETS_DB = (0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 1, 2.5)
LATENCY_BUCKETS_EXTERNAL = (0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30)

__all__ = [
    "MetricsEmitter",
    "PrometheusEmitter",
    "OpenTelemetryEmitter",
    "CompositeEmitter",
    "NoopEmitter",
    "init_default_emitter",
    "set_default_emitter",
    "get_default_emitter",
    "increment",
    "observe",
    "gauge_set",
    "gauge_inc",
    "gauge_dec",
    "timer",
    "track_operation",
    "LATENCY_BUCKETS_DEFAULT",
    "LATENCY_BUCKETS_DB",
    "LATENCY_BUCKETS_EXTERNAL",
]
