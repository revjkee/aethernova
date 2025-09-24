# -*- coding: utf-8 -*-
"""
adapters.observability_adapter
------------------------------

Единый промышленный адаптер наблюдаемости (метрики, трейсы, события) для DataFabric.

Возможности:
- Унифицированный API: counters, gauges, histograms; spans; event logs
- Провайдеры: OpenTelemetry, Prometheus client, StatsD, No-op
- Мягкие импорты (без жестких зависимостей), безопасная деградация
- Асинхронные хелперы: таймеры, контекст-менеджеры, декоратор @observed
- Кэширование инструментов метрик, минимизация аллокаций в горячем пути
- Correlation-идентификаторы через contextvars (request_id, trace_id)
- Сэмплинг событий (probabilistic), теги/атрибуты, поддержка high-cardinality safe-тегов
- Structured logging hook (через стандартный logging), без дублей

© DataFabric Core. MIT License.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import logging
import os
import random
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Mapping, MutableMapping, Optional, Tuple
from contextlib import asynccontextmanager, contextmanager
import contextvars

# ------------------------------- Логгер --------------------------------------

logger = logging.getLogger("datafabric.adapters.observability")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# ---------------------------- Контекст запроса -------------------------------

_request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("df_request_id", default="")
_trace_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("df_trace_id", default="")

def set_request_id(request_id: Optional[str] = None) -> str:
    rid = request_id or uuid.uuid4().hex
    _request_id_ctx.set(rid)
    return rid

def set_trace_id(trace_id: Optional[str] = None) -> str:
    tid = trace_id or uuid.uuid4().hex
    _trace_id_ctx.set(tid)
    return tid

def get_request_id() -> str:
    return _request_id_ctx.get()

def get_trace_id() -> str:
    return _trace_id_ctx.get()

# ------------------------------ Конфигурация ---------------------------------

@dataclass(frozen=True)
class ObservabilityConfig:
    provider: str = field(default_factory=lambda: os.getenv("DF_OBS_PROVIDER", "noop"))  # "otel"|"prom"|"statsd"|"noop"
    service_name: str = field(default_factory=lambda: os.getenv("DF_SERVICE_NAME", "datafabric"))
    service_namespace: str = "datafabric"
    service_version: str = "0.0.0"
    # Метрики
    metrics_prefix: str = "df"
    # Сэмплинг событий/логов
    event_sample_rate: float = 1.0  # 0..1
    # Разрешить high-cardinality теги (может привести к росту метрик)
    allow_high_cardinality_tags: bool = False
    # Настройки провайдеров (свободные поля)
    otel_endpoint: Optional[str] = None      # OTLP/HTTP или gRPC endpoint, если применяется
    prom_namespace: Optional[str] = None
    statsd_host: str = "127.0.0.1"
    statsd_port: int = 8125
    # Встроенный лог событий
    enable_event_logging: bool = True


# ------------------------------ Интерфейс ------------------------------------

class Observability:
    """
    Унифицированный интерфейс. Везде используйте только эти методы.
    """
    def counter(self, name: str, *, description: str = "", unit: str = "", tags: Optional[Mapping[str, str]] = None) -> Callable[[float, Optional[Mapping[str, str]]], None]:
        raise NotImplementedError

    def gauge(self, name: str, *, description: str = "", unit: str = "", tags: Optional[Mapping[str, str]] = None) -> Callable[[float, Optional[Mapping[str, str]]], None]:
        raise NotImplementedError

    def histogram(self, name: str, *, description: str = "", unit: str = "", tags: Optional[Mapping[str, str]] = None) -> Callable[[float, Optional[Mapping[str, str]]], None]:
        raise NotImplementedError

    @contextmanager
    def span(self, name: str, *, attributes: Optional[Mapping[str, Any]] = None):
        raise NotImplementedError

    @asynccontextmanager
    async def aspawn(self, name: str, *, attributes: Optional[Mapping[str, Any]] = None):
        raise NotImplementedError

    def event(self, name: str, *, attributes: Optional[Mapping[str, Any]] = None, level: int = logging.INFO, sample_rate: Optional[float] = None) -> None:
        raise NotImplementedError

    async def shutdown(self) -> None:
        raise NotImplementedError


# ------------------------- Кэш инструментов метрик ---------------------------

class _MetricCache:
    def __init__(self) -> None:
        self._counters: MutableMapping[str, Any] = {}
        self._gauges: MutableMapping[str, Any] = {}
        self._hist: MutableMapping[str, Any] = {}

    def key(self, name: str, tags: Optional[Mapping[str, str]]) -> str:
        if not tags:
            return name
        # Важно: порядок тегов фиксируем
        items = ",".join(f"{k}={v}" for k, v in sorted(tags.items()))
        return f"{name}|{items}"


# ------------------------ Провайдер: No-op (по умолчанию) --------------------

class NoopProvider(Observability):
    def __init__(self, cfg: ObservabilityConfig) -> None:
        self.cfg = cfg
        self._cache = _MetricCache()

    def counter(self, name: str, *, description: str = "", unit: str = "", tags: Optional[Mapping[str, str]] = None):
        def _inc(value: float = 1.0, extra_tags: Optional[Mapping[str, str]] = None) -> None:
            return
        return _inc

    def gauge(self, name: str, *, description: str = "", unit: str = "", tags: Optional[Mapping[str, str]] = None):
        def _set(value: float, extra_tags: Optional[Mapping[str, str]] = None) -> None:
            return
        return _set

    def histogram(self, name: str, *, description: str = "", unit: str = "", tags: Optional[Mapping[str, str]] = None):
        def _obs(value: float, extra_tags: Optional[Mapping[str, str]] = None) -> None:
            return
        return _obs

    @contextmanager
    def span(self, name: str, *, attributes: Optional[Mapping[str, Any]] = None):
        yield

    @asynccontextmanager
    async def aspawn(self, name: str, *, attributes: Optional[Mapping[str, Any]] = None):
        yield

    def event(self, name: str, *, attributes: Optional[Mapping[str, Any]] = None, level: int = logging.INFO, sample_rate: Optional[float] = None) -> None:
        if not self.cfg.enable_event_logging:
            return
        # Даже в no-op режиме полезно вывести структурированный лог
        sr = self.cfg.event_sample_rate if sample_rate is None else sample_rate
        if sr >= 1.0 or random.random() < max(0.0, min(1.0, sr)):
            logger.log(level, "event=%s service=%s trace_id=%s request_id=%s attrs=%s",
                       name, self.cfg.service_name, get_trace_id(), get_request_id(), dict(attributes or {}))

    async def shutdown(self) -> None:
        return


# --------------------------- Провайдер: OpenTelemetry ------------------------

class OtelProvider(Observability):
    def __init__(self, cfg: ObservabilityConfig) -> None:
        self.cfg = cfg
        # Мягкие импорты
        try:
            from opentelemetry import metrics as _metrics  # type: ignore
            from opentelemetry import trace as _trace  # type: ignore
            from opentelemetry.sdk.resources import Resource  # type: ignore
            from opentelemetry.sdk.metrics import MeterProvider  # type: ignore
            from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader  # type: ignore
            from opentelemetry.sdk.trace import TracerProvider  # type: ignore
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter  # type: ignore
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter  # type: ignore
            from opentelemetry.sdk.trace.export import BatchSpanProcessor  # type: ignore
        except Exception as e:  # pragma: no cover
            logger.warning("OpenTelemetry not available, falling back to Noop.")
            raise

        resource = Resource.create({
            "service.name": cfg.service_name,
            "service.namespace": cfg.service_namespace,
            "service.version": cfg.service_version,
        })

        # Метрики
        reader = PeriodicExportingMetricReader(OTLPMetricExporter(endpoint=cfg.otel_endpoint) if cfg.otel_endpoint else OTLPMetricExporter())
        meter_provider = MeterProvider(resource=resource, metric_readers=[reader])
        _metrics.set_meter_provider(meter_provider)
        self._meter = _metrics.get_meter(cfg.service_name)
        # Трейсы
        tracer_provider = TracerProvider(resource=resource)
        tracer_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=cfg.otel_endpoint) if cfg.otel_endpoint else OTLPSpanExporter()))
        _trace.set_tracer_provider(tracer_provider)
        self._tracer = _trace.get_tracer(cfg.service_name)

        self._cache = _MetricCache()
        self._metrics_mod = _metrics
        self._trace_mod = _trace
        self._tracer_provider = tracer_provider
        self._meter_provider = meter_provider

    def _labels(self, base: Optional[Mapping[str, str]], extra: Optional[Mapping[str, str]]) -> Dict[str, str]:
        tags = dict(base or {})
        tags.update(extra or {})
        if not self.cfg.allow_high_cardinality_tags:
            # простая защита от чрезмерной кардинальности: обнуляем request_id, если присутствует
            tags.pop("request_id", None)
        return tags

    def counter(self, name: str, *, description: str = "", unit: str = "", tags: Optional[Mapping[str, str]] = None):
        key = self._cache.key(name, tags)
        inst = self._cache._counters.get(key)
        if inst is None:
            inst = self._meter.create_counter(name, unit=unit or "1", description=description)
            self._cache._counters[key] = (inst, tags or {})
        counter, base_tags = self._cache._counters[key]
        def _inc(value: float = 1.0, extra_tags: Optional[Mapping[str, str]] = None) -> None:
            counter.add(float(value), attributes=self._labels(base_tags, extra_tags))
        return _inc

    def gauge(self, name: str, *, description: str = "", unit: str = "", tags: Optional[Mapping[str, str]] = None):
        # В OTel SDK нет "gauge" как синхронной метрики — используем ObservableGauge pull-модель.
        key = self._cache.key(name, tags)
        if key not in self._cache._gauges:
            latest_val: Dict[str, float] = {"v": 0.0}
            base_tags = dict(tags or {})
            def _callback(_obs):
                _obs.observe(latest_val["v"], attributes=self._labels(base_tags, None))
            self._meter.create_observable_gauge(name, callbacks=[_callback], description=description, unit=unit or "1")
            self._cache._gauges[key] = (latest_val, base_tags)
        latest_val, base_tags = self._cache._gauges[key]
        def _set(value: float, extra_tags: Optional[Mapping[str, str]] = None) -> None:
            # Для OTel мы игнорируем extra_tags (pull модель), но храним одну линию
            latest_val["v"] = float(value)
        return _set

    def histogram(self, name: str, *, description: str = "", unit: str = "", tags: Optional[Mapping[str, str]] = None):
        key = self._cache.key(name, tags)
        inst = self._cache._hist.get(key)
        if inst is None:
            inst = self._meter.create_histogram(name, unit=unit or "ms", description=description)
            self._cache._hist[key] = (inst, tags or {})
        hist, base_tags = self._cache._hist[key]
        def _obs(value: float, extra_tags: Optional[Mapping[str, str]] = None) -> None:
            hist.record(float(value), attributes=self._labels(base_tags, extra_tags))
        return _obs

    @contextmanager
    def span(self, name: str, *, attributes: Optional[Mapping[str, Any]] = None):
        ctx_attrs = {"request_id": get_request_id()}
        ctx_attrs.update(attributes or {})
        with self._tracer.start_as_current_span(name, attributes=ctx_attrs) as sp:
            yield sp

    @asynccontextmanager
    async def aspawn(self, name: str, *, attributes: Optional[Mapping[str, Any]] = None):
        with self.span(name, attributes=attributes) as sp:
            yield sp

    def event(self, name: str, *, attributes: Optional[Mapping[str, Any]] = None, level: int = logging.INFO, sample_rate: Optional[float] = None) -> None:
        sr = self.cfg.event_sample_rate if sample_rate is None else sample_rate
        if sr < 1.0 and random.random() >= max(0.0, min(1.0, sr)):
            return
        # Добавляем в текущий span, если он есть
        try:
            current_span = self._trace_mod.get_current_span()
            if current_span is not None:
                attrs = dict(attributes or {})
                attrs.setdefault("request_id", get_request_id())
                attrs.setdefault("service", self.cfg.service_name)
                current_span.add_event(name, attributes=attrs)
        except Exception:
            pass
        if self.cfg.enable_event_logging:
            logger.log(level, "event=%s service=%s trace_id=%s request_id=%s attrs=%s",
                       name, self.cfg.service_name, get_trace_id(), get_request_id(), dict(attributes or {}))

    async def shutdown(self) -> None:
        with contextlib.suppress(Exception):
            self._tracer_provider.shutdown()  # type: ignore
        with contextlib.suppress(Exception):
            self._meter_provider.shutdown()  # type: ignore


# ----------------------------- Провайдер: Prometheus -------------------------

class PromProvider(Observability):
    def __init__(self, cfg: ObservabilityConfig) -> None:
        self.cfg = cfg
        try:
            from prometheus_client import Counter, Gauge, Histogram, CollectorRegistry  # type: ignore
        except Exception as e:
            logger.warning("prometheus_client not available, falling back to Noop.")
            raise
        self._Counter = Counter
        self._Gauge = Gauge
        self._Histogram = Histogram
        self._reg = CollectorRegistry()
        self._cache = _MetricCache()
        self._namespace = cfg.prom_namespace or cfg.metrics_prefix

    def _labelnames(self, tags: Optional[Mapping[str, str]]) -> Tuple[str, ...]:
        if not tags:
            return tuple()
        names = tuple(sorted(tags.keys()))
        if not self.cfg.allow_high_cardinality_tags and "request_id" in names:
            names = tuple(x for x in names if x != "request_id")
        return names

    def counter(self, name: str, *, description: str = "", unit: str = "", tags: Optional[Mapping[str, str]] = None):
        key = self._cache.key(name, tags)
        inst = self._cache._counters.get(key)
        if inst is None:
            labelnames = self._labelnames(tags)
            c = self._Counter(f"{self._namespace}_{name}", description or name, labelnames=labelnames, registry=self._reg)
            self._cache._counters[key] = (c, tags or {}, labelnames)
        c, base_tags, labelnames = self._cache._counters[key]
        def _inc(value: float = 1.0, extra_tags: Optional[Mapping[str, str]] = None) -> None:
            labels = dict(base_tags)
            labels.update(extra_tags or {})
            labels = {k: v for k, v in labels.items() if k in labelnames}
            c.labels(**labels).inc(float(value)) if labelnames else c.inc(float(value))
        return _inc

    def gauge(self, name: str, *, description: str = "", unit: str = "", tags: Optional[Mapping[str, str]] = None):
        key = self._cache.key(name, tags)
        inst = self._cache._gauges.get(key)
        if inst is None:
            labelnames = self._labelnames(tags)
            g = self._Gauge(f"{self._namespace}_{name}", description or name, labelnames=labelnames, registry=self._reg)
            self._cache._gauges[key] = (g, tags or {}, labelnames)
        g, base_tags, labelnames = self._cache._gauges[key]
        def _set(value: float, extra_tags: Optional[Mapping[str, str]] = None) -> None:
            labels = dict(base_tags)
            labels.update(extra_tags or {})
            labels = {k: v for k, v in labels.items() if k in labelnames}
            g.labels(**labels).set(float(value)) if labelnames else g.set(float(value))
        return _set

    def histogram(self, name: str, *, description: str = "", unit: str = "", tags: Optional[Mapping[str, str]] = None):
        key = self._cache.key(name, tags)
        inst = self._cache._hist.get(key)
        if inst is None:
            labelnames = self._labelnames(tags)
            h = self._Histogram(f"{self._namespace}_{name}", description or name, labelnames=labelnames, registry=self._reg)
            self._cache._hist[key] = (h, tags or {}, labelnames)
        h, base_tags, labelnames = self._cache._hist[key]
        def _obs(value: float, extra_tags: Optional[Mapping[str, str]] = None) -> None:
            labels = dict(base_tags)
            labels.update(extra_tags or {})
            labels = {k: v for k, v in labels.items() if k in labelnames}
            h.labels(**labels).observe(float(value)) if labelnames else h.observe(float(value))
        return _obs

    @contextmanager
    def span(self, name: str, *, attributes: Optional[Mapping[str, Any]] = None):
        # В Prometheus нет трейсинга — используем структурированный лог + таймер
        t0 = time.time()
        try:
            yield None
        finally:
            dur_ms = (time.time() - t0) * 1000.0
            logger.info("span name=%s duration_ms=%.3f attrs=%s request_id=%s", name, dur_ms, dict(attributes or {}), get_request_id())

    @asynccontextmanager
    async def aspawn(self, name: str, *, attributes: Optional[Mapping[str, Any]] = None):
        with self.span(name, attributes=attributes):
            yield None

    def event(self, name: str, *, attributes: Optional[Mapping[str, Any]] = None, level: int = logging.INFO, sample_rate: Optional[float] = None) -> None:
        sr = sample_rate if sample_rate is not None else 1.0
        if sr >= 1.0 or random.random() < max(0.0, min(1.0, sr)):
            logger.log(level, "event=%s service=%s request_id=%s attrs=%s", name, self.cfg.service_name, get_request_id(), dict(attributes or {}))

    async def shutdown(self) -> None:
        return


# ------------------------------ Провайдер: StatsD ----------------------------

class StatsdProvider(Observability):
    def __init__(self, cfg: ObservabilityConfig) -> None:
        self.cfg = cfg
        try:
            from statsd import StatsClient  # type: ignore
        except Exception as e:
            logger.warning("statsd client not available, falling back to Noop.")
            raise
        self._client = StatsClient(host=cfg.statsd_host, port=cfg.statsd_port, prefix=cfg.metrics_prefix)

    def counter(self, name: str, *, description: str = "", unit: str = "", tags: Optional[Mapping[str, str]] = None):
        def _inc(value: float = 1.0, extra_tags: Optional[Mapping[str, str]] = None):
            self._client.incr(name, int(value))
        return _inc

    def gauge(self, name: str, *, description: str = "", unit: str = "", tags: Optional[Mapping[str, str]] = None):
        def _set(value: float, extra_tags: Optional[Mapping[str, str]] = None):
            self._client.gauge(name, float(value))
        return _set

    def histogram(self, name: str, *, description: str = "", unit: str = "", tags: Optional[Mapping[str, str]] = None):
        def _obs(value: float, extra_tags: Optional[Mapping[str, str]] = None):
            # Многие StatsD не имеют histogram; используем timing
            self._client.timing(name, float(value))
        return _obs

    @contextmanager
    def span(self, name: str, *, attributes: Optional[Mapping[str, Any]] = None):
        t0 = time.time()
        try:
            yield None
        finally:
            dur_ms = (time.time() - t0) * 1000.0
            self._client.timing(f"{name}.duration_ms", dur_ms)

    @asynccontextmanager
    async def aspawn(self, name: str, *, attributes: Optional[Mapping[str, Any]] = None):
        with self.span(name, attributes=attributes):
            yield None

    def event(self, name: str, *, attributes: Optional[Mapping[str, Any]] = None, level: int = logging.INFO, sample_rate: Optional[float] = None) -> None:
        logger.log(level, "event=%s service=%s request_id=%s attrs=%s", name, self.cfg.service_name, get_request_id(), dict(attributes or {}))

    async def shutdown(self) -> None:
        return


# ------------------------------- Фасад/фабрика -------------------------------

class ObservabilityAdapter(Observability):
    """
    Фасад. Создает конкретного провайдера в зависимости от конфигурации/окружения.
    """
    def __init__(self, cfg: Optional[ObservabilityConfig] = None) -> None:
        self.cfg = cfg or ObservabilityConfig()
        self._impl: Observability = self._make_impl(self.cfg)

        # Базовые инструменты (кэшируются пользователями адаптера)
        self._counter_errors = self.counter("errors_total", description="Total errors", tags={"service": self.cfg.service_name})
        self._hist_latency = self.histogram("latency_ms", description="Operation latency", unit="ms", tags={"service": self.cfg.service_name})

    def _make_impl(self, cfg: ObservabilityConfig) -> Observability:
        prov = (cfg.provider or "noop").lower()
        with contextlib.suppress(Exception):
            if prov == "otel":
                return OtelProvider(cfg)
        with contextlib.suppress(Exception):
            if prov == "prom":
                return PromProvider(cfg)
        with contextlib.suppress(Exception):
            if prov == "statsd":
                return StatsdProvider(cfg)
        return NoopProvider(cfg)

    # ----- делегирование -----

    def counter(self, name: str, *, description: str = "", unit: str = "", tags: Optional[Mapping[str, str]] = None):
        return self._impl.counter(name, description=description, unit=unit, tags=tags)

    def gauge(self, name: str, *, description: str = "", unit: str = "", tags: Optional[Mapping[str, str]] = None):
        return self._impl.gauge(name, description=description, unit=unit, tags=tags)

    def histogram(self, name: str, *, description: str = "", unit: str = "", tags: Optional[Mapping[str, str]] = None):
        return self._impl.histogram(name, description=description, unit=unit, tags=tags)

    @contextmanager
    def span(self, name: str, *, attributes: Optional[Mapping[str, Any]] = None):
        with self._impl.span(name, attributes=attributes) as sp:
            yield sp

    @asynccontextmanager
    async def aspawn(self, name: str, *, attributes: Optional[Mapping[str, Any]] = None):
        async with self._impl.aspawn(name, attributes=attributes) as sp:
            yield sp

    def event(self, name: str, *, attributes: Optional[Mapping[str, Any]] = None, level: int = logging.INFO, sample_rate: Optional[float] = None) -> None:
        return self._impl.event(name, attributes=attributes, level=level, sample_rate=sample_rate)

    async def shutdown(self) -> None:
        await self._impl.shutdown()

    # --------------------- Декораторы/утилиты высокого уровня -----------------

    def observed(self, name: Optional[str] = None, *, attrs: Optional[Mapping[str, Any]] = None, record_exceptions: bool = True):
        """
        Декоратор для измерения латентности/ошибок + span.
        Пример:
            @obs.observed("load_dataset", attrs={"component": "metadata"})
            async def load_dataset(...): ...
        """
        def _decor(func: Callable):
            fname = name or func.__name__
            if asyncio.iscoroutinefunction(func):
                @functools.wraps(func)
                async def _aw(*a, **kw):
                    t0 = time.time()
                    try:
                        async with self.aspawn(fname, attributes=attrs):
                            return await func(*a, **kw)
                    except Exception:
                        if record_exceptions:
                            self._counter_errors(1.0, {"fn": fname})
                            self.event("exception", attributes={"fn": fname}, level=logging.ERROR, sample_rate=1.0)
                        raise
                    finally:
                        self._hist_latency((time.time() - t0) * 1000.0, {"fn": fname})
                return _aw
            else:
                @functools.wraps(func)
                def _w(*a, **kw):
                    t0 = time.time()
                    try:
                        with self.span(fname, attributes=attrs):
                            return func(*a, **kw)
                    except Exception:
                        if record_exceptions:
                            self._counter_errors(1.0, {"fn": fname})
                            self.event("exception", attributes={"fn": fname}, level=logging.ERROR, sample_rate=1.0)
                        raise
                    finally:
                        self._hist_latency((time.time() - t0) * 1000.0, {"fn": fname})
                return _w
        return _decor


# ------------------------------- Self-test -----------------------------------

async def _selftest() -> None:
    # No-op
    obs = ObservabilityAdapter(ObservabilityConfig(provider="noop", service_name="df-core"))
    rid = set_request_id("req-123")
    tid = set_trace_id("trace-xyz")
    c = obs.counter("tests_total", tags={"component": "observability"})
    g = obs.gauge("queue_depth", tags={"component": "observability"})
    h = obs.histogram("step_ms", unit="ms", tags={"component": "observability"})

    @obs.observed("async_step", attrs={"component": "observability"})
    async def async_step():
        await asyncio.sleep(0.01)
        c(1)
        g(42)
        h(12.3)

    with obs.span("sync_step", attributes={"k": "v"}):
        c(2, {"phase": "sync"})

    await async_step()
    obs.event("selftest_complete", attributes={"rid": rid, "tid": tid})
    await obs.shutdown()

if __name__ == "__main__":  # pragma: no cover
    try:
        asyncio.run(_selftest())
        print("ObservabilityAdapter selftest passed.")
    except Exception as e:
        print(f"ObservabilityAdapter selftest failed: {e}")
