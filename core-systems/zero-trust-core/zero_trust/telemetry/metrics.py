# -*- coding: utf-8 -*-
"""
Zero Trust Core — Telemetry Metrics
Промышленный модуль метрик с безопасной обработкой контекста и PII,
адаптерами Prometheus/OTLP и продвинутой защитой от ошибок интеграции.

Особенности:
- Единый потокобезопасный реестр метрик с валидацией и freeze().
- Типы: Counter, Gauge, Histogram. Единый API с строгой типизацией.
- Контекст (contextvars): tenant_id, request_id, session_id, trace_id, component.
- Санитизация лейблов, ограничение кардинальности, хеширование PII (SHA256 + соль).
- Экспортеры: Prometheus (pull), OTLP (push) — включаются/комбинируются через ENV.
- Fallback: если нет зависимостей, используется NoOpExporter без падений.
- Async‑дружелюбность, безопасная инициализация, sampling.
- Конфигурация через переменные окружения (ZT_*).

ENV переменные (с разумными дефолтами):
- ZT_METRICS_EXPORTER=prometheus|otlp|both|noop (default: prometheus при наличии prometheus_client иначе noop)
- ZT_PROMETHEUS_PORT=9464
- ZT_PROMETHEUS_ADDR=0.0.0.0
- ZT_OTLP_ENDPOINT=http://localhost:4318
- ZT_ENV=prod|staging|dev (default: dev)
- ZT_REGION=eu-north-1 (пример)
- ZT_SERVICE=zero-trust-core
- ZT_VERSION=1.0.0
- ZT_COMPONENT=telemetry
- ZT_PII_SALT=<строка-соли> (опционально)
- ZT_METRICS_SAMPLE=1.0 (0.0..1.0)
- ZT_LABEL_MAX=12 (макс. кол-во пользовательских лейблов)
- ZT_VALUE_MAX_LEN=128 (ограничение длины значений лейблов)
- ZT_NAME_MAX_LEN=120 (ограничение длины имен метрик)
- ZT_FREEZE_AFTER_INIT=true|false (default: true)

Зависимости (опционально):
- prometheus_client (для PrometheusExport)
- opentelemetry-sdk, opentelemetry-exporter-otlp (для OTLPExport)
"""
from __future__ import annotations

import os
import re
import sys
import json
import time
import math
import hashlib
import random
import threading
import contextvars
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

# ---------- Optional deps detection ----------
try:
    from prometheus_client import Counter as PCounter
    from prometheus_client import Gauge as PGauge
    from prometheus_client import Histogram as PHistogram
    from prometheus_client import CollectorRegistry, start_http_server
    _HAS_PROM = True
except Exception:  # pragma: no cover
    _HAS_PROM = False

try:
    # OTel metrics stable API (SDK 1.27+)
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
    from opentelemetry.metrics import get_meter_provider, set_meter_provider
    from opentelemetry.metrics import Meter
    from opentelemetry.metrics import CallbackOptions
    _HAS_OTEL = True
except Exception:  # pragma: no cover
    _HAS_OTEL = False


# ---------- Config helpers ----------
def _env(name: str, default: str) -> str:
    return os.getenv(name, default)


def _env_float(name: str, default: float) -> float:
    v = os.getenv(name)
    if v is None:
        return default
    try:
        f = float(v)
        if f < 0.0:
            return 0.0
        if f > 1.0 and name == "ZT_METRICS_SAMPLE":
            return 1.0
        return f
    except Exception:
        return default


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None:
        return default
    try:
        return int(v)
    except Exception:
        return default


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")


# ---------- Safe context ----------
_ctx_tenant_id: contextvars.ContextVar[str] = contextvars.ContextVar("tenant_id", default="unknown")
_ctx_request_id: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="unknown")
_ctx_session_id: contextvars.ContextVar[str] = contextvars.ContextVar("session_id", default="unknown")
_ctx_trace_id: contextvars.ContextVar[str] = contextvars.ContextVar("trace_id", default="unknown")
_ctx_component: contextvars.ContextVar[str] = contextvars.ContextVar("component", default=_env("ZT_COMPONENT", "telemetry"))

def bind_context(
    tenant_id: Optional[str] = None,
    request_id: Optional[str] = None,
    session_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    component: Optional[str] = None,
) -> None:
    if tenant_id is not None:
        _ctx_tenant_id.set(tenant_id)
    if request_id is not None:
        _ctx_request_id.set(request_id)
    if session_id is not None:
        _ctx_session_id.set(session_id)
    if trace_id is not None:
        _ctx_trace_id.set(trace_id)
    if component is not None:
        _ctx_component.set(component)


# ---------- Security: sanitization & hashing ----------
_ALLOWED_NAME_RE = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")
_ALLOWED_LABEL_NAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
_SANITIZE_VAL_RE = re.compile(r"[^a-zA-Z0-9_.:\-@/ ]")
_MAX_LABELS = _env_int("ZT_LABEL_MAX", 12)
_MAX_VAL_LEN = _env_int("ZT_VALUE_MAX_LEN", 128)
_MAX_NAME_LEN = _env_int("ZT_NAME_MAX_LEN", 120)
_PII_SALT = _env("ZT_PII_SALT", "")

def _normalize_metric_name(name: str) -> str:
    name = name.strip().replace(" ", "_").replace("-", "_")
    if len(name) > _MAX_NAME_LEN:
        name = name[:_MAX_NAME_LEN]
    if not _ALLOWED_NAME_RE.match(name):
        # Префиксуем и фильтруем недопустимые символы
        name = "m_" + re.sub(r"[^a-zA-Z0-9_:]", "_", name)
    return name

def _normalize_label_name(name: str) -> str:
    name = name.strip().replace("-", "_")
    if len(name) > 64:
        name = name[:64]
    if not _ALLOWED_LABEL_NAME_RE.match(name):
        name = "l_" + re.sub(r"[^a-zA-Z0-9_]", "_", name)
    return name

def _sanitize_label_value(value: str) -> str:
    # Ограничиваем длину и состав
    v = value.strip()
    if len(v) > _MAX_VAL_LEN:
        v = v[:_MAX_VAL_LEN]
    v = _SANITIZE_VAL_RE.sub("_", v)
    return v if v else "unknown"

def _hash_pii(value: str) -> str:
    if not value:
        return "unknown"
    if not _PII_SALT:
        # Если нет соли, хешируем все равно (с пустой солью) — лучше, чем raw.
        salt = ""
    else:
        salt = _PII_SALT
    h = hashlib.sha256()
    h.update((salt + "::" + value).encode("utf-8"))
    return h.hexdigest()

def scrub_labels(labels: Mapping[str, Union[str, int, float]], pii_keys: Iterable[str] = ()) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if len(labels) > _MAX_LABELS:
        # Жестко защищаемся от кардинальности
        # Берем первые N, остальное отбрасываем детерминированно
        items = list(labels.items())[:_MAX_LABELS]
    else:
        items = labels.items()
    pii_set = set(_normalize_label_name(k) for k in pii_keys)
    for k, v in items:
        k_norm = _normalize_label_name(str(k))
        val = str(v)
        if k_norm in pii_set:
            val = _hash_pii(val)
        out[k_norm] = _sanitize_label_value(val)
    return out


# ---------- Metric types ----------
class MetricType(Enum):
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"


@dataclass(frozen=True)
class MetricDefinition:
    name: str
    description: str
    mtype: MetricType
    label_names: Tuple[str, ...] = field(default_factory=tuple)
    buckets: Optional[Tuple[float, ...]] = None  # для histogram
    pii_label_names: Tuple[str, ...] = field(default_factory=tuple)

    def normalized(self) -> "MetricDefinition":
        nname = _normalize_metric_name(self.name)
        lbls = tuple(_normalize_label_name(x) for x in self.label_names)
        pii_lbls = tuple(_normalize_label_name(x) for x in self.pii_label_names)
        if self.mtype is MetricType.HISTOGRAM and self.buckets:
            buckets = tuple(sorted(set(float(b) for b in self.buckets)))
        else:
            buckets = self.buckets
        return MetricDefinition(
            name=nname,
            description=self.description.strip(),
            mtype=self.mtype,
            label_names=lbls,
            buckets=buckets,
            pii_label_names=pii_lbls,
        )


# ---------- Exporter Abstraction ----------
class MetricHandle:
    def inc(self, amount: float = 1.0, labels: Optional[Mapping[str, Union[str, int, float]]] = None) -> None:
        raise NotImplementedError

    def set(self, value: float, labels: Optional[Mapping[str, Union[str, int, float]]] = None) -> None:
        raise NotImplementedError

    def observe(self, value: float, labels: Optional[Mapping[str, Union[str, int, float]]] = None) -> None:
        raise NotImplementedError


class Exporter:
    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def register(self, mdef: MetricDefinition) -> MetricHandle:
        raise NotImplementedError

    def enrich_labels(self, labels: Optional[Mapping[str, Union[str, int, float]]]) -> Dict[str, str]:
        # Добавляем стандартные лейблы контекста Zero Trust
        base = {
            "tenant_id": _hash_pii(_ctx_tenant_id.get()),
            "request_id": _sanitize_label_value(_ctx_request_id.get()),
            "session_id": _sanitize_label_value(_ctx_session_id.get()),
            "trace_id": _sanitize_label_value(_ctx_trace_id.get()),
            "component": _sanitize_label_value(_ctx_component.get()),
            "env": _sanitize_label_value(_env("ZT_ENV", "dev")),
            "region": _sanitize_label_value(_env("ZT_REGION", "unknown")),
            "service": _sanitize_label_value(_env("ZT_SERVICE", "zero-trust-core")),
            "version": _sanitize_label_value(_env("ZT_VERSION", "0.0.0")),
        }
        user = labels or {}
        # Применяем scrub включая PII флаги из mdef позднее в конкретных handle
        # Здесь только санитизация общих полей, если передали
        for k, v in user.items():
            k_norm = _normalize_label_name(str(k))
            base.setdefault(k_norm, _sanitize_label_value(str(v)))
        return base


# ---------- NoOp Exporter ----------
class NoOpHandle(MetricHandle):
    def inc(self, amount: float = 1.0, labels: Optional[Mapping[str, Union[str, int, float]]] = None) -> None:
        return

    def set(self, value: float, labels: Optional[Mapping[str, Union[str, int, float]]] = None) -> None:
        return

    def observe(self, value: float, labels: Optional[Mapping[str, Union[str, int, float]]] = None) -> None:
        return


class NoOpExporter(Exporter):
    def register(self, mdef: MetricDefinition) -> MetricHandle:
        return NoOpHandle()


# ---------- Prometheus Exporter ----------
class _PromHandle(MetricHandle):
    def __init__(self, mdef: MetricDefinition, impl: Union[PCounter, PGauge, PHistogram], exporter: "PrometheusExporter"):
        self._mdef = mdef
        self._impl = impl
        self._exp = exporter
        self._sample = _env_float("ZT_METRICS_SAMPLE", 1.0)

    def _labels(self, labels: Optional[Mapping[str, Union[str, int, float]]]) -> Dict[str, str]:
        enriched = self._exp.enrich_labels(labels)
        # применяем scrub с учетом PII
        return scrub_labels(enriched, pii_keys=self._mdef.pii_label_names)

    def _should_sample(self) -> bool:
        s = self._sample
        if s >= 1.0:
            return True
        return random.random() <= s

    def inc(self, amount: float = 1.0, labels: Optional[Mapping[str, Union[str, int, float]]] = None) -> None:
        if self._mdef.mtype is not MetricType.COUNTER or amount <= 0 or not self._should_sample():
            return
        self._impl.labels(**self._labels(labels)).inc(amount)

    def set(self, value: float, labels: Optional[Mapping[str, Union[str, int, float]]] = None) -> None:
        if self._mdef.mtype is not MetricType.GAUGE or not self._should_sample():
            return
        self._impl.labels(**self._labels(labels)).set(value)

    def observe(self, value: float, labels: Optional[Mapping[str, Union[str, int, float]]] = None) -> None:
        if self._mdef.mtype is not MetricType.HISTOGRAM or not self._should_sample():
            return
        self._impl.labels(**self._labels(labels)).observe(value)


class PrometheusExporter(Exporter):
    def __init__(self) -> None:
        if not _HAS_PROM:
            raise RuntimeError("prometheus_client is not available")
        self._registry = CollectorRegistry(auto_describe=True)
        self._port = _env_int("ZT_PROMETHEUS_PORT", 9464)
        self._addr = _env("ZT_PROMETHEUS_ADDR", "0.0.0.0")
        self._started = False
        self._server_thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        self._cache: Dict[Tuple[str, Tuple[str, ...]], Union[PCounter, PGauge, PHistogram]] = {}

        # Стандартные лейблы — всегда включены
        self._std_labels = (
            "tenant_id",
            "request_id",
            "session_id",
            "trace_id",
            "component",
            "env",
            "region",
            "service",
            "version",
        )

    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            # Запуск HTTP‑эндпоинта в отдельном демоне
            def _serve():
                # Привязываем к дефолтному реестру нельзя, используем свой и Bridge не делаем — стартуем сервер с глобальным реестром,
                # но публиковать свой реестр проще через REGISTRY, потому стартуем обычный и регистрируем наш?
                # Вариант: отдельный процесс/порт. Для простоты — стандартный сервер на нашем порту,
                # но т.к. start_http_server использует глобальный REGISTRY, создадим кастомный сервер ниже.
                from prometheus_client import exposition, core

                class _CustomCollector(core.CollectorRegistry):  # pragma: no cover
                    pass  # не используем

                # Воспользуемся низкоуровневой функцией — сделаем WSGI app.
                app = exposition.make_wsgi_app(self._registry)
                from wsgiref.simple_server import make_server
                httpd = make_server(self._addr, self._port, app)
                httpd.serve_forever()

            t = threading.Thread(target=_serve, name="prometheus-http", daemon=True)
            t.start()
            self._server_thread = t
            self._started = True

    def stop(self) -> None:
        # WSGI simple_server не поддерживает мягкую остановку без доп. обвязки.
        # Оставляем no-op: процесс завершится — сервер закроется.
        pass

    def register(self, mdef: MetricDefinition) -> MetricHandle:
        mdef = mdef.normalized()
        with self._lock:
            label_names = self._std_labels + tuple(mdef.label_names)
            key = (mdef.name, label_names)
            if key in self._cache:
                impl = self._cache[key]
            else:
                if mdef.mtype is MetricType.COUNTER:
                    impl = PCounter(mdef.name, mdef.description, labelnames=label_names, registry=self._registry)
                elif mdef.mtype is MetricType.GAUGE:
                    impl = PGauge(mdef.name, mdef.description, labelnames=label_names, registry=self._registry)
                elif mdef.mtype is MetricType.HISTOGRAM:
                    if mdef.buckets:
                        impl = PHistogram(
                            mdef.name, mdef.description, labelnames=label_names, registry=self._registry, buckets=mdef.buckets
                        )
                    else:
                        impl = PHistogram(mdef.name, mdef.description, labelnames=label_names, registry=self._registry)
                else:
                    raise ValueError(f"Unsupported metric type: {mdef.mtype}")
                self._cache[key] = impl
            return _PromHandle(mdef, impl, self)


# ---------- OTLP Exporter ----------
class _OTelGaugeState:
    """
    Хранилище последних значений gauge по комбинации лейблов.
    ObservableGauge считывает значения в callback.
    """
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._values: Dict[Tuple[Tuple[str, str], ...], float] = {}

    def set(self, labels: Mapping[str, str], value: float) -> None:
        with self._lock:
            key = tuple(sorted((k, v) for k, v in labels.items()))
            self._values[key] = float(value)

    def snapshot(self) -> List[Tuple[Tuple[Tuple[str, str], ...], float]]:
        with self._lock:
            return list(self._values.items())


class _OTelHandle(MetricHandle):
    def __init__(self, mdef: MetricDefinition, exporter: "OTLPExporter"):
        self._mdef = mdef
        self._exp = exporter
        self._sample = _env_float("ZT_METRICS_SAMPLE", 1.0)
        # Инструменты создаются в экспортере и хранятся в кэше
        self._counter = exporter.get_or_create_counter(mdef) if mdef.mtype is MetricType.COUNTER else None
        self._histogram = exporter.get_or_create_histogram(mdef) if mdef.mtype is MetricType.HISTOGRAM else None
        self._gauge_state = exporter.get_or_create_gauge_state(mdef) if mdef.mtype is MetricType.GAUGE else None

    def _labels(self, labels: Optional[Mapping[str, Union[str, int, float]]]) -> Dict[str, str]:
        enriched = self._exp.enrich_labels(labels)
        return scrub_labels(enriched, pii_keys=self._mdef.pii_label_names)

    def _should_sample(self) -> bool:
        s = self._sample
        if s >= 1.0:
            return True
        return random.random() <= s

    def inc(self, amount: float = 1.0, labels: Optional[Mapping[str, Union[str, int, float]]] = None) -> None:
        if self._mdef.mtype is not MetricType.COUNTER or amount <= 0 or not self._should_sample():
            return
        ctr = self._counter
        if ctr is None:
            return
        # OTel counters are monotonic
        ctr.add(amount, attributes=self._labels(labels))

    def set(self, value: float, labels: Optional[Mapping[str, Union[str, int, float]]] = None) -> None:
        if self._mdef.mtype is not MetricType.GAUGE or not self._should_sample():
            return
        st = self._gauge_state
        if st is None:
            return
        st.set(self._labels(labels), float(value))

    def observe(self, value: float, labels: Optional[Mapping[str, Union[str, int, float]]] = None) -> None:
        if self._mdef.mtype is not MetricType.HISTOGRAM or not self._should_sample():
            return
        hist = self._histogram
        if hist is None:
            return
        hist.record(float(value), attributes=self._labels(labels))


class OTLPExporter(Exporter):
    def __init__(self) -> None:
        if not _HAS_OTEL:
            raise RuntimeError("opentelemetry-sdk/exporter-otlp are not available")
        self._endpoint = _env("ZT_OTLP_ENDPOINT", "http://localhost:4318")
        self._mp: Optional[MeterProvider] = None
        self._meter: Optional[Meter] = None
        self._reader: Optional[PeriodicExportingMetricReader] = None
        self._lock = threading.RLock()
        self._counters: Dict[Tuple[str, Tuple[str, ...]], Any] = {}
        self._histograms: Dict[Tuple[str, Tuple[str, ...]], Any] = {}
        self._gauges_state: Dict[Tuple[str, Tuple[str, ...]], _OTelGaugeState] = {}
        self._gauges_registered: Dict[Tuple[str, Tuple[str, ...]], bool] = {}

        self._std_labels = (
            "tenant_id",
            "request_id",
            "session_id",
            "trace_id",
            "component",
            "env",
            "region",
            "service",
            "version",
        )

    def start(self) -> None:
        with self._lock:
            if self._mp is not None:
                return
            exporter = OTLPMetricExporter(endpoint=self._endpoint)
            self._reader = PeriodicExportingMetricReader(exporter)
            self._mp = MeterProvider(metric_readers=[self._reader])
            set_meter_provider(self._mp)
            self._meter = get_meter_provider().get_meter(_env("ZT_SERVICE", "zero-trust-core"))

    def stop(self) -> None:
        with self._lock:
            if self._mp is not None:
                try:
                    self._mp.shutdown()
                except Exception:
                    pass
            self._mp = None
            self._meter = None

    def _key(self, mdef: MetricDefinition) -> Tuple[str, Tuple[str, ...]]:
        label_names = self._std_labels + tuple(mdef.label_names)
        return (mdef.name, label_names)

    def get_or_create_counter(self, mdef: MetricDefinition):
        assert self._meter is not None
        key = self._key(mdef)
        with self._lock:
            if key in self._counters:
                return self._counters[key]
            ctr = self._meter.create_counter(mdef.name, description=mdef.description)
            self._counters[key] = ctr
            return ctr

    def get_or_create_histogram(self, mdef: MetricDefinition):
        assert self._meter is not None
        key = self._key(mdef)
        with self._lock:
            if key in self._histograms:
                return self._histograms[key]
            # OTel не принимает кастомные buckets на API‑уровне; они на стороне бэкенда.
            hist = self._meter.create_histogram(mdef.name, description=mdef.description)
            self._histograms[key] = hist
            return hist

    def get_or_create_gauge_state(self, mdef: MetricDefinition) -> _OTelGaugeState:
        assert self._meter is not None
        key = self._key(mdef)
        with self._lock:
            if key in self._gauges_state:
                return self._gauges_state[key]
            state = _OTelGaugeState()
            self._gauges_state[key] = state
            if not self._gauges_registered.get(key):
                # Регистрируем ObservableGauge однократно
                def _callback(options: CallbackOptions):
                    snap = state.snapshot()
                    for labels_kv, value in snap:
                        yield {
                            "name": mdef.name,
                            "description": mdef.description,
                            "value": value,
                            "attributes": dict(labels_kv),
                        }
                # create_observable_gauge доступен через meter
                try:
                    self._meter.create_observable_gauge(
                        mdef.name,
                        callbacks=[lambda options: (ot for ot in _callback(options))],  # генератор
                        description=mdef.description,
                    )
                except Exception:
                    # В разных версиях API сигнатуры могут отличаться; просто защищаемся.
                    pass
                self._gauges_registered[key] = True
            return state

    def register(self, mdef: MetricDefinition) -> MetricHandle:
        mdef = mdef.normalized()
        return _OTelHandle(mdef, self)


# ---------- Metrics Registry ----------
class MetricsRegistry:
    """
    Единая точка создания метрик. Управляет экспортерами, freeze‑состоянием, валидациями.
    """
    def __init__(self, exporters: Sequence[Exporter]) -> None:
        self._exporters = list(exporters)
        self._lock = threading.RLock()
        self._frozen = _env_bool("ZT_FREEZE_AFTER_INIT", True)
        self._defs: Dict[str, MetricDefinition] = {}
        self._handles: Dict[str, List[MetricHandle]] = {}

        # Базовые histogram buckets (секунды): p50..p99.9 в разумном диапазоне
        self._default_buckets = (
            0.001, 0.0025, 0.005,
            0.01, 0.025, 0.05,
            0.1, 0.25, 0.5,
            1.0, 2.5, 5.0,
            10.0
        )

    def start(self) -> None:
        for e in self._exporters:
            try:
                e.start()
            except Exception:
                # Не валим процесс из-за экспортера
                pass

    def stop(self) -> None:
        for e in self._exporters:
            try:
                e.stop()
            except Exception:
                pass

    def freeze(self) -> None:
        with self._lock:
            self._frozen = True

    def _ensure_unfrozen(self) -> None:
        if self._frozen:
            # Разрешаем повторную регистрацию ранее объявленных метрик; новые — запрещены.
            raise RuntimeError("MetricsRegistry is frozen; new metrics cannot be created")

    def _register(self, mdef: MetricDefinition) -> List[MetricHandle]:
        mdef = mdef.normalized()
        name = mdef.name
        if len(mdef.label_names) > _MAX_LABELS:
            raise ValueError(f"Too many label names: {len(mdef.label_names)} > {_MAX_LABELS}")
        if not _ALLOWED_NAME_RE.match(name):
            raise ValueError(f"Invalid metric name after normalization: {name}")
        for ln in mdef.label_names:
            if not _ALLOWED_LABEL_NAME_RE.match(ln):
                raise ValueError(f"Invalid label name after normalization: {ln}")

        with self._lock:
            if name in self._defs:
                # Разрешаем idempotent регистрацию с теми же параметрами
                if self._defs[name] != mdef:
                    raise ValueError(f"Metric {name} already defined with different schema")
                return self._handles[name]
            # Создаем на всех экспортерах
            handles: List[MetricHandle] = []
            for e in self._exporters:
                try:
                    h = e.register(mdef)
                    handles.append(h)
                except Exception:
                    # Если экспортер отвалился — пропускаем
                    pass
            self._defs[name] = mdef
            self._handles[name] = handles
            return handles

    # -- Public factory methods --
    def counter(self, name: str, description: str, label_names: Sequence[str] = (), pii_label_names: Sequence[str] = ()) -> "Counter":
        if self._frozen:
            # Разрешаем создание handle, если метрика уже объявлена ранее
            if name not in self._defs:
                raise RuntimeError("Registry frozen and metric not pre-declared")
        mdef = MetricDefinition(name=name, description=description, mtype=MetricType.COUNTER,
                                label_names=tuple(label_names), pii_label_names=tuple(pii_label_names))
        handles = self._register(mdef)
        return Counter(name=mdef.name, handles=handles)

    def gauge(self, name: str, description: str, label_names: Sequence[str] = (), pii_label_names: Sequence[str] = ()) -> "Gauge":
        if self._frozen:
            if name not in self._defs:
                raise RuntimeError("Registry frozen and metric not pre-declared")
        mdef = MetricDefinition(name=name, description=description, mtype=MetricType.GAUGE,
                                label_names=tuple(label_names), pii_label_names=tuple(pii_label_names))
        handles = self._register(mdef)
        return Gauge(name=mdef.name, handles=handles)

    def histogram(
        self,
        name: str,
        description: str,
        label_names: Sequence[str] = (),
        pii_label_names: Sequence[str] = (),
        buckets: Optional[Sequence[float]] = None,
    ) -> "Histogram":
        if self._frozen:
            if name not in self._defs:
                raise RuntimeError("Registry frozen and metric not pre-declared")
        if buckets is None:
            buckets = self._default_buckets
        mdef = MetricDefinition(
            name=name,
            description=description,
            mtype=MetricType.HISTOGRAM,
            label_names=tuple(label_names),
            pii_label_names=tuple(pii_label_names),
            buckets=tuple(float(b) for b in buckets),
        )
        handles = self._register(mdef)
        return Histogram(name=mdef.name, handles=handles)


# ---------- Public metric wrappers ----------
class _Base:
    def __init__(self, name: str, handles: Sequence[MetricHandle]) -> None:
        self._name = name
        self._handles = list(handles)

    @property
    def name(self) -> str:
        return self._name

    def _fanout(self, fn: str, *args: Any, **kwargs: Any) -> None:
        for h in self._handles:
            try:
                getattr(h, fn)(*args, **kwargs)
            except Exception:
                # Не даем метрикам ломать рабочие потоки
                pass


class Counter(_Base):
    def inc(self, amount: float = 1.0, labels: Optional[Mapping[str, Union[str, int, float]]] = None) -> None:
        self._fanout("inc", amount=amount, labels=labels)


class Gauge(_Base):
    def set(self, value: float, labels: Optional[Mapping[str, Union[str, int, float]]] = None) -> None:
        self._fanout("set", value=value, labels=labels)


class Histogram(_Base):
    def observe(self, value: float, labels: Optional[Mapping[str, Union[str, int, float]]] = None) -> None:
        self._fanout("observe", value=value, labels=labels)


# ---------- Global registry builder ----------
_registry_singleton: Optional[MetricsRegistry] = None
_registry_lock = threading.RLock()

def _choose_exporters() -> List[Exporter]:
    choice = _env("ZT_METRICS_EXPORTER", "").strip().lower()
    exporters: List[Exporter] = []

    def _maybe_prom() -> None:
        if _HAS_PROM:
            try:
                exporters.append(PrometheusExporter())
            except Exception:
                pass

    def _maybe_otlp() -> None:
        if _HAS_OTEL:
            try:
                exporters.append(OTLPExporter())
            except Exception:
                pass

    if choice in ("", None, "auto"):  # по умолчанию пытаемся прометеус
        if _HAS_PROM:
            _maybe_prom()
        elif _HAS_OTEL:
            _maybe_otlp()
        else:
            exporters.append(NoOpExporter())
    elif choice == "prometheus":
        if _HAS_PROM:
            _maybe_prom()
        else:
            exporters.append(NoOpExporter())
    elif choice == "otlp":
        if _HAS_OTEL:
            _maybe_otlp()
        else:
            exporters.append(NoOpExporter())
    elif choice == "both":
        any_added = False
        if _HAS_PROM:
            _maybe_prom(); any_added = True
        if _HAS_OTEL:
            _maybe_otlp(); any_added = True
        if not any_added:
            exporters.append(NoOpExporter())
    else:
        exporters.append(NoOpExporter())
    if not exporters:
        exporters.append(NoOpExporter())
    return exporters


def get_registry() -> MetricsRegistry:
    global _registry_singleton
    with _registry_lock:
        if _registry_singleton is not None:
            return _registry_singleton
        exporters = _choose_exporters()
        reg = MetricsRegistry(exporters=exporters)
        reg.start()
        # Freeze по умолчанию: запрещаем ad‑hoc создание новых метрик в рантайме.
        if _env_bool("ZT_FREEZE_AFTER_INIT", True):
            reg.freeze()
        _registry_singleton = reg
        return reg


# ---------- Pre-declare core metrics (optional but useful) ----------
def predeclare_core_metrics() -> None:
    """
    Предзаявляем набор базовых метрик Zero Trust, чтобы они существовали сразу,
    даже если реестр заморожен.
    """
    reg = get_registry()
    # Временно открываем регистрацию новых метрик, затем снова заморозка
    # Делаем это локально и безопасно для повторных вызовов.
    unfroze = False
    try:
        if reg._frozen:  # type: ignore[attr-defined]
            reg._frozen = False  # type: ignore[attr-defined]
            unfroze = True

        reg.counter(
            "zt_requests_total",
            "Количество обработанных запросов Zero Trust Gateway",
            label_names=("route", "status"),
            pii_label_names=("tenant_id",),
        )
        reg.histogram(
            "zt_request_latency_seconds",
            "Латентность обработки запросов",
            label_names=("route", "status"),
            pii_label_names=("tenant_id",),
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
        )
        reg.gauge(
            "zt_active_sessions",
            "Текущее количество активных Zero Trust сессий",
            label_names=("node",),
            pii_label_names=("tenant_id",),
        )
    finally:
        if unfroze:
            reg.freeze()


# ---------- Simple self-test (can be removed in production) ----------
def _selfcheck_noop() -> None:  # pragma: no cover
    bind_context(tenant_id="acme", request_id="r1", session_id="s1", trace_id="t1", component="ingress")
    reg = get_registry()
    try:
        # Попробуем получить уже предзаявленные
        c = reg.counter("zt_requests_total", "desc")
        h = reg.histogram("zt_request_latency_seconds", "desc")
        g = reg.gauge("zt_active_sessions", "desc")
        c.inc(1, labels={"route": "/auth", "status": "200"})
        h.observe(0.012, labels={"route": "/auth", "status": "200"})
        g.set(42, labels={"node": "gw-1"})
    except Exception as e:
        # Не падаем
        sys.stderr.write(f"[metrics] selfcheck failed: {e}\n")


# Инициализация по импорту: предзаявляем ядро, но не спамим selfcheck
try:
    predeclare_core_metrics()
except Exception:
    pass
