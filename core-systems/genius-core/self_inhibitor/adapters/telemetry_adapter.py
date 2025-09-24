# path: core-systems/genius_core/security/self_inhibitor/adapters/telemetry_adapter.py
from __future__ import annotations

import contextlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

# =========================
# Конфигурация
# =========================

@dataclass
class TelemetryConfig:
    service_name: str = os.getenv("SERVICE_NAME", "genius-core")
    service_version: str = os.getenv("SERVICE_VERSION", "0.0.0")
    environment: str = os.getenv("ENVIRONMENT", "dev")
    # Включение бэкендов
    enable_logging: bool = True
    enable_opentelemetry: bool = bool(int(os.getenv("ENABLE_OTEL", "0")))
    enable_prometheus: bool = bool(int(os.getenv("ENABLE_PROM", "0")))
    # OpenTelemetry имена
    otel_tracer_name: str = "genius_core.self_inhibitor"
    otel_meter_name: str = "genius_core.self_inhibitor"
    # Prometheus параметры
    prom_namespace: str = "genius"
    prom_subsystem: str = "self_inhibitor"
    # Редакция (регекспы как строки)
    redact_patterns: Sequence[Tuple[str, str]] = field(default_factory=lambda: [
        (r"(?i)\b(authorization|x-api-key|api[-_]?key|token|secret|password)\s*[:=]\s*([^\s,;]+)", r"\1:[REDACTED]"),
        (r"\beyJ[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+", "[REDACTED_JWT]"),
        (r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b", "[REDACTED_EMAIL]"),
        (r"\b(?:\d[ -]*?){13,19}\b", "[REDACTED_CC]"),
    ])
    # Ведро гистограмм по умолчанию (секунды)
    histogram_buckets: Sequence[float] = (
        0.001, 0.005, 0.01, 0.025, 0.05,
        0.1, 0.25, 0.5, 1.0, 2.5,
        5.0, 10.0
    )


# =========================
# Базовый интерфейс
# =========================

class TelemetryBackend:
    def event(self, name: str, level: str = "info", **fields: Any) -> None:
        pass

    def incr(self, name: str, value: float = 1.0, **labels: Any) -> None:
        pass

    def observe(self, name: str, value: float, **labels: Any) -> None:
        pass

    def timer(self, name: str, **labels: Any):
        return _Timer(self, name, labels)

    def span(self, name: str, **attributes: Any):
        return contextlib.nullcontext()  # по умолчанию без трассировки


# =========================
# Утилиты: редакция и таймер
# =========================

def _scrub(value: Any, patterns: Sequence[Tuple[str, str]]) -> Any:
    import re
    if value is None:
        return None
    if isinstance(value, str):
        s = value
        for pat, repl in patterns:
            s = re.sub(pat, repl, s)
        return s
    if isinstance(value, dict):
        return {k: _scrub(v, patterns) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_scrub(v, patterns) for v in value]
    return value

class _Timer:
    def __init__(self, backend: TelemetryBackend, name: str, labels: Mapping[str, Any]):
        self.backend = backend
        self.name = name
        self.labels = dict(labels)
        self.t0 = None

    def __enter__(self):
        self.t0 = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb):
        elapsed = time.perf_counter() - (self.t0 or time.perf_counter())
        self.backend.observe(self.name, elapsed, **self.labels)

    async def __aenter__(self):
        self.t0 = time.perf_counter()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        elapsed = time.perf_counter() - (self.t0 or time.perf_counter())
        self.backend.observe(self.name, elapsed, **self.labels)


# =========================
# Логгер-бэкенд (fallback)
# =========================

class LoggingBackend(TelemetryBackend):
    def __init__(self, cfg: TelemetryConfig):
        self.cfg = cfg
        # Попытка использовать ваш модуль телеметрии, иначе stdlib
        try:
            from omnimind.telemetry.logging import get_logger, log_extra  # type: ignore
            self._log = get_logger("genius_core.self_inhibitor.telemetry")
            self._extra = log_extra
            self._has_omni = True
        except Exception:
            self._log = logging.getLogger("genius_core.self_inhibitor.telemetry")
            self._extra = lambda **kw: {"extra": {"extra_fields": kw}}
            self._has_omni = False

    def event(self, name: str, level: str = "info", **fields: Any) -> None:
        payload = {
            "service": self.cfg.service_name,
            "service_version": self.cfg.service_version,
            "env": self.cfg.environment,
            "event": name,
        }
        payload.update(fields)
        safe = _scrub(payload, self.cfg.redact_patterns)
        try:
            msg = safe.pop("message", None) or name
            fn = getattr(self._log, level.lower(), self._log.info)
            fn(msg, **self._extra(**safe))
        except Exception:
            # Никакие ошибки телеметрии не должны влиять на рабочий поток
            pass

    def incr(self, name: str, value: float = 1.0, **labels: Any) -> None:
        labels = _scrub(labels, self.cfg.redact_patterns)
        self.event("metric.counter", metric=name, value=value, labels=labels)

    def observe(self, name: str, value: float, **labels: Any) -> None:
        labels = _scrub(labels, self.cfg.redact_patterns)
        self.event("metric.histogram", metric=name, value=value, labels=labels)


# =========================
# OpenTelemetry-бэкенд (опционально)
# =========================

class OpenTelemetryBackend(TelemetryBackend):
    def __init__(self, cfg: TelemetryConfig):
        self.cfg = cfg
        try:
            from opentelemetry import trace, metrics  # type: ignore
            self._trace = trace
            self._metrics = metrics
            self._tracer = trace.get_tracer(cfg.otel_tracer_name, cfg.service_version)
            self._meter = metrics.get_meter(cfg.otel_meter_name, cfg.service_version)
            self._counters: Dict[Tuple[str, Tuple[str, ...]], Any] = {}
            self._hists: Dict[Tuple[str, Tuple[str, ...]], Any] = {}
            self._ok = True
        except Exception:
            self._ok = False  # graceful fallback

        # На события безопасности используем и логгер тоже (для видимости)
        self._log = LoggingBackend(cfg)

    def _label_key(self, labels: Mapping[str, Any]) -> Tuple[str, ...]:
        return tuple(sorted(labels.keys()))

    def event(self, name: str, level: str = "info", **fields: Any) -> None:
        # В OTel нет «событий приложения» вне трассы — отправим как лог-событие через LoggingBackend
        self._log.event(name, level, **fields)

    def incr(self, name: str, value: float = 1.0, **labels: Any) -> None:
        labels = _scrub(labels, self.cfg.redact_patterns)
        if not self._ok:
            return self._log.incr(name, value, **labels)
        try:
            key = (name, self._label_key(labels))
            ctr = self._counters.get(key)
            if ctr is None:
                # API OTel может отличаться в вашей версии. Я не могу это проверить здесь: I cannot verify this.
                ctr = self._meter.create_counter(name)  # type: ignore[attr-defined]
                self._counters[key] = ctr
            ctr.add(value, attributes=dict(labels))  # type: ignore[attr-defined]
        except Exception:
            # безопасный fallback
            self._log.incr(name, value, **labels)

    def observe(self, name: str, value: float, **labels: Any) -> None:
        labels = _scrub(labels, self.cfg.redact_patterns)
        if not self._ok:
            return self._log.observe(name, value, **labels)
        try:
            key = (name, self._label_key(labels))
            h = self._hists.get(key)
            if h is None:
                # API OTel может отличаться в вашей версии. Я не могу это проверить здесь: I cannot verify this.
                h = self._meter.create_histogram(name)  # type: ignore[attr-defined]
                self._hists[key] = h
            h.record(value, attributes=dict(labels))  # type: ignore[attr-defined]
        except Exception:
            self._log.observe(name, value, **labels)

    def span(self, name: str, **attributes: Any):
        if not self._ok:
            return contextlib.nullcontext()
        attributes = _scrub(attributes, self.cfg.redact_patterns)
        class _SpanCtx:
            def __enter__(inner):
                inner._span = self._tracer.start_span(name)  # type: ignore[attr-defined]
                with contextlib.suppress(Exception):
                    if attributes:
                        inner._span.set_attributes(attributes)  # type: ignore[attr-defined]
                inner._ctx = self._trace.use_span(inner._span, end_on_exit=True)  # type: ignore[attr-defined]
                inner._ctx.__enter__()
                return inner._span
            def __exit__(inner, exc_type, exc, tb):
                try:
                    if exc:
                        # set status error if available
                        with contextlib.suppress(Exception):
                            from opentelemetry.trace.status import Status, StatusCode  # type: ignore
                            inner._span.set_status(Status(StatusCode.ERROR))  # type: ignore[attr-defined]
                finally:
                    inner._ctx.__exit__(exc_type, exc, tb)
        return _SpanCtx()


# =========================
# Prometheus-бэкенд (опционально)
# =========================

class PrometheusBackend(TelemetryBackend):
    def __init__(self, cfg: TelemetryConfig):
        self.cfg = cfg
        try:
            from prometheus_client import Counter, Histogram  # type: ignore
            self._Counter = Counter
            self._Histogram = Histogram
            self._counters: Dict[Tuple[str, Tuple[str, ...]], Any] = {}
            self._hists: Dict[Tuple[str, Tuple[str, ...]], Any] = {}
            self._ok = True
        except Exception:
            self._ok = False
        self._log = LoggingBackend(cfg)

    def _label_key(self, labels: Mapping[str, Any]) -> Tuple[str, ...]:
        return tuple(sorted(labels.keys()))

    def event(self, name: str, level: str = "info", **fields: Any) -> None:
        # События — через логгер
        self._log.event(name, level, **fields)

    def incr(self, name: str, value: float = 1.0, **labels: Any) -> None:
        if not self._ok:
            return self._log.incr(name, value, **labels)
        try:
            label_keys = self._label_key(labels)
            key = (name, label_keys)
            c = self._counters.get(key)
            if c is None:
                c = self._Counter(
                    name,
                    f"{name} counter",
                    labelkeys=list(label_keys),
                    namespace=self.cfg.prom_namespace,
                    subsystem=self.cfg.prom_subsystem,
                )
                self._counters[key] = c
            if label_keys:
                c.labels(**{k: str(labels[k]) for k in label_keys}).inc(value)
            else:
                c.inc(value)
        except Exception:
            self._log.incr(name, value, **labels)

    def observe(self, name: str, value: float, **labels: Any) -> None:
        if not self._ok:
            return self._log.observe(name, value, **labels)
        try:
            label_keys = self._label_key(labels)
            key = (name, label_keys)
            h = self._hists.get(key)
            if h is None:
                h = self._Histogram(
                    name,
                    f"{name} histogram",
                    labelkeys=list(label_keys),
                    namespace=self.cfg.prom_namespace,
                    subsystem=self.cfg.prom_subsystem,
                    buckets=tuple(self.cfg.histogram_buckets),
                )
                self._hists[key] = h
            if label_keys:
                h.labels(**{k: str(labels[k]) for k in label_keys}).observe(value)
            else:
                h.observe(value)
        except Exception:
            self._log.observe(name, value, **labels)


# =========================
# Мультиплексор
# =========================

class TelemetryMultiplexer(TelemetryBackend):
    def __init__(self, backends: Iterable[TelemetryBackend]):
        self.backends = list(backends)

    def event(self, name: str, level: str = "info", **fields: Any) -> None:
        for b in self.backends:
            with contextlib.suppress(Exception):
                b.event(name, level, **fields)

    def incr(self, name: str, value: float = 1.0, **labels: Any) -> None:
        for b in self.backends:
            with contextlib.suppress(Exception):
                b.incr(name, value, **labels)

    def observe(self, name: str, value: float, **labels: Any) -> None:
        for b in self.backends:
            with contextlib.suppress(Exception):
                b.observe(name, value, **labels)

    def timer(self, name: str, **labels: Any):
        # Возвращаем общий таймер, пишущий во все backends
        return _MuxTimer(self.backends, name, labels)

    def span(self, name: str, **attributes: Any):
        return _MuxSpan([b.span(name, **attributes) for b in self.backends])


class _MuxTimer:
    def __init__(self, backends: Sequence[TelemetryBackend], name: str, labels: Mapping[str, Any]):
        self.backends = backends
        self.name = name
        self.labels = dict(labels)
        self.t0 = None

    def __enter__(self):
        self.t0 = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb):
        elapsed = time.perf_counter() - (self.t0 or time.perf_counter())
        for b in self.backends:
            with contextlib.suppress(Exception):
                b.observe(self.name, elapsed, **self.labels)

    async def __aenter__(self):
        self.t0 = time.perf_counter()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        elapsed = time.perf_counter() - (self.t0 or time.perf_counter())
        for b in self.backends:
            with contextlib.suppress(Exception):
                b.observe(self.name, elapsed, **self.labels)


class _MuxSpan:
    def __init__(self, spans: Sequence[contextlib.AbstractContextManager]):
        self.spans = spans

    def __enter__(self):
        self.ctx = [s.__enter__() for s in self.spans]
        return self

    def __exit__(self, exc_type, exc, tb):
        for s in reversed(self.spans):
            with contextlib.suppress(Exception):
                s.__exit__(exc_type, exc, tb)


# =========================
# Фабрика
# =========================

def build_telemetry(cfg: Optional[TelemetryConfig] = None) -> TelemetryBackend:
    cfg = cfg or TelemetryConfig()
    backends: list[TelemetryBackend] = []
    if cfg.enable_logging:
        backends.append(LoggingBackend(cfg))
    if cfg.enable_opentelemetry:
        backends.append(OpenTelemetryBackend(cfg))
    if cfg.enable_prometheus:
        backends.append(PrometheusBackend(cfg))
    if not backends:
        backends.append(LoggingBackend(cfg))  # гарантированный fallback
    if len(backends) == 1:
        return backends[0]
    return TelemetryMultiplexer(backends)


# =========================
# Пример (комментарии)
# =========================
# cfg = TelemetryConfig(
#     service_name="genius-core",
#     environment="prod",
#     enable_logging=True,
#     enable_opentelemetry=True,   # при наличии opentelemetry
#     enable_prometheus=True,      # при наличии prometheus_client
# )
# telemetry = build_telemetry(cfg)
#
# # Событие безопасности
# telemetry.event(
#     "security.blocked",
#     level="warning",
#     path="/graphql",
#     reason="INTROSPECTION_BLOCKED",
#     identity="ip:203.0.113.10"
# )
#
# # Счётчик
# telemetry.incr("requests_total", method="POST", path="/graphql", status="200")
#
# # Таймер (секунды)
# with telemetry.timer("request_duration_seconds", method="POST", path="/graphql"):
#     ...  # обработка запроса
#
# # Спан трассировки (если OTel доступен)
# with telemetry.span("graphql.validation", rule="complexity"):
#     ...  # валидация запроса
