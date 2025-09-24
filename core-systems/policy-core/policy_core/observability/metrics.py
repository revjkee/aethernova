# -*- coding: utf-8 -*-
"""
policy-core / policy_core / observability / metrics.py

Единый слой метрик для policy-core:
- Без внешних зависимостей (fallback-реализация).
- Автоматически использует prometheus_client, если он доступен.
- Счетчики, гистограммы, таймеры (sync/async), безопасные лейблы.
- Инструментирование FastAPI (middleware) + ASGI-эндпоинт /metrics.
- Готовые доменные метрики: PDP/PEP/Obligations, репозиторий, HTTP.

Python 3.10+

Окружение (необязательно):
  METRICS_ENABLED=true|false (default: true)
  METRICS_EXPORTER=prometheus|none (default: prometheus if lib present else none)
  METRICS_NAMESPACE=policy
  METRICS_SUBSYSTEM=core
  METRICS_BUCKETS=0.005,0.01,0.025,0.05,0.1,0.25,0.5,1,2.5,5,10
"""

from __future__ import annotations

import asyncio
import os
import time
import typing as _t
from contextlib import contextmanager, asynccontextmanager
from dataclasses import dataclass
from threading import Lock

Json = _t.Union[dict, list, str, int, float, bool, None]


# --------------------------------------------------------------------------------------
# УТИЛИТЫ
# --------------------------------------------------------------------------------------

def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _env_str(name: str, default: str) -> str:
    v = os.getenv(name)
    return default if v is None else v


def _env_buckets(name: str, default: _t.Sequence[float]) -> _t.Sequence[float]:
    v = os.getenv(name)
    if not v:
        return default
    try:
        arr = [float(x.strip()) for x in v.split(",") if x.strip()]
        arr = sorted(x for x in arr if x > 0.0)
        return arr or default
    except Exception:
        return default


def _safe_label_value(v: _t.Optional[str]) -> str:
    if v is None:
        return "none"
    v = str(v)
    # ограничим длину во избежание взрыва кардинальности
    return v[:120] if len(v) > 120 else v


# --------------------------------------------------------------------------------------
# АДАПТЕРЫ МЕТРИК
# --------------------------------------------------------------------------------------

class _Counter:
    def inc(self, value: float = 1.0, **labels: str) -> None:
        raise NotImplementedError()


class _Histogram:
    def observe(self, value: float, **labels: str) -> None:
        raise NotImplementedError()

    @contextmanager
    def time(self, **labels: str):
        start = time.perf_counter()
        try:
            yield
        finally:
            self.observe(time.perf_counter() - start, **labels)

    @asynccontextmanager
    async def atime(self, **labels: str):
        start = time.perf_counter()
        try:
            yield
        finally:
            self.observe(time.perf_counter() - start, **labels)


# ----- Fallback (без зависимостей) -----

class _LocalCounter(_Counter):
    def __init__(self, name: str, label_names: _t.Tuple[str, ...]):
        self._name = name
        self._label_names = label_names
        self._lock = Lock()
        self._data: dict[tuple[str, ...], float] = {}

    def inc(self, value: float = 1.0, **labels: str) -> None:
        key = tuple(_safe_label_value(labels.get(k)) for k in self._label_names)
        with self._lock:
            self._data[key] = self._data.get(key, 0.0) + float(value)


class _LocalHistogram(_Histogram):
    def __init__(self, name: str, label_names: _t.Tuple[str, ...], buckets: _t.Sequence[float]):
        self._name = name
        self._label_names = label_names
        self._buckets = tuple(sorted(buckets))
        self._lock = Lock()
        # (labels) -> {"sum": float, "count": int, "buckets": [int]*len(buckets)}
        self._data: dict[tuple[str, ...], dict[str, _t.Any]] = {}

    def observe(self, value: float, **labels: str) -> None:
        key = tuple(_safe_label_value(labels.get(k)) for k in self._label_names)
        v = float(value)
        with self._lock:
            s = self._data.get(key)
            if s is None:
                s = {"sum": 0.0, "count": 0, "buckets": [0] * len(self._buckets)}
                self._data[key] = s
            s["sum"] += v
            s["count"] += 1
            # инкремент подходящего бакета
            for i, b in enumerate(self._buckets):
                if v <= b:
                    s["buckets"][i] += 1
                    break

    # Экспорт в формат Prometheus text для /metrics (fallback)
    def _export_lines(self, full_name: str) -> _t.Iterable[str]:
        with self._lock:
            for key, s in self._data.items():
                labels = ",".join(f'{ln}="{lv}"' for ln, lv in zip(self._label_names, key))
                # кумулятивные бакеты
                cum = 0
                for i, b in enumerate(self._buckets):
                    cum += s["buckets"][i]
                    yield f'{full_name}_bucket{{{labels},le="{self._buckets[i]}"}} {cum}'
                yield f'{full_name}_sum{{{labels}}} {s["sum"]}'
                yield f'{full_name}_count{{{labels}}} {s["count"]}'


class _LocalExporter:
    """
    Сборка и экспорт всех локальных метрик в текст Prometheus (OpenMetrics совместимо по основным частям).
    """
    def __init__(self, namespace: str, subsystem: str):
        self.namespace = namespace
        self.subsystem = subsystem
        self._counters: dict[str, _LocalCounter] = {}
        self._hists: dict[str, _LocalHistogram] = {}

    def register_counter(self, name: str, labels: _t.Tuple[str, ...]) -> _LocalCounter:
        self._counters.setdefault(name, _LocalCounter(name, labels))
        return self._counters[name]

    def register_histogram(self, name: str, labels: _t.Tuple[str, ...], buckets: _t.Sequence[float]) -> _LocalHistogram:
        self._hists.setdefault(name, _LocalHistogram(name, labels, buckets))
        return self._hists[name]

    def export_text(self) -> str:
        lines: list[str] = []
        for name, c in self._counters.items():
            full = f"{self.namespace}_{self.subsystem}_{name}"
            # локальные счетчики экспортируем как gauge с лейблом total (упрощение)
            # в реальном Prometheus они будут нативными Counter/Histogram, если lib доступна.
            # Для простоты выведем только sum по лейблам (сохранение точности не критично для fallback).
            # Можно расширить при необходимости.
            # Здесь оставим пусто (интерпретируем через _LocalMetrics.inc_export()).
            pass  # Counters будут экспортироваться из регистра Metrics._export_text_counters
        # гистограммы
        for name, h in self._hists.items():
            full = f"{self.namespace}_{self.subsystem}_{name}"
            lines.extend(h._export_lines(full))
        return "\n".join(lines)


# ----- Prometheus (если доступен) -----

def _try_import_prom():
    try:
        import prometheus_client  # type: ignore
        from prometheus_client import Counter, Histogram, REGISTRY, CollectorRegistry
        from prometheus_client.exposition import generate_latest, CONTENT_TYPE_LATEST
        return True, prometheus_client, Counter, Histogram, REGISTRY, CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST
    except Exception:
        return False, None, None, None, None, None, None, None


_PROM_AVAILABLE, _prometheus_client, _PromCounter, _PromHistogram, _PROM_REGISTRY, _PromCollectorRegistry, _prom_generate_latest, _prom_content_type = _try_import_prom()


# --------------------------------------------------------------------------------------
# ОСНОВНОЙ РЕЕСТР
# --------------------------------------------------------------------------------------

_DEFAULT_BUCKETS = _env_buckets(
    "METRICS_BUCKETS",
    (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)


@dataclass
class _MetricDef:
    name: str
    help: str
    label_names: _t.Tuple[str, ...]
    buckets: _t.Optional[_t.Sequence[float]] = None  # for histogram


class Metrics:
    """
    Главный реестр метрик и точка интеграции.
    """
    def __init__(self) -> None:
        self.enabled = _env_bool("METRICS_ENABLED", True)
        self.namespace = _env_str("METRICS_NAMESPACE", "policy")
        self.subsystem = _env_str("METRICS_SUBSYSTEM", "core")
        exporter_env = _env_str("METRICS_EXPORTER", "prometheus")
        self.exporter = "prometheus" if (_PROM_AVAILABLE and exporter_env != "none") else "none"

        self._local = _LocalExporter(self.namespace, self.subsystem)
        self._lock = Lock()
        self._counters: dict[str, _Counter] = {}
        self._histograms: dict[str, _Histogram] = {}
        # отдельное хранение для локального экспорта счетчиков
        self._local_counters_storage: dict[str, dict[tuple[str, ...], float]] = {}

        if self.exporter == "prometheus":
            # создаем реальный Prometheus registry по умолчанию глобальный
            self._prom_registry = _PROM_REGISTRY
        else:
            self._prom_registry = None

        # Преднастроенные метрики домена
        self._define_domain_metrics()

    # ----------------- Регистрация/получение метрик -----------------

    def counter(self, name: str, help: str, label_names: _t.Sequence[str] = ()) -> _Counter:
        key = f"c:{name}:{','.join(label_names)}"
        with self._lock:
            if key in self._counters:
                return self._counters[key]
            labels = tuple(label_names)
            if self.exporter == "prometheus":
                prom_name = f"{self.namespace}_{self.subsystem}_{name}"
                c = _PromCounter(prom_name, help, labelnames=labels, registry=self._prom_registry)
                adapter = _PromCounterAdapter(c, labels)
            else:
                lc = self._local.register_counter(name, labels)
                adapter = _LocalCounterAdapter(lc, labels, self._local_counters_storage.setdefault(name, {}))
            self._counters[key] = adapter
            return adapter

    def histogram(self, name: str, help: str, label_names: _t.Sequence[str] = (), buckets: _t.Sequence[float] | None = None) -> _Histogram:
        key = f"h:{name}:{','.join(label_names)}"
        with self._lock:
            if key in self._histograms:
                return self._histograms[key]
            labels = tuple(label_names)
            buckets = tuple(buckets or _DEFAULT_BUCKETS)
            if self.exporter == "prometheus":
                prom_name = f"{self.namespace}_{self.subsystem}_{name}"
                h = _PromHistogram(prom_name, help, labelnames=labels, buckets=buckets, registry=self._prom_registry)
                adapter = _PromHistogramAdapter(h, labels)
            else:
                lh = self._local.register_histogram(name, labels, buckets)
                adapter = _LocalHistogramAdapter(lh, labels)
            self._histograms[key] = adapter
            return adapter

    # ----------------- Хелперы для инкрементов/таймера -----------------

    def inc(self, name: str, help: str, labels: dict[str, _t.Any] | None = None, label_names: _t.Sequence[str] = ()) -> None:
        if not self.enabled:
            return
        c = self.counter(name, help, label_names=label_names)
        c.inc(**{k: _safe_label_value(v) for k, v in (labels or {}).items()})

    def observe(self, name: str, help: str, value: float, labels: dict[str, _t.Any] | None = None, label_names: _t.Sequence[str] = (), buckets: _t.Sequence[float] | None = None) -> None:
        if not self.enabled:
            return
        h = self.histogram(name, help, label_names=label_names, buckets=buckets)
        h.observe(float(value), **{k: _safe_label_value(v) for k, v in (labels or {}).items()})

    @contextmanager
    def time(self, name: str, help: str, labels: dict[str, _t.Any] | None = None, label_names: _t.Sequence[str] = (), buckets: _t.Sequence[float] | None = None):
        if not self.enabled:
            yield
            return
        h = self.histogram(name, help, label_names=label_names, buckets=buckets)
        with h.time(**{k: _safe_label_value(v) for k, v in (labels or {}).items()}):
            yield

    @asynccontextmanager
    async def atime(self, name: str, help: str, labels: dict[str, _t.Any] | None = None, label_names: _t.Sequence[str] = (), buckets: _t.Sequence[float] | None = None):
        if not self.enabled:
            yield
            return
        h = self.histogram(name, help, label_names=label_names, buckets=buckets)
        async with h.atime(**{k: _safe_label_value(v) for k, v in (labels or {}).items()}):
            yield

    # ----------------- ASGI экспорт / FastAPI middleware -----------------

    def make_asgi_app(self):
        """
        Возвращает ASGI-приложение для экспорта метрик.
        Если доступен prometheus_client — отдает нативный формат Prometheus, иначе fallback-текст.
        """
        async def app(scope, receive, send):
            if scope["type"] != "http":
                await send({"type": "http.response.start", "status": 404, "headers": []})
                await send({"type": "http.response.body", "body": b"", "more_body": False})
                return
            if self.exporter == "prometheus":
                data = _prom_generate_latest(self._prom_registry)
                headers = [(b"content-type", _prom_content_type.encode("ascii"))]
                await send({"type": "http.response.start", "status": 200, "headers": headers})
                await send({"type": "http.response.body", "body": data, "more_body": False})
            else:
                # экспорт счетчиков (локально): соберем текст
                text_lines = []
                ns = self.namespace
                ss = self.subsystem
                for name, store in self._local_counters_storage.items():
                    full = f"{ns}_{ss}_{name}_total"
                    for key, val in store.items():
                        # ключи соответствуют label_names из регистратора
                        # вычислить label_names из любого зарегистрированного адаптера
                        # мы сохранили только значения; для простоты выведем без лейблов, суммарно
                        # (расширение возможно при необходимости)
                        text_lines.append(f"{full} {val}")
                text_lines.append(self._local.export_text())
                data = ("\n".join(text_lines) + "\n").encode("utf-8")
                headers = [(b"content-type", b"text/plain; version=0.0.4; charset=utf-8")]
                await send({"type": "http.response.start", "status": 200, "headers": headers})
                await send({"type": "http.response.body", "body": data, "more_body": False})
        return app

    def instrument_fastapi(self, app, path: str = "/metrics", skip_paths: set[str] | None = None) -> None:
        """
        Подключить middleware HTTP и смонтировать /metrics.
        """
        skip_paths = skip_paths or set()

        # Смонтируем /metrics
        try:
            app.mount(path, self.make_asgi_app())
        except Exception:
            # Не критично
            pass

        # Middleware HTTP
        @app.middleware("http")
        async def _metrics_http_mw(request, call_next):
            # избегаем рекурсии по /metrics
            if request.url.path in skip_paths or request.url.path == path:
                return await call_next(request)

            method = request.method
            start = time.perf_counter()
            try:
                response = await call_next(request)
                status_code = getattr(response, "status_code", 500)
            except Exception:
                status_code = 500
                raise
            finally:
                dur = time.perf_counter() - start
                # Попробуем получить шаблон пути (уменьшаем кардинальность)
                route_pattern = getattr(getattr(request.scope, "get", lambda *_: None)("route"), "path", None) \
                                or getattr(request.scope.get("router"), "default", None) \
                                or request.scope.get("path", request.url.path)

                path_tmpl = getattr(getattr(request.scope.get("route"), "path", None), "__str__", lambda: None)() \
                            if request.scope.get("route") else request.url.path

                # В большинстве случаев в Starlette/FastAPI можно взять request.scope["route"].path
                if hasattr(request, "app") and hasattr(request.app, "router"):
                    r = request.scope.get("route")
                    if r is not None and hasattr(r, "path"):
                        path_tmpl = r.path

                labels = {
                    "method": method,
                    "path": _safe_label_value(path_tmpl),
                    "status": str(status_code),
                }
                self.inc("http_requests_total", "HTTP requests count", labels, ("method", "path", "status"))
                self.observe("http_request_duration_seconds", "HTTP request duration seconds", dur, labels, ("method", "path", "status"))
            return response

    # ----------------- Доменные шорткаты -----------------

    # PDP
    def pdp_decision(self, decision: str, effect: str, tenant: str | None = None, policy_id: str | None = None):
        self.inc(
            "pdp_decisions_total",
            "PDP decisions",
            {"decision": decision, "effect": effect, "tenant": tenant, "policy_id": policy_id},
            ("decision", "effect", "tenant", "policy_id"),
        )

    @asynccontextmanager
    async def pdp_eval_time(self, tenant: str | None = None, policy_id: str | None = None):
        async with self.atime(
            "pdp_eval_seconds",
            "PDP evaluation time",
            {"tenant": tenant, "policy_id": policy_id},
            ("tenant", "policy_id"),
        ):
            yield

    # Obligations
    def obligation_applied(self, obl_type: str, status: str = "ok", tenant: str | None = None):
        self.inc(
            "obligation_applied_total",
            "Obligation applications",
            {"type": obl_type, "status": status, "tenant": tenant},
            ("type", "status", "tenant"),
        )

    # Repository
    @asynccontextmanager
    async def repo_op(self, op: str, store: str, tenant: str | None = None):
        labels = {"op": op, "store": store, "tenant": tenant, "status": "ok"}
        start = time.perf_counter()
        try:
            yield
        except Exception:
            labels["status"] = "error"
            raise
        finally:
            dur = time.perf_counter() - start
            self.observe("repo_op_seconds", "Repository operation seconds", dur, labels, ("op", "store", "tenant", "status"))

    # Cache events (опционально)
    def cache_event(self, event: str, cache: str = "decision"):
        self.inc("cache_events_total", "Cache events", {"event": event, "cache": cache}, ("event", "cache"))

    # ----------------- Внутреннее объявление доменных метрик (idempotent) -----------------

    def _define_domain_metrics(self) -> None:
        # Создаем заранее, чтобы получить стабильность имен и типов
        self.counter("http_requests_total", "HTTP requests count", ("method", "path", "status"))
        self.histogram("http_request_duration_seconds", "HTTP request duration seconds", ("method", "path", "status"))

        self.counter("pdp_decisions_total", "PDP decisions", ("decision", "effect", "tenant", "policy_id"))
        self.histogram("pdp_eval_seconds", "PDP evaluation time", ("tenant", "policy_id"))

        self.counter("obligation_applied_total", "Obligation applications", ("type", "status", "tenant"))

        self.histogram("repo_op_seconds", "Repository operation seconds", ("op", "store", "tenant", "status"))

        self.counter("cache_events_total", "Cache events", ("event", "cache"))

    # ----------------- Fallback экспорт счетчиков -----------------

    def _export_text_counters(self) -> str:
        if self.exporter == "prometheus":
            return ""
        lines: list[str] = []
        ns = self.namespace
        ss = self.subsystem
        with self._lock:
            for key, adapter in self._counters.items():
                # adapter у локального хранит ссылку на хранилище значений
                if isinstance(adapter, _LocalCounterAdapter):
                    name = key.split(":", 2)[1]
                    full = f"{ns}_{ss}_{name}_total"
                    store = adapter._store
                    # Выводим суммарное значение без лейблов (упрощение fallback'а).
                    total = sum(store.values())
                    lines.append(f"{full} {total}")
        return "\n".join(lines)


# --------------------------------------------------------------------------------------
# АДАПТЕРЫ КОНКРЕТНЫХ РЕАЛИЗАЦИЙ
# --------------------------------------------------------------------------------------

class _PromCounterAdapter(_Counter):
    def __init__(self, counter, label_names: _t.Tuple[str, ...]):
        self._c = counter
        self._label_names = label_names

    def inc(self, value: float = 1.0, **labels: str) -> None:
        labels = {k: _safe_label_value(labels.get(k)) for k in self._label_names}
        self._c.labels(**labels).inc(value)


class _PromHistogramAdapter(_Histogram):
    def __init__(self, hist, label_names: _t.Tuple[str, ...]):
        self._h = hist
        self._label_names = label_names

    def observe(self, value: float, **labels: str) -> None:
        labels = {k: _safe_label_value(labels.get(k)) for k in self._label_names}
        self._h.labels(**labels).observe(value)

    @contextmanager
    def time(self, **labels: str):
        labels = {k: _safe_label_value(labels.get(k)) for k in self._label_names}
        with self._h.labels(**labels).time():
            yield


class _LocalCounterAdapter(_Counter):
    def __init__(self, counter: _LocalCounter, label_names: _t.Tuple[str, ...], store_ref: dict[tuple[str, ...], float]):
        self._c = counter
        self._label_names = label_names
        self._store = store_ref  # для fallback экспорта

    def inc(self, value: float = 1.0, **labels: str) -> None:
        # сохраним по ключам для локального экспорта
        key = tuple(_safe_label_value(labels.get(k)) for k in self._label_names)
        self._store[key] = self._store.get(key, 0.0) + float(value)
        self._c.inc(value, **labels)


class _LocalHistogramAdapter(_Histogram):
    def __init__(self, hist: _LocalHistogram, label_names: _t.Tuple[str, ...]):
        self._h = hist
        self._label_names = label_names

    def observe(self, value: float, **labels: str) -> None:
        self._h.observe(value, **labels)


# --------------------------------------------------------------------------------------
# СИНГЛТОН
# --------------------------------------------------------------------------------------

_metrics_singleton: Metrics | None = None

def get_metrics() -> Metrics:
    global _metrics_singleton
    if _metrics_singleton is None:
        _metrics_singleton = Metrics()
    return _metrics_singleton


# --------------------------------------------------------------------------------------
# ПРИМЕР ИНТЕГРАЦИИ (не исполняется при импорте)
# --------------------------------------------------------------------------------------

if __name__ == "__main__":
    import asyncio

    m = get_metrics()
    print(f"Exporter: {m.exporter}, enabled={m.enabled}")

    # Пример: PDP
    m.pdp_decision("Permit", "allow", tenant="acme", policy_id="pol-1")

    async def run():
        async with m.pdp_eval_time(tenant="acme", policy_id="pol-1"):
            await asyncio.sleep(0.02)

        # Репозиторий
        try:
            async with m.repo_op("get", "policy", tenant="acme"):
                await asyncio.sleep(0.015)
        except Exception:
            pass

        # Облигейшены
        m.obligation_applied("redact", "ok", tenant="acme")

    asyncio.run(run())

    # Fallback экспорт (если нет prometheus_client)
    if m.exporter == "none":
        print("--- /metrics (fallback) ---")
        print(m._export_text_counters())
