# path: ops/api/graphql/metrics.py
# License: MIT
from __future__ import annotations

import os
import threading
import time
from typing import Dict, List, Optional, Tuple, Callable

from fastapi import APIRouter, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

try:
    # Опционально: подключим Strawberry extension, если доступно
    from strawberry.extensions import SchemaExtension
except Exception:  # strawberry не установлен — расширение просто не будет использовано
    SchemaExtension = object  # type: ignore


# =========================
# Внутренний потокобезопасный реестр метрик
# =========================

class _Counter:
    __slots__ = ("name", "help", "label_names", "_values", "_lock")

    def __init__(self, name: str, help: str, label_names: Tuple[str, ...]) -> None:
        self.name = name
        self.help = help
        self.label_names = label_names
        self._values: Dict[Tuple[str, ...], float] = {}
        self._lock = threading.RLock()

    def inc(self, labels: Tuple[str, ...], value: float = 1.0) -> None:
        with self._lock:
            self._values[labels] = self._values.get(labels, 0.0) + value

    def export(self) -> List[str]:
        lines: List[str] = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} counter"]
        with self._lock:
            for label_vals, val in self._values.items():
                lbl = _fmt_labels(self.label_names, label_vals)
                lines.append(f"{self.name}{lbl} {val}")
        return lines


class _Histogram:
    __slots__ = ("name", "help", "label_names", "buckets", "_counts", "_sums", "_lock")

    def __init__(self, name: str, help: str, label_names: Tuple[str, ...], buckets_ms: Tuple[int, ...]) -> None:
        self.name = name
        self.help = help
        self.label_names = label_names
        self.buckets = buckets_ms
        self._counts: Dict[Tuple[str, ...], List[int]] = {}
        self._sums: Dict[Tuple[str, ...], float] = {}
        self._lock = threading.RLock()

    def observe(self, labels: Tuple[str, ...], value_ms: float) -> None:
        with self._lock:
            if labels not in self._counts:
                self._counts[labels] = [0 for _ in self.buckets] + [0]  # +Inf
                self._sums[labels] = 0.0
            self._sums[labels] += value_ms
            # бинарный поиск
            lo, hi = 0, len(self.buckets) - 1
            idx = None
            while lo <= hi:
                mid = (lo + hi) // 2
                if value_ms <= self.buckets[mid]:
                    idx = mid
                    hi = mid - 1
                else:
                    lo = mid + 1
            if idx is None:
                # +Inf
                self._counts[labels][-1] += 1
            else:
                self._counts[labels][idx] += 1

    def export(self) -> List[str]:
        lines: List[str] = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} histogram"]
        with self._lock:
            for label_vals, counts in self._counts.items():
                # cumulative buckets
                cum = 0
                for i, b in enumerate(self.buckets):
                    cum += counts[i]
                    lbl = _fmt_labels(self.label_names + ("le",), label_vals + (str(b),))
                    lines.append(f"{self.name}_bucket{lbl} {cum}")
                # +Inf
                cum += counts[-1]
                lbl_inf = _fmt_labels(self.label_names + ("le",), label_vals + ("+Inf",))
                lines.append(f"{self.name}_bucket{lbl_inf} {cum}")
                # sum и count
                lbl_plain = _fmt_labels(self.label_names, label_vals)
                lines.append(f"{self.name}_sum{lbl_plain} {self._sums[label_vals]}")
                total = sum(counts)
                lines.append(f"{self.name}_count{lbl_plain} {total}")
        return lines


def _escape(v: str) -> str:
    return v.replace("\\", "\\\\").replace("\n", "\\n").replace("\"", "\\\"")


def _fmt_labels(names: Tuple[str, ...], values: Tuple[str, ...]) -> str:
    if not names:
        return ""
    pairs = [f'{n}="{_escape(v)}"' for n, v in zip(names, values)]
    return "{" + ",".join(pairs) + "}"


class _Registry:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.counters: Dict[Tuple[str, Tuple[str, ...]], _Counter] = {}
        self.hists: Dict[Tuple[str, Tuple[str, ...]], _Histogram] = {}

    def counter(self, name: str, help: str, label_names: Tuple[str, ...]) -> _Counter:
        key = (name, label_names)
        with self._lock:
            c = self.counters.get(key)
            if c is None:
                c = _Counter(name, help, label_names)
                self.counters[key] = c
            return c

    def histogram(self, name: str, help: str, label_names: Tuple[str, ...], buckets_ms: Tuple[int, ...]) -> _Histogram:
        key = (name, label_names)
        with self._lock:
            h = self.hists.get(key)
            if h is None:
                h = _Histogram(name, help, label_names, buckets_ms)
                self.hists[key] = h
            return h

    def export(self) -> str:
        lines: List[str] = []
        with self._lock:
            for c in self.counters.values():
                lines.extend(c.export())
            for h in self.hists.values():
                lines.extend(h.export())
        return "\n".join(lines) + "\n"


_REG = _Registry()


# =========================
# Конфигурация и стабильные лейблы
# =========================

# Бакеты длительности в миллисекундах — сообразно производственным сервисам
_DEFAULT_BUCKETS_MS: Tuple[int, ...] = tuple(
    int(x) for x in (1, 2, 5, 10, 20, 50, 100, 200, 400, 800, 1500, 3000, 5000, 10000)
)

APP_NAME = os.getenv("APP_NAME", "neurocity-graphql")
SERVICE_LABELS = ("app",)
SERVICE_VALUES = (APP_NAME,)

def _svc(labels: Tuple[str, ...]) -> Tuple[str, ...]:
    # Дополняем системным лейблом приложения
    return SERVICE_VALUES + labels

def _svc_names(names: Tuple[str, ...]) -> Tuple[str, ...]:
    return SERVICE_LABELS + names


# =========================
# Объявление метрик
# =========================

# HTTP
_http_req_total = _REG.counter(
    "http_requests_total",
    "Total number of HTTP requests",
    _svc_names(("route", "method", "code")),
)
_http_req_duration = _REG.histogram(
    "http_request_duration_ms",
    "HTTP request duration in milliseconds",
    _svc_names(("route", "method")),
    _DEFAULT_BUCKETS_MS,
)
_http_req_in_bytes = _REG.counter(
    "http_request_bytes_total",
    "Total HTTP request bytes (based on Content-Length when available)",
    _svc_names(("route", "method")),
)
_http_resp_bytes = _REG.counter(
    "http_response_bytes_total",
    "Total HTTP response bytes (based on Content-Length when available)",
    _svc_names(("route", "method", "code")),
)

# GraphQL
_gql_ops_total = _REG.counter(
    "gql_operations_total",
    "Total GraphQL operations by type/name/outcome",
    _svc_names(("operation", "operation_name", "outcome")),
)
_gql_ops_duration = _REG.histogram(
    "gql_operation_duration_ms",
    "GraphQL operation duration in milliseconds",
    _svc_names(("operation", "operation_name")),
    _DEFAULT_BUCKETS_MS,
)
_gql_apq_total = _REG.counter(
    "gql_apq_requests_total",
    "Persisted query (APQ) requests: hit/miss",
    _svc_names(("hit",)),
)


# =========================
# Утилиты нормализации лейблов (ограничение кардинальности)
# =========================

def _norm_route(path: str) -> str:
    # Фиксируем только ключевые эндпоинты, остальное агрегируем
    if path.startswith("/graphql"):
        return "/graphql"
    if path.startswith("/apq"):
        return "/apq"
    if path.startswith("/metrics"):
        return "/metrics"
    if path.startswith("/health") or path.startswith("/healthz"):
        return "/healthz"
    return "/other"

def _norm_method(m: Optional[str]) -> str:
    return (m or "GET").upper()

def _norm_code(code: Optional[int]) -> str:
    try:
        return str(int(code or 200))
    except Exception:
        return "200"

def _norm_op_name(name: Optional[str]) -> str:
    if not name:
        return "anonymous"
    # ограничим длину, уберем пробелы/кавычки
    trimmed = name.strip().replace('"', "").replace("\\", "")
    return trimmed[:64] if trimmed else "anonymous"

def _norm_op_type(op: Optional[str]) -> str:
    op = (op or "query").lower()
    return op if op in ("query", "mutation", "subscription") else "query"

def _content_length_from_headers(headers) -> Optional[int]:
    try:
        v = headers.get("content-length")
        if v is None:
            return None
        return max(0, int(v))
    except Exception:
        return None


# =========================
# HTTP middleware
# =========================

class HttpMetricsMiddleware(BaseHTTPMiddleware):
    """
    Подключение:
        app.add_middleware(HttpMetricsMiddleware)
    Отслеживает длительность, код ответа и байты для всех HTTP-запросов.
    """

    async def dispatch(self, request: Request, call_next: Callable):
        start = time.perf_counter()
        route = _norm_route(request.url.path)
        method = _norm_method(request.method)
        req_len = _content_length_from_headers(request.headers) or 0
        _http_req_in_bytes.inc(_svc((route, method)), req_len)

        resp = await call_next(request)

        dur_ms = (time.perf_counter() - start) * 1000.0
        code = _norm_code(resp.status_code)
        _http_req_duration.observe(_svc((route, method)), dur_ms)
        _http_req_total.inc(_svc((route, method, code)), 1.0)

        # попробуем взять длину ответа
        resp_len = 0
        try:
            resp_len = _content_length_from_headers(resp.headers) or 0
        except Exception:
            resp_len = 0
        _http_resp_bytes.inc(_svc((route, method, code)), resp_len)

        return resp


# =========================
# Strawberry extension для GraphQL операций
# =========================

class GraphQLOperationMetrics(SchemaExtension):
    """
    Подключение в GraphQLRouter:
        extensions=[lambda: GraphQLOperationMetrics(), ...]
    Измеряет длительность и исход (success/error) по типу и имени операции.
    """

    def on_execute(self):
        # Пытаемся получить имя/тип операции из контекста выполнения Strawberry
        op_type = "query"
        op_name = "anonymous"
        try:
            ctx = self.execution_context  # type: ignore[attr-defined]
            if getattr(ctx, "operation_name", None):
                op_name = _norm_op_name(ctx.operation_name)  # type: ignore
            if getattr(ctx, "operation_type", None):
                # Enum.name или str
                raw = getattr(ctx.operation_type, "name", None) or str(ctx.operation_type)
                op_type = _norm_op_type(raw)
        except Exception:
            pass

        start = time.perf_counter()
        outcome = "success"

        try:
            yield
        except Exception:
            outcome = "error"
            raise
        finally:
            dur_ms = (time.perf_counter() - start) * 1000.0
            labels = _svc((op_type, op_name))
            _gql_ops_duration.observe(labels, dur_ms)
            _gql_ops_total.inc(_svc((op_type, op_name, outcome)), 1.0)


# =========================
# Хелперы для APQ (можно вызывать из транспорта)
# =========================

def apq_metric(*, hit: bool) -> None:
    _gql_apq_total.inc(_svc(("true" if hit else "false",)), 1.0)


# =========================
# /metrics endpoint
# =========================

metrics_router = APIRouter()

@metrics_router.get("/metrics")
async def metrics() -> Response:
    text = _REG.export()
    # Prometheus text format content-type
    return Response(text, media_type="text/plain; version=0.0.4; charset=utf-8")


# =========================
# Мини-демо интеграции (опционально)
# =========================
# В сервере:
#   from .metrics import metrics_router, HttpMetricsMiddleware, GraphQLOperationMetrics, apq_metric
#   app.add_middleware(HttpMetricsMiddleware)
#   app.include_router(metrics_router, prefix="")
#   GraphQLRouter(..., extensions=[lambda: GraphQLOperationMetrics(), ...])
#
# В APQ-транспорте:
#   apq_metric(hit=True/False)
