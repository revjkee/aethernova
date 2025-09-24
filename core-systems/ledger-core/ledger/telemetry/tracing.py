from __future__ import annotations

import contextlib
import functools
import os
import time
import types
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, Mapping, Optional, Tuple, TypeVar, Union

# Опциональный импорт OTEL: при отсутствии — no-op
try:
    from opentelemetry import baggage, context, propagate, trace
    from opentelemetry.context import Context
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.sdk.trace.sampling import (
        ParentBased,
        TraceIdRatioBased,
        ALWAYS_OFF,
        ALWAYS_ON,
    )
    from opentelemetry.semconv.resource import ResourceAttributes
    from opentelemetry.trace import (
        Span,
        SpanKind,
        Status,
        StatusCode,
        Link,
        NonRecordingSpan,
        SpanContext,
        TraceFlags,
    )
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
    _OTEL = True
except Exception:
    _OTEL = False
    # Минимальные заглушки типов
    Span = Any
    SpanKind = types.SimpleNamespace(INTERNAL="internal", CLIENT="client", SERVER="server", PRODUCER="producer", CONSUMER="consumer")

try:
    from fastapi import Request, Response
except Exception:
    Request = Any  # type: ignore
    Response = Any  # type: ignore


# =========================
# Конфигурация
# =========================

@dataclass
class TracingConfig:
    service_name: str = os.getenv("OTEL_SERVICE_NAME", "ledger-core")
    service_version: str = os.getenv("OTEL_SERVICE_VERSION", os.getenv("APP_VERSION", "0.0.0"))
    environment: str = os.getenv("APP_ENV", "dev")
    otlp_endpoint: str = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")  # gRPC
    otlp_insecure: bool = os.getenv("OTEL_EXPORTER_OTLP_INSECURE", "true").lower() == "true"
    # Сэмплинг: always_on|always_off|ratio
    sampler: str = os.getenv("OTEL_TRACES_SAMPLER", "ratio")
    sampler_ratio: float = float(os.getenv("OTEL_TRACES_SAMPLER_ARG", "0.2"))
    # Заголовок корреляции приложения
    request_id_header: str = os.getenv("REQUEST_ID_HEADER", "x-request-id")
    # Разрешённые ключи baggage для пропагации
    baggage_keys: Tuple[str, ...] = tuple(
        os.getenv("OTEL_BAGGAGE_KEYS", "tenant_id,user_id,correlation_id").split(",")
    )


# =========================
# Инициализация/Shutdown
# =========================

class Tracing:
    """
    Инициализирует OTEL трейсинг, предоставляет хелперы для пропагации и декораторы.
    В no-op режиме методы безопасно ничего не делают.
    """
    def __init__(self, cfg: Optional[TracingConfig] = None) -> None:
        self.cfg = cfg or TracingConfig()
        self.tracer = None
        self._shutdown_funcs: list[Callable[[], None]] = []

    def setup(self) -> None:
        if not _OTEL:
            return
        # Ресурс сервиса
        resource = Resource.create(
            {
                ResourceAttributes.SERVICE_NAME: self.cfg.service_name,
                ResourceAttributes.SERVICE_VERSION: self.cfg.service_version,
                ResourceAttributes.DEPLOYMENT_ENVIRONMENT: self.cfg.environment,
            }
        )
        # Сэмплер
        sampler_name = (self.cfg.sampler or "ratio").lower()
        if sampler_name == "always_on":
            sampler = ALWAYS_ON
        elif sampler_name == "always_off":
            sampler = ALWAYS_OFF
        else:
            sampler = ParentBased(TraceIdRatioBased(max(0.0, min(1.0, self.cfg.sampler_ratio))))
        # Провайдер + экспортер
        tp = TracerProvider(resource=resource, sampler=sampler)
        exp = OTLPSpanExporter(endpoint=self.cfg.otlp_endpoint, insecure=self.cfg.otlp_insecure)
        bsp = BatchSpanProcessor(
            exp,
            max_queue_size=int(os.getenv("OTEL_BSP_MAX_QUEUE_SIZE", "2048")),
            schedule_delay_millis=int(os.getenv("OTEL_BSP_SCHEDULE_DELAY_MS", "500")),
            max_export_batch_size=int(os.getenv("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", "512")),
            exporter_timeout_millis=int(float(os.getenv("OTEL_BSP_EXPORT_TIMEOUT", "30")) * 1000),
        )
        tp.add_span_processor(bsp)
        trace.set_tracer_provider(tp)
        self.tracer = trace.get_tracer(self.cfg.service_name)
        propagate.set_global_textmap(TraceContextTextMapPropagator())
        self._shutdown_funcs.append(lambda: tp.shutdown())

    def shutdown(self) -> None:
        for fn in self._shutdown_funcs:
            with contextlib.suppress(Exception):
                fn()

    # =========================
    # Пропагация: HTTP
    # =========================

    def inject_http_headers(self, headers: Optional[Dict[str, str]] = None, *, extra_baggage: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
        """
        Вставляет W3C traceparent/tracestate + baggage в словарь заголовков.
        """
        hdrs: Dict[str, str] = dict(headers or {})
        if not _OTEL:
            return hdrs
        carrier = _Carrier(hdrs)
        ctx = context.get_current()
        if extra_baggage:
            for k, v in extra_baggage.items():
                if k in self.cfg.baggage_keys:
                    ctx = baggage.set_baggage(k, str(v), ctx)
        propagate.inject(carrier.set, carrier, context=ctx)
        return hdrs

    def extract_http_headers(self, headers: Mapping[str, str]) -> Any:
        """
        Извлекает контекст из заголовков HTTP и возвращает OTEL Context (или None в no-op).
        """
        if not _OTEL:
            return None
        carrier = _Carrier(headers)
        return propagate.extract(carrier.get, carrier)

    # =========================
    # Пропагация: сообщения (очереди/шины)
    # =========================

    def inject_message_headers(self, headers: Optional[Dict[str, str]] = None, *, extra_baggage: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
        """
        То же, что inject_http_headers, но для абстрактных сообщений (dict headers).
        """
        return self.inject_http_headers(headers, extra_baggage=extra_baggage)

    def extract_message_context(self, headers: Mapping[str, str]) -> Any:
        """
        Возвращает OTEL Context из заголовков сообщения.
        """
        return self.extract_http_headers(headers)

    # =========================
    # Спаны: продьюсер/консьюмер/клиент/сервер
    # =========================

    @contextlib.contextmanager
    def span(self, name: str, *, kind: str | SpanKind = SpanKind.INTERNAL, attributes: Optional[Mapping[str, Any]] = None, links: Optional[Iterable[Link]] = None):
        """
        Универсальный контекстный менеджер спана.
        """
        if not (_OTEL and self.tracer):
            yield _NoopSpan()
            return
        sp = self.tracer.start_span(name=name, kind=kind, attributes=dict(attributes or {}), links=list(links or []))
        try:
            yield sp
        except Exception as e:
            sp.record_exception(e)
            sp.set_status(Status(StatusCode.ERROR, str(e)))
            raise
        finally:
            sp.end()

    def start_producer_span(self, name: str, *, attributes: Optional[Mapping[str, Any]] = None) -> Any:
        return self.span(name, kind=SpanKind.PRODUCER, attributes=attributes)

    def start_consumer_span(self, name: str, *, extracted_ctx: Any = None, attributes: Optional[Mapping[str, Any]] = None, link_parent: bool = True):
        """
        Создать CONSUMER спан. Если передан extracted_ctx, будет создан link или продолжение.
        """
        if not (_OTEL and self.tracer):
            return self.span(name, kind=SpanKind.CONSUMER, attributes=attributes)
        parent_ctx = extracted_ctx if extracted_ctx is not None else context.get_current()
        # Попробуем извлечь SpanContext для линка
        link: Optional[Link] = None
        if link_parent:
            sc = trace.get_current_span(parent_ctx).get_span_context() if parent_ctx else None
            if sc and sc.is_valid:
                link = Link(sc)
        return self.span(name, kind=SpanKind.CONSUMER, attributes=attributes, links=[link] if link else None)

    # =========================
    # Декоратор traced (sync/async)
    # =========================

    F = TypeVar("F", bound=Callable[..., Any])

    def traced(
        self,
        name: Optional[str] = None,
        *,
        kind: str | SpanKind = SpanKind.INTERNAL,
        attr_fn: Optional[Callable[[Tuple[Any, ...], Dict[str, Any]], Mapping[str, Any]]] = None,
    ) -> Callable[[F], F]:
        """
        Декоратор: оборачивает функцию в спан, фиксирует ошибки и атрибуты.
        attr_fn(args, kwargs) -> dict для вычисления атрибутов на лету (без PII).
        """
        def _decorator(fn: F) -> F:  # type: ignore
            span_name = name or f"{fn.__module__}.{fn.__qualname__}"

            if _is_coro(fn):
                @functools.wraps(fn)
                async def _aw(*args, **kwargs):
                    attrs = dict(attr_fn(args, kwargs) if attr_fn else {})
                    with self.span(span_name, kind=kind, attributes=attrs):
                        return await fn(*args, **kwargs)
                return _aw  # type: ignore
            else:
                @functools.wraps(fn)
                def _sw(*args, **kwargs):
                    attrs = dict(attr_fn(args, kwargs) if attr_fn else {})
                    with self.span(span_name, kind=kind, attributes=attrs):
                        return fn(*args, **kwargs)
                return _sw  # type: ignore

        return _decorator

    # =========================
    # FastAPI‑middleware (только трейсинг)
    # =========================

    def fastapi_tracing_middleware(self):
        """
        Лёгкий ASGI middleware: создаёт SERVER спан, прокидывает request_id и baggage.
        Используйте, если нужен отдельный middleware именно для трейсинга.
        """
        cfg = self.cfg
        tracer = self.tracer

        async def _mw(request: Request, call_next: Callable[[Request], Awaitable[Response]]):
            req_id = request.headers.get(cfg.request_id_header) or str(uuid.uuid4())
            attrs = {
                "http.method": request.method,
                "http.target": str(request.url),
                "net.peer.ip": request.client.host if request.client else "",
                "request_id": req_id,
            }
            if not (_OTEL and tracer):
                response = await call_next(request)
                try:
                    response.headers.setdefault(cfg.request_id_header, req_id)
                except Exception:
                    pass
                return response

            # Извлечь контекст из входящих заголовков
            ctx_in = self.extract_http_headers(request.headers)
            # Принудительно добавим baggage: correlation_id=request_id
            if ctx_in is not None:
                ctx_in = baggage.set_baggage("correlation_id", req_id, ctx_in)

            token = context.attach(ctx_in or context.get_current())
            try:
                with self.span(f"HTTP {request.method} {request.url.path}", kind=SpanKind.SERVER, attributes=attrs) as sp:
                    resp = await call_next(request)
                    sp.set_attribute("http.status_code", getattr(resp, "status_code", 200))
                    try:
                        resp.headers.setdefault(cfg.request_id_header, req_id)
                    except Exception:
                        pass
                    sp.set_status(Status(StatusCode.OK))
                    return resp
            except Exception as e:
                # Ошибка будет записана в self.span
                raise
            finally:
                context.detach(token)

        return _mw


# =========================
# Вспомогательные
# =========================

class _Carrier:
    """
    textmap‑carrier для OTEL: get/set над словарём заголовков.
    """
    def __init__(self, headers: Mapping[str, str] | Dict[str, str]):
        self._h = dict(headers)

    def get(self, key: str) -> Iterable[str]:
        v = self._h.get(key) or self._h.get(key.lower()) or self._h.get(key.upper())
        return [v] if isinstance(v, str) else ([] if v is None else [str(v)])

    def set(self, key: str, value: str) -> None:
        # Заголовки в HTTP без учёта регистра — нормализуем в lowercase
        self._h[key.lower()] = value

    def __iter__(self):
        return iter(self._h)

    def __getitem__(self, key: str) -> str:
        return self._h[key]

    def __setitem__(self, key: str, value: str) -> None:
        self._h[key] = value

    def __repr__(self) -> str:
        return f"_Carrier({self._h!r})"


class _NoopSpan:
    def set_attribute(self, *a, **k): ...
    def record_exception(self, *a, **k): ...
    def set_status(self, *a, **k): ...
    def end(self): ...


def _is_coro(fn: Callable[..., Any]) -> bool:
    return hasattr(fn, "__call__") and hasattr(fn, "__code__") and (hasattr(fn, "__await__") or asyncio_is_coro(fn))


def asyncio_is_coro(fn: Callable[..., Any]) -> bool:
    try:
        import inspect
        return inspect.iscoroutinefunction(fn)
    except Exception:
        return False


# =========================
# Фабрика singleton
# =========================

_singleton: Optional[Tracing] = None

def get_tracing() -> Tracing:
    global _singleton
    if _singleton is None:
        t = Tracing()
        t.setup()
        _singleton = t
    return _singleton


# =========================
# Примеры интеграции (для справки; можно удалить)
# =========================
# from fastapi import FastAPI
# from ledger.telemetry.tracing import get_tracing
#
# tracing = get_tracing()
# app = FastAPI()
# app.middleware("http")(tracing.fastapi_tracing_middleware())
#
# @app.get("/ping")
# @tracing.traced(kind=SpanKind.INTERNAL)
# async def ping():
#     return {"ok": True}
#
# # Продьюсер сообщения:
# headers = tracing.inject_message_headers({}, extra_baggage={"tenant_id": "t-1"})
# with tracing.start_producer_span("redis.publish", attributes={"stream": "ledger.events"}):
#     ...
#
# # Консьюмер сообщения:
# ctx = tracing.extract_message_context(headers)
# with tracing.start_consumer_span("redis.consume", extracted_ctx=ctx, attributes={"stream": "ledger.events"}):
#     ...
#
# # Shutdown:
# tracing.shutdown()
