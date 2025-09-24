# -*- coding: utf-8 -*-
"""
OmniMind Core — Execution Context SDK

Назначение:
- Асинхронно-безопасный контекст выполнения на основе contextvars
- Корреляция request_id/trace_id/span_id, user_id, client_ip
- Дедлайны и отмена (CancellationToken) с безопасным распространением
- Инструментация: тайминг, счетчики (опционально Prometheus)
- Мягкая интеграция с OpenTelemetry (если доступен)
- Интеграция с HTTP (FastAPI/Starlette) через from_http_request
- Адаптер логгера, автоматически добавляющий контекст в записи журналов
- Безопасная передача контекста в asyncio.create_task

Внешние зависимости:
- Опционально: prometheus_client, opentelemetry
- Жестких зависимостей, кроме стандартной библиотеки, нет.

Copyright:
- Этот модуль не хранит секреты и не делает неподтвержденных предположений.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import dataclasses
import json
import logging
import time
import types
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Mapping, Optional, Tuple, TypeVar, Union, overload

# --- Опциональные интеграции -------------------------------------------------

try:  # Prometheus (опционально)
    from prometheus_client import Counter, Histogram  # type: ignore
    _PROM_AVAILABLE = True
except Exception:  # pragma: no cover
    _PROM_AVAILABLE = False
    Counter = Histogram = None  # type: ignore

try:  # OpenTelemetry (опционально)
    from opentelemetry import trace  # type: ignore
    from opentelemetry.trace import Tracer, Span  # type: ignore
    _OTEL_AVAILABLE = True
except Exception:  # pragma: no cover
    _OTEL_AVAILABLE = False
    trace = None  # type: ignore
    Tracer = Span = object  # type: ignore

# --- Метрики (ленивая инициализация) -----------------------------------------

if _PROM_AVAILABLE:
    CTX_ACTIVE = Counter(
        "omnimind_ctx_active_total",
        "Total number of contexts activated",
        ["env"],
    )
    CTX_INSTRUMENT_DURATION = Histogram(
        "omnimind_ctx_instrument_duration_seconds",
        "Duration of instrumented operations",
        ["op"],
        buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
    )
else:  # no-op заглушки
    class _Noop:
        def labels(self, *args, **kwargs): return self
        def inc(self, *args, **kwargs): pass
        def observe(self, *args, **kwargs): pass
    CTX_ACTIVE = CTX_INSTRUMENT_DURATION = _Noop()  # type: ignore

# --- Контекстные переменные ---------------------------------------------------

_CTX: contextvars.ContextVar["Context"] = contextvars.ContextVar("omnimind_context", default=None)  # type: ignore

# --- Вспомогательные сущности -------------------------------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _new_id() -> str:
    return uuid.uuid4().hex

def _normalize_env(env: Optional[str]) -> str:
    return (env or "production").lower()

@dataclass(frozen=True)
class Deadline:
    """
    Дедлайн основан на абсолютном моменте времени.
    """
    expires_at: Optional[float] = None  # epoch seconds

    @staticmethod
    def from_timeout(seconds: Optional[float]) -> "Deadline":
        if seconds is None:
            return Deadline(None)
        return Deadline(time.time() + float(seconds))

    def remaining(self) -> Optional[float]:
        if self.expires_at is None:
            return None
        return max(0.0, self.expires_at - time.time())

    def expired(self) -> bool:
        rem = self.remaining()
        return rem is not None and rem <= 0.0

    async def sleep(self, seconds: float) -> None:
        """
        Спит не дольше дедлайна. Возбуждает asyncio.TimeoutError при истечении.
        """
        if self.expires_at is None:
            await asyncio.sleep(seconds)
            return
        end = time.time() + seconds
        while True:
            rem_ctx = self.remaining()
            if rem_ctx is not None and rem_ctx <= 0:
                raise asyncio.TimeoutError("Deadline expired during sleep")
            to_sleep = min(seconds, rem_ctx if rem_ctx is not None else seconds)
            await asyncio.sleep(min(to_sleep, 0.05 if to_sleep < 0.1 else to_sleep))
            seconds = end - time.time()
            if seconds <= 0:
                return

class CancellationToken:
    """
    Потокобезопасный токен отмены. Совместим с asyncio.
    """
    __slots__ = ("_event", "_reason")

    def __init__(self) -> None:
        self._event = asyncio.Event()
        self._reason: Optional[str] = None

    def cancel(self, reason: Optional[str] = None) -> None:
        if not self._event.is_set():
            self._reason = reason
            self._event.set()

    def is_cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> Optional[str]:
        return self._reason

    async def wait(self) -> None:
        await self._event.wait()

# --- Адаптер логгера ----------------------------------------------------------

class ContextLoggerAdapter(logging.LoggerAdapter):
    """
    Добавляет поля контекста в лог-записи.
    """
    def __init__(self, logger: logging.Logger, ctx: "Context"):
        super().__init__(logger, {})
        self._ctx = ctx

    def process(self, msg, kwargs):
        extra = kwargs.get("extra", {})
        extra.update({
            "request_id": self._ctx.request_id,
            "trace_id": self._ctx.trace_id or "",
            "span_id": self._ctx.span_id or "",
            "env": self._ctx.env,
        })
        # опциональные сведения
        if self._ctx.user_id:
            extra["user_id"] = self._ctx.user_id
        if self._ctx.client_ip:
            extra["client_ip"] = self._ctx.client_ip
        kwargs["extra"] = extra
        return msg, kwargs

# --- Основной контекст --------------------------------------------------------

@dataclass(frozen=True)
class Context:
    """
    Носитель метаданных запроса и настроек выполнения.
    Иммутабелен; для изменений создавайте дочерние контексты .child().
    """
    request_id: str
    env: str = field(default="production")
    trace_id: Optional[str] = field(default=None)
    span_id: Optional[str] = field(default=None)
    user_id: Optional[str] = field(default=None)
    client_ip: Optional[str] = field(default=None)
    tags: Mapping[str, str] = field(default_factory=dict)
    start_time: datetime = field(default_factory=_utcnow)
    deadline: Deadline = field(default_factory=Deadline)
    cancel_token: CancellationToken = field(default_factory=CancellationToken)
    kv: Mapping[str, Any] = field(default_factory=dict)

    # --- Фабрики --------------------------------------------------------------

    @staticmethod
    def new(env: Optional[str] = None, request_id: Optional[str] = None, **kwargs: Any) -> "Context":
        ctx = Context(
            request_id=request_id or _new_id(),
            env=_normalize_env(env),
            **kwargs,
        )
        return ctx

    @staticmethod
    def from_http_request(request: Any, env: Optional[str] = None) -> "Context":
        """
        Создает контекст на основе FastAPI/Starlette Request.
        Не импортирует FastAPI напрямую, чтобы избежать жесткой зависимости.
        """
        headers = {}
        try:
            headers = dict(request.headers)  # Starlette Headers -> dict
        except Exception:
            pass

        rid = headers.get("x-request-id") or _new_id()
        traceparent = headers.get("traceparent")
        # traceparent формата W3C: version-traceid-spanid-flags
        t_id, s_id = None, None
        if traceparent:
            try:
                parts = traceparent.split("-")
                if len(parts) >= 3:
                    t_id, s_id = parts[1], parts[2]
            except Exception:
                t_id, s_id = None, None

        client_ip = None
        try:
            client_ip = request.client.host  # Starlette
        except Exception:
            pass

        return Context.new(
            env=env,
            request_id=rid,
            trace_id=t_id,
            span_id=s_id,
            client_ip=client_ip,
        )

    # --- Мутации через порождение --------------------------------------------

    def child(
        self,
        *,
        request_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        user_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        tags: Optional[Mapping[str, str]] = None,
        timeout_s: Optional[float] = None,
        kv: Optional[Mapping[str, Any]] = None,
    ) -> "Context":
        """
        Порождает новый контекст на основе текущего.
        Если задан timeout_s, формируется новый Deadline, иначе наследуется текущий.
        """
        return Context(
            request_id=request_id or self.request_id,
            env=self.env,
            trace_id=trace_id if trace_id is not None else self.trace_id,
            span_id=span_id if span_id is not None else self.span_id,
            user_id=user_id if user_id is not None else self.user_id,
            client_ip=client_ip if client_ip is not None else self.client_ip,
            tags={**(self.tags or {}), **(tags or {})},
            start_time=self.start_time,
            deadline=Deadline.from_timeout(timeout_s) if timeout_s is not None else self.deadline,
            cancel_token=self.cancel_token,
            kv={**(self.kv or {}), **(kv or {})},
        )

    # --- Утилиты --------------------------------------------------------------

    def bind_logger(self, logger: Optional[logging.Logger] = None) -> ContextLoggerAdapter:
        lg = logger or logging.getLogger("omnimind")
        return ContextLoggerAdapter(lg, self)

    def to_json(self) -> str:
        return json.dumps({
            "request_id": self.request_id,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "env": self.env,
            "user_id": self.user_id,
            "client_ip": self.client_ip,
            "tags": dict(self.tags or {}),
            "start_time": self.start_time.isoformat(),
            "deadline": self.deadline.expires_at,
        }, ensure_ascii=False)

    # Контекстный менеджер для активации в текущем execution context
    def activate(self):
        return _Activation(self)

# --- Активация контекста ------------------------------------------------------

class _Activation:
    def __init__(self, ctx: Context) -> None:
        self._ctx = ctx
        self._token: Optional[contextvars.Token] = None

    def __enter__(self):
        self._token = _CTX.set(self._ctx)
        if _PROM_AVAILABLE:
            CTX_ACTIVE.labels(env=self._ctx.env).inc()
        return self._ctx

    def __exit__(self, exc_type, exc, tb):
        if self._token is not None:
            _CTX.reset(self._token)
            self._token = None
        # не подавляем исключения
        return False

# --- Глобальные вспомогательные функции --------------------------------------

def current() -> Optional[Context]:
    """
    Возвращает текущий активный контекст или None.
    """
    try:
        return _CTX.get()
    except LookupError:
        return None

def require_current() -> Context:
    ctx = current()
    if ctx is None:
        raise RuntimeError("Context is not active")
    return ctx

# Безопасная передача контекста в создаваемые задачи
def create_task(coro, *, name: Optional[str] = None, ctx: Optional[Context] = None) -> asyncio.Task:
    """
    Обертка над asyncio.create_task, которая переносит контекст в новую задачу.
    """
    ctx_to_use = ctx or current()
    if ctx_to_use is None:
        return asyncio.create_task(coro, name=name)
    def _runner(coro_):
        async def _w():
            with ctx_to_use.activate():
                return await coro_
        return _w()
    return asyncio.create_task(_runner(coro), name=name)

# --- Инструментация -----------------------------------------------------------

F = TypeVar("F", bound=Callable[..., Any])

def instrument(op: str) -> Callable[[F], F]:
    """
    Декоратор, измеряющий длительность вызова и пишущий в лог с контекстом.
    Пример:
        @instrument("db.query")
        async def fetch(...): ...
    """
    def decorator(fn: F) -> F:
        if asyncio.iscoroutinefunction(fn):
            async def aw(*args, **kwargs):
                t0 = time.perf_counter()
                try:
                    return await fn(*args, **kwargs)
                finally:
                    dur = time.perf_counter() - t0
                    if _PROM_AVAILABLE:
                        CTX_INSTRUMENT_DURATION.labels(op=op).observe(dur)
                    lg = (current() or Context.new()).bind_logger(logging.getLogger("omnimind.instrument"))
                    lg.info(f"op={op} duration={dur:.6f}s")
            return types.FunctionType(aw.__code__, aw.__globals__, fn.__name__, aw.__defaults__, aw.__closure__)  # type: ignore
        else:
            def sw(*args, **kwargs):
                t0 = time.perf_counter()
                try:
                    return fn(*args, **kwargs)
                finally:
                    dur = time.perf_counter() - t0
                    if _PROM_AVAILABLE:
                        CTX_INSTRUMENT_DURATION.labels(op=op).observe(dur)
                    lg = (current() or Context.new()).bind_logger(logging.getLogger("omnimind.instrument"))
                    lg.info(f"op={op} duration={dur:.6f}s")
            return types.FunctionType(sw.__code__, sw.__globals__, fn.__name__, sw.__defaults__, sw.__closure__)  # type: ignore
    return decorator

# --- OpenTelemetry хелперы (мягкая зависимость) -------------------------------

@contextlib.contextmanager
def otel_span(name: str, attributes: Optional[Mapping[str, Any]] = None):
    """
    Контекстный менеджер для OTEL спана. Работает только если доступен opentelemetry.
    """
    if not _OTEL_AVAILABLE:
        # no-op
        yield None
        return
    tracer: Tracer = trace.get_tracer("omnimind.context")  # type: ignore
    with tracer.start_as_current_span(name) as span:  # type: ignore
        try:
            if attributes:
                for k, v in attributes.items():
                    try:
                        span.set_attribute(k, v)  # type: ignore
                    except Exception:
                        pass
            yield span
        finally:
            pass

# --- Интеграция с FastAPI/Starlette ------------------------------------------

def from_http_request(request: Any, env: Optional[str] = None, timeout_s: Optional[float] = None) -> Context:
    """
    Удобная обертка вокруг Context.from_http_request с установкой дедлайна.
    """
    base = Context.from_http_request(request, env=env)
    return base.child(timeout_s=timeout_s)

# --- Примитивы ожидания с учетoм дедлайна/отмены -----------------------------

async def wait_with_context(aw, *, ctx: Optional[Context] = None) -> Any:
    """
    Ожидает корутину с учетом дедлайна и токена отмены. Генерирует TimeoutError.
    """
    ctx = ctx or current()
    if ctx is None:
        return await aw

    async def _cancel_watch(task: asyncio.Task):
        await ctx.cancel_token.wait()
        if not task.done():
            task.cancel()

    task = asyncio.create_task(aw)
    watcher = asyncio.create_task(_cancel_watch(task))
    try:
        timeout = ctx.deadline.remaining()
        return await asyncio.wait_for(task, timeout=timeout)
    finally:
        watcher.cancel()
        with contextlib.suppress(Exception):
            await watcher

# --- Простейшее KV API --------------------------------------------------------

def ctx_get(key: str, default: Any = None, *, ctx: Optional[Context] = None) -> Any:
    ctx = ctx or current()
    if ctx is None or ctx.kv is None:
        return default
    return ctx.kv.get(key, default)

def ctx_with(**entries: Any) -> contextlib.AbstractContextManager[Context]:
    """
    Возвращает контекстный менеджер, расширяющий активный контекст парами KV.
    """
    base = require_current()
    child = base.child(kv=entries)
    return child.activate()

# --- Пример безопасного использования в корутине ------------------------------
# async def handler(request):
#     ctx = from_http_request(request, env=os.getenv("APP_ENV", "production"), timeout_s=30)
#     with ctx.activate():
#         log = ctx.bind_logger(logging.getLogger("omnimind.http"))
#         log.info("handling request")
#         result = await wait_with_context(do_work())
#         return result
