# -*- coding: utf-8 -*-
"""
veilmind.context
----------------
Промышленный Request/Task‑контекст для приложений veilmind‑core.

Основные возможности:
- Контекст на базе contextvars: correlation_id, request_id (ULID), tenant, subject, scopes.
- Дедлайны и отмена: deadline_ts, remaining(), cancel(), TimeoutError при enforce_deadline().
- Tamper‑evident audit chain hash для последовательностей операций.
- Интеграция с FastAPI/Starlette (извлечение заголовков, SecurityContext из request.state).
- Request‑scoped логгер: LoggerAdapter + Logging Filter для автоподмешивания полей.
- Пропагация контекста в asyncio.create_task() и run_in_executor().
- Условная интеграция с OpenTelemetry (если пакет установлен): start_span().

Внешних обязательных зависимостей нет (Starlette/OTel — опционально).
"""

from __future__ import annotations

import asyncio
import base64
import contextvars
import dataclasses
import functools
import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import TracebackType
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional, Tuple, Type, Callable, Awaitable

# -----------------------------------------------------------------------------
# Вспомогательные функции
# -----------------------------------------------------------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _epoch_ms(dt: Optional[datetime] = None) -> int:
    t = (dt or _utcnow()).timestamp()
    return int(round(t * 1000.0))

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

# -----------------------------------------------------------------------------
# ULID (монотонный) — без внешних зависимостей
# -----------------------------------------------------------------------------

# Crockford Base32
_BASE32 = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_ULID_LOCK = threading.Lock()
_ULID_LAST_TS = 0
_ULID_LAST_RAND = bytearray(os.urandom(10))

def _ulid_new() -> str:
    """
    Генерация монотонного ULID:
    - 48 бит времени (мс от эпохи)
    - 80 бит случайности; при одинаковом ts увеличиваем случайность +1
    """
    global _ULID_LAST_TS, _ULID_LAST_RAND
    with _ULID_LOCK:
        ts = _epoch_ms()
        if ts == _ULID_LAST_TS:
            # инкремент случайной части
            for i in range(9, -1, -1):
                _ULID_LAST_RAND[i] = (int(_ULID_LAST_RAND[i]) + 1) & 0xFF
                if _ULID_LAST_RAND[i] != 0:
                    break
        else:
            _ULID_LAST_TS = ts
            _ULID_LAST_RAND = bytearray(os.urandom(10))
        # Итого: 6 байт ts + 10 байт rand
        ts_bytes = ts.to_bytes(6, "big", signed=False)
        ulid_bytes = ts_bytes + bytes(_ULID_LAST_RAND)
    # кодирование в Crockford Base32 (26 символов)
    v = int.from_bytes(ulid_bytes, "big")
    out = bytearray(26)
    for i in range(26)[::-1]:
        out[i] = _BASE32[v & 0x1F]
        v >>= 5
    return out.decode("ascii")

# -----------------------------------------------------------------------------
# Контекст и хеш‑цепочка
# -----------------------------------------------------------------------------

def _chain_next(prev_hash: Optional[str], payload: Mapping[str, Any]) -> str:
    """
    Tamper‑evident chain:
        H = base64url( sha256( prev_raw || sha256(canonical_json(payload)) ) )
    где prev_raw = base64url_decode(prev_hash) при наличии.
    """
    inner = _sha256(_canonical_json(payload))
    if prev_hash:
        # восстановим байты предыдущего хеша
        pad = "=" * ((4 - len(prev_hash) % 4) % 4)
        prev_raw = base64.urlsafe_b64decode(prev_hash + pad)
        data = prev_raw + inner
    else:
        data = inner
    return _b64url(_sha256(data))

@dataclass(frozen=True)
class SecurityLike:
    """Небольшой интерфейс, который мы ожидаем от request.state.security."""
    method: str
    subject: str
    tenant: Optional[str]
    scopes: Tuple[str, ...] = ()
    claims: Dict[str, Any] = dataclasses.field(default_factory=dict)

@dataclass
class RequestContext:
    # Идентификаторы
    request_id: str = field(default_factory=_ulid_new)         # ULID — уникальный id запроса
    correlation_id: Optional[str] = None                       # извлекается из заголовков клиента
    trace_id: Optional[str] = None                             # из traceparent/библиотек трассировки
    # Безопасность/арендатор
    tenant: Optional[str] = None
    subject: Optional[str] = None
    scopes: Tuple[str, ...] = ()
    # Сетевые метаданные
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    # Временные характеристики
    start_utc: datetime = field(default_factory=_utcnow)
    deadline_ts: Optional[float] = None                        # абсолютный дедлайн, UNIX seconds (float)
    cancel_event: asyncio.Event = field(default_factory=asyncio.Event, repr=False)
    # Аудит/цепочка
    chain_hash: Optional[str] = None
    # Дополнительные поля
    extras: Dict[str, Any] = field(default_factory=dict)

    # ------------------------ Вспомогательные методы ------------------------

    def elapsed_ms(self) -> int:
        return int(round((time.time() - self.start_utc.timestamp()) * 1000.0))

    def remaining(self) -> Optional[float]:
        if self.deadline_ts is None:
            return None
        return max(0.0, self.deadline_ts - time.time())

    def with_deadline(self, timeout_seconds: float) -> "RequestContext":
        """Возвращает новый контекст с дедлайном относительно текущего момента."""
        new = dataclasses.replace(self, deadline_ts=(time.time() + float(timeout_seconds)))
        return new

    def cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def cancel(self) -> None:
        self.cancel_event.set()

    def enforce_deadline(self) -> None:
        if self.cancelled():
            raise TimeoutError("operation cancelled")
        rem = self.remaining()
        if rem is not None and rem <= 0:
            raise TimeoutError("deadline exceeded")

    def with_extras(self, **values: Any) -> "RequestContext":
        new_extras = dict(self.extras)
        new_extras.update(values)
        return dataclasses.replace(self, extras=new_extras)

    def update_chain(self, event: Mapping[str, Any]) -> "RequestContext":
        """Возвращает новый контекст со свежим chain_hash по переданному событию."""
        new_hash = _chain_next(self.chain_hash, dict(event))
        return dataclasses.replace(self, chain_hash=new_hash)

    def to_public_dict(self) -> Dict[str, Any]:
        """Безопасное представление для логов/заголовков (без секретов)."""
        return {
            "request_id": self.request_id,
            "correlation_id": self.correlation_id,
            "trace_id": self.trace_id,
            "tenant": self.tenant,
            "subject": self.subject,
            "scopes": list(self.scopes or ()),
            "client_ip": self.client_ip,
            "user_agent": self.user_agent,
            "start_utc": self.start_utc.isoformat(),
            "deadline_ts": self.deadline_ts,
            "elapsed_ms": self.elapsed_ms(),
            "chain_hash": self.chain_hash,
            "extras": self.extras,
        }

# -----------------------------------------------------------------------------
# contextvars и менеджеры
# -----------------------------------------------------------------------------

_CTX_VAR: contextvars.ContextVar[Optional[RequestContext]] = contextvars.ContextVar("veilmind_request_ctx", default=None)

def get_current() -> RequestContext:
    ctx = _CTX_VAR.get()
    if ctx is None:
        raise RuntimeError("No RequestContext bound")
    return ctx

class use_context:
    """
    Контекстный менеджер/async‑контекст для установки RequestContext в contextvars.
    Пример:
        with use_context(ctx):
            ...
        async with use_context(ctx):
            ...
    """
    def __init__(self, ctx: RequestContext):
        self._ctx = ctx
        self._token: Optional[contextvars.Token] = None

    def __enter__(self) -> RequestContext:
        self._token = _CTX_VAR.set(self._ctx)
        return self._ctx

    def __exit__(self, exc_type: Optional[Type[BaseException]], exc: Optional[BaseException], tb: Optional[TracebackType]) -> None:
        assert self._token is not None
        _CTX_VAR.reset(self._token)

    async def __aenter__(self) -> RequestContext:
        self._token = _CTX_VAR.set(self._ctx)
        return self._ctx

    async def __aexit__(self, exc_type: Optional[Type[BaseException]], exc: Optional[BaseException], tb: Optional[TracebackType]) -> None:
        assert self._token is not None
        _CTX_VAR.reset(self._token)

# -----------------------------------------------------------------------------
# Интеграция с Starlette/FastAPI (опционально)
# -----------------------------------------------------------------------------

def bind_from_starlette(request: Any, *, default_timeout_s: Optional[float] = None) -> RequestContext:
    """
    Построить RequestContext из Starlette/FASTAPI Request.
    Не требует FastAPI как зависимости; ожидает у объекта поля .headers, .client, .state.
    """
    headers: Mapping[str, str] = getattr(request, "headers", {}) or {}
    # Корреляция и трассировка
    correlation = headers.get("x-correlation-id") or headers.get("x-request-id")
    traceparent = headers.get("traceparent")  # если есть — можно извлечь trace_id (для простоты оставим строкой)
    # Клиент
    client_ip = None
    try:
        xff = headers.get("x-forwarded-for")
        if xff:
            client_ip = xff.split(",")[0].strip()
        elif getattr(request, "client", None):
            client_ip = request.client.host
    except Exception:
        client_ip = None
    ua = headers.get("user-agent")
    # SecurityContext (см. middleware/auth.py)
    tenant = None
    subject = None
    scopes: Tuple[str, ...] = ()
    state = getattr(request, "state", None)
    sec = getattr(state, "security", None)
    if sec is not None:
        tenant = getattr(sec, "tenant", None)
        subject = getattr(sec, "subject", None)
        scopes = tuple(getattr(sec, "scopes", ()) or ())

    ctx = RequestContext(
        correlation_id=correlation,
        trace_id=traceparent,
        tenant=tenant,
        subject=subject,
        scopes=scopes,
        client_ip=client_ip,
        user_agent=ua,
    )
    if default_timeout_s:
        ctx = ctx.with_deadline(default_timeout_s)
    return ctx

# -----------------------------------------------------------------------------
# Логирование: Filter и LoggerAdapter
# -----------------------------------------------------------------------------

class _ContextFilter(logging.Filter):
    """
    Автоматически подмешивает поля контекста в запись логгера:
      request_id, correlation_id, tenant, subject, trace_id, elapsed_ms.
    Не ломает форматтеры — поля доступны как %(request_id)s и т.п.
    """
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            ctx = _CTX_VAR.get()
        except Exception:
            ctx = None
        if ctx is None:
            # заполним пустыми значениями
            setattr(record, "request_id", "")
            setattr(record, "correlation_id", "")
            setattr(record, "tenant", "")
            setattr(record, "subject", "")
            setattr(record, "trace_id", "")
            setattr(record, "elapsed_ms", 0)
            return True
        setattr(record, "request_id", ctx.request_id)
        setattr(record, "correlation_id", ctx.correlation_id or "")
        setattr(record, "tenant", ctx.tenant or "")
        setattr(record, "subject", ctx.subject or "")
        setattr(record, "trace_id", ctx.trace_id or "")
        setattr(record, "elapsed_ms", ctx.elapsed_ms())
        return True

class _CtxAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        extra = kwargs.get("extra") or {}
        try:
            ctx = get_current()
            extra = {**extra,
                     "request_id": ctx.request_id,
                     "correlation_id": ctx.correlation_id or "",
                     "tenant": ctx.tenant or "",
                     "subject": ctx.subject or "",
                     "trace_id": ctx.trace_id or "",
                     "elapsed_ms": ctx.elapsed_ms()}
            kwargs["extra"] = extra
        except Exception:
            kwargs["extra"] = extra
        return msg, kwargs

def install_context_filter(root_logger: Optional[logging.Logger] = None) -> None:
    """
    Устанавливает фильтр _ContextFilter на корневой логгер (или переданный).
    Вызывайте один раз при старте приложения.
    """
    lg = root_logger or logging.getLogger()
    # Не дублируем фильтры при повторных вызовах
    for f in lg.filters:
        if isinstance(f, _ContextFilter):
            return
    lg.addFilter(_ContextFilter())

def get_logger(name: str = "veilmind") -> logging.Logger:
    """
    Возвращает LoggerAdapter, добавляющий контекстные поля.
    Используйте вместо logging.getLogger в бизнес‑коде.
    """
    base = logging.getLogger(name)
    return _CtxAdapter(base, {})

# -----------------------------------------------------------------------------
# Пропагация контекста в async‑таски и тред‑пулы
# -----------------------------------------------------------------------------

def create_task(coro: Awaitable[Any], *, name: Optional[str] = None) -> asyncio.Task:
    """
    Создает asyncio.Task, сохраняя текущий контекст (contextvars) внутри таска.
    """
    ctxvars_snapshot = contextvars.copy_context()
    async def runner():
        return await ctxvars_snapshot.run(lambda: coro)  # контекст применится для исполнения корутины
    return asyncio.create_task(runner(), name=name)

def run_in_executor(func: Callable[..., Any], *args, loop: Optional[asyncio.AbstractEventLoop] = None, **kwargs) -> asyncio.Future:
    """
    Запускает функцию в тред‑пуле, прокидывая contextvars внутри.
    Возвращает Future.
    """
    loop = loop or asyncio.get_event_loop()
    ctxvars_snapshot = contextvars.copy_context()

    def bound_call():
        return ctxvars_snapshot.run(lambda: func(*args, **kwargs))

    return loop.run_in_executor(None, bound_call)

# -----------------------------------------------------------------------------
# OpenTelemetry (опционально)
# -----------------------------------------------------------------------------

_OTEL_TRACER = None
try:
    from opentelemetry import trace as _otel_trace  # type: ignore
    _OTEL_TRACER = _otel_trace.get_tracer("veilmind.context")
except Exception:  # opentelemetry не установлен — игнорируем
    _OTEL_TRACER = None

class _NoopSpan:
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb): return False
    async def __aenter__(self): return self
    async def __aexit__(self, exc_type, exc, tb): return False
    def set_attribute(self, *_, **__): pass

def start_span(name: str, attributes: Optional[Dict[str, Any]] = None):
    """
    Начинает span OpenTelemetry (если доступен). Иначе — no‑op контекстный менеджер.
    """
    if _OTEL_TRACER is None:
        return _NoopSpan()
    span_cm = _OTEL_TRACER.start_as_current_span(name)
    # Вернем обертку, которая установит атрибуты при входе
    class _AttrWrapper:
        def __enter__(self):
            span = span_cm.__enter__()
            if attributes:
                for k, v in attributes.items():
                    span.set_attribute(k, v)
            # добавим request_id/tenant, если есть контекст
            try:
                ctx = get_current()
                span.set_attribute("veilmind.request_id", ctx.request_id)
                if ctx.tenant: span.set_attribute("veilmind.tenant", ctx.tenant)
                if ctx.subject: span.set_attribute("veilmind.subject", ctx.subject)
            except Exception:
                pass
            return span
        def __exit__(self, et, ev, tb):
            return span_cm.__exit__(et, ev, tb)
        async def __aenter__(self):
            span = await span_cm.__aenter__()
            if attributes:
                for k, v in attributes.items():
                    span.set_attribute(k, v)
            try:
                ctx = get_current()
                span.set_attribute("veilmind.request_id", ctx.request_id)
                if ctx.tenant: span.set_attribute("veilmind.tenant", ctx.tenant)
                if ctx.subject: span.set_attribute("veilmind.subject", ctx.subject)
            except Exception:
                pass
            return span
        async def __aexit__(self, et, ev, tb):
            return await span_cm.__aexit__(et, ev, tb)
    return _AttrWrapper()

# -----------------------------------------------------------------------------
# Утилиты HTTP‑заголовков для проброса вниз по стеку
# -----------------------------------------------------------------------------

def as_headers(ctx: Optional[RequestContext] = None) -> Dict[str, str]:
    """
    Канареечные заголовки для внутренней трассировки и аудита.
    Не содержат секретов.
    """
    c = ctx or get_current()
    h = {
        "X-Request-ID": c.request_id,
        "X-Correlation-ID": c.correlation_id or "",
        "X-Tenant": c.tenant or "",
        "X-Client-IP": c.client_ip or "",
        "X-Started-At": c.start_utc.isoformat(),
        "X-Elapsed-Ms": str(c.elapsed_ms()),
    }
    if c.chain_hash:
        h["X-Chain-Hash"] = c.chain_hash
    return {k: v for k, v in h.items() if v}

# -----------------------------------------------------------------------------
# Примитив: обертка для функций/корутин, применяющая enforce_deadline()
# -----------------------------------------------------------------------------

def with_deadline_enforcement(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    Декоратор, проверяющий отмену/дедлайн перед вызовом функции и после её выполнения.
    """
    if asyncio.iscoroutinefunction(func):
        @functools.wraps(func)
        async def _aw(*args, **kwargs):
            try:
                get_current().enforce_deadline()
            except Exception:
                raise
            res = await func(*args, **kwargs)
            get_current().enforce_deadline()
            return res
        return _aw
    else:
        @functools.wraps(func)
        def _w(*args, **kwargs):
            get_current().enforce_deadline()
            res = func(*args, **kwargs)
            get_current().enforce_deadline()
            return res
        return _w

# -----------------------------------------------------------------------------
# Пример удобной фабрики контекста для HTTP обработчиков
# -----------------------------------------------------------------------------

async def context_dependency(request: Any, default_timeout_s: Optional[float] = None) -> RequestContext:
    """
    FastAPI Depends‑совместимая зависимость:
        ctx = Depends(context_dependency)
    Гарантирует наличие контекста в течении обработки запроса.
    """
    ctx = bind_from_starlette(request, default_timeout_s=default_timeout_s)
    # Если уже есть связанный контекст (вложенные роуты) — не перетираем
    try:
        _ = get_current()
        # Уже привязан; обновим chain_hash для новой стадии
        with use_context(get_current().update_chain({"stage": "handler_enter", "ts": _epoch_ms()})):
            return get_current()
    except Exception:
        pass
    # Свяжем новый контекст
    with use_context(ctx.update_chain({"stage": "handler_enter", "ts": _epoch_ms()})):
        return get_current()
