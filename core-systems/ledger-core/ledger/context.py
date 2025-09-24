# ledger-core/ledger/context.py
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from typing import Any, AsyncIterator, Callable, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple

try:  # OpenTelemetry опционально
    from opentelemetry import trace as otel_trace  # type: ignore
    from opentelemetry.trace import Tracer, Span, SpanKind  # type: ignore
except Exception:  # pragma: no cover
    otel_trace = None  # type: ignore
    Tracer = Span = None  # type: ignore
    SpanKind = None  # type: ignore

# -----------------------------
# Глобальные contextvars
# -----------------------------

_CTX: ContextVar["LedgerContext"] = ContextVar("ledger_context", default=None)  # type: ignore
_DB_SESSION: ContextVar[Any] = ContextVar("ledger_db_session", default=None)
_LOG_BOUND: ContextVar[bool] = ContextVar("ledger_log_bound", default=False)

# -----------------------------
# Вспомогательные функции
# -----------------------------

def _now() -> float:
    return time.time()

def _gen_id() -> str:
    return uuid.uuid4().hex

def _sanitize(s: Optional[str], max_len: int = 256) -> Optional[str]:
    if s is None:
        return None
    s = s.strip()
    return s[:max_len] if len(s) > max_len else s

def _parse_csv(s: Optional[str]) -> List[str]:
    if not s:
        return []
    return [p.strip() for p in s.split(",") if p.strip()]

# -----------------------------
# Основная модель контекста
# -----------------------------

@dataclass(slots=True)
class LedgerContext:
    request_id: str
    correlation_id: str
    tenant_id: Optional[str] = None
    principal_id: Optional[str] = None
    roles: Sequence[str] = field(default_factory=tuple)
    scopes: Sequence[str] = field(default_factory=tuple)

    # Атрибуты окружения
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    locale: Optional[str] = None
    region: Optional[str] = None

    # Тайм‑менеджмент
    started_at: float = field(default_factory=_now)
    deadline_ts: Optional[float] = None  # unix ts, если задан дедлайн

    # Трейсинг (опционально)
    trace_id: Optional[str] = None
    span: Any = None  # opentelemetry.trace.Span | None

    # Произвольные метаданные
    extras: Dict[str, Any] = field(default_factory=dict)

    def with_deadline(self, timeout_sec: float) -> "LedgerContext":
        return replace(self, deadline_ts=self.started_at + float(timeout_sec))

    def remaining(self) -> Optional[float]:
        if self.deadline_ts is None:
            return None
        return max(0.0, self.deadline_ts - _now())

    def is_expired(self) -> bool:
        r = self.remaining()
        return r is not None and r <= 0.0

    def child(self, **overrides: Any) -> "LedgerContext":
        """Создать дочерний контекст (для фоновой задачи/вложенной операции)."""
        base = self
        data = {**base.__dict__, **overrides}
        # дочерний request_id по‑новому, correlation_id наследуем если не переопределён
        data.setdefault("request_id", _gen_id())
        data.setdefault("correlation_id", base.correlation_id)
        data.setdefault("started_at", _now())
        return LedgerContext(**data)  # type: ignore[arg-type]


# -----------------------------
# Доступ к текущему контексту
# -----------------------------

def current() -> Optional[LedgerContext]:
    """Возвращает текущий LedgerContext или None."""
    return _CTX.get()

def require() -> LedgerContext:
    ctx = _CTX.get()
    if ctx is None:
        raise RuntimeError("LedgerContext is not set in this task")
    return ctx

def bind(ctx: LedgerContext) -> LedgerContext:
    _CTX.set(ctx)
    return ctx

def clear() -> None:
    _CTX.set(None)

# -----------------------------
# DB Session helpers (опционально)
# -----------------------------

def set_db_session(session: Any) -> None:
    """Привязать SQLAlchemy/другую сессию к контексту."""
    _DB_SESSION.set(session)

def get_db_session() -> Any:
    return _DB_SESSION.get()

# -----------------------------
# Создание контекста из заголовков/метаданных
# -----------------------------

DEFAULT_TENANT_HEADER = "x-tenant-id"
DEFAULT_REQ_HEADER = "x-request-id"
DEFAULT_CORR_HEADER = "x-correlation-id"
DEFAULT_PRINCIPAL_HEADER = "x-principal-id"
DEFAULT_ROLES_HEADER = "x-roles"
DEFAULT_SCOPES_HEADER = "x-scopes"
DEFAULT_DEADLINE_HEADER = "x-deadline-seconds"
DEFAULT_LOCALE_HEADER = "x-locale"
DEFAULT_REGION_HEADER = "x-region"
DEFAULT_UA_HEADER = "user-agent"
DEFAULT_IP_HEADER = "x-forwarded-for"

def from_headers(hdrs: Mapping[str, str]) -> LedgerContext:
    h = {k.lower(): v for k, v in hdrs.items()}
    req_id = _sanitize(h.get(DEFAULT_REQ_HEADER)) or _gen_id()
    corr_id = _sanitize(h.get(DEFAULT_CORR_HEADER)) or req_id
    tenant = _sanitize(h.get(DEFAULT_TENANT_HEADER))
    principal = _sanitize(h.get(DEFAULT_PRINCIPAL_HEADER))
    roles = tuple(_parse_csv(h.get(DEFAULT_ROLES_HEADER)))
    scopes = tuple(_parse_csv(h.get(DEFAULT_SCOPES_HEADER)))
    locale = _sanitize(h.get(DEFAULT_LOCALE_HEADER))
    region = _sanitize(h.get(DEFAULT_REGION_HEADER))
    ua = _sanitize(h.get(DEFAULT_UA_HEADER))
    ip = _sanitize((h.get(DEFAULT_IP_HEADER) or "").split(",")[0].strip()) or None
    deadline_ts: Optional[float] = None
    if h.get(DEFAULT_DEADLINE_HEADER):
        try:
            deadline_ts = _now() + float(h[DEFAULT_DEADLINE_HEADER])
        except Exception:
            deadline_ts = None

    ctx = LedgerContext(
        request_id=req_id,
        correlation_id=corr_id,
        tenant_id=tenant,
        principal_id=principal,
        roles=roles,
        scopes=scopes,
        ip=ip,
        user_agent=ua,
        locale=locale,
        region=region,
        deadline_ts=deadline_ts,
    )
    return ctx

# -----------------------------
# Логирование: привязка контекста к LogRecord
# -----------------------------

class _ContextLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        ctx = current()
        if ctx:
            setattr(record, "request_id", ctx.request_id)
            setattr(record, "correlation_id", ctx.correlation_id)
            setattr(record, "tenant_id", ctx.tenant_id or "")
            setattr(record, "principal_id", ctx.principal_id or "")
            setattr(record, "trace_id", ctx.trace_id or "")
        else:
            setattr(record, "request_id", "")
            setattr(record, "correlation_id", "")
            setattr(record, "tenant_id", "")
            setattr(record, "principal_id", "")
            setattr(record, "trace_id", "")
        return True

def bind_logging(logger: Optional[logging.Logger] = None) -> None:
    """Добавляет фильтр, чтобы контекст автоматически попадал в логи."""
    if _LOG_BOUND.get():
        return
    filt = _ContextLogFilter()
    root = logger or logging.getLogger()
    root.addFilter(filt)
    _LOG_BOUND.set(True)

# -----------------------------
# Трассировка (опционально OTel)
# -----------------------------

@asynccontextmanager
async def traced_span(name: str, attributes: Optional[Dict[str, Any]] = None) -> AsyncIterator[Optional[Any]]:
    """Создать span для текущей операции (если OTel доступен)."""
    span = None
    tracer: Optional[Tracer] = None
    if otel_trace:
        tracer = otel_trace.get_tracer("ledger-core.context")
        span = tracer.start_span(name=name, kind=SpanKind.INTERNAL if SpanKind else None)
        if attributes:
            try:
                for k, v in attributes.items():
                    span.set_attribute(k, v)  # type: ignore[attr-defined]
            except Exception:
                pass
    try:
        yield span
    finally:
        if span:
            try:
                span.end()  # type: ignore[attr-defined]
            except Exception:
                pass

# -----------------------------
# Контекст‑менеджеры активации
# -----------------------------

@contextmanager
def use(ctx: LedgerContext) -> Iterator[LedgerContext]:
    token = _CTX.set(ctx)
    try:
        yield ctx
    finally:
        _CTX.reset(token)

@asynccontextmanager
async def use_async(ctx: LedgerContext) -> AsyncIterator[LedgerContext]:
    token = _CTX.set(ctx)
    try:
        yield ctx
    finally:
        _CTX.reset(token)

# -----------------------------
# Интеграция с ASGI (Starlette/FastAPI)
# -----------------------------

class ContextMiddleware:
    """
    ASGI middleware, формирующее LedgerContext из заголовков и распространяющее его на обработчик.
    Добавляет заголовки X-Request-Id/X-Correlation-Id в ответ.
    Следит за дедлайном: при истечении — 504.
    """

    def __init__(
        self,
        app: Any,
        *,
        request_id_header: str = DEFAULT_REQ_HEADER,
        correlation_id_header: str = DEFAULT_CORR_HEADER,
        on_bind: Optional[Callable[[LedgerContext], None]] = None,
        otel_span_name: str = "http.request",
    ) -> None:
        self.app = app
        self.request_id_header = request_id_header
        self.correlation_id_header = correlation_id_header
        self.on_bind = on_bind
        self.otel_span_name = otel_span_name

    async def __call__(self, scope: Dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        headers = {}
        for k, v in scope.get("headers") or []:
            headers[k.decode("latin1")] = v.decode("latin1")

        ctx = from_headers(headers)
        bind_logging()  # гарантируем привязку фильтра к логам
        if self.on_bind:
            try:
                self.on_bind(ctx)
            except Exception:
                logging.exception("context on_bind failed")

        async def send_with_ids(message: Dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                hdrs = list(message.get("headers", []))
                hdrs.append((self.request_id_header.encode("ascii"), ctx.request_id.encode("ascii")))
                hdrs.append((self.correlation_id_header.encode("ascii"), ctx.correlation_id.encode("ascii")))
                message = {**message, "headers": hdrs}
            await send(message)

        # Дедлайн/таймаут запроса
        timeout = ctx.remaining()

        async def run_handler() -> None:
            async with use_async(ctx):
                async with traced_span(self.otel_span_name, {"http.method": scope.get("method", ""), "http.route": scope.get("path", "")}):
                    await self.app(scope, receive, send_with_ids)

        if timeout is not None and timeout > 0:
            try:
                await asyncio.wait_for(run_handler(), timeout=timeout)
            except asyncio.TimeoutError:
                logging.warning("request deadline exceeded request_id=%s", ctx.request_id)
                await _send_json(send_with_ids, 504, {"error": "deadline_exceeded", "request_id": ctx.request_id})
        else:
            await run_handler()

async def _send_json(send: Callable, status: int, payload: Dict[str, Any]) -> None:
    body = (  # минимальная сериализация без внешних зависимостей
        b'{"error":"' + payload.get("error", "error").encode("utf-8") + b'","request_id":"' + payload.get("request_id", "").encode("utf-8") + b'"}'
    )
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json; charset=utf-8")],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})

# -----------------------------
# Хелперы для фоновых задач
# -----------------------------

def spawn_inherit_context(coro_factory: Callable[[], "asyncio.Future[Any]"]) -> asyncio.Task:
    """
    Порождает фоновую задачу, наследующую текущий контекст.
    Пример:
        async def worker():
            ctx = require()
            ...
        spawn_inherit_context(lambda: worker())
    """
    parent = current()
    async def runner():
        if parent:
            async with use_async(parent.child()):
                return await coro_factory()
        return await coro_factory()
    return asyncio.create_task(runner())

# -----------------------------
# Примеры использования (docstring‑only)
# -----------------------------

"""
HTTP (FastAPI):
---------------
from fastapi import FastAPI
from ledger_core.ledger.context import ContextMiddleware, require

app = FastAPI()
app.add_middleware(ContextMiddleware)

@app.get("/me")
async def me():
    ctx = require()
    return {"request_id": ctx.request_id, "principal": ctx.principal_id}

gRPC:
-----
В gRPC интерсепторе сформируйте LedgerContext из metadata и вызовите `bind(ctx)` на время запроса.

Логи:
-----
В конфигурации логгера добавьте формат с полями %(request_id)s %(correlation_id)s %(tenant_id)s %(principal_id)s.

SQLAlchemy:
-----------
В начале запроса вызовите set_db_session(session); внутри сервисов — get_db_session() для доступа без циклических зависимостей.
"""
