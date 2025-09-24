# datafabric-core/datafabric/context.py
# -*- coding: utf-8 -*-
"""
Industrial Execution Context for DataFabric.

Key features:
- contextvars-based async-safe context propagation
- Correlation IDs (request_id, trace_id, span_id), tenant/user/session bindings
- Deadlines (absolute) and cooperative cancellation
- Deterministic, header-friendly serialization (X-Request-Id, X-Tenant-Id, X-DF-Context)
- Structured logging adapter without hard dependencies
- Trace hooks (on_enter, on_exit, on_event)
- Resource management via AsyncExitStack
- Child contexts (immutable-style bind/override), tags and attributes
- Task spawning helpers that preserve context
- Optional FastAPI/Starlette integration helpers (no hard deps)
- No hard dependency on OpenTelemetry/msgpack/etc.

Python: 3.10+ (uses asyncio and contextvars)
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import json
import os
import secrets
import time
import types
import uuid
from dataclasses import dataclass, field, replace
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Dict,
    Mapping,
    MutableMapping,
    Optional,
    Tuple,
    Union,
)

# ------- Context variable (process-wide) -------

_CTX_VAR: contextvars.ContextVar["ExecutionContext"] = contextvars.ContextVar(
    "datafabric_execution_context", default=None  # type: ignore[arg-type]
)

# ------- Utilities -------

def _utc_ms() -> int:
    return int(time.time() * 1000)


def _monotonic() -> float:
    return time.monotonic()


def _gen_id() -> str:
    # 128-bit randomness, hex; good for request/trace IDs
    return secrets.token_hex(16)


def _coalesce(*vals: Optional[str], default: Optional[str] = None) -> Optional[str]:
    for v in vals:
        if v:
            return v
    return default


# ------- Error types -------

class DeadlineExceeded(Exception):
    """Raised when deadline is reached."""


class ContextCancelled(Exception):
    """Raised when context was cancelled cooperatively."""


# ------- Trace hooks -------

@dataclass
class TraceHooks:
    on_enter: Optional[Callable[["ExecutionContext"], None]] = None
    on_exit: Optional[Callable[["ExecutionContext"], None]] = None
    on_event: Optional[Callable[[str, Mapping[str, Any]], None]] = None


# ------- Logging adapter (no hard deps) -------

class StructLogger:
    """
    Minimal structured logger adapter. Integrates with stdlib logging if present,
    but does not depend on it. You can plug your own sink via .sink.
    """

    def __init__(self, sink: Optional[Callable[[Mapping[str, Any]], None]] = None) -> None:
        self.sink = sink or self._default_sink

    def _default_sink(self, record: Mapping[str, Any]) -> None:
        # Fallback: JSON line to stdout
        try:
            print(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
        except Exception:
            # last resort, avoid crashing logging path
            print(str(record))

    def log(self, level: str, message: str, **fields: Any) -> None:
        rec = {"ts": _utc_ms(), "level": level.upper(), "msg": message}
        rec.update(fields)
        self.sink(rec)

    def info(self, message: str, **fields: Any) -> None:
        self.log("INFO", message, **fields)

    def warn(self, message: str, **fields: Any) -> None:
        self.log("WARN", message, **fields)

    def error(self, message: str, **fields: Any) -> None:
        self.log("ERROR", message, **fields)

    def debug(self, message: str, **fields: Any) -> None:
        self.log("DEBUG", message, **fields)


# ------- ExecutionContext -------

@dataclass(frozen=True)
class ExecutionContext:
    """
    Immutable execution context snapshot. Use .bind() / .child() to derive.
    Cancellation and resource stack are managed out-of-band (ContextHandle).
    """

    # Identity / correlation
    request_id: str
    trace_id: str
    span_id: str

    # Multi-tenancy / principal
    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None

    # Attributes & tags
    attrs: Mapping[str, Any] = field(default_factory=dict)
    tags: Mapping[str, str] = field(default_factory=dict)

    # Time management
    started_monotonic: float = field(default_factory=_monotonic)
    deadline_ms: Optional[int] = None  # absolute UTC ms

    # Operational
    source: Optional[str] = None            # e.g., "http", "worker", "cron"
    client_addr: Optional[str] = None
    user_agent: Optional[str] = None
    env: Optional[str] = field(default_factory=lambda: os.getenv("ENV") or os.getenv("ENVIRONMENT"))

    # Logging/tracing
    logger: StructLogger = field(default_factory=StructLogger)
    trace_hooks: TraceHooks = field(default_factory=TraceHooks)

    # ---- Derivation APIs ----

    def bind(self, **updates: Any) -> "ExecutionContext":
        """
        Return a copy with updated fields (shallow, immutable).
        Allowed keys are dataclass fields, attrs, tags are merged.
        """
        new_attrs = dict(self.attrs)
        new_tags = dict(self.tags)

        if "attrs" in updates:
            merged = dict(new_attrs)
            merged.update(updates.pop("attrs") or {})
            updates["attrs"] = merged
        if "tags" in updates:
            merged_t = dict(new_tags)
            merged_t.update(updates.pop("tags") or {})
            updates["tags"] = merged_t

        return replace(self, **updates)

    def child(self, span_id: Optional[str] = None, **updates: Any) -> "ExecutionContext":
        """
        Produce a child context (new span), preserving trace/request IDs by default.
        """
        span_id = span_id or _gen_id()
        return self.bind(span_id=span_id, **updates)

    # ---- Introspection ----

    def remaining_ms(self) -> Optional[int]:
        if self.deadline_ms is None:
            return None
        rem = self.deadline_ms - _utc_ms()
        return max(0, rem)

    def is_expired(self) -> bool:
        rem = self.remaining_ms()
        return rem is not None and rem <= 0

    # ---- Header serialization ----

    def to_headers(self) -> Dict[str, str]:
        """
        Serialize context to HTTP/WebSocket headers.
        Compact and deterministic.
        """
        hdr = {
            "X-Request-Id": self.request_id,
            "X-Trace-Id": self.trace_id,
            "X-Span-Id": self.span_id,
        }
        if self.tenant_id:
            hdr["X-Tenant-Id"] = self.tenant_id
        if self.user_id:
            hdr["X-User-Id"] = self.user_id
        if self.session_id:
            hdr["X-Session-Id"] = self.session_id
        if self.deadline_ms:
            hdr["X-Deadline-Ms"] = str(self.deadline_ms)

        # Pack attrs/tags into a single header to avoid header bloat
        meta = {"attrs": self.attrs or {}, "tags": self.tags or {}}
        if meta["attrs"] or meta["tags"]:
            hdr["X-DF-Context"] = json.dumps(meta, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        return hdr

    @staticmethod
    def from_headers(headers: Mapping[str, str], default_source: Optional[str] = None) -> "ExecutionContext":
        """
        Construct context from HTTP/WebSocket headers. Missing parts are generated.
        """
        req_id = headers.get("x-request-id") or headers.get("X-Request-Id")
        trace_id = headers.get("x-trace-id") or headers.get("X-Trace-Id")
        span_id = headers.get("x-span-id") or headers.get("X-Span-Id")
        tenant = headers.get("x-tenant-id") or headers.get("X-Tenant-Id")
        user = headers.get("x-user-id") or headers.get("X-User-Id")
        session = headers.get("x-session-id") or headers.get("X-Session-Id")
        deadline_raw = headers.get("x-deadline-ms") or headers.get("X-Deadline-Ms")

        attrs: Dict[str, Any] = {}
        tags: Dict[str, str] = {}
        meta_raw = headers.get("x-df-context") or headers.get("X-DF-Context")
        if meta_raw:
            try:
                meta = json.loads(meta_raw)
                if isinstance(meta, dict):
                    if isinstance(meta.get("attrs"), dict):
                        attrs.update(meta["attrs"])
                    if isinstance(meta.get("tags"), dict):
                        tags.update({str(k): str(v) for k, v in meta["tags"].items()})
            except Exception:
                # Header may be malformed; ignore silently to avoid coupling
                pass

        deadline_ms = None
        if deadline_raw:
            try:
                deadline_ms = int(deadline_raw)
            except Exception:
                deadline_ms = None

        return ExecutionContext(
            request_id=_coalesce(req_id, default=_gen_id()),
            trace_id=_coalesce(trace_id, req_id, default=_gen_id()),
            span_id=_coalesce(span_id, default=_gen_id()),
            tenant_id=tenant,
            user_id=user,
            session_id=session,
            attrs=attrs,
            tags=tags,
            deadline_ms=deadline_ms,
            source=default_source,
        )


# ------- Context handle: cancellation, resources, deadline enforcement -------

@dataclass
class ContextHandle:
    ctx: ExecutionContext
    _token: Optional[contextvars.Token] = field(default=None, init=False)
    _cancel_event: asyncio.Event = field(default_factory=asyncio.Event, init=False)
    _stack: contextlib.AsyncExitStack = field(default_factory=contextlib.AsyncExitStack, init=False)

    async def __aenter__(self) -> "ContextHandle":
        self._token = _CTX_VAR.set(self.ctx)
        # Trace hook
        if self.ctx.trace_hooks.on_enter:
            try:
                self.ctx.trace_hooks.on_enter(self.ctx)
            except Exception:
                pass
        return self

    async def __aexit__(self, exc_type, exc, tb) -> Optional[bool]:
        # Trace hook
        if self.ctx.trace_hooks.on_exit:
            try:
                self.ctx.trace_hooks.on_exit(self.ctx)
            except Exception:
                pass
        # Restore previous context
        if self._token is not None:
            _CTX_VAR.reset(self._token)
        # Close managed resources
        await self._stack.aclose()
        # Do not suppress exceptions
        return None

    # ---- Cancellation & deadline ----

    def cancel(self) -> None:
        self._cancel_event.set()

    def cancelled(self) -> bool:
        return self._cancel_event.is_set()

    async def check(self) -> None:
        """
        Raise if cancelled or deadline exceeded.
        Intended to be called at cooperative checkpoints.
        """
        if self.cancelled():
            raise ContextCancelled("context cancelled")
        if self.ctx.is_expired():
            raise DeadlineExceeded("deadline exceeded")

    async def sleep(self, delay: float) -> None:
        """
        Sleep cooperatively respecting deadline/cancellation.
        """
        if delay <= 0:
            return
        start = _monotonic()
        while True:
            await asyncio.wait(
                [
                    asyncio.create_task(asyncio.sleep(min(0.05, delay))),
                    asyncio.create_task(self._cancel_event.wait()),
                ],
                return_when=asyncio.FIRST_COMPLETED,
            )
            if self.cancelled():
                raise ContextCancelled("context cancelled")
            if self.ctx.is_expired():
                raise DeadlineExceeded("deadline exceeded")
            elapsed = _monotonic() - start
            if elapsed >= delay:
                return

    # ---- Resource management passthrough ----

    async def enter_async_context(self, cm) -> Any:
        return await self._stack.enter_async_context(cm)

    def push_async_callback(self, func: Callable[..., Awaitable[None]], *args, **kwargs) -> None:
        async def _cb():
            await func(*args, **kwargs)
        self._stack.push_async_callback(lambda: _cb())


# ------- Context creation/helpers -------

def new_context(
    *,
    request_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    span_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    user_id: Optional[str] = None,
    session_id: Optional[str] = None,
    attrs: Optional[Mapping[str, Any]] = None,
    tags: Optional[Mapping[str, str]] = None,
    source: Optional[str] = None,
    client_addr: Optional[str] = None,
    user_agent: Optional[str] = None,
    deadline_ms: Optional[int] = None,
    logger: Optional[StructLogger] = None,
    trace_hooks: Optional[TraceHooks] = None,
) -> ExecutionContext:
    return ExecutionContext(
        request_id=request_id or _gen_id(),
        trace_id=trace_id or request_id or _gen_id(),
        span_id=span_id or _gen_id(),
        tenant_id=tenant_id,
        user_id=user_id,
        session_id=session_id,
        attrs=dict(attrs or {}),
        tags=dict(tags or {}),
        source=source,
        client_addr=client_addr,
        user_agent=user_agent,
        deadline_ms=deadline_ms,
        logger=logger or StructLogger(),
        trace_hooks=trace_hooks or TraceHooks(),
    )


def current_context() -> ExecutionContext:
    ctx = _CTX_VAR.get()
    if ctx is None:
        ctx = new_context(source="implicit")
        _CTX_VAR.set(ctx)
    return ctx


@contextlib.asynccontextmanager
async def with_context(ctx: ExecutionContext) -> AsyncIterator[ContextHandle]:
    handle = ContextHandle(ctx)
    async with handle:
        yield handle


def set_deadline_in(ms_from_now: int) -> ExecutionContext:
    ctx = current_context()
    return ctx.bind(deadline_ms=_utc_ms() + max(0, int(ms_from_now)))


def set_tag(key: str, value: str) -> ExecutionContext:
    ctx = current_context()
    tags = dict(ctx.tags)
    tags[key] = value
    new_ctx = ctx.bind(tags=tags)
    _CTX_VAR.set(new_ctx)
    return new_ctx


def set_attr(key: str, value: Any) -> ExecutionContext:
    ctx = current_context()
    attrs = dict(ctx.attrs)
    attrs[key] = value
    new_ctx = ctx.bind(attrs=attrs)
    _CTX_VAR.set(new_ctx)
    return new_ctx


# ------- Timeout helper (cooperative) -------

@contextlib.asynccontextmanager
async def deadline_guard() -> AsyncIterator[None]:
    """
    Raise DeadlineExceeded when context deadline reached while awaiting.
    Implemented cooperatively by checking before and after the body.
    """
    ctx = current_context()
    if ctx.is_expired():
        raise DeadlineExceeded("deadline exceeded (pre-check)")
    try:
        yield
    finally:
        if ctx.is_expired():
            raise DeadlineExceeded("deadline exceeded (post-check)")


# ------- Task spawning preserving context -------

def spawn_with_context(
    coro_fn: Callable[..., Awaitable[Any]],
    *args: Any,
    name: Optional[str] = None,
    ctx: Optional[ExecutionContext] = None,
    loop: Optional[asyncio.AbstractEventLoop] = None,
) -> asyncio.Task:
    """
    Spawn a task that inherits the given or current context.
    """
    base_ctx = ctx or current_context()
    run_ctx = contextvars.copy_context()

    async def _runner():
        # ensure ExecutionContext is in this copy
        _CTX_VAR.set(base_ctx)
        return await coro_fn(*args)

    lp = loop or asyncio.get_running_loop()
    return lp.create_task(run_ctx.run(_runner), name=name)


# ------- FastAPI/Starlette integration (optional) -------

def fastapi_context_from_request(request) -> ExecutionContext:
    """
    Build context from FastAPI Request (if FastAPI/Starlette present).
    We do not import fastapi/starlette directly to avoid hard dependency.
    """
    headers = {}
    try:
        # Starlette Headers are case-insensitive; convert to plain dict[str,str]
        for k, v in request.headers.items():
            headers[k] = v
    except Exception:
        pass

    client_addr = None
    try:
        if getattr(request, "client", None):
            client = request.client
            client_addr = f"{client.host}:{client.port}"
    except Exception:
        pass

    user_agent = headers.get("user-agent")
    ctx = ExecutionContext.from_headers(headers, default_source="http")
    return ctx.bind(client_addr=client_addr, user_agent=user_agent)


async def fastapi_context_dependency(request) -> ExecutionContext:
    """
    FastAPI dependency to inject ExecutionContext per-request.
    Usage:
        from fastapi import Depends
        @app.get("/ping")
        async def ping(ctx: ExecutionContext = Depends(fastapi_context_dependency)):
            return {"ok": True, "request_id": ctx.request_id}
    """
    ctx = fastapi_context_from_request(request)
    # install into contextvar for downstream code
    _CTX_VAR.set(ctx)
    return ctx


# ------- Event/trace helpers -------

def trace_event(event: str, **fields: Any) -> None:
    ctx = current_context()
    payload = {
        "event": event,
        "ts": _utc_ms(),
        "request_id": ctx.request_id,
        "trace_id": ctx.trace_id,
        "span_id": ctx.span_id,
        "tenant_id": ctx.tenant_id,
        "user_id": ctx.user_id,
        "source": ctx.source,
        "fields": fields,
    }
    if ctx.trace_hooks.on_event:
        try:
            ctx.trace_hooks.on_event(event, payload)
        except Exception:
            pass
    # Also emit via logger for observability
    ctx.logger.info("trace_event", **payload)


# ------- Example: context-aware log helpers -------

def log_info(message: str, **fields: Any) -> None:
    ctx = current_context()
    ctx.logger.info(
        message,
        request_id=ctx.request_id,
        trace_id=ctx.trace_id,
        span_id=ctx.span_id,
        tenant_id=ctx.tenant_id,
        user_id=ctx.user_id,
        **fields,
    )


def log_error(message: str, **fields: Any) -> None:
    ctx = current_context()
    ctx.logger.error(
        message,
        request_id=ctx.request_id,
        trace_id=ctx.trace_id,
        span_id=ctx.span_id,
        tenant_id=ctx.tenant_id,
        user_id=ctx.user_id,
        **fields,
    )


def log_debug(message: str, **fields: Any) -> None:
    ctx = current_context()
    ctx.logger.debug(
        message,
        request_id=ctx.request_id,
        trace_id=ctx.trace_id,
        span_id=ctx.span_id,
        tenant_id=ctx.tenant_id,
        user_id=ctx.user_id,
        **fields,
    )


# ------- Hardening notes -------
# - No global mutable state beyond contextvar; contexts are immutable snapshots.
# - Deadlines are cooperative by design; combine with server-side timeouts for robustness.
# - For OpenTelemetry integration, set TraceHooks to emit spans and wire logger to OTLP.
# - For workers/cron, call new_context(source="worker") at task start.
# - For WebSocket, re-use headers serialization with protocols layer.

# ------- End of module -------
