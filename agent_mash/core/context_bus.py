# agent_mash/core/context_bus.py
from __future__ import annotations

import asyncio
import contextlib
import contextvars
import dataclasses
import datetime as _dt
import functools
import inspect
import logging
import secrets
import time
from collections import defaultdict
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Generic, Optional, Protocol, TypeVar, Union, cast

logger = logging.getLogger(__name__)

T = TypeVar("T")
R = TypeVar("R")

# =========================
# Errors
# =========================


class ContextBusError(RuntimeError):
    """Base error for ContextBus."""


class BusNotRunning(ContextBusError):
    """Raised when an operation requires a running bus."""


class HandlerNotFound(ContextBusError):
    """Raised when no handler is registered for a request message type."""


class RequestTimeout(ContextBusError):
    """Raised when request() exceeded timeout."""


class PublishRejected(ContextBusError):
    """Raised when publish() rejected due to backpressure or shutdown."""


class SubscriberError(ContextBusError):
    """Raised when a subscriber handler fails (wrapped when configured)."""


# =========================
# Time / IDs
# =========================


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


def _new_id(prefix: str = "") -> str:
    # URL-safe, no padding; stable for logs and correlation.
    token = secrets.token_urlsafe(16)
    return f"{prefix}{token}" if prefix else token


# =========================
# Envelope / Context
# =========================


@dataclass(frozen=True, slots=True)
class Trace:
    """Minimal trace context; extend via middleware if needed."""
    trace_id: str = field(default_factory=lambda: _new_id("tr_"))
    span_id: str = field(default_factory=lambda: _new_id("sp_"))
    parent_span_id: Optional[str] = None

    def child(self) -> "Trace":
        return Trace(trace_id=self.trace_id, span_id=_new_id("sp_"), parent_span_id=self.span_id)


@dataclass(frozen=True, slots=True)
class Envelope(Generic[T]):
    """
    Canonical message wrapper.
    payload: any object (event/command/query)
    meta: immutable metadata map
    """
    message_id: str = field(default_factory=lambda: _new_id("msg_"))
    correlation_id: str = field(default_factory=lambda: _new_id("cor_"))
    causation_id: Optional[str] = None
    created_at: _dt.datetime = field(default_factory=_utcnow)
    trace: Trace = field(default_factory=Trace)
    topic: str = "default"
    sender: Optional[str] = None
    meta: Mapping[str, Any] = field(default_factory=dict)
    payload: T = cast(T, None)

    def with_topic(self, topic: str) -> "Envelope[T]":
        return dataclasses.replace(self, topic=topic)

    def with_sender(self, sender: Optional[str]) -> "Envelope[T]":
        return dataclasses.replace(self, sender=sender)

    def with_meta(self, **meta: Any) -> "Envelope[T]":
        merged = dict(self.meta)
        merged.update(meta)
        return dataclasses.replace(self, meta=merged)

    def child(self, payload: Any, *, topic: Optional[str] = None, sender: Optional[str] = None) -> "Envelope[Any]":
        return Envelope(
            correlation_id=self.correlation_id,
            causation_id=self.message_id,
            trace=self.trace.child(),
            topic=topic if topic is not None else self.topic,
            sender=sender if sender is not None else self.sender,
            meta=self.meta,
            payload=payload,
        )


_current_envelope: contextvars.ContextVar[Optional[Envelope[Any]]] = contextvars.ContextVar(
    "context_bus_current_envelope",
    default=None,
)


def current_envelope() -> Optional[Envelope[Any]]:
    return _current_envelope.get()


@contextlib.contextmanager
def bind_envelope(env: Optional[Envelope[Any]]) -> Iterable[None]:
    token = _current_envelope.set(env)
    try:
        yield
    finally:
        _current_envelope.reset(token)


# =========================
# Middleware
# =========================

PublishFn = Callable[[Envelope[Any]], Awaitable[None]]
RequestFn = Callable[[Envelope[Any], type[R]], Awaitable[R]]


class Middleware(Protocol):
    async def publish(self, env: Envelope[Any], call_next: PublishFn) -> None: ...
    async def request(self, env: Envelope[Any], response_type: type[R], call_next: RequestFn) -> R: ...


class BaseMiddleware:
    async def publish(self, env: Envelope[Any], call_next: PublishFn) -> None:
        await call_next(env)

    async def request(self, env: Envelope[Any], response_type: type[R], call_next: RequestFn) -> R:
        return await call_next(env, response_type)


# =========================
# Handlers
# =========================

EventHandler = Callable[[Envelope[Any]], Awaitable[None]]
ReqHandler = Callable[[Envelope[Any]], Awaitable[Any]]


def _ensure_awaitable(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Awaitable[Any]:
    res = fn(*args, **kwargs)
    if inspect.isawaitable(res):
        return cast(Awaitable[Any], res)
    async def _wrap() -> Any:
        return res
    return _wrap()


# =========================
# Subscriptions
# =========================


@dataclass(slots=True)
class _Subscription:
    id: str
    topic: str
    handler: EventHandler
    concurrency: int
    semaphore: asyncio.Semaphore
    name: str


# =========================
# ContextBus
# =========================


class ContextBus:
    """
    Industrial-grade async in-memory message bus for agent_mash.

    Features:
    - publish/subscribe by topic
    - request/reply by message type with timeout
    - middleware pipeline for publish and request
    - correlation/causation/tracing via Envelope + contextvars
    - controlled concurrency and safe shutdown
    """

    def __init__(
        self,
        *,
        default_topic: str = "default",
        max_queue_size: int = 10_000,
        publish_timeout_s: float = 1.0,
        shutdown_timeout_s: float = 5.0,
        drop_on_full: bool = False,
        raise_subscriber_exceptions: bool = False,
    ) -> None:
        self._default_topic = default_topic
        self._max_queue_size = int(max_queue_size)
        self._publish_timeout_s = float(publish_timeout_s)
        self._shutdown_timeout_s = float(shutdown_timeout_s)
        self._drop_on_full = bool(drop_on_full)
        self._raise_subscriber_exceptions = bool(raise_subscriber_exceptions)

        self._running = False
        self._closing = False

        # topic -> list[sub_id]
        self._subs_by_topic: dict[str, list[str]] = defaultdict(list)
        self._subs: dict[str, _Subscription] = {}

        # topic -> queue of envelopes (fanout by dispatcher)
        self._topic_queues: dict[str, asyncio.Queue[Envelope[Any]]] = {}
        self._dispatch_tasks: dict[str, asyncio.Task[None]] = {}

        # request handlers: msg_type -> handler
        self._req_handlers: dict[type[Any], ReqHandler] = {}

        # middlewares
        self._middlewares: list[Middleware] = []

        # task tracking
        self._tasks: set[asyncio.Task[Any]] = set()
        self._tasks_lock = asyncio.Lock()

        # lifecycle lock
        self._state_lock = asyncio.Lock()

    # -------------------------
    # Lifecycle
    # -------------------------

    @property
    def is_running(self) -> bool:
        return self._running and not self._closing

    async def start(self) -> None:
        async with self._state_lock:
            if self._running:
                return
            self._running = True
            self._closing = False

    async def stop(self) -> None:
        async with self._state_lock:
            if not self._running:
                return
            self._closing = True

        # stop dispatchers first
        for topic, task in list(self._dispatch_tasks.items()):
            task.cancel()

        # wait for tasks to finish
        await self._drain_tasks(timeout=self._shutdown_timeout_s)

        # cleanup queues and dispatchers
        self._dispatch_tasks.clear()
        self._topic_queues.clear()

        async with self._state_lock:
            self._running = False
            self._closing = False

    # -------------------------
    # Middleware management
    # -------------------------

    def add_middleware(self, mw: Middleware) -> None:
        self._middlewares.append(mw)

    # -------------------------
    # Subscriptions
    # -------------------------

    def subscribe(
        self,
        topic: str,
        handler: EventHandler,
        *,
        concurrency: int = 1,
        name: Optional[str] = None,
    ) -> str:
        if concurrency < 1:
            raise ValueError("concurrency must be >= 1")

        sub_id = _new_id("sub_")
        sub = _Subscription(
            id=sub_id,
            topic=topic,
            handler=handler,
            concurrency=concurrency,
            semaphore=asyncio.Semaphore(concurrency),
            name=name or getattr(handler, "__name__", "subscriber"),
        )
        self._subs[sub_id] = sub
        self._subs_by_topic[topic].append(sub_id)

        # Ensure dispatcher exists for this topic
        self._ensure_topic(topic)

        return sub_id

    def unsubscribe(self, sub_id: str) -> None:
        sub = self._subs.pop(sub_id, None)
        if not sub:
            return
        ids = self._subs_by_topic.get(sub.topic)
        if ids and sub_id in ids:
            ids.remove(sub_id)

    # -------------------------
    # Request handlers
    # -------------------------

    def register_handler(self, message_type: type[Any], handler: ReqHandler) -> None:
        self._req_handlers[message_type] = handler

    def unregister_handler(self, message_type: type[Any]) -> None:
        self._req_handlers.pop(message_type, None)

    # -------------------------
    # Public API
    # -------------------------

    async def publish(
        self,
        payload: Any,
        *,
        topic: Optional[str] = None,
        sender: Optional[str] = None,
        meta: Optional[Mapping[str, Any]] = None,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None,
        trace: Optional[Trace] = None,
    ) -> None:
        env = Envelope(
            topic=topic or self._default_topic,
            sender=sender,
            meta=meta or {},
            correlation_id=correlation_id or _new_id("cor_"),
            causation_id=causation_id,
            trace=trace or Trace(),
            payload=payload,
        )
        await self.publish_envelope(env)

    async def publish_envelope(self, env: Envelope[Any]) -> None:
        if not self.is_running:
            raise BusNotRunning("ContextBus is not running")

        # middleware chain
        async def _core_publish(e: Envelope[Any]) -> None:
            await self._enqueue_topic(e.topic, e)

        call: PublishFn = _core_publish
        for mw in reversed(self._middlewares):
            next_call = call

            async def _mw_call(e: Envelope[Any], *, _mw=mw, _next=next_call) -> None:
                await _mw.publish(e, _next)

            call = _mw_call

        await call(env)

    async def request(
        self,
        payload: Any,
        response_type: type[R],
        *,
        sender: Optional[str] = None,
        meta: Optional[Mapping[str, Any]] = None,
        timeout_s: float = 5.0,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None,
        trace: Optional[Trace] = None,
    ) -> R:
        env = Envelope(
            topic="__request__",
            sender=sender,
            meta=meta or {},
            correlation_id=correlation_id or _new_id("cor_"),
            causation_id=causation_id,
            trace=trace or Trace(),
            payload=payload,
        )
        return await self.request_envelope(env, response_type=response_type, timeout_s=timeout_s)

    async def request_envelope(
        self,
        env: Envelope[Any],
        *,
        response_type: type[R],
        timeout_s: float = 5.0,
    ) -> R:
        if not self.is_running:
            raise BusNotRunning("ContextBus is not running")

        async def _core_request(e: Envelope[Any], rt: type[R]) -> R:
            return await self._handle_request(e, rt, timeout_s=timeout_s)

        call: RequestFn = _core_request
        for mw in reversed(self._middlewares):
            next_call = call

            async def _mw_call(e: Envelope[Any], rt: type[R], *, _mw=mw, _next=next_call) -> R:
                return await _mw.request(e, rt, _next)

            call = _mw_call

        return await call(env, response_type)

    # -------------------------
    # Internals: topic dispatch
    # -------------------------

    def _ensure_topic(self, topic: str) -> None:
        if topic not in self._topic_queues:
            self._topic_queues[topic] = asyncio.Queue(maxsize=self._max_queue_size)
        if topic not in self._dispatch_tasks:
            self._dispatch_tasks[topic] = asyncio.create_task(self._dispatch_loop(topic))

    async def _enqueue_topic(self, topic: str, env: Envelope[Any]) -> None:
        self._ensure_topic(topic)
        q = self._topic_queues[topic]

        if self._closing:
            raise PublishRejected("ContextBus is closing")

        try:
            if self._drop_on_full:
                q.put_nowait(env)
                return
            await asyncio.wait_for(q.put(env), timeout=self._publish_timeout_s)
        except asyncio.QueueFull as e:
            raise PublishRejected(f"Topic queue is full: {topic}") from e
        except asyncio.TimeoutError as e:
            raise PublishRejected(f"Publish timeout on topic: {topic}") from e

    async def _dispatch_loop(self, topic: str) -> None:
        q = self._topic_queues[topic]
        try:
            while True:
                env = await q.get()
                try:
                    await self._fanout(topic, env)
                finally:
                    q.task_done()
        except asyncio.CancelledError:
            # graceful exit
            return
        except Exception:
            logger.exception("ContextBus dispatcher crashed for topic=%s", topic)
            return

    async def _fanout(self, topic: str, env: Envelope[Any]) -> None:
        subs = list(self._subs_by_topic.get(topic, []))
        if not subs:
            return

        # schedule subscriber calls without blocking dispatcher
        for sub_id in subs:
            sub = self._subs.get(sub_id)
            if not sub:
                continue

            async def _run(sub_: _Subscription, env_: Envelope[Any]) -> None:
                async with sub_.semaphore:
                    with bind_envelope(env_):
                        try:
                            await sub_.handler(env_)
                        except asyncio.CancelledError:
                            raise
                        except Exception as e:
                            logger.exception(
                                "Subscriber failed: topic=%s sub=%s name=%s msg_id=%s cor_id=%s",
                                topic,
                                sub_.id,
                                sub_.name,
                                env_.message_id,
                                env_.correlation_id,
                            )
                            if self._raise_subscriber_exceptions:
                                raise SubscriberError(str(e)) from e

            task = asyncio.create_task(_run(sub, env))
            await self._track_task(task)

    # -------------------------
    # Internals: request handling
    # -------------------------

    async def _handle_request(self, env: Envelope[Any], response_type: type[R], *, timeout_s: float) -> R:
        msg_type = type(env.payload)
        handler = self._req_handlers.get(msg_type)
        if handler is None:
            raise HandlerNotFound(f"No request handler for message type: {msg_type.__name__}")

        async def _call() -> Any:
            with bind_envelope(env):
                return await _ensure_awaitable(handler, env)

        start = time.monotonic()
        try:
            result = await asyncio.wait_for(_call(), timeout=timeout_s)
        except asyncio.TimeoutError as e:
            elapsed = time.monotonic() - start
            raise RequestTimeout(f"Request timed out after {elapsed:.3f}s for {msg_type.__name__}") from e

        # strong-ish typing check, but not overstrict: allow subclasses
        if not isinstance(result, response_type):
            raise TypeError(
                f"Request handler for {msg_type.__name__} returned {type(result).__name__}, "
                f"expected {response_type.__name__}"
            )
        return cast(R, result)

    # -------------------------
    # Task tracking
    # -------------------------

    async def _track_task(self, task: asyncio.Task[Any]) -> None:
        async with self._tasks_lock:
            self._tasks.add(task)
        task.add_done_callback(self._on_task_done)

    def _on_task_done(self, task: asyncio.Task[Any]) -> None:
        # no await in callback; best-effort cleanup
        try:
            exc = task.exception()
            if exc is not None and not isinstance(exc, asyncio.CancelledError):
                logger.debug("Tracked task ended with exception: %r", exc)
        except asyncio.CancelledError:
            pass
        finally:
            # schedule removal safely
            asyncio.get_event_loop().call_soon_threadsafe(self._tasks.discard, task)

    async def _drain_tasks(self, *, timeout: float) -> None:
        deadline = time.monotonic() + float(timeout)
        while True:
            async with self._tasks_lock:
                tasks = [t for t in self._tasks if not t.done()]
            if not tasks:
                return

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                # cancel remaining tasks
                for t in tasks:
                    t.cancel()
                return

            done, pending = await asyncio.wait(tasks, timeout=min(0.25, remaining))
            _ = (done, pending)

    # -------------------------
    # Utilities
    # -------------------------

    def wrap_publisher(self, *, topic: Optional[str] = None, sender: Optional[str] = None) -> Callable[[Any], Awaitable[None]]:
        """
        Convenience factory: returns async fn(payload) -> publish(payload, topic=..., sender=...)
        """
        t = topic
        s = sender

        async def _pub(payload: Any) -> None:
            env = current_envelope()
            if env is not None:
                # inherit correlation/trace when called within handler
                child = env.child(payload, topic=t or env.topic, sender=s or env.sender)
                await self.publish_envelope(child)
            else:
                await self.publish(payload, topic=t, sender=s)

        return _pub


# =========================
# Reference middlewares
# =========================


class LoggingMiddleware(BaseMiddleware):
    """
    Minimal structured logging.
    Keep it lightweight; full observability should live in observability-core.
    """

    def __init__(self, *, log_payload: bool = False) -> None:
        self._log_payload = bool(log_payload)

    async def publish(self, env: Envelope[Any], call_next: PublishFn) -> None:
        logger.debug(
            "publish topic=%s msg_id=%s cor_id=%s sender=%s type=%s",
            env.topic,
            env.message_id,
            env.correlation_id,
            env.sender,
            type(env.payload).__name__,
        )
        if self._log_payload:
            logger.debug("payload=%r", env.payload)
        await call_next(env)

    async def request(self, env: Envelope[Any], response_type: type[R], call_next: RequestFn) -> R:
        t0 = time.monotonic()
        try:
            res = await call_next(env, response_type)
            dt = time.monotonic() - t0
            logger.debug(
                "request ok msg_id=%s cor_id=%s type=%s -> %s in %.3fs",
                env.message_id,
                env.correlation_id,
                type(env.payload).__name__,
                response_type.__name__,
                dt,
            )
            return res
        except Exception:
            dt = time.monotonic() - t0
            logger.exception(
                "request fail msg_id=%s cor_id=%s type=%s in %.3fs",
                env.message_id,
                env.correlation_id,
                type(env.payload).__name__,
                dt,
            )
            raise


class ConcurrencyLimitMiddleware(BaseMiddleware):
    """
    Global concurrency limiter for publish fanout and requests.
    Useful as a safety brake under burst load.
    """

    def __init__(self, *, max_in_flight: int = 1_000) -> None:
        if max_in_flight < 1:
            raise ValueError("max_in_flight must be >= 1")
        self._sem = asyncio.Semaphore(max_in_flight)

    async def publish(self, env: Envelope[Any], call_next: PublishFn) -> None:
        async with self._sem:
            await call_next(env)

    async def request(self, env: Envelope[Any], response_type: type[R], call_next: RequestFn) -> R:
        async with self._sem:
            return await call_next(env, response_type)
