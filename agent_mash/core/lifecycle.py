# agent_mash/core/lifecycle.py
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import enum
import logging
import time
import traceback
from collections.abc import Awaitable, Callable, Coroutine
from typing import Any, Optional, Protocol, Sequence


logger = logging.getLogger(__name__)


class LifecycleError(RuntimeError):
    """Base lifecycle error."""


class LifecycleTransitionError(LifecycleError):
    """Raised when an illegal state transition is attempted."""


class LifecycleTimeoutError(LifecycleError):
    """Raised when an operation exceeds its timeout."""


class LifecycleStartError(LifecycleError):
    """Raised when start fails."""


class LifecycleStopError(LifecycleError):
    """Raised when stop fails."""


class ComponentRole(str, enum.Enum):
    AGENT = "agent"
    SERVICE = "service"
    WORKER = "worker"
    ROUTER = "router"
    STORAGE = "storage"
    OBSERVABILITY = "observability"
    OTHER = "other"


class LifecycleState(str, enum.Enum):
    NEW = "new"
    INITIALIZING = "initializing"
    READY = "ready"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"


class LifecycleEventType(str, enum.Enum):
    STATE_CHANGED = "state_changed"
    START_REQUESTED = "start_requested"
    STARTED = "started"
    STOP_REQUESTED = "stop_requested"
    STOPPED = "stopped"
    HEALTH = "health"
    ERROR = "error"


@dataclasses.dataclass(frozen=True, slots=True)
class LifecycleEvent:
    type: LifecycleEventType
    ts_monotonic: float
    component_id: str
    role: ComponentRole
    state: LifecycleState
    payload: dict[str, Any]


@dataclasses.dataclass(slots=True)
class HealthStatus:
    ok: bool
    ts_monotonic: float
    details: dict[str, Any]

    @staticmethod
    def healthy(**details: Any) -> "HealthStatus":
        return HealthStatus(ok=True, ts_monotonic=time.monotonic(), details=dict(details))

    @staticmethod
    def unhealthy(**details: Any) -> "HealthStatus":
        return HealthStatus(ok=False, ts_monotonic=time.monotonic(), details=dict(details))


@dataclasses.dataclass(frozen=True, slots=True)
class RunContext:
    """
    Immutable context passed to lifecycle components.
    Keep it dependency-free to avoid import cycles.
    """
    component_id: str
    role: ComponentRole
    started_at_monotonic: float
    metadata: dict[str, Any]
    cancel_event: asyncio.Event

    def is_cancelled(self) -> bool:
        return self.cancel_event.is_set()


Hook = Callable[[LifecycleEvent], Awaitable[None]]
ErrorHook = Callable[[BaseException, LifecycleEvent], Awaitable[None]]


class LifecycleComponent(Protocol):
    """
    Contract for any component that wants to be managed.

    Notes:
    - `run` is optional: if omitted, component is considered "one-shot" started.
    - `stop` must be idempotent: may be called multiple times.
    """

    @property
    def component_id(self) -> str: ...

    @property
    def role(self) -> ComponentRole: ...

    async def init(self, ctx: RunContext) -> None: ...
    async def start(self, ctx: RunContext) -> None: ...
    async def stop(self, ctx: RunContext) -> None: ...

    async def run(self, ctx: RunContext) -> None:  # optional
        raise NotImplementedError

    async def health(self, ctx: RunContext) -> HealthStatus:  # optional
        return HealthStatus.healthy()


class _NoopComponent:
    def __init__(self, component_id: str, role: ComponentRole) -> None:
        self._id = component_id
        self._role = role

    @property
    def component_id(self) -> str:
        return self._id

    @property
    def role(self) -> ComponentRole:
        return self._role

    async def init(self, ctx: RunContext) -> None:
        return None

    async def start(self, ctx: RunContext) -> None:
        return None

    async def stop(self, ctx: RunContext) -> None:
        return None


class LifecycleManager:
    """
    Industrial-grade lifecycle manager:
    - Strict state machine with transition validation
    - Timeouts for init/start/stop/run join
    - Cancellation propagation
    - Background run-task supervision
    - Event bus (async hooks) for observability
    - Health polling helper
    - Idempotent stop
    """

    def __init__(
        self,
        component: LifecycleComponent | None = None,
        *,
        component_id: str = "unknown",
        role: ComponentRole = ComponentRole.OTHER,
        metadata: Optional[dict[str, Any]] = None,
        init_timeout_s: float = 15.0,
        start_timeout_s: float = 30.0,
        stop_timeout_s: float = 30.0,
        run_grace_timeout_s: float = 10.0,
        hook_concurrency: int = 16,
    ) -> None:
        self._component: LifecycleComponent = component or _NoopComponent(component_id, role)
        self._component_id = getattr(self._component, "component_id", component_id) or component_id
        self._role = getattr(self._component, "role", role) or role

        self._state: LifecycleState = LifecycleState.NEW
        self._state_lock = asyncio.Lock()

        self._init_timeout_s = float(init_timeout_s)
        self._start_timeout_s = float(start_timeout_s)
        self._stop_timeout_s = float(stop_timeout_s)
        self._run_grace_timeout_s = float(run_grace_timeout_s)

        self._started_at: float | None = None
        self._cancel_event = asyncio.Event()
        self._ctx: RunContext | None = None

        self._run_task: asyncio.Task[None] | None = None
        self._stop_task: asyncio.Task[None] | None = None

        self._hooks: list[Hook] = []
        self._error_hooks: list[ErrorHook] = []

        self._hook_sem = asyncio.Semaphore(max(1, int(hook_concurrency)))
        self._metadata = dict(metadata or {})

        self._last_error: BaseException | None = None
        self._last_error_tb: str | None = None

    @property
    def component_id(self) -> str:
        return self._component_id

    @property
    def role(self) -> ComponentRole:
        return self._role

    @property
    def state(self) -> LifecycleState:
        return self._state

    @property
    def last_error(self) -> BaseException | None:
        return self._last_error

    def add_hook(self, hook: Hook) -> None:
        self._hooks.append(hook)

    def add_error_hook(self, hook: ErrorHook) -> None:
        self._error_hooks.append(hook)

    def request_cancel(self) -> None:
        self._cancel_event.set()

    def _mk_ctx(self) -> RunContext:
        if self._started_at is None:
            raise LifecycleError("RunContext requested before initialization")
        return RunContext(
            component_id=self._component_id,
            role=self._role,
            started_at_monotonic=self._started_at,
            metadata=dict(self._metadata),
            cancel_event=self._cancel_event,
        )

    async def _emit(self, event_type: LifecycleEventType, *, payload: Optional[dict[str, Any]] = None) -> None:
        ctx_state = self._state
        event = LifecycleEvent(
            type=event_type,
            ts_monotonic=time.monotonic(),
            component_id=self._component_id,
            role=self._role,
            state=ctx_state,
            payload=dict(payload or {}),
        )

        async def _safe_call(h: Hook) -> None:
            async with self._hook_sem:
                try:
                    await h(event)
                except Exception:
                    logger.exception("Lifecycle hook failed: component_id=%s type=%s", self._component_id, event_type)

        if self._hooks:
            await asyncio.gather(*(_safe_call(h) for h in tuple(self._hooks)), return_exceptions=True)

    async def _emit_error(self, exc: BaseException, origin: str) -> None:
        self._last_error = exc
        self._last_error_tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))

        await self._emit(
            LifecycleEventType.ERROR,
            payload={
                "origin": origin,
                "exc_type": type(exc).__name__,
                "exc": str(exc),
            },
        )

        async def _safe_call(h: ErrorHook) -> None:
            async with self._hook_sem:
                try:
                    # provide current state snapshot in event
                    event = LifecycleEvent(
                        type=LifecycleEventType.ERROR,
                        ts_monotonic=time.monotonic(),
                        component_id=self._component_id,
                        role=self._role,
                        state=self._state,
                        payload={
                            "origin": origin,
                            "exc_type": type(exc).__name__,
                            "exc": str(exc),
                        },
                    )
                    await h(exc, event)
                except Exception:
                    logger.exception("Lifecycle error hook failed: component_id=%s origin=%s", self._component_id, origin)

        if self._error_hooks:
            await asyncio.gather(*(_safe_call(h) for h in tuple(self._error_hooks)), return_exceptions=True)

    async def _set_state(self, new_state: LifecycleState, *, reason: str) -> None:
        async with self._state_lock:
            old = self._state
            if old == new_state:
                return
            self._state = new_state
        await self._emit(LifecycleEventType.STATE_CHANGED, payload={"from": old.value, "to": new_state.value, "reason": reason})

    async def _require_state(self, allowed: Sequence[LifecycleState], *, action: str) -> None:
        if self._state not in allowed:
            raise LifecycleTransitionError(f"Illegal state for {action}: {self._state.value} allowed={[s.value for s in allowed]}")

    async def initialize(self) -> None:
        await self._require_state([LifecycleState.NEW], action="initialize")
        await self._set_state(LifecycleState.INITIALIZING, reason="initialize() called")

        self._started_at = time.monotonic()
        self._ctx = self._mk_ctx()

        try:
            await asyncio.wait_for(self._component.init(self._ctx), timeout=self._init_timeout_s)
        except asyncio.TimeoutError as e:
            exc = LifecycleTimeoutError(f"init() timeout after {self._init_timeout_s:.3f}s")
            await self._emit_error(exc, origin="init_timeout")
            await self._set_state(LifecycleState.FAILED, reason="init timeout")
            raise exc from e
        except Exception as e:
            await self._emit_error(e, origin="init_exception")
            await self._set_state(LifecycleState.FAILED, reason="init exception")
            raise LifecycleStartError("init() failed") from e

        await self._set_state(LifecycleState.READY, reason="init completed")

    async def start(self) -> None:
        if self._state == LifecycleState.NEW:
            await self.initialize()

        await self._require_state([LifecycleState.READY], action="start")
        await self._emit(LifecycleEventType.START_REQUESTED, payload={})
        await self._set_state(LifecycleState.STARTING, reason="start() called")

        if self._ctx is None:
            self._ctx = self._mk_ctx()

        try:
            await asyncio.wait_for(self._component.start(self._ctx), timeout=self._start_timeout_s)
        except asyncio.TimeoutError as e:
            exc = LifecycleTimeoutError(f"start() timeout after {self._start_timeout_s:.3f}s")
            await self._emit_error(exc, origin="start_timeout")
            await self._set_state(LifecycleState.FAILED, reason="start timeout")
            raise exc from e
        except Exception as e:
            await self._emit_error(e, origin="start_exception")
            await self._set_state(LifecycleState.FAILED, reason="start exception")
            raise LifecycleStartError("start() failed") from e

        await self._set_state(LifecycleState.RUNNING, reason="start completed")
        await self._emit(LifecycleEventType.STARTED, payload={})

        # If component defines run(), supervise it as background task.
        run_coro: Coroutine[Any, Any, None] | None = None
        try:
            run_impl = getattr(self._component, "run", None)
            if run_impl is not None:
                # If run is not overridden it may raise NotImplementedError; handle in task.
                run_coro = run_impl(self._ctx)
        except Exception as e:
            await self._emit_error(e, origin="run_bind_exception")
            await self._set_state(LifecycleState.FAILED, reason="run bind exception")
            raise LifecycleStartError("run() binding failed") from e

        if run_coro is not None:
            self._run_task = asyncio.create_task(self._run_supervisor(run_coro), name=f"lifecycle.run:{self._component_id}")

    async def _run_supervisor(self, run_coro: Coroutine[Any, Any, None]) -> None:
        assert self._ctx is not None
        try:
            await run_coro
        except NotImplementedError:
            # Treat as "no background run loop"
            return
        except asyncio.CancelledError:
            raise
        except Exception as e:
            await self._emit_error(e, origin="run_exception")
            await self._set_state(LifecycleState.FAILED, reason="run exception")
            # Request cancellation so upper orchestration can react.
            self.request_cancel()

    async def stop(self) -> None:
        # Idempotent stop orchestration; serialize multiple concurrent stop callers.
        if self._stop_task is not None:
            await self._stop_task
            return

        self._stop_task = asyncio.create_task(self._stop_impl(), name=f"lifecycle.stop:{self._component_id}")
        try:
            await self._stop_task
        finally:
            self._stop_task = None

    async def _stop_impl(self) -> None:
        if self._state in (LifecycleState.STOPPED, LifecycleState.NEW):
            return

        # From FAILED we still attempt best-effort stop to release resources.
        if self._state not in (LifecycleState.RUNNING, LifecycleState.READY, LifecycleState.FAILED, LifecycleState.STARTING):
            raise LifecycleTransitionError(f"Illegal state for stop: {self._state.value}")

        await self._emit(LifecycleEventType.STOP_REQUESTED, payload={})
        await self._set_state(LifecycleState.STOPPING, reason="stop() called")
        self.request_cancel()

        # Try graceful completion of run loop.
        if self._run_task is not None and not self._run_task.done():
            with contextlib.suppress(Exception):
                await asyncio.wait_for(asyncio.shield(self._run_task), timeout=self._run_grace_timeout_s)

        # Cancel run task if still alive.
        if self._run_task is not None and not self._run_task.done():
            self._run_task.cancel()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(asyncio.shield(self._run_task), timeout=self._run_grace_timeout_s)

        # Call component.stop
        if self._ctx is None:
            # if stop before init completed, create minimal ctx
            if self._started_at is None:
                self._started_at = time.monotonic()
            self._ctx = self._mk_ctx()

        try:
            await asyncio.wait_for(self._component.stop(self._ctx), timeout=self._stop_timeout_s)
        except asyncio.TimeoutError as e:
            exc = LifecycleTimeoutError(f"stop() timeout after {self._stop_timeout_s:.3f}s")
            await self._emit_error(exc, origin="stop_timeout")
            await self._set_state(LifecycleState.FAILED, reason="stop timeout")
            raise exc from e
        except Exception as e:
            await self._emit_error(e, origin="stop_exception")
            await self._set_state(LifecycleState.FAILED, reason="stop exception")
            raise LifecycleStopError("stop() failed") from e

        await self._set_state(LifecycleState.STOPPED, reason="stop completed")
        await self._emit(LifecycleEventType.STOPPED, payload={})

    async def join(self) -> None:
        """
        Wait for completion:
        - if run loop exists: wait for it
        - else: returns after start()
        """
        if self._run_task is None:
            return
        with contextlib.suppress(asyncio.CancelledError):
            await self._run_task

    async def health(self) -> HealthStatus:
        """
        Returns component health if implemented; otherwise healthy.
        Emits HEALTH event with details.
        """
        if self._ctx is None:
            # Not started yet: consider unhealthy to prevent false positives.
            hs = HealthStatus.unhealthy(reason="not_initialized", state=self._state.value)
            await self._emit(LifecycleEventType.HEALTH, payload={"ok": hs.ok, "details": dict(hs.details)})
            return hs

        try:
            health_impl = getattr(self._component, "health", None)
            if health_impl is None:
                hs = HealthStatus.healthy(state=self._state.value)
            else:
                hs = await health_impl(self._ctx)
        except Exception as e:
            await self._emit_error(e, origin="health_exception")
            hs = HealthStatus.unhealthy(reason="health_exception", exc_type=type(e).__name__, state=self._state.value)

        await self._emit(LifecycleEventType.HEALTH, payload={"ok": hs.ok, "details": dict(hs.details)})
        return hs

    async def run_forever(self, *, stop_on_cancel: bool = True) -> None:
        """
        Convenience helper:
        - start component
        - wait until cancelled or run loop ends
        - stop component
        """
        await self.start()
        try:
            if self._run_task is None:
                # If no background loop, just wait for cancel.
                await self._cancel_event.wait()
            else:
                done, _ = await asyncio.wait(
                    {self._run_task, asyncio.create_task(self._cancel_event.wait())},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                _ = done
        finally:
            if stop_on_cancel:
                with contextlib.suppress(Exception):
                    await self.stop()

    def snapshot(self) -> dict[str, Any]:
        """
        Synchronous snapshot for diagnostics/logging.
        """
        return {
            "component_id": self._component_id,
            "role": self._role.value,
            "state": self._state.value,
            "started_at_monotonic": self._started_at,
            "cancelled": self._cancel_event.is_set(),
            "has_run_task": self._run_task is not None,
            "run_task_done": (self._run_task.done() if self._run_task else None),
            "last_error_type": (type(self._last_error).__name__ if self._last_error else None),
            "last_error": (str(self._last_error) if self._last_error else None),
            "last_error_tb": self._last_error_tb,
        }
