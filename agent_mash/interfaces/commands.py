# agent_mash/interfaces/commands.py
# -*- coding: utf-8 -*-

from __future__ import annotations

import asyncio
import contextvars
import dataclasses
import datetime as _dt
import inspect
import json
import logging
import time
import types
import typing as t
import uuid

logger = logging.getLogger(__name__)

TCommand = t.TypeVar("TCommand", bound="Command")
TResult = t.TypeVar("TResult")
TAny = t.TypeVar("TAny")


# =========================
# Exceptions (stable API)
# =========================

class CommandError(Exception):
    """Base class for all command-related errors."""


class CommandRegistrationError(CommandError):
    """Raised when handler registration is invalid or conflicting."""


class CommandDispatchError(CommandError):
    """Raised when dispatch fails for operational reasons."""


class CommandValidationError(CommandError):
    """Raised when a command is structurally invalid."""


class CommandTimeoutError(CommandDispatchError):
    """Raised when dispatch exceeds a configured deadline."""


class CommandHandlerNotFound(CommandDispatchError):
    """Raised when no handler is registered for a command."""


class CommandHandlerTypeError(CommandRegistrationError):
    """Raised when a handler has an invalid signature."""


class CommandSerializationError(CommandError):
    """Raised when a command cannot be serialized/deserialized safely."""


# =========================
# Metadata & Context
# =========================

@dataclasses.dataclass(frozen=True, slots=True)
class CommandMeta:
    """
    Execution metadata for a command.

    Fields are intentionally explicit and stable to support:
    - distributed tracing (correlation_id, causation_id)
    - idempotency (idempotency_key)
    - deadline/timeout management (deadline_utc)
    - auditing & provenance (actor_id, tenant_id, tags)
    """
    command_id: str = dataclasses.field(default_factory=lambda: uuid.uuid4().hex)
    correlation_id: str = dataclasses.field(default_factory=lambda: uuid.uuid4().hex)
    causation_id: str | None = None

    created_at_utc: _dt.datetime = dataclasses.field(
        default_factory=lambda: _dt.datetime.now(tz=_dt.timezone.utc)
    )

    actor_id: str | None = None
    tenant_id: str | None = None

    idempotency_key: str | None = None

    deadline_utc: _dt.datetime | None = None
    tags: tuple[str, ...] = ()

    def with_deadline_in(self, seconds: float) -> "CommandMeta":
        if seconds <= 0:
            raise ValueError("seconds must be > 0")
        return dataclasses.replace(
            self,
            deadline_utc=_dt.datetime.now(tz=_dt.timezone.utc) + _dt.timedelta(seconds=seconds),
        )

    def is_expired(self, now_utc: _dt.datetime | None = None) -> bool:
        if self.deadline_utc is None:
            return False
        now = now_utc or _dt.datetime.now(tz=_dt.timezone.utc)
        return now >= self.deadline_utc


@dataclasses.dataclass(frozen=True, slots=True)
class CommandContext:
    """
    Runtime context for dispatch, visible to handlers/middlewares.
    """
    meta: CommandMeta
    started_at_monotonic: float = dataclasses.field(default_factory=time.monotonic)

    def remaining_seconds(self) -> float | None:
        if self.meta.deadline_utc is None:
            return None
        now = _dt.datetime.now(tz=_dt.timezone.utc)
        remaining = (self.meta.deadline_utc - now).total_seconds()
        return max(0.0, remaining)

    def elapsed_seconds(self) -> float:
        return max(0.0, time.monotonic() - self.started_at_monotonic)


_current_context: contextvars.ContextVar[CommandContext | None] = contextvars.ContextVar(
    "agent_mash_command_context",
    default=None,
)


def get_current_command_context() -> CommandContext | None:
    return _current_context.get()


# =========================
# Command contract
# =========================

class Command(t.Protocol):
    """
    Minimal command protocol.

    You can use:
    - dataclasses with a `meta: CommandMeta` field
    - pydantic models with a `meta` attribute
    - any object that provides `.meta` and (optionally) `.validate()`

    The bus will enforce:
    - presence of `.meta` attribute of type CommandMeta
    - optional `validate()` callable
    """

    meta: CommandMeta

    def validate(self) -> None: ...


@dataclasses.dataclass(frozen=True, slots=True)
class BaseCommand:
    """
    Default base implementation for commands.

    Projects can extend it:
    - add payload fields in derived dataclasses
    - override validate() if needed
    """
    meta: CommandMeta = dataclasses.field(default_factory=CommandMeta)

    def validate(self) -> None:
        if not isinstance(self.meta, CommandMeta):
            raise CommandValidationError("meta must be CommandMeta")
        # Basic sanity checks
        if not isinstance(self.meta.command_id, str) or not self.meta.command_id:
            raise CommandValidationError("meta.command_id must be non-empty str")
        if not isinstance(self.meta.correlation_id, str) or not self.meta.correlation_id:
            raise CommandValidationError("meta.correlation_id must be non-empty str")
        if self.meta.deadline_utc is not None and self.meta.deadline_utc.tzinfo is None:
            raise CommandValidationError("meta.deadline_utc must be timezone-aware (UTC)")
        if self.meta.tags and any((not isinstance(x, str) or not x) for x in self.meta.tags):
            raise CommandValidationError("meta.tags must be tuple of non-empty str")


# =========================
# Handler interfaces
# =========================

# A handler may be sync or async.
CommandHandler = t.Callable[[TCommand, CommandContext], t.Awaitable[TResult] | TResult]

# Middleware signature:
# middleware(command, ctx, next) -> TResult (sync or async)
NextCallable = t.Callable[[], t.Awaitable[TResult] | TResult]
Middleware = t.Callable[[TCommand, CommandContext, NextCallable], t.Awaitable[TResult] | TResult]


def _is_awaitable(obj: t.Any) -> bool:
    return inspect.isawaitable(obj)


async def _maybe_await(obj: t.Any) -> t.Any:
    if _is_awaitable(obj):
        return await t.cast(t.Awaitable[t.Any], obj)
    return obj


def _ensure_command_valid(cmd: t.Any) -> Command:
    if cmd is None:
        raise CommandValidationError("command must not be None")
    if not hasattr(cmd, "meta"):
        raise CommandValidationError("command must have .meta attribute")
    meta = getattr(cmd, "meta", None)
    if not isinstance(meta, CommandMeta):
        raise CommandValidationError("command.meta must be CommandMeta")
    validate = getattr(cmd, "validate", None)
    if validate is not None and not callable(validate):
        raise CommandValidationError("command.validate must be callable if present")
    # If validate exists, run it
    if callable(validate):
        validate()
    else:
        # At least validate meta basics
        BaseCommand(meta=meta).validate()
    return t.cast(Command, cmd)


def _validate_handler_signature(handler: t.Any) -> None:
    if not callable(handler):
        raise CommandHandlerTypeError("handler must be callable")

    try:
        sig = inspect.signature(handler)
    except (TypeError, ValueError) as e:
        raise CommandHandlerTypeError(f"cannot introspect handler signature: {e}") from e

    params = list(sig.parameters.values())
    if len(params) < 1:
        raise CommandHandlerTypeError("handler must accept at least (command, ctx)")
    # We require 2 params: (command, ctx). Additional optional params are not supported (stability).
    if len(params) != 2:
        raise CommandHandlerTypeError("handler must have signature (command, ctx)")

    if params[0].kind not in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD):
        raise CommandHandlerTypeError("first param must be positional")
    if params[1].kind not in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD):
        raise CommandHandlerTypeError("second param must be positional")


def _validate_middleware_signature(mw: t.Any) -> None:
    if not callable(mw):
        raise CommandHandlerTypeError("middleware must be callable")
    try:
        sig = inspect.signature(mw)
    except (TypeError, ValueError) as e:
        raise CommandHandlerTypeError(f"cannot introspect middleware signature: {e}") from e
    params = list(sig.parameters.values())
    if len(params) != 3:
        raise CommandHandlerTypeError("middleware must have signature (command, ctx, next)")
    for i in range(3):
        if params[i].kind not in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD):
            raise CommandHandlerTypeError("middleware params must be positional")


# =========================
# Serialization (safe-by-default)
# =========================

def _default_json(o: t.Any) -> t.Any:
    if dataclasses.is_dataclass(o):
        return dataclasses.asdict(o)
    if isinstance(o, (_dt.datetime,)):
        # ISO8601; keep tzinfo if present
        return o.isoformat()
    if isinstance(o, (uuid.UUID,)):
        return str(o)
    if isinstance(o, (set, frozenset)):
        return list(o)
    raise TypeError(f"Object of type {type(o).__name__} is not JSON serializable")


def serialize_command(cmd: Command) -> str:
    """
    Serialize a command to JSON.

    Safety notes:
    - This is intended for logging / transport when you control the receiving side.
    - Deserialization of arbitrary classes is not provided here on purpose.
    """
    try:
        _ensure_command_valid(cmd)
        payload = {
            "type": f"{cmd.__class__.__module__}.{cmd.__class__.__qualname__}",
            "meta": dataclasses.asdict(cmd.meta),
            "data": _extract_command_data(cmd),
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=_default_json)
    except CommandError:
        raise
    except Exception as e:
        raise CommandSerializationError(str(e)) from e


def _extract_command_data(cmd: Command) -> dict[str, t.Any]:
    # Prefer dataclass fields (excluding meta)
    if dataclasses.is_dataclass(cmd):
        out: dict[str, t.Any] = {}
        for f in dataclasses.fields(cmd):
            if f.name == "meta":
                continue
            out[f.name] = getattr(cmd, f.name)
        return out

    # Fallback: attempt to use __dict__ but exclude meta and private
    d = getattr(cmd, "__dict__", None)
    if isinstance(d, dict):
        return {k: v for k, v in d.items() if k != "meta" and not k.startswith("_")}

    # Final fallback: no data
    return {}


# =========================
# Hooks (optional)
# =========================

@dataclasses.dataclass(frozen=True, slots=True)
class DispatchEvent:
    command_type: str
    command_id: str
    correlation_id: str
    causation_id: str | None
    actor_id: str | None
    tenant_id: str | None
    started_at_utc: _dt.datetime
    finished_at_utc: _dt.datetime | None = None
    ok: bool | None = None
    error_type: str | None = None
    error_message: str | None = None
    elapsed_seconds: float | None = None


DispatchHook = t.Callable[[DispatchEvent], None]


# =========================
# CommandBus (industrial)
# =========================

class CommandBus:
    """
    Industrial-grade command bus.

    Features:
    - strict handler registration per command type
    - sync/async dispatch (single API: dispatch / dispatch_async)
    - middleware pipeline (sync/async)
    - context propagation (contextvars)
    - optional dispatch hooks (audit/metrics)
    - deadline/timeout enforcement (best-effort)
    """

    __slots__ = (
        "_handlers",
        "_middlewares",
        "_hooks",
        "_lock",
        "_strict",
        "_default_timeout_seconds",
    )

    def __init__(
        self,
        *,
        strict: bool = True,
        default_timeout_seconds: float | None = None,
        middlewares: t.Iterable[Middleware] | None = None,
        hooks: t.Iterable[DispatchHook] | None = None,
    ) -> None:
        self._handlers: dict[type[object], CommandHandler[t.Any, t.Any]] = {}
        self._middlewares: list[Middleware] = []
        self._hooks: list[DispatchHook] = []
        self._lock = asyncio.Lock()
        self._strict = bool(strict)
        self._default_timeout_seconds = default_timeout_seconds

        if middlewares:
            for mw in middlewares:
                self.add_middleware(mw)
        if hooks:
            for h in hooks:
                self.add_hook(h)

    def add_hook(self, hook: DispatchHook) -> None:
        if not callable(hook):
            raise CommandRegistrationError("hook must be callable")
        self._hooks.append(hook)

    def add_middleware(self, middleware: Middleware) -> None:
        _validate_middleware_signature(middleware)
        self._middlewares.append(middleware)

    def register(self, command_type: type[TCommand], handler: CommandHandler[TCommand, TResult]) -> None:
        """
        Register a handler for a command type.

        In strict mode:
        - one handler per command type
        - re-registration raises
        """
        if not isinstance(command_type, type):
            raise CommandRegistrationError("command_type must be a type")
        _validate_handler_signature(handler)

        if self._strict and command_type in self._handlers:
            raise CommandRegistrationError(f"handler already registered for {command_type!r}")

        self._handlers[command_type] = t.cast(CommandHandler[t.Any, t.Any], handler)

    def unregister(self, command_type: type[object]) -> None:
        self._handlers.pop(command_type, None)

    def has_handler(self, command_type: type[object]) -> bool:
        return command_type in self._handlers

    def dispatch(self, command: TCommand) -> TResult:
        """
        Synchronous dispatch.

        If handler/middlewares are async, this method runs an event loop policy-safe bridge:
        - if no loop running: asyncio.run
        - if loop running: raises (use dispatch_async)
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is not None and loop.is_running():
            raise CommandDispatchError(
                "dispatch() cannot be used inside a running event loop; use await dispatch_async()"
            )

        return asyncio.run(self.dispatch_async(command))

    async def dispatch_async(self, command: TCommand) -> TResult:
        """
        Asynchronous dispatch (preferred).
        """
        cmd = _ensure_command_valid(command)
        cmd_type = type(cmd)

        handler = self._handlers.get(cmd_type)
        if handler is None:
            raise CommandHandlerNotFound(f"no handler registered for {cmd_type!r}")

        # Deadline policy
        if cmd.meta.is_expired():
            raise CommandTimeoutError("command deadline exceeded before dispatch")

        ctx = CommandContext(meta=cmd.meta)
        token = _current_context.set(ctx)

        started_utc = _dt.datetime.now(tz=_dt.timezone.utc)
        evt = DispatchEvent(
            command_type=f"{cmd_type.__module__}.{cmd_type.__qualname__}",
            command_id=cmd.meta.command_id,
            correlation_id=cmd.meta.correlation_id,
            causation_id=cmd.meta.causation_id,
            actor_id=cmd.meta.actor_id,
            tenant_id=cmd.meta.tenant_id,
            started_at_utc=started_utc,
        )

        try:
            result = await self._dispatch_with_pipeline(cmd, ctx, handler)
            finished_utc = _dt.datetime.now(tz=_dt.timezone.utc)

            evt = dataclasses.replace(
                evt,
                finished_at_utc=finished_utc,
                ok=True,
                elapsed_seconds=ctx.elapsed_seconds(),
            )
            self._emit_hooks(evt)
            return t.cast(TResult, result)

        except Exception as e:
            finished_utc = _dt.datetime.now(tz=_dt.timezone.utc)
            evt = dataclasses.replace(
                evt,
                finished_at_utc=finished_utc,
                ok=False,
                error_type=type(e).__name__,
                error_message=str(e),
                elapsed_seconds=ctx.elapsed_seconds(),
            )
            self._emit_hooks(evt)
            raise

        finally:
            _current_context.reset(token)

    async def _dispatch_with_pipeline(
        self,
        command: TCommand,
        ctx: CommandContext,
        handler: CommandHandler[TCommand, TResult],
    ) -> TResult:
        """
        Build middleware chain around the final handler.
        Middleware order is FIFO: added first -> executes first.
        """

        async def final_call() -> TResult:
            # deadline enforcement (best-effort)
            await self._enforce_deadline(ctx)
            out = handler(command, ctx)
            out2 = await _maybe_await(out)
            return t.cast(TResult, out2)

        # Build chain from last to first
        next_fn: NextCallable[TResult] = final_call

        for mw in reversed(self._middlewares):
            prev_next = next_fn

            async def make_next(middleware: Middleware, prev: NextCallable[TResult]) -> NextCallable[TResult]:
                async def _next() -> TResult:
                    await self._enforce_deadline(ctx)
                    res = middleware(command, ctx, prev)
                    res2 = await _maybe_await(res)
                    return t.cast(TResult, res2)
                return _next

            next_fn = await make_next(mw, prev_next)

        # Optional global timeout if provided
        timeout = self._compute_timeout_seconds(ctx)
        if timeout is None:
            return await next_fn()

        try:
            return await asyncio.wait_for(next_fn(), timeout=timeout)
        except asyncio.TimeoutError as e:
            raise CommandTimeoutError("command dispatch timed out") from e

    async def _enforce_deadline(self, ctx: CommandContext) -> None:
        if ctx.meta.deadline_utc is None:
            return
        if ctx.meta.is_expired():
            raise CommandTimeoutError("command deadline exceeded during dispatch")
        # If remaining is extremely low, yield control to allow cancellation points
        remaining = ctx.remaining_seconds()
        if remaining is not None and remaining <= 0.0:
            raise CommandTimeoutError("command deadline exceeded during dispatch")
        await asyncio.sleep(0)

    def _compute_timeout_seconds(self, ctx: CommandContext) -> float | None:
        """
        Timeout resolution order:
        1) ctx.meta.deadline_utc -> derived remaining seconds
        2) self._default_timeout_seconds
        """
        remaining = ctx.remaining_seconds()
        if remaining is not None:
            # Avoid 0 timeout edge
            return max(0.001, remaining)

        if self._default_timeout_seconds is None:
            return None

        if self._default_timeout_seconds <= 0:
            return None

        return float(self._default_timeout_seconds)

    def _emit_hooks(self, event: DispatchEvent) -> None:
        for hook in self._hooks:
            try:
                hook(event)
            except Exception:
                # Hooks must never break dispatch guarantees
                logger.exception("command dispatch hook failed")

    async def register_async(self, command_type: type[TCommand], handler: CommandHandler[TCommand, TResult]) -> None:
        """
        Async-safe registration helper (useful in dynamic/plugin systems).
        """
        async with self._lock:
            self.register(command_type, handler)

    def snapshot_registry(self) -> dict[str, str]:
        """
        Returns a stable, human-readable view of current registrations.
        Useful for diagnostics and audits.
        """
        out: dict[str, str] = {}
        for k, v in self._handlers.items():
            out[f"{k.__module__}.{k.__qualname__}"] = f"{v.__module__}.{getattr(v, '__qualname__', v.__name__)}"
        return dict(sorted(out.items(), key=lambda x: x[0]))


# =========================
# Optional: middleware utilities
# =========================

def logging_middleware(
    *,
    level: int = logging.INFO,
    include_payload: bool = False,
) -> Middleware:
    """
    Factory for a conservative logging middleware.
    Avoids leaking secrets by default (include_payload=False).
    """

    def _mw(command: Command, ctx: CommandContext, next_call: NextCallable[TResult]) -> t.Awaitable[TResult] | TResult:
        cmd_type = type(command)
        base = {
            "command_type": f"{cmd_type.__module__}.{cmd_type.__qualname__}",
            "command_id": ctx.meta.command_id,
            "correlation_id": ctx.meta.correlation_id,
            "causation_id": ctx.meta.causation_id,
            "actor_id": ctx.meta.actor_id,
            "tenant_id": ctx.meta.tenant_id,
            "idempotency_key": ctx.meta.idempotency_key,
        }
        if include_payload:
            try:
                base["command"] = serialize_command(command)
            except Exception:
                base["command"] = "<unserializable>"

        logger.log(level, "command.dispatch.start %s", base)
        started = time.monotonic()

        async def _run() -> TResult:
            try:
                res = await _maybe_await(next_call())
                elapsed = max(0.0, time.monotonic() - started)
                logger.log(level, "command.dispatch.ok %s elapsed=%.6f", base, elapsed)
                return t.cast(TResult, res)
            except Exception as e:
                elapsed = max(0.0, time.monotonic() - started)
                logger.exception("command.dispatch.fail %s elapsed=%.6f error=%s", base, elapsed, type(e).__name__)
                raise

        return _run()

    _validate_middleware_signature(_mw)
    return _mw
