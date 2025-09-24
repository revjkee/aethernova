# policy-core/policy_core/pep/sdk_hooks.py
# Industrial PEP SDK hooks for Zero-Trust enforcement in NeuroCity/TeslaAI stack.
# Async-first. Deny-by-default. No external hard deps.

from __future__ import annotations

import asyncio
import contextlib
import functools
import hashlib
import inspect
import json
import logging
import time
import types
import uuid
from dataclasses import dataclass, field
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Tuple,
    Union,
    runtime_checkable,
)

# Optional OpenTelemetry (soft dependency)
try:
    from opentelemetry import trace as _ot_trace  # type: ignore
    _OTEL_TRACER = _ot_trace.get_tracer("policy_core.pep.sdk_hooks")
except Exception:  # pragma: no cover
    _OTEL_TRACER = None  # graceful fallback


__all__ = [
    "PolicyDecision",
    "PolicyDeniedError",
    "PolicyEngine",
    "SDKHooks",
    "Effect",
]


# ----------------------------
# Types and basic definitions
# ----------------------------

Effect = str  # "Permit" | "Deny"

@dataclass(frozen=True)
class PolicyDecision:
    effect: Effect  # "Permit" or "Deny"
    reason: str = ""
    policy_id: Optional[str] = None
    obligations: Mapping[str, Any] = field(default_factory=dict)
    ttl_seconds: Optional[int] = None
    timestamp: float = field(default_factory=lambda: time.time())

    @property
    def allowed(self) -> bool:
        return self.effect == "Permit"


class PolicyDeniedError(PermissionError):
    """Raised when a policy decision denies an operation."""

    def __init__(
        self,
        action: str,
        subject: Mapping[str, Any],
        resource: Mapping[str, Any],
        environment: Optional[Mapping[str, Any]],
        decision: PolicyDecision,
        correlation_id: str,
    ) -> None:
        msg = (
            f"Access denied (action={action}, effect={decision.effect}, "
            f"policy_id={decision.policy_id}, reason={decision.reason}, "
            f"correlation_id={correlation_id})"
        )
        super().__init__(msg)
        self.action = action
        self.subject = subject
        self.resource = resource
        self.environment = environment
        self.decision = decision
        self.correlation_id = correlation_id


@runtime_checkable
class PolicyEngine(Protocol):
    """Async policy engine (PDP) interface."""

    async def evaluate(
        self,
        subject: Mapping[str, Any],
        action: str,
        resource: Mapping[str, Any],
        environment: Optional[Mapping[str, Any]] = None,
    ) -> PolicyDecision:
        ...


# ----------------------------
# TTL cache (async-safe)
# ----------------------------

class _TTLCache:
    def __init__(self, capacity: int = 10000) -> None:
        self._cap = max(1, capacity)
        self._store: Dict[str, Tuple[float, PolicyDecision]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[PolicyDecision]:
        async with self._lock:
            item = self._store.get(key)
            if not item:
                return None
            exp, dec = item
            if exp and exp < time.time():
                self._store.pop(key, None)
                return None
            return dec

    async def set(self, key: str, dec: PolicyDecision, ttl_seconds: Optional[int]) -> None:
        if ttl_seconds is None or ttl_seconds <= 0:
            return
        exp = time.time() + ttl_seconds
        async with self._lock:
            if len(self._store) >= self._cap:
                # Evict an arbitrary item (simple policy). Could be replaced by LRU if needed.
                self._store.pop(next(iter(self._store)), None)
            self._store[key] = (exp, dec)

    async def purge(self) -> None:
        now = time.time()
        async with self._lock:
            dead = [k for k, (exp, _) in self._store.items() if exp and exp < now]
            for k in dead:
                self._store.pop(k, None)


# ----------------------------
# Circuit breaker (async)
# ----------------------------

class _CircuitBreakerState:
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class _CircuitBreaker:
    def __init__(
        self,
        failure_threshold: int = 5,
        reset_timeout: float = 15.0,
        half_open_max_calls: int = 3,
    ) -> None:
        self.failure_threshold = max(1, failure_threshold)
        self.reset_timeout = max(1.0, reset_timeout)
        self.half_open_max_calls = max(1, half_open_max_calls)

        self._state = _CircuitBreakerState.CLOSED
        self._failures = 0
        self._opened_at = 0.0
        self._half_open_calls = 0
        self._lock = asyncio.Lock()

    async def allow(self) -> bool:
        async with self._lock:
            if self._state == _CircuitBreakerState.OPEN:
                if time.time() - self._opened_at >= self.reset_timeout:
                    self._state = _CircuitBreakerState.HALF_OPEN
                    self._half_open_calls = 0
                else:
                    return False

            if self._state == _CircuitBreakerState.HALF_OPEN:
                if self._half_open_calls >= self.half_open_max_calls:
                    return False
                self._half_open_calls += 1
            return True

    async def record_success(self) -> None:
        async with self._lock:
            self._failures = 0
            if self._state in (_CircuitBreakerState.HALF_OPEN, _CircuitBreakerState.OPEN):
                self._state = _CircuitBreakerState.CLOSED
                self._opened_at = 0.0
                self._half_open_calls = 0

    async def record_failure(self) -> None:
        async with self._lock:
            self._failures += 1
            if self._failures >= self.failure_threshold:
                self._state = _CircuitBreakerState.OPEN
                self._opened_at = time.time()
                self._half_open_calls = 0


# ----------------------------
# Utilities
# ----------------------------

def _stable_hash(data: Any) -> str:
    try:
        blob = json.dumps(data, sort_keys=True, separators=(",", ":"))
    except Exception:
        blob = repr(data)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _json_log(logger: logging.Logger, level: int, event: str, **fields: Any) -> None:
    payload = {"event": event, **fields}
    try:
        logger.log(level, json.dumps(payload, ensure_ascii=False))
    except Exception:
        # no JSON? fallback to repr
        logger.log(level, f"{event} {fields}")


def _maybe_await(func_result: Any) -> Awaitable[Any]:
    if inspect.isawaitable(func_result):
        return func_result  # type: ignore
    async def _wrap() -> Any:
        return func_result
    return _wrap()


def _call_resolver(resolver: Union[Callable[..., Any], Mapping[str, Any], None], *a: Any, **kw: Any) -> Mapping[str, Any]:
    if resolver is None:
        return {}
    if isinstance(resolver, Mapping):
        return resolver
    try:
        res = resolver(*a, **kw)
        if inspect.isawaitable(res):
            # resolver may be async; resolve synchronously here is not allowed
            # we handle async resolvers at call sites
            return {}  # placeholder; actual async path elsewhere
        return res or {}
    except Exception:
        return {}


# ----------------------------
# SDK Hooks (PEP)
# ----------------------------

class SDKHooks:
    """
    Policy Enforcement Point hooks.

    - async-first enforcement: deny-by-default on errors
    - decision cache with TTL
    - circuit breaker around PDP
    - structured JSON audit logging
    - pre/post hooks and obligations handlers
    - optional OpenTelemetry spans

    Usage (typical):
        hooks = SDKHooks(engine=my_engine)
        @hooks.enforce(action="orders:create", resource=lambda req: {"id": req.order_id})
        async def create_order(req): ...
    """

    def __init__(
        self,
        engine: PolicyEngine,
        *,
        default_ttl_seconds: int = 5,
        cache_capacity: int = 10000,
        failure_threshold: int = 5,
        reset_timeout: float = 15.0,
        half_open_max_calls: int = 3,
        logger: Optional[logging.Logger] = None,
        correlation_field: str = "correlation_id",
        deny_on_error: bool = True,
    ) -> None:
        self.engine = engine
        self.default_ttl_seconds = max(0, int(default_ttl_seconds))
        self.cache = _TTLCache(capacity=cache_capacity)
        self.breaker = _CircuitBreaker(
            failure_threshold=failure_threshold,
            reset_timeout=reset_timeout,
            half_open_max_calls=half_open_max_calls,
        )
        self.logger = logger or logging.getLogger("policy_core.pep.sdk_hooks")
        self.correlation_field = correlation_field
        self.deny_on_error = deny_on_error

        self._pre_hooks: list[Callable[[Mapping[str, Any], str, Mapping[str, Any], Optional[Mapping[str, Any]], str], Awaitable[None]]] = []
        self._post_hooks: list[Callable[[Mapping[str, Any], str, Mapping[str, Any], Optional[Mapping[str, Any]], str, PolicyDecision, Optional[BaseException]], Awaitable[None]]] = []
        self._obligation_handlers: dict[str, Callable[[Any, Mapping[str, Any]], Awaitable[None]]] = {}

    # -------- Hook registration --------

    def register_pre_hook(
        self,
        func: Callable[[Mapping[str, Any], str, Mapping[str, Any], Optional[Mapping[str, Any]], str], Awaitable[None]],
    ) -> None:
        self._pre_hooks.append(func)

    def register_post_hook(
        self,
        func: Callable[[Mapping[str, Any], str, Mapping[str, Any], Optional[Mapping[str, Any]], str, PolicyDecision, Optional[BaseException]], Awaitable[None]],
    ) -> None:
        self._post_hooks.append(func)

    def register_obligation_handler(
        self,
        name: str,
        func: Callable[[Any, Mapping[str, Any]], Awaitable[None]],
    ) -> None:
        self._obligation_handlers[name] = func

    # -------- Public API --------

    async def decide(
        self,
        *,
        subject: Mapping[str, Any],
        action: str,
        resource: Mapping[str, Any],
        environment: Optional[Mapping[str, Any]] = None,
        correlation_id: Optional[str] = None,
        cache_ttl_seconds: Optional[int] = None,
    ) -> PolicyDecision:
        """Ask PDP, with cache and circuit breaker."""
        correlation_id = correlation_id or str(uuid.uuid4())
        env = environment or {}

        cache_key = self._decision_key(subject, action, resource, env)
        cached = await self.cache.get(cache_key)
        if cached is not None:
            _json_log(
                self.logger,
                logging.DEBUG,
                "policy.cache.hit",
                action=action,
                effect=cached.effect,
                policy_id=cached.policy_id,
                correlation_id=correlation_id,
            )
            return cached

        if not await self.breaker.allow():
            # Circuit open -> conservative deny
            decision = PolicyDecision(effect="Deny", reason="circuit_open")
            _json_log(
                self.logger,
                logging.WARNING,
                "policy.circuit.open",
                action=action,
                correlation_id=correlation_id,
            )
            return decision

        # Pre-hooks (telemetry, rate context, etc.)
        await self._run_pre_hooks(subject, action, resource, env, correlation_id)

        span_cm = _otel_span("policy.evaluate") if _OTEL_TRACER else contextlib.nullcontext()
        async with _maybe_async_context(span_cm):
            try:
                decision = await self.engine.evaluate(subject, action, resource, env)
                await self.breaker.record_success()
            except Exception as exc:
                await self.breaker.record_failure()
                _json_log(
                    self.logger,
                    logging.ERROR,
                    "policy.evaluate.error",
                    action=action,
                    error=str(exc),
                    correlation_id=correlation_id,
                )
                if self.deny_on_error:
                    decision = PolicyDecision(effect="Deny", reason="pdp_error")
                else:
                    decision = PolicyDecision(effect="Permit", reason="pdp_error_permit")

        ttl = decision.ttl_seconds if decision.ttl_seconds is not None else self.default_ttl_seconds
        await self.cache.set(cache_key, decision, ttl)

        _json_log(
            self.logger,
            logging.INFO,
            "policy.decision",
            action=action,
            effect=decision.effect,
            policy_id=decision.policy_id,
            reason=decision.reason,
            ttl=ttl,
            correlation_id=correlation_id,
        )
        return decision

    def enforce(
        self,
        *,
        action: str,
        subject: Union[Callable[..., Any], Mapping[str, Any], None] = None,
        resource: Union[Callable[..., Any], Mapping[str, Any], None] = None,
        environment: Union[Callable[..., Any], Mapping[str, Any], None] = None,
        cache_ttl_seconds: Optional[int] = None,
        effect_on_error: Optional[Effect] = None,  # override deny_on_error if set
        on_deny: Optional[Callable[[PolicyDeniedError], Awaitable[None]]] = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """
        Decorator to enforce policy before function execution.

        subject/resource/environment may be:
          - dict-like mapping
          - callable(*args, **kwargs) -> mapping (can be async)
        """
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            is_async = asyncio.iscoroutinefunction(fn)

            @functools.wraps(fn)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                # For sync functions, run the async enforcement in an event loop if present.
                return asyncio.run(self._enforced_call(fn, False, action, subject, resource, environment,
                                                       cache_ttl_seconds, effect_on_error, on_deny, *args, **kwargs))

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                return await self._enforced_call(fn, True, action, subject, resource, environment,
                                                 cache_ttl_seconds, effect_on_error, on_deny, *args, **kwargs)

            return async_wrapper if is_async else sync_wrapper

        return decorator

    @contextlib.asynccontextmanager
    async def context(
        self,
        *,
        action: str,
        subject: Mapping[str, Any],
        resource: Mapping[str, Any],
        environment: Optional[Mapping[str, Any]] = None,
        cache_ttl_seconds: Optional[int] = None,
        effect_on_error: Optional[Effect] = None,
    ):
        """Async context manager for manual block enforcement."""
        correlation_id = str(uuid.uuid4())
        decision = await self.decide(
            subject=subject,
            action=action,
            resource=resource,
            environment=environment,
            correlation_id=correlation_id,
            cache_ttl_seconds=cache_ttl_seconds,
        )
        if not decision.allowed:
            error = PolicyDeniedError(action, subject, resource, environment, decision, correlation_id)
            await self._run_post_hooks(subject, action, resource, environment or {}, correlation_id, decision, error)
            raise error

        await self._apply_obligations(decision)
        try:
            yield
            await self._run_post_hooks(subject, action, resource, environment or {}, correlation_id, decision, None)
        except Exception as exc:
            await self._run_post_hooks(subject, action, resource, environment or {}, correlation_id, decision, exc)
            raise

    # -------- Internal helpers --------

    async def _enforced_call(
        self,
        fn: Callable[..., Any],
        is_async_fn: bool,
        action: str,
        subject_resolver: Union[Callable[..., Any], Mapping[str, Any], None],
        resource_resolver: Union[Callable[..., Any], Mapping[str, Any], None],
        env_resolver: Union[Callable[..., Any], Mapping[str, Any], None],
        cache_ttl_seconds: Optional[int],
        effect_on_error: Optional[Effect],
        on_deny: Optional[Callable[[PolicyDeniedError], Awaitable[None]]],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        correlation_id = str(uuid.uuid4())

        # Resolve dynamic attributes (supports async resolvers)
        subject = await _resolve_mapping(subject_resolver, *args, **kwargs)
        resource = await _resolve_mapping(resource_resolver, *args, **kwargs)
        environment = await _resolve_mapping(env_resolver, *args, **kwargs)

        decision = await self.decide(
            subject=subject,
            action=action,
            resource=resource,
            environment=environment,
            correlation_id=correlation_id,
            cache_ttl_seconds=cache_ttl_seconds,
        )

        if not decision.allowed:
            error = PolicyDeniedError(action, subject, resource, environment, decision, correlation_id)
            await self._run_post_hooks(subject, action, resource, environment, correlation_id, decision, error)
            if on_deny:
                await on_deny(error)
            raise error

        # obligations before execution if any
        await self._apply_obligations(decision)

        try:
            if is_async_fn:
                result = await fn(*args, **kwargs)
            else:
                # sync path inside async runner
                loop = asyncio.get_running_loop()
                result = await loop.run_in_executor(None, functools.partial(fn, *args, **kwargs))
            await self._run_post_hooks(subject, action, resource, environment, correlation_id, decision, None)
            return result
        except Exception as exc:
            await self._run_post_hooks(subject, action, resource, environment, correlation_id, decision, exc)
            raise

    async def _apply_obligations(self, decision: PolicyDecision) -> None:
        if not decision.obligations:
            return
        for name, payload in decision.obligations.items():
            handler = self._obligation_handlers.get(name)
            if not handler:
                _json_log(self.logger, logging.WARNING, "policy.obligation.unhandled", obligation=name)
                continue
            try:
                await handler(payload, decision.obligations)
            except Exception as exc:
                _json_log(self.logger, logging.ERROR, "policy.obligation.error", obligation=name, error=str(exc))

    async def _run_pre_hooks(
        self,
        subject: Mapping[str, Any],
        action: str,
        resource: Mapping[str, Any],
        environment: Mapping[str, Any],
        correlation_id: str,
    ) -> None:
        for hook in self._pre_hooks:
            try:
                await hook(subject, action, resource, environment, correlation_id)
            except Exception as exc:
                _json_log(self.logger, logging.ERROR, "policy.pre_hook.error", error=str(exc), correlation_id=correlation_id)

    async def _run_post_hooks(
        self,
        subject: Mapping[str, Any],
        action: str,
        resource: Mapping[str, Any],
        environment: Mapping[str, Any],
        correlation_id: str,
        decision: PolicyDecision,
        error: Optional[BaseException],
    ) -> None:
        for hook in self._post_hooks:
            try:
                await hook(subject, action, resource, environment, correlation_id, decision, error)
            except Exception as exc:
                _json_log(self.logger, logging.ERROR, "policy.post_hook.error", error=str(exc), correlation_id=correlation_id)

    def _decision_key(
        self,
        subject: Mapping[str, Any],
        action: str,
        resource: Mapping[str, Any],
        environment: Mapping[str, Any],
    ) -> str:
        payload = {
            "s": subject,
            "a": action,
            "r": resource,
            "e": environment,
        }
        return _stable_hash(payload)


# ----------------------------
# Async helpers
# ----------------------------

async def _resolve_mapping(
    resolver: Union[Callable[..., Any], Mapping[str, Any], None],
    *args: Any,
    **kwargs: Any,
) -> Mapping[str, Any]:
    if resolver is None:
        return {}
    if isinstance(resolver, Mapping):
        return resolver
    try:
        res = resolver(*args, **kwargs)
        if inspect.isawaitable(res):
            return (await res) or {}
        return res or {}
    except Exception:
        return {}


@contextlib.asynccontextmanager
async def _maybe_async_context(cm: Any):
    """Accept sync or async context managers uniformly."""
    if hasattr(cm, "__aenter__") and hasattr(cm, "__aexit__"):
        async with cm:
            yield
    elif hasattr(cm, "__enter__") and hasattr(cm, "__exit__"):
        with cm:
            yield
    else:
        yield


def _otel_span(name: str):
    if not _OTEL_TRACER:
        return contextlib.nullcontext()
    return _OTEL_TRACER.start_as_current_span(name)
