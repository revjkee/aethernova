# policy_core/pdp/combiner.py
"""
Industrial-grade PDP policy combiner.

Features:
- Strongly-typed Decision model with Effect, Status, obligations/advice merging.
- Sync and async evaluation paths with bounded concurrency and timeouts.
- XACML-inspired algorithms: permit-overrides, deny-overrides, first-applicable,
  ordered-permit-overrides, unanimous-permit, threshold-consensus.
- Extensible CombinerRegistry for custom strategies.
- Structured logging, tracing (correlation id), timing metrics.
- Robust Indeterminate handling and exception-to-decision mapping.

No external dependencies beyond the Python 3.11 stdlib.
"""

from __future__ import annotations

import abc
import asyncio
import contextvars
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    Union,
    runtime_checkable,
)

# -----------------------------------------------------------------------------
# Logging / tracing
# -----------------------------------------------------------------------------

_LOG = logging.getLogger("policy_core.pdp.combiner")
if not _LOG.handlers:
    # Default handler (production code would configure logging externally).
    _handler = logging.StreamHandler()
    _formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s [%(name)s] trace=%(trace_id)s %(message)s"
    )
    _handler.setFormatter(_formatter)
    _LOG.addHandler(_handler)
    _LOG.setLevel(logging.INFO)

_trace_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("trace_id", default="")


def _trace() -> str:
    tid = _trace_id_ctx.get()
    if not tid:
        tid = uuid.uuid4().hex
        _trace_id_ctx.set(tid)
    return tid


class _LogExtra(dict):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.setdefault("trace_id", _trace())


# -----------------------------------------------------------------------------
# Core domain types
# -----------------------------------------------------------------------------

class Effect(Enum):
    PERMIT = auto()
    DENY = auto()
    NOT_APPLICABLE = auto()
    INDETERMINATE = auto()  # includes any evaluation error or ambiguity


@dataclass(slots=True, frozen=True)
class Obligation:
    id: str
    attributes: Mapping[str, Any] = field(default_factory=dict)


@dataclass(slots=True, frozen=True)
class Advice:
    id: str
    attributes: Mapping[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Status:
    code: str = "ok"
    message: str = ""
    detail: Mapping[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Decision:
    effect: Effect
    obligations: List[Obligation] = field(default_factory=list)
    advice: List[Advice] = field(default_factory=list)
    status: Status = field(default_factory=Status)
    # Optional extra data for auditing/debugging:
    attributes: Dict[str, Any] = field(default_factory=dict)  # e.g., "policy_id", "latency_ms"
    errors: List[str] = field(default_factory=list)  # textual representation of exceptions

    def with_effect(self, effect: Effect) -> "Decision":
        self.effect = effect
        return self

    def add_obligations(self, items: Iterable[Obligation]) -> None:
        self.obligations.extend(items)

    def add_advice(self, items: Iterable[Advice]) -> None:
        self.advice.extend(items)

    def add_errors(self, items: Iterable[str]) -> None:
        self.errors.extend(items)


# -----------------------------------------------------------------------------
# Exceptions
# -----------------------------------------------------------------------------

class CombinerError(RuntimeError):
    """Base error for combiner."""


class UnknownAlgorithmError(CombinerError):
    pass


class EvaluationError(CombinerError):
    pass


# -----------------------------------------------------------------------------
# Evaluable Policy Protocol
# -----------------------------------------------------------------------------

Context = Mapping[str, Any]


@runtime_checkable
class Evaluable(Protocol):
    """
    A policy-like object that can be evaluated synchronously or asynchronously.

    Implementers may provide only one of the two methods; the combiner will wrap
    sync methods into a thread loop if used in async paths and vice versa.
    """

    def evaluate(self, context: Context) -> Decision:  # pragma: no cover - Protocol
        ...

    async def evaluate_async(self, context: Context) -> Decision:  # pragma: no cover - Protocol
        ...


# Helper types: evaluable can also be callables returning Decision / Awaitable[Decision]
SyncPolicyCallable = Callable[[Context], Decision]
AsyncPolicyCallable = Callable[[Context], Awaitable[Decision]]
PolicyLike = Union[Evaluable, SyncPolicyCallable, AsyncPolicyCallable]


# -----------------------------------------------------------------------------
# Utility helpers
# -----------------------------------------------------------------------------

def _now_ms() -> int:
    return int(time.time() * 1000)


def _mk_indeterminate(msg: str, *, policy_id: Optional[str] = None, exc: Optional[BaseException] = None) -> Decision:
    status = Status(code="indeterminate", message=msg)
    errors = [repr(exc)] if exc else []
    attrs: Dict[str, Any] = {}
    if policy_id is not None:
        attrs["policy_id"] = policy_id
    return Decision(effect=Effect.INDETERMINATE, status=status, attributes=attrs, errors=errors)


def _merge_obligations(base: Decision, src: Decision) -> None:
    if src.obligations:
        base.add_obligations(src.obligations)
    if src.advice:
        base.add_advice(src.advice)


async def _eval_one_async(
    item: PolicyLike,
    context: Context,
    *,
    timeout: Optional[float],
    policy_id: str,
) -> Decision:
    """
    Evaluate a single policy-like in async mode, with timeout protection.
    Maps exceptions to INDETERMINATE.
    """
    start = _now_ms()
    try:
        async def _call_async() -> Decision:
            if isinstance(item, Evaluable):
                # Prefer native async if available
                if hasattr(item, "evaluate_async") and getattr(item, "evaluate_async") is not Evaluable.evaluate_async:
                    return await item.evaluate_async(context)
                # Fallback to sync method executed in default loop's thread
                if hasattr(item, "evaluate") and getattr(item, "evaluate") is not Evaluable.evaluate:
                    loop = asyncio.get_running_loop()
                    return await loop.run_in_executor(None, item.evaluate, context)
                raise EvaluationError(f"Evaluable {item!r} has no evaluate/evaluate_async")
            # Callable branches
            if asyncio.iscoroutinefunction(item):  # type: ignore[arg-type]
                return await item(context)  # type: ignore[misc]
            # Sync callable fallback
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, item, context)  # type: ignore[misc]

        if timeout and timeout > 0:
            decision = await asyncio.wait_for(_call_async(), timeout=timeout)
        else:
            decision = await _call_async()

        # Attach latency/policy_id
        decision.attributes.setdefault("policy_id", policy_id)
        decision.attributes["latency_ms"] = _now_ms() - start
        return decision

    except asyncio.TimeoutError as e:
        _LOG.warning("Policy evaluation timeout: %s", policy_id, extra=_LogExtra())
        d = _mk_indeterminate("timeout", policy_id=policy_id, exc=e)
        d.attributes["latency_ms"] = _now_ms() - start
        return d
    except BaseException as e:  # noqa: BLE001 (we map to Indeterminate)
        _LOG.exception("Policy evaluation error: %s", policy_id, extra=_LogExtra())
        d = _mk_indeterminate("exception", policy_id=policy_id, exc=e)
        d.attributes["latency_ms"] = _now_ms() - start
        return d


def _eval_one_sync(item: PolicyLike, context: Context, *, policy_id: str) -> Decision:
    """Synchronous evaluation with exception mapping."""
    start = _now_ms()
    try:
        if isinstance(item, Evaluable):
            if hasattr(item, "evaluate") and getattr(item, "evaluate") is not Evaluable.evaluate:
                d = item.evaluate(context)
            elif hasattr(item, "evaluate_async") and getattr(item, "evaluate_async") is not Evaluable.evaluate_async:
                # Run async implementation in a private loop
                d = asyncio.run(item.evaluate_async(context))
            else:
                raise EvaluationError(f"Evaluable {item!r} has no evaluate/evaluate_async")
        else:
            if asyncio.iscoroutinefunction(item):  # type: ignore[arg-type]
                d = asyncio.run(item(context))  # type: ignore[misc]
            else:
                d = item(context)  # type: ignore[misc]
        d.attributes.setdefault("policy_id", policy_id)
        d.attributes["latency_ms"] = _now_ms() - start
        return d
    except BaseException as e:  # noqa: BLE001
        _LOG.exception("Policy evaluation error: %s", policy_id, extra=_LogExtra())
        d = _mk_indeterminate("exception", policy_id=policy_id, exc=e)
        d.attributes["latency_ms"] = _now_ms() - start
        return d


async def _gather_with_limit(
    items: Sequence[Tuple[str, PolicyLike]],
    context: Context,
    *,
    concurrency: int,
    timeout_per_policy: Optional[float],
) -> List[Decision]:
    sem = asyncio.Semaphore(concurrency) if concurrency > 0 else None  # unlimited if 0/negative

    async def _wrapped(pid: str, policy: PolicyLike) -> Decision:
        if sem is None:
            return await _eval_one_async(policy, context, timeout=timeout_per_policy, policy_id=pid)
        async with sem:
            return await _eval_one_async(policy, context, timeout=timeout_per_policy, policy_id=pid)

    tasks = [asyncio.create_task(_wrapped(pid, p)) for pid, p in items]
    return await asyncio.gather(*tasks)


# -----------------------------------------------------------------------------
# Strategy Protocol and Base class
# -----------------------------------------------------------------------------

class Strategy(abc.ABC):
    """
    Base class for a combining strategy.
    Subclasses implement `combine_sync` and/or `combine_async`.
    """

    name: str = "base"

    def __init__(self, *, merge_obligations: bool = True) -> None:
        self.merge_obligations = merge_obligations

    # --- Async path ----------------------------------------------------------

    async def combine_async(
        self,
        policies: Sequence[Tuple[str, PolicyLike]],
        context: Context,
        *,
        concurrency: int = 16,
        timeout_per_policy: Optional[float] = None,
    ) -> Decision:
        results = await _gather_with_limit(
            policies, context, concurrency=concurrency, timeout_per_policy=timeout_per_policy
        )
        return self._reduce(results)

    # --- Sync path -----------------------------------------------------------

    def combine_sync(self, policies: Sequence[Tuple[str, PolicyLike]], context: Context) -> Decision:
        results = [_eval_one_sync(p, context, policy_id=pid) for pid, p in policies]
        return self._reduce(results)

    # --- Reduction (to be implemented by subclasses) -------------------------

    @abc.abstractmethod
    def _reduce(self, results: Sequence[Decision]) -> Decision:
        ...


# -----------------------------------------------------------------------------
# Concrete Strategies
# -----------------------------------------------------------------------------

class PermitOverrides(Strategy):
    name = "permit-overrides"

    def _reduce(self, results: Sequence[Decision]) -> Decision:
        any_permit: Optional[Decision] = None
        any_indeterminate: Optional[Decision] = None
        base = Decision(effect=Effect.NOT_APPLICABLE)

        for d in results:
            if d.effect is Effect.DENY:
                # Permit's override means deny doesn't short-circuit.
                _merge_obligations(base, d) if self.merge_obligations else None
                continue
            if d.effect is Effect.PERMIT:
                if self.merge_obligations:
                    if any_permit is None:
                        any_permit = Decision(effect=Effect.PERMIT)
                    _merge_obligations(any_permit, d)
                else:
                    any_permit = d
            elif d.effect is Effect.INDETERMINATE and any_indeterminate is None:
                any_indeterminate = d

        if any_permit is not None:
            return any_permit.with_effect(Effect.PERMIT)
        if any_indeterminate is not None:
            return any_indeterminate.with_effect(Effect.INDETERMINATE)
        return base.with_effect(Effect.NOT_APPLICABLE)


class DenyOverrides(Strategy):
    name = "deny-overrides"

    def _reduce(self, results: Sequence[Decision]) -> Decision:
        any_deny: Optional[Decision] = None
        any_indeterminate: Optional[Decision] = None
        base = Decision(effect=Effect.NOT_APPLICABLE)

        for d in results:
            if d.effect is Effect.DENY:
                if self.merge_obligations:
                    if any_deny is None:
                        any_deny = Decision(effect=Effect.DENY)
                    _merge_obligations(any_deny, d)
                else:
                    any_deny = d
            elif d.effect is Effect.INDETERMINATE and any_indeterminate is None:
                any_indeterminate = d
            elif d.effect is Effect.PERMIT:
                _merge_obligations(base, d) if self.merge_obligations else None

        if any_deny is not None:
            return any_deny.with_effect(Effect.DENY)
        if any_indeterminate is not None:
            return any_indeterminate.with_effect(Effect.INDETERMINATE)
        return base.with_effect(Effect.NOT_APPLICABLE)


class FirstApplicable(Strategy):
    name = "first-applicable"

    def _reduce(self, results: Sequence[Decision]) -> Decision:
        for d in results:
            if d.effect is not Effect.NOT_APPLICABLE:
                return d
        return Decision(effect=Effect.NOT_APPLICABLE)


class OrderedPermitOverrides(Strategy):
    """
    Like permit-overrides, but respects policy order for merging and short-circuits
    when a PERMIT is encountered (after merging prior DENY obligations if enabled).
    """
    name = "ordered-permit-overrides"

    def _reduce(self, results: Sequence[Decision]) -> Decision:
        base = Decision(effect=Effect.NOT_APPLICABLE)
        ind: Optional[Decision] = None
        for d in results:
            if d.effect is Effect.PERMIT:
                if self.merge_obligations:
                    _merge_obligations(base, d)
                    return base.with_effect(Effect.PERMIT)
                return d
            if d.effect is Effect.DENY and self.merge_obligations:
                _merge_obligations(base, d)
            if d.effect is Effect.INDETERMINATE and ind is None:
                ind = d
        return ind.with_effect(Effect.INDETERMINATE) if ind else base.with_effect(Effect.NOT_APPLICABLE)


class UnanimousPermit(Strategy):
    """
    All applicable must be PERMIT; if any DENY -> DENY, if any INDETERMINATE -> INDETERMINATE.
    If none applicable -> NOT_APPLICABLE.
    """
    name = "unanimous-permit"

    def _reduce(self, results: Sequence[Decision]) -> Decision:
        applicable = [d for d in results if d.effect is not Effect.NOT_APPLICABLE]
        if not applicable:
            return Decision(effect=Effect.NOT_APPLICABLE)
        base = Decision(effect=Effect.PERMIT)
        for d in applicable:
            if d.effect is Effect.DENY:
                return d.with_effect(Effect.DENY)
            if d.effect is Effect.INDETERMINATE:
                return d.with_effect(Effect.INDETERMINATE)
            if self.merge_obligations:
                _merge_obligations(base, d)
        return base.with_effect(Effect.PERMIT)


class ThresholdConsensus(Strategy):
    """
    Threshold-based consensus by weights.
    - Each Decision may carry numeric weight in `attributes["weight"]` (default 1).
    - Accept if sum(weights where effect==PERMIT) / sum(weights of applicable) >= threshold.
    - If any DENY exists and deny_strict=True -> DENY regardless of threshold.
    - Any INDETERMINATE -> INDETERMINATE unless ignore_indeterminate=True.
    """
    name = "threshold-consensus"

    def __init__(
        self,
        *,
        threshold: float = 0.5,
        deny_strict: bool = True,
        ignore_indeterminate: bool = False,
        merge_obligations: bool = True,
    ) -> None:
        super().__init__(merge_obligations=merge_obligations)
        if not (0.0 <= threshold <= 1.0):
            raise ValueError("threshold must be in [0,1]")
        self.threshold = threshold
        self.deny_strict = deny_strict
        self.ignore_indeterminate = ignore_indeterminate

    def _reduce(self, results: Sequence[Decision]) -> Decision:
        applicable: List[Decision] = [d for d in results if d.effect is not Effect.NOT_APPLICABLE]
        if not applicable:
            return Decision(effect=Effect.NOT_APPLICABLE)

        if not self.ignore_indeterminate and any(d.effect is Effect.INDETERMINATE for d in applicable):
            # Choose a representative INDETERMINATE
            for d in applicable:
                if d.effect is Effect.INDETERMINATE:
                    return d.with_effect(Effect.INDETERMINATE)

        if self.deny_strict and any(d.effect is Effect.DENY for d in applicable):
            for d in applicable:
                if d.effect is Effect.DENY:
                    return d.with_effect(Effect.DENY)

        total_w = 0.0
        permit_w = 0.0
        base = Decision(effect=Effect.PERMIT)
        for d in applicable:
            w = float(d.attributes.get("weight", 1.0))
            total_w += w
            if d.effect is Effect.PERMIT:
                permit_w += w
                if self.merge_obligations:
                    _merge_obligations(base, d)

        ratio = (permit_w / total_w) if total_w > 0 else 0.0
        base.attributes["consensus_ratio"] = ratio
        return base.with_effect(Effect.PERMIT if ratio >= self.threshold else Effect.NOT_APPLICABLE)


# -----------------------------------------------------------------------------
# Registry
# -----------------------------------------------------------------------------

class CombinerRegistry:
    """
    Registry of strategies by name.
    """

    def __init__(self) -> None:
        self._by_name: Dict[str, Callable[[], Strategy]] = {}

    def register(self, name: str, factory: Callable[[], Strategy]) -> None:
        key = name.strip().lower()
        if key in self._by_name:
            _LOG.warning("Overriding combiner strategy: %s", key, extra=_LogExtra())
        self._by_name[key] = factory

    def create(self, name: str) -> Strategy:
        key = name.strip().lower()
        try:
            return self._by_name[key]()
        except KeyError as e:
            raise UnknownAlgorithmError(f"Unknown combiner algorithm: {name}") from e

    def names(self) -> List[str]:
        return sorted(self._by_name.keys())


_registry = CombinerRegistry()
_registry.register(PermitOverrides.name, lambda: PermitOverrides())
_registry.register(DenyOverrides.name, lambda: DenyOverrides())
_registry.register(FirstApplicable.name, lambda: FirstApplicable())
_registry.register(OrderedPermitOverrides.name, lambda: OrderedPermitOverrides())
_registry.register(UnanimousPermit.name, lambda: UnanimousPermit())
# ThresholdConsensus requires params; expose a factory for default; advanced users can instantiate directly.
_registry.register(ThresholdConsensus.name, lambda: ThresholdConsensus())


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------

def combine(
    algorithm: str,
    policies: Sequence[PolicyLike] | Mapping[str, PolicyLike],
    context: Context,
    *,
    merge_obligations: bool = True,
) -> Decision:
    """
    Synchronous combining entrypoint.

    `policies` can be:
      - Sequence of PolicyLike (assigned synthetic ids "p0", "p1", ...)
      - Mapping policy_id -> PolicyLike

    For parametric algorithms (e.g., ThresholdConsensus), instantiate the strategy class
    directly and call `strategy.combine_sync(...)`.
    """
    trace_id = _trace()
    start = _now_ms()
    _LOG.info("combine(sync) start algorithm=%s", algorithm, extra=_LogExtra())
    try:
        if isinstance(policies, Mapping):
            items: List[Tuple[str, PolicyLike]] = list(policies.items())
        else:
            items = [(f"p{i}", p) for i, p in enumerate(policies)]
        strat = _registry.create(algorithm)
        strat.merge_obligations = merge_obligations
        decision = strat.combine_sync(items, context)
        decision.attributes.setdefault("trace_id", trace_id)
        decision.attributes["combiner_algorithm"] = strat.name
        decision.attributes["latency_ms"] = _now_ms() - start
        return decision
    finally:
        _LOG.info("combine(sync) end algorithm=%s", algorithm, extra=_LogExtra())


async def acombine(
    algorithm: str,
    policies: Sequence[PolicyLike] | Mapping[str, PolicyLike],
    context: Context,
    *,
    concurrency: int = 16,
    timeout_per_policy: Optional[float] = None,
    merge_obligations: bool = True,
) -> Decision:
    """
    Asynchronous combining entrypoint with bounded concurrency & per-policy timeout.
    """
    trace_id = _trace()
    start = _now_ms()
    _LOG.info(
        "combine(async) start algorithm=%s concurrency=%s timeout=%s",
        algorithm,
        concurrency,
        timeout_per_policy,
        extra=_LogExtra(),
    )
    try:
        if isinstance(policies, Mapping):
            items: List[Tuple[str, PolicyLike]] = list(policies.items())
        else:
            items = [(f"p{i}", p) for i, p in enumerate(policies)]
        strat = _registry.create(algorithm)
        strat.merge_obligations = merge_obligations
        decision = await strat.combine_async(
            items, context, concurrency=concurrency, timeout_per_policy=timeout_per_policy
        )
        decision.attributes.setdefault("trace_id", trace_id)
        decision.attributes["combiner_algorithm"] = strat.name
        decision.attributes["latency_ms"] = _now_ms() - start
        return decision
    finally:
        _LOG.info("combine(async) end algorithm=%s", algorithm, extra=_LogExtra())


# -----------------------------------------------------------------------------
# Convenience for advanced users: direct class accessors
# -----------------------------------------------------------------------------

def registry() -> CombinerRegistry:
    return _registry


__all__ = [
    # Domain
    "Effect",
    "Obligation",
    "Advice",
    "Status",
    "Decision",
    "Context",
    "Evaluable",
    "PolicyLike",
    # Errors
    "CombinerError",
    "UnknownAlgorithmError",
    "EvaluationError",
    # Strategies
    "Strategy",
    "PermitOverrides",
    "DenyOverrides",
    "FirstApplicable",
    "OrderedPermitOverrides",
    "UnanimousPermit",
    "ThresholdConsensus",
    # API
    "combine",
    "acombine",
    "registry",
]
