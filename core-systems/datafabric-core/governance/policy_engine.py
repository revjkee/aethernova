# path: datafabric-core/datafabric/governance/policy_engine.py
# -*- coding: utf-8 -*-
"""
Industrial-grade Policy Engine for Data Fabric Governance.

Key properties:
- Deny-by-default, fail-closed semantics
- Safe condition evaluation via restricted AST
- Pluggable policy stores and attribute resolvers
- Combining algorithms: DENY_OVERRIDES, PERMIT_OVERRIDES, FIRST_APPLICABLE
- Deterministic, idempotent evaluation with timeouts
- Structured audit trail and rationale
- Async-first API for integration with modern stacks
- Minimal dependencies (stdlib only)
"""

from __future__ import annotations

import abc
import asyncio
import dataclasses
import functools
import inspect
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum, auto
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

import ast
import threading
from contextlib import asynccontextmanager

__all__ = [
    "Decision",
    "Effect",
    "CombiningAlgorithm",
    "Obligation",
    "PolicyTarget",
    "Policy",
    "PolicySet",
    "RequestContext",
    "EvaluationResult",
    "PolicyStore",
    "InMemoryPolicyStore",
    "AttributeResolver",
    "CompositeAttributeResolver",
    "GovernanceAuditSink",
    "LoggingAuditSink",
    "PolicyDecisionPoint",
    "PolicyEngineConfig",
    "PolicyEngineError",
    "PolicyEvaluationTimeout",
    "PolicyValidationError",
    "ConditionEvaluationError",
]


# ---------- Exceptions ----------

class PolicyEngineError(Exception):
    """Base error for policy engine."""


class PolicyEvaluationTimeout(PolicyEngineError):
    """Raised when evaluation exceeds configured timeout."""


class PolicyValidationError(PolicyEngineError):
    """Raised when policy is invalid."""


class ConditionEvaluationError(PolicyEngineError):
    """Raised when condition evaluation fails."""


# ---------- Enums & Models ----------

class Decision(Enum):
    PERMIT = auto()
    DENY = auto()
    NOT_APPLICABLE = auto()
    INDETERMINATE = auto()


class Effect(Enum):
    PERMIT = auto()
    DENY = auto()


class CombiningAlgorithm(Enum):
    """How to combine multiple applicable policies."""
    DENY_OVERRIDES = auto()
    PERMIT_OVERRIDES = auto()
    FIRST_APPLICABLE = auto()


@dataclass(frozen=True)
class Obligation:
    """
    Obligation returned to the PEP for post-decision actions.
    The engine does not execute obligations; it returns them for the caller to enforce.
    """
    id: str
    params: Mapping[str, Any] = dataclasses.field(default_factory=dict)
    on_effect: Effect = Effect.PERMIT
    description: Optional[str] = None


@dataclass(frozen=True)
class PolicyTarget:
    """
    Target filters which requests a policy applies to before evaluating conditions.
    All declared constraints must match (logical AND).
    Supported keys: subject, resource, action, environment.
    Each maps to dict of attribute->expected_value (exact or 'in' for sequences).
    """
    subject: Mapping[str, Any] = dataclasses.field(default_factory=dict)
    resource: Mapping[str, Any] = dataclasses.field(default_factory=dict)
    action: Mapping[str, Any] = dataclasses.field(default_factory=dict)
    environment: Mapping[str, Any] = dataclasses.field(default_factory=dict)


@dataclass(frozen=True)
class Policy:
    """
    A single policy unit.
    """
    id: str
    version: str
    effect: Effect
    priority: int = 100  # lower number -> higher priority
    target: PolicyTarget = dataclasses.field(default_factory=PolicyTarget)
    condition: Optional[str] = None  # safe expression over attributes
    obligations: Tuple[Obligation, ...] = tuple()
    description: Optional[str] = None
    tags: Tuple[str, ...] = tuple()
    enabled: bool = True
    created_at: datetime = dataclasses.field(default_factory=lambda: datetime.now(timezone.utc))

    def validate(self) -> None:
        if not self.id or not self.version:
            raise PolicyValidationError("Policy must have non-empty id and version")
        if self.priority < 0:
            raise PolicyValidationError("Policy priority must be >= 0")
        if self.condition is not None and not isinstance(self.condition, str):
            raise PolicyValidationError("Policy.condition must be a string or None")
        # Basic target shape sanity
        for block_name, block in (
            ("subject", self.target.subject),
            ("resource", self.target.resource),
            ("action", self.target.action),
            ("environment", self.target.environment),
        ):
            if not isinstance(block, Mapping):
                raise PolicyValidationError(f"Target.{block_name} must be a mapping")


@dataclass(frozen=True)
class PolicySet:
    """
    A named collection of policies evaluated together under a combining algorithm.
    """
    id: str
    algorithm: CombiningAlgorithm = CombiningAlgorithm.DENY_OVERRIDES
    policies: Tuple[Policy, ...] = tuple()
    description: Optional[str] = None
    version: str = "1.0"

    def validate(self) -> None:
        if not self.id:
            raise PolicyValidationError("PolicySet must have non-empty id")
        for p in self.policies:
            p.validate()


@dataclass(frozen=True)
class RequestContext:
    """
    Encapsulates evaluation context.
    Attributes may already be resolved or require AttributeResolver.
    """
    subject: Mapping[str, Any]
    resource: Mapping[str, Any]
    action: Mapping[str, Any]
    environment: Mapping[str, Any] = dataclasses.field(default_factory=dict)
    # Optional correlation ids for traceability
    request_id: Optional[str] = None
    tenant_id: Optional[str] = None


@dataclass(frozen=True)
class EvaluationResult:
    """
    Final decision with detailed rationale.
    """
    decision: Decision
    obligations: Tuple[Obligation, ...] = tuple()
    matched_policies: Tuple[str, ...] = tuple()
    algorithm: CombiningAlgorithm = CombiningAlgorithm.DENY_OVERRIDES
    rationale: Mapping[str, Any] = dataclasses.field(default_factory=dict)
    evaluation_time_ms: int = 0
    timestamp: datetime = dataclasses.field(default_factory=lambda: datetime.now(timezone.utc))


# ---------- Attribute Resolver Interfaces ----------

class AttributeResolver(abc.ABC):
    """
    Resolves missing attributes at evaluation-time (e.g., RBAC entitlements, PII flags).
    Implementations should be side-effect free, idempotent, and cancellable.
    """

    @abc.abstractmethod
    async def resolve(
        self,
        ctx: RequestContext,
        *,
        required: Mapping[str, Iterable[str]] | None = None,
        timeout: Optional[float] = None,
    ) -> Mapping[str, Mapping[str, Any]]:
        """
        Return a mapping with keys: subject, resource, action, environment.
        Each is a dict of attribute->value to merge with ctx before evaluation.
        Only resolve what is missing or requested via 'required'.
        """


class CompositeAttributeResolver(AttributeResolver):
    """
    Chains multiple resolvers. First non-missing value wins.
    """

    def __init__(self, resolvers: Sequence[AttributeResolver]):
        self._resolvers = list(resolvers)

    async def resolve(
        self,
        ctx: RequestContext,
        *,
        required: Mapping[str, Iterable[str]] | None = None,
        timeout: Optional[float] = None,
    ) -> Mapping[str, Mapping[str, Any]]:
        per_block: Dict[str, Dict[str, Any]] = {
            "subject": {},
            "resource": {},
            "action": {},
            "environment": {},
        }
        # Deadline-aware resolution
        deadline = time.monotonic() + timeout if timeout else None

        async def _remaining_timeout() -> Optional[float]:
            if deadline is None:
                return None
            rem = deadline - time.monotonic()
            return max(0.0, rem)

        for r in self._resolvers:
            rem = await _remaining_timeout()
            if rem is not None and rem == 0.0:
                break
            result = await r.resolve(ctx, required=required, timeout=rem)
            for k in per_block.keys():
                # Fill only missing keys
                for ak, av in result.get(k, {}).items():
                    if ak not in per_block[k]:
                        per_block[k][ak] = av
        return per_block


# ---------- Policy Store Abstractions ----------

class PolicyStore(abc.ABC):
    """
    Abstract policy store. Implement durable stores by subclassing (e.g., SQL/NoSQL).
    """

    @abc.abstractmethod
    async def list_policy_sets(
        self,
        *,
        tenant_id: Optional[str] = None,
        tags: Optional[Iterable[str]] = None,
        enabled_only: bool = True,
    ) -> Sequence[PolicySet]:
        """Return policy sets to evaluate for a request."""

    @abc.abstractmethod
    async def upsert_policy_set(self, policy_set: PolicySet) -> None:
        """Insert or update a policy set (atomic)."""

    @abc.abstractmethod
    async def get_policy_set(self, policy_set_id: str) -> Optional[PolicySet]:
        """Fetch a policy set by id."""

    @abc.abstractmethod
    async def disable_policy(self, policy_set_id: str, policy_id: str) -> None:
        """Soft-disable a policy within a set."""


class InMemoryPolicyStore(PolicyStore):
    """
    Thread-safe in-memory store for tests and low-latency control planes.
    """

    def __init__(self) -> None:
        self._sets: Dict[str, PolicySet] = {}
        self._lock = threading.RLock()

    async def list_policy_sets(
        self,
        *,
        tenant_id: Optional[str] = None,
        tags: Optional[Iterable[str]] = None,
        enabled_only: bool = True,
    ) -> Sequence[PolicySet]:
        with self._lock:
            sets = list(self._sets.values())
        if tags:
            tset = set(tags)
            sets = [
                dataclasses.replace(
                    s,
                    policies=tuple(p for p in s.policies if tset.intersection(p.tags)),
                )
                for s in sets
            ]
        if enabled_only:
            sets = [
                dataclasses.replace(
                    s,
                    policies=tuple(p for p in s.policies if p.enabled),
                )
                for s in sets
            ]
        return sets

    async def upsert_policy_set(self, policy_set: PolicySet) -> None:
        policy_set.validate()
        with self._lock:
            self._sets[policy_set.id] = policy_set

    async def get_policy_set(self, policy_set_id: str) -> Optional[PolicySet]:
        with self._lock:
            return self._sets.get(policy_set_id)

    async def disable_policy(self, policy_set_id: str, policy_id: str) -> None:
        with self._lock:
            s = self._sets.get(policy_set_id)
            if not s:
                return
            new_policies: List[Policy] = []
            for p in s.policies:
                if p.id == policy_id:
                    new_policies.append(dataclasses.replace(p, enabled=False))
                else:
                    new_policies.append(p)
            self._sets[policy_set_id] = dataclasses.replace(s, policies=tuple(new_policies))


# ---------- Audit Sink ----------

class GovernanceAuditSink(abc.ABC):
    """
    Receives immutable audit events for storage/forwarding.
    """

    @abc.abstractmethod
    async def emit(self, event: Mapping[str, Any]) -> None:
        """
        Implement durable, lossless storage if possible.
        """


class LoggingAuditSink(GovernanceAuditSink):
    """
    Default sink to python logging. Replace with Kafka/DB in production control-plane.
    """

    def __init__(self, logger: Optional[logging.Logger] = None, level: int = logging.INFO):
        self._logger = logger or logging.getLogger("datafabric.policy.audit")
        self._level = level

    async def emit(self, event: Mapping[str, Any]) -> None:
        self._logger.log(self._level, "POLICY_AUDIT %s", event)


# ---------- Safe Expression Evaluator ----------

class _SafeEvaluator:
    """
    Safely evaluate boolean expressions over request attributes using a restricted AST.
    Supported:
      - literals: None, bool, int, float, str
      - containers: tuple, list, dict (literal)
      - names: variables from supplied context only
      - ops: and, or, not; ==, !=, <, <=, >, >=; in, not in; +, -, *, /, %, //; unary +/-
      - attribute and item access for dict-like/attr objects
      - builtins (whitelisted only): len, any, all, sum, min, max, sorted, set, frozenset
    Disallowed:
      - function definitions/calls (except whitelisted simple functions)
      - comprehensions, lambdas, generators
      - imports, attribute of modules, eval/exec, etc.
    """

    _ALLOWED_BUILTINS: Mapping[str, Callable[..., Any]] = {
        "len": len,
        "any": any,
        "all": all,
        "sum": sum,
        "min": min,
        "max": max,
        "sorted": sorted,
        "set": set,
        "frozenset": frozenset,
    }

    _ALLOWED_NODES = (
        ast.Expression, ast.BoolOp, ast.BinOp, ast.UnaryOp, ast.IfExp,
        ast.Compare, ast.Name, ast.Load, ast.Constant, ast.Tuple, ast.List, ast.Dict,
        ast.Subscript, ast.Attribute, ast.And, ast.Or, ast.Not, ast.In, ast.NotIn,
        ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
        ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.USub, ast.UAdd,
        ast.Call,  # limited to allowed builtins only
    )

    def __init__(self) -> None:
        self._compile_cache: Dict[str, ast.AST] = {}
        self._lock = threading.RLock()

    def _compile_expr(self, expr: str) -> ast.AST:
        with self._lock:
            node = self._compile_cache.get(expr)
            if node is not None:
                return node
        try:
            parsed = ast.parse(expr, mode="eval")
        except SyntaxError as e:
            raise ConditionEvaluationError(f"Invalid condition syntax: {e}") from e
        for n in ast.walk(parsed):
            if not isinstance(n, self._ALLOWED_NODES):
                raise ConditionEvaluationError(f"Disallowed expression node: {type(n).__name__}")
            if isinstance(n, ast.Call):
                if not isinstance(n.func, ast.Name):
                    raise ConditionEvaluationError("Only whitelisted builtin calls are allowed")
                if n.keywords:
                    # Allow keyword args but ensure simple names only
                    for kw in n.keywords:
                        if kw.arg is None:
                            raise ConditionEvaluationError("No **kwargs splat allowed")
                # Function name must be allowed builtin
                if n.func.id not in self._ALLOWED_BUILTINS:
                    raise ConditionEvaluationError(f"Call to '{n.func.id}' not allowed")
        with self._lock:
            self._compile_cache[expr] = parsed
        return parsed

    def eval(self, expr: str, variables: Mapping[str, Any]) -> Any:
        parsed = self._compile_expr(expr)
        # Prepare read-only builtins
        safe_builtins = dict(self._ALLOWED_BUILTINS)

        # No globals except safe builtins
        globals_ns = {"__builtins__": safe_builtins}
        locals_ns = dict(variables)

        try:
            return eval(  # noqa: S307 - guarded by AST whitelist and limited builtins
                compile(parsed, filename="<policy_expr>", mode="eval"),
                globals_ns,
                locals_ns,
            )
        except Exception as e:
            raise ConditionEvaluationError(f"Error evaluating condition: {e}") from e


# ---------- Engine Config ----------

@dataclass(frozen=True)
class PolicyEngineConfig:
    max_eval_time: float = 0.150  # seconds timeout for total evaluation
    algorithm: CombiningAlgorithm = CombiningAlgorithm.DENY_OVERRIDES
    clock: Callable[[], float] = time.monotonic  # injectable for tests
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
    enable_rationale: bool = True
    evaluate_disabled: bool = False  # if True, include disabled policies (for dry-runs)


# ---------- PDP (Policy Decision Point) ----------

class PolicyDecisionPoint:
    """
    Central decision engine.

    Thread-safe, async-first.
    """

    def __init__(
        self,
        store: PolicyStore,
        resolver: Optional[AttributeResolver] = None,
        audit_sink: Optional[GovernanceAuditSink] = None,
        config: Optional[PolicyEngineConfig] = None,
    ) -> None:
        self._store = store
        self._resolver = resolver or CompositeAttributeResolver([])
        self._audit = audit_sink or LoggingAuditSink()
        self._cfg = config or PolicyEngineConfig()
        self._evaluator = _SafeEvaluator()
        self._logger = logging.getLogger("datafabric.policy.pdp")

    async def evaluate(
        self,
        ctx: RequestContext,
        *,
        policy_set_ids: Optional[Sequence[str]] = None,
        tags: Optional[Iterable[str]] = None,
        timeout: Optional[float] = None,
    ) -> EvaluationResult:
        """
        Evaluate request against policy sets.

        Fail-closed: If anything goes wrong or times out -> DENY.
        """
        overall_timeout = timeout or self._cfg.max_eval_time
        start = self._cfg.clock()
        deadline = start + overall_timeout

        def remaining() -> float:
            return max(0.0, deadline - self._cfg.clock())

        # Resolve attributes
        try:
            resolved = await self._resolver.resolve(ctx, timeout=remaining())
        except Exception as e:
            await self._emit_audit(ctx, decision=Decision.DENY, rationale={"error": f"resolver: {e}"})
            return self._fail_closed(ctx, start, reason=f"resolver error: {e}")

        merged_ctx = RequestContext(
            subject={**resolved.get("subject", {}), **ctx.subject},
            resource={**resolved.get("resource", {}), **ctx.resource},
            action={**resolved.get("action", {}), **ctx.action},
            environment={**resolved.get("environment", {}), **ctx.environment},
            request_id=ctx.request_id,
            tenant_id=ctx.tenant_id,
        )

        # Fetch policy sets
        try:
            if policy_set_ids:
                sets = []
                for sid in policy_set_ids:
                    ps = await self._store.get_policy_set(sid)
                    if ps:
                        sets.append(ps)
            else:
                sets = await self._store.list_policy_sets(
                    tenant_id=ctx.tenant_id,
                    tags=tags,
                    enabled_only=not self._cfg.evaluate_disabled,
                )
        except Exception as e:
            await self._emit_audit(merged_ctx, decision=Decision.DENY, rationale={"error": f"store: {e}"})
            return self._fail_closed(merged_ctx, start, reason=f"store error: {e}")

        # Sort policies by priority within each set
        sorted_sets: List[PolicySet] = []
        for s in sets:
            pols = sorted(s.policies, key=lambda p: p.priority)
            sorted_sets.append(dataclasses.replace(s, policies=tuple(pols)))

        # Evaluate sets sequentially; combine results per-set, then aggregate across sets via engine default algorithm
        try:
            combined_result = await self._evaluate_sets(merged_ctx, sorted_sets, remaining)
        except PolicyEvaluationTimeout as e:
            await self._emit_audit(merged_ctx, decision=Decision.DENY, rationale={"error": str(e)})
            return self._fail_closed(merged_ctx, start, reason=str(e))
        except Exception as e:
            await self._emit_audit(merged_ctx, decision=Decision.DENY, rationale={"error": f"evaluation: {e}"})
            return self._fail_closed(merged_ctx, start, reason=f"evaluation error: {e}")

        total_ms = int((self._cfg.clock() - start) * 1000)
        result = dataclasses.replace(combined_result, evaluation_time_ms=total_ms)

        await self._emit_audit(merged_ctx, decision=result.decision, rationale=result.rationale)
        return result

    async def _evaluate_sets(
        self,
        ctx: RequestContext,
        sets: Sequence[PolicySet],
        remaining: Callable[[], float],
    ) -> EvaluationResult:
        algo = self._cfg.algorithm
        rationale: Dict[str, Any] = {"engine_algorithm": algo.name, "sets": []}
        matched_ids: List[str] = []
        obligations: List[Obligation] = []

        decision = Decision.NOT_APPLICABLE

        for s in sets:
            if remaining() <= 0.0:
                raise PolicyEvaluationTimeout("Evaluation timed out (sets)")

            set_result, set_matched, set_obl, set_rat = await self._evaluate_set(ctx, s, remaining)
            matched_ids.extend(set_matched)
            obligations.extend(set_obl)
            if self._cfg.enable_rationale:
                rationale["sets"].append({"id": s.id, "result": set_result.name, "details": set_rat})

            # Aggregate per engine algorithm
            if algo == CombiningAlgorithm.DENY_OVERRIDES:
                if set_result == Decision.DENY:
                    decision = Decision.DENY
                    break
                elif set_result == Decision.PERMIT and decision != Decision.PERMIT:
                    decision = Decision.PERMIT
                elif set_result == Decision.INDETERMINATE and decision == Decision.NOT_APPLICABLE:
                    decision = Decision.INDETERMINATE
            elif algo == CombiningAlgorithm.PERMIT_OVERRIDES:
                if set_result == Decision.PERMIT:
                    decision = Decision.PERMIT
                    break
                elif set_result == Decision.DENY and decision != Decision.DENY:
                    decision = Decision.DENY
                elif set_result == Decision.INDETERMINATE and decision == Decision.NOT_APPLICABLE:
                    decision = Decision.INDETERMINATE
            else:  # FIRST_APPLICABLE
                if set_result in (Decision.PERMIT, Decision.DENY, Decision.INDETERMINATE):
                    decision = set_result
                    break

        if decision == Decision.NOT_APPLICABLE:
            # Fail-closed at the end
            decision = Decision.DENY

        return EvaluationResult(
            decision=decision,
            obligations=tuple(obligations if decision == Decision.PERMIT else o for o in obligations if o.on_effect == Effect.DENY and decision == Decision.DENY) if False else tuple(obligations),
            matched_policies=tuple(matched_ids),
            algorithm=self._cfg.algorithm,
            rationale=rationale if self._cfg.enable_rationale else {},
        )

    async def _evaluate_set(
        self,
        ctx: RequestContext,
        policy_set: PolicySet,
        remaining: Callable[[], float],
    ) -> Tuple[Decision, List[str], List[Obligation], Mapping[str, Any]]:
        algo = policy_set.algorithm
        matched_ids: List[str] = []
        obligations: List[Obligation] = []
        decision = Decision.NOT_APPLICABLE
        rat_details: Dict[str, Any] = {"algorithm": algo.name, "policies": []} if self._cfg.enable_rationale else {}

        for p in policy_set.policies:
            if remaining() <= 0.0:
                raise PolicyEvaluationTimeout("Evaluation timed out (policies)")

            applicable, match_reason = self._is_applicable(ctx, p)
            if self._cfg.enable_rationale:
                rat_p: Dict[str, Any] = {"id": p.id, "priority": p.priority, "applicable": applicable, "match": match_reason}
            if not applicable:
                if self._cfg.enable_rationale:
                    rat_details.setdefault("policies", []).append(rat_p)
                continue

            cond_ok, cond_reason = self._eval_condition(ctx, p, remaining)
            if self._cfg.enable_rationale:
                rat_p["condition"] = cond_reason
            if not cond_ok:
                # condition failed -> not applicable
                if self._cfg.enable_rationale:
                    rat_details.setdefault("policies", []).append(rat_p)
                continue

            matched_ids.append(p.id)
            # Combining at set-level
            if algo == CombiningAlgorithm.DENY_OVERRIDES:
                if p.effect == Effect.DENY:
                    decision = Decision.DENY
                    obligations.extend([o for o in p.obligations if o.on_effect == Effect.DENY])
                    if self._cfg.enable_rationale:
                        rat_p["selected"] = True
                        rat_details.setdefault("policies", []).append(rat_p)
                    break
                else:
                    # permit policy, remember but continue scanning for denies
                    decision = Decision.PERMIT
                    obligations.extend([o for o in p.obligations if o.on_effect == Effect.PERMIT])
            elif algo == CombiningAlgorithm.PERMIT_OVERRIDES:
                if p.effect == Effect.PERMIT:
                    decision = Decision.PERMIT
                    obligations.extend([o for o in p.obligations if o.on_effect == Effect.PERMIT])
                    if self._cfg.enable_rationale:
                        rat_p["selected"] = True
                        rat_details.setdefault("policies", []).append(rat_p)
                    break
                else:
                    decision = Decision.DENY
                    obligations.extend([o for o in p.obligations if o.on_effect == Effect.DENY])
            else:  # FIRST_APPLICABLE
                decision = Decision.PERMIT if p.effect == Effect.PERMIT else Decision.DENY
                obligations.extend([o for o in p.obligations if o.on_effect == p.effect])
                if self._cfg.enable_rationale:
                    rat_p["selected"] = True
                    rat_details.setdefault("policies", []).append(rat_p)
                break

            if self._cfg.enable_rationale:
                rat_p["selected"] = True
                rat_details.setdefault("policies", []).append(rat_p)

        if decision == Decision.NOT_APPLICABLE:
            decision = Decision.NOT_APPLICABLE

        return decision, matched_ids, obligations, rat_details

    def _is_applicable(self, ctx: RequestContext, policy: Policy) -> Tuple[bool, Mapping[str, Any]]:
        """
        Target match: All specified attributes must match (equality or membership).
        """
        def match_block(block: Mapping[str, Any], data: Mapping[str, Any]) -> Tuple[bool, Dict[str, Any]]:
            reasons: Dict[str, Any] = {}
            for k, v in block.items():
                actual = data.get(k, None)
                ok = False
                if isinstance(v, (list, tuple, set, frozenset)):
                    ok = actual in v
                else:
                    ok = actual == v
                reasons[k] = {"expected": v, "actual": actual, "ok": ok}
                if not ok:
                    return False, reasons
            return True, reasons

        all_ok = True
        detail: Dict[str, Any] = {}
        for name in ("subject", "resource", "action", "environment"):
            block = getattr(policy.target, name)
            ok, reason = match_block(block, getattr(ctx, name))
            detail[name] = reason
            if not ok:
                all_ok = False
                break
        return all_ok, detail

    def _eval_condition(
        self,
        ctx: RequestContext,
        policy: Policy,
        remaining: Callable[[], float],
    ) -> Tuple[bool, Mapping[str, Any]]:
        """
        Evaluate condition expression against merged attributes.
        Returns (bool, rationale).
        """
        if not policy.condition:
            return True, {"skipped": True, "reason": "no_condition"}

        if remaining() <= 0.0:
            raise PolicyEvaluationTimeout("Evaluation timed out (condition)")

        variables = {
            # Expose blocks under their names
            "subject": ctx.subject,
            "resource": ctx.resource,
            "action": ctx.action,
            "env": ctx.environment,
            # Convenience aliases
            "environment": ctx.environment,
            # Time helpers (read-only)
            "now": self._cfg.now(),
            "utcnow": self._cfg.now(),
        }

        try:
            result = self._evaluator.eval(policy.condition, variables)
            ok = bool(result)
            return ok, {"expr": policy.condition, "result": bool(result)}
        except ConditionEvaluationError as e:
            # Fail closed on eval error
            self._logger.warning("Condition evaluation failed for policy %s: %s", policy.id, e)
            return False, {"expr": policy.condition, "error": str(e)}

    def _fail_closed(self, ctx: RequestContext, start: float, reason: str) -> EvaluationResult:
        total_ms = int((self._cfg.clock() - start) * 1000)
        return EvaluationResult(
            decision=Decision.DENY,
            obligations=tuple(),
            matched_policies=tuple(),
            algorithm=self._cfg.algorithm,
            rationale={"fail_closed": True, "reason": reason} if self._cfg.enable_rationale else {},
            evaluation_time_ms=total_ms,
        )

    async def _emit_audit(self, ctx: RequestContext, *, decision: Decision, rationale: Mapping[str, Any]) -> None:
        event = {
            "ts": self._cfg.now().isoformat(),
            "tenant_id": ctx.tenant_id,
            "request_id": ctx.request_id,
            "decision": decision.name,
            "subject": _truncate_for_audit(ctx.subject),
            "resource": _truncate_for_audit(ctx.resource),
            "action": _truncate_for_audit(ctx.action),
            "environment": _truncate_for_audit(ctx.environment),
            "rationale": rationale if self._cfg.enable_rationale else {},
        }
        try:
            await self._audit.emit(event)
        except Exception:
            # Never fail decision due to audit problems
            self._logger.exception("Audit sink failed")


def _truncate_for_audit(d: Mapping[str, Any], *, limit: int = 2048) -> Mapping[str, Any]:
    """
    Ensure audit payloads are bounded. Truncate long values.
    """
    out: Dict[str, Any] = {}
    size = 0
    for k, v in d.items():
        s = str(v)
        if size + len(s) > limit:
            out[k] = s[: max(0, limit - size)] + "…"
            break
        out[k] = v if len(s) <= 256 else s[:256] + "…"
        size += len(s)
    return out


# ---------- Utilities for Builders / Validation ----------

def build_policy(
    *,
    id: str,
    version: str,
    effect: Effect,
    priority: int = 100,
    target: Optional[Mapping[str, Mapping[str, Any]]] = None,
    condition: Optional[str] = None,
    obligations: Optional[Iterable[Obligation]] = None,
    description: Optional[str] = None,
    tags: Optional[Iterable[str]] = None,
    enabled: bool = True,
) -> Policy:
    """
    Convenience builder with validation.
    """
    t = target or {}
    p = Policy(
        id=id,
        version=version,
        effect=effect,
        priority=priority,
        target=PolicyTarget(
            subject=t.get("subject", {}) or {},
            resource=t.get("resource", {}) or {},
            action=t.get("action", {}) or {},
            environment=t.get("environment", {}) or {},
        ),
        condition=condition,
        obligations=tuple(obligations or ()),
        description=description,
        tags=tuple(tags or ()),
        enabled=enabled,
    )
    p.validate()
    return p


def build_policy_set(
    *,
    id: str,
    policies: Iterable[Policy],
    algorithm: CombiningAlgorithm = CombiningAlgorithm.DENY_OVERRIDES,
    description: Optional[str] = None,
    version: str = "1.0",
) -> PolicySet:
    ps = PolicySet(
        id=id,
        algorithm=algorithm,
        policies=tuple(policies),
        description=description,
        version=version,
    )
    ps.validate()
    return ps


# ---------- Example placeholder resolvers (no external IO) ----------

class StaticAttributeResolver(AttributeResolver):
    """
    A resolver that injects static attributes (useful for tests or composition).
    """

    def __init__(self, attributes: Mapping[str, Mapping[str, Any]]):
        self._attrs = {
            "subject": dict(attributes.get("subject", {})),
            "resource": dict(attributes.get("resource", {})),
            "action": dict(attributes.get("action", {})),
            "environment": dict(attributes.get("environment", {})),
        }

    async def resolve(
        self,
        ctx: RequestContext,
        *,
        required: Mapping[str, Iterable[str]] | None = None,
        timeout: Optional[float] = None,
    ) -> Mapping[str, Mapping[str, Any]]:
        # Only provide attributes not already in ctx unless explicitly required
        out: Dict[str, Dict[str, Any]] = {"subject": {}, "resource": {}, "action": {}, "environment": {}}
        for block in out.keys():
            avail = self._attrs.get(block, {})
            req = set(required.get(block, [])) if
