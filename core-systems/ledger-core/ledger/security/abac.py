# ledger/security/abac.py
# Industrial-grade Attribute-Based Access Control (ABAC) for ledger-core.
# Async-first, safe expression engine (AST sandbox), PDP/PEP/PIP separation,
# policy combining algorithms, auditing, caching, and typed Pydantic schemas.
#
# Tested with: Python 3.11+, pydantic>=2
#
# External deps: pydantic
# Standard lib: ast, asyncio, dataclasses, datetime, enum, fnmatch, logging,
#              time, typing, contextlib, functools, hashlib, re
from __future__ import annotations

import ast
import asyncio
import fnmatch
import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from functools import lru_cache
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple, Union

from pydantic import BaseModel, Field, ValidationError, field_validator

# ------------------------------------------------------------------------------
# Logging: structured, minimal defaults
# ------------------------------------------------------------------------------
logger = logging.getLogger("ledger.security.abac")
if not logger.handlers:
    _h = logging.StreamHandler()
    _f = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    _h.setFormatter(_f)
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# ------------------------------------------------------------------------------
# ABAC domain types
# ------------------------------------------------------------------------------

class Effect(str, Enum):
    PERMIT = "permit"
    DENY = "deny"
    NOT_APPLICABLE = "not_applicable"
    INDETERMINATE = "indeterminate"

class CombiningAlgo(str, Enum):
    DENY_OVERRIDES = "deny_overrides"
    PERMIT_OVERRIDES = "permit_overrides"
    FIRST_APPLICABLE = "first_applicable"

# Obligation = side-effect hints to PEP (e.g., reason codes, masking behavior)
class Obligation(BaseModel):
    id: str = Field(..., description="Obligation identifier")
    params: Dict[str, Any] = Field(default_factory=dict)

# Target matching supports wildcard masks for action, resource types, etc.
class Target(BaseModel):
    actions: List[str] = Field(default_factory=list, description="e.g., ['transfer:*', 'ledger.read']")
    subject_attrs: Dict[str, Any] = Field(default_factory=dict, description="Exact match or fnmatch for strings")
    object_attrs: Dict[str, Any] = Field(default_factory=dict, description="Exact match or fnmatch for strings")
    env_attrs: Dict[str, Any] = Field(default_factory=dict, description="Exact match or fnmatch for strings")

    @staticmethod
    def _match_kv(candidate: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
        for key, val in expected.items():
            if key not in candidate:
                return False
            c = candidate[key]
            if isinstance(val, str) and isinstance(c, str):
                if not fnmatch.fnmatchcase(c, val):
                    return False
            elif isinstance(val, (list, tuple, set)):
                # any-of semantics for lists
                if isinstance(c, (list, tuple, set)):
                    if not any(_match_value(cv, val) for cv in c):
                        return False
                else:
                    if not _match_value(c, val):
                        return False
            else:
                if c != val:
                    return False
        return True

    def matches(self, s: Mapping[str, Any], o: Mapping[str, Any], a: str, e: Mapping[str, Any]) -> bool:
        # actions empty => any
        if self.actions:
            ok = any(fnmatch.fnmatchcase(a, pat) for pat in self.actions)
            if not ok:
                return False
        return (
            self._match_kv(s, self.subject_attrs) and
            self._match_kv(o, self.object_attrs) and
            self._match_kv(e, self.env_attrs)
        )

def _match_value(candidate: Any, patterns: Iterable[Any]) -> bool:
    for p in patterns:
        if isinstance(p, str) and isinstance(candidate, str):
            if fnmatch.fnmatchcase(candidate, p):
                return True
        else:
            if candidate == p:
                return True
    return False

class Condition(BaseModel):
    expr: str = Field(..., description="Safe expression using s, o, a, e, now()")
    description: Optional[str] = None

class Rule(BaseModel):
    id: str
    effect: Effect
    target: Optional[Target] = None
    condition: Optional[Condition] = None
    obligations: List[Obligation] = Field(default_factory=list)
    priority: int = Field(100, description="Lower number => evaluated earlier for first_applicable")

class Policy(BaseModel):
    id: str
    version: str = Field("1.0")
    combining: CombiningAlgo = Field(CombiningAlgo.DENY_OVERRIDES)
    target: Optional[Target] = None
    rules: List[Rule] = Field(default_factory=list)
    obligations: List[Obligation] = Field(default_factory=list, description="Policy-wide obligations on match")
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("rules")
    @classmethod
    def _sorted_rules(cls, v: List[Rule]) -> List[Rule]:
        return sorted(v, key=lambda r: r.priority)

class PolicyBundle(BaseModel):
    id: str
    etag: str
    updated_at: datetime
    policies: List[Policy]

# ------------------------------------------------------------------------------
# Decision & trace
# ------------------------------------------------------------------------------

@dataclass(frozen=True)
class Decision:
    effect: Effect
    obligations: Tuple[Obligation, ...] = field(default_factory=tuple)
    used_policies: Tuple[str, ...] = field(default_factory=tuple)
    used_rules: Tuple[str, ...] = field(default_factory=tuple)
    reason: str = ""
    attributes: Dict[str, Any] = field(default_factory=dict)  # snapshot of resolved attrs

# ------------------------------------------------------------------------------
# Safe expression engine (AST sandbox)
# ------------------------------------------------------------------------------

class ExprError(Exception):
    pass

_ALLOWED_AST_NODES = (
    ast.Expression, ast.BoolOp, ast.BinOp, ast.UnaryOp, ast.Compare, ast.Name,
    ast.Load, ast.Constant, ast.And, ast.Or, ast.Not, ast.Eq, ast.NotEq, ast.Lt,
    ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn, ast.Add, ast.Sub, ast.Mult,
    ast.Div, ast.Mod, ast.Pow, ast.USub, ast.Call, ast.Attribute, ast.Subscript,
    ast.Index, ast.Slice, ast.List, ast.Tuple, ast.Dict, ast.IfExp, ast.Is, ast.IsNot,
)

_SAFE_FUNCS: Dict[str, Callable[..., Any]] = {
    "len": len,
    "any": any,
    "all": all,
    "min": min,
    "max": max,
    "sum": sum,
}

class _NowCallable:
    def __call__(self) -> int:
        # Unix timestamp seconds (integer) for deterministic comparisons
        return int(time.time())

SAFE_HELPERS: Dict[str, Any] = {"now": _NowCallable()}

def _validate_ast(node: ast.AST) -> None:
    for child in ast.walk(node):
        if not isinstance(child, _ALLOWED_AST_NODES):
            raise ExprError(f"Disallowed AST node: {type(child).__name__}")
        # Block access to dunder names and __class__-style escapes
        if isinstance(child, ast.Attribute):
            if isinstance(child.attr, str) and child.attr.startswith("__"):
                raise ExprError("Dunder attribute access is forbidden")
        if isinstance(child, ast.Name):
            if child.id.startswith("__"):
                raise ExprError("Dunder name is forbidden")

@lru_cache(maxsize=4096)
def _compile_expr(expr: str) -> ast.AST:
    try:
        node = ast.parse(expr, mode="eval")
    except SyntaxError as e:
        raise ExprError(f"Invalid expression syntax: {e}") from e
    _validate_ast(node)
    return node

def _eval_expr(expr: str, ctx: Dict[str, Any]) -> Any:
    node = _compile_expr(expr)
    return _eval_ast(node.body, ctx)

def _eval_ast(node: ast.AST, ctx: Dict[str, Any]) -> Any:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        if node.id in ctx:
            return ctx[node.id]
        if node.id in _SAFE_FUNCS:
            return _SAFE_FUNCS[node.id]
        if node.id in SAFE_HELPERS:
            return SAFE_HELPERS[node.id]
        raise ExprError(f"Unknown identifier: {node.id}")
    if isinstance(node, ast.BoolOp):
        vals = [_eval_ast(v, ctx) for v in node.values]
        if isinstance(node.op, ast.And):
            return all(vals)
        if isinstance(node.op, ast.Or):
            return any(vals)
        raise ExprError("Unsupported boolean operator")
    if isinstance(node, ast.UnaryOp):
        val = _eval_ast(node.operand, ctx)
        if isinstance(node.op, ast.Not):
            return not val
        if isinstance(node.op, ast.USub):
            return -val
        raise ExprError("Unsupported unary operator")
    if isinstance(node, ast.BinOp):
        l = _eval_ast(node.left, ctx)
        r = _eval_ast(node.right, ctx)
        if isinstance(node.op, ast.Add): return l + r
        if isinstance(node.op, ast.Sub): return l - r
        if isinstance(node.op, ast.Mult): return l * r
        if isinstance(node.op, ast.Div): return l / r
        if isinstance(node.op, ast.Mod): return l % r
        if isinstance(node.op, ast.Pow): return l ** r
        raise ExprError("Unsupported binary operator")
    if isinstance(node, ast.Compare):
        left = _eval_ast(node.left, ctx)
        for op, comparator in zip(node.ops, node.comparators):
            right = _eval_ast(comparator, ctx)
            ok = (
                isinstance(op, ast.Eq) and left == right or
                isinstance(op, ast.NotEq) and left != right or
                isinstance(op, ast.Lt) and left < right or
                isinstance(op, ast.LtE) and left <= right or
                isinstance(op, ast.Gt) and left > right or
                isinstance(op, ast.GtE) and left >= right or
                isinstance(op, ast.In) and left in right or
                isinstance(op, ast.NotIn) and left not in right or
                isinstance(op, ast.Is) and (left is right) or
                isinstance(op, ast.IsNot) and (left is not right)
            )
            if not ok:
                return False
            left = right
        return True
    if isinstance(node, ast.IfExp):
        cond = _eval_ast(node.test, ctx)
        return _eval_ast(node.body if cond else node.orelse, ctx)
    if isinstance(node, ast.Attribute):
        base = _eval_ast(node.value, ctx)
        if isinstance(node.attr, str) and node.attr.startswith("__"):
            raise ExprError("Dunder attribute access is forbidden")
        return getattr(base, node.attr) if hasattr(base, node.attr) else base.get(node.attr)
    if isinstance(node, ast.Subscript):
        base = _eval_ast(node.value, ctx)
        key = _eval_ast(node.slice.value if isinstance(node.slice, ast.Index) else node.slice, ctx)
        return base[key]
    if isinstance(node, ast.Call):
        fn = _eval_ast(node.func, ctx)
        args = [_eval_ast(a, ctx) for a in node.args]
        kwargs = {kw.arg: _eval_ast(kw.value, ctx) for kw in node.keywords}
        # Whitelist only safe callables introduced via ctx or SAFE_FUNCS
        if fn in _SAFE_FUNCS.values() or fn in SAFE_HELPERS.values():
            return fn(*args, **kwargs)
        raise ExprError("Function calls are restricted")
    if isinstance(node, (ast.Tuple, ast.List)):
        return [_eval_ast(x, ctx) for x in node.elts]
    if isinstance(node, ast.Dict):
        return { _eval_ast(k, ctx): _eval_ast(v, ctx) for k, v in zip(node.keys, node.values) }
    raise ExprError(f"Unsupported expression element: {type(node).__name__}")

# ------------------------------------------------------------------------------
# PIP (Policy Information Point): async attribute providers
# ------------------------------------------------------------------------------

class AttributeProvider(Protocol):
    async def get_subject_attrs(self, subject_id: str) -> Mapping[str, Any]: ...
    async def get_object_attrs(self, object_id: str) -> Mapping[str, Any]: ...
    async def get_env_attrs(self) -> Mapping[str, Any]: ...

# Default pass-through provider (attributes already provided by caller)
class PassthroughAttributeProvider:
    async def get_subject_attrs(self, subject_id: str) -> Mapping[str, Any]:
        return {}
    async def get_object_attrs(self, object_id: str) -> Mapping[str, Any]:
        return {}
    async def get_env_attrs(self) -> Mapping[str, Any]:
        return {}

# ------------------------------------------------------------------------------
# Policy store (atomic, versioned)
# ------------------------------------------------------------------------------

class PolicyStore:
    def __init__(self) -> None:
        self._bundle: Optional[PolicyBundle] = None
        self._lock = asyncio.Lock()

    @staticmethod
    def _calc_etag(policies: Sequence[Policy]) -> str:
        h = hashlib.sha256()
        for p in sorted(policies, key=lambda x: x.id):
            h.update(p.id.encode())
            h.update(p.version.encode())
            h.update(str(p.model_dump(mode="json", round_trip=True)).encode())
        return h.hexdigest()

    async def load(self, policies: Sequence[Mapping[str, Any]], bundle_id: str = "default") -> PolicyBundle:
        # Validate/construct policies
        validated: List[Policy] = []
        for pd in policies:
            try:
                validated.append(Policy(**pd))
            except ValidationError as e:
                raise ValueError(f"Invalid policy {pd.get('id')}: {e}") from e
        etag = self._calc_etag(validated)
        bundle = PolicyBundle(
            id=bundle_id,
            etag=etag,
            updated_at=datetime.now(timezone.utc),
            policies=validated,
        )
        async with self._lock:
            self._bundle = bundle
        logger.info(f"Policy bundle '{bundle_id}' loaded with {len(validated)} policies, etag={etag[:12]}")
        return bundle

    async def get_bundle(self) -> Optional[PolicyBundle]:
        async with self._lock:
            return self._bundle

# ------------------------------------------------------------------------------
# PDP (Policy Decision Point)
# ------------------------------------------------------------------------------

@dataclass
class EvaluationContext:
    subject_id: str
    object_id: str
    action: str
    # Caller can pre-supply attributes; PIP may add/override
    subject_attrs: Dict[str, Any] = field(default_factory=dict)
    object_attrs: Dict[str, Any] = field(default_factory=dict)
    env_attrs: Dict[str, Any] = field(default_factory=dict)
    timeout_sec: float = 0  # 0 => no timeout

class PDP:
    def __init__(
        self,
        store: PolicyStore,
        provider: Optional[AttributeProvider] = None,
        audit_sink: Optional[Callable[[Decision], None]] = None,
    ) -> None:
        self._store = store
        self._provider = provider or PassthroughAttributeProvider()
        self._audit = audit_sink or self._default_audit

    def _default_audit(self, decision: Decision) -> None:
        logger.info(
            "ABAC decision | effect=%s | policies=%s | rules=%s | reason=%s",
            decision.effect, ",".join(decision.used_policies), ",".join(decision.used_rules), decision.reason
        )

    async def _resolve_attributes(self, ctx: EvaluationContext) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        # Merge caller-supplied and provider-sourced attributes (provider overrides)
        s0, o0, e0 = ctx.subject_attrs.copy(), ctx.object_attrs.copy(), ctx.env_attrs.copy()
        s1 = await self._provider.get_subject_attrs(ctx.subject_id)
        o1 = await self._provider.get_object_attrs(ctx.object_id)
        e1 = await self._provider.get_env_attrs()
        s0.update(s1)
        o0.update(o1)
        e0.update(e1)
        # Standard attributes
        s0.setdefault("id", ctx.subject_id)
        o0.setdefault("id", ctx.object_id)
        e0.setdefault("action", ctx.action)
        e0.setdefault("timezone", "UTC")
        e0.setdefault("timestamp", int(time.time()))
        return s0, o0, e0

    async def evaluate(self, ctx: EvaluationContext) -> Decision:
        bundle = await self._store.get_bundle()
        if not bundle:
            d = Decision(effect=Effect.INDETERMINATE, reason="No policy bundle loaded")
            self._audit(d)
            return d

        async def _run() -> Decision:
            s, o, e = await self._resolve_attributes(ctx)
            # Evaluate each policy using its combining algorithm
            policy_decisions: List[Decision] = []
            for pol in bundle.policies:
                d = await self._eval_policy(pol, s, o, ctx.action, e)
                policy_decisions.append(d)

            # Combine across policies with global deny-overrides (defensive default)
            final = self._combine_global(policy_decisions)
            # attach attributes snapshot for audit/debug
            final = Decision(
                effect=final.effect,
                obligations=final.obligations,
                used_policies=final.used_policies,
                used_rules=final.used_rules,
                reason=final.reason,
                attributes={"s": s, "o": o, "a": ctx.action, "e": e},
            )
            self._audit(final)
            return final

        if ctx.timeout_sec and ctx.timeout_sec > 0:
            try:
                return await asyncio.wait_for(_run(), timeout=ctx.timeout_sec)
            except asyncio.TimeoutError:
                d = Decision(effect=Effect.INDETERMINATE, reason="PDP evaluation timeout")
                self._audit(d)
                return d
        else:
            return await _run()

    async def _eval_policy(self, policy: Policy, s: Mapping[str, Any], o: Mapping[str, Any], a: str, e: Mapping[str, Any]) -> Decision:
        # Policy target
        if policy.target and not policy.target.matches(s, o, a, e):
            return Decision(effect=Effect.NOT_APPLICABLE, reason=f"Policy {policy.id} target mismatch")

        # Evaluate rules per algorithm
        matched_rules: List[Rule] = []
        reasons: List[str] = []

        if policy.combining == CombiningAlgo.FIRST_APPLICABLE:
            for r in policy.rules:
                d, rsn = await self._eval_rule(r, s, o, a, e)
                if d != Effect.NOT_APPLICABLE and d != Effect.INDETERMINATE:
                    obls = tuple([*r.obligations, *policy.obligations])
                    return Decision(effect=d, obligations=obls, used_policies=(policy.id,), used_rules=(r.id,), reason=f"{policy.id}:{rsn}")
                # accumulate only for trace
                if d != Effect.NOT_APPLICABLE:
                    reasons.append(f"{r.id}:{d}")
            return Decision(effect=Effect.NOT_APPLICABLE if not reasons else Effect.INDETERMINATE, reason=f"{policy.id}:no first-applicable")

        deny_seen = False
        permit_seen = False
        acc_obls: List[Obligation] = []
        used_r: List[str] = []

        for r in policy.rules:
            eff, rsn = await self._eval_rule(r, s, o, a, e)
            if eff == Effect.NOT_APPLICABLE:
                continue
            used_r.append(r.id)
            reasons.append(f"{r.id}:{rsn}")
            if eff == Effect.DENY:
                deny_seen = True
                acc_obls.extend(r.obligations)
                if policy.combining == CombiningAlgo.DENY_OVERRIDES:
                    return Decision(
                        effect=Effect.DENY,
                        obligations=tuple([*acc_obls, *policy.obligations]),
                        used_policies=(policy.id,),
                        used_rules=tuple(used_r),
                        reason=f"{policy.id}:deny-overrides",
                    )
            elif eff == Effect.PERMIT:
                permit_seen = True
                acc_obls.extend(r.obligations)
                if policy.combining == CombiningAlgo.PERMIT_OVERRIDES:
                    return Decision(
                        effect=Effect.PERMIT,
                        obligations=tuple([*acc_obls, *policy.obligations]),
                        used_policies=(policy.id,),
                        used_rules=tuple(used_r),
                        reason=f"{policy.id}:permit-overrides",
                    )

        # No early return => synthesize
        if policy.combining == CombiningAlgo.DENY_OVERRIDES:
            if deny_seen:
                return Decision(effect=Effect.DENY, obligations=tuple([*acc_obls, *policy.obligations]), used_policies=(policy.id,), used_rules=tuple(used_r), reason=f"{policy.id}:deny-dominates")
            if permit_seen:
                return Decision(effect=Effect.PERMIT, obligations=tuple([*acc_obls, *policy.obligations]), used_policies=(policy.id,), used_rules=tuple(used_r), reason=f"{policy.id}:permit-after-scan")
            return Decision(effect=Effect.NOT_APPLICABLE, reason=f"{policy.id}:no-match")

        if policy.combining == CombiningAlgo.PERMIT_OVERRIDES:
            if permit_seen:
                return Decision(effect=Effect.PERMIT, obligations=tuple([*acc_obls, *policy.obligations]), used_policies=(policy.id,), used_rules=tuple(used_r), reason=f"{policy.id}:permit-dominates")
            if deny_seen:
                return Decision(effect=Effect.DENY, obligations=tuple([*acc_obls, *policy.obligations]), used_policies=(policy.id,), used_rules=tuple(used_r), reason=f"{policy.id}:deny-after-scan")
            return Decision(effect=Effect.NOT_APPLICABLE, reason=f"{policy.id}:no-match")

        # FIRST_APPLICABLE already handled
        return Decision(effect=Effect.NOT_APPLICABLE, reason=f"{policy.id}:no-rules")

    async def _eval_rule(self, rule: Rule, s: Mapping[str, Any], o: Mapping[str, Any], a: str, e: Mapping[str, Any]) -> Tuple[Effect, str]:
        if rule.target and not rule.target.matches(s, o, a, e):
            return Effect.NOT_APPLICABLE, f"{rule.id}:target-mismatch"
        if rule.condition and rule.condition.expr:
            try:
                ok = _eval_expr(rule.condition.expr, {"s": s, "o": o, "a": a, "e": e, **_SAFE_FUNCS, **SAFE_HELPERS})
                if not isinstance(ok, bool):
                    return Effect.INDETERMINATE, f"{rule.id}:non-bool-condition"
                if not ok:
                    return Effect.NOT_APPLICABLE, f"{rule.id}:cond-false"
            except ExprError as ex:
                # Defensive default: condition error => indeterminate (never permit)
                return Effect.INDETERMINATE, f"{rule.id}:expr-error:{ex}"
        return rule.effect, f"{rule.id}:matched"

    @staticmethod
    def _combine_global(policy_decisions: Sequence[Decision]) -> Decision:
        # Defensive global combining: deny dominates, then permit, else not applicable, else indeterminate
        used_policies: List[str] = []
        used_rules: List[str] = []
        obligations: List[Obligation] = []
        reasons: List[str] = []

        for d in policy_decisions:
            reasons.append(d.reason)
            if d.effect == Effect.DENY:
                used_policies.extend(d.used_policies)
                used_rules.extend(d.used_rules)
                obligations.extend(d.obligations)
                return Decision(effect=Effect.DENY, obligations=tuple(obligations), used_policies=tuple(used_policies or d.used_policies), used_rules=tuple(used_rules or d.used_rules), reason="global:deny-overrides")
        for d in policy_decisions:
            if d.effect == Effect.PERMIT:
                used_policies.extend(d.used_policies)
                used_rules.extend(d.used_rules)
                obligations.extend(d.obligations)
                return Decision(effect=Effect.PERMIT, obligations=tuple(obligations), used_policies=tuple(used_policies or d.used_policies), used_rules=tuple(used_rules or d.used_rules), reason="global:permit")
        if all(d.effect == Effect.NOT_APPLICABLE for d in policy_decisions):
            return Decision(effect=Effect.NOT_APPLICABLE, reason="global:not-applicable")
        return Decision(effect=Effect.INDETERMINATE, reason="global:indeterminate")

# ------------------------------------------------------------------------------
# PEP convenience helpers
# ------------------------------------------------------------------------------

async def enforce(
    pdp: PDP,
    subject_id: str,
    object_id: str,
    action: str,
    subject_attrs: Optional[Mapping[str, Any]] = None,
    object_attrs: Optional[Mapping[str, Any]] = None,
    env_attrs: Optional[Mapping[str, Any]] = None,
    timeout_sec: float = 0,
) -> Decision:
    """
    One-shot PEP helper to request a decision from PDP.
    """
    ctx = EvaluationContext(
        subject_id=subject_id,
        object_id=object_id,
        action=action,
        subject_attrs=dict(subject_attrs or {}),
        object_attrs=dict(object_attrs or {}),
        env_attrs=dict(env_attrs or {}),
        timeout_sec=timeout_sec,
    )
    return await pdp.evaluate(ctx)

# ------------------------------------------------------------------------------
# Example of policy JSON (documentation-only)
# ------------------------------------------------------------------------------
# {
#   "id": "ledger.core.v1",
#   "version": "1.4",
#   "combining": "deny_overrides",
#   "target": {
#     "actions": ["ledger.*"]
#   },
#   "rules": [
#     {
#       "id": "deny-suspended-user",
#       "effect": "deny",
#       "priority": 10,
#       "condition": { "expr": "s.get('status') == 'suspended'" },
#       "obligations": [{"id": "reason", "params": {"code": "user_suspended"}}]
#     },
#     {
#       "id": "permit-office-hours",
#       "effect": "permit",
#       "priority": 50,
#       "target": {"actions": ["ledger.read", "ledger.transfer:*"]},
#       "condition": { "expr": "(e.get('hour') >= 8) and (e.get('hour') < 20)"}
#     }
#   ]
# }

# ------------------------------------------------------------------------------
# Minimal default provider illustrating env enrichment (hour, ip risk)
# ------------------------------------------------------------------------------

class DefaultEnvProvider(PassthroughAttributeProvider):
    async def get_env_attrs(self) -> Mapping[str, Any]:
        ts = int(time.time())
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return {"timestamp": ts, "hour": dt.hour, "timezone": "UTC"}

# ------------------------------------------------------------------------------
# Factory utilities
# ------------------------------------------------------------------------------

def build_pdp_with_policies(
    policies: Sequence[Mapping[str, Any]],
    provider: Optional[AttributeProvider] = None,
    bundle_id: str = "default",
) -> Tuple[PDP, PolicyStore, PolicyBundle]:
    """
    Synchronous convenience to construct PDP+Store and load policies.
    Intended for app bootstrap (wrap into async if needed).
    """
    store = PolicyStore()
    # Run sync helper by driving event loop; callers in async contexts should
    # prefer: store.load(...) awaited explicitly.
    loop = asyncio.get_event_loop()
    bundle = loop.run_until_complete(store.load(policies, bundle_id=bundle_id))
    pdp = PDP(store, provider=provider or DefaultEnvProvider())
    return pdp, store, bundle
