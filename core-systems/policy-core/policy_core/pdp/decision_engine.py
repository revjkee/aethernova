# policy-core/policy_core/pdp/decision_engine.py
"""
Industrial-grade Policy Decision Point (PDP) engine.

Features:
- Async, fail-closed Zero-Trust PDP with ABAC/RBAC rule evaluation
- Safe expression evaluator (AST whitelist)
- Combining algorithms: deny_overrides, permit_overrides, first_applicable, ordered_deny_overrides
- In-memory policy store with revision hashing
- TTL LRU cache for decisions (async-safe)
- Structured audit logs & lightweight metrics
- Optional HMAC signature for decision integrity
- Pluggable attribute resolvers and function registry (CIDR, regex, glob, time windows, etc.)

This file is self-contained and has no third-party dependencies.
"""

from __future__ import annotations

import asyncio
import contextvars
import dataclasses
import enum
import fnmatch
import hashlib
import hmac
import ipaddress
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Callable, Union

import ast

# ---------------------------- Logging setup ----------------------------

LOGGER_NAME = "policy_core.pdp.decision_engine"
logger = logging.getLogger(LOGGER_NAME)
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(message)s"))
    logger.addHandler(_handler)
logger.setLevel(logging.INFO)

# ---------------------------- Context & Observability ----------------------------

request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")
span_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("span_id", default="")


def _now_utc_ts() -> float:
    return time.time()


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------- Enums & Data Models ----------------------------

class Effect(enum.Enum):
    PERMIT = "permit"
    DENY = "deny"


class DecisionType(enum.Enum):
    PERMIT = "permit"
    DENY = "deny"
    NOT_APPLICABLE = "not_applicable"
    INDETERMINATE = "indeterminate"


class CombiningAlgo(enum.Enum):
    DENY_OVERRIDES = "deny_overrides"
    PERMIT_OVERRIDES = "permit_overrides"
    FIRST_APPLICABLE = "first_applicable"
    ORDERED_DENY_OVERRIDES = "ordered_deny_overrides"


@dataclass(frozen=True)
class Obligation:
    id: str
    attributes: Mapping[str, Any] = dataclasses.field(default_factory=dict)


@dataclass(frozen=True)
class Advice:
    id: str
    attributes: Mapping[str, Any] = dataclasses.field(default_factory=dict)


@dataclass
class Rule:
    id: str
    effect: Effect
    condition: Optional[str] = None  # safe expression
    obligations: Sequence[Obligation] = dataclasses.field(default_factory=tuple)
    advice: Sequence[Advice] = dataclasses.field(default_factory=tuple)

    # cached compiled AST for condition
    _compiled: Optional[ast.AST] = dataclasses.field(default=None, init=False, repr=False)


@dataclass
class Policy:
    id: str
    version: Union[int, str] = 1
    algo: CombiningAlgo = CombiningAlgo.DENY_OVERRIDES
    target: Optional[str] = None
    rules: Sequence[Rule] = dataclasses.field(default_factory=tuple)
    priority: int = 0  # higher first
    metadata: Mapping[str, Any] = dataclasses.field(default_factory=dict)

    _target_compiled: Optional[ast.AST] = dataclasses.field(default=None, init=False, repr=False)


@dataclass(frozen=True)
class DecisionRequest:
    subject: Mapping[str, Any]
    resource: Mapping[str, Any]
    action: str
    env: Mapping[str, Any] = dataclasses.field(default_factory=dict)


@dataclass
class DecisionResponse:
    decision: DecisionType
    obligations: List[Obligation] = field(default_factory=list)
    advice: List[Advice] = field(default_factory=list)
    policy_id: Optional[str] = None
    matched_rules: List[str] = field(default_factory=list)
    reason: Optional[str] = None
    timestamp: str = field(default_factory=_now_utc_iso)
    latency_ms: float = 0.0
    decision_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    signature: Optional[str] = None

    def to_dict(self, include_signature: bool = True) -> Dict[str, Any]:
        d = {
            "decision": self.decision.value,
            "obligations": [{"id": o.id, "attributes": dict(o.attributes)} for o in self.obligations],
            "advice": [{"id": a.id, "attributes": dict(a.attributes)} for a in self.advice],
            "policy_id": self.policy_id,
            "matched_rules": list(self.matched_rules),
            "reason": self.reason,
            "timestamp": self.timestamp,
            "latency_ms": self.latency_ms,
            "decision_id": self.decision_id,
        }
        if include_signature:
            d["signature"] = self.signature
        return d


# ---------------------------- Utility: AttrDict (dot-notation) ----------------------------

class AttrDict(dict):
    """
    Dictionary with dot-notation access. Missing keys return None.
    Nested mappings are wrapped recursively.
    """

    def __getattr__(self, item: str) -> Any:
        try:
            v = self[item]
        except KeyError:
            return None
        return _wrap(v)

    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


def _wrap(value: Any) -> Any:
    if isinstance(value, Mapping):
        return AttrDict({k: _wrap(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        t = type(value)
        return t(_wrap(v) for v in value)
    return value


# ---------------------------- Safe Expression Evaluator ----------------------------

_ALLOWED_NODES = {
    ast.Expression, ast.BoolOp, ast.BinOp, ast.UnaryOp, ast.IfExp,
    ast.Compare, ast.Name, ast.Load, ast.Constant, ast.Dict, ast.Set, ast.List, ast.Tuple,
    ast.And, ast.Or, ast.Not, ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn,
    ast.Subscript, ast.Slice, ast.Index, ast.Call, ast.Attribute, ast.Is, ast.IsNot,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.FloorDiv, ast.Pow,
}

class UnsafeExpressionError(Exception):
    pass


class SafeExpr:
    """
    Safe evaluator for boolean/data expressions over a restricted AST.
    Supports:
      - literals, dict/set/list/tuple
      - boolean / comparison ops
      - arithmetic (+, -, *, /, //, %, **)
      - attribute and subscript access
      - whitelisted functions via fn.<name>(...)
      - dot-notation via AttrDict
    """

    def __init__(self, functions: Mapping[str, Callable[..., Any]]):
        self.functions = functions

    def compile(self, expr: Optional[str]) -> Optional[ast.AST]:
        if not expr:
            return None
        try:
            node = ast.parse(expr, mode="eval")
        except SyntaxError as e:
            raise UnsafeExpressionError(f"syntax error: {e}") from e
        self._validate(node)
        return node

    def _validate(self, node: ast.AST) -> None:
        for child in ast.walk(node):
            if type(child) not in _ALLOWED_NODES:
                raise UnsafeExpressionError(f"disallowed AST node: {type(child).__name__}")
            if isinstance(child, ast.Call):
                # Only allow calls to fn.<name>
                if not isinstance(child.func, ast.Attribute) or not isinstance(child.func.value, ast.Name):
                    raise UnsafeExpressionError("only fn.<name>(...) calls are allowed")
                if child.func.value.id != "fn":
                    raise UnsafeExpressionError("function calls must be namespaced under 'fn'")
            if isinstance(child, ast.Attribute):
                # Allow arbitrary attribute names; resolution is controlled by AttrDict
                pass

    def eval(self, compiled: Optional[ast.AST], context: Mapping[str, Any]) -> Any:
        if compiled is None:
            return True
        return self._eval_node(compiled.body, context)

    # ---- Node evaluators ----

    def _eval_node(self, node: ast.AST, ctx: Mapping[str, Any]) -> Any:
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id == "fn":
                return _FunctionNamespace(self.functions)
            return ctx.get(node.id, None)
        if isinstance(node, ast.Attribute):
            base = self._eval_node(node.value, ctx)
            return getattr(base, node.attr, None)
        if isinstance(node, ast.Dict):
            return {_const(k, ctx, self): self._eval_node(v, ctx) for k, v in zip(node.keys, node.values)}
        if isinstance(node, ast.Set):
            return {self._eval_node(e, ctx) for e in node.elts}
        if isinstance(node, ast.List):
            return [self._eval_node(e, ctx) for e in node.elts]
        if isinstance(node, ast.Tuple):
            return tuple(self._eval_node(e, ctx) for e in node.elts)
        if isinstance(node, ast.UnaryOp):
            v = self._eval_node(node.operand, ctx)
            if isinstance(node.op, ast.Not):
                return not v
            if isinstance(node.op, ast.USub):
                return -v
            if isinstance(node.op, ast.UAdd):
                return +v
        if isinstance(node, ast.BinOp):
            left = self._eval_node(node.left, ctx)
            right = self._eval_node(node.right, ctx)
            if isinstance(node.op, ast.Add): return left + right
            if isinstance(node.op, ast.Sub): return left - right
            if isinstance(node.op, ast.Mult): return left * right
            if isinstance(node.op, ast.Div): return left / right
            if isinstance(node.op, ast.FloorDiv): return left // right
            if isinstance(node.op, ast.Mod): return left % right
            if isinstance(node.op, ast.Pow): return left ** right
        if isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                for v in node.values:
                    if not self._eval_node(v, ctx):
                        return False
                return True
            if isinstance(node.op, ast.Or):
                for v in node.values:
                    if self._eval_node(v, ctx):
                        return True
                return False
        if isinstance(node, ast.Compare):
            left = self._eval_node(node.left, ctx)
            result = True
            for op, comparator in zip(node.ops, node.comparators):
                right = self._eval_node(comparator, ctx)
                if isinstance(op, ast.Eq): ok = left == right
                elif isinstance(op, ast.NotEq): ok = left != right
                elif isinstance(op, ast.Lt): ok = left < right
                elif isinstance(op, ast.LtE): ok = left <= right
                elif isinstance(op, ast.Gt): ok = left > right
                elif isinstance(op, ast.GtE): ok = left >= right
                elif isinstance(op, ast.In): ok = left in right
                elif isinstance(op, ast.NotIn): ok = left not in right
                elif isinstance(op, ast.Is): ok = left is right
                elif isinstance(op, ast.IsNot): ok = left is not right
                else: ok = False
                if not ok:
                    result = False
                    break
                left = right
            return result
        if isinstance(node, ast.IfExp):
            test = self._eval_node(node.test, ctx)
            return self._eval_node(node.body if test else node.orelse, ctx)
        if isinstance(node, ast.Subscript):
            base = self._eval_node(node.value, ctx)
            sl = node.slice
            if isinstance(sl, ast.Slice):
                lower = self._eval_node(sl.lower, ctx) if sl.lower else None
                upper = self._eval_node(sl.upper, ctx) if sl.upper else None
                step = self._eval_node(sl.step, ctx) if sl.step else None
                return base[slice(lower, upper, step)]
            key = self._eval_node(sl, ctx)
            return base[key]
        if isinstance(node, ast.Call):
            func_obj = self._eval_node(node.func, ctx)
            args = [self._eval_node(a, ctx) for a in node.args]
            kwargs = {kw.arg: self._eval_node(kw.value, ctx) for kw in node.keywords}
            return func_obj(*args, **kwargs)
        raise UnsafeExpressionError(f"unsupported node: {type(node).__name__}")


def _const(node: Optional[ast.AST], ctx: Mapping[str, Any], se: SafeExpr):
    return se._eval_node(node, ctx) if node is not None else None


class _FunctionNamespace:
    def __init__(self, registry: Mapping[str, Callable[..., Any]]):
        self._reg = registry

    def __getattr__(self, item: str) -> Callable[..., Any]:
        if item not in self._reg:
            raise UnsafeExpressionError(f"unknown function: fn.{item}")
        return self._reg[item]


# ---------------------------- Built-in function registry ----------------------------

def _fn_now_ts() -> float:
    return _now_utc_ts()


def _fn_equals_icase(a: Any, b: Any) -> bool:
    return str(a).lower() == str(b).lower()


def _fn_glob(text: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(str(text), str(pattern))


def _fn_regex(text: str, pattern: str) -> bool:
    return re.fullmatch(pattern, str(text)) is not None


def _fn_ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return False


def _fn_cidr_contains(cidr_big: str, cidr_small: str) -> bool:
    try:
        return ipaddress.ip_network(cidr_small, strict=False).subnet_of(ipaddress.ip_network(cidr_big, strict=False))
    except Exception:
        return False


def _fn_any_of(items: Iterable[Any], allowed: Iterable[Any]) -> bool:
    s = set(map(str, items))
    a = set(map(str, allowed))
    return bool(s & a)


def _fn_all_of(items: Iterable[Any], required: Iterable[Any]) -> bool:
    s = set(map(str, items))
    r = set(map(str, required))
    return r.issubset(s)


def _fn_between_hours(hour_from: int, hour_to: int, tz_offset_minutes: int = 0) -> bool:
    # hour_from/hour_to in [0..23]; supports wrap-around (e.g., 22-6)
    now = datetime.now(timezone.utc)
    if tz_offset_minutes:
        now = now.astimezone(timezone.utc).astimezone()
        now = now.fromtimestamp(now.timestamp() + tz_offset_minutes * 60, tz=timezone.utc)
    h = now.hour
    if hour_from <= hour_to:
        return hour_from <= h < hour_to
    return h >= hour_from or h < hour_to


BUILTIN_FN: Dict[str, Callable[..., Any]] = {
    "now_ts": _fn_now_ts,
    "equals_icase": _fn_equals_icase,
    "glob": _fn_glob,
    "regex": _fn_regex,
    "ip_in_cidr": _fn_ip_in_cidr,
    "cidr_contains": _fn_cidr_contains,
    "any_of": _fn_any_of,
    "all_of": _fn_all_of,
    "between_hours": _fn_between_hours,
}

# ---------------------------- Policy Store Interfaces ----------------------------

class PolicyStore:
    async def get_policies(self) -> Sequence[Policy]:
        raise NotImplementedError

    async def revision(self) -> str:
        """
        Revision string that changes whenever any policy content changes.
        """
        raise NotImplementedError


class InMemoryPolicyStore(PolicyStore):
    def __init__(self, policies: Optional[Sequence[Policy]] = None):
        self._policies: List[Policy] = list(policies or [])
        self._rev: str = self._compute_rev()

    def replace(self, policies: Sequence[Policy]) -> None:
        self._policies = list(policies)
        self._rev = self._compute_rev()

    async def get_policies(self) -> Sequence[Policy]:
        return tuple(sorted(self._policies, key=lambda p: (-p.priority, p.id)))

    async def revision(self) -> str:
        return self._rev

    def _compute_rev(self) -> str:
        m = hashlib.sha256()
        for p in sorted(self._policies, key=lambda p: (p.id, str(p.version))):
            m.update(p.id.encode())
            m.update(str(p.version).encode())
            m.update(p.algo.value.encode())
            m.update((p.target or "").encode())
            for r in p.rules:
                m.update(r.id.encode())
                m.update(r.effect.value.encode())
                m.update((r.condition or "").encode())
        return m.hexdigest()


# ---------------------------- TTL LRU Cache ----------------------------

class _TTLCache:
    def __init__(self, maxsize: int, ttl_seconds: int):
        self._data: Dict[str, Tuple[float, Any]] = {}
        self._order: List[str] = []
        self._maxsize = maxsize
        self._ttl = ttl_seconds
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            expires, value = item
            if expires < _now_utc_ts():
                self._delete_unlocked(key)
                return None
            # refresh LRU
            if key in self._order:
                self._order.remove(key)
            self._order.append(key)
            return value

    async def set(self, key: str, value: Any) -> None:
        async with self._lock:
            now = _now_utc_ts()
            self._data[key] = (now + self._ttl, value)
            if key in self._order:
                self._order.remove(key)
            self._order.append(key)
            await self._evict_unlocked()

    async def _evict_unlocked(self) -> None:
        while len(self._order) > self._maxsize:
            oldest = self._order.pop(0)
            self._data.pop(oldest, None)

    def _delete_unlocked(self, key: str) -> None:
        self._data.pop(key, None)
        try:
            self._order.remove(key)
        except ValueError:
            pass


# ---------------------------- Configuration ----------------------------

@dataclass
class DecisionEngineConfig:
    cache_ttl_seconds: int = 60
    cache_max_entries: int = 10_000
    fail_closed: bool = True
    log_decisions: bool = True
    metrics_enabled: bool = True
    enable_signature: bool = False
    hmac_secret: Optional[bytes] = None
    default_algo: CombiningAlgo = CombiningAlgo.DENY_OVERRIDES
    # pre-compile policies on load for performance
    precompile: bool = True


# ---------------------------- Metrics (lightweight) ----------------------------

@dataclass
class _Metrics:
    total_requests: int = 0
    total_cached_hits: int = 0
    total_permits: int = 0
    total_denies: int = 0
    total_indeterminate: int = 0
    total_not_applicable: int = 0


# ---------------------------- Decision Engine ----------------------------

class DecisionEngine:
    def __init__(
        self,
        store: PolicyStore,
        config: Optional[DecisionEngineConfig] = None,
        functions: Optional[Mapping[str, Callable[..., Any]]] = None,
    ):
        self.store = store
        self.cfg = config or DecisionEngineConfig()
        self.functions = dict(BUILTIN_FN)
        if functions:
            self.functions.update(functions)
        self._safe = SafeExpr(functions=self.functions)
        self._cache = _TTLCache(self.cfg.cache_max_entries, self.cfg.cache_ttl_seconds)
        self._metrics = _Metrics()
        self._compile_lock = asyncio.Lock()

    # ------------------------ Public API ------------------------

    async def load_and_precompile(self) -> None:
        """
        Loads policies and precompiles targets/conditions for performance.
        """
        if not self.cfg.precompile:
            return
        async with self._compile_lock:
            policies = await self.store.get_policies()
            for p in policies:
                if p.target and p._target_compiled is None:
                    p._target_compiled = self._safe.compile(p.target)
                for r in p.rules:
                    if r.condition and r._compiled is None:
                        r._compiled = self._safe.compile(r.condition)

    async def evaluate(self, request: DecisionRequest) -> DecisionResponse:
        start = _now_utc_ts()
        req_id = request_id_ctx.set(str(uuid.uuid4()))
        span_id_ctx.set(str(uuid.uuid4()))
        try:
            # Build a stable cache key
            rev = await self.store.revision()
            cache_key = self._cache_key(rev, request)
            cached = await self._cache.get(cache_key)
            if cached is not None:
                self._metrics.total_cached_hits += 1
                resp: DecisionResponse = cached
                # Re-stamp timestamp/latency but keep decision_id/signature
                resp = dataclasses.replace(resp, timestamp=_now_utc_iso(), latency_ms=( _now_utc_ts() - start) * 1000.0)
                if self.cfg.log_decisions:
                    self._log_decision(request, resp, cached_hit=True)
                return resp

            # Ensure compiled ASTs exist when enabled
            if self.cfg.precompile:
                await self.load_and_precompile()

            # Prepare context
            ctx = self._make_context(request)

            # Evaluate policies
            policies = await self.store.get_policies()
            final = self._evaluate_policies(ctx, policies)

            latency_ms = (_now_utc_ts() - start) * 1000.0
            final.latency_ms = latency_ms

            # Optionally sign decision
            if self.cfg.enable_signature and self.cfg.hmac_secret:
                final.signature = self._sign(final)

            # Record metrics
            self._metrics.total_requests += 1
            if final.decision is DecisionType.PERMIT:
                self._metrics.total_permits += 1
            elif final.decision is DecisionType.DENY:
                self._metrics.total_denies += 1
            elif final.decision is DecisionType.NOT_APPLICABLE:
                self._metrics.total_not_applicable += 1
            else:
                self._metrics.total_indeterminate += 1

            # Cache
            await self._cache.set(cache_key, final)

            if self.cfg.log_decisions:
                self._log_decision(request, final)

            return final
        finally:
            request_id_ctx.reset(req_id)

    def metrics_snapshot(self) -> Mapping[str, Any]:
        m = self._metrics
        return {
            "total_requests": m.total_requests,
            "cache_hits": m.total_cached_hits,
            "permits": m.total_permits,
            "denies": m.total_denies,
            "indeterminate": m.total_indeterminate,
            "not_applicable": m.total_not_applicable,
        }

    # ------------------------ Internals ------------------------

    def _make_context(self, request: DecisionRequest) -> Mapping[str, Any]:
        subject = _wrap(dict(request.subject))
        resource = _wrap(dict(request.resource))
        env = _wrap(dict(request.env))
        action = request.action
        # enrich env
        if "now_ts" not in env:
            env = AttrDict({**env, "now_ts": _now_utc_ts(), "now_iso": _now_utc_iso()})
        ctx = {
            "subject": subject,
            "resource": resource,
            "env": env,
            "action": action,
            "fn": _FunctionNamespace(self.functions),  # for runtime safety; not used directly in AST
        }
        return ctx

    def _evaluate_policies(self, ctx: Mapping[str, Any], policies: Sequence[Policy]) -> DecisionResponse:
        matched: List[Tuple[Policy, DecisionResponse]] = []
        indeterminate_errors: List[str] = []

        for p in policies:
            try:
                if not self._match_target(p, ctx):
                    continue
                resp = self._evaluate_policy(p, ctx)
                if resp.decision != DecisionType.NOT_APPLICABLE:
                    matched.append((p, resp))
            except Exception as e:
                err = f"policy:{p.id} error:{e}"
                indeterminate_errors.append(err)
                logger.exception("Policy evaluation error: %s", err)

        if not matched and not indeterminate_errors:
            return DecisionResponse(decision=DecisionType.NOT_APPLICABLE, reason="no_policy_matched")

        # Combine across policies by policy priority ordering using DENY_OVERRIDES as outer default
        combined = self._combine_multi(matched, CombiningAlgo.DENY_OVERRIDES)
        if combined.decision is DecisionType.INDETERMINATE and self.cfg.fail_closed:
            combined = dataclasses.replace(combined, decision=DecisionType.DENY, reason="fail_closed:indeterminate")
        if indeterminate_errors and combined.reason is None:
            combined.reason = ";".join(indeterminate_errors)
        return combined

    def _match_target(self, policy: Policy, ctx: Mapping[str, Any]) -> bool:
        if not policy.target:
            return True
        compiled = policy._target_compiled or self._safe.compile(policy.target)
        return bool(self._safe.eval(compiled, ctx))

    def _evaluate_policy(self, policy: Policy, ctx: Mapping[str, Any]) -> DecisionResponse:
        algo = policy.algo or self.cfg.default_algo
        decisions: List[Tuple[Rule, DecisionResponse]] = []
        for r in policy.rules:
            try:
                applies = True
                if r.condition:
                    compiled = r._compiled or self._safe.compile(r.condition)
                    applies = bool(self._safe.eval(compiled, ctx))
                if not applies:
                    continue
                dr = DecisionResponse(
                    decision=DecisionType.PERMIT if r.effect is Effect.PERMIT else DecisionType.DENY,
                    obligations=list(r.obligations),
                    advice=list(r.advice),
                    policy_id=policy.id,
                    matched_rules=[r.id],
                )
                decisions.append((r, dr))
            except Exception as e:
                # rule error -> INDETERMINATE for the policy
                reason = f"rule_error:{policy.id}:{r.id}:{e}"
                logger.exception("Rule evaluation error: %s", reason)
                ind = DecisionResponse(
                    decision=DecisionType.INDETERMINATE,
                    obligations=[],
                    advice=[],
                    policy_id=policy.id,
                    matched_rules=[r.id],
                    reason=reason,
                )
                decisions.append((r, ind))

        if not decisions:
            return DecisionResponse(decision=DecisionType.NOT_APPLICABLE, policy_id=policy.id)

        result = self._combine_rules(policy.id, decisions, algo)
        return result

    # ------------------------ Combining algorithms ------------------------

    def _combine_rules(
        self,
        policy_id: str,
        rules_and_decisions: Sequence[Tuple[Rule, DecisionResponse]],
        algo: CombiningAlgo,
    ) -> DecisionResponse:
        if algo is CombiningAlgo.FIRST_APPLICABLE:
            for r, d in rules_and_decisions:
                if d.decision in (DecisionType.PERMIT, DecisionType.DENY, DecisionType.INDETERMINATE):
                    return d
            return DecisionResponse(decision=DecisionType.NOT_APPLICABLE, policy_id=policy_id)

        deny_seen: Optional[DecisionResponse] = None
        permit_seen: Optional[DecisionResponse] = None
        indet_seen: Optional[DecisionResponse] = None
        obligations: List[Obligation] = []
        advice: List[Advice] = []
        matched_rules: List[str] = []

        ordered = rules_and_decisions if algo is CombiningAlgo.ORDERED_DENY_OVERRIDES else rules_and_decisions

        for r, d in ordered:
            matched_rules.extend(d.matched_rules)
            obligations.extend(d.obligations)
            advice.extend(d.advice)
            if d.decision is DecisionType.DENY:
                deny_seen = d if not deny_seen else deny_seen
                if algo in (CombiningAlgo.DENY_OVERRIDES, CombiningAlgo.ORDERED_DENY_OVERRIDES):
                    return dataclasses.replace(d, obligations=obligations, advice=advice, matched_rules=matched_rules)
            elif d.decision is DecisionType.PERMIT:
                permit_seen = d if not permit_seen else permit_seen
                if algo is CombiningAlgo.PERMIT_OVERRIDES:
                    return dataclasses.replace(d, obligations=obligations, advice=advice, matched_rules=matched_rules)
            elif d.decision is DecisionType.INDETERMINATE:
                indet_seen = d if not indet_seen else indet_seen

        if algo in (CombiningAlgo.DENY_OVERRIDES, CombiningAlgo.ORDERED_DENY_OVERRIDES):
            if deny_seen:
                return dataclasses.replace(deny_seen, obligations=obligations, advice=advice, matched_rules=matched_rules)
            if permit_seen:
                return dataclasses.replace(permit_seen, obligations=obligations, advice=advice, matched_rules=matched_rules)
        elif algo is CombiningAlgo.PERMIT_OVERRIDES:
            if permit_seen:
                return dataclasses.replace(permit_seen, obligations=obligations, advice=advice, matched_rules=matched_rules)
            if deny_seen:
                return dataclasses.replace(deny_seen, obligations=obligations, advice=advice, matched_rules=matched_rules)

        if indet_seen:
            return dataclasses.replace(indet_seen, obligations=obligations, advice=advice, matched_rules=matched_rules)

        return DecisionResponse(decision=DecisionType.NOT_APPLICABLE, policy_id=policy_id)

    def _combine_multi(
        self,
        policy_decisions: Sequence[Tuple[Policy, DecisionResponse]],
        outer_algo: CombiningAlgo,
    ) -> DecisionResponse:
        # For now, apply the same combining logic across policies (already ordered by priority)
        deny_seen: Optional[DecisionResponse] = None
        permit_seen: Optional[DecisionResponse] = None
        indet_seen: Optional[DecisionResponse] = None
        obligations: List[Obligation] = []
        advice: List[Advice] = []
        matched_rules: List[str] = []
        policy_id: Optional[str] = None

        for p, d in policy_decisions:
            policy_id = p.id  # last matched policy id (highest priority first)
            matched_rules.extend(d.matched_rules)
            obligations.extend(d.obligations)
            advice.extend(d.advice)
            if d.decision is DecisionType.DENY:
                deny_seen = d if not deny_seen else deny_seen
                if outer_algo in (CombiningAlgo.DENY_OVERRIDES, CombiningAlgo.ORDERED_DENY_OVERRIDES):
                    return dataclasses.replace(d, obligations=obligations, advice=advice, matched_rules=matched_rules)
            elif d.decision is DecisionType.PERMIT:
                permit_seen = d if not permit_seen else permit_seen
                if outer_algo is CombiningAlgo.PERMIT_OVERRIDES:
                    return dataclasses.replace(d, obligations=obligations, advice=advice, matched_rules=matched_rules)
            elif d.decision is DecisionType.INDETERMINATE:
                indet_seen = d if not indet_seen else indet_seen

        if outer_algo in (CombiningAlgo.DENY_OVERRIDES, CombiningAlgo.ORDERED_DENY_OVERRIDES):
            if deny_seen:
                return dataclasses.replace(deny_seen, obligations=obligations, advice=advice, matched_rules=matched_rules)
            if permit_seen:
                return dataclasses.replace(permit_seen, obligations=obligations, advice=advice, matched_rules=matched_rules)
        elif outer_algo is CombiningAlgo.PERMIT_OVERRIDES:
            if permit_seen:
                return dataclasses.replace(permit_seen, obligations=obligations, advice=advice, matched_rules=matched_rules)
            if deny_seen:
                return dataclasses.replace(deny_seen, obligations=obligations, advice=advice, matched_rules=matched_rules)

        if indet_seen:
            return dataclasses.replace(indet_seen, obligations=obligations, advice=advice, matched_rules=matched_rules)

        return DecisionResponse(decision=DecisionType.NOT_APPLICABLE, policy_id=policy_id)

    # ------------------------ Signing ------------------------

    def _sign(self, resp: DecisionResponse) -> str:
        body = json.dumps(resp.to_dict(include_signature=False), sort_keys=True, separators=(",", ":")).encode()
        mac = hmac.new(self.cfg.hmac_secret, body, hashlib.sha256).hexdigest()
        return mac

    # ------------------------ Helpers ------------------------

    def _cache_key(self, rev: str, req: DecisionRequest) -> str:
        h = hashlib.sha256()
        h.update(rev.encode())
        # Order fields stably for hash
        payload = {
            "subject": _stable(req.subject),
            "resource": _stable(req.resource),
            "action": req.action,
            "env": _stable(req.env),
        }
        h.update(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
        return h.hexdigest()

    def _log_decision(self, req: DecisionRequest, resp: DecisionResponse, cached_hit: bool = False) -> None:
        record = {
            "event": "pdp_decision",
            "request_id": request_id_ctx.get(),
            "span_id": span_id_ctx.get(),
            "cached": cached_hit,
            "subject": _redact(req.subject),
            "resource": _redact(req.resource),
            "action": req.action,
            "env": _redact(req.env),
            "decision": resp.to_dict(),
        }
        logger.info(json.dumps(record, ensure_ascii=False))


# ---------------------------- Builders / Parsing ----------------------------

def parse_policy(doc: Mapping[str, Any]) -> Policy:
    """
    Convert JSON-like dict into Policy dataclass, compiling conditions if needed.
    """
    try:
        algo = CombiningAlgo(doc.get("algo", CombiningAlgo.DENY_OVERRIDES.value))
    except ValueError:
        raise ValueError(f"unknown combining algo: {doc.get('algo')}")

    rules_doc = doc.get("rules", [])
    rules: List[Rule] = []
    for rd in rules_doc:
        try:
            eff = Effect(rd["effect"])
        except Exception:
            raise ValueError(f"invalid effect in rule:{rd.get('id')}")
        obligations = [Obligation(id=o.get("id", "obligation"), attributes=o.get("attributes", {})) for o in rd.get("obligations", [])]
        advice = [Advice(id=a.get("id", "advice"), attributes=a.get("attributes", {})) for a in rd.get("advice", [])]
        rules.append(Rule(
            id=str(rd["id"]),
            effect=eff,
            condition=rd.get("condition"),
            obligations=tuple(obligations),
            advice=tuple(advice),
        ))

    p = Policy(
        id=str(doc["id"]),
        version=doc.get("version", 1),
        algo=algo,
        target=doc.get("target"),
        rules=tuple(rules),
        priority=int(doc.get("priority", 0)),
        metadata=doc.get("metadata", {}),
    )
    return p


def build_store_from_docs(policy_docs: Sequence[Mapping[str, Any]]) -> InMemoryPolicyStore:
    policies = [parse_policy(d) for d in policy_docs]
    return InMemoryPolicyStore(policies)


# ---------------------------- Serialization Helpers ----------------------------

def _stable(obj: Any) -> Any:
    """
    Convert to a JSON-stable structure (sort keys, convert non-serializable types).
    """
    if isinstance(obj, Mapping):
        return {k: _stable(v) for k, v in sorted(obj.items(), key=lambda x: x[0])}
    if isinstance(obj, (list, tuple)):
        return [_stable(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    # Fallback to string representation
    return str(obj)


def _redact(obj: Any, redact_keys: Tuple[str, ...] = ("password", "secret", "token", "authorization", "cookie")) -> Any:
    if isinstance(obj, Mapping):
        out = {}
        for k, v in obj.items():
            if str(k).lower() in redact_keys:
                out[k] = "***"
            else:
                out[k] = _redact(v, redact_keys)
        return out
    if isinstance(obj, list):
        return [_redact(x, redact_keys) for x in obj]
    return obj


# ---------------------------- Example of Attribute Resolver (interface) ----------------------------

class AttributeResolver:
    """
    Interface for external attribute resolution (e.g., fetch roles/claims).
    Implementations can be injected into the request pre-processing pipeline.
    """
    async def resolve(self, subject: Mapping[str, Any], resource: Mapping[str, Any], env: Mapping[str, Any]) -> Tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]:
        return subject, resource, env


# ---------------------------- End of file ----------------------------
