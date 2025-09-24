# path: datafabric/governance/abac.py
"""
Industrial ABAC engine for DataFabric:
- Policy grammar (PolicySet -> Policy -> Rule -> Condition)
- PDP (decision), PEP (enforcement helpers), PIP (attribute resolvers)
- Effects: PERMIT/DENY/NOT_APPLICABLE/INDETERMINATE
- Combining algorithms: deny-overrides, permit-overrides, first-applicable
- Safe operator library (no eval), regex with size guard
- Decision caching with versioned invalidation
- In-memory and file-based policy stores (JSON/YAML) with reload
- Audit trace and obligations/advice propagation
- Sync + Async APIs, thread/process safe (RLock)
"""

from __future__ import annotations

import dataclasses
import functools
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

try:
    import yaml  # optional
except Exception:  # pragma: no cover
    yaml = None  # type: ignore

__all__ = [
    "Effect",
    "Decision",
    "AttributeContext",
    "Condition",
    "Rule",
    "Policy",
    "PolicySet",
    "CombiningAlg",
    "Obligation",
    "Advice",
    "PIP",
    "PolicyStore",
    "InMemoryPolicyStore",
    "FilePolicyStore",
    "PDP",
    "pep_enforce",
]

logger = logging.getLogger("datafabric.abac")
logger.addHandler(logging.NullHandler())

# -------- Core types

class Effect(str, Enum):
    PERMIT = "Permit"
    DENY = "Deny"
    NOT_APPLICABLE = "NotApplicable"
    INDETERMINATE = "Indeterminate"

class CombiningAlg(str, Enum):
    DENY_OVERRIDES = "deny-overrides"
    PERMIT_OVERRIDES = "permit-overrides"
    FIRST_APPLICABLE = "first-applicable"

@dataclass(frozen=True)
class Obligation:
    id: str
    attributes: Mapping[str, Any] = dataclasses.field(default_factory=dict)

@dataclass(frozen=True)
class Advice:
    id: str
    attributes: Mapping[str, Any] = dataclasses.field(default_factory=dict)

@dataclass
class Decision:
    effect: Effect
    obligations: List[Obligation] = field(default_factory=list)
    advice: List[Advice] = field(default_factory=list)
    trace: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)

    def explain(self) -> str:
        lines = [f"Decision: {self.effect}"]
        if self.reasons:
            lines.append("Reasons:")
            lines.extend(f"  - {r}" for r in self.reasons)
        if self.trace:
            lines.append("Trace:")
            lines.extend(f"  - {t}" for t in self.trace)
        if self.obligations:
            lines.append("Obligations:")
            lines.extend(f"  - {o.id}: {dict(o.attributes)}" for o in self.obligations)
        if self.advice:
            lines.append("Advice:")
            lines.extend(f"  - {a.id}: {dict(a.attributes)}" for a in self.advice)
        return "\n".join(lines)

# -------- Attribute context & resolvers (PIP)

@dataclass
class AttributeContext:
    subject: Mapping[str, Any]
    resource: Mapping[str, Any]
    action: Mapping[str, Any]
    environment: Mapping[str, Any] = field(default_factory=dict)

    def get(self, path: str, default: Any = None) -> Any:
        """
        Resolve dotted path like 'subject.role' or 'resource.owner.id'.
        Supports '[index]' for lists and dict-style '["key"]'.
        """
        root_map = {
            "subject": self.subject,
            "resource": self.resource,
            "action": self.action,
            "environment": self.environment,
        }
        if not path:
            return default
        parts = _split_path(path)
        if parts[0] not in root_map:
            return default
        cur: Any = root_map[parts[0]]
        for p in parts[1:]:
            try:
                if isinstance(cur, Mapping) and p in cur:
                    cur = cur[p]  # type: ignore
                elif isinstance(cur, Sequence) and isinstance(p, int) and 0 <= p < len(cur):  # type: ignore
                    cur = cur[p]  # type: ignore
                else:
                    return default
            except Exception:
                return default
        return cur

def _split_path(path: str) -> List[Union[str, int]]:
    # Minimal, safe parser for dotted paths with [index] and ["key"] tokens.
    out: List[Union[str, int]] = []
    token = ""
    i = 0
    while i < len(path):
        c = path[i]
        if c == ".":
            if token:
                out.append(token)
                token = ""
            i += 1
        elif c == "[":
            if token:
                out.append(token)
                token = ""
            j = path.find("]", i + 1)
            if j == -1:
                raise ValueError(f"Unclosed bracket in path: {path}")
            body = path[i + 1 : j].strip()
            if body.startswith('"') and body.endswith('"'):
                out.append(body[1:-1])
            else:
                try:
                    out.append(int(body))
                except Exception as e:
                    raise ValueError(f"Invalid index/key {body} in path {path}") from e
            i = j + 1
        else:
            token += c
            i += 1
    if token:
        out.append(token)
    # Normalize to strings/ints
    out2: List[Union[str, int]] = []
    for v in out:
        if isinstance(v, str):
            out2.append(v.strip())
        else:
            out2.append(v)
    return out2

class PIP:
    """
    Pluggable attribute resolvers. Each resolver is a callable:
        resolver(context: AttributeContext, missing_keys: Sequence[str]) -> Dict[str, Any]
    Register resolvers to dynamically enrich 'environment' and others.
    """

    def __init__(self):
        self._resolvers: List[Callable[[AttributeContext, Sequence[str]], Mapping[str, Any]]] = []

    def register(self, resolver: Callable[[AttributeContext, Sequence[str]], Mapping[str, Any]]) -> None:
        self._resolvers.append(resolver)

    def resolve(self, ctx: AttributeContext, missing: Sequence[str]) -> Dict[str, Any]:
        aggregated: Dict[str, Any] = {}
        for r in self._resolvers:
            try:
                data = dict(r(ctx, missing))
                aggregated.update(data)
            except Exception as e:
                logger.warning("PIP resolver failed: %s", e)
        return aggregated

# -------- Operators (safe)

_MAX_REGEX_LEN = 512

def _safe_regex(pattern: str) -> re.Pattern:
    if len(pattern) > _MAX_REGEX_LEN:
        raise ValueError("Regex pattern too long")
    return re.compile(pattern)

OperatorFn = Callable[[Any, Any], bool]

class Ops:
    @staticmethod
    def eq(a: Any, b: Any) -> bool:
        return a == b

    @staticmethod
    def ne(a: Any, b: Any) -> bool:
        return a != b

    @staticmethod
    def lt(a: Any, b: Any) -> bool:
        try:
            return a < b  # type: ignore
        except Exception:
            return False

    @staticmethod
    def lte(a: Any, b: Any) -> bool:
        try:
            return a <= b  # type: ignore
        except Exception:
            return False

    @staticmethod
    def gt(a: Any, b: Any) -> bool:
        try:
            return a > b  # type: ignore
        except Exception:
            return False

    @staticmethod
    def gte(a: Any, b: Any) -> bool:
        try:
            return a >= b  # type: ignore
        except Exception:
            return False

    @staticmethod
    def isin(a: Any, b: Any) -> bool:
        try:
            return a in b  # type: ignore
        except Exception:
            return False

    @staticmethod
    def contains(a: Any, b: Any) -> bool:
        try:
            return b in a  # type: ignore
        except Exception:
            return False

    @staticmethod
    def startswith(a: Any, b: Any) -> bool:
        return isinstance(a, str) and isinstance(b, str) and a.startswith(b)

    @staticmethod
    def endswith(a: Any, b: Any) -> bool:
        return isinstance(a, str) and isinstance(b, str) and a.endswith(b)

    @staticmethod
    def matches(a: Any, b: Any) -> bool:
        if not isinstance(a, str) or not isinstance(b, str):
            return False
        return bool(_safe_regex(b).search(a))

    @staticmethod
    def subset(a: Any, b: Any) -> bool:
        try:
            return set(a).issubset(set(b))  # type: ignore
        except Exception:
            return False

    @staticmethod
    def superset(a: Any, b: Any) -> bool:
        try:
            return set(a).issuperset(set(b))  # type: ignore
        except Exception:
            return False

OPERATORS: Dict[str, OperatorFn] = {
    "eq": Ops.eq, "ne": Ops.ne,
    "lt": Ops.lt, "lte": Ops.lte, "gt": Ops.gt, "gte": Ops.gte,
    "in": Ops.isin, "contains": Ops.contains,
    "startswith": Ops.startswith, "endswith": Ops.endswith,
    "matches": Ops.matches,
    "subset": Ops.subset, "superset": Ops.superset,
}

# -------- Conditions

@dataclass(frozen=True)
class Operand:
    # Either a literal value or an attribute path (starts with subject/resource/action/environment)
    is_attr: bool
    value: Any

    @staticmethod
    def attr(path: str) -> "Operand":
        return Operand(True, path)

    @staticmethod
    def lit(value: Any) -> "Operand":
        return Operand(False, value)

@dataclass(frozen=True)
class Predicate:
    operator: str
    left: Operand
    right: Operand

@dataclass(frozen=True)
class BooleanExpr:
    # Either a predicate, or a boolean combinator over expressions
    predicate: Optional[Predicate] = None
    all_of: Optional[Sequence["BooleanExpr"]] = None
    any_of: Optional[Sequence["BooleanExpr"]] = None
    not_expr: Optional["BooleanExpr"] = None

    def is_leaf(self) -> bool:
        return self.predicate is not None

Condition = BooleanExpr  # alias

# -------- Policy structure

@dataclass(frozen=True)
class Rule:
    id: str
    effect: Effect
    condition: Optional[Condition] = None
    obligations: Sequence[Obligation] = dataclasses.field(default_factory=tuple)
    advice: Sequence[Advice] = dataclasses.field(default_factory=tuple)
    description: Optional[str] = None

@dataclass(frozen=True)
class Policy:
    id: str
    target: Optional[Condition] = None
    rules: Sequence[Rule] = dataclasses.field(default_factory=tuple)
    algorithm: CombiningAlg = CombiningAlg.DENY_OVERRIDES
    obligations: Sequence[Obligation] = dataclasses.field(default_factory=tuple)
    advice: Sequence[Advice] = dataclasses.field(default_factory=tuple)
    description: Optional[str] = None

@dataclass(frozen=True)
class PolicySet:
    id: str
    policies: Sequence[Union["Policy", "PolicySet"]] = dataclasses.field(default_factory=tuple)
    target: Optional[Condition] = None
    algorithm: CombiningAlg = CombiningAlg.DENY_OVERRIDES
    obligations: Sequence[Obligation] = dataclasses.field(default_factory=tuple)
    advice: Sequence[Advice] = dataclasses.field(default_factory=tuple)
    version: str = "1"  # used for cache invalidation
    description: Optional[str] = None

# -------- Evaluation

@dataclass
class EvalConfig:
    short_circuit: bool = True
    redact_values_in_trace: bool = True
    decision_cache_ttl_sec: int = 30
    max_trace_depth: int = 2048

class PDP:
    def __init__(self, store: "PolicyStore", pip: Optional[PIP] = None, config: Optional[EvalConfig] = None):
        self._store = store
        self._pip = pip or PIP()
        self._cfg = config or EvalConfig()
        self._cache: MutableMapping[Tuple[str, str], Tuple[float, Decision, str]] = {}
        self._lock = threading.RLock()

    # ---- Public APIs

    def decide(self, ctx: AttributeContext) -> Decision:
        cache_key = self._cache_key(ctx)
        now = time.time()
        with self._lock:
            cached = self._cache.get(cache_key)
            if cached:
                ts, decision, v = cached
                if now - ts <= self._cfg.decision_cache_ttl_sec and v == self._store.version():
                    return _clone_decision(decision)

        ps = self._store.load()
        decision = self._eval_policyset(ps, ctx, [], 0)
        with self._lock:
            self._cache[cache_key] = (now, decision, self._store.version())
        return _clone_decision(decision)

    async def decide_async(self, ctx: AttributeContext) -> Decision:
        # lightweight: reuse sync path (I/O minimal). If store is file-based, it does local reads.
        return self.decide(ctx)

    # ---- Internals

    def _cache_key(self, ctx: AttributeContext) -> Tuple[str, str]:
        # Coarse cache key: action, subject roles/id, resource type/id
        subj = f"{ctx.subject.get('id')}|{ctx.subject.get('role')}"
        res = f"{ctx.resource.get('type')}|{ctx.resource.get('id')}"
        act = f"{ctx.action.get('name')}"
        env = str(ctx.environment.get("tenant") or "")
        # Include policy version to keep cache coherent on change
        return (f"{act}|{subj}|{res}|{env}", self._store.version())

    def _eval_policyset(self, pset: PolicySet, ctx: AttributeContext, trace: List[str], depth: int) -> Decision:
        if depth > self._cfg.max_trace_depth:
            return Decision(Effect.INDETERMINATE, reasons=["Max trace depth reached"])

        if pset.target and not self._eval_condition(pset.target, ctx, trace, depth + 1):
            return Decision(Effect.NOT_APPLICABLE, trace=trace + [f"PolicySet {pset.id} target: no match"])

        effects: List[Decision] = []
        for p in pset.policies:
            if isinstance(p, PolicySet):
                d = self._eval_policyset(p, ctx, trace + [f"Enter PolicySet {p.id}"], depth + 1)
            else:
                d = self._eval_policy(p, ctx, trace + [f"Enter Policy {p.id}"], depth + 1)
            effects.append(d)
            if self._cfg.short_circuit:
                if pset.algorithm == CombiningAlg.DENY_OVERRIDES and d.effect == Effect.DENY:
                    return _merge_with_container(d, pset)
                if pset.algorithm == CombiningAlg.PERMIT_OVERRIDES and d.effect == Effect.PERMIT:
                    return _merge_with_container(d, pset)
                if pset.algorithm == CombiningAlg.FIRST_APPLICABLE and d.effect in (Effect.PERMIT, Effect.DENY):
                    return _merge_with_container(d, pset)

        final = _combine(effects, pset.algorithm)
        return _merge_with_container(final, pset)

    def _eval_policy(self, pol: Policy, ctx: AttributeContext, trace: List[str], depth: int) -> Decision:
        if pol.target and not self._eval_condition(pol.target, ctx, trace, depth + 1):
            return Decision(Effect.NOT_APPLICABLE, trace=trace + [f"Policy {pol.id} target: no match"])

        decisions: List[Decision] = []
        for r in pol.rules:
            d = self._eval_rule(r, ctx, trace + [f"Rule {r.id}"], depth + 1)
            decisions.append(d)
            if self._cfg.short_circuit:
                if pol.algorithm == CombiningAlg.DENY_OVERRIDES and d.effect == Effect.DENY:
                    return _merge_with_container(d, pol)
                if pol.algorithm == CombiningAlg.PERMIT_OVERRIDES and d.effect == Effect.PERMIT:
                    return _merge_with_container(d, pol)
                if pol.algorithm == CombiningAlg.FIRST_APPLICABLE and d.effect in (Effect.PERMIT, Effect.DENY):
                    return _merge_with_container(d, pol)

        final = _combine(decisions, pol.algorithm)
        return _merge_with_container(final, pol)

    def _eval_rule(self, rule: Rule, ctx: AttributeContext, trace: List[str], depth: int) -> Decision:
        try:
            if rule.condition is None or self._eval_condition(rule.condition, ctx, trace, depth + 1):
                return Decision(rule.effect, obligations=list(rule.obligations), advice=list(rule.advice),
                                trace=trace + [f"Rule {rule.id} -> {rule.effect}"])
            return Decision(Effect.NOT_APPLICABLE, trace=trace + [f"Rule {rule.id} -> NotApplicable"])
        except Exception as e:
            return Decision(Effect.INDETERMINATE, reasons=[f"Rule {rule.id} error: {e}"], trace=trace)

    def _eval_condition(self, cond: Condition, ctx: AttributeContext, trace: List[str], depth: int) -> bool:
        if cond.predicate:
            pred = cond.predicate
            op = OPERATORS.get(pred.operator)
            if not op:
                return False
            left = self._resolve_operand(pred.left, ctx)
            right = self._resolve_operand(pred.right, ctx)
            ok = op(left, right)
            if self._cfg.redact_values_in_trace:
                trace.append(f"Predicate {pred.operator}({('attr' if pred.left.is_attr else 'lit')}, {('attr' if pred.right.is_attr else 'lit')}) -> {ok}")
            else:
                trace.append(f"Predicate {pred.operator}({left!r}, {right!r}) -> {ok}")
            return ok

        if cond.all_of is not None:
            for c in cond.all_of:
                if not self._eval_condition(c, ctx, trace, depth + 1):
                    trace.append("all_of -> False")
                    return False
            trace.append("all_of -> True")
            return True

        if cond.any_of is not None:
            for c in cond.any_of:
                if self._eval_condition(c, ctx, trace, depth + 1):
                    trace.append("any_of -> True")
                    return True
            trace.append("any_of -> False")
            return False

        if cond.not_expr is not None:
            val = self._eval_condition(cond.not_expr, ctx, trace, depth + 1)
            trace.append(f"not -> {not val}")
            return not val

        return True  # empty condition matches

    def _resolve_operand(self, op: Operand, ctx: AttributeContext) -> Any:
        if not op.is_attr:
            return op.value
        return ctx.get(str(op.value), None)

# -------- Combining helpers

def _combine(decisions: Sequence[Decision], alg: CombiningAlg) -> Decision:
    if not decisions:
        return Decision(Effect.NOT_APPLICABLE)

    if alg == CombiningAlg.DENY_OVERRIDES:
        deny = next((d for d in decisions if d.effect == Effect.DENY), None)
        if deny:
            return deny
        permit = next((d for d in decisions if d.effect == Effect.PERMIT), None)
        if permit:
            return permit
        ind = next((d for d in decisions if d.effect == Effect.INDETERMINATE), None)
        return ind or Decision(Effect.NOT_APPLICABLE)

    if alg == CombiningAlg.PERMIT_OVERRIDES:
        permit = next((d for d in decisions if d.effect == Effect.PERMIT), None)
        if permit:
            return permit
        deny = next((d for d in decisions if d.effect == Effect.DENY), None)
        if deny:
            return deny
        ind = next((d for d in decisions if d.effect == Effect.INDETERMINATE), None)
        return ind or Decision(Effect.NOT_APPLICABLE)

    # FIRST_APPLICABLE
    for d in decisions:
        if d.effect in (Effect.PERMIT, Effect.DENY):
            return d
    ind = next((d for d in decisions if d.effect == Effect.INDETERMINATE), None)
    return ind or Decision(Effect.NOT_APPLICABLE)

def _merge_with_container(dec: Decision, container: Union[Policy, PolicySet]) -> Decision:
    obligations = list(dec.obligations)
    advice = list(dec.advice)
    obligations.extend(getattr(container, "obligations", []) or [])
    advice.extend(getattr(container, "advice", []) or [])
    trace = list(dec.trace) + [f"container:{getattr(container, 'id', '?')} obligations={len(obligations)} advice={len(advice)}"]
    return Decision(dec.effect, obligations=obligations, advice=advice, trace=trace, reasons=list(dec.reasons))

def _clone_decision(d: Decision) -> Decision:
    return Decision(d.effect, obligations=list(d.obligations), advice=list(d.advice), trace=list(d.trace), reasons=list(d.reasons))

# -------- Policy stores

class PolicyStore:
    def load(self) -> PolicySet:
        raise NotImplementedError

    def version(self) -> str:
        raise NotImplementedError

class InMemoryPolicyStore(PolicyStore):
    def __init__(self, policyset: PolicySet):
        self._ps = policyset
        self._ver = policyset.version

    def load(self) -> PolicySet:
        return self._ps

    def version(self) -> str:
        return self._ver

    def replace(self, new_ps: PolicySet) -> None:
        self._ps = new_ps
        self._ver = new_ps.version

class FilePolicyStore(PolicyStore):
    """
    Directory-based store:
      - Loads a single PolicySet from JSON/YAML file.
      - Watches mtime to bump version automatically.
    """
    def __init__(self, file_path: Union[str, Path]):
        self._path = Path(file_path)
        self._lock = threading.RLock()
        self._cached: Optional[PolicySet] = None
        self._mtime: float = 0.0
        self._version: str = "0"

    def load(self) -> PolicySet:
        with self._lock:
            stat = self._path.stat()
            if not self._cached or stat.st_mtime != self._mtime:
                self._cached = _parse_policyset(self._path)
                self._mtime = stat.st_mtime
                self._version = f"{int(self._mtime)}"
            return self._cached

    def version(self) -> str:
        with self._lock:
            return self._version

def _parse_policyset(path: Path) -> PolicySet:
    data = _load_structured(path)
    try:
        return _policyset_from_dict(data)
    except Exception as e:
        raise ValueError(f"Invalid policy file {path}: {e}") from e

def _load_structured(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        if yaml is None:
            raise RuntimeError("PyYAML not available")
        return yaml.safe_load(text)
    return json.loads(text)

# -------- Parsing from dict

def _operand_from(x: Any) -> Operand:
    if isinstance(x, dict) and "attr" in x:
        return Operand.attr(str(x["attr"]))
    return Operand.lit(x)

def _predicate_from(d: Mapping[str, Any]) -> Predicate:
    return Predicate(
        operator=str(d["operator"]),
        left=_operand_from(d["left"]),
        right=_operand_from(d["right"]),
    )

def _condition_from(d: Optional[Mapping[str, Any]]) -> Optional[Condition]:
    if d is None:
        return None
    if "predicate" in d:
        return BooleanExpr(predicate=_predicate_from(d["predicate"]))
    if "all_of" in d:
        return BooleanExpr(all_of=[_condition_from(c) for c in d["all_of"] if c])  # type: ignore
    if "any_of" in d:
        return BooleanExpr(any_of=[_condition_from(c) for c in d["any_of"] if c])  # type: ignore
    if "not" in d:
        return BooleanExpr(not_expr=_condition_from(d["not"]))  # type: ignore
    # Fallback: treat dict as predicate-friendly form
    if {"operator", "left", "right"}.issubset(d.keys()):
        return BooleanExpr(predicate=_predicate_from(d))
    raise ValueError(f"Unknown condition format: {d}")

def _obligation_from(d: Mapping[str, Any]) -> Obligation:
    return Obligation(id=str(d["id"]), attributes=dict(d.get("attributes", {})))

def _advice_from(d: Mapping[str, Any]) -> Advice:
    return Advice(id=str(d["id"]), attributes=dict(d.get("attributes", {})))

def _rule_from(d: Mapping[str, Any]) -> Rule:
    return Rule(
        id=str(d["id"]),
        effect=Effect(str(d["effect"])),
        condition=_condition_from(d.get("condition")),
        obligations=[_obligation_from(o) for o in d.get("obligations", [])],
        advice=[_advice_from(a) for a in d.get("advice", [])],
        description=d.get("description"),
    )

def _policy_from(d: Mapping[str, Any]) -> Policy:
    return Policy(
        id=str(d["id"]),
        target=_condition_from(d.get("target")),
        rules=[_rule_from(r) for r in d.get("rules", [])],
        algorithm=CombiningAlg(str(d.get("algorithm", CombiningAlg.DENY_OVERRIDES))),
        obligations=[_obligation_from(o) for o in d.get("obligations", [])],
        advice=[_advice_from(a) for a in d.get("advice", [])],
        description=d.get("description"),
    )

def _policyset_from_dict(d: Mapping[str, Any]) -> PolicySet:
    def _pp(x: Mapping[str, Any]) -> Union[Policy, PolicySet]:
        if "policies" in x:
            return PolicySet(
                id=str(x["id"]),
                policies=[_pp(y) for y in x.get("policies", [])],
                target=_condition_from(x.get("target")),
                algorithm=CombiningAlg(str(x.get("algorithm", CombiningAlg.DENY_OVERRIDES))),
                obligations=[_obligation_from(o) for o in x.get("obligations", [])],
                advice=[_advice_from(a) for a in x.get("advice", [])],
                version=str(x.get("version", "1")),
                description=x.get("description"),
            )
        return _policy_from(x)

    if "policies" not in d:
        raise ValueError("PolicySet must contain 'policies'")
    return PolicySet(
        id=str(d["id"]),
        policies=[_pp(x) for x in d["policies"]],
        target=_condition_from(d.get("target")),
        algorithm=CombiningAlg(str(d.get("algorithm", CombiningAlg.DENY_OVERRIDES))),
        obligations=[_obligation_from(o) for o in d.get("obligations", [])],
        advice=[_advice_from(a) for a in d.get("advice", [])],
        version=str(d.get("version", "1")),
        description=d.get("description"),
    )

# -------- PEP decorator

def pep_enforce(pdp: PDP,
                action_name: str,
                subject_fn: Callable[..., Mapping[str, Any]],
                resource_fn: Callable[..., Mapping[str, Any]],
                env_fn: Optional[Callable[..., Mapping[str, Any]]] = None,
                on_deny: Optional[Callable[[Decision], None]] = None):
    """
    Decorate a function to enforce ABAC before execution.
    subject_fn/resource_fn/env_fn receive the same *args, **kwargs as the target function.
    """

    def wrapper(fn: Callable):
        @functools.wraps(fn)
        def inner(*args, **kwargs):
            subject = dict(subject_fn(*args, **kwargs))
            resource = dict(resource_fn(*args, **kwargs))
            environment = dict(env_fn(*args, **kwargs)) if env_fn else {}
            action = {"name": action_name}

            ctx = AttributeContext(subject=subject, resource=resource, action=action, environment=environment)
            decision = pdp.decide(ctx)
            if decision.effect == Effect.PERMIT:
                return fn(*args, **kwargs)
            if on_deny:
                on_deny(decision)
            raise PermissionError(decision.explain())
        return inner
    return wrapper

# -------- Minimal built-in policies (optional defaults)

def make_default_policyset(version: str = "1") -> PolicySet:
    """
    Default secure baseline: deny by default, allow admins explicitly.
    """
    admin_rule = Rule(
        id="allow-admins",
        effect=Effect.PERMIT,
        condition=Condition(predicate=Predicate("eq", Operand.attr("subject.role"), Operand.lit("admin"))),
    )
    default_deny = Rule(id="deny-otherwise", effect=Effect.DENY)
    base_policy = Policy(
        id="base-access",
        rules=[admin_rule, default_deny],
        algorithm=CombiningAlg.FIRST_APPLICABLE,
    )
    return PolicySet(id="root", policies=[base_policy], version=version)

# -------- Utilities for quick in-code policy creation

def simple_rule(rule_id: str, effect: Effect, left_attr: str, operator: str, right_value: Any) -> Rule:
    return Rule(
        id=rule_id,
        effect=effect,
        condition=Condition(predicate=Predicate(operator, Operand.attr(left_attr), Operand.lit(right_value))),
    )

# -------- Example-safe self test (optional, no side effects)
if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    store = InMemoryPolicyStore(make_default_policyset())
    pdp = PDP(store)

    ctx = AttributeContext(
        subject={"id": "u1", "role": "user"},
        resource={"id": "doc1", "type": "document", "owner": "u1"},
        action={"name": "read"},
        environment={"tenant": "t1"},
    )
    d1 = pdp.decide(ctx)
    print(d1.explain())

    # update policy: allow owner
    owner_rule = simple_rule("allow-owner", Effect.PERMIT, "resource.owner", "eq", "u1")
    pol = Policy(id="doc-access", rules=[owner_rule, Rule(id="deny", effect=Effect.DENY)], algorithm=CombiningAlg.FIRST_APPLICABLE)
    store.replace(PolicySet(id="root", policies=[pol], version=str(int(time.time()))))
    d2 = pdp.decide(ctx)
    print(d2.explain())
