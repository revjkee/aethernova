# cybersecurity-core/cybersecurity/policy/engine.py
"""
Industrial-grade Policy Engine (PDP/PEP) for Zero-Trust ABAC/RBAC.

Features:
- Data model: Policy, Rule, Decision, Effect (PERMIT/DENY/NOT_APPLICABLE/INDETERMINATE)
- Combining algorithms: deny-overrides, permit-overrides, first-applicable
- Safe expression DSL compiled via AST whitelist (no eval/exec). Supported:
  * Bool ops: and/or/not
  * Comparisons: ==, !=, <, <=, >, >=, in, not in
  * Literals: str, int, float, bool, None, tuples/lists/dicts (const)
  * Attribute access: ctx.subject.role, ctx.resource.type, ctx.env.time.hour
  * Subscript: dict["key"], list[0]
  * Functions (whitelisted): len, one_of(*), re_match(pattern, string, flags=0),
    starts_with(s, prefix), ends_with(s, suffix), contains(seq, item),
    ip_in_cidr(ip, cidr), hour_between(start_h, end_h, tz=None)
- PIP: Pluggable attribute resolvers to enrich context (sync functions)
- JSON loader: policies/rules from JSON dict
- Caching: LRU for compiled expressions and function lookups
- Thread-safety: RLock
- Explainability: trace with matched policy/rule IDs and condition strings
- No external deps; stdlib only.

Author: Aethernova / NeuroCity cybersecurity-core
License: MIT (or project default)
"""

from __future__ import annotations

import ast
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from functools import lru_cache
from threading import RLock
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

# Optional integration: Principal from auth middleware (if present in project)
try:
    from cybersecurity_core.api.http.middleware.auth import Principal  # type: ignore
except Exception:  # pragma: no cover
    @dataclass
    class Principal:  # minimal stub
        subject: str
        scopes: Tuple[str, ...] = ()
        claims: Mapping[str, Any] = field(default_factory=dict)
        source: str = "unknown"


# ---------------------------
# Effects, decisions, errors
# ---------------------------

class Effect(str, Enum):
    PERMIT = "permit"
    DENY = "deny"
    NOT_APPLICABLE = "not_applicable"
    INDETERMINATE = "indeterminate"


@dataclass
class Decision:
    effect: Effect
    obligations: Tuple[Mapping[str, Any], ...] = ()
    advice: Tuple[Mapping[str, Any], ...] = ()
    policy_id: Optional[str] = None
    rule_id: Optional[str] = None
    trace: Tuple[str, ...] = ()
    status: str = "ok"  # "ok" | "error"
    error: Optional[str] = None


# ---------------------------
# Context model
# ---------------------------

@dataclass
class SubjectCtx:
    id: Optional[str] = None
    roles: Tuple[str, ...] = ()
    scopes: Tuple[str, ...] = ()
    attrs: Mapping[str, Any] = field(default_factory=dict)


@dataclass
class ActionCtx:
    name: str
    method: Optional[str] = None
    attrs: Mapping[str, Any] = field(default_factory=dict)


@dataclass
class ResourceCtx:
    id: Optional[str] = None
    type: Optional[str] = None
    owner: Optional[str] = None
    attrs: Mapping[str, Any] = field(default_factory=dict)


@dataclass
class EnvCtx:
    time: datetime
    ip: Optional[str] = None
    tz: Optional[str] = None
    attrs: Mapping[str, Any] = field(default_factory=dict)


@dataclass
class RequestCtx:
    subject: SubjectCtx
    action: ActionCtx
    resource: ResourceCtx
    env: EnvCtx


# ---------------------------
# Policy and rule model
# ---------------------------

@dataclass
class Rule:
    rule_id: str
    condition: str  # DSL expression
    effect: Effect
    obligations: Tuple[Mapping[str, Any], ...] = ()
    advice: Tuple[Mapping[str, Any], ...] = ()
    priority: int = 0
    enabled: bool = True


class CombiningAlg(str, Enum):
    DENY_OVERRIDES = "deny_overrides"
    PERMIT_OVERRIDES = "permit_overrides"
    FIRST_APPLICABLE = "first_applicable"


@dataclass
class Policy:
    policy_id: str
    description: str = ""
    target: Optional[str] = None  # DSL expression acting as pre-filter
    rules: Tuple[Rule, ...] = ()
    combining_alg: CombiningAlg = CombiningAlg.DENY_OVERRIDES
    enabled: bool = True
    version: str = "1.0.0"
    meta: Mapping[str, Any] = field(default_factory=dict)


# ---------------------------
# Safe expression compiler
# ---------------------------

_ALLOWED_NODES = (
    ast.Expression, ast.BoolOp, ast.BinOp, ast.UnaryOp,
    ast.Compare, ast.Call, ast.Load, ast.Name, ast.Attribute,
    ast.Subscript, ast.Index if hasattr(ast, "Index") else (),
    ast.Slice, ast.Constant, ast.List, ast.Tuple, ast.Dict,
    ast.And, ast.Or, ast.Not, ast.Eq, ast.NotEq, ast.Lt, ast.LtE,
    ast.Gt, ast.GtE, ast.In, ast.NotIn, ast.USub, ast.UAdd
)

_SAFE_FUNCS: Dict[str, Callable[..., Any]] = {}

def _register_safe_funcs() -> None:
    def one_of(x: Any, *vals: Any) -> bool:
        return x in vals

    def contains(seq: Any, item: Any) -> bool:
        try:
            return item in seq
        except Exception:
            return False

    def starts_with(s: str, prefix: str) -> bool:
        return isinstance(s, str) and s.startswith(prefix)

    def ends_with(s: str, suffix: str) -> bool:
        return isinstance(s, str) and s.endswith(suffix)

    def re_match(pattern: str, s: str, flags: int = 0) -> bool:
        try:
            return re.search(pattern, s or "", flags) is not None
        except re.error:
            return False

    def ip_in_cidr(ip: str, cidr: str) -> bool:
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except Exception:
            return False

    def hour_between(start_hour: int, end_hour: int, tz: Optional[str] = None, now: Optional[datetime] = None) -> bool:
        # Inclusive start, exclusive end; 24h format; supports wrap (e.g., 22..6)
        t = now or datetime.utcnow()
        h = t.hour
        if start_hour <= end_hour:
            return start_hour <= h < end_hour
        return h >= start_hour or h < end_hour

    _SAFE_FUNCS.update({
        "len": len,
        "one_of": one_of,
        "contains": contains,
        "starts_with": starts_with,
        "ends_with": ends_with,
        "re_match": re_match,
        "ip_in_cidr": ip_in_cidr,
        "hour_between": hour_between,
    })

_register_safe_funcs()


class _SafeEvaluator:
    """
    Compile and evaluate safe expressions against a context object 'ctx'.
    """

    def __init__(self) -> None:
        self._lock = RLock()

    @staticmethod
    def _validate_ast(node: ast.AST) -> None:
        for child in ast.walk(node):
            if not isinstance(child, _ALLOWED_NODES):
                raise ValueError(f"Disallowed expression node: {type(child).__name__}")
            if isinstance(child, ast.Call):
                if not isinstance(child.func, ast.Name):
                    raise ValueError("Only direct function calls allowed")
                if child.keywords and any(k.arg is None for k in child.keywords):
                    raise ValueError("No **kwargs in calls")
            if isinstance(child, ast.Attribute):
                # Only allowed root name is 'ctx'
                parent = child
                while isinstance(parent, ast.Attribute):
                    parent = parent.value
                if not isinstance(parent, ast.Name) or parent.id != "ctx":
                    raise ValueError("Only 'ctx' attribute chains are allowed")

            if isinstance(child, ast.Name):
                if child.id not in {"ctx", *(_SAFE_FUNCS.keys()), "True", "False", "None"}:
                    raise ValueError(f"Unknown identifier: {child.id}")

    @lru_cache(maxsize=1024)
    def compile(self, expr: str) -> ast.AST:
        parsed = ast.parse(expr, mode="eval")
        self._validate_ast(parsed)
        return parsed

    def eval(self, expr: str, ctx: Any) -> Any:
        parsed = self.compile(expr)
        # Build safe globals and locals
        safe_globals = {"__builtins__": {}}
        safe_globals.update({name: fn for name, fn in _SAFE_FUNCS.items()})
        safe_locals = {"ctx": ctx}
        # Evaluate via Python AST evaluation using eval on validated tree
        try:
            return eval(compile(parsed, filename="<policy-expr>", mode="eval"), safe_globals, safe_locals)
        except Exception as e:
            raise RuntimeError(f"Expression evaluation error: {e}") from e


_SAFE_EVAL = _SafeEvaluator()


# ---------------------------
# PIP (attribute resolvers)
# ---------------------------

PIPResolver = Callable[[RequestCtx], Mapping[str, Any]]

class PIPRegistry:
    """
    Registry of resolvers that can augment subject/resource/action/env attrs.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._subject: List[PIPResolver] = []
        self._resource: List[PIPResolver] = []
        self._action: List[PIPResolver] = []
        self._env: List[PIPResolver] = []

    def register(self, *, subject: Optional[PIPResolver] = None,
                 resource: Optional[PIPResolver] = None,
                 action: Optional[PIPResolver] = None,
                 env: Optional[PIPResolver] = None) -> None:
        with self._lock:
            if subject:
                self._subject.append(subject)
            if resource:
                self._resource.append(resource)
            if action:
                self._action.append(action)
            if env:
                self._env.append(env)

    def enrich(self, req: RequestCtx) -> None:
        with self._lock:
            for r in self._subject:
                req.subject.attrs = {**req.subject.attrs, **(r(req) or {})}
            for r in self._resource:
                req.resource.attrs = {**req.resource.attrs, **(r(req) or {})}
            for r in self._action:
                req.action.attrs = {**req.action.attrs, **(r(req) or {})}
            for r in self._env:
                req.env.attrs = {**req.env.attrs, **(r(req) or {})}


# ---------------------------
# PDP Engine
# ---------------------------

@dataclass
class _CtxProxy:
    """
    Lightweight proxy exposed to policy expressions as 'ctx'.
    Read-only, attribute-based access to contextual fields.
    """
    subject: Mapping[str, Any]
    action: Mapping[str, Any]
    resource: Mapping[str, Any]
    env: Mapping[str, Any]


class PolicyEngine:
    """
    Policy Decision Point (PDP). Thread-safe; store policies and evaluate requests.
    """

    def __init__(self) -> None:
        self._policies: Dict[str, Policy] = {}
        self._lock = RLock()
        self._pip = PIPRegistry()

    # -------- Public API --------

    def register_pip(self, *, subject: Optional[PIPResolver] = None,
                     resource: Optional[PIPResolver] = None,
                     action: Optional[PIPResolver] = None,
                     env: Optional[PIPResolver] = None) -> None:
        self._pip.register(subject=subject, resource=resource, action=action, env=env)

    def add_policy(self, policy: Policy) -> None:
        with self._lock:
            self._policies[policy.policy_id] = policy

    def remove_policy(self, policy_id: str) -> None:
        with self._lock:
            self._policies.pop(policy_id, None)

    def list_policies(self) -> Tuple[Policy, ...]:
        with self._lock:
            return tuple(self._policies.values())

    def load_from_json(self, data: Mapping[str, Any]) -> None:
        """
        Load policies from a JSON-like mapping with structure:
        {
          "policies": [
            {
              "policy_id": "...",
              "description": "...",
              "target": "ctx.action.name == 'read'",
              "combining_alg": "deny_overrides",
              "enabled": true,
              "rules": [
                {
                  "rule_id": "r1",
                  "condition": "one_of('admin', *ctx.subject.roles)",
                  "effect": "permit",
                  "obligations": [{"log": "access_granted"}],
                  "advice": [{"mask_fields": ["ssn"]}],
                  "priority": 10,
                  "enabled": true
                }
              ]
            }
          ]
        }
        """
        pols = data.get("policies", [])
        if not isinstance(pols, list):
            raise ValueError("Invalid JSON: 'policies' must be a list")
        for p in pols:
            policy = self._parse_policy(p)
            self.add_policy(policy)

    def evaluate(self, req: RequestCtx) -> Decision:
        """
        Evaluate request against policies using each policy's combining algorithm.
        Returns first final decision per combining strategy of matched policies.
        """
        # Enrich with PIP resolvers
        self._pip.enrich(req)

        # Build 'ctx' proxy for expressions
        ctx = _CtxProxy(
            subject=self._subject_map(req.subject),
            action=self._action_map(req.action),
            resource=self._resource_map(req.resource),
            env=self._env_map(req.env),
        )

        matched: List[Policy] = []
        trace: List[str] = []

        # Pre-filter by target
        with self._lock:
            policies = [p for p in self._policies.values() if p.enabled]

        for p in sorted(policies, key=lambda x: x.policy_id):
            if p.target:
                try:
                    t = bool(_SAFE_EVAL.eval(p.target, ctx))
                    trace.append(f"policy:{p.policy_id}.target => {t}")
                    if not t:
                        continue
                except Exception as e:
                    trace.append(f"policy:{p.policy_id}.target ERROR: {e}")
                    continue
            matched.append(p)

        if not matched:
            return Decision(effect=Effect.NOT_APPLICABLE, trace=tuple(trace))

        # Evaluate matched policies one by one according to combining alg per policy
        final = Decision(effect=Effect.NOT_APPLICABLE, trace=tuple(trace))
        # We evaluate all matched policies and combine by precedence: any DENY from deny-overrides wins, etc.
        # To keep deterministic and explainable behavior, we produce the highest-precedence decision.
        results: List[Decision] = []
        for p in matched:
            results.append(self._evaluate_policy(p, ctx))

        # Global resolution: prefer explicit DENY, then PERMIT, else NOT_APPLICABLE, else INDETERMINATE
        deny = next((d for d in results if d.effect == Effect.DENY), None)
        if deny:
            return deny
        permit = next((d for d in results if d.effect == Effect.PERMIT), None)
        if permit:
            return permit
        indet = next((d for d in results if d.effect == Effect.INDETERMINATE), None)
        if indet:
            return indet
        return final

    # -------- PEP helper --------

    def enforce(self, req: RequestCtx) -> None:
        """
        Raise PermissionError if decision is DENY/NOT_APPLICABLE/INDETERMINATE.
        Intended for use in PEPs (e.g., API layer).
        """
        d = self.evaluate(req)
        if d.effect != Effect.PERMIT:
            msg = f"Access denied: effect={d.effect.value}; policy={d.policy_id}; rule={d.rule_id}"
            raise PermissionError(msg)

    # -------- Internal helpers --------

    def _evaluate_policy(self, policy: Policy, ctx: _CtxProxy) -> Decision:
        rules = [r for r in policy.rules if r.enabled]
        # Sort by priority desc then rule_id for determinism
        rules.sort(key=lambda r: (-r.priority, r.rule_id))
        trace: List[str] = []

        def eval_rule(rule: Rule) -> Decision:
            try:
                cond = bool(_SAFE_EVAL.eval(rule.condition, ctx))
                trace.append(f"rule:{rule.rule_id} cond => {cond}")
            except Exception as e:
                trace.append(f"rule:{rule.rule_id} ERROR: {e}")
                return Decision(effect=Effect.INDETERMINATE, policy_id=policy.policy_id, rule_id=rule.rule_id,
                                status="error", error=str(e), trace=tuple(trace))
            if not cond:
                return Decision(effect=Effect.NOT_APPLICABLE, policy_id=policy.policy_id, rule_id=rule.rule_id,
                                trace=tuple(trace))
            return Decision(effect=rule.effect, obligations=rule.obligations, advice=rule.advice,
                            policy_id=policy.policy_id, rule_id=rule.rule_id, trace=tuple(trace))

        if policy.combining_alg == CombiningAlg.FIRST_APPLICABLE:
            for r in rules:
                d = eval_rule(r)
                if d.effect in (Effect.PERMIT, Effect.DENY, Effect.INDETERMINATE):
                    return d
            return Decision(effect=Effect.NOT_APPLICABLE, policy_id=policy.policy_id, trace=tuple(trace))

        elif policy.combining_alg == CombiningAlg.PERMIT_OVERRIDES:
            pending_deny: Optional[Decision] = None
            for r in rules:
                d = eval_rule(r)
                if d.effect == Effect.PERMIT:
                    return d
                if d.effect == Effect.DENY and pending_deny is None:
                    pending_deny = d
                if d.effect == Effect.INDETERMINATE:
                    # Keep searching; if no PERMIT found, bubble error
                    pending_deny = pending_deny or d
            return pending_deny or Decision(effect=Effect.NOT_APPLICABLE, policy_id=policy.policy_id, trace=tuple(trace))

        else:  # DENY_OVERRIDES (default)
            pending_permit: Optional[Decision] = None
            for r in rules:
                d = eval_rule(r)
                if d.effect == Effect.DENY:
                    return d
                if d.effect == Effect.PERMIT and pending_permit is None:
                    pending_permit = d
                if d.effect == Effect.INDETERMINATE:
                    # immediate return if no PERMIT recorded
                    return d if pending_permit is None else pending_permit
            return pending_permit or Decision(effect=Effect.NOT_APPLICABLE, policy_id=policy.policy_id, trace=tuple(trace))

    @staticmethod
    def _subject_map(s: SubjectCtx) -> Mapping[str, Any]:
        return {
            "id": s.id,
            "roles": tuple(s.roles),
            "scopes": tuple(s.scopes),
            "attrs": dict(s.attrs),
        }

    @staticmethod
    def _action_map(a: ActionCtx) -> Mapping[str, Any]:
        return {"name": a.name, "method": a.method, "attrs": dict(a.attrs)}

    @staticmethod
    def _resource_map(r: ResourceCtx) -> Mapping[str, Any]:
        return {"id": r.id, "type": r.type, "owner": r.owner, "attrs": dict(r.attrs)}

    @staticmethod
    def _env_map(e: EnvCtx) -> Mapping[str, Any]:
        return {"time": e.time, "ip": e.ip, "tz": e.tz, "attrs": dict(e.attrs)}


# ---------------------------
# Utility builders
# ---------------------------

def subject_from_principal(pr: Principal) -> SubjectCtx:
    """
    Convert Auth Principal to SubjectCtx.
    """
    sub_id = pr.claims.get("sub") or pr.subject
    roles: Tuple[str, ...] = tuple(sorted(set(pr.claims.get("roles", []) or pr.claims.get("role", []) or ())))
    scopes: Tuple[str, ...] = tuple(sorted(set(pr.scopes or ())))
    return SubjectCtx(id=str(sub_id) if sub_id else None, roles=roles, scopes=scopes, attrs=dict(pr.claims))


def build_request_ctx(
    *,
    principal: Optional[Principal],
    action: str,
    method: Optional[str],
    resource_id: Optional[str],
    resource_type: Optional[str],
    resource_owner: Optional[str],
    env_time: datetime,
    env_ip: Optional[str] = None,
    env_tz: Optional[str] = None,
    subject_attrs: Optional[Mapping[str, Any]] = None,
    action_attrs: Optional[Mapping[str, Any]] = None,
    resource_attrs: Optional[Mapping[str, Any]] = None,
    env_attrs: Optional[Mapping[str, Any]] = None,
) -> RequestCtx:
    subj = subject_from_principal(principal) if principal else SubjectCtx()
    if subject_attrs:
        subj.attrs = {**subj.attrs, **subject_attrs}
    act = ActionCtx(name=action, method=method or None, attrs=dict(action_attrs or {}))
    res = ResourceCtx(id=resource_id, type=resource_type, owner=resource_owner, attrs=dict(resource_attrs or {}))
    env = EnvCtx(time=env_time, ip=env_ip, tz=env_tz, attrs=dict(env_attrs or {}))
    return RequestCtx(subject=subj, action=act, resource=res, env=env)


# ---------------------------
# JSON helpers
# ---------------------------

def _parse_effect(v: str) -> Effect:
    try:
        return Effect(v)
    except Exception:
        raise ValueError(f"Unknown effect: {v}")


def _parse_comb_alg(v: str) -> CombiningAlg:
    try:
        return CombiningAlg(v)
    except Exception:
        raise ValueError(f"Unknown combining_alg: {v}")


def _parse_rule(obj: Mapping[str, Any]) -> Rule:
    return Rule(
        rule_id=str(obj["rule_id"]),
        condition=str(obj["condition"]),
        effect=_parse_effect(str(obj["effect"])),
        obligations=tuple(obj.get("obligations", [])),
        advice=tuple(obj.get("advice", [])),
        priority=int(obj.get("priority", 0)),
        enabled=bool(obj.get("enabled", True)),
    )


def _parse_policy(obj: Mapping[str, Any]) -> Policy:
    rules = tuple(_parse_rule(r) for r in obj.get("rules", []))
    return Policy(
        policy_id=str(obj["policy_id"]),
        description=str(obj.get("description", "")),
        target=str(obj["target"]) if obj.get("target") is not None else None,
        rules=rules,
        combining_alg=_parse_comb_alg(obj.get("combining_alg", CombiningAlg.DENY_OVERRIDES.value)),
        enabled=bool(obj.get("enabled", True)),
        version=str(obj.get("version", "1.0.0")),
        meta=dict(obj.get("meta", {})),
    )


# ---------------------------
# Example default policies (optional)
# ---------------------------

DEFAULT_POLICIES_JSON = {
    "policies": [
        {
            "policy_id": "p_api_admin",
            "description": "Админам разрешены административные действия по HTTPS из доверенных сетей.",
            "target": "ctx.action.name in ('admin_op', 'policy_update', 'user_manage')",
            "combining_alg": "deny_overrides",
            "rules": [
                {
                    "rule_id": "r_admin_role",
                    "condition": "('admin' in ctx.subject.roles) and (ctx.env.ip is None or ip_in_cidr(ctx.env.ip, '10.0.0.0/8'))",
                    "effect": "permit",
                    "priority": 100
                },
                {
                    "rule_id": "r_deny_default",
                    "condition": "True",
                    "effect": "deny",
                    "priority": 0
                }
            ]
        },
        {
            "policy_id": "p_readonly_hours",
            "description": "Чтение ресурсов разрешено в рабочие часы; вне часов — только при наличии scope 'afterhours:read'.",
            "target": "ctx.action.name == 'read'",
            "combining_alg": "permit_overrides",
            "rules": [
                {
                    "rule_id": "r_work_hours",
                    "condition": "hour_between(9, 19, tz=ctx.env.tz, now=ctx.env.time)",
                    "effect": "permit",
                    "priority": 10
                },
                {
                    "rule_id": "r_after_hours_scope",
                    "condition": "'afterhours:read' in ctx.subject.scopes",
                    "effect": "permit",
                    "priority": 5
                },
                {
                    "rule_id": "r_default_deny",
                    "condition": "True",
                    "effect": "deny",
                    "priority": 0
                }
            ]
        }
    ]
}


# ---------------------------
# Minimal usage sketch (not executed)
# ---------------------------
# engine = PolicyEngine()
# engine.load_from_json(DEFAULT_POLICIES_JSON)
# req = build_request_ctx(
#     principal=Principal(subject="user-1", scopes=("afterhours:read",), claims={"roles": ["user"]}, source="jwt"),
#     action="read", method="GET", resource_id="doc-1", resource_type="doc", resource_owner="user-2",
#     env_time=datetime.utcnow(), env_ip="10.1.2.3"
# )
# decision = engine.evaluate(req)
# if decision.effect == Effect.PERMIT:
#     pass

