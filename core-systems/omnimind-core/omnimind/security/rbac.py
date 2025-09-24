# SPDX-License-Identifier: Apache-2.0
"""
Industrial RBAC/ABAC engine for Omnimind Core.

Features
- RBAC with role inheritance and multi-tenant scoping
- ABAC via safe condition evaluator (boolean ops, comparisons, "in", IP/CIDR helpers)
- Allow/Deny policies with priorities and wildcard patterns for resources/actions
- Deterministic decision rules: explicit deny > explicit allow; default deny
- LRU decision cache with invalidation on policy changes
- Audit trail and explain() for troubleshooting
- Zero external dependencies (standard library only)

Glossary
- Principal: subject (user/service) with roles and attributes
- Resource: typed reference with id and attributes
- Action: verb string (e.g., "read", "write", "delete", "admin", "list", "create")
- Policy: rule with effect (allow|deny), filters and optional condition

Example policy JSON (see load_policies):
{
  "version": 1,
  "roles": {
    "viewer": [],
    "editor": ["viewer"],
    "admin": ["editor"]
  },
  "policies": [
    {
      "id": "p1",
      "effect": "allow",
      "roles_any": ["viewer", "editor", "admin"],
      "actions": ["read", "list"],
      "resource_type": "doc",
      "resource_id": "*",
      "priority": 100
    },
    {
      "id": "p2",
      "effect": "allow",
      "roles_any": ["editor", "admin"],
      "actions": ["create", "write"],
      "resource_type": "doc",
      "resource_id": "org:{principal.tenant_id}:*",
      "when": "resource.tenant_id == principal.tenant_id",
      "priority": 90
    },
    {
      "id": "p3",
      "effect": "deny",
      "roles_any": ["*"],
      "actions": ["*"],
      "resource_type": "doc",
      "resource_id": "*",
      "when": "env.now_hour < 7 or env.now_hour > 22",
      "priority": 10
    }
  ]
}
"""

from __future__ import annotations

import functools
import ipaddress
import json
import time
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

# ----------------------------- Data models ----------------------------------


@dataclass(frozen=True)
class Principal:
    id: str
    roles: Tuple[str, ...] = field(default_factory=tuple)
    tenant_id: Optional[str] = None
    attributes: Mapping[str, Any] = field(default_factory=dict)  # e.g., ip, scopes, labels


@dataclass(frozen=True)
class Resource:
    type: str
    id: str
    tenant_id: Optional[str] = None
    attributes: Mapping[str, Any] = field(default_factory=dict)  # e.g., owner_id, path, labels


@dataclass(frozen=True)
class Decision:
    allowed: bool
    effect: str  # "allow"|"deny"|"default_deny"
    policy_id: Optional[str]
    reason: str
    matched: List[str] = field(default_factory=list)  # policy ids examined positively
    audit: Mapping[str, Any] = field(default_factory=dict)


@dataclass
class Policy:
    id: str
    effect: str  # "allow" or "deny"
    roles_any: Tuple[str, ...]  # any of these roles or "*" to match any role
    actions: Tuple[str, ...]  # verbs or ["*"]
    resource_type: str  # e.g., "doc" or "*"
    resource_id: str  # glob with substitutions, e.g. "org:{principal.tenant_id}:*"
    when: Optional[str] = None  # safe condition expression
    priority: int = 100  # lower number = higher priority
    cacheable: bool = True  # skip cache if False

    def matches_static(self, principal_roles: Tuple[str, ...], action: str, res_type: str, res_id: str) -> bool:
        # role match
        if "*" not in self.roles_any:
            if not any(r in principal_roles for r in self.roles_any):
                return False
        # action match
        if "*" not in self.actions and action not in self.actions:
            return False
        # resource type match (exact or wildcard)
        if self.resource_type != "*" and self.resource_type != res_type:
            return False
        # resource id glob match done later after substitution
        return True

    def render_res_id(self, principal: Principal, resource: Resource, env: Mapping[str, Any]) -> str:
        # simple brace substitution for {principal.xxx}, {resource.xxx}, {env.xxx}
        def sub(s: str, ctx: Mapping[str, Any]) -> str:
            out = s
            for k, v in ctx.items():
                out = out.replace("{" + k + "}", str(v))
            return out

        ctx = {
            "principal.id": principal.id,
            "principal.tenant_id": principal.tenant_id or "",
            "resource.id": resource.id,
            "resource.tenant_id": resource.tenant_id or "",
            "env.now_hour": str(env.get("now_hour", "")),
            "env.env": str(env.get("env", "")),
        }
        # flatten attributes
        for k, v in (principal.attributes or {}).items():
            ctx[f"principal.{k}"] = v
        for k, v in (resource.attributes or {}).items():
            ctx[f"resource.{k}"] = v
        return sub(self.resource_id, ctx)


# ----------------------------- Role graph ------------------------------------


class RoleGraph:
    def __init__(self, inherits: Mapping[str, Sequence[str]] | None = None) -> None:
        # inherits[role] -> parents
        self._parents: Dict[str, Tuple[str, ...]] = {
            k: tuple(v) for k, v in (inherits or {}).items()
        }

    def effective_roles(self, given: Iterable[str]) -> Tuple[str, ...]:
        result: List[str] = []
        seen: set[str] = set()

        def dfs(r: str) -> None:
            if r in seen:
                return
            seen.add(r)
            result.append(r)
            for p in self._parents.get(r, ()):
                dfs(p)

        for r in given:
            dfs(r)
        return tuple(dict.fromkeys(result))  # stable unique order


# ------------------------- Safe condition evaluator --------------------------


class SafeCondition:
    """
    Very small, safe evaluator for boolean expressions.

    Supported:
      - literals: strings, ints, bools, None
      - vars: principal.<key>, resource.<key>, env.<key>
      - ops: and, or, not, ==, !=, in, <=, <, >=, >
      - functions: cidr_contains(ip, cidr), startswith(str, prefix), endswith(str, suffix)

    Expression example:
      "resource.tenant_id == principal.tenant_id and cidr_contains(principal.ip, '10.0.0.0/8')"
    """

    @staticmethod
    def eval(expr: str, *, principal: Mapping[str, Any], resource: Mapping[str, Any], env: Mapping[str, Any]) -> bool:
        import ast

        allowed_nodes = (
            ast.Expression, ast.BoolOp, ast.UnaryOp, ast.BinOp, ast.Compare,
            ast.Name, ast.Load, ast.Constant, ast.And, ast.Or, ast.Not,
            ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn,
            ast.Call, ast.Attribute
        )

        def _node(n: ast.AST) -> Any:
            if not isinstance(n, allowed_nodes):
                raise ValueError(f"Unsupported expression element: {type(n).__name__}")

            if isinstance(n, ast.Expression):
                return _node(n.body)

            if isinstance(n, ast.BoolOp):
                vals = [_node(v) for v in n.values]
                if isinstance(n.op, ast.And):
                    return all(vals)
                elif isinstance(n.op, ast.Or):
                    return any(vals)
                else:
                    raise ValueError("Unsupported boolean operator")

            if isinstance(n, ast.UnaryOp):
                if isinstance(n.op, ast.Not):
                    return not _node(n.operand)
                raise ValueError("Unsupported unary operator")

            if isinstance(n, ast.BinOp):
                # Only + allowed for string concat
                if isinstance(n.op, ast.Add):
                    left = _node(n.left)
                    right = _node(n.right)
                    return str(left) + str(right)
                raise ValueError("Unsupported binary operator")

            if isinstance(n, ast.Compare):
                left = _node(n.left)
                results: List[bool] = []
                for op, comp in zip(n.ops, n.comparators):
                    right = _node(comp)
                    if isinstance(op, ast.Eq):
                        results.append(left == right)
                    elif isinstance(op, ast.NotEq):
                        results.append(left != right)
                    elif isinstance(op, ast.Lt):
                        results.append(left < right)  # type: ignore[operator]
                    elif isinstance(op, ast.LtE):
                        results.append(left <= right)  # type: ignore[operator]
                    elif isinstance(op, ast.Gt):
                        results.append(left > right)  # type: ignore[operator]
                    elif isinstance(op, ast.GtE):
                        results.append(left >= right)  # type: ignore[operator]
                    elif isinstance(op, (ast.In,)):
                        results.append(left in right)  # type: ignore[operator]
                    elif isinstance(op, ast.NotIn):
                        results.append(left not in right)  # type: ignore[operator]
                    else:
                        raise ValueError("Unsupported comparison")
                    left = right
                return all(results)

            if isinstance(n, ast.Name):
                if n.id == "principal":
                    return principal
                if n.id == "resource":
                    return resource
                if n.id == "env":
                    return env
                # Functions
                if n.id in ("cidr_contains", "startswith", "endswith"):
                    return n.id
                raise ValueError(f"Unknown name: {n.id}")

            if isinstance(n, ast.Attribute):
                base = _node(n.value)
                if not isinstance(base, dict):
                    raise ValueError("Attribute base must be dict-like")
                return base.get(n.attr)

            if isinstance(n, ast.Constant):
                return n.value

            if isinstance(n, ast.Call):
                func = _node(n.func)
                args = [_node(a) for a in n.args]
                if func == "cidr_contains":
                    return SafeCondition._cidr_contains(str(args[0]), str(args[1]))
                if func == "startswith":
                    return str(args[0]).startswith(str(args[1]))
                if func == "endswith":
                    return str(args[0]).endswith(str(args[1]))
                raise ValueError(f"Unknown function: {func}")

            raise ValueError("Unsupported expression")

        tree = ast.parse(expr, mode="eval")
        return bool(_node(tree))

    @staticmethod
    def _cidr_contains(ip: str, cidr: str) -> bool:
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except Exception:
            return False


# ----------------------------- RBAC Engine -----------------------------------


class AuthorizationError(RuntimeError):
    pass


class RbacEngine:
    def __init__(self, role_graph: Optional[RoleGraph] = None) -> None:
        self._role_graph = role_graph or RoleGraph({})
        self._policies: List[Policy] = []
        self._decision_cache = _DecisionCache(maxsize=5000, ttl_seconds=30)

    # Policy management

    def add_policy(self, p: Policy) -> None:
        self._policies.append(p)
        self._policies.sort(key=lambda x: (x.priority, 0 if x.effect == "deny" else 1))
        self._decision_cache.clear()

    def set_policies(self, policies: Sequence[Policy]) -> None:
        self._policies = list(policies)
        self._policies.sort(key=lambda x: (x.priority, 0 if x.effect == "deny" else 1))
        self._decision_cache.clear()

    def load_policies(self, data: Mapping[str, Any]) -> None:
        # Accept raw dict (e.g., from JSON). No YAML here to avoid external deps.
        roles = data.get("roles") or {}
        self._role_graph = RoleGraph(roles)
        policies: List[Policy] = []
        for item in data.get("policies") or []:
            policies.append(
                Policy(
                    id=str(item["id"]),
                    effect=str(item["effect"]).lower(),
                    roles_any=tuple(item.get("roles_any") or ("*",)),
                    actions=tuple(item.get("actions") or ("*",)),
                    resource_type=str(item.get("resource_type") or "*"),
                    resource_id=str(item.get("resource_id") or "*"),
                    when=item.get("when"),
                    priority=int(item.get("priority", 100)),
                    cacheable=bool(item.get("cacheable", True)),
                )
            )
        self.set_policies(policies)

    # Decision

    def check(
        self,
        principal: Principal,
        action: str,
        resource: Resource,
        *,
        env: Optional[Mapping[str, Any]] = None,
        explain: bool = False,
    ) -> Decision:
        if action is None or not action:
            raise AuthorizationError("Action must be non-empty")
        env = dict(env or {})
        # common environment derivations
        if "now_hour" not in env:
            import datetime as _dt

            env["now_hour"] = _dt.datetime.utcnow().hour
        env.setdefault("env", "production")

        eff_roles = self._role_graph.effective_roles(principal.roles)
        cache_key = None
        if not explain:
            cache_key = self._decision_cache.build_key(principal, eff_roles, action, resource, env)

            cached = self._decision_cache.get(cache_key)
            if cached is not None:
                return cached

        matched: List[str] = []
        allow_hit: Optional[Policy] = None
        deny_hit: Optional[Policy] = None

        for p in self._policies:
            if not p.matches_static(eff_roles, action, resource.type, resource.id):
                continue

            # Render resource_id mask with simple substitutions and match
            rid_mask = p.render_res_id(principal, resource, env)
            if not (rid_mask == "*" or fnmatchcase(resource.id, rid_mask)):
                continue

            # Prepare contexts for safe condition eval
            cond_ok = True
            if p.when:
                cond_ok = SafeCondition.eval(
                    p.when,
                    principal=_flatten_ctx("principal", principal),
                    resource=_flatten_ctx("resource", resource),
                    env=dict(env),
                )
            if not cond_ok:
                continue

            matched.append(p.id)
            if p.effect == "deny":
                deny_hit = p
                break  # deny takes precedence immediately by priority-sort
            else:
                allow_hit = allow_hit or p  # first allow by order

        if deny_hit:
            decision = Decision(
                allowed=False,
                effect="deny",
                policy_id=deny_hit.id,
                reason="matched deny policy",
                matched=matched,
                audit=_audit(principal, action, resource, env, deny_hit),
            )
        elif allow_hit:
            decision = Decision(
                allowed=True,
                effect="allow",
                policy_id=allow_hit.id,
                reason="matched allow policy",
                matched=matched,
                audit=_audit(principal, action, resource, env, allow_hit),
            )
        else:
            decision = Decision(
                allowed=False,
                effect="default_deny",
                policy_id=None,
                reason="no matching policy",
                matched=matched,
                audit=_audit(principal, action, resource, env, None),
            )

        if cache_key and (allow_hit is None or allow_hit.cacheable) and (deny_hit is None or deny_hit.cacheable):
            self._decision_cache.put(cache_key, decision)

        return decision

    # Decorator for imperative guard

    def require(self, action: str, resource_provider):
        """
        Decorator for function-level enforcement.

        Usage:
            engine = RbacEngine(...)

            @engine.require("write", lambda self, *a, **kw: Resource(type="doc", id=kw["doc_id"]))
            def update(self, doc_id: str): ...
        """

        def deco(fn):
            def wrapper(*args, **kwargs):
                principal = kwargs.get("principal")
                if principal is None:
                    raise AuthorizationError("principal is required")
                resource = resource_provider(*args, **kwargs)
                decision = self.check(principal, action, resource)
                if not decision.allowed:
                    raise AuthorizationError(f"forbidden: {decision.reason} via {decision.policy_id}")
                return fn(*args, **kwargs)

            return wrapper

        return deco


# ------------------------------- Utilities -----------------------------------


def _flatten_ctx(prefix: str, obj: Any) -> Dict[str, Any]:
    if isinstance(obj, Principal):
        out = {"id": obj.id, "tenant_id": obj.tenant_id}
        out.update(obj.attributes or {})
        return out
    if isinstance(obj, Resource):
        out = {"id": obj.id, "tenant_id": obj.tenant_id}
        out.update(obj.attributes or {})
        return out
    if isinstance(obj, dict):
        return dict(obj)
    return {"value": obj}


def _audit(principal: Principal, action: str, resource: Resource, env: Mapping[str, Any], policy: Optional[Policy]) -> Mapping[str, Any]:
    return {
        "principal_id": principal.id,
        "tenant_id": principal.tenant_id,
        "roles": list(principal.roles),
        "action": action,
        "resource": {"type": resource.type, "id": resource.id, "tenant_id": resource.tenant_id},
        "env": dict(env),
        "policy": policy.id if policy else None,
        "ts": int(time.time()),
    }


class _DecisionCache:
    def __init__(self, maxsize: int, ttl_seconds: int) -> None:
        self._data: Dict[Tuple[Any, ...], Tuple[Decision, float]] = {}
        self._max = maxsize
        self._ttl = ttl_seconds

    def clear(self) -> None:
        self._data.clear()

    def build_key(self, principal: Principal, eff_roles: Tuple[str, ...], action: str, resource: Resource, env: Mapping[str, Any]) -> Tuple[Any, ...]:
        # Use stable subset of env to keep cache from exploding
        env_key = (env.get("env"), env.get("now_hour"))
        return (principal.id, eff_roles, principal.tenant_id, action, resource.type, resource.id, env_key)

    def get(self, key: Tuple[Any, ...]) -> Optional[Decision]:
        item = self._data.get(key)
        if not item:
            return None
        decision, ts = item
        if (time.time() - ts) > self._ttl:
            try:
                del self._data[key]
            except KeyError:
                pass
            return None
        return decision

    def put(self, key: Tuple[Any, ...], decision: Decision) -> None:
        if len(self._data) >= self._max:
            # naive eviction: drop oldest
            oldest_key = min(self._data.items(), key=lambda kv: kv[1][1])[0]
            self._data.pop(oldest_key, None)
        self._data[key] = (decision, time.time())


# ------------------------------- Helpers -------------------------------------


def make_engine_from_json(json_str: str) -> RbacEngine:
    data = json.loads(json_str)
    engine = RbacEngine()
    engine.load_policies(data)
    return engine


# ------------------------------- Self-check ----------------------------------


if __name__ == "__main__":
    # Minimal self-test
    policies = {
        "version": 1,
        "roles": {"editor": ["viewer"], "admin": ["editor"]},
        "policies": [
            {
                "id": "allow_read_all",
                "effect": "allow",
                "roles_any": ["viewer", "editor", "admin"],
                "actions": ["read", "list"],
                "resource_type": "doc",
                "resource_id": "*",
                "priority": 100,
            },
            {
                "id": "allow_write_same_tenant",
                "effect": "allow",
                "roles_any": ["editor", "admin"],
                "actions": ["write", "create"],
                "resource_type": "doc",
                "resource_id": "org:{principal.tenant_id}:*",
                "when": "resource.tenant_id == principal.tenant_id",
                "priority": 90,
            },
            {
                "id": "deny_night_ops",
                "effect": "deny",
                "roles_any": ["*"],
                "actions": ["*"],
                "resource_type": "doc",
                "resource_id": "*",
                "when": "env.now_hour < 6 or env.now_hour > 22",
                "priority": 10,
            },
        ],
    }

    engine = make_engine_from_json(json.dumps(policies))
    alice = Principal(id="u1", roles=("editor",), tenant_id="t1", attributes={"ip": "10.0.5.1"})
    bob = Principal(id="u2", roles=("viewer",), tenant_id="t2", attributes={"ip": "192.168.1.2"})
    res1 = Resource(type="doc", id="org:t1:doc:42", tenant_id="t1", attributes={"owner_id": "u1"})
    res2 = Resource(type="doc", id="org:t2:doc:999", tenant_id="t2", attributes={"owner_id": "u9"})

    # Force daytime for demo
    env = {"now_hour": 12, "env": "production"}

    d1 = engine.check(alice, "write", res1, env=env, explain=True)
    print("alice write res1 ->", d1)

    d2 = engine.check(alice, "write", res2, env=env, explain=True)
    print("alice write res2 ->", d2)

    d3 = engine.check(bob, "read", res2, env=env, explain=True)
    print("bob read res2 ->", d3)

    # Night deny
    d4 = engine.check(alice, "read", res1, env={"now_hour": 23})
    print("alice read res1 at 23h ->", d4)
