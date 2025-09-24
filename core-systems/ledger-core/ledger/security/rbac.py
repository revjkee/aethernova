# ledger/security/rbac.py
# -*- coding: utf-8 -*-
"""
Industrial-grade RBAC(+conditions) engine for ledger-core.

Features:
- Roles with hierarchical inheritance and explicit ALLOW/DENY permissions.
- Hybrid RBAC+ (RBAC with safe conditional constraints akin to ABAC predicates).
- DENY overrides ALLOW across all matched permissions (fail-safe default deny).
- Resource matching by exact ID, type, or glob masks (e.g., "ledger:tx:*").
- Safe, auditable condition evaluation via restricted AST evaluator.
- Decision caching with TTL and LRU bound; thread-safe policy store (in-memory) and Protocol for pluggable stores.
- Rich observability: metric, trace and audit sinks (Protocol-based, optional).
- Deterministic explainability: PolicyDecision contains all matched rules and reasons.
- Decorator for service handlers to enforce decisions and emit audit records.

No I/O; external identity resolution performed by integrator.
"""

from __future__ import annotations

import ast
import fnmatch
import json
import logging
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Protocol, Sequence, Tuple, Set, runtime_checkable

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------

logger = logging.getLogger("ledger.security.rbac")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# -----------------------------------------------------------------------------
# Errors
# -----------------------------------------------------------------------------

class RBACError(Exception):
    """Base class for RBAC errors."""

class PolicyStoreError(RBACError):
    """Policy store operation failed."""

class InvalidPolicyError(RBACError):
    """Invalid role/principal/policy structure."""

class AuthorizationError(RBACError):
    """Thrown when authorization decorator denies access."""

# -----------------------------------------------------------------------------
# Observability Protocols
# -----------------------------------------------------------------------------

@runtime_checkable
class MetricSink(Protocol):
    def incr(self, name: str, value: int = 1, *, tags: Optional[Dict[str, str]] = None) -> None: ...
    def timing(self, name: str, ms: float, *, tags: Optional[Dict[str, str]] = None) -> None: ...

@runtime_checkable
class TraceSink(Protocol):
    def span(self, name: str, **kwargs) -> "TraceSpan": ...

class TraceSpan:
    def __init__(self, name: str):
        self.name = name
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb): return False
    def set_tag(self, key: str, value: Any): return self

@runtime_checkable
class AuditSink(Protocol):
    def record(self, event: Dict[str, Any]) -> None: ...

# -----------------------------------------------------------------------------
# Core Models
# -----------------------------------------------------------------------------

class Effect(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"

@dataclass(frozen=True)
class Permission:
    """
    Permission describes (action, resource) pair with optional condition.
    resource supports exact match or glob (e.g., "ledger:tx:*" or "ledger:account:123").
    action supports exact or glob (e.g., "tx.read", "tx.*").
    condition: safe expression string evaluated against (principal.attrs, ctx).
    """
    action: str
    resource: str
    effect: Effect = Effect.ALLOW
    condition: Optional[str] = None
    description: Optional[str] = None

    def __post_init__(self):
        if not self.action or not self.resource:
            raise InvalidPolicyError("Permission requires non-empty action and resource")
        if not isinstance(self.effect, Effect):
            raise InvalidPolicyError("Permission.effect must be Effect")
        if self.condition is not None and not isinstance(self.condition, str):
            raise InvalidPolicyError("Permission.condition must be str or None")

@dataclass
class Role:
    """
    Role with permissions and optional parent roles (inheritance).
    """
    name: str
    permissions: List[Permission] = field(default_factory=list)
    parents: List[str] = field(default_factory=list)  # names of parent roles
    description: Optional[str] = None
    version: int = 1

    def __post_init__(self):
        if not self.name:
            raise InvalidPolicyError("Role.name must be non-empty")
        # Deduplicate permissions deterministically
        uniq: Dict[Tuple[str, str, Effect, Optional[str]], Permission] = {}
        for p in self.permissions:
            uniq[(p.action, p.resource, p.effect, p.condition)] = p
        self.permissions = list(uniq.values())

@dataclass
class Principal:
    """
    Principal (subject). 'attrs' holds arbitrary attributes for conditions.
    """
    id: str
    roles: List[str] = field(default_factory=list)
    attrs: Dict[str, Any] = field(default_factory=dict)
    version: int = 1

    def __post_init__(self):
        if not self.id:
            raise InvalidPolicyError("Principal.id must be non-empty")

@dataclass(frozen=True)
class MatchDetail:
    role: str
    permission: Permission
    matched_action: bool
    matched_resource: bool
    condition_result: Optional[bool]

@dataclass
class PolicyDecision:
    allowed: bool
    effect: Effect
    principal_id: str
    action: str
    resource: str
    matched: List[MatchDetail] = field(default_factory=list)
    reason: Optional[str] = None
    evaluated_at: float = field(default_factory=lambda: time.time())

# -----------------------------------------------------------------------------
# Safe Condition Evaluator (AST whitelist)
# -----------------------------------------------------------------------------

_ALLOWED_NODES = {
    ast.Expression, ast.BoolOp, ast.BinOp, ast.UnaryOp, ast.Compare, ast.Name, ast.Load,
    ast.Constant, ast.And, ast.Or, ast.Not, ast.Eq, ast.NotEq, ast.Gt, ast.GtE, ast.Lt, ast.LtE,
    ast.In, ast.NotIn, ast.Is, ast.IsNot, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.USub,
    ast.Dict, ast.List, ast.Tuple, ast.IfExp, ast.Call, ast.keyword, ast.Attribute, ast.Index, ast.Subscript
}

# Allowed function names and attribute roots to reduce attack surface
_ALLOWED_FUNCS = {
    "len": len,
    "any": any,
    "all": all,
    "min": min,
    "max": max,
    "set": set,
    "sorted": sorted,
}

# Guards: only allow attribute access on whitelisted roots 'principal' and 'ctx'
_ALLOWED_ATTR_ROOTS = {"principal", "ctx"}

class UnsafeExpression(RBACError):
    pass

def _ensure_safe_ast(node: ast.AST) -> None:
    for n in ast.walk(node):
        if type(n) not in _ALLOWED_NODES:
            raise UnsafeExpression(f"Disallowed AST node: {type(n).__name__}")
        # Disallow function calls to anything not whitelisted
        if isinstance(n, ast.Call):
            if isinstance(n.func, ast.Name):
                if n.func.id not in _ALLOWED_FUNCS:
                    raise UnsafeExpression(f"Call to not allowed function: {n.func.id}")
            elif isinstance(n.func, ast.Attribute):
                # Allow attribute call only if base is allowed root and attribute is plain (e.g., ctx.get('k'))
                if not (isinstance(n.func.value, ast.Name) and n.func.value.id in _ALLOWED_ATTR_ROOTS):
                    raise UnsafeExpression("Calls on non-whitelisted objects are forbidden")
        # Disallow attribute access except on 'principal' or 'ctx'
        if isinstance(n, ast.Attribute):
            base = n.value
            if not (isinstance(base, ast.Name) and base.id in _ALLOWED_ATTR_ROOTS):
                raise UnsafeExpression("Attribute access is restricted to 'principal' and 'ctx'")

def safe_eval(expr: str, *, principal: Dict[str, Any], ctx: Dict[str, Any]) -> bool:
    """
    Evaluate boolean expression safely. Variables:
      - principal: dict of principal attrs
      - ctx: dict of request context (resource owner, env, time, ip, etc)
    """
    try:
        node = ast.parse(expr, mode="eval")
        _ensure_safe_ast(node)
        env = {"__builtins__": {}}
        env.update(_ALLOWED_FUNCS)
        env["principal"] = principal
        env["ctx"] = ctx
        return bool(eval(compile(node, filename="<rbac-condition>", mode="eval"), env, {}))
    except UnsafeExpression as ue:
        logger.warning("Unsafe RBAC condition rejected: %s", ue)
        raise InvalidPolicyError(f"Unsafe condition rejected: {ue}") from ue
    except Exception as exc:
        logger.warning("RBAC condition evaluation error: %s", exc)
        raise InvalidPolicyError("Condition evaluation error") from exc

# -----------------------------------------------------------------------------
# Policy Store Protocols & In-memory Implementation
# -----------------------------------------------------------------------------

@runtime_checkable
class PolicyStore(Protocol):
    def get_role(self, name: str) -> Optional[Role]: ...
    def upsert_role(self, role: Role) -> None: ...
    def delete_role(self, name: str) -> None: ...
    def list_roles(self) -> List[Role]: ...
    def get_principal(self, principal_id: str) -> Optional[Principal]: ...
    def upsert_principal(self, principal: Principal) -> None: ...
    def delete_principal(self, principal_id: str) -> None: ...

class InMemoryPolicyStore(PolicyStore):
    """
    Thread-safe in-memory store suitable for tests and small deployments.
    """
    def __init__(self):
        self._roles: Dict[str, Role] = {}
        self._principals: Dict[str, Principal] = {}
        self._lock = threading.RLock()

    def get_role(self, name: str) -> Optional[Role]:
        with self._lock:
            return self._roles.get(name)

    def upsert_role(self, role: Role) -> None:
        with self._lock:
            self._roles[role.name] = role

    def delete_role(self, name: str) -> None:
        with self._lock:
            self._roles.pop(name, None)

    def list_roles(self) -> List[Role]:
        with self._lock:
            return list(self._roles.values())

    def get_principal(self, principal_id: str) -> Optional[Principal]:
        with self._lock:
            return self._principals.get(principal_id)

    def upsert_principal(self, principal: Principal) -> None:
        with self._lock:
            self._principals[principal.id] = principal

    def delete_principal(self, principal_id: str) -> None:
        with self._lock:
            self._principals.pop(principal_id, None)

# -----------------------------------------------------------------------------
# Decision Cache (TTL + LRU)
# -----------------------------------------------------------------------------

class _TTLCache:
    def __init__(self, maxsize: int = 4096, ttl_seconds: float = 2.0):
        self.maxsize = maxsize
        self.ttl = ttl_seconds
        self._lock = threading.RLock()
        self._data: OrderedDict[Tuple, Tuple[float, PolicyDecision]] = OrderedDict()

    def get(self, key: Tuple) -> Optional[PolicyDecision]:
        now = time.time()
        with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            ts, val = item
            if now - ts > self.ttl:
                self._data.pop(key, None)
                return None
            # LRU touch
            self._data.move_to_end(key)
            return val

    def put(self, key: Tuple, val: PolicyDecision) -> None:
        with self._lock:
            self._data[key] = (time.time(), val)
            self._data.move_to_end(key)
            # Evict
            while len(self._data) > self.maxsize:
                self._data.popitem(last=False)

# -----------------------------------------------------------------------------
# RBAC Engine
# -----------------------------------------------------------------------------

def _norm(s: str) -> str:
    return s.strip()

def _split_resource(res: str) -> List[str]:
    # Allow "namespace:type:id" or arbitrary path-like segments
    return [part for part in res.split(":") if part]

def _resource_match(pattern: str, value: str) -> bool:
    # Glob match on the full resource string
    if pattern == value:
        return True
    return fnmatch.fnmatchcase(value, pattern)

def _action_match(pattern: str, value: str) -> bool:
    if pattern == value:
        return True
    return fnmatch.fnmatchcase(value, pattern)

@dataclass
class RBACConfig:
    cache_ttl_s: float = 2.0
    cache_size: int = 8192
    deny_on_error: bool = True  # Fail-safe default deny when evaluation fails

class RBACEngine:
    """
    Deterministic, explainable RBAC engine with DENY override and safe conditions.
    """

    def __init__(
        self,
        store: PolicyStore,
        *,
        metric_sink: Optional[MetricSink] = None,
        trace_sink: Optional[TraceSink] = None,
        audit_sink: Optional[AuditSink] = None,
        config: Optional[RBACConfig] = None,
    ):
        self._store = store
        self._metric = metric_sink
        self._trace = trace_sink
        self._audit = audit_sink
        self._cfg = config or RBACConfig()
        self._cache = _TTLCache(maxsize=self._cfg.cache_size, ttl_seconds=self._cfg.cache_ttl_s)
        self._lock = threading.RLock()

    # --------------------- Public API ---------------------

    def is_allowed(
        self,
        principal_id: str,
        action: str,
        resource: str,
        *,
        ctx: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        """
        Main call: returns PolicyDecision with full explainability.
        """
        key = (principal_id, _norm(action), _norm(resource), self._stable_ctx_key(ctx))
        cached = self._cache.get(key)
        if cached:
            self._metric_incr("rbac.decision.cache.hit")
            return cached

        with self._span("rbac.is_allowed") as span:
            t0 = time.time()
            span.set_tag("principal_id", principal_id)
            span.set_tag("action", action)
            span.set_tag("resource", resource)
            try:
                principal = self._store.get_principal(principal_id)
                if principal is None:
                    self._metric_incr("rbac.principal.missing")
                    decision = self._deny(principal_id, action, resource, reason="principal_not_found")
                    self._cache.put(key, decision)
                    self._audit_decision(decision, ctx)
                    return decision

                flat_perms, role_order = self._collect_permissions(principal.roles)
                matched, allow_hit, deny_hit = self._evaluate_permissions(
                    principal, flat_perms, action, resource, ctx or {}
                )

                if deny_hit:
                    decision = PolicyDecision(
                        allowed=False,
                        effect=Effect.DENY,
                        principal_id=principal_id,
                        action=action,
                        resource=resource,
                        matched=matched,
                        reason="deny_override",
                    )
                elif allow_hit:
                    decision = PolicyDecision(
                        allowed=True,
                        effect=Effect.ALLOW,
                        principal_id=principal_id,
                        action=action,
                        resource=resource,
                        matched=matched,
                        reason="allow_match",
                    )
                else:
                    decision = self._deny(principal_id, action, resource, reason="no_match")

                self._metric_timing("rbac.decision.ms", (time.time() - t0) * 1000.0)
                self._cache.put(key, decision)
                self._audit_decision(decision, ctx)
                return decision
            except Exception as exc:
                logger.exception("RBAC evaluation error")
                self._metric_incr("rbac.decision.error")
                if self._cfg.deny_on_error:
                    decision = self._deny(principal_id, action, resource, reason="engine_error")
                    self._audit_decision(decision, ctx, error=str(exc))
                    return decision
                raise

    # --------------------- Internals ----------------------

    def _collect_permissions(self, role_names: Sequence[str]) -> Tuple[List[Tuple[str, Permission]], List[str]]:
        """
        Resolve roles into a flattened permission list with inheritance.
        Returns:
          - list of (role_name, permission)
          - topologically expanded role order
        """
        visited: Set[str] = set()
        order: List[str] = []
        out: List[Tuple[str, Permission]] = []
        stack: deque[str] = deque(role_names)

        while stack:
            name = stack.popleft()
            if name in visited:
                continue
            role = self._store.get_role(name)
            if role is None:
                logger.warning("RBAC role missing: %s", name)
                continue
            visited.add(name)
            order.append(name)
            for parent in role.parents:
                stack.append(parent)
            for p in role.permissions:
                out.append((role.name, p))

        return out, order

    def _evaluate_permissions(
        self,
        principal: Principal,
        perms: List[Tuple[str, Permission]],
        action: str,
        resource: str,
        ctx: Dict[str, Any],
    ) -> Tuple[List[MatchDetail], bool, bool]:
        """
        Evaluate permissions, returning matched details and whether any ALLOW/DENY hit.
        DENY overrides ALLOW by caller logic.
        """
        matched: List[MatchDetail] = []
        allow_hit = False
        deny_hit = False

        for role_name, perm in perms:
            if not _action_match(perm.action, action):
                continue
            if not _resource_match(perm.resource, resource):
                continue

            cond_result: Optional[bool] = None
            if perm.condition:
                cond_result = safe_eval(perm.condition, principal=principal.attrs, ctx=ctx)
                if not cond_result:
                    # condition explicitly false; not a hit
                    matched.append(MatchDetail(role=role_name, permission=perm,
                                               matched_action=True, matched_resource=True,
                                               condition_result=False))
                    continue

            # We have a hit
            matched.append(MatchDetail(role=role_name, permission=perm,
                                       matched_action=True, matched_resource=True,
                                       condition_result=cond_result))
            if perm.effect == Effect.DENY:
                deny_hit = True
            elif perm.effect == Effect.ALLOW:
                allow_hit = True

        return matched, allow_hit, deny_hit

    def _deny(self, principal_id: str, action: str, resource: str, *, reason: str) -> PolicyDecision:
        return PolicyDecision(
            allowed=False,
            effect=Effect.DENY,
            principal_id=principal_id,
            action=action,
            resource=resource,
            matched=[],
            reason=reason,
        )

    # --------------------- Observability helpers ----------------------

    def _span(self, name: str):
        if self._trace:
            try:
                return self._trace.span(name)
            except Exception:
                pass
        return TraceSpan(name)

    def _metric_incr(self, name: str, value: int = 1, tags: Optional[Dict[str, str]] = None) -> None:
        if self._metric:
            try:
                self._metric.incr(name, value=value, tags=tags)
            except Exception:
                logger.debug("Metric sink incr failed", exc_info=True)

    def _metric_timing(self, name: str, ms: float, tags: Optional[Dict[str, str]] = None) -> None:
        if self._metric:
            try:
                self._metric.timing(name, ms, tags=tags)
            except Exception:
                logger.debug("Metric sink timing failed", exc_info=True)

    def _audit_decision(self, decision: PolicyDecision, ctx: Optional[Dict[str, Any]], error: Optional[str] = None) -> None:
        if not self._audit:
            return
        try:
            payload = {
                "type": "rbac.decision",
                "allowed": decision.allowed,
                "effect": decision.effect.value,
                "principal_id": decision.principal_id,
                "action": decision.action,
                "resource": decision.resource,
                "reason": decision.reason,
                "matched": [
                    {
                        "role": m.role,
                        "permission": {
                            "action": m.permission.action,
                            "resource": m.permission.resource,
                            "effect": m.permission.effect.value,
                            "condition": m.permission.condition,
                            "description": m.permission.description,
                        },
                        "condition_result": m.condition_result,
                    }
                    for m in decision.matched
                ],
                "ctx_keys": sorted(list((ctx or {}).keys())),
                "evaluated_at": decision.evaluated_at,
                "error": error,
            }
            self._audit.record(payload)
        except Exception:
            logger.debug("Audit sink failed", exc_info=True)

    @staticmethod
    def _stable_ctx_key(ctx: Optional[Dict[str, Any]]) -> Tuple:
        """
        Build a stable hashable key from ctx for caching (only simple scalars kept).
        """
        if not ctx:
            return ()
        items: List[Tuple[str, Any]] = []
        for k, v in ctx.items():
            if isinstance(v, (str, int, float, bool, type(None))):
                items.append((k, v))
            else:
                # skip non-scalar for cache key
                continue
        return tuple(sorted(items))

# -----------------------------------------------------------------------------
# Decorator for service integration
# -----------------------------------------------------------------------------

def require(
    engine: RBACEngine,
    action: str,
    resource_getter: Optional[Any] = None,
    *,
    principal_getter: Optional[Any] = None,
    ctx_getter: Optional[Any] = None,
):
    """
    Decorator to enforce RBAC on a handler.

    Parameters:
      - engine: RBACEngine instance
      - action: required action string
      - resource_getter: callable(*args, **kwargs) -> str  (extract resource id from request)
      - principal_getter: callable(*args, **kwargs) -> str (extract principal id)
      - ctx_getter: callable(*args, **kwargs) -> dict     (optional context)

    Usage sketch (framework-agnostic):

        @require(engine, "tx.read", resource_getter=lambda req: f"ledger:tx:{req.path_id}",
                 principal_getter=lambda req: req.user_id, ctx_getter=lambda req: {"ip": req.ip})
        def handler(req): ...

    If access is denied, raises AuthorizationError with structured reason.
    """
    if not callable(resource_getter):
        raise InvalidPolicyError("resource_getter must be callable")
    if not callable(principal_getter):
        raise InvalidPolicyError("principal_getter must be callable")

    def decorator(fn):
        def wrapper(*args, **kwargs):
            res = resource_getter(*args, **kwargs)
            pid = principal_getter(*args, **kwargs)
            ctx = ctx_getter(*args, **kwargs) if callable(ctx_getter) else {}
            decision = engine.is_allowed(pid, action, res, ctx=ctx)
            if not decision.allowed:
                raise AuthorizationError(
                    json.dumps(
                        {
                            "error": "access_denied",
                            "principal_id": pid,
                            "action": action,
                            "resource": res,
                            "reason": decision.reason,
                            "effect": decision.effect.value,
                            "matched": [
                                {"role": m.role, "effect": m.permission.effect.value, "perm_action": m.permission.action,
                                 "perm_resource": m.permission.resource, "condition": m.permission.condition,
                                 "condition_result": m.condition_result}
                                for m in decision.matched
                            ],
                        },
                        ensure_ascii=False,
                    )
                )
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# -----------------------------------------------------------------------------
# Serialization helpers (for backup/migration APIs)
# -----------------------------------------------------------------------------

def role_to_dict(role: Role) -> Dict[str, Any]:
    return {
        "name": role.name,
        "description": role.description,
        "version": role.version,
        "parents": list(role.parents),
        "permissions": [
            {
                "action": p.action,
                "resource": p.resource,
                "effect": p.effect.value,
                "condition": p.condition,
                "description": p.description,
            }
            for p in role.permissions
        ],
    }

def role_from_dict(d: Dict[str, Any]) -> Role:
    try:
        perms = [
            Permission(
                action=p["action"],
                resource=p["resource"],
                effect=Effect(p.get("effect", "ALLOW")),
                condition=p.get("condition"),
                description=p.get("description"),
            )
            for p in d.get("permissions", [])
        ]
        return Role(
            name=d["name"],
            description=d.get("description"),
            version=int(d.get("version", 1)),
            parents=list(d.get("parents", []) or []),
            permissions=perms,
        )
    except Exception as exc:
        raise InvalidPolicyError(f"Invalid role dict: {exc}") from exc

def principal_to_dict(pr: Principal) -> Dict[str, Any]:
    return {"id": pr.id, "roles": list(pr.roles), "attrs": dict(pr.attrs), "version": pr.version}

def principal_from_dict(d: Dict[str, Any]) -> Principal:
    try:
        return Principal(id=d["id"], roles=list(d.get("roles", []) or []), attrs=dict(d.get("attrs", {}) or {}), version=int(d.get("version", 1)))
    except Exception as exc:
        raise InvalidPolicyError(f"Invalid principal dict: {exc}") from exc

# -----------------------------------------------------------------------------
# Example minimal setup (non-executing sketch)
# -----------------------------------------------------------------------------

def _example_setup():
    """
    Minimal illustrative setup to demonstrate structures (do not execute in production flow).
    """
    store = InMemoryPolicyStore()
    # Define roles
    auditor = Role(
        name="auditor",
        permissions=[
            Permission(action="tx.read", resource="ledger:tx:*", effect=Effect.ALLOW),
            Permission(action="account.read", resource="ledger:account:*", effect=Effect.ALLOW,
                       condition="ctx.get('org') == principal.get('org')"),
        ],
        description="Read-only auditor in same org",
    )
    admin = Role(
        name="admin",
        parents=["auditor"],
        permissions=[
            Permission(action="*", resource="ledger:*", effect=Effect.ALLOW),
            Permission(action="tx.delete", resource="ledger:tx:*", effect=Effect.DENY, description="Safety deny"),
        ],
        description="Administrator with explicit safety deny",
    )
    store.upsert_role(auditor)
    store.upsert_role(admin)

    # Bind principal
    store.upsert_principal(Principal(id="u:alice", roles=["auditor"], attrs={"org": "acme"}))

    engine = RBACEngine(store)
    # decision = engine.is_allowed("u:alice", "account.read", "ledger:account:123", ctx={"org": "acme"})

__all__ = [
    "RBACEngine",
    "RBACConfig",
    "PolicyStore",
    "InMemoryPolicyStore",
    "MetricSink",
    "TraceSink",
    "AuditSink",
    "Role",
    "Permission",
    "Principal",
    "Effect",
    "PolicyDecision",
    "MatchDetail",
    "AuthorizationError",
    "RBACError",
    "PolicyStoreError",
    "InvalidPolicyError",
]
