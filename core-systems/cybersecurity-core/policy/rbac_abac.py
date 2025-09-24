# cybersecurity-core/cybersecurity/policy/rbac_abac.py
# Industrial-grade RBAC + ABAC policy engine for Zero-Trust services.
# Python 3.10+
# Optional dependency: prometheus_client (for metrics)
from __future__ import annotations

import ast
import fnmatch
import json
import logging
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    from prometheus_client import Counter, Histogram  # type: ignore
    _PROM = True
except Exception:  # pragma: no cover
    _PROM = False


# =========================
# Logging (structured JSON)
# =========================

_REDACT_KEYS = {"password", "token", "secret", "authorization", "api_key", "x-api-key", "cookie"}
_REDACT_MASK = "******"

def _redact_obj(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: (_REDACT_MASK if str(k).lower() in _REDACT_KEYS else _redact_obj(v)) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        t = type(obj)
        return t(_redact_obj(v) for v in obj)
    return obj

class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = {
            "ts": int(time.time() * 1000),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        extra = getattr(record, "extra", None)
        if isinstance(extra, dict):
            base.update(_redact_obj(extra))
        try:
            return json.dumps(base, ensure_ascii=False, separators=(",", ":"))
        except Exception:
            return f'{base["ts"]} {base["level"]} {base["logger"]} {base["msg"]}'

def _get_logger(name: str = "cybersec.policy") -> logging.Logger:
    lg = logging.getLogger(name)
    if not lg.handlers:
        lg.setLevel(logging.INFO)
        h = logging.StreamHandler()
        h.setFormatter(_JsonFormatter())
        lg.addHandler(h)
        lg.propagate = False
    return lg

LOGGER = _get_logger()


# =========================
# Metrics (optional)
# =========================

if _PROM:
    POLICY_DECISIONS = Counter("policy_decisions_total", "RBAC/ABAC decisions", ["effect", "reason"])
    POLICY_LAT = Histogram("policy_eval_seconds", "Policy evaluation time", buckets=(0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1))
else:  # pragma: no cover
    POLICY_DECISIONS = None
    POLICY_LAT = None


# =========================
# Core models
# =========================

class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"

@dataclass(frozen=True)
class Subject:
    id: str
    roles: frozenset[str] = field(default_factory=frozenset)
    attrs: Mapping[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class Resource:
    type: str
    id: str
    attrs: Mapping[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class Environment:
    attrs: Mapping[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class Decision:
    effect: Effect
    allowed: bool
    reason: str
    obligations: Mapping[str, Any] = field(default_factory=dict)
    rule: Optional[str] = None
    policy_version: str = "0"

class PolicyError(Exception):
    pass

class Forbidden(PolicyError):
    pass


# =========================
# Safe condition compiler (mini-DSL)
# =========================
# Expression variables:
#   s  -> subject.attrs dict, r -> resource.attrs dict, env -> environment.attrs dict
#   sid -> subject.id, rid -> resource.id, rtype -> resource.type
# Allowed operations: and/or/not, comparisons (==, !=, <, <=, >, >=), in/not in,
# attribute access via dict keys s["dept"] or dot-like helper: get(s, "dept")
# Allowed helper funcs: get, regex, startswith, endswith, contains, any_in, all_in, len
# No function calls besides whitelisted.

_ALLOWED_FUNCS: Dict[str, Callable[..., Any]] = {
    "get": lambda d, k, default=None: d.get(k, default) if isinstance(d, Mapping) else default,
    "regex": lambda pattern, value: re.search(pattern, str(value or "")) is not None,
    "startswith": lambda value, prefix: str(value or "").startswith(str(prefix)),
    "endswith": lambda value, suffix: str(value or "").endswith(str(suffix)),
    "contains": lambda container, item: (item in container) if container is not None else False,
    "any_in": lambda items, container: any(i in container for i in (items or [])),
    "all_in": lambda items, container: all(i in container for i in (items or [])),
    "len": lambda x: len(x) if x is not None else 0,
    "now": lambda: int(time.time()),  # epoch seconds
}

_ALLOWED_AST_NODES = {
    ast.Expression, ast.BoolOp, ast.BinOp, ast.UnaryOp, ast.Compare, ast.Name, ast.Load,
    ast.Constant, ast.Subscript, ast.Index, ast.List, ast.Tuple, ast.Dict,
    ast.And, ast.Or, ast.Not, ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
    ast.In, ast.NotIn, ast.Call
}

class Condition:
    def __init__(self, expr: Optional[str] = None, fn: Optional[Callable[[Subject, Resource, Environment], bool]] = None):
        if not expr and not fn:
            # No condition => always true
            self._fn = lambda *_: True
            self.expr = "true"
        elif fn:
            self._fn = fn
            self.expr = getattr(fn, "__name__", "<callable>")
        else:
            self.expr = expr or "true"
            self._fn = self._compile_expr(self.expr)

    def __call__(self, s: Subject, r: Resource, env: Environment) -> bool:
        return bool(self._fn(s, r, env))

    @staticmethod
    def _compile_expr(expr: str) -> Callable[[Subject, Resource, Environment], bool]:
        try:
            tree = ast.parse(expr, mode="eval")
        except SyntaxError as e:
            raise PolicyError(f"Invalid condition syntax: {e}") from e
        # Whitelist nodes
        for node in ast.walk(tree):
            if type(node) not in _ALLOWED_AST_NODES:
                raise PolicyError(f"Disallowed expression element: {type(node).__name__}")
            if isinstance(node, ast.Call):
                if not isinstance(node.func, ast.Name) or node.func.id not in _ALLOWED_FUNCS:
                    raise PolicyError("Only whitelisted helper functions are allowed")
        code = compile(tree, "<cond>", "eval")

        def _fn(s: Subject, r: Resource, env: Environment) -> bool:
            local_vars = {
                "s": dict(s.attrs),
                "sid": s.id,
                "r": dict(r.attrs),
                "rid": r.id,
                "rtype": r.type,
            }
            return bool(eval(code, {"__builtins__": {}}, {**_ALLOWED_FUNCS, **local_vars}))
        return _fn

    @classmethod
    def always(cls) -> "Condition":
        return cls("True")


# =========================
# Policy & Role definitions
# =========================

@dataclass(frozen=True)
class Role:
    name: str
    parents: frozenset[str] = field(default_factory=frozenset)  # inheritance: member of parent roles as well

@dataclass(frozen=True)
class Rule:
    name: str
    effect: Effect
    actions: tuple[str, ...]  # wildcard patterns, e.g., "orders:*", "orders:read"
    resource_types: tuple[str, ...]  # wildcard resource types, e.g., "orders", "docs:*"
    resource_ids: tuple[str, ...] = ()  # optional whitelist/filters with wildcards
    roles: frozenset[str] = field(default_factory=frozenset)  # RBAC gate; empty = any role
    condition: Condition = field(default_factory=Condition.always)  # ABAC condition
    obligations: Mapping[str, Any] = field(default_factory=dict)
    priority: int = 100  # lower evaluated first (deny-overrides regardless)

    def matches(self, subject_roles: frozenset[str], action: str, resource: Resource, env: Environment, resolved_roles: Mapping[str, frozenset[str]]) -> bool:
        # RBAC: if roles specified, subject must have at least one (considering inheritance)
        if self.roles:
            s_all_roles = _expand_roles(subject_roles, resolved_roles)
            if self.roles.isdisjoint(s_all_roles):
                return False
        # Action & resource type
        if not any(fnmatch.fnmatchcase(action, pat) for pat in self.actions):
            return False
        if not any(fnmatch.fnmatchcase(resource.type, pat) for pat in self.resource_types):
            return False
        # Resource id filter if present
        if self.resource_ids and not any(fnmatch.fnmatchcase(resource.id, pat) for pat in self.resource_ids):
            return False
        # ABAC condition
        return self.condition(Subject("<masked>", subject_roles, {}), resource, env) if False else self.condition  # kept for clarity
        # Note: real Subject object with attrs needed; above line replaced below in PDP logic.


# =========================
# Policy store with versioning and thread-safety
# =========================

@dataclass
class Policy:
    version: str
    roles: Dict[str, Role]
    rules: List[Rule]

class RWLock:
    """Simple RW lock for CPython."""
    def __init__(self):
        self._read_ready = threading.Condition(threading.Lock())
        self._readers = 0

    def r_acquire(self):
        with self._read_ready:
            self._readers += 1

    def r_release(self):
        with self._read_ready:
            self._readers -= 1
            if self._readers == 0:
                self._read_ready.notify_all()

    def w_acquire(self):
        self._read_ready.acquire()
        while self._readers > 0:
            self._read_ready.wait()

    def w_release(self):
        self._read_ready.release()

class PolicyStore:
    def __init__(self, policy: Policy):
        self._lock = RWLock()
        self._policy = policy
        # Precompute role closure
        self._role_closure = self._compute_role_closure(policy.roles)

    def get(self) -> Tuple[Policy, Mapping[str, frozenset[str]]]:
        self._lock.r_acquire()
        try:
            return self._policy, self._role_closure
        finally:
            self._lock.r_release()

    def update(self, policy: Policy) -> None:
        self._lock.w_acquire()
        try:
            self._policy = policy
            self._role_closure = self._compute_role_closure(policy.roles)
        finally:
            self._lock.w_release()

    @staticmethod
    def _compute_role_closure(roles: Mapping[str, Role]) -> Dict[str, frozenset[str]]:
        # For each role, compute set including itself and all ancestors
        closure: Dict[str, frozenset[str]] = {}
        cache: Dict[str, frozenset[str]] = {}

        def expand(name: str, stack: Optional[set[str]] = None) -> frozenset[str]:
            if name in cache:
                return cache[name]
            if name not in roles:
                cache[name] = frozenset({name})
                return cache[name]
            stack = stack or set()
            if name in stack:
                raise PolicyError(f"Role cycle detected at {name}")
            stack.add(name)
            parents = roles[name].parents
            acc: set[str] = {name}
            for p in parents:
                acc.update(expand(p, stack))
            stack.remove(name)
            cache[name] = frozenset(acc)
            return cache[name]

        for r in roles.keys():
            closure[r] = expand(r)
        return closure


# =========================
# PDP with deny-overrides + decision cache (TTL)
# =========================

@dataclass
class _CacheEntry:
    decision: Decision
    expire_at: float

class PDP:
    def __init__(self, store: PolicyStore, *, ttl_seconds: float = 2.0, cache_size: int = 10000):
        self._store = store
        self._ttl = float(ttl_seconds)
        self._cache_size = int(cache_size)
        self._cache: Dict[Tuple[str, str, str, str], _CacheEntry] = {}
        self._cache_lock = threading.Lock()

    def evaluate(self, subject: Subject, resource: Resource, action: str, env: Optional[Environment] = None, *, request_id: Optional[str] = None) -> Decision:
        env = env or Environment({})
        req_id = request_id or str(uuid.uuid4())
        t0 = time.perf_counter()

        # Cache key: subject.id, resource.type, action, policy_version (attrs excluded to avoid stale PII; TTL small)
        policy, role_closure = self._store.get()
        cache_key = (subject.id, resource.type + ":" + resource.id, action, policy.version)
        now = time.monotonic()

        with self._cache_lock:
            entry = self._cache.get(cache_key)
            if entry and entry.expire_at > now:
                dec = entry.decision
                self._emit_metrics(dec, t0)
                LOGGER.info("policy.decision.cached", extra={"extra": {
                    "request_id": req_id, "subject": subject.id, "action": action, "resource": f"{resource.type}:{resource.id}",
                    "effect": dec.effect.value, "reason": dec.reason, "policy_version": policy.version
                }})
                return dec

        # Sort rules by priority asc; deny-overrides: any matching DENY wins immediately
        rules = sorted(policy.rules, key=lambda r: r.priority)
        allow_best: Optional[Decision] = None

        for rule in rules:
            # RBAC gate + action/type/id match
            if not _rule_static_match(rule, subject.roles, action, resource, role_closure):
                continue
            # ABAC condition
            if not rule.condition(subject, resource, env):
                continue

            reason = f"rule:{rule.name}"
            if rule.effect is Effect.DENY:
                dec = Decision(effect=Effect.DENY, allowed=False, reason=reason, obligations=rule.obligations, rule=rule.name, policy_version=policy.version)
                self._cache_put(cache_key, dec)
                self._emit_metrics(dec, t0)
                LOGGER.info("policy.decision", extra={"extra": {
                    "request_id": req_id, "subject": subject.id, "roles": sorted(subject.roles),
                    "action": action, "resource": f"{resource.type}:{resource.id}",
                    "effect": "deny", "rule": rule.name, "policy_version": policy.version
                }})
                return dec
            else:
                # Keep first (highest priority) allow
                if allow_best is None:
                    allow_best = Decision(effect=Effect.ALLOW, allowed=True, reason=reason, obligations=rule.obligations, rule=rule.name, policy_version=policy.version)
                # do not break; a lower-priority deny could still appear (deny-overrides)

        # Finalize
        dec = allow_best or Decision(effect=Effect.DENY, allowed=False, reason="default_deny", policy_version=policy.version)
        self._cache_put(cache_key, dec)
        self._emit_metrics(dec, t0)
        LOGGER.info("policy.decision", extra={"extra": {
            "request_id": req_id, "subject": subject.id, "roles": sorted(subject.roles),
            "action": action, "resource": f"{resource.type}:{resource.id}",
            "effect": dec.effect.value, "rule": dec.rule, "policy_version": policy.version
        }})
        return dec

    def enforce_or_raise(self, subject: Subject, resource: Resource, action: str, env: Optional[Environment] = None, *, request_id: Optional[str] = None) -> Decision:
        dec = self.evaluate(subject, resource, action, env, request_id=request_id)
        if not dec.allowed:
            raise Forbidden(f"Access denied: {dec.reason}")
        return dec

    def _cache_put(self, key: Tuple[str, str, str, str], dec: Decision) -> None:
        with self._cache_lock:
            if len(self._cache) >= self._cache_size:
                # simple random eviction
                self._cache.pop(next(iter(self._cache)))
            self._cache[key] = _CacheEntry(decision=dec, expire_at=time.monotonic() + self._ttl)

    @staticmethod
    def _emit_metrics(dec: Decision, t0: float) -> None:
        if not _PROM:
            return
        try:
            if POLICY_DECISIONS:
                POLICY_DECISIONS.labels(dec.effect.value, dec.reason or "").inc()
            if POLICY_LAT:
                POLICY_LAT.observe(max(0.0, time.perf_counter() - t0))
        except Exception:
            pass


# =========================
# Helpers
# =========================

def _expand_roles(subject_roles: frozenset[str], closure: Mapping[str, frozenset[str]]) -> frozenset[str]:
    acc: set[str] = set()
    for r in subject_roles:
        acc.add(r)
        if r in closure:
            acc.update(closure[r])
    return frozenset(acc)

def _rule_static_match(rule: Rule, subj_roles: frozenset[str], action: str, resource: Resource, closure: Mapping[str, frozenset[str]]) -> bool:
    # Roles
    if rule.roles:
        s_all = _expand_roles(subj_roles, closure)
        if rule.roles.isdisjoint(s_all):
            return False
    # Action
    if rule.actions and not any(fnmatch.fnmatchcase(action, a) for a in rule.actions):
        return False
    # Resource type and id
    if rule.resource_types and not any(fnmatch.fnmatchcase(resource.type, t) for t in rule.resource_types):
        return False
    if rule.resource_ids and not any(fnmatch.fnmatchcase(resource.id, rid) for rid in rule.resource_ids):
        return False
    return True


# =========================
# Builders / Loaders
# =========================

def build_role(name: str, parents: Iterable[str] | None = None) -> Role:
    return Role(name=name, parents=frozenset(parents or []))

def build_rule(
    name: str,
    *,
    effect: str,
    actions: Sequence[str],
    resource_types: Sequence[str],
    resource_ids: Sequence[str] | None = None,
    roles: Iterable[str] | None = None,
    condition: str | Condition | None = None,
    obligations: Mapping[str, Any] | None = None,
    priority: int = 100,
) -> Rule:
    eff = Effect.ALLOW if effect.lower() == "allow" else Effect.DENY
    cond = condition if isinstance(condition, Condition) else (Condition(condition) if condition else Condition.always())
    return Rule(
        name=name,
        effect=eff,
        actions=tuple(actions),
        resource_types=tuple(resource_types),
        resource_ids=tuple(resource_ids or ()),
        roles=frozenset(roles or []),
        condition=cond,
        obligations=obligations or {},
        priority=int(priority),
    )

def policy_from_dict(doc: Mapping[str, Any]) -> Policy:
    """
    YAML/JSON structure example:
    version: "2025-09-03"
    roles:
      admin: {parents: [user]}
      user: {parents: []}
    rules:
      - name: deny_deleted_docs
        effect: deny
        actions: ["docs:*"]
        resource_types: ["docs"]
        condition: 'get(r, "status") == "deleted"'
        priority: 10
      - name: allow_own_doc_read
        effect: allow
        actions: ["docs:read"]
        resource_types: ["docs"]
        roles: ["user"]
        condition: 'get(r, "owner_id") == sid'
        priority: 50
      - name: allow_admin_all
        effect: allow
        actions: ["*"]
        resource_types: ["*"]
        roles: ["admin"]
        priority: 100
    """
    version = str(doc.get("version") or str(int(time.time())))
    roles_doc = doc.get("roles") or {}
    rules_doc = doc.get("rules") or []

    roles: Dict[str, Role] = {}
    for name, r in roles_doc.items():
        parents = r.get("parents") or []
        roles[name] = build_role(name, parents)

    rules: List[Rule] = []
    for r in rules_doc:
        rules.append(build_rule(
            name=r["name"],
            effect=r["effect"],
            actions=r.get("actions", ["*"]),
            resource_types=r.get("resource_types", ["*"]),
            resource_ids=r.get("resource_ids"),
            roles=r.get("roles"),
            condition=r.get("condition"),
            obligations=r.get("obligations"),
            priority=r.get("priority", 100),
        ))

    return Policy(version=version, roles=roles, rules=rules)


# =========================
# Example of default policy (safe to remove/override)
# =========================

DEFAULT_POLICY = policy_from_dict({
    "version": "1",
    "roles": {
        "admin": {"parents": ["user"]},
        "user": {"parents": []},
        "auditor": {"parents": []},
    },
    "rules": [
        # Global security guardrails
        {
            "name": "deny_blocked_users",
            "effect": "deny",
            "actions": ["*"],
            "resource_types": ["*"],
            "condition": 'get(s, "blocked", False) == True',
            "priority": 1,
        },
        # SoD: user cannot approve their own request
        {
            "name": "deny_self_approve",
            "effect": "deny",
            "actions": ["requests:approve"],
            "resource_types": ["requests"],
            "condition": 'get(r, "created_by") == sid',
            "priority": 5,
        },
        # Auditors: read-only across domains
        {
            "name": "allow_auditor_read",
            "effect": "allow",
            "actions": ["*:read", "*:list", "*:export"],
            "resource_types": ["*"],
            "roles": ["auditor"],
            "priority": 40,
        },
        # Users: read own documents
        {
            "name": "allow_user_read_own_docs",
            "effect": "allow",
            "actions": ["docs:read", "docs:list"],
            "resource_types": ["docs"],
            "roles": ["user"],
            "condition": 'get(r, "owner_id") == sid',
            "priority": 50,
        },
        # Admins: full access
        {
            "name": "allow_admin_all",
            "effect": "allow",
            "actions": ["*"],
            "resource_types": ["*"],
            "roles": ["admin"],
            "priority": 100,
        },
    ]
})


# =========================
# Factory for ready-to-use PDP
# =========================

def new_pdp(policy: Policy | None = None, *, ttl_seconds: float = 2.0, cache_size: int = 10000) -> PDP:
    store = PolicyStore(policy or DEFAULT_POLICY)
    return PDP(store, ttl_seconds=ttl_seconds, cache_size=cache_size)


# =========================
# Minimal inline tests (can be removed)
# =========================

if __name__ == "__main__":  # pragma: no cover
    pdp = new_pdp()
    subj_admin = Subject(id="u1", roles=frozenset({"admin"}), attrs={"dept": "it"})
    subj_user = Subject(id="u2", roles=frozenset({"user"}), attrs={"dept": "sales"})
    res_doc_u2 = Resource(type="docs", id="d42", attrs={"owner_id": "u2", "status": "active"})
    res_doc_deleted = Resource(type="docs", id="d9", attrs={"owner_id": "u2", "status": "deleted"})
    env = Environment(attrs={"ip": "10.0.0.5"})

    # 1) Deleted doc must be denied to anyone
    dec = pdp.evaluate(subj_admin, res_doc_deleted, "docs:read", env)
    print(dec)

    # 2) User reads own doc -> allow
    dec = pdp.evaluate(subj_user, res_doc_u2, "docs:read", env)
    print(dec)

    # 3) User approves own request -> deny
    req = Resource(type="requests", id="r1", attrs={"created_by": "u2"})
    dec = pdp.evaluate(subj_user, req, "requests:approve", env)
    print(dec)
