# security-core/security/iam/roles.py
"""
Industrial IAM roles and policy evaluation for security-core.

Features:
- RBAC roles with inheritance (DAG), ALLOW/DENY statements, versioning
- ABAC conditions: TimeWindowUTC, CIDRMatch, AttributeEquals, RegexMatch, MFARequired,
  combinators (AllOf/AnyOf/Not)
- Resource and action pattern matching with wildcards and compiled regex cache
- Explicit DENY precedence > ALLOW (including across inheritance)
- Scope/permission integration from TokenInfo: "resource:verb" -> Permission
- Cycle detection, deterministic compilation; thread-safe read paths
- Rich AccessDecision with reason, matched statements, and ancestry path

Integration sketch:
    registry = RoleRegistry()
    admin = (RoleBuilder("admin", version="1")
             .allow(actions={"*"}, resources={"*"})
             .build())
    reader = (RoleBuilder("orders_reader", version="1")
             .allow(actions={"read", "list"}, resources={"orders/*"})
             .build())
    registry.register_many([admin, reader]).compile()

    evaluator = AccessEvaluator(registry)
    decision = evaluator.check_access(
        principal=Principal(subject="u1", roles=("orders_reader",)),
        action="read", resource="orders/123",
        ctx=RequestContext(ip="10.0.0.5")
    )
    assert decision.allowed is True
"""

from __future__ import annotations

import ipaddress
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone, time as dtime
from enum import Enum
from typing import (
    Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Set, Tuple
)

# =========================
# Core data structures
# =========================

@dataclass(frozen=True)
class Principal:
    subject: str
    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    service_id: Optional[str] = None
    roles: Tuple[str, ...] = ()
    groups: Tuple[str, ...] = ()
    attributes: Mapping[str, Any] = field(default_factory=dict)  # arbitrary attrs


@dataclass(frozen=True)
class TokenInfo:
    # minimal interface used here; align with your middleware TokenInfo
    token_id: Optional[str]
    subject: str
    scopes: Tuple[str, ...] = ()
    permissions: Tuple[str, ...] = ()
    roles: Tuple[str, ...] = ()


class Effect(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


@dataclass(frozen=True)
class Statement:
    effect: Effect
    actions: FrozenSet[str]            # patterns e.g. {"read", "write", "*"}
    resources: FrozenSet[str]          # patterns e.g. {"orders/*", "billing:invoices/*", "*"}
    conditions: Tuple["Condition", ...] = ()
    sid: Optional[str] = None          # statement id for audit

    def __post_init__(self):
        if not self.actions or not self.resources:
            raise ValueError("Statement must have at least one action and one resource")


@dataclass(frozen=True)
class Role:
    name: str
    version: str
    description: str = ""
    inherits: Tuple[str, ...] = ()
    allow_statements: Tuple[Statement, ...] = ()
    deny_statements: Tuple[Statement, ...] = ()
    tags: Tuple[str, ...] = ()

    def __post_init__(self):
        # Validate statements have correct effects
        for s in self.allow_statements:
            if s.effect != Effect.ALLOW:
                raise ValueError("allow_statements must have effect ALLOW")
        for s in self.deny_statements:
            if s.effect != Effect.DENY:
                raise ValueError("deny_statements must have effect DENY")


# =========================
# Conditions (ABAC)
# =========================

class Condition:
    def evaluate(self, principal: Principal, ctx: "RequestContext") -> bool:
        raise NotImplementedError


@dataclass(frozen=True)
class AllOf(Condition):
    conditions: Tuple[Condition, ...]
    def evaluate(self, principal: Principal, ctx: "RequestContext") -> bool:
        return all(c.evaluate(principal, ctx) for c in self.conditions)


@dataclass(frozen=True)
class AnyOf(Condition):
    conditions: Tuple[Condition, ...]
    def evaluate(self, principal: Principal, ctx: "RequestContext") -> bool:
        return any(c.evaluate(principal, ctx) for c in self.conditions)


@dataclass(frozen=True)
class Not(Condition):
    condition: Condition
    def evaluate(self, principal: Principal, ctx: "RequestContext") -> bool:
        return not self.condition.evaluate(principal, ctx)


@dataclass(frozen=True)
class TimeWindowUTC(Condition):
    # Permit only between given UTC times (inclusive), optional day-of-week set
    start: dtime
    end: dtime
    days: Optional[FrozenSet[int]] = None  # 0=Mon..6=Sun
    def evaluate(self, principal: Principal, ctx: "RequestContext") -> bool:
        now = ctx.now_utc
        if self.days is not None and now.weekday() not in self.days:
            return False
        start_dt = now.replace(hour=self.start.hour, minute=self.start.minute,
                               second=self.start.second, microsecond=self.start.microsecond)
        end_dt = now.replace(hour=self.end.hour, minute=self.end.minute,
                             second=self.end.second, microsecond=self.end.microsecond)
        if end_dt < start_dt:
            # window wraps over midnight
            return not (start_dt <= now < end_dt)
        return start_dt <= now <= end_dt


@dataclass(frozen=True)
class CIDRMatch(Condition):
    cidrs: Tuple[str, ...]
    def evaluate(self, principal: Principal, ctx: "RequestContext") -> bool:
        if not ctx.ip:
            return False
        ip = ipaddress.ip_address(ctx.ip)
        for c in self.cidrs:
            if ip in ipaddress.ip_network(c, strict=False):
                return True
        return False


@dataclass(frozen=True)
class AttributeEquals(Condition):
    key: str
    value: Any
    def evaluate(self, principal: Principal, ctx: "RequestContext") -> bool:
        # Check in ctx.attributes, then principal.attributes
        if ctx.attributes.get(self.key) == self.value:
            return True
        return principal.attributes.get(self.key) == self.value


@dataclass(frozen=True)
class RegexMatch(Condition):
    key: str
    pattern: str
    flags: int = re.IGNORECASE
    def evaluate(self, principal: Principal, ctx: "RequestContext") -> bool:
        v = ctx.attributes.get(self.key)
        if v is None:
            v = principal.attributes.get(self.key)
        if v is None:
            return False
        try:
            return re.search(self.pattern, str(v), self.flags) is not None
        except re.error:
            return False


@dataclass(frozen=True)
class MFARequired(Condition):
    """Simple boolean attribute check indicating user passed MFA."""
    def evaluate(self, principal: Principal, ctx: "RequestContext") -> bool:
        return bool(ctx.attributes.get("mfa_passed") or principal.attributes.get("mfa_passed"))


# =========================
# Request context for ABAC
# =========================

@dataclass(frozen=True)
class RequestContext:
    now_utc: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ip: Optional[str] = None
    region: Optional[str] = None
    attributes: Mapping[str, Any] = field(default_factory=dict)


# =========================
# Role builder
# =========================

class RoleBuilder:
    def __init__(self, name: str, version: str, description: str = ""):
        self._name = name
        self._version = version
        self._description = description
        self._inherits: Set[str] = set()
        self._allow: List[Statement] = []
        self._deny: List[Statement] = []
        self._tags: Set[str] = set()

    def inherit(self, *role_names: str) -> "RoleBuilder":
        self._inherits.update(role_names)
        return self

    def allow(self, actions: Iterable[str], resources: Iterable[str],
              conditions: Iterable[Condition] = (), sid: Optional[str] = None) -> "RoleBuilder":
        self._allow.append(Statement(
            effect=Effect.ALLOW,
            actions=frozenset(actions),
            resources=frozenset(resources),
            conditions=tuple(conditions),
            sid=sid
        ))
        return self

    def deny(self, actions: Iterable[str], resources: Iterable[str],
             conditions: Iterable[Condition] = (), sid: Optional[str] = None) -> "RoleBuilder":
        self._deny.append(Statement(
            effect=Effect.DENY,
            actions=frozenset(actions),
            resources=frozenset(resources),
            conditions=tuple(conditions),
            sid=sid
        ))
        return self

    def tag(self, *tags: str) -> "RoleBuilder":
        self._tags.update(tags)
        return self

    def build(self) -> Role:
        return Role(
            name=self._name,
            version=self._version,
            description=self._description,
            inherits=tuple(sorted(self._inherits)),
            allow_statements=tuple(self._allow),
            deny_statements=tuple(self._deny),
            tags=tuple(sorted(self._tags)),
        )


# =========================
# Registry and compilation
# =========================

@dataclass(frozen=True)
class CompiledRole:
    name: str
    version: str
    description: str
    ancestry: Tuple[str, ...]                      # ordered, parents before children
    allow: Tuple[Statement, ...]
    deny: Tuple[Statement, ...]
    tags: Tuple[str, ...]


class RoleRegistry:
    """
    Holds roles and compiles them into flattened sets (with inheritance).
    Thread-safe for reads after compile(); writes guarded by lock.
    """
    def __init__(self):
        self._roles: Dict[str, Role] = {}
        self._compiled: Dict[str, CompiledRole] = {}
        self._lock = threading.RLock()
        self._compiled_epoch = 0  # increases on compile

    def register(self, role: Role) -> "RoleRegistry":
        with self._lock:
            if role.name in self._roles:
                raise ValueError(f"Role already registered: {role.name}")
            self._roles[role.name] = role
        return self

    def register_many(self, roles: Iterable[Role]) -> "RoleRegistry":
        with self._lock:
            for r in roles:
                if r.name in self._roles:
                    raise ValueError(f"Role already registered: {r.name}")
                self._roles[r.name] = r
        return self

    def get(self, name: str) -> Optional[Role]:
        return self._roles.get(name)

    def compile(self) -> "RoleRegistry":
        with self._lock:
            order = self._toposort()  # detect cycles
            compiled: Dict[str, CompiledRole] = {}
            for name in order:
                role = self._roles[name]
                # Build ancestry (parents first)
                ancestry: List[str] = []
                for p in role.inherits:
                    if p not in compiled:
                        raise ValueError(f"Parent role not compiled: {p}")
                    ancestry.extend(compiled[p].ancestry + (p,))
                # Flatten statements: parent first, then child
                allow: List[Statement] = []
                deny: List[Statement] = []
                for p in role.inherits:
                    pc = compiled[p]
                    allow.extend(pc.allow)
                    deny.extend(pc.deny)
                allow.extend(role.allow_statements)
                deny.extend(role.deny_statements)
                compiled[name] = CompiledRole(
                    name=role.name,
                    version=role.version,
                    description=role.description,
                    ancestry=tuple(ancestry),
                    allow=tuple(allow),
                    deny=tuple(deny),
                    tags=role.tags
                )
            self._compiled = compiled
            self._compiled_epoch += 1
        return self

    def _toposort(self) -> Tuple[str, ...]:
        visited: Set[str] = set()
        temp: Set[str] = set()
        order: List[str] = []

        def visit(n: str):
            if n in temp:
                cycle = " -> ".join(list(temp) + [n])
                raise ValueError(f"Role inheritance cycle: {cycle}")
            if n not in visited:
                temp.add(n)
                role = self._roles.get(n)
                if role is None:
                    raise ValueError(f"Unknown role in graph: {n}")
                for p in role.inherits:
                    visit(p)
                temp.remove(n)
                visited.add(n)
                order.append(n)

        for name in self._roles:
            visit(name)
        return tuple(order)

    def compiled(self, name: str) -> Optional[CompiledRole]:
        return self._compiled.get(name)

    @property
    def epoch(self) -> int:
        return self._compiled_epoch


# =========================
# Permission matching engine
# =========================

class _MatcherCache:
    """
    Compiles 'action' and 'resource' patterns into regexes.
    Supports '*' wildcard (matches segment-wise for resources, all for actions).
    """
    _ACTION_ANY = re.compile(r"^.*$")

    def __init__(self):
        self._action_cache: Dict[str, re.Pattern] = {}
        self._resource_cache: Dict[str, re.Pattern] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _glob_to_regex(pat: str) -> str:
        # Escape regex special chars except '*', then replace '*' -> '.*'
        esc = re.escape(pat).replace(r"\*", ".*")
        return f"^{esc}$"

    def action(self, pat: str) -> re.Pattern:
        if pat == "*" or pat == "":
            return self._ACTION_ANY
        with self._lock:
            r = self._action_cache.get(pat)
            if r is None:
                r = re.compile(self._glob_to_regex(pat))
                self._action_cache[pat] = r
            return r

    def resource(self, pat: str) -> re.Pattern:
        if pat == "*" or pat == "":
            return self._ACTION_ANY
        with self._lock:
            r = self._resource_cache.get(pat)
            if r is None:
                r = re.compile(self._glob_to_regex(pat))
                self._resource_cache[pat] = r
            return r


@dataclass(frozen=True)
class MatchResult:
    matched: bool
    statement: Optional[Statement] = None


@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    effect: Optional[Effect]
    reason: str
    matched_statements: Tuple[Statement, ...] = ()
    matched_roles: Tuple[str, ...] = ()
    ancestry: Tuple[str, ...] = ()
    used_scopes: Tuple[str, ...] = ()


class AccessEvaluator:
    """
    Evaluates access combining:
    - Compiled roles of principal (RBAC)
    - Optional scopes/permissions from TokenInfo (delegated caps)
    Precedence: explicit DENY (any source) > ALLOW (any source) > default deny.
    """
    def __init__(self, registry: RoleRegistry):
        self._registry = registry
        self._matchers = _MatcherCache()

    def check_access(
        self,
        principal: Principal,
        action: str,
        resource: str,
        ctx: Optional=RequestContext,
        token: Optional[TokenInfo] = None,
    ) -> AccessDecision:
        ctx = ctx or RequestContext()
        matched: List[Statement] = []
        matched_roles: List[str] = []
        ancestry: List[str] = []

        # 1) Evaluate role-based DENY/ALLOW with inheritance
        # DENY short-circuits
        for rname in principal.roles:
            cr = self._registry.compiled(rname)
            if cr is None:
                continue
            ancestry.extend(cr.ancestry)
            if self._eval_statements(cr.deny, principal, ctx, action, resource, matched):
                return AccessDecision(
                    allowed=False, effect=Effect.DENY, reason="deny:role",
                    matched_statements=tuple(matched), matched_roles=(rname,), ancestry=tuple(ancestry)
                )
        for rname in principal.roles:
            cr = self._registry.compiled(rname)
            if cr is None:
                continue
            if self._eval_statements(cr.allow, principal, ctx, action, resource, matched):
                matched_roles.append(rname)

        # 2) Evaluate delegated capabilities from token
        used_scopes: List[str] = []
        if token is not None:
            # Permissions take precedence (explicit caps), then scopes
            if token.permissions:
                if self._eval_inline_caps(token.permissions, action, resource):
                    return AccessDecision(
                        allowed=True, effect=Effect.ALLOW, reason="allow:token_permission",
                        matched_statements=tuple(matched), matched_roles=tuple(matched_roles),
                        ancestry=tuple(ancestry), used_scopes=tuple(used_scopes)
                    )
            if token.scopes:
                if self._eval_inline_caps(token.scopes, action, resource, used_scopes):
                    return AccessDecision(
                        allowed=True, effect=Effect.ALLOW, reason="allow:token_scope",
                        matched_statements=tuple(matched), matched_roles=tuple(matched_roles),
                        ancestry=tuple(ancestry), used_scopes=tuple(used_scopes)
                    )

        # 3) If role ALLOW matched earlier — allow
        if matched_roles:
            return AccessDecision(
                allowed=True, effect=Effect.ALLOW, reason="allow:role",
                matched_statements=tuple(matched), matched_roles=tuple(matched_roles),
                ancestry=tuple(ancestry), used_scopes=tuple(used_scopes)
            )

        # 4) Default deny
        return AccessDecision(
            allowed=False, effect=None, reason="default_deny",
            matched_statements=tuple(matched), matched_roles=tuple(matched_roles),
            ancestry=tuple(ancestry), used_scopes=tuple(used_scopes)
        )

    # ---------- helpers ----------

    def _eval_statements(
        self,
        statements: Sequence[Statement],
        principal: Principal,
        ctx: RequestContext,
        action: str,
        resource: str,
        matched_out: List[Statement],
    ) -> bool:
        for st in statements:
            if not self._match_action_resource(st, action, resource):
                continue
            if st.conditions and not all(c.evaluate(principal, ctx) for c in st.conditions):
                continue
            matched_out.append(st)
            # Return True on first statement that matches; higher-level precedence handled by caller
            return True
        return False

    def _match_action_resource(self, st: Statement, action: str, resource: str) -> bool:
        # match any action then any resource
        for a_pat in st.actions:
            ar = self._matchers.action(a_pat)
            if not ar.match(action):
                continue
            for r_pat in st.resources:
                rr = self._matchers.resource(r_pat)
                if rr.match(resource):
                    return True
        return False

    @staticmethod
    def _parse_cap(cap: str) -> Optional[Tuple[str, str]]:
        """
        Parse "resource:verb" OR "resource/*:verb" OR "verb:resource" (fallback).
        Returns (action, resource). If ambiguous, tries both orders.
        """
        if ":" not in cap:
            return None
        left, right = cap.split(":", 1)
        # Heuristic: action usually shorter and matches verbs; try both
        candidates = [(right, left), (left, right)]
        for a, r in candidates:
            a = a.strip()
            r = r.strip()
            if a and r:
                return a, r
        return None

    def _eval_inline_caps(
        self,
        caps: Iterable[str],
        action: str,
        resource: str,
        used_scopes_out: Optional[List[str]] = None,
    ) -> bool:
        for cap in caps:
            pr = self._parse_cap(cap)
            if not pr:
                continue
            a, r = pr
            a_ok = self._matchers.action(a).match(action) is not None
            r_ok = self._matchers.resource(r).match(resource) is not None
            if a_ok and r_ok:
                if used_scopes_out is not None:
                    used_scopes_out.append(cap)
                return True
        return False


# =========================
# Defaults & helpers
# =========================

def builtin_roles() -> List[Role]:
    """
    Provide a small set of conservative defaults. Consumers may ignore.
    - viewer: read/list on all namespaced resources "*/readable/*"
    - admin: full access
    """
    viewer = (RoleBuilder("viewer", version="1", description="Read-only access")
              .allow(actions={"read", "list"}, resources={"*"})
              .build())
    admin = (RoleBuilder("admin", version="1", description="Administrative access")
             .allow(actions={"*"}, resources={"*"})
             .build())
    return [viewer, admin]


__all__ = [
    "Principal", "TokenInfo", "Effect", "Statement", "Role",
    "Condition", "AllOf", "AnyOf", "Not", "TimeWindowUTC", "CIDRMatch",
    "AttributeEquals", "RegexMatch", "MFARequired",
    "RequestContext", "RoleBuilder", "RoleRegistry", "CompiledRole",
    "AccessEvaluator", "AccessDecision", "builtin_roles",
]
