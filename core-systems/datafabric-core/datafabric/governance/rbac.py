# -*- coding: utf-8 -*-
"""
Industrial-grade async RBAC core for DataFabric.

Features:
- Roles with inheritance
- Policies (ALLOW/DENY) with resource patterns and conditions (predicates)
- Explicit DENY precedence
- Async storage abstraction + in-memory implementation with fine-grained locking
- TTL decision cache with version-based invalidation
- Structured audit hook
- Strict typing and defensive validations
- No external dependencies

Usage:
    service = RBACService(store=InMemoryPolicyStore())
    await service.create_role("admin")
    await service.add_policy(
        role="admin",
        policy=Policy.new_allow(resource="projects/*", actions={"read", "write"})
    )
    decision = await service.check_access(
        subject=Subject(id="u1", attributes={"dept": "it"}, roles={"admin"}),
        action="write",
        resource="projects/alpha",
        context={"ip": "10.0.0.1"}
    )
    if decision.allowed:
        ...
"""

from __future__ import annotations

import asyncio
import fnmatch
import logging
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Iterable,
    List,
    MutableMapping,
    Optional,
    Set,
    Tuple,
)


# ----------------------------- Logging setup ---------------------------------

logger = logging.getLogger("datafabric.rbac")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


# ------------------------------ Exceptions -----------------------------------

class RBACError(Exception):
    """Base class for RBAC errors."""


class ValidationError(RBACError):
    """Input/consistency validation error."""


class NotFoundError(RBACError):
    """Entity not found in store."""


class ConflictError(RBACError):
    """Conflicting operation (e.g., duplicate role)."""


# ------------------------------- Enums ---------------------------------------

class Effect(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class DecisionType(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    NOT_APPLICABLE = "NOT_APPLICABLE"


# ----------------------------- Data Models -----------------------------------

Condition = Callable[[Dict[str, Any], Dict[str, Any]], bool]
# condition(subject_attributes, context) -> bool

def _validate_name(name: str, kind: str) -> None:
    if not name or not isinstance(name, str):
        raise ValidationError(f"{kind} name must be a non-empty string.")
    if any(ch in name for ch in " \t\r\n"):
        raise ValidationError(f"{kind} name must not contain whitespace: {name!r}")


@dataclass(frozen=True)
class Policy:
    """
    Policy defines an effect for actions on resource pattern, guarded by optional condition.

    - resource: glob-style mask (e.g., 'projects/*', 'db/*/table/*')
    - actions: set of action strings
    - effect: ALLOW or DENY
    - condition: optional predicate(subject_attrs, context) -> bool
    - description: free text for auditability
    """
    id: str
    resource: str
    actions: FrozenSet[str]
    effect: Effect
    condition: Optional[Condition] = None
    description: str = ""

    def __post_init__(self):
        if not self.resource:
            raise ValidationError("Policy.resource must be non-empty.")
        if not self.actions:
            raise ValidationError("Policy.actions must be non-empty.")
        for a in self.actions:
            if not a or not isinstance(a, str):
                raise ValidationError("Actions must be non-empty strings.")

    @staticmethod
    def new_allow(resource: str, actions: Iterable[str], *, condition: Optional[Condition] = None, description: str = "") -> "Policy":
        return Policy(
            id=str(uuid.uuid4()),
            resource=resource,
            actions=frozenset(set(actions)),
            effect=Effect.ALLOW,
            condition=condition,
            description=description,
        )

    @staticmethod
    def new_deny(resource: str, actions: Iterable[str], *, condition: Optional[Condition] = None, description: str = "") -> "Policy":
        return Policy(
            id=str(uuid.uuid4()),
            resource=resource,
            actions=frozenset(set(actions)),
            effect=Effect.DENY,
            condition=condition,
            description=description,
        )


@dataclass
class Role:
    """
    Role groups policies and may inherit from parent roles.
    Inheritance is additive: policies of parents apply to the role.
    """
    name: str
    policies: Dict[str, Policy] = field(default_factory=dict)  # policy_id -> Policy
    parents: Set[str] = field(default_factory=set)

    def __post_init__(self):
        _validate_name(self.name, "Role")

    def add_policy(self, policy: Policy) -> None:
        if policy.id in self.policies:
            raise ConflictError(f"Policy {policy.id} already exists in role {self.name}.")
        self.policies[policy.id] = policy

    def remove_policy(self, policy_id: str) -> None:
        if policy_id not in self.policies:
            raise NotFoundError(f"Policy {policy_id} not found in role {self.name}.")
        del self.policies[policy_id]


@dataclass(frozen=True)
class Subject:
    """
    Subject is an access requester (human, service, agent).
    - id: stable identifier
    - attributes: arbitrary subject attributes (dept, clearance, tags)
    - roles: attached role names (direct, not expanded)
    """
    id: str
    attributes: Dict[str, Any]
    roles: FrozenSet[str] = field(default_factory=frozenset)

    def __post_init__(self):
        if not self.id:
            raise ValidationError("Subject.id must be non-empty.")


# ----------------------------- Audit Models ----------------------------------

@dataclass(frozen=True)
class AuditEvent:
    subject_id: str
    action: str
    resource: str
    decision: DecisionType
    reason: str
    context: Dict[str, Any]
    timestamp: float = field(default_factory=lambda: time.time())


class Auditor(ABC):
    """Audit hook interface."""

    @abstractmethod
    async def emit(self, event: AuditEvent) -> None:
        ...


class LoggingAuditor(Auditor):
    """Default auditor writing to logger."""

    def __init__(self, level: int = logging.INFO) -> None:
        self._level = level

    async def emit(self, event: AuditEvent) -> None:
        logger.log(
            self._level,
            "AUDIT subject=%s action=%s resource=%s decision=%s reason=%s context=%s",
            event.subject_id, event.action, event.resource, event.decision, event.reason, event.context,
        )


# ------------------------------ Stores ---------------------------------------

class PolicyStore(ABC):
    """
    Abstract async storage for roles, policies, and subject-role bindings.

    Implementations must be concurrency-safe and ensure visibility after awaited operations.
    """

    @abstractmethod
    async def create_role(self, role: Role) -> None: ...

    @abstractmethod
    async def delete_role(self, role_name: str) -> None: ...

    @abstractmethod
    async def get_role(self, role_name: str) -> Role: ...

    @abstractmethod
    async def upsert_role(self, role: Role) -> None: ...

    @abstractmethod
    async def list_roles(self) -> List[str]: ...

    @abstractmethod
    async def assign_role_to_subject(self, subject_id: str, role_name: str) -> None: ...

    @abstractmethod
    async def revoke_role_from_subject(self, subject_id: str, role_name: str) -> None: ...

    @abstractmethod
    async def get_subject_roles(self, subject_id: str) -> Set[str]: ...

    @abstractmethod
    async def set_role_parents(self, role_name: str, parents: Set[str]) -> None: ...


class InMemoryPolicyStore(PolicyStore):
    """
    Async in-memory store. Thread-safe via per-structure locks.
    Suitable for tests and small deployments. Replace with Redis/DB for production scale.
    """

    def __init__(self) -> None:
        self._roles: Dict[str, Role] = {}
        self._bindings: Dict[str, Set[str]] = {}  # subject_id -> {role_name}
        self._lock = asyncio.Lock()

    async def create_role(self, role: Role) -> None:
        async with self._lock:
            if role.name in self._roles:
                raise ConflictError(f"Role {role.name} already exists.")
            self._roles[role.name] = role

    async def delete_role(self, role_name: str) -> None:
        async with self._lock:
            if role_name not in self._roles:
                raise NotFoundError(f"Role {role_name} not found.")
            del self._roles[role_name]
            for roles in self._bindings.values():
                roles.discard(role_name)
            for r in self._roles.values():
                r.parents.discard(role_name)

    async def get_role(self, role_name: str) -> Role:
        async with self._lock:
            role = self._roles.get(role_name)
            if not role:
                raise NotFoundError(f"Role {role_name} not found.")
            # Return a shallow copy to prevent external mutation without upsert
            return Role(name=role.name, policies=dict(role.policies), parents=set(role.parents))

    async def upsert_role(self, role: Role) -> None:
        async with self._lock:
            self._roles[role.name] = role

    async def list_roles(self) -> List[str]:
        async with self._lock:
            return list(self._roles.keys())

    async def assign_role_to_subject(self, subject_id: str, role_name: str) -> None:
        async with self._lock:
            if role_name not in self._roles:
                raise NotFoundError(f"Role {role_name} not found.")
            self._bindings.setdefault(subject_id, set()).add(role_name)

    async def revoke_role_from_subject(self, subject_id: str, role_name: str) -> None:
        async with self._lock:
            if subject_id in self._bindings:
                self._bindings[subject_id].discard(role_name)

    async def get_subject_roles(self, subject_id: str) -> Set[str]:
        async with self._lock:
            return set(self._bindings.get(subject_id, set()))

    async def set_role_parents(self, role_name: str, parents: Set[str]) -> None:
        async with self._lock:
            if role_name not in self._roles:
                raise NotFoundError(f"Role {role_name} not found.")
            # Validate parents exist
            for p in parents:
                if p not in self._roles:
                    raise ValidationError(f"Parent role {p} not found for {role_name}.")
            self._roles[role_name].parents = set(parents)


# ----------------------------- Matching Utils --------------------------------

def match_resource(pattern: str, resource: str) -> bool:
    """Glob-style resource matcher with fnmatch (POSIX-like)."""
    return fnmatch.fnmatchcase(resource, pattern)


def safe_condition_true(subject_attrs: Dict[str, Any], context: Dict[str, Any]) -> bool:
    """Default permissive condition (always true)."""
    return True


# --------------------------- Decision / Result --------------------------------

@dataclass(frozen=True)
class Decision:
    decision: DecisionType
    reason: str
    matched_policy_ids: Tuple[str, ...] = field(default_factory=tuple)

    @property
    def allowed(self) -> bool:
        return self.decision == DecisionType.ALLOW


# ----------------------------- RBAC Service -----------------------------------

class RBACService:
    """
    Policy Decision Point (PDP) with:
    - async stores
    - role inheritance traversal
    - DENY precedence
    - TTL decision cache with version increment on mutations
    - pluggable auditing
    """

    def __init__(
        self,
        store: PolicyStore,
        auditor: Optional[Auditor] = None,
        *,
        cache_ttl_seconds: int = 3,   # short TTL to balance freshness/perf
        max_cache_size: int = 50_000,
    ) -> None:
        self._store = store
        self._auditor = auditor or LoggingAuditor()
        self._cache_ttl = max(0, cache_ttl_seconds)
        self._max_cache_size = max_cache_size
        self._cache: MutableMapping[Tuple[Any, ...], Tuple[float, Decision]] = {}
        self._cache_lock = asyncio.Lock()
        self._version = 0  # increments on any policy/role mutation
        self._version_lock = asyncio.Lock()

    # --------------------- Public admin API (mutating) ---------------------

    async def create_role(self, name: str, *, parents: Optional[Set[str]] = None) -> None:
        _validate_name(name, "Role")
        role = Role(name=name, parents=set(parents or set()))
        await self._store.create_role(role)
        await self._bump_version()

    async def delete_role(self, name: str) -> None:
        await self._store.delete_role(name)
        await self._bump_version()

    async def set_role_parents(self, name: str, parents: Set[str]) -> None:
        await self._store.set_role_parents(name, parents)
        await self._bump_version()

    async def add_policy(self, role: str, policy: Policy) -> str:
        r = await self._store.get_role(role)
        r.add_policy(policy)
        await self._store.upsert_role(r)
        await self._bump_version()
        return policy.id

    async def remove_policy(self, role: str, policy_id: str) -> None:
        r = await self._store.get_role(role)
        r.remove_policy(policy_id)
        await self._store.upsert_role(r)
        await self._bump_version()

    async def assign_role(self, subject_id: str, role_name: str) -> None:
        await self._store.assign_role_to_subject(subject_id, role_name)
        await self._bump_version()

    async def revoke_role(self, subject_id: str, role_name: str) -> None:
        await self._store.revoke_role_from_subject(subject_id, role_name)
        await self._bump_version()

    # --------------------- Decision API (read path) ------------------------

    async def check_access(
        self,
        subject: Subject,
        action: str,
        resource: str,
        context: Optional[Dict[str, Any]] = None,
        *,
        include_bindings_from_store: bool = True,
        audit: bool = True,
    ) -> Decision:
        """
        Evaluate access decision for (subject, action, resource, context).

        - include_bindings_from_store: augment subject.roles with roles bound in store
        - audit: emit audit event (recommended)
        """
        ctx = context or {}
        if not action or not isinstance(action, str):
            raise ValidationError("Action must be a non-empty string.")
        if not resource or not isinstance(resource, str):
            raise ValidationError("Resource must be a non-empty string.")

        subject_roles = set(subject.roles)
        if include_bindings_from_store:
            bound = await self._store.get_subject_roles(subject.id)
            subject_roles |= bound

        # Cache key incorporates PDP version to ensure freshness after mutations
        version = await self._get_version()
        cache_key = self._make_cache_key(version, subject.id, frozenset(subject_roles), action, resource, frozenset((ctx or {}).items()))

        # Fast path: cache lookup
        if self._cache_ttl > 0:
            hit = await self._cache_get(cache_key)
            if hit is not None:
                if audit:
                    await self._audit(subject.id, action, resource, hit.decision, f"cache:v{version}; {hit.reason}", ctx)
                return hit

        # Build role closure (with inheritance)
        role_graph = await self._load_roles(subject_roles)
        closure = self._expand_roles(role_graph, subject_roles)

        # Gather applicable policies
        policies = self._collect_policies(role_graph, closure)

        decision = self._evaluate_policies(
            policies=policies,
            action=action,
            resource=resource,
            subject_attrs=subject.attributes,
            context=ctx,
        )

        if self._cache_ttl > 0:
            await self._cache_set(cache_key, decision)

        if audit:
            await self._audit(subject.id, action, resource, decision.decision, decision.reason, ctx)

        return decision

    # --------------------------- Internals --------------------------------

    async def _load_roles(self, names: Set[str]) -> Dict[str, Role]:
        """Fetch roles and all ancestors referenced in parent links."""
        to_visit = set(names)
        visited: Set[str] = set()
        graph: Dict[str, Role] = {}

        while to_visit:
            name = to_visit.pop()
            if name in visited:
                continue
            try:
                role = await self._store.get_role(name)
            except NotFoundError:
                logger.warning("RBAC: subject references unknown role %r; skipping.", name)
                visited.add(name)
                continue
            graph[name] = role
            visited.add(name)
            # enqueue parents
            for p in role.parents:
                if p not in visited:
                    to_visit.add(p)
        return graph

    @staticmethod
    def _expand_roles(graph: Dict[str, Role], roots: Set[str]) -> Set[str]:
        """Compute transitive closure of roles (roots + all parents)."""
        closure: Set[str] = set()
        stack: List[str] = list(roots)
        while stack:
            r = stack.pop()
            if r in closure:
                continue
            closure.add(r)
            role = graph.get(r)
            if role:
                for p in role.parents:
                    if p not in closure:
                        stack.append(p)
        return closure

    @staticmethod
    def _collect_policies(graph: Dict[str, Role], closure: Set[str]) -> List[Policy]:
        """Collect all policies across roles in closure."""
        policies: List[Policy] = []
        for rname in closure:
            role = graph.get(rname)
            if not role:
                continue
            policies.extend(role.policies.values())
        return policies

    @staticmethod
    def _policy_applies(
        policy: Policy,
        *,
        action: str,
        resource: str,
        subject_attrs: Dict[str, Any],
        context: Dict[str, Any],
    ) -> bool:
        if action not in policy.actions:
            return False
        if not match_resource(policy.resource, resource):
            return False
        cond = policy.condition or safe_condition_true
        try:
            return bool(cond(subject_attrs, context))
        except Exception as e:
            logger.error("Policy %s condition raised %r; treating as not applicable.", policy.id, e)
            return False

    def _evaluate_policies(
        self,
        *,
        policies: List[Policy],
        action: str,
        resource: str,
        subject_attrs: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Decision:
        """
        Evaluate with DENY > ALLOW > NOT_APPLICABLE.
        Accumulate matched policy ids for traceability.
        """
        matched_allow: List[str] = []
        matched_deny: List[str] = []

        for p in policies:
            if not self._policy_applies(p, action=action, resource=resource, subject_attrs=subject_attrs, context=context):
                continue
            if p.effect == Effect.DENY:
                matched_deny.append(p.id)
            elif p.effect == Effect.ALLOW:
                matched_allow.append(p.id)

        if matched_deny:
            return Decision(
                decision=DecisionType.DENY,
                reason=f"explicit_deny count={len(matched_deny)}",
                matched_policy_ids=tuple(matched_deny),
            )
        if matched_allow:
            return Decision(
                decision=DecisionType.ALLOW,
                reason=f"explicit_allow count={len(matched_allow)}",
                matched_policy_ids=tuple(matched_allow),
            )
        return Decision(
            decision=DecisionType.NOT_APPLICABLE,
            reason="no_matching_policies",
            matched_policy_ids=tuple(),
        )

    # ---------------------------- Cache -----------------------------------

    def _make_cache_key(
        self,
        version: int,
        subject_id: str,
        roles: FrozenSet[str],
        action: str,
        resource: str,
        context_items: FrozenSet[Tuple[str, Any]],
    ) -> Tuple[Any, ...]:
        # Ensure stable hashable key; version guarantees invalidation on mutations.
        return (version, subject_id, roles, action, resource, context_items)

    async def _cache_get(self, key: Tuple[Any, ...]) -> Optional[Decision]:
        async with self._cache_lock:
            entry = self._cache.get(key)
            if not entry:
                return None
            ts, decision = entry
            if (time.time() - ts) > self._cache_ttl:
                del self._cache[key]
                return None
            return decision

    async def _cache_set(self, key: Tuple[Any, ...], decision: Decision) -> None:
        async with self._cache_lock:
            # simple size cap eviction: pop oldest one if needed
            if len(self._cache) >= self._max_cache_size:
                oldest_key = min(self._cache.items(), key=lambda kv: kv[1][0])[0]
                self._cache.pop(oldest_key, None)
            self._cache[key] = (time.time(), decision)

    async def _bump_version(self) -> None:
        async with self._version_lock:
            self._version += 1
        # flush cache opportunistically
        async with self._cache_lock:
            self._cache.clear()

    async def _get_version(self) -> int:
        async with self._version_lock:
            return self._version

    # ----------------------------- Audit ----------------------------------

    async def _audit(
        self,
        subject_id: str,
        action: str,
        resource: str,
        decision: DecisionType,
        reason: str,
        context: Dict[str, Any],
    ) -> None:
        try:
            await self._auditor.emit(
                AuditEvent(
                    subject_id=subject_id,
                    action=action,
                    resource=resource,
                    decision=decision,
                    reason=reason,
                    context=dict(context),
                )
            )
        except Exception as e:
            # Never break PDP due to audit failures
            logger.error("RBAC audit failed: %r", e)


# ---------------------------- Convenience ------------------------------------

def require(decision: Decision) -> None:
    """
    Helper for PEP: raise on non-ALLOW decisions.
    """
    if not decision.allowed:
        raise PermissionError(f"Access denied: {decision.decision}; reason={decision.reason}; policies={decision.matched_policy_ids!r}")


# ----------------------- Example Conditions (Predicates) ----------------------

def cond_department_is(expected: str) -> Condition:
    def _inner(attrs: Dict[str, Any], ctx: Dict[str, Any]) -> bool:
        return attrs.get("dept") == expected
    return _inner


def cond_time_between(start_epoch: float, end_epoch: float) -> Condition:
    def _inner(attrs: Dict[str, Any], ctx: Dict[str, Any]) -> bool:
        now = ctx.get("now_epoch", time.time())
        return start_epoch <= float(now) <= end_epoch
    return _inner


def cond_ip_in_subnet(prefix: str) -> Condition:
    """
    Simple startswith-based check for RFC1918-like prefixes.
    For stronger checks integrate with ipaddress/ACLs at gateway.
    """
    def _inner(attrs: Dict[str, Any], ctx: Dict[str, Any]) -> bool:
        ip = ctx.get("ip")
        if not isinstance(ip, str):
            return False
        return ip.startswith(prefix)
    return _inner


# ------------------------------- Self-test -----------------------------------

async def _selftest() -> None:
    store = InMemoryPolicyStore()
    rbac = RBACService(store)

    await rbac.create_role("viewer")
    await rbac.add_policy("viewer", Policy.new_allow("projects/*", {"read"}))

    await rbac.create_role("ops", parents={"viewer"})
    await rbac.add_policy("ops", Policy.new_allow("projects/*", {"write"}, condition=cond_department_is("it")))
    await rbac.add_policy("ops", Policy.new_deny("projects/secret/*", {"read", "write"}))

    subj = Subject(id="u1", attributes={"dept": "it"}, roles=frozenset({"ops"}))
    d1 = await rbac.check_access(subj, "read", "projects/alpha", {"ip": "10.0.0.1"})
    assert d1.allowed

    d2 = await rbac.check_access(subj, "write", "projects/secret/x", {})
    assert not d2.allowed and d2.decision == DecisionType.DENY

    subj2 = Subject(id="u2", attributes={"dept": "sales"}, roles=frozenset({"viewer"}))
    d3 = await rbac.check_access(subj2, "write", "projects/alpha", {})
    assert d3.decision == DecisionType.NOT_APPLICABLE

    # bindings from store
    await rbac.assign_role("u3", "viewer")
    subj3 = Subject(id="u3", attributes={}, roles=frozenset())
    d4 = await rbac.check_access(subj3, "read", "projects/alpha", {})
    assert d4.allowed

if __name__ == "__main__":  # pragma: no cover
    asyncio.run(_selftest())
