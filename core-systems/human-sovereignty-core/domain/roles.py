from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from fnmatch import fnmatchcase
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Set, Tuple


class RoleError(ValueError):
    pass


class Permission(str, Enum):
    READ_POLICY = "human_sov.policy.read"
    WRITE_POLICY = "human_sov.policy.write"
    APPLY_POLICY = "human_sov.policy.apply"
    REVIEW_POLICY = "human_sov.policy.review"
    OVERRIDE_POLICY = "human_sov.policy.override"

    READ_AUDIT = "human_sov.audit.read"
    EXPORT_AUDIT = "human_sov.audit.export"

    READ_DOMAINS = "human_sov.domains.read"
    WRITE_DOMAINS = "human_sov.domains.write"
    IMPORT_DOMAINS = "human_sov.domains.import"
    EXPORT_DOMAINS = "human_sov.domains.export"

    READ_DECISIONS = "human_sov.decisions.read"
    WRITE_DECISIONS = "human_sov.decisions.write"

    READ_INTEGRATIONS = "human_sov.integrations.read"
    WRITE_INTEGRATIONS = "human_sov.integrations.write"

    READ_SYSTEM = "human_sov.system.read"
    ADMIN_SYSTEM = "human_sov.system.admin"

    BREAK_GLASS = "human_sov.break_glass"


class ScopeKind(str, Enum):
    GLOBAL = "global"
    ENVIRONMENT = "environment"
    SERVICE = "service"
    TENANT = "tenant"


def _require_nonempty(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RoleError(f"{field_name} must be a non-empty string")
    return value.strip()


def _dedupe_preserve_order(items: Sequence[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for i in items:
        if i in seen:
            continue
        seen.add(i)
        out.append(i)
    return out


def _validate_scope_pattern(pattern: str) -> str:
    p = _require_nonempty(pattern, "scope pattern")
    if len(p) > 256:
        raise RoleError("scope pattern too long")
    return p


def _validate_permissions(perms: Iterable[Permission]) -> FrozenSet[Permission]:
    perm_set: Set[Permission] = set()
    for p in perms:
        if not isinstance(p, Permission):
            raise RoleError("permission must be Permission enum")
        perm_set.add(p)
    if not perm_set:
        raise RoleError("permissions set must not be empty")
    return frozenset(sorted(perm_set, key=lambda x: x.value))


@dataclass(frozen=True, slots=True)
class ScopeRule:
    kind: ScopeKind
    pattern: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", ScopeKind(self.kind))
        object.__setattr__(self, "pattern", _validate_scope_pattern(self.pattern))

    def matches(self, kind: ScopeKind, value: str) -> bool:
        if ScopeKind(kind) != self.kind:
            return False
        v = _require_nonempty(value, "scope value")
        return fnmatchcase(v, self.pattern)

    def to_dict(self) -> Dict[str, str]:
        return {"kind": self.kind.value, "pattern": self.pattern}


@dataclass(frozen=True, slots=True)
class Role:
    id: str
    name: str
    description: str
    permissions: FrozenSet[Permission]
    scopes: Tuple[ScopeRule, ...] = field(default_factory=tuple)
    system: bool = True
    immutable: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _require_nonempty(self.id, "role id"))
        object.__setattr__(self, "name", _require_nonempty(self.name, "role name"))
        object.__setattr__(self, "description", _require_nonempty(self.description, "role description"))
        object.__setattr__(self, "permissions", _validate_permissions(self.permissions))

        normalized_scopes: List[ScopeRule] = []
        for s in self.scopes:
            if not isinstance(s, ScopeRule):
                raise RoleError("scopes must be ScopeRule items")
            normalized_scopes.append(s)

        unique = []
        seen = set()
        for s in normalized_scopes:
            k = (s.kind.value, s.pattern)
            if k in seen:
                continue
            seen.add(k)
            unique.append(s)
        object.__setattr__(self, "scopes", tuple(unique))

        if not isinstance(self.system, bool):
            raise RoleError("system must be bool")
        if not isinstance(self.immutable, bool):
            raise RoleError("immutable must be bool")

    def allows(self, permission: Permission, scope_kind: ScopeKind, scope_value: str) -> bool:
        if permission not in self.permissions:
            return False
        if not self.scopes:
            return True
        for rule in self.scopes:
            if rule.matches(scope_kind, scope_value):
                return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "permissions": [p.value for p in self.permissions],
            "scopes": [s.to_dict() for s in self.scopes],
            "system": self.system,
            "immutable": self.immutable,
        }

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "Role":
        if not isinstance(data, Mapping):
            raise RoleError("role data must be a mapping")

        rid = _require_nonempty(str(data.get("id", "")), "role id")
        name = _require_nonempty(str(data.get("name", "")), "role name")
        desc = _require_nonempty(str(data.get("description", "")), "role description")

        raw_perms = data.get("permissions", [])
        if not isinstance(raw_perms, Sequence) or isinstance(raw_perms, (str, bytes)):
            raise RoleError("permissions must be a list")
        perms: List[Permission] = []
        for p in raw_perms:
            try:
                perms.append(Permission(str(p)))
            except Exception as e:
                raise RoleError(f"unknown permission: {p}") from e

        raw_scopes = data.get("scopes", [])
        scopes: List[ScopeRule] = []
        if raw_scopes is None:
            raw_scopes = []
        if not isinstance(raw_scopes, Sequence) or isinstance(raw_scopes, (str, bytes)):
            raise RoleError("scopes must be a list")
        for s in raw_scopes:
            if not isinstance(s, Mapping):
                raise RoleError("scope rule must be a mapping")
            kind = s.get("kind")
            pattern = s.get("pattern")
            try:
                scopes.append(ScopeRule(kind=ScopeKind(str(kind)), pattern=str(pattern)))
            except Exception as e:
                raise RoleError(f"invalid scope rule: {s}") from e

        system = bool(data.get("system", False))
        immutable = bool(data.get("immutable", False))

        return Role(
            id=rid,
            name=name,
            description=desc,
            permissions=frozenset(perms),
            scopes=tuple(scopes),
            system=system,
            immutable=immutable,
        )


@dataclass(frozen=True, slots=True)
class Principal:
    subject: str
    roles: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "subject", _require_nonempty(self.subject, "subject"))
        if not isinstance(self.roles, tuple):
            object.__setattr__(self, "roles", tuple(self.roles))
        normalized = _dedupe_preserve_order([_require_nonempty(r, "role id") for r in self.roles])
        object.__setattr__(self, "roles", tuple(normalized))

    def to_dict(self) -> Dict[str, Any]:
        return {"subject": self.subject, "roles": list(self.roles)}

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "Principal":
        if not isinstance(data, Mapping):
            raise RoleError("principal data must be a mapping")
        subject = _require_nonempty(str(data.get("subject", "")), "subject")
        roles = data.get("roles", [])
        if not isinstance(roles, Sequence) or isinstance(roles, (str, bytes)):
            raise RoleError("roles must be a list")
        return Principal(subject=subject, roles=tuple(str(r) for r in roles))


class RoleRegistry:
    def __init__(self, roles: Iterable[Role]) -> None:
        self._roles_by_id: Dict[str, Role] = {}
        for role in roles:
            self.register(role)

    def register(self, role: Role) -> None:
        if not isinstance(role, Role):
            raise RoleError("role must be Role")
        if role.id in self._roles_by_id:
            raise RoleError(f"duplicate role id: {role.id}")
        self._roles_by_id[role.id] = role

    def get(self, role_id: str) -> Role:
        rid = _require_nonempty(role_id, "role id")
        try:
            return self._roles_by_id[rid]
        except KeyError as e:
            raise RoleError(f"unknown role id: {rid}") from e

    def try_get(self, role_id: str) -> Optional[Role]:
        if not role_id or not str(role_id).strip():
            return None
        return self._roles_by_id.get(str(role_id).strip())

    def list_roles(self) -> Tuple[Role, ...]:
        return tuple(sorted(self._roles_by_id.values(), key=lambda r: r.id))

    def to_dict(self) -> Dict[str, Any]:
        return {"roles": [r.to_dict() for r in self.list_roles()]}

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "RoleRegistry":
        if not isinstance(data, Mapping):
            raise RoleError("registry data must be a mapping")
        roles_data = data.get("roles", [])
        if not isinstance(roles_data, Sequence) or isinstance(roles_data, (str, bytes)):
            raise RoleError("roles must be a list")
        roles = [Role.from_dict(r) for r in roles_data]
        return RoleRegistry(roles)


class AccessDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class AccessCheck:
    principal: Principal
    permission: Permission
    scope_kind: ScopeKind
    scope_value: str

    def __post_init__(self) -> None:
        if not isinstance(self.principal, Principal):
            raise RoleError("principal must be Principal")
        object.__setattr__(self, "permission", Permission(self.permission))
        object.__setattr__(self, "scope_kind", ScopeKind(self.scope_kind))
        object.__setattr__(self, "scope_value", _require_nonempty(self.scope_value, "scope value"))


@dataclass(frozen=True, slots=True)
class AccessResult:
    decision: AccessDecision
    matched_roles: Tuple[str, ...]
    reason: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "decision", AccessDecision(self.decision))
        object.__setattr__(self, "reason", _require_nonempty(self.reason, "reason"))
        if not isinstance(self.matched_roles, tuple):
            object.__setattr__(self, "matched_roles", tuple(self.matched_roles))
        object.__setattr__(self, "matched_roles", tuple(_dedupe_preserve_order(list(self.matched_roles))))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value,
            "matched_roles": list(self.matched_roles),
            "reason": self.reason,
        }


class AccessController:
    def __init__(self, registry: RoleRegistry) -> None:
        if not isinstance(registry, RoleRegistry):
            raise RoleError("registry must be RoleRegistry")
        self._registry = registry

    def check(self, req: AccessCheck) -> AccessResult:
        matched: List[str] = []

        for role_id in req.principal.roles:
            role = self._registry.try_get(role_id)
            if role is None:
                continue
            if role.allows(req.permission, req.scope_kind, req.scope_value):
                matched.append(role.id)

        if matched:
            return AccessResult(
                decision=AccessDecision.ALLOW,
                matched_roles=tuple(matched),
                reason="permission granted by role match",
            )

        return AccessResult(
            decision=AccessDecision.DENY,
            matched_roles=tuple(),
            reason="no role grants the requested permission for the given scope",
        )


def _scope(*pairs: Tuple[ScopeKind, str]) -> Tuple[ScopeRule, ...]:
    rules = [ScopeRule(kind=k, pattern=p) for k, p in pairs]
    return tuple(rules)


ROLE_OWNER = Role(
    id="HS_OWNER",
    name="Human Sovereignty Owner",
    description="Top-level owner. Full control including break-glass.",
    permissions=frozenset(set(Permission)),
    scopes=_scope((ScopeKind.GLOBAL, "*")),
    system=True,
    immutable=True,
)

ROLE_GOVERNOR = Role(
    id="HS_GOVERNOR",
    name="Human Sovereignty Governor",
    description="Strategic governance. Can approve and apply policies, manage domains, read/export audit.",
    permissions=frozenset(
        {
            Permission.READ_POLICY,
            Permission.WRITE_POLICY,
            Permission.REVIEW_POLICY,
            Permission.APPLY_POLICY,
            Permission.OVERRIDE_POLICY,
            Permission.READ_DOMAINS,
            Permission.WRITE_DOMAINS,
            Permission.IMPORT_DOMAINS,
            Permission.EXPORT_DOMAINS,
            Permission.READ_AUDIT,
            Permission.EXPORT_AUDIT,
            Permission.READ_SYSTEM,
        }
    ),
    scopes=_scope((ScopeKind.GLOBAL, "*")),
    system=True,
    immutable=True,
)

ROLE_POLICY_ADMIN = Role(
    id="HS_POLICY_ADMIN",
    name="Policy Admin",
    description="Manages policy definitions and deployments within allowed scopes.",
    permissions=frozenset(
        {
            Permission.READ_POLICY,
            Permission.WRITE_POLICY,
            Permission.REVIEW_POLICY,
            Permission.APPLY_POLICY,
            Permission.READ_DOMAINS,
            Permission.WRITE_DOMAINS,
            Permission.IMPORT_DOMAINS,
            Permission.EXPORT_DOMAINS,
            Permission.READ_SYSTEM,
        }
    ),
    scopes=_scope((ScopeKind.ENVIRONMENT, "*"), (ScopeKind.SERVICE, "*")),
    system=True,
    immutable=True,
)

ROLE_AUDITOR = Role(
    id="HS_AUDITOR",
    name="Auditor",
    description="Read-only audit access with export for compliance and investigations.",
    permissions=frozenset(
        {
            Permission.READ_AUDIT,
            Permission.EXPORT_AUDIT,
            Permission.READ_POLICY,
            Permission.READ_DOMAINS,
            Permission.READ_DECISIONS,
            Permission.READ_SYSTEM,
        }
    ),
    scopes=_scope((ScopeKind.GLOBAL, "*")),
    system=True,
    immutable=True,
)

ROLE_OPERATOR = Role(
    id="HS_OPERATOR",
    name="Operator",
    description="Operations role. Can record decisions and start mitigation workflows, but cannot override policy.",
    permissions=frozenset(
        {
            Permission.READ_POLICY,
            Permission.READ_DOMAINS,
            Permission.READ_DECISIONS,
            Permission.WRITE_DECISIONS,
            Permission.READ_SYSTEM,
            Permission.READ_INTEGRATIONS,
        }
    ),
    scopes=_scope((ScopeKind.ENVIRONMENT, "*"), (ScopeKind.SERVICE, "*")),
    system=True,
    immutable=True,
)

ROLE_SERVICE = Role(
    id="HS_SERVICE",
    name="Service Principal",
    description="Non-human service identity. Minimal read access required for runtime decisions.",
    permissions=frozenset(
        {
            Permission.READ_POLICY,
            Permission.READ_DOMAINS,
            Permission.READ_DECISIONS,
        }
    ),
    scopes=_scope((ScopeKind.SERVICE, "*")),
    system=True,
    immutable=True,
)

ROLE_READONLY = Role(
    id="HS_READONLY",
    name="Read Only",
    description="Read-only access to policy and domains for visibility.",
    permissions=frozenset(
        {
            Permission.READ_POLICY,
            Permission.READ_DOMAINS,
            Permission.READ_SYSTEM,
        }
    ),
    scopes=_scope((ScopeKind.GLOBAL, "*")),
    system=True,
    immutable=True,
)

SYSTEM_ROLES: Tuple[Role, ...] = (
    ROLE_OWNER,
    ROLE_GOVERNOR,
    ROLE_POLICY_ADMIN,
    ROLE_AUDITOR,
    ROLE_OPERATOR,
    ROLE_SERVICE,
    ROLE_READONLY,
)

SYSTEM_ROLE_REGISTRY = RoleRegistry(SYSTEM_ROLES)
SYSTEM_ACCESS = AccessController(SYSTEM_ROLE_REGISTRY)
