# human-sovereignty-core/domain/permissions.py
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from typing import (
    FrozenSet,
    Iterable,
    Iterator,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

__all__ = [
    "PermissionError",
    "PermissionParseError",
    "PermissionValidationError",
    "Action",
    "Environment",
    "Wildcard",
    "Permission",
    "PermissionPattern",
    "PermissionSet",
    "parse_permission",
    "parse_pattern",
    "normalize_token",
    "is_valid_token",
]


class PermissionError(Exception):
    """Base class for permission-related errors."""


class PermissionParseError(PermissionError):
    """Raised when a permission string cannot be parsed safely."""


class PermissionValidationError(PermissionError):
    """Raised when a permission or pattern violates validation rules."""


class Wildcard(str, Enum):
    ANY = "*"


class Environment(str, Enum):
    DEV = "dev"
    STAGING = "staging"
    PROD = "prod"


class Action(str, Enum):
    # Keep action vocabulary stable. Extend only with backward-compatible semantics.
    READ = "read"
    WRITE = "write"
    APPROVE = "approve"
    REJECT = "reject"
    ESCALATE = "escalate"
    OVERRIDE = "override"
    EXECUTE = "execute"
    AUDIT = "audit"


_TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$", re.IGNORECASE)
_MAX_STR_LEN = 256


def normalize_token(value: str) -> str:
    if not isinstance(value, str):
        raise PermissionValidationError("token must be a string")
    v = value.strip().lower()
    if not v:
        raise PermissionValidationError("token must not be empty")
    if len(v) > 64:
        raise PermissionValidationError("token too long")
    return v


def is_valid_token(value: str) -> bool:
    if not isinstance(value, str):
        return False
    v = value.strip().lower()
    if not v or len(v) > 64:
        return False
    return _TOKEN_RE.match(v) is not None


def _validate_token_or_wildcard(value: str, field: str) -> str:
    v = value.strip().lower()
    if v == Wildcard.ANY.value:
        return v
    if not is_valid_token(v):
        raise PermissionValidationError(f"invalid {field} token: {value!r}")
    return v


def _validate_str_limit(value: str, field: str) -> None:
    if len(value) > _MAX_STR_LEN:
        raise PermissionValidationError(f"{field} too long")


@dataclass(frozen=True, slots=True)
class Permission:
    """
    Canonical permission.

    Format: {domain}:{action}:{resource}
    - domain: service or bounded subsystem identifier, e.g. "human_sovereignty"
    - action: operation, e.g. "approve"
    - resource: entity identifier, e.g. "approval_request" or "decision_packet"
    """

    domain: str
    action: str
    resource: str

    def __post_init__(self) -> None:
        d = _validate_token_or_wildcard(self.domain, "domain")
        a = _validate_token_or_wildcard(self.action, "action")
        r = _validate_token_or_wildcard(self.resource, "resource")
        object.__setattr__(self, "domain", d)
        object.__setattr__(self, "action", a)
        object.__setattr__(self, "resource", r)
        _validate_str_limit(self.domain, "domain")
        _validate_str_limit(self.action, "action")
        _validate_str_limit(self.resource, "resource")

    @property
    def is_wild(self) -> bool:
        return (
            self.domain == Wildcard.ANY.value
            or self.action == Wildcard.ANY.value
            or self.resource == Wildcard.ANY.value
        )

    def to_string(self) -> str:
        return f"{self.domain}:{self.action}:{self.resource}"

    def __str__(self) -> str:
        return self.to_string()


@dataclass(frozen=True, slots=True)
class PermissionPattern:
    """
    Permission pattern supports wildcards per segment.

    Examples:
      - "human_sovereignty:approve:approval_request"
      - "human_sovereignty:*:approval_request"
      - "*:*:*"
    """

    domain: str
    action: str
    resource: str

    def __post_init__(self) -> None:
        d = _validate_token_or_wildcard(self.domain, "domain")
        a = _validate_token_or_wildcard(self.action, "action")
        r = _validate_token_or_wildcard(self.resource, "resource")
        object.__setattr__(self, "domain", d)
        object.__setattr__(self, "action", a)
        object.__setattr__(self, "resource", r)
        _validate_str_limit(self.domain, "domain")
        _validate_str_limit(self.action, "action")
        _validate_str_limit(self.resource, "resource")

    def to_string(self) -> str:
        return f"{self.domain}:{self.action}:{self.resource}"

    def matches(self, perm: Permission) -> bool:
        return _segment_match(self.domain, perm.domain) and _segment_match(
            self.action, perm.action
        ) and _segment_match(self.resource, perm.resource)

    def specificity(self) -> int:
        # Higher value means more specific.
        return int(self.domain != Wildcard.ANY.value) + int(
            self.action != Wildcard.ANY.value
        ) + int(self.resource != Wildcard.ANY.value)

    def __str__(self) -> str:
        return self.to_string()


def _segment_match(pattern_segment: str, value_segment: str) -> bool:
    if pattern_segment == Wildcard.ANY.value:
        return True
    return pattern_segment == value_segment


def _split_triplet(value: str, what: str) -> Tuple[str, str, str]:
    if not isinstance(value, str):
        raise PermissionParseError(f"{what} must be a string")
    s = value.strip()
    if not s:
        raise PermissionParseError(f"{what} must not be empty")
    if len(s) > _MAX_STR_LEN:
        raise PermissionParseError(f"{what} too long")

    parts = [p.strip() for p in s.split(":")]
    if len(parts) != 3:
        raise PermissionParseError(
            f"{what} must have exactly 3 segments: domain:action:resource"
        )
    if any(p == "" for p in parts):
        raise PermissionParseError(f"{what} has empty segment")
    return parts[0], parts[1], parts[2]


@lru_cache(maxsize=4096)
def parse_permission(value: str) -> Permission:
    d, a, r = _split_triplet(value, "permission")
    return Permission(domain=d, action=a, resource=r)


@lru_cache(maxsize=4096)
def parse_pattern(value: str) -> PermissionPattern:
    d, a, r = _split_triplet(value, "permission pattern")
    return PermissionPattern(domain=d, action=a, resource=r)


class PermissionSet:
    """
    Immutable permission set with safe operations.

    Semantics:
    - allow_patterns: list of PermissionPattern that can grant permissions.
    - deny_patterns: list of PermissionPattern that block permissions (deny wins).

    Effective access decision:
      deny if any deny pattern matches
      allow if any allow pattern matches
      otherwise deny (fail-closed)
    """

    __slots__ = ("_allow", "_deny")

    def __init__(
        self,
        allow: Optional[Iterable[Union[PermissionPattern, str]]] = None,
        deny: Optional[Iterable[Union[PermissionPattern, str]]] = None,
    ) -> None:
        allow_patterns = _coerce_patterns(allow or ())
        deny_patterns = _coerce_patterns(deny or ())
        self._allow = tuple(_sorted_patterns(allow_patterns))
        self._deny = tuple(_sorted_patterns(deny_patterns))

    @property
    def allow_patterns(self) -> Tuple[PermissionPattern, ...]:
        return self._allow

    @property
    def deny_patterns(self) -> Tuple[PermissionPattern, ...]:
        return self._deny

    def is_allowed(self, perm: Union[Permission, str]) -> bool:
        p = perm if isinstance(perm, Permission) else parse_permission(perm)
        for pat in self._deny:
            if pat.matches(p):
                return False
        for pat in self._allow:
            if pat.matches(p):
                return True
        return False

    def with_allow(self, *patterns: Union[PermissionPattern, str]) -> "PermissionSet":
        return PermissionSet(allow=(*self._allow, *patterns), deny=self._deny)

    def with_deny(self, *patterns: Union[PermissionPattern, str]) -> "PermissionSet":
        return PermissionSet(allow=self._allow, deny=(*self._deny, *patterns))

    def union(self, other: "PermissionSet") -> "PermissionSet":
        return PermissionSet(allow=(*self._allow, *other._allow), deny=(*self._deny, *other._deny))

    def __iter__(self) -> Iterator[PermissionPattern]:
        yield from self._allow

    def __len__(self) -> int:
        return len(self._allow)

    def to_dict(self) -> dict:
        return {
            "allow": [p.to_string() for p in self._allow],
            "deny": [p.to_string() for p in self._deny],
        }

    @staticmethod
    def from_dict(data: Mapping[str, object]) -> "PermissionSet":
        if not isinstance(data, Mapping):
            raise PermissionValidationError("permissions payload must be a mapping")
        allow = data.get("allow", [])
        deny = data.get("deny", [])
        if not isinstance(allow, Sequence) or isinstance(allow, (str, bytes)):
            raise PermissionValidationError("allow must be a list")
        if not isinstance(deny, Sequence) or isinstance(deny, (str, bytes)):
            raise PermissionValidationError("deny must be a list")
        return PermissionSet(allow=allow, deny=deny)

    def __repr__(self) -> str:
        return f"PermissionSet(allow={len(self._allow)}, deny={len(self._deny)})"


def _coerce_patterns(values: Iterable[Union[PermissionPattern, str]]) -> FrozenSet[PermissionPattern]:
    out: set[PermissionPattern] = set()
    for v in values:
        if isinstance(v, PermissionPattern):
            out.add(v)
        elif isinstance(v, str):
            out.add(parse_pattern(v))
        else:
            raise PermissionValidationError("pattern must be PermissionPattern or str")
    return frozenset(out)


def _sorted_patterns(values: FrozenSet[PermissionPattern]) -> Tuple[PermissionPattern, ...]:
    # Deterministic ordering: most specific first, then lexicographic.
    return tuple(
        sorted(
            values,
            key=lambda p: (-p.specificity(), p.domain, p.action, p.resource),
        )
    )
