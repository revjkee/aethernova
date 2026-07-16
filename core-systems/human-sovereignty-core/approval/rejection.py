# human-sovereignty-core/approval/rejection.py
from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Final, Iterable, Mapping, Sequence


class RejectionError(RuntimeError):
    pass


_SAFE_CODE_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Z0-9_]{3,64}$")
_SAFE_FIELD_RE: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z0-9_.\-]{1,128}$")


class RejectionSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class RejectionDomain(str, Enum):
    VALIDATION = "validation"
    POLICY = "policy"
    APPROVAL = "approval"
    SECURITY = "security"
    EXECUTION = "execution"
    LIFECYCLE = "lifecycle"
    SYSTEM = "system"


class RejectionCode(str, Enum):
    # Generic / system
    INTERNAL_ERROR = "INTERNAL_ERROR"
    UNEXPECTED_STATE = "UNEXPECTED_STATE"
    UNSUPPORTED_OPERATION = "UNSUPPORTED_OPERATION"

    # Validation
    INVALID_SCHEMA = "INVALID_SCHEMA"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    INVALID_ORIGIN = "INVALID_ORIGIN"
    INVALID_TTL = "INVALID_TTL"
    MALFORMED_PAYLOAD = "MALFORMED_PAYLOAD"

    # Policy
    RED_DOMAIN = "RED_DOMAIN"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    LIMITS_EXCEEDED = "LIMITS_EXCEEDED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"

    # Approval workflow
    DENIED = "DENIED"
    VETOED = "VETOED"
    ESCALATION_TIMEOUT = "ESCALATION_TIMEOUT"

    # Security / webui
    CSRF_FAILED = "CSRF_FAILED"
    ORIGIN_NOT_ALLOWED = "ORIGIN_NOT_ALLOWED"
    RATE_LIMITED = "RATE_LIMITED"

    # Execution
    EXECUTION_FAILED = "EXECUTION_FAILED"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"

    # Lifecycle
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


def _require_code(value: str) -> str:
    if not _SAFE_CODE_RE.fullmatch(value):
        raise RejectionError(f"Unsafe rejection code: {value!r}")
    return value


def _require_field_name(value: str) -> str:
    if not _SAFE_FIELD_RE.fullmatch(value):
        raise RejectionError(f"Unsafe field name: {value!r}")
    return value


def _safe_str(value: Any, max_len: int = 4096) -> str:
    s = str(value)
    if len(s) > max_len:
        return s[: max_len - 3] + "..."
    return s


def _now_unix() -> float:
    return time.time()


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class RejectionDetail:
    """
    Structured detail for a rejection.
    Field-level issues (schema errors, invalid values, etc.) go here.
    """

    field: str
    issue: str
    hint: str | None = None

    def __post_init__(self) -> None:
        _require_field_name(self.field)
        object.__setattr__(self, "issue", _safe_str(self.issue, 2048))
        if self.hint is not None:
            object.__setattr__(self, "hint", _safe_str(self.hint, 2048))

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"field": self.field, "issue": self.issue}
        if self.hint is not None:
            out["hint"] = self.hint
        return out


@dataclass(frozen=True, slots=True)
class Rejection:
    """
    Canonical rejection object, safe for logs, API responses, and audits.

    Design choices:
    - Has a stable 'fingerprint' computed from canonical fields for dedupe.
    - Separates safe_message (for UI) from debug_context (for internal logs).
    - Never requires secrets in fields; debug_context is best-effort and redaction-ready.
    """

    code: RejectionCode
    domain: RejectionDomain
    severity: RejectionSeverity = RejectionSeverity.ERROR

    safe_message: str = "Request rejected."
    details: tuple[RejectionDetail, ...] = ()

    # Correlation and audit
    rejection_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    occurred_at_unix: float = field(default_factory=_now_unix)

    # Optional: actor/request context
    request_id: str | None = None
    packet_id: str | None = None
    actor_id: str | None = None

    # Optional: internal-only context (do not expose to untrusted clients)
    debug_context: Mapping[str, Any] | None = None

    # Optional: external references (tickets, audit events)
    references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_code(self.code.value)
        object.__setattr__(self, "safe_message", _safe_str(self.safe_message, 2048))

        if self.request_id is not None:
            object.__setattr__(self, "request_id", _safe_str(self.request_id, 256))
        if self.packet_id is not None:
            object.__setattr__(self, "packet_id", _safe_str(self.packet_id, 256))
        if self.actor_id is not None:
            object.__setattr__(self, "actor_id", _safe_str(self.actor_id, 256))

        # Normalize references to safe short strings
        if self.references:
            object.__setattr__(
                self,
                "references",
                tuple(_safe_str(r, 256) for r in self.references),
            )

        # Make details deterministic (sorted) to stabilize fingerprint when callers pass in random order
        if self.details:
            sorted_details = tuple(sorted(self.details, key=lambda d: (d.field, d.issue, d.hint or "")))
            object.__setattr__(self, "details", sorted_details)

    def fingerprint(self) -> str:
        """
        Deterministic fingerprint for deduplication and correlation.
        Does not include timestamps or random IDs.
        """
        base = {
            "code": self.code.value,
            "domain": self.domain.value,
            "severity": self.severity.value,
            "safe_message": self.safe_message,
            "details": [d.to_dict() for d in self.details],
            "request_id": self.request_id,
            "packet_id": self.packet_id,
            "actor_id": self.actor_id,
            "references": list(self.references),
        }
        return _sha256_hex(_canonical_json(base))

    def to_public_dict(self) -> dict[str, Any]:
        """
        Safe for returning to UI clients.
        Excludes debug_context and other sensitive fields.
        """
        return {
            "rejection_id": self.rejection_id,
            "occurred_at_unix": self.occurred_at_unix,
            "code": self.code.value,
            "domain": self.domain.value,
            "severity": self.severity.value,
            "message": self.safe_message,
            "details": [d.to_dict() for d in self.details],
            "request_id": self.request_id,
            "packet_id": self.packet_id,
        }

    def to_internal_dict(self) -> dict[str, Any]:
        """
        For internal logs/audit pipelines.
        """
        out = dict(self.to_public_dict())
        out["actor_id"] = self.actor_id
        out["references"] = list(self.references)
        out["fingerprint"] = self.fingerprint()
        if self.debug_context is not None:
            out["debug_context"] = self.debug_context
        return out

    def to_json(self, public: bool = True) -> str:
        return _canonical_json(self.to_public_dict() if public else self.to_internal_dict())


@dataclass(frozen=True, slots=True)
class RejectionBundle:
    """
    Bundle multiple rejections into a single result.
    Supports stable ordering and aggregation.
    """

    items: tuple[Rejection, ...] = ()

    def __post_init__(self) -> None:
        if not self.items:
            return
        # Stable ordering by (severity, domain, code, fingerprint)
        ordered = tuple(
            sorted(
                self.items,
                key=lambda r: (r.severity.value, r.domain.value, r.code.value, r.fingerprint()),
            )
        )
        object.__setattr__(self, "items", ordered)

    def is_empty(self) -> bool:
        return len(self.items) == 0

    def fingerprints(self) -> tuple[str, ...]:
        return tuple(r.fingerprint() for r in self.items)

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "count": len(self.items),
            "items": [r.to_public_dict() for r in self.items],
        }

    def to_internal_dict(self) -> dict[str, Any]:
        return {
            "count": len(self.items),
            "items": [r.to_internal_dict() for r in self.items],
        }

    def to_json(self, public: bool = True) -> str:
        return _canonical_json(self.to_public_dict() if public else self.to_internal_dict())

    def raise_if_any(self) -> None:
        if self.items:
            raise RejectionError(self.to_json(public=False))


def reject(
    *,
    code: RejectionCode,
    domain: RejectionDomain,
    severity: RejectionSeverity = RejectionSeverity.ERROR,
    safe_message: str = "Request rejected.",
    details: Sequence[RejectionDetail] | None = None,
    request_id: str | None = None,
    packet_id: str | None = None,
    actor_id: str | None = None,
    debug_context: Mapping[str, Any] | None = None,
    references: Iterable[str] | None = None,
) -> Rejection:
    return Rejection(
        code=code,
        domain=domain,
        severity=severity,
        safe_message=safe_message,
        details=tuple(details or ()),
        request_id=request_id,
        packet_id=packet_id,
        actor_id=actor_id,
        debug_context=debug_context,
        references=tuple(references or ()),
    )


__all__ = [
    "RejectionError",
    "RejectionSeverity",
    "RejectionDomain",
    "RejectionCode",
    "RejectionDetail",
    "Rejection",
    "RejectionBundle",
    "reject",
]
