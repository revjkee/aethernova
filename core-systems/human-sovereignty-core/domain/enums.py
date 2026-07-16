# human-sovereignty-core/domain/enums.py
#
# Domain enums for Human Sovereignty Core.
#
# Design principles:
# - Explicitness over convenience
# - Deterministic string values for persistence, APIs, audit logs
# - Separation of concerns: enums describe state, not behavior
# - Forward-compatible: safe to extend without breaking stored data
#
# This file contains no assumptions about infrastructure or policy.
# It only defines domain-level classifications.

from __future__ import annotations

from enum import Enum
from typing import Set


class StrEnum(str, Enum):
    """
    Base class for string-backed enums.

    Rationale:
    - Stable serialization to JSON, DB, logs
    - Human-readable audit records
    - No implicit numeric coupling
    """

    def __str__(self) -> str:
        return self.value

    @classmethod
    def values(cls) -> Set[str]:
        return {e.value for e in cls}


class SovereigntyDomain(StrEnum):
    """
    High-level sovereignty domains.

    Used to classify which human right or autonomy surface
    is affected by an action, decision, or policy.
    """

    IDENTITY = "identity"
    BODY = "body"
    MIND = "mind"
    DATA = "data"
    ECONOMIC = "economic"
    DIGITAL = "digital"
    POLITICAL = "political"


class HumanConsentState(StrEnum):
    """
    Explicit consent state of a human subject.

    These values must be treated as legally and ethically significant.
    """

    UNKNOWN = "unknown"
    GRANTED = "granted"
    DENIED = "denied"
    REVOKED = "revoked"
    EXPIRED = "expired"


class DecisionAuthority(StrEnum):
    """
    Who or what made the decision.

    This enum is critical for auditability and accountability.
    """

    HUMAN = "human"
    HUMAN_GROUP = "human_group"
    AI_ASSISTED = "ai_assisted"
    AI_AUTONOMOUS = "ai_autonomous"
    SYSTEM_ENFORCED = "system_enforced"


class RiskLevel(StrEnum):
    """
    Abstract risk level classification.

    Used consistently across security, ethics, and governance layers.
    """

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EnforcementAction(StrEnum):
    """
    Possible enforcement actions applied by the system.

    These values describe outcomes, not intent.
    """

    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    ESCALATE = "escalate"
    TERMINATE = "terminate"


class AuditEventType(StrEnum):
    """
    Types of audit events emitted by the Human Sovereignty Core.

    Used for immutable audit logs and compliance pipelines.
    """

    ACCESS_REQUEST = "access_request"
    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED = "access_denied"
    CONSENT_CHANGED = "consent_changed"
    POLICY_EVALUATED = "policy_evaluated"
    ENFORCEMENT_APPLIED = "enforcement_applied"
    SYSTEM_OVERRIDE = "system_override"


class SovereigntyViolationType(StrEnum):
    """
    Canonical classification of sovereignty violations.

    These values must remain stable once introduced.
    """

    CONSENT_BYPASS = "consent_bypass"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_EXTRACTION = "data_extraction"
    COERCION = "coercion"
    SURVEILLANCE = "surveillance"
    MANIPULATION = "manipulation"
    AUTONOMY_OVERRIDE = "autonomy_override"


class ResolutionStatus(StrEnum):
    """
    Resolution lifecycle state for incidents or violations.
    """

    OPEN = "open"
    UNDER_REVIEW = "under_review"
    MITIGATED = "mitigated"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class PolicyScope(StrEnum):
    """
    Scope at which a policy applies.
    """

    GLOBAL = "global"
    ORGANIZATION = "organization"
    PROJECT = "project"
    INDIVIDUAL = "individual"


class SystemTrustLevel(StrEnum):
    """
    Trust level assigned to a system component.

    This is a relative, internal classification.
    """

    UNTRUSTED = "untrusted"
    LIMITED = "limited"
    TRUSTED = "trusted"
    CRITICAL = "critical"
