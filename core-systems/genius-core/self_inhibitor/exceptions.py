"""
genius_core.security.self_inhibitor.exceptions
Industrial-grade exception hierarchy for Self-Inhibitor policy enforcement.

Key features:
- Strongly typed error codes and severities.
- Safe serialization (dict / RFC7807 problem+json).
- Mappings to HTTP and gRPC status codes (no external deps).
- Logging level hints and remediation guidance.
- Context redaction to avoid leaking sensitive data in logs.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from http import HTTPStatus
from typing import Any, Dict, Mapping, MutableMapping, Optional


# ---------------------------
# Enums
# ---------------------------

class Severity(Enum):
    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50


class ErrorCode(str, Enum):
    POLICY_VIOLATION = "policy_violation"
    UNSAFE_CONTENT = "unsafe_content"
    PROMPT_INJECTION_DETECTED = "prompt_injection_detected"
    DATA_LEAK_DETECTED = "data_leak_detected"
    PII_EXPOSURE_DETECTED = "pii_exposure_detected"
    MALWARE_SUSPECTED = "malware_suspected"
    COMPLIANCE_ERROR = "compliance_error"
    USER_CONSENT_REQUIRED = "user_consent_required"
    ACTION_BLOCKED = "action_blocked"
    TOOL_MISUSE = "tool_misuse"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    BACKOFF_REQUIRED = "backoff_required"
    CIRCUIT_OPEN = "circuit_open"
    QUARANTINE_TRIGGERED = "quarantine_triggered"
    REDTEAM_TRAP_TRIGGERED = "redteam_trap_triggered"
    OUTPUT_FILTERING_ERROR = "output_filtering_error"
    INTERNAL_EVALUATION_ERROR = "internal_evaluation_error"


# ---------------------------
# Defaults and mappings
# ---------------------------

_DEFAULT_HTTP: Dict[ErrorCode, HTTPStatus] = {
    ErrorCode.POLICY_VIOLATION: HTTPStatus.FORBIDDEN,
    ErrorCode.UNSAFE_CONTENT: HTTPStatus.FORBIDDEN,
    ErrorCode.PROMPT_INJECTION_DETECTED: HTTPStatus.FORBIDDEN,
    ErrorCode.DATA_LEAK_DETECTED: HTTPStatus.FORBIDDEN,
    ErrorCode.PII_EXPOSURE_DETECTED: HTTPStatus.FORBIDDEN,
    ErrorCode.MALWARE_SUSPECTED: HTTPStatus.FORBIDDEN,
    ErrorCode.COMPLIANCE_ERROR: HTTPStatus.UNAVAILABLE_FOR_LEGAL_REASONS,
    ErrorCode.USER_CONSENT_REQUIRED: HTTPStatus.PRECONDITION_REQUIRED,
    ErrorCode.ACTION_BLOCKED: HTTPStatus.FORBIDDEN,
    ErrorCode.TOOL_MISUSE: HTTPStatus.BAD_REQUEST,
    ErrorCode.RATE_LIMIT_EXCEEDED: HTTPStatus.TOO_MANY_REQUESTS,
    ErrorCode.BACKOFF_REQUIRED: HTTPStatus.TOO_MANY_REQUESTS,
    ErrorCode.CIRCUIT_OPEN: HTTPStatus.SERVICE_UNAVAILABLE,
    ErrorCode.QUARANTINE_TRIGGERED: HTTPStatus.LOCKED,
    ErrorCode.REDTEAM_TRAP_TRIGGERED: HTTPStatus.FORBIDDEN,
    ErrorCode.OUTPUT_FILTERING_ERROR: HTTPStatus.UNPROCESSABLE_ENTITY,
    ErrorCode.INTERNAL_EVALUATION_ERROR: HTTPStatus.INTERNAL_SERVER_ERROR,
}

_DEFAULT_SEVERITY: Dict[ErrorCode, Severity] = {
    ErrorCode.POLICY_VIOLATION: Severity.MEDIUM,
    ErrorCode.UNSAFE_CONTENT: Severity.HIGH,
    ErrorCode.PROMPT_INJECTION_DETECTED: Severity.MEDIUM,
    ErrorCode.DATA_LEAK_DETECTED: Severity.CRITICAL,
    ErrorCode.PII_EXPOSURE_DETECTED: Severity.HIGH,
    ErrorCode.MALWARE_SUSPECTED: Severity.CRITICAL,
    ErrorCode.COMPLIANCE_ERROR: Severity.HIGH,
    ErrorCode.USER_CONSENT_REQUIRED: Severity.INFO,
    ErrorCode.ACTION_BLOCKED: Severity.MEDIUM,
    ErrorCode.TOOL_MISUSE: Severity.LOW,
    ErrorCode.RATE_LIMIT_EXCEEDED: Severity.LOW,
    ErrorCode.BACKOFF_REQUIRED: Severity.LOW,
    ErrorCode.CIRCUIT_OPEN: Severity.MEDIUM,
    ErrorCode.QUARANTINE_TRIGGERED: Severity.HIGH,
    ErrorCode.REDTEAM_TRAP_TRIGGERED: Severity.HIGH,
    ErrorCode.OUTPUT_FILTERING_ERROR: Severity.MEDIUM,
    ErrorCode.INTERNAL_EVALUATION_ERROR: Severity.HIGH,
}

_DEFAULT_LOG_LEVEL: Dict[Severity, int] = {
    Severity.INFO: logging.INFO,
    Severity.LOW: logging.WARNING,
    Severity.MEDIUM: logging.WARNING,
    Severity.HIGH: logging.ERROR,
    Severity.CRITICAL: logging.CRITICAL,
}

# Minimal gRPC status code mapping to integers to avoid dependency
# https://grpc.github.io/grpc/core/md_doc_statuscodes.html
_GRPC_STATUS: Dict[ErrorCode, int] = {
    ErrorCode.POLICY_VIOLATION: 7,          # PERMISSION_DENIED
    ErrorCode.UNSAFE_CONTENT: 7,            # PERMISSION_DENIED
    ErrorCode.PROMPT_INJECTION_DETECTED: 7, # PERMISSION_DENIED
    ErrorCode.DATA_LEAK_DETECTED: 7,        # PERMISSION_DENIED
    ErrorCode.PII_EXPOSURE_DETECTED: 7,     # PERMISSION_DENIED
    ErrorCode.MALWARE_SUSPECTED: 7,         # PERMISSION_DENIED
    ErrorCode.COMPLIANCE_ERROR: 10,         # ABORTED (legal)
    ErrorCode.USER_CONSENT_REQUIRED: 9,     # FAILED_PRECONDITION
    ErrorCode.ACTION_BLOCKED: 7,            # PERMISSION_DENIED
    ErrorCode.TOOL_MISUSE: 3,               # INVALID_ARGUMENT
    ErrorCode.RATE_LIMIT_EXCEEDED: 8,       # RESOURCE_EXHAUSTED
    ErrorCode.BACKOFF_REQUIRED: 8,          # RESOURCE_EXHAUSTED
    ErrorCode.CIRCUIT_OPEN: 14,             # UNAVAILABLE
    ErrorCode.QUARANTINE_TRIGGERED: 7,      # PERMISSION_DENIED
    ErrorCode.REDTEAM_TRAP_TRIGGERED: 7,    # PERMISSION_DENIED
    ErrorCode.OUTPUT_FILTERING_ERROR: 13,   # INTERNAL
    ErrorCode.INTERNAL_EVALUATION_ERROR: 13,# INTERNAL
}


# ---------------------------
# Utilities
# ---------------------------

_PII_PATTERNS = [
    re.compile(r"\b\d{12,19}\b"),              # card-like
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),      # ssn-like
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),  # email
]

def _redact(value: Any, max_len: int = 2048) -> Any:
    """
    Best-effort redaction for logging/serialization to avoid leaking sensitive data.
    """
    try:
        s = str(value)
    except Exception:
        return "<unprintable>"
    s = s[:max_len]
    for pat in _PII_PATTERNS:
        s = pat.sub("[REDACTED]", s)
    return s

def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ---------------------------
# Base exception
# ---------------------------

@dataclass
class SelfInhibitorError(Exception):
    code: ErrorCode
    message: str
    user_message: Optional[str] = None
    severity: Optional[Severity] = None
    http_status: Optional[HTTPStatus] = None
    policy_id: Optional[str] = None
    rule_id: Optional[str] = None
    advice: Optional[str] = None
    remediation: Optional[str] = None
    trace_id: Optional[str] = None
    incident_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    context: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity is None:
            self.severity = _DEFAULT_SEVERITY.get(self.code, Severity.MEDIUM)
        if self.http_status is None:
            self.http_status = _DEFAULT_HTTP.get(self.code, HTTPStatus.FORBIDDEN)
        if not self.trace_id:
            self.trace_id = os.getenv("TRACE_ID") or None
        # Ensure context is safe to serialize
        self.context = {k: _redact(v) for k, v in (self.context or {}).items()}

    # Python exception protocol
    def __str__(self) -> str:
        return f"{self.code}: {self.message} (incident={self.incident_id})"

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} code={self.code} severity={self.severity} http={int(self.http_status or 0)} incident={self.incident_id}>"

    # Logging helper
    @property
    def log_level(self) -> int:
        return _DEFAULT_LOG_LEVEL.get(self.severity or Severity.MEDIUM, logging.ERROR)

    # gRPC status helper
    @property
    def grpc_status(self) -> int:
        return _GRPC_STATUS.get(self.code, 13)

    # RFC 7807 problem+json serializer
    def to_problem_details(self, instance: Optional[str] = None) -> Dict[str, Any]:
        status = int(self.http_status or HTTPStatus.FORBIDDEN)
        problem = {
            "type": f"urn:genius-core:self-inhibitor:{self.code}",
            "title": self.code.replace("_", " ").title(),
            "status": status,
            "detail": self.user_message or "Request blocked by self-inhibitor.",
            "instance": instance or f"urn:incident:{self.incident_id}",
            "timestamp": _now_iso(),
        }
        extensions = {
            "severity": (self.severity or Severity.MEDIUM).name,
            "policy_id": self.policy_id,
            "rule_id": self.rule_id,
            "advice": self.advice,
            "remediation": self.remediation,
            "trace_id": self.trace_id,
        }
        # Include minimal redacted context under "context"
        if self.context:
            extensions["context"] = self.context
        # Drop None values
        for k in list(extensions.keys()):
            if extensions[k] is None:
                del extensions[k]
        problem.update(extensions)
        return problem

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "message": _redact(self.message),
            "user_message": self.user_message,
            "severity": (self.severity or Severity.MEDIUM).name,
            "http_status": int(self.http_status or HTTPStatus.FORBIDDEN),
            "policy_id": self.policy_id,
            "rule_id": self.rule_id,
            "advice": self.advice,
            "remediation": self.remediation,
            "trace_id": self.trace_id,
            "incident_id": self.incident_id,
            "context": self.context or {},
            "timestamp": _now_iso(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    # Predicates
    def is_retryable(self) -> bool:
        return self.code in {
            ErrorCode.RATE_LIMIT_EXCEEDED,
            ErrorCode.BACKOFF_REQUIRED,
            ErrorCode.CIRCUIT_OPEN,
        }

    def is_security_breach(self) -> bool:
        return self.code in {
            ErrorCode.DATA_LEAK_DETECTED,
            ErrorCode.PII_EXPOSURE_DETECTED,
            ErrorCode.MALWARE_SUSPECTED,
        }


# ---------------------------
# Concrete exceptions
# ---------------------------

class PolicyViolation(SelfInhibitorError):
    def __init__(self, message: str = "Policy violation", **kw: Any) -> None:
        super().__init__(
            code=ErrorCode.POLICY_VIOLATION,
            message=message,
            user_message=kw.pop("user_message", "Action blocked due to policy violation."),
            **kw,
        )


class UnsafeContentDetected(SelfInhibitorError):
    def __init__(self, message: str = "Unsafe content detected", **kw: Any) -> None:
        super().__init__(
            code=ErrorCode.UNSAFE_CONTENT,
            message=message,
            user_message=kw.pop("user_message", "Content rejected due to safety rules."),
            **kw,
        )


class PromptInjectionDetected(SelfInhibitorError):
    def __init__(self, message: str = "Prompt injection attempt detected", **kw: Any) -> None:
        super().__init__(
            code=ErrorCode.PROMPT_INJECTION_DETECTED,
            message=message,
            user_message=kw.pop("user_message", "Request blocked by security policy."),
            **kw,
        )


class DataLeakDetected(SelfInhibitorError):
    def __init__(self, message: str = "Potential data leak detected", **kw: Any) -> None:
        super().__init__(
            code=ErrorCode.DATA_LEAK_DETECTED,
            message=message,
            user_message=kw.pop("user_message", "Request blocked to prevent data leak."),
            **kw,
        )


class PIIExposureDetected(SelfInhibitorError):
    def __init__(self, message: str = "PII exposure detected", **kw: Any) -> None:
        super().__init__(
            code=ErrorCode.PII_EXPOSURE_DETECTED,
            message=message,
            user_message=kw.pop("user_message", "Request blocked due to PII exposure."),
            **kw,
        )


class MalwareSuspected(SelfInhibitorError):
    def __init__(self, message: str = "Malware or exploit suspected", **kw: Any) -> None:
        super().__init__(
            code=ErrorCode.MALWARE_SUSPECTED,
            message=message,
            user_message=kw.pop("user_message", "Request blocked due to security concerns."),
            **kw,
        )


class ComplianceError(SelfInhibitorError):
    def __init__(self, message: str = "Compliance restriction", **kw: Any) -> None:
        super().__init__(
            code=ErrorCode.COMPLIANCE_ERROR,
            message=message,
            user_message=kw.pop("user_message", "Content unavailable due to compliance rules."),
            **kw,
        )


class UserConsentRequired(SelfInhibitorError):
    def __init__(self, message: str = "User consent required", **kw: Any) -> None:
        super().__init__(
            code=ErrorCode.USER_CONSENT_REQUIRED,
            message=message,
            user_message=kw.pop("user_message", "Consent required to proceed."),
            **kw,
        )


class ActionBlocked(SelfInhibitorError):
    def __init__(self, message: str = "Action has been blocked", **kw: Any) -> None:
        super().__init__(
            code=ErrorCode.ACTION_BLOCKED,
            message=message,
            user_message=kw.pop("user_message", "Action blocked by policy."),
            **kw,
        )


class ToolMisuse(SelfInhibitorError):
    def __init__(self, message: str = "Tool misuse detected", **kw: Any) -> None:
        super().__init__(
            code=ErrorCode.TOOL_MISUSE,
            message=message,
            user_message=kw.pop("user_message", "Invalid tool usage."),
            **kw,
        )


class RateLimitExceeded(SelfInhibitorError):
    def __init__(self, message: str = "Rate limit exceeded", **kw: Any) -> None:
        super().__init__(
            code=ErrorCode.RATE_LIMIT_EXCEEDED,
            message=message,
            user_message=kw.pop("user_message", "Too many requests, please retry later."),
            **kw,
        )


class BackoffRequired(SelfInhibitorError):
    def __init__(self, message: str = "Backoff required", **kw: Any) -> None:
        super().__init__(
            code=ErrorCode.BACKOFF_REQUIRED,
            message=message,
            user_message=kw.pop("user_message", "Please slow down and retry."),
            **kw,
        )


class CircuitOpen(SelfInhibitorError):
    def __init__(self, message: str = "Circuit is open", **kw: Any) -> None:
        super().__init__(
            code=ErrorCode.CIRCUIT_OPEN,
            message=message,
            user_message=kw.pop("user_message", "Service temporarily unavailable."),
            **kw,
        )


class QuarantineTriggered(SelfInhibitorError):
    def __init__(self, message: str = "Quarantine triggered", **kw: Any) -> None:
        super().__init__(
            code=ErrorCode.QUARANTINE_TRIGGERED,
            message=message,
            user_message=kw.pop("user_message", "Request quarantined by security policy."),
            **kw,
        )


class RedTeamTrapTriggered(SelfInhibitorError):
    def __init__(self, message: str = "Red-team trap triggered", **kw: Any) -> None:
        super().__init__(
            code=ErrorCode.REDTEAM_TRAP_TRIGGERED,
            message=message,
            user_message=kw.pop("user_message", "Request blocked by security trap."),
            **kw,
        )


class OutputFilteringError(SelfInhibitorError):
    def __init__(self, message: str = "Output filtering failed", **kw: Any) -> None:
        super().__init__(
            code=ErrorCode.OUTPUT_FILTERING_ERROR,
            message=message,
            user_message=kw.pop("user_message", "Could not safely produce the output."),
            **kw,
        )


class InternalEvaluationError(SelfInhibitorError):
    def __init__(self, message: str = "Internal evaluation error", **kw: Any) -> None:
        super().__init__(
            code=ErrorCode.INTERNAL_EVALUATION_ERROR,
            message=message,
            user_message=kw.pop("user_message", "Internal error during safety evaluation."),
            **kw,
        )


# ---------------------------
# Factory helpers
# ---------------------------

def make_policy_violation(rule_id: str, policy_id: Optional[str] = None, detail: str = "", **ctx: Any) -> PolicyViolation:
    return PolicyViolation(
        message=f"Policy '{policy_id or 'unknown'}' rule '{rule_id}' violation: {detail or 'blocked'}",
        policy_id=policy_id,
        rule_id=rule_id,
        context=ctx,
        advice="See policy logs for details.",
        remediation="Adjust input or request elevated permissions.",
    )

def make_data_leak(snippet: str, source: str = "unknown", **ctx: Any) -> DataLeakDetected:
    return DataLeakDetected(
        message=f"Potential data leak from source {source}",
        user_message="Request appears to expose sensitive data.",
        context={"snippet": snippet, "source": source, **ctx},
        advice="Redact sensitive fragments.",
        remediation="Remove secrets or PII and retry.",
        severity=Severity.CRITICAL,
    )


# ---------------------------
# Logging utility
# ---------------------------

def log_exception(exc: SelfInhibitorError, logger: Optional[logging.Logger] = None) -> None:
    logger = logger or logging.getLogger("genius_core.security.self_inhibitor")
    payload = exc.to_dict()
    # Structured log line
    logger.log(exc.log_level, json.dumps(payload, ensure_ascii=False))


# ---------------------------
# Example guard (optional)
# ---------------------------

def guard_raise_if_blocked(result: Mapping[str, Any]) -> None:
    """
    Convert a generic policy-check result into a typed exception.
    Expected shape:
      {"allowed": bool, "code": "policy_violation", "message": "...", "policy_id": "...", "rule_id": "...", "context": {...}}
    """
    if result.get("allowed", False):
        return
    code = ErrorCode(result.get("code", ErrorCode.POLICY_VIOLATION))
    klass = {
        ErrorCode.POLICY_VIOLATION: PolicyViolation,
        ErrorCode.UNSAFE_CONTENT: UnsafeContentDetected,
        ErrorCode.PROMPT_INJECTION_DETECTED: PromptInjectionDetected,
        ErrorCode.DATA_LEAK_DETECTED: DataLeakDetected,
        ErrorCode.PII_EXPOSURE_DETECTED: PIIExposureDetected,
        ErrorCode.MALWARE_SUSPECTED: MalwareSuspected,
        ErrorCode.COMPLIANCE_ERROR: ComplianceError,
        ErrorCode.USER_CONSENT_REQUIRED: UserConsentRequired,
        ErrorCode.ACTION_BLOCKED: ActionBlocked,
        ErrorCode.TOOL_MISUSE: ToolMisuse,
        ErrorCode.RATE_LIMIT_EXCEEDED: RateLimitExceeded,
        ErrorCode.BACKOFF_REQUIRED: BackoffRequired,
        ErrorCode.CIRCUIT_OPEN: CircuitOpen,
        ErrorCode.QUARANTINE_TRIGGERED: QuarantineTriggered,
        ErrorCode.REDTEAM_TRAP_TRIGGERED: RedTeamTrapTriggered,
        ErrorCode.OUTPUT_FILTERING_ERROR: OutputFilteringError,
        ErrorCode.INTERNAL_EVALUATION_ERROR: InternalEvaluationError,
    }.get(code, PolicyViolation)

    raise klass(
        message=str(result.get("message") or "Blocked by self-inhibitor"),
        policy_id=result.get("policy_id"),
        rule_id=result.get("rule_id"),
        context=dict(result.get("context") or {}),
        advice=result.get("advice"),
        remediation=result.get("remediation"),
        user_message=result.get("user_message"),
        trace_id=result.get("trace_id"),
    )
