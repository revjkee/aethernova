# human-sovereignty-core/approval/channels/webui_channel.py
# Industrial-grade WebUI approval channel.
# Contract: request + observe only. NO approve / deny.
# Python 3.11+ recommended.

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional, Sequence

# Local dependency
try:
    from human_sovereignty_core.approval.approval_gate import (  # type: ignore
        ApprovalGate,
        ApprovalRecord,
        ApprovalRequest,
        ApprovalGateError,
    )
except Exception as _e:  # pragma: no cover
    raise ImportError(
        "webui_channel.py requires human_sovereignty_core.approval.approval_gate"
    ) from _e


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class WebUIChannelError(RuntimeError):
    """Base error for WebUI approval channel."""


class ForbiddenOperationError(WebUIChannelError):
    """Raised when WebUI attempts a forbidden operation."""


class InvalidWebUIRequestError(WebUIChannelError):
    """Raised when WebUI request payload is invalid."""


@dataclass(slots=True)
class WebUIAuditEvent:
    """
    Audit event for WebUI interactions.

    Used only for request/observe actions.
    """

    occurred_at: datetime
    actor_id: str
    action: str
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "occurred_at": self.occurred_at.isoformat(),
            "actor_id": self.actor_id,
            "action": self.action,
            "details": dict(self.details),
        }


@dataclass(slots=True)
class WebUIChannel:
    """
    WebUIChannel exposes a restricted interface to ApprovalGate.

    Guarantees:
      - cannot approve or deny
      - can only create approval requests
      - can only observe approval records
      - all interactions are auditable
    """

    gate: ApprovalGate

    _audit_log: list[WebUIAuditEvent] = field(default_factory=list, init=False)

    def request_approval(
        self,
        *,
        actor_id: str,
        action: str,
        subject_id: str,
        risk_factors: Sequence[Any],
        context: Optional[Mapping[str, Any]] = None,
        request_id: Optional[str] = None,
    ) -> ApprovalRecord:
        """
        Creates or retrieves an approval request.

        This is the ONLY mutating operation allowed from WebUI.
        """
        actor = (actor_id or "").strip()
        if not actor:
            raise InvalidWebUIRequestError("actor_id must be non-empty")

        act = (action or "").strip()
        subj = (subject_id or "").strip()

        if not act:
            raise InvalidWebUIRequestError("action must be non-empty")
        if not subj:
            raise InvalidWebUIRequestError("subject_id must be non-empty")

        req = ApprovalRequest(
            action=act,
            subject_id=subj,
            requester_id=actor,
            risk_factors=risk_factors,
            context=dict(context or {}),
            request_id=request_id,
        )

        try:
            record = self.gate.create_or_get(req)
        except ApprovalGateError as e:
            raise WebUIChannelError(str(e)) from e

        self._audit_log.append(
            WebUIAuditEvent(
                occurred_at=_utc_now(),
                actor_id=actor,
                action="REQUEST_APPROVAL",
                details={
                    "approval_id": record.approval_id,
                    "request_id": record.request_id,
                    "risk_level": record.risk_level.value,
                },
            )
        )
        return record

    def observe(
        self,
        *,
        actor_id: str,
        approval_id: str,
    ) -> Dict[str, Any]:
        """
        Returns a read-only projection of an approval record.

        Sensitive internal fields are filtered out.
        """
        actor = (actor_id or "").strip()
        if not actor:
            raise InvalidWebUIRequestError("actor_id must be non-empty")

        aid = (approval_id or "").strip()
        if not aid:
            raise InvalidWebUIRequestError("approval_id must be non-empty")

        try:
            rec = self.gate.get(aid)
        except ApprovalGateError as e:
            raise WebUIChannelError(str(e)) from e

        view = {
            "approval_id": rec.approval_id,
            "request_id": rec.request_id,
            "action": rec.action,
            "subject_id": rec.subject_id,
            "created_at": rec.created_at.isoformat(),
            "expires_at": rec.expires_at.isoformat() if rec.expires_at else None,
            "risk_level": rec.risk_level.value,
            "risk_score": rec.risk_score,
            "risk_reasons": list(rec.risk_reasons),
            "required_approvers": rec.required_approvers,
            "state": rec.state.value,
            "decision": rec.decision.value if rec.decision else None,
            "trail": [e.to_dict() for e in rec.trail],
        }

        self._audit_log.append(
            WebUIAuditEvent(
                occurred_at=_utc_now(),
                actor_id=actor,
                action="OBSERVE_APPROVAL",
                details={"approval_id": rec.approval_id, "state": rec.state.value},
            )
        )
        return view

    def audit_log(self) -> Sequence[Dict[str, Any]]:
        """
        Returns WebUI audit log as read-only data.
        """
        return [e.to_dict() for e in self._audit_log]

    # Explicitly forbidden operations

    def approve(self, *args: Any, **kwargs: Any) -> None:
        raise ForbiddenOperationError("WebUI channel cannot approve decisions")

    def deny(self, *args: Any, **kwargs: Any) -> None:
        raise ForbiddenOperationError("WebUI channel cannot deny decisions")

    def submit_verifications(self, *args: Any, **kwargs: Any) -> None:
        raise ForbiddenOperationError(
            "WebUI channel cannot submit verifications directly"
        )
