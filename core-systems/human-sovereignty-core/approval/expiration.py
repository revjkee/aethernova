# path: human-sovereignty-core/approval/expiration.py
from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional


class ApprovalExpired(RuntimeError):
    pass


class ApprovalInvalid(RuntimeError):
    pass


@dataclass(frozen=True)
class ApprovalWindow:
    """
    Represents a strictly bounded approval time window.
    Approval is valid only in [issued_at_utc, expires_at_utc).
    """
    issued_at_utc: _dt.datetime
    expires_at_utc: _dt.datetime
    approver_id: str
    reason: str
    approval_id: str

    def validate(self, now_utc: Optional[_dt.datetime] = None) -> None:
        now = now_utc or _dt.datetime.now(tz=_dt.timezone.utc)

        if self.issued_at_utc.tzinfo is None or self.expires_at_utc.tzinfo is None:
            raise ApprovalInvalid("approval timestamps must be timezone-aware")

        if self.expires_at_utc <= self.issued_at_utc:
            raise ApprovalInvalid("expires_at_utc must be after issued_at_utc")

        if not self.approver_id or not self.approver_id.strip():
            raise ApprovalInvalid("approver_id is required")

        if not self.reason or not self.reason.strip():
            raise ApprovalInvalid("reason is required")

        if now < self.issued_at_utc:
            raise ApprovalInvalid("approval not yet valid")

        if now >= self.expires_at_utc:
            raise ApprovalExpired("approval window expired")

    def is_expired(self, now_utc: Optional[_dt.datetime] = None) -> bool:
        now = now_utc or _dt.datetime.now(tz=_dt.timezone.utc)
        return now >= self.expires_at_utc

    def fingerprint(self) -> str:
        payload = {
            "approval_id": self.approval_id,
            "approver_id": self.approver_id,
            "issued_at_utc": _iso_utc(self.issued_at_utc),
            "expires_at_utc": _iso_utc(self.expires_at_utc),
            "reason": self.reason,
        }
        return hashlib.sha256(_json_dumps_canonical(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ApprovalCheckResult:
    ok: bool
    expired: bool
    approval_fingerprint: str
    checked_at_utc: str
    reason: Optional[str] = None


def check_approval(
    approval: ApprovalWindow,
    *,
    now_utc: Optional[_dt.datetime] = None,
) -> ApprovalCheckResult:
    """
    Fail-closed approval validation.
    Any error or ambiguity results in denial.
    """
    now = now_utc or _dt.datetime.now(tz=_dt.timezone.utc)

    try:
        approval.validate(now_utc=now)
        return ApprovalCheckResult(
            ok=True,
            expired=False,
            approval_fingerprint=approval.fingerprint(),
            checked_at_utc=_iso_utc(now),
        )
    except ApprovalExpired as e:
        return ApprovalCheckResult(
            ok=False,
            expired=True,
            approval_fingerprint=approval.fingerprint(),
            checked_at_utc=_iso_utc(now),
            reason=str(e),
        )
    except Exception as e:
        return ApprovalCheckResult(
            ok=False,
            expired=False,
            approval_fingerprint=approval.fingerprint(),
            checked_at_utc=_iso_utc(now),
            reason=str(e),
        )


def enforce_approval(
    approval: ApprovalWindow,
    *,
    now_utc: Optional[_dt.datetime] = None,
) -> ApprovalCheckResult:
    """
    Enforces approval validity.
    Raises on any failure.
    """
    result = check_approval(approval, now_utc=now_utc)
    if not result.ok:
        if result.expired:
            raise ApprovalExpired(result.reason or "approval expired")
        raise ApprovalInvalid(result.reason or "approval invalid")
    return result


def approval_from_dict(data: Mapping[str, Any]) -> ApprovalWindow:
    """
    Strict parsing from external representations.
    """
    try:
        issued = _parse_dt_utc(data["issued_at_utc"])
        expires = _parse_dt_utc(data["expires_at_utc"])
        return ApprovalWindow(
            approval_id=str(data["approval_id"]),
            approver_id=str(data["approver_id"]),
            issued_at_utc=issued,
            expires_at_utc=expires,
            reason=str(data["reason"]),
        )
    except KeyError as e:
        raise ApprovalInvalid(f"missing field: {e}") from e


def approval_to_dict(approval: ApprovalWindow) -> Dict[str, Any]:
    return {
        "approval_id": approval.approval_id,
        "approver_id": approval.approver_id,
        "issued_at_utc": _iso_utc(approval.issued_at_utc),
        "expires_at_utc": _iso_utc(approval.expires_at_utc),
        "reason": approval.reason,
        "fingerprint": approval.fingerprint(),
    }


def _iso_utc(dt: _dt.datetime) -> str:
    if dt.tzinfo is None:
        raise ApprovalInvalid("datetime must be timezone-aware")
    return dt.astimezone(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_dt_utc(value: Any) -> _dt.datetime:
    if isinstance(value, _dt.datetime):
        if value.tzinfo is None:
            raise ApprovalInvalid("datetime must be timezone-aware")
        return value.astimezone(_dt.timezone.utc)

    if not isinstance(value, str):
        raise ApprovalInvalid("datetime must be ISO-8601 string")

    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"

    try:
        dt = _dt.datetime.fromisoformat(s)
    except ValueError as e:
        raise ApprovalInvalid("invalid datetime format") from e

    if dt.tzinfo is None:
        raise ApprovalInvalid("datetime must include timezone")

    return dt.astimezone(_dt.timezone.utc)


def _json_dumps_canonical(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
