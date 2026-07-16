# human-sovereignty-core/approval/channels/cli_channel.py
from __future__ import annotations

import json
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Optional, Sequence, Tuple, Union

try:
    from human_sovereignty_core.decision_packets.redaction import redact as redact_value  # type: ignore
except Exception:  # pragma: no cover
    redact_value = None  # type: ignore


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_tty() -> bool:
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:
        return False


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class ApprovalOutcome(str, Enum):
    APPROVED = "approved"
    REJECTED = "rejected"
    TIMEOUT = "timeout"
    ERROR = "error"


class ApprovalExitCode(int, Enum):
    OK_APPROVED = 0
    OK_REJECTED = 1
    ERR_TIMEOUT = 2
    ERR_USAGE = 64
    ERR_RUNTIME = 70


@dataclass(frozen=True)
class ApprovalRequest:
    request_id: str
    title: str
    summary: str
    severity: str = "SEV2"
    risk: str = "medium"
    reason: str = ""
    actor: str = "unknown"
    created_at: str = field(default_factory=_utcnow_iso)

    payload: Dict[str, Any] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    constraints: Dict[str, Any] = field(default_factory=dict)

    require_operator: bool = True
    require_reason_on_reject: bool = True
    allow_override_token: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "title": self.title,
            "summary": self.summary,
            "severity": self.severity,
            "risk": self.risk,
            "reason": self.reason,
            "actor": self.actor,
            "created_at": self.created_at,
            "payload": self.payload,
            "context": self.context,
            "constraints": self.constraints,
            "require_operator": self.require_operator,
            "require_reason_on_reject": self.require_reason_on_reject,
            "allow_override_token": self.allow_override_token,
        }


@dataclass(frozen=True)
class ApprovalResponse:
    request_id: str
    outcome: ApprovalOutcome
    operator: str
    operator_source: str
    decided_at: str
    rationale: str = ""
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "outcome": self.outcome.value,
            "operator": self.operator,
            "operator_source": self.operator_source,
            "decided_at": self.decided_at,
            "rationale": self.rationale,
            "meta": self.meta,
        }


class _Timeout(Exception):
    pass


class _Alarm:
    def __init__(self, seconds: int) -> None:
        self.seconds = int(seconds)
        self._enabled = False
        self._prev_handler = None

    def __enter__(self) -> "_Alarm":
        if self.seconds <= 0:
            return self
        if hasattr(signal, "SIGALRM"):
            self._prev_handler = signal.getsignal(signal.SIGALRM)
            signal.signal(signal.SIGALRM, self._handler)
            signal.alarm(self.seconds)
            self._enabled = True
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._enabled and hasattr(signal, "SIGALRM"):
            signal.alarm(0)
            if self._prev_handler is not None:
                signal.signal(signal.SIGALRM, self._prev_handler)

    @staticmethod
    def _handler(signum, frame) -> None:  # pragma: no cover
        raise _Timeout("timeout")


def _get_operator_from_env(env: MappingLike) -> Tuple[str, str]:
    for key in ("HS_OPERATOR", "HUMAN_OPERATOR", "OPERATOR", "USER", "USERNAME"):
        v = env.get(key)
        if v and str(v).strip():
            return str(v).strip(), f"env:{key}"
    return "unknown", "env:none"


def _read_line(prompt: str) -> str:
    sys.stdout.write(prompt)
    sys.stdout.flush()
    line = sys.stdin.readline()
    if not line:
        return ""
    return line.strip()


def _normalize_yes_no(s: str) -> Optional[bool]:
    v = (s or "").strip().lower()
    if v in ("y", "yes", "да", "д"):
        return True
    if v in ("n", "no", "нет", "н"):
        return False
    return None


def _redact(obj: Any) -> Any:
    if redact_value is None:
        return obj
    try:
        return redact_value(obj)
    except Exception:
        return obj


MappingLike = Dict[str, str]


@dataclass
class CLIChannelConfig:
    timeout_seconds: int = 600
    strict_non_interactive: bool = True
    print_redacted_request: bool = True
    output_json_response: bool = True

    env_auto_approve: str = "HS_AUTO_APPROVE"
    env_auto_reject: str = "HS_AUTO_REJECT"
    env_operator: str = "HS_OPERATOR"
    env_override_token: str = "HS_OVERRIDE_TOKEN"

    require_override_token_for_auto: bool = True

    def validate(self) -> None:
        if self.timeout_seconds < 0:
            raise ValueError("timeout_seconds must be >= 0")


class CLIApprovalChannel:
    def __init__(
        self,
        config: Optional[CLIChannelConfig] = None,
        audit_hook: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        env: Optional[MappingLike] = None,
    ) -> None:
        self.config = config or CLIChannelConfig()
        self.config.validate()
        self.audit_hook = audit_hook
        self.env = env if env is not None else dict(os.environ)

    def approve(self, request: ApprovalRequest) -> ApprovalResponse:
        started_at = time.time()

        operator, operator_source = _get_operator_from_env(self.env)
        if request.require_operator and operator == "unknown":
            operator = "unknown"

        self._audit("approval_requested", {"request": _redact(request.to_dict()), "operator": operator})

        if self.config.print_redacted_request:
            self._print_request(request)

        auto = self._try_auto_decide(request=request, operator=operator)
        if auto is not None:
            self._audit("approval_decided_auto", {"response": auto.to_dict(), "elapsed_ms": self._elapsed_ms(started_at)})
            self._maybe_print_response(auto)
            return auto

        if not _is_tty():
            if self.config.strict_non_interactive:
                resp = ApprovalResponse(
                    request_id=request.request_id,
                    outcome=ApprovalOutcome.REJECTED,
                    operator=operator,
                    operator_source=operator_source,
                    decided_at=_utcnow_iso(),
                    rationale="non_interactive_mode_denied",
                    meta={"mode": "non_interactive", "strict": True},
                )
                self._audit("approval_denied_non_interactive", {"response": resp.to_dict(), "elapsed_ms": self._elapsed_ms(started_at)})
                self._maybe_print_response(resp)
                return resp

            resp = ApprovalResponse(
                request_id=request.request_id,
                outcome=ApprovalOutcome.TIMEOUT,
                operator=operator,
                operator_source=operator_source,
                decided_at=_utcnow_iso(),
                rationale="non_interactive_no_input",
                meta={"mode": "non_interactive", "strict": False},
            )
            self._audit("approval_timeout_non_interactive", {"response": resp.to_dict(), "elapsed_ms": self._elapsed_ms(started_at)})
            self._maybe_print_response(resp)
            return resp

        try:
            with _Alarm(self.config.timeout_seconds):
                resp = self._interactive_flow(request=request, operator=operator, operator_source=operator_source)
        except _Timeout:
            resp = ApprovalResponse(
                request_id=request.request_id,
                outcome=ApprovalOutcome.TIMEOUT,
                operator=operator,
                operator_source=operator_source,
                decided_at=_utcnow_iso(),
                rationale="operator_input_timeout",
                meta={"timeout_seconds": self.config.timeout_seconds},
            )
        except Exception as e:
            resp = ApprovalResponse(
                request_id=request.request_id,
                outcome=ApprovalOutcome.ERROR,
                operator=operator,
                operator_source=operator_source,
                decided_at=_utcnow_iso(),
                rationale="runtime_error",
                meta={"error": str(e)[:512]},
            )

        self._audit("approval_decided", {"response": resp.to_dict(), "elapsed_ms": self._elapsed_ms(started_at)})
        self._maybe_print_response(resp)
        return resp

    def exit_code(self, response: ApprovalResponse) -> int:
        if response.outcome == ApprovalOutcome.APPROVED:
            return int(ApprovalExitCode.OK_APPROVED)
        if response.outcome == ApprovalOutcome.REJECTED:
            return int(ApprovalExitCode.OK_REJECTED)
        if response.outcome == ApprovalOutcome.TIMEOUT:
            return int(ApprovalExitCode.ERR_TIMEOUT)
        return int(ApprovalExitCode.ERR_RUNTIME)

    def _interactive_flow(self, request: ApprovalRequest, operator: str, operator_source: str) -> ApprovalResponse:
        sys.stdout.write("\nApproval required\n")
        sys.stdout.write("Type yes to approve, no to reject\n")
        sys.stdout.flush()

        decision: Optional[bool] = None
        while decision is None:
            ans = _read_line("Decision (yes/no): ")
            decision = _normalize_yes_no(ans)

        rationale = ""
        if decision is False and request.require_reason_on_reject:
            while not rationale.strip():
                rationale = _read_line("Rejection reason: ").strip()

        return ApprovalResponse(
            request_id=request.request_id,
            outcome=ApprovalOutcome.APPROVED if decision else ApprovalOutcome.REJECTED,
            operator=operator,
            operator_source=operator_source,
            decided_at=_utcnow_iso(),
            rationale=rationale,
            meta={"mode": "interactive"},
        )

    def _try_auto_decide(self, request: ApprovalRequest, operator: str) -> Optional[ApprovalResponse]:
        auto_approve = self._env_truthy(self.config.env_auto_approve)
        auto_reject = self._env_truthy(self.config.env_auto_reject)

        if auto_approve and auto_reject:
            return ApprovalResponse(
                request_id=request.request_id,
                outcome=ApprovalOutcome.ERROR,
                operator=operator,
                operator_source=f"env:{self.config.env_auto_approve},{self.config.env_auto_reject}",
                decided_at=_utcnow_iso(),
                rationale="conflicting_auto_flags",
                meta={"auto_approve": True, "auto_reject": True},
            )

        if not auto_approve and not auto_reject:
            return None

        if self.config.require_override_token_for_auto or request.allow_override_token:
            token_env = str(self.env.get(self.config.env_override_token, "")).strip()
            if not token_env:
                return ApprovalResponse(
                    request_id=request.request_id,
                    outcome=ApprovalOutcome.REJECTED,
                    operator=operator,
                    operator_source=f"env:{self.config.env_override_token}",
                    decided_at=_utcnow_iso(),
                    rationale="missing_override_token_for_auto",
                    meta={"auto_requested": True},
                )

        outcome = ApprovalOutcome.APPROVED if auto_approve else ApprovalOutcome.REJECTED
        src = f"env:{self.config.env_auto_approve}" if auto_approve else f"env:{self.config.env_auto_reject}"
        return ApprovalResponse(
            request_id=request.request_id,
            outcome=outcome,
            operator=operator,
            operator_source=src,
            decided_at=_utcnow_iso(),
            rationale="auto_decision",
            meta={"mode": "auto"},
        )

    def _env_truthy(self, key: str) -> bool:
        v = str(self.env.get(key, "")).strip().lower()
        return v in ("1", "true", "yes", "y", "да", "on")

    def _print_request(self, request: ApprovalRequest) -> None:
        safe = _redact(request.to_dict())
        sys.stdout.write("\nRequest\n")
        sys.stdout.write(_json_dumps(safe) + "\n")
        sys.stdout.flush()

    def _maybe_print_response(self, response: ApprovalResponse) -> None:
        if not self.config.output_json_response:
            return
        sys.stdout.write("\nResponse\n")
        sys.stdout.write(_json_dumps(response.to_dict()) + "\n")
        sys.stdout.flush()

    def _audit(self, event: str, payload: Dict[str, Any]) -> None:
        if self.audit_hook is None:
            return
        try:
            self.audit_hook(event, payload)
        except Exception:
            return

    @staticmethod
    def _elapsed_ms(started_at: float) -> int:
        return int((time.time() - started_at) * 1000)
