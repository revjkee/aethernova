# agent_mash/resilience/recovery/emergency.py
from __future__ import annotations

import dataclasses
import enum
import hashlib
import hmac
import json
import time
import uuid
from typing import Any, Dict, Iterable, Mapping, Optional, Protocol, Sequence, Tuple, Union


JsonDict = Dict[str, Any]
JsonLike = Union[JsonDict, str, int, float, bool, None]


class EmergencyError(RuntimeError):
    pass


class PayloadInvalid(EmergencyError):
    pass


class AuditSinkError(EmergencyError):
    pass


class EmergencyLevel(str, enum.Enum):
    SEV0 = "sev0"
    SEV1 = "sev1"
    SEV2 = "sev2"
    SEV3 = "sev3"


class EmergencyStatus(str, enum.Enum):
    DECLARED = "declared"
    MITIGATING = "mitigating"
    STABILIZED = "stabilized"
    RECOVERING = "recovering"
    RESOLVED = "resolved"
    ABORTED = "aborted"


class RecoveryActionType(str, enum.Enum):
    ISOLATE = "isolate"
    FAILOVER = "failover"
    SCALE = "scale"
    DISABLE = "disable"
    RESTORE = "restore"
    VERIFY = "verify"
    COMMUNICATE = "communicate"


@dataclasses.dataclass(frozen=True)
class EmergencyContext:
    incident_id: str
    level: EmergencyLevel
    service: str
    environment: str
    region: Optional[str]
    declared_at_ms: int
    actor_id: Optional[str]
    trace_id: str


@dataclasses.dataclass(frozen=True)
class RecoveryAction:
    action_id: str
    action_type: RecoveryActionType
    title: str
    description: str
    owner: str
    executed: bool = False
    executed_at_ms: Optional[int] = None
    result: Optional[str] = None


@dataclasses.dataclass(frozen=True)
class EmergencyTimelineEvent:
    ts_ms: int
    message: str
    data: Mapping[str, JsonLike] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True)
class EmergencyPlan:
    context: EmergencyContext
    status: EmergencyStatus
    actions: Tuple[RecoveryAction, ...]
    timeline: Tuple[EmergencyTimelineEvent, ...]
    policy_version: str = "emergency-recovery-v1"

    def to_dict(self) -> JsonDict:
        return {
            "incident_id": self.context.incident_id,
            "level": self.context.level.value,
            "service": self.context.service,
            "environment": self.context.environment,
            "region": self.context.region,
            "status": self.status.value,
            "declared_at_ms": self.context.declared_at_ms,
            "trace_id": self.context.trace_id,
            "actions": [dataclasses.asdict(a) for a in self.actions],
            "timeline": [dataclasses.asdict(e) for e in self.timeline],
            "policy_version": self.policy_version,
        }


class AuditSink(Protocol):
    async def emit(self, event: Mapping[str, JsonLike]) -> None:
        ...


def _now_ms() -> int:
    return int(time.time() * 1000)


def _stable_json(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except TypeError as e:
        raise PayloadInvalid(str(e)) from e


def _blake2b_hex(data: bytes, digest_size: int = 16) -> str:
    h_ = hashlib.blake2b(digest_size=digest_size)
    h_.update(data)
    return h_.hexdigest()


def _hmac_sha256_hex(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _trace_id(
    *,
    declared_at_ms: int,
    incident_id: str,
    service: str,
    level: EmergencyLevel,
    hmac_key: Optional[bytes],
) -> str:
    base = {
        "ts": declared_at_ms,
        "incident": incident_id,
        "service": service,
        "level": level.value,
    }
    raw = _stable_json(base).encode("utf-8")
    if hmac_key:
        return _hmac_sha256_hex(hmac_key, raw)
    return _blake2b_hex(raw, digest_size=16)


@dataclasses.dataclass(frozen=True)
class EmergencyPolicy:
    policy_version: str = "emergency-recovery-v1"
    default_owner: str = "oncall"
    trace_hmac_key: Optional[bytes] = None
    max_actions: int = 64


class EmergencyRecoveryManager:
    def __init__(
        self,
        *,
        policy: EmergencyPolicy,
        audit_sink: Optional[AuditSink] = None,
    ) -> None:
        if not policy.policy_version:
            raise PayloadInvalid("policy_version must be non-empty")
        self._policy = policy
        self._audit_sink = audit_sink

    async def declare(
        self,
        *,
        level: EmergencyLevel,
        service: str,
        environment: str,
        region: Optional[str] = None,
        actor_id: Optional[str] = None,
    ) -> EmergencyPlan:
        declared_at_ms = _now_ms()
        incident_id = _blake2b_hex(f"{service}:{declared_at_ms}:{uuid.uuid4().hex}".encode("utf-8"), digest_size=16)
        trace = _trace_id(
            declared_at_ms=declared_at_ms,
            incident_id=incident_id,
            service=service,
            level=level,
            hmac_key=self._policy.trace_hmac_key,
        )

        context = EmergencyContext(
            incident_id=incident_id,
            level=level,
            service=service,
            environment=environment,
            region=region,
            declared_at_ms=declared_at_ms,
            actor_id=actor_id,
            trace_id=trace,
        )

        timeline = (
            EmergencyTimelineEvent(
                ts_ms=declared_at_ms,
                message="Emergency declared",
                data={"level": level.value, "service": service},
            ),
        )

        actions = self._default_actions(context)

        plan = EmergencyPlan(
            context=context,
            status=EmergencyStatus.DECLARED,
            actions=actions,
            timeline=timeline,
            policy_version=self._policy.policy_version,
        )

        await self._audit(plan, event="declare")
        return plan

    def _default_actions(self, ctx: EmergencyContext) -> Tuple[RecoveryAction, ...]:
        base_actions: Sequence[Tuple[RecoveryActionType, str, str]] = (
            (
                RecoveryActionType.COMMUNICATE,
                "Notify stakeholders",
                "Inform on-call team and stakeholders about the emergency.",
            ),
            (
                RecoveryActionType.ISOLATE,
                "Isolate affected components",
                "Limit blast radius by isolating unhealthy components.",
            ),
            (
                RecoveryActionType.FAILOVER,
                "Initiate failover",
                "Switch traffic to standby or backup systems if available.",
            ),
            (
                RecoveryActionType.RESTORE,
                "Restore service",
                "Recover primary service to a healthy state.",
            ),
            (
                RecoveryActionType.VERIFY,
                "Verify stability",
                "Confirm metrics and user experience are stable.",
            ),
        )

        actions: list[RecoveryAction] = []
        for idx, (atype, title, desc) in enumerate(base_actions):
            if len(actions) >= self._policy.max_actions:
                break
            aid = _blake2b_hex(f"{ctx.incident_id}:{atype.value}:{idx}".encode("utf-8"), digest_size=16)
            actions.append(
                RecoveryAction(
                    action_id=aid,
                    action_type=atype,
                    title=title,
                    description=desc,
                    owner=self._policy.default_owner,
                )
            )
        return tuple(actions)

    async def update_status(
        self,
        plan: EmergencyPlan,
        *,
        status: EmergencyStatus,
        message: str,
        data: Optional[Mapping[str, JsonLike]] = None,
    ) -> EmergencyPlan:
        event = EmergencyTimelineEvent(
            ts_ms=_now_ms(),
            message=message,
            data=data or {},
        )
        updated = dataclasses.replace(
            plan,
            status=status,
            timeline=plan.timeline + (event,),
        )
        await self._audit(updated, event="status_update")
        return updated

    async def mark_action_executed(
        self,
        plan: EmergencyPlan,
        *,
        action_id: str,
        result: str,
    ) -> EmergencyPlan:
        now = _now_ms()
        new_actions: list[RecoveryAction] = []
        found = False

        for a in plan.actions:
            if a.action_id == action_id:
                found = True
                new_actions.append(
                    dataclasses.replace(
                        a,
                        executed=True,
                        executed_at_ms=now,
                        result=result,
                    )
                )
            else:
                new_actions.append(a)

        if not found:
            raise EmergencyError("action_id not found")

        event = EmergencyTimelineEvent(
            ts_ms=now,
            message="Action executed",
            data={"action_id": action_id, "result": result},
        )

        updated = dataclasses.replace(
            plan,
            actions=tuple(new_actions),
            timeline=plan.timeline + (event,),
        )
        await self._audit(updated, event="action_executed")
        return updated

    async def _audit(self, plan: EmergencyPlan, *, event: str) -> None:
        if self._audit_sink is None:
            return
        payload: JsonDict = {
            "event": event,
            "incident_id": plan.context.incident_id,
            "trace_id": plan.context.trace_id,
            "status": plan.status.value,
            "level": plan.context.level.value,
            "service": plan.context.service,
            "environment": plan.context.environment,
            "region": plan.context.region,
            "timestamp_ms": _now_ms(),
            "actions": [dataclasses.asdict(a) for a in plan.actions],
        }
        try:
            await self._audit_sink.emit(payload)
        except Exception as e:
            raise AuditSinkError(str(e)) from e
