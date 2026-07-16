# path: human-sovereignty-core/decision_packets/lifecycle.py
from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import json
import threading
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from human_sovereignty_core.bootstrap.invariants import (
    DecisionContext,
    InvariantResult,
    SovereigntyPolicy,
    enforce as enforce_invariants,
    get_default_policy,
)

# NOTE:
# - This module is designed to be "fail-closed".
# - Any invalid transition or missing mandatory data raises.
# - All mutations produce deterministic audit events.


class PacketError(RuntimeError):
    pass


class TransitionDenied(PacketError):
    pass


class PacketExpired(PacketError):
    pass


class PacketState(Enum):
    DRAFT = "draft"
    SUBMITTED = "submitted"
    VALIDATED = "validated"
    AWAITING_HUMAN_APPROVAL = "awaiting_human_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    EXECUTED = "executed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    ARCHIVED = "archived"


class PacketEventType(Enum):
    CREATE = "create"
    SUBMIT = "submit"
    VALIDATE = "validate"
    REQUIRE_APPROVAL = "require_approval"
    APPROVE = "approve"
    REJECT = "reject"
    START_EXECUTION = "start_execution"
    FINISH_EXECUTION = "finish_execution"
    FAIL = "fail"
    CANCEL = "cancel"
    EXPIRE = "expire"
    ARCHIVE = "archive"


@dataclass(frozen=True)
class PacketEvent:
    event_id: str
    packet_id: str
    type: PacketEventType
    from_state: PacketState
    to_state: PacketState
    at_utc: str  # ISO-8601 Z
    actor: str
    reason: str
    data: Mapping[str, Any] = field(default_factory=dict)
    fingerprint: str = ""

    def with_fingerprint(self) -> "PacketEvent":
        payload = {
            "event_id": self.event_id,
            "packet_id": self.packet_id,
            "type": self.type.value,
            "from_state": self.from_state.value,
            "to_state": self.to_state.value,
            "at_utc": self.at_utc,
            "actor": self.actor,
            "reason": self.reason,
            "data": _canonicalize(self.data),
        }
        fp = hashlib.sha256(_json_dumps_canonical(payload).encode("utf-8")).hexdigest()
        return dataclasses.replace(self, fingerprint=fp)


@dataclass(frozen=True)
class DecisionPacket:
    packet_id: str
    created_at_utc: _dt.datetime
    ttl_seconds: int
    context: DecisionContext
    state: PacketState = PacketState.DRAFT
    events: Tuple[PacketEvent, ...] = field(default_factory=tuple)

    def is_expired(self, now_utc: Optional[_dt.datetime] = None) -> bool:
        now = now_utc or _dt.datetime.now(tz=_dt.timezone.utc)
        return now >= (self.created_at_utc + _dt.timedelta(seconds=int(self.ttl_seconds)))

    def expires_at_utc(self) -> _dt.datetime:
        return self.created_at_utc + _dt.timedelta(seconds=int(self.ttl_seconds))

    def fingerprint(self) -> str:
        payload = {
            "packet_id": self.packet_id,
            "created_at_utc": _iso_utc(self.created_at_utc),
            "ttl_seconds": int(self.ttl_seconds),
            "context_fp": self.context.fingerprint(),
            "state": self.state.value,
            "events": [e.fingerprint for e in self.events],
        }
        return hashlib.sha256(_json_dumps_canonical(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class LifecycleConfig:
    # Fail-closed by default.
    fail_closed: bool = True
    # Upper bound for TTL to avoid "eternal pending" packets.
    max_ttl_seconds: int = 7 * 24 * 3600
    # If true, auto-move to EXPIRED when TTL elapsed on any operation.
    auto_expire_on_touch: bool = True
    # Require reason strings on sensitive events.
    require_reason: bool = True
    # Keep audit events bounded; older events can be compacted by archiver.
    max_events: int = 10_000


_DEFAULT_CONFIG = LifecycleConfig()
_LOCK = threading.RLock()


def get_default_config() -> LifecycleConfig:
    return _DEFAULT_CONFIG


def set_default_config(cfg: LifecycleConfig) -> None:
    global _DEFAULT_CONFIG
    _DEFAULT_CONFIG = cfg


TransitionHook = Callable[[DecisionPacket, PacketEvent], None]


@dataclass
class Lifecycle:
    policy: SovereigntyPolicy = field(default_factory=get_default_policy)
    config: LifecycleConfig = field(default_factory=get_default_config)
    on_event: Optional[TransitionHook] = None

    def new_packet(
        self,
        *,
        context: DecisionContext,
        ttl_seconds: int,
        actor: str,
        reason: str = "create",
        packet_id: Optional[str] = None,
        now_utc: Optional[_dt.datetime] = None,
    ) -> DecisionPacket:
        now = now_utc or _dt.datetime.now(tz=_dt.timezone.utc)
        pid = packet_id or str(uuid.uuid4())
        ttl = int(ttl_seconds)
        if ttl <= 0:
            raise PacketError("ttl_seconds must be positive")
        if ttl > self.config.max_ttl_seconds:
            raise PacketError("ttl_seconds exceeds max_ttl_seconds")
        pkt = DecisionPacket(packet_id=pid, created_at_utc=now, ttl_seconds=ttl, context=context)
        pkt = self._append_event(
            pkt,
            self._mk_event(
                packet_id=pid,
                etype=PacketEventType.CREATE,
                from_state=PacketState.DRAFT,
                to_state=PacketState.DRAFT,
                actor=actor,
                reason=reason,
                data={"context_fp": context.fingerprint()},
                now_utc=now,
            ),
        )
        return pkt

    def submit(self, pkt: DecisionPacket, *, actor: str, reason: str, now_utc: Optional[_dt.datetime] = None) -> DecisionPacket:
        return self._transition(pkt, PacketEventType.SUBMIT, PacketState.SUBMITTED, actor=actor, reason=reason, now_utc=now_utc)

    def validate(self, pkt: DecisionPacket, *, actor: str, reason: str, now_utc: Optional[_dt.datetime] = None) -> Tuple[DecisionPacket, InvariantResult]:
        with _LOCK:
            pkt = self._touch(pkt, now_utc)
            self._require_state(pkt, {PacketState.SUBMITTED}, PacketEventType.VALIDATE)

            now = now_utc or _dt.datetime.now(tz=_dt.timezone.utc)
            # Enforce sovereignty invariants against the decision context.
            inv = enforce_invariants(pkt.context, policy=self.policy, now_utc=now)

            pkt = self._append_event(
                dataclasses.replace(pkt, state=PacketState.VALIDATED),
                self._mk_event(
                    packet_id=pkt.packet_id,
                    etype=PacketEventType.VALIDATE,
                    from_state=PacketState.SUBMITTED,
                    to_state=PacketState.VALIDATED,
                    actor=actor,
                    reason=reason,
                    data={"invariants": dataclasses.asdict(inv)},
                    now_utc=now,
                ),
            )

            # Decide whether approval is required.
            if inv.approval_mode.value == "required":
                pkt = self._append_event(
                    dataclasses.replace(pkt, state=PacketState.AWAITING_HUMAN_APPROVAL),
                    self._mk_event(
                        packet_id=pkt.packet_id,
                        etype=PacketEventType.REQUIRE_APPROVAL,
                        from_state=PacketState.VALIDATED,
                        to_state=PacketState.AWAITING_HUMAN_APPROVAL,
                        actor=actor,
                        reason="approval_required_by_policy",
                        data={"policy_id": inv.policy_id},
                        now_utc=now,
                    ),
                )
            else:
                pkt = self._append_event(
                    dataclasses.replace(pkt, state=PacketState.APPROVED),
                    self._mk_event(
                        packet_id=pkt.packet_id,
                        etype=PacketEventType.APPROVE,
                        from_state=PacketState.VALIDATED,
                        to_state=PacketState.APPROVED,
                        actor=actor,
                        reason="auto_approved_noncritical",
                        data={"policy_id": inv.policy_id},
                        now_utc=now,
                    ),
                )

            return pkt, inv

    def approve(self, pkt: DecisionPacket, *, actor: str, reason: str, now_utc: Optional[_dt.datetime] = None) -> DecisionPacket:
        with _LOCK:
            pkt = self._touch(pkt, now_utc)
            self._require_state(pkt, {PacketState.AWAITING_HUMAN_APPROVAL}, PacketEventType.APPROVE)
            now = now_utc or _dt.datetime.now(tz=_dt.timezone.utc)
            # Approval must be by the human sovereign; enforce invariant again (fail-closed).
            inv = enforce_invariants(pkt.context, policy=self.policy, now_utc=now)
            if inv.approval_mode.value != "required":
                raise TransitionDenied("approval not required by policy for this packet")
            pkt = self._append_event(
                dataclasses.replace(pkt, state=PacketState.APPROVED),
                self._mk_event(
                    packet_id=pkt.packet_id,
                    etype=PacketEventType.APPROVE,
                    from_state=PacketState.AWAITING_HUMAN_APPROVAL,
                    to_state=PacketState.APPROVED,
                    actor=actor,
                    reason=reason,
                    data={"invariants_fp": inv.context_fingerprint, "policy_id": inv.policy_id},
                    now_utc=now,
                ),
            )
            return pkt

    def reject(self, pkt: DecisionPacket, *, actor: str, reason: str, now_utc: Optional[_dt.datetime] = None) -> DecisionPacket:
        return self._transition(pkt, PacketEventType.REJECT, PacketState.REJECTED, actor=actor, reason=reason, now_utc=now_utc)

    def start_execution(self, pkt: DecisionPacket, *, actor: str, reason: str, now_utc: Optional[_dt.datetime] = None) -> DecisionPacket:
        with _LOCK:
            pkt = self._touch(pkt, now_utc)
            self._require_state(pkt, {PacketState.APPROVED}, PacketEventType.START_EXECUTION)
            now = now_utc or _dt.datetime.now(tz=_dt.timezone.utc)
            # Last gate before execution: invariants must pass (fail-closed).
            enforce_invariants(pkt.context, policy=self.policy, now_utc=now)
            return self._append_event(
                dataclasses.replace(pkt, state=PacketState.EXECUTING),
                self._mk_event(
                    packet_id=pkt.packet_id,
                    etype=PacketEventType.START_EXECUTION,
                    from_state=PacketState.APPROVED,
                    to_state=PacketState.EXECUTING,
                    actor=actor,
                    reason=reason,
                    data={"context_fp": pkt.context.fingerprint()},
                    now_utc=now,
                ),
            )

    def finish_execution(self, pkt: DecisionPacket, *, actor: str, reason: str, result: Mapping[str, Any], now_utc: Optional[_dt.datetime] = None) -> DecisionPacket:
        with _LOCK:
            pkt = self._touch(pkt, now_utc)
            self._require_state(pkt, {PacketState.EXECUTING}, PacketEventType.FINISH_EXECUTION)
            now = now_utc or _dt.datetime.now(tz=_dt.timezone.utc)
            return self._append_event(
                dataclasses.replace(pkt, state=PacketState.EXECUTED),
                self._mk_event(
                    packet_id=pkt.packet_id,
                    etype=PacketEventType.FINISH_EXECUTION,
                    from_state=PacketState.EXECUTING,
                    to_state=PacketState.EXECUTED,
                    actor=actor,
                    reason=reason,
                    data={"result": _canonicalize(result)},
                    now_utc=now,
                ),
            )

    def fail(self, pkt: DecisionPacket, *, actor: str, reason: str, error: str, now_utc: Optional[_dt.datetime] = None) -> DecisionPacket:
        with _LOCK:
            pkt = self._touch(pkt, now_utc)
            self._require_state(pkt, {PacketState.EXECUTING, PacketState.SUBMITTED, PacketState.VALIDATED, PacketState.AWAITING_HUMAN_APPROVAL, PacketState.APPROVED}, PacketEventType.FAIL)
            now = now_utc or _dt.datetime.now(tz=_dt.timezone.utc)
            return self._append_event(
                dataclasses.replace(pkt, state=PacketState.FAILED),
                self._mk_event(
                    packet_id=pkt.packet_id,
                    etype=PacketEventType.FAIL,
                    from_state=pkt.state,
                    to_state=PacketState.FAILED,
                    actor=actor,
                    reason=reason,
                    data={"error": str(error)[:8192]},
                    now_utc=now,
                ),
            )

    def cancel(self, pkt: DecisionPacket, *, actor: str, reason: str, now_utc: Optional[_dt.datetime] = None) -> DecisionPacket:
        with _LOCK:
            pkt = self._touch(pkt, now_utc)
            if pkt.state in {PacketState.EXECUTED, PacketState.ARCHIVED, PacketState.EXPIRED}:
                raise TransitionDenied("cannot cancel terminal state")
            now = now_utc or _dt.datetime.now(tz=_dt.timezone.utc)
            return self._append_event(
                dataclasses.replace(pkt, state=PacketState.CANCELLED),
                self._mk_event(
                    packet_id=pkt.packet_id,
                    etype=PacketEventType.CANCEL,
                    from_state=pkt.state,
                    to_state=PacketState.CANCELLED,
                    actor=actor,
                    reason=reason,
                    data={},
                    now_utc=now,
                ),
            )

    def archive(self, pkt: DecisionPacket, *, actor: str, reason: str, now_utc: Optional[_dt.datetime] = None) -> DecisionPacket:
        with _LOCK:
            pkt = self._touch(pkt, now_utc)
            if pkt.state not in {PacketState.EXECUTED, PacketState.REJECTED, PacketState.FAILED, PacketState.CANCELLED, PacketState.EXPIRED}:
                raise TransitionDenied("archive allowed only for terminal states")
            now = now_utc or _dt.datetime.now(tz=_dt.timezone.utc)
            return self._append_event(
                dataclasses.replace(pkt, state=PacketState.ARCHIVED),
                self._mk_event(
                    packet_id=pkt.packet_id,
                    etype=PacketEventType.ARCHIVE,
                    from_state=pkt.state,
                    to_state=PacketState.ARCHIVED,
                    actor=actor,
                    reason=reason,
                    data={"final_fp": pkt.fingerprint()},
                    now_utc=now,
                ),
            )

    def _transition(
        self,
        pkt: DecisionPacket,
        etype: PacketEventType,
        to_state: PacketState,
        *,
        actor: str,
        reason: str,
        now_utc: Optional[_dt.datetime],
    ) -> DecisionPacket:
        with _LOCK:
            pkt = self._touch(pkt, now_utc)
            now = now_utc or _dt.datetime.now(tz=_dt.timezone.utc)
            self._require_reason(reason)
            allowed = _ALLOWED_TRANSITIONS.get((pkt.state, etype))
            if allowed != to_state:
                raise TransitionDenied(f"transition denied: {pkt.state.value} --{etype.value}--> {to_state.value}")
            return self._append_event(
                dataclasses.replace(pkt, state=to_state),
                self._mk_event(
                    packet_id=pkt.packet_id,
                    etype=etype,
                    from_state=pkt.state,
                    to_state=to_state,
                    actor=actor,
                    reason=reason,
                    data={},
                    now_utc=now,
                ),
            )

    def _touch(self, pkt: DecisionPacket, now_utc: Optional[_dt.datetime]) -> DecisionPacket:
        if not self.config.auto_expire_on_touch:
            return pkt
        now = now_utc or _dt.datetime.now(tz=_dt.timezone.utc)
        if pkt.state in {PacketState.EXECUTED, PacketState.REJECTED, PacketState.FAILED, PacketState.CANCELLED, PacketState.ARCHIVED, PacketState.EXPIRED}:
            return pkt
        if pkt.is_expired(now):
            return self._expire(pkt, actor="system", reason="ttl_elapsed", now_utc=now)
        return pkt

    def _expire(self, pkt: DecisionPacket, *, actor: str, reason: str, now_utc: _dt.datetime) -> DecisionPacket:
        ev = self._mk_event(
            packet_id=pkt.packet_id,
            etype=PacketEventType.EXPIRE,
            from_state=pkt.state,
            to_state=PacketState.EXPIRED,
            actor=actor,
            reason=reason,
            data={"expires_at_utc": _iso_utc(pkt.expires_at_utc())},
            now_utc=now_utc,
        )
        return self._append_event(dataclasses.replace(pkt, state=PacketState.EXPIRED), ev)

    def _append_event(self, pkt: DecisionPacket, ev: PacketEvent) -> DecisionPacket:
        ev_fp = ev.with_fingerprint()
        events = pkt.events + (ev_fp,)
        if len(events) > self.config.max_events:
            raise PacketError("max_events exceeded")
        new_pkt = dataclasses.replace(pkt, events=events)
        if self.on_event:
            self.on_event(new_pkt, ev_fp)
        return new_pkt

    def _mk_event(
        self,
        *,
        packet_id: str,
        etype: PacketEventType,
        from_state: PacketState,
        to_st_
