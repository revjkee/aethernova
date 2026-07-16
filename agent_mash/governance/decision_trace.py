# agent_mash/governance/decision_trace.py
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


class DecisionTraceError(RuntimeError):
    pass


class DecisionTraceValidationError(DecisionTraceError):
    pass


class DecisionTraceIntegrityError(DecisionTraceError):
    pass


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_str(v: Any, field: str, max_len: int = 4096) -> str:
    if not isinstance(v, str):
        raise DecisionTraceValidationError(f"{field} must be str")
    s = v.strip()
    if not s:
        raise DecisionTraceValidationError(f"{field} must be non-empty")
    if len(s) > max_len:
        raise DecisionTraceValidationError(f"{field} too long")
    return s


def _ensure_optional_str(v: Any, field: str, max_len: int = 4096) -> Optional[str]:
    if v is None:
        return None
    if not isinstance(v, str):
        raise DecisionTraceValidationError(f"{field} must be str or None")
    s = v.strip()
    if not s:
        return None
    if len(s) > max_len:
        raise DecisionTraceValidationError(f"{field} too long")
    return s


def _ensure_int(v: Any, field: str, min_value: Optional[int] = None, max_value: Optional[int] = None) -> int:
    if not isinstance(v, int):
        raise DecisionTraceValidationError(f"{field} must be int")
    if min_value is not None and v < min_value:
        raise DecisionTraceValidationError(f"{field} must be >= {min_value}")
    if max_value is not None and v > max_value:
        raise DecisionTraceValidationError(f"{field} must be <= {max_value}")
    return v


def _ensure_dict(v: Any, field: str, max_keys: int = 2048) -> Dict[str, Any]:
    if v is None:
        return {}
    if not isinstance(v, dict):
        raise DecisionTraceValidationError(f"{field} must be dict")
    if len(v) > max_keys:
        raise DecisionTraceValidationError(f"{field} too many keys")
    for k in v.keys():
        if not isinstance(k, str):
            raise DecisionTraceValidationError(f"{field} keys must be str")
        if len(k) > 256:
            raise DecisionTraceValidationError(f"{field} key too long")
    return v


def _canonicalize(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, list):
        return [_canonicalize(x) for x in value]
    if isinstance(value, tuple):
        return [_canonicalize(x) for x in value]
    if isinstance(value, dict):
        items: List[Tuple[str, Any]] = []
        for k, v in value.items():
            if not isinstance(k, str):
                raise DecisionTraceValidationError("payload contains non-string key")
            items.append((k, _canonicalize(v)))
        items.sort(key=lambda kv: kv[0])
        return {k: v for k, v in items}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    return str(value)


def canonical_json_dumps(value: Any) -> str:
    normalized = _canonicalize(value)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def blake2b_hex(data: Union[str, bytes], digest_size: int = 32) -> str:
    if isinstance(data, str):
        b = data.encode("utf-8")
    else:
        b = data
    h = hashlib.blake2b(b, digest_size=digest_size)
    return h.hexdigest()


_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")


def _ensure_hash(v: Any, field: str) -> str:
    s = _ensure_str(v, field, max_len=128).lower()
    if not _HEX_64_RE.fullmatch(s):
        raise DecisionTraceValidationError(f"{field} must be 64 hex chars")
    return s


def _redact_dict(d: Mapping[str, Any], redact_keys: Sequence[str]) -> Dict[str, Any]:
    if not redact_keys:
        return dict(d)
    lowered = {k.lower() for k in redact_keys}
    out: Dict[str, Any] = {}
    for k, v in d.items():
        if k.lower() in lowered:
            out[k] = "***REDACTED***"
        else:
            out[k] = v
    return out


@dataclass(frozen=True)
class DecisionTraceEvent:
    version: int
    event_id: str
    chain_id: str
    index: int
    ts_utc: str
    actor: str
    subject: str
    action: str
    outcome: str
    reason: Optional[str]
    payload: Dict[str, Any]
    prev_hash: Optional[str]
    event_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "event_id": self.event_id,
            "chain_id": self.chain_id,
            "index": self.index,
            "ts_utc": self.ts_utc,
            "actor": self.actor,
            "subject": self.subject,
            "action": self.action,
            "outcome": self.outcome,
            "reason": self.reason,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "event_hash": self.event_hash,
        }

    def to_canonical_json(self) -> str:
        return canonical_json_dumps(self.to_dict())

    def redacted(self, redact_payload_keys: Sequence[str]) -> "DecisionTraceEvent":
        return dataclasses.replace(self, payload=_redact_dict(self.payload, redact_payload_keys))

    def verify_hash(self) -> None:
        expected = compute_event_hash(
            version=self.version,
            event_id=self.event_id,
            chain_id=self.chain_id,
            index=self.index,
            ts_utc=self.ts_utc,
            actor=self.actor,
            subject=self.subject,
            action=self.action,
            outcome=self.outcome,
            reason=self.reason,
            payload=self.payload,
            prev_hash=self.prev_hash,
        )
        if expected != self.event_hash:
            raise DecisionTraceIntegrityError("event hash mismatch")


def compute_event_hash(
    version: int,
    event_id: str,
    chain_id: str,
    index: int,
    ts_utc: str,
    actor: str,
    subject: str,
    action: str,
    outcome: str,
    reason: Optional[str],
    payload: Mapping[str, Any],
    prev_hash: Optional[str],
) -> str:
    base = {
        "version": version,
        "event_id": event_id,
        "chain_id": chain_id,
        "index": index,
        "ts_utc": ts_utc,
        "actor": actor,
        "subject": subject,
        "action": action,
        "outcome": outcome,
        "reason": reason,
        "payload": dict(payload),
        "prev_hash": prev_hash,
    }
    return blake2b_hex(canonical_json_dumps(base), digest_size=32)


def new_event_id(prefix: str = "evt") -> str:
    t = int(time.time() * 1000)
    r = os.urandom(16).hex()
    return f"{prefix}_{t}_{r}"


def new_chain_id(prefix: str = "chain") -> str:
    t = int(time.time() * 1000)
    r = os.urandom(16).hex()
    return f"{prefix}_{t}_{r}"


@dataclass
class DecisionTraceChain:
    chain_id: str
    version: int = 1
    _events: List[DecisionTraceEvent] = dataclasses.field(default_factory=list)

    @property
    def events(self) -> Tuple[DecisionTraceEvent, ...]:
        return tuple(self._events)

    @property
    def last_hash(self) -> Optional[str]:
        if not self._events:
            return None
        return self._events[-1].event_hash

    @property
    def next_index(self) -> int:
        return len(self._events)

    def append(
        self,
        actor: str,
        subject: str,
        action: str,
        outcome: str,
        reason: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        ts_utc: Optional[str] = None,
        event_id: Optional[str] = None,
    ) -> DecisionTraceEvent:
        actor_s = _ensure_str(actor, "actor")
        subject_s = _ensure_str(subject, "subject")
        action_s = _ensure_str(action, "action")
        outcome_s = _ensure_str(outcome, "outcome")
        reason_s = _ensure_optional_str(reason, "reason")
        payload_d = _ensure_dict(payload, "payload")
        ts = _ensure_str(ts_utc, "ts_utc") if ts_utc is not None else _utc_now_iso()
        eid = _ensure_str(event_id, "event_id") if event_id is not None else new_event_id()

        idx = self.next_index
        prev = self.last_hash

        ev_hash = compute_event_hash(
            version=self.version,
            event_id=eid,
            chain_id=self.chain_id,
            index=idx,
            ts_utc=ts,
            actor=actor_s,
            subject=subject_s,
            action=action_s,
            outcome=outcome_s,
            reason=reason_s,
            payload=payload_d,
            prev_hash=prev,
        )

        ev = DecisionTraceEvent(
            version=self.version,
            event_id=eid,
            chain_id=self.chain_id,
            index=idx,
            ts_utc=ts,
            actor=actor_s,
            subject=subject_s,
            action=action_s,
            outcome=outcome_s,
            reason=reason_s,
            payload=_canonicalize(payload_d),
            prev_hash=prev,
            event_hash=ev_hash,
        )

        self._events.append(ev)
        return ev

    def verify_integrity(self) -> None:
        if not self.chain_id or not isinstance(self.chain_id, str):
            raise DecisionTraceValidationError("chain_id invalid")
        if not isinstance(self.version, int) or self.version < 1:
            raise DecisionTraceValidationError("version invalid")

        prev: Optional[str] = None
        for i, ev in enumerate(self._events):
            if ev.chain_id != self.chain_id:
                raise DecisionTraceIntegrityError("chain_id mismatch inside chain")
            if ev.index != i:
                raise DecisionTraceIntegrityError("index sequence broken")
            if ev.prev_hash != prev:
                raise DecisionTraceIntegrityError("prev_hash linkage broken")
            ev.verify_hash()
            prev = ev.event_hash

    def to_jsonl(self) -> str:
        lines = []
        for ev in self._events:
            lines.append(canonical_json_dumps(ev.to_dict()))
        return "\n".join(lines) + ("\n" if lines else "")

    def write_jsonl(self, path: Union[str, Path]) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        data = self.to_jsonl().encode("utf-8")
        p.write_bytes(data)

    @staticmethod
    def from_jsonl(chain_id: str, jsonl: str) -> "DecisionTraceChain":
        cid = _ensure_str(chain_id, "chain_id")
        chain = DecisionTraceChain(chain_id=cid, version=1)
        if not jsonl.strip():
            return chain

        lines = [ln for ln in jsonl.splitlines() if ln.strip()]
        for ln in lines:
            obj = json.loads(ln)
            ev = parse_event(obj)
            if ev.chain_id != cid:
                raise DecisionTraceIntegrityError("chain_id mismatch in imported event")
            chain._events.append(ev)

        chain.verify_integrity()
        return chain

    @staticmethod
    def read_jsonl(path: Union[str, Path], chain_id: str) -> "DecisionTraceChain":
        p = Path(path)
        data = p.read_text(encoding="utf-8")
        return DecisionTraceChain.from_jsonl(chain_id=chain_id, jsonl=data)


def parse_event(obj: Mapping[str, Any]) -> DecisionTraceEvent:
    if not isinstance(obj, dict):
        raise DecisionTraceValidationError("event must be dict")

    version = _ensure_int(obj.get("version"), "version", min_value=1, max_value=16)
    event_id = _ensure_str(obj.get("event_id"), "event_id")
    chain_id = _ensure_str(obj.get("chain_id"), "chain_id")
    index = _ensure_int(obj.get("index"), "index", min_value=0, max_value=10**9)
    ts_utc = _ensure_str(obj.get("ts_utc"), "ts_utc")
    actor = _ensure_str(obj.get("actor"), "actor")
    subject = _ensure_str(obj.get("subject"), "subject")
    action = _ensure_str(obj.get("action"), "action")
    outcome = _ensure_str(obj.get("outcome"), "outcome")
    reason = _ensure_optional_str(obj.get("reason"), "reason")
    payload = _ensure_dict(obj.get("payload"), "payload")
    prev_hash = obj.get("prev_hash")
    if prev_hash is not None:
        prev_hash = _ensure_hash(prev_hash, "prev_hash")
    event_hash = _ensure_hash(obj.get("event_hash"), "event_hash")

    ev = DecisionTraceEvent(
        version=version,
        event_id=event_id,
        chain_id=chain_id,
        index=index,
        ts_utc=ts_utc,
        actor=actor,
        subject=subject,
        action=action,
        outcome=outcome,
        reason=reason,
        payload=_canonicalize(payload),
        prev_hash=prev_hash,
        event_hash=event_hash,
    )

    ev.verify_hash()
    return ev


def build_decision_trace_for_decision_packet(
    chain: DecisionTraceChain,
    actor: str,
    packet_id: str,
    decision_name: str,
    outcome: str,
    reason: Optional[str],
    payload: Optional[Dict[str, Any]] = None,
) -> DecisionTraceEvent:
    subject = _ensure_str(packet_id, "packet_id")
    action = _ensure_str(decision_name, "decision_name")
    return chain.append(
        actor=actor,
        subject=subject,
        action=action,
        outcome=outcome,
        reason=reason,
        payload=payload or {},
    )
