# human-sovereignty-core/audit/decision_trace.py
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
import uuid
from dataclasses import dataclass, field, asdict, is_dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

JsonPrimitive = Union[str, int, float, bool, None]
JsonLike = Union[JsonPrimitive, Mapping[str, Any], Sequence[Any]]


# ============================
# Exceptions
# ============================

class DecisionTraceError(Exception):
    """Base exception for decision trace errors."""


class ValidationError(DecisionTraceError):
    """Raised when validation fails."""


class CanonicalizationError(DecisionTraceError):
    """Raised when canonicalization fails."""


class IntegrityError(DecisionTraceError):
    """Raised when integrity checks fail."""


# ============================
# Constants
# ============================

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}$"
)

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

_DEFAULT_ALLOWED_HASHES = ("sha256", "sha512", "sha3_256", "sha3_512", "blake2b", "blake2s")


# ============================
# Utilities
# ============================

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(dt: datetime) -> str:
    if not isinstance(dt, datetime):
        raise ValidationError("timestamp must be datetime")
    if dt.tzinfo is None:
        raise ValidationError("timestamp must be timezone-aware")
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso_utc(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValidationError("timestamp must be a non-empty ISO-8601 string")
    try:
        if value.endswith("Z"):
            return datetime.fromisoformat(value[:-1]).replace(tzinfo=timezone.utc)
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            raise ValidationError("timestamp must include timezone offset or Z")
        return dt.astimezone(timezone.utc)
    except ValueError as e:
        raise ValidationError(f"invalid ISO-8601 timestamp: {value!r}") from e


def new_uuid() -> str:
    return str(uuid.uuid4())


def ensure_uuid(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not _UUID_RE.match(value):
        raise ValidationError(f"{field_name} must be a UUID string")
    return value.lower()


def ensure_nonempty_str(value: str, field_name: str, max_len: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field_name} must be a non-empty string")
    v = value.strip()
    if len(v) > max_len:
        raise ValidationError(f"{field_name} exceeds max length {max_len}")
    return v


def ensure_optional_str(value: Optional[str], field_name: str, max_len: int = 4096) -> Optional[str]:
    if value is None:
        return None
    return ensure_nonempty_str(value, field_name, max_len=max_len)


def ensure_hex(value: str, field_name: str, min_len: int = 32, max_len: int = 256) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{field_name} must be a non-empty hex string")
    if not _HEX_RE.match(value):
        raise ValidationError(f"{field_name} must be hex-only")
    if len(value) < min_len or len(value) > max_len:
        raise ValidationError(f"{field_name} length must be in [{min_len}, {max_len}]")
    return value.lower()


def ensure_b64url(value: str, field_name: str, max_len: int = 16384) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{field_name} must be a non-empty base64url string")
    if len(value) > max_len:
        raise ValidationError(f"{field_name} exceeds max length {max_len}")
    padded = value + "=" * ((4 - (len(value) % 4)) % 4)
    try:
        base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as e:
        raise ValidationError(f"{field_name} is not valid base64url") from e
    return value


def _json_dumps_canonical(obj: Any) -> str:
    try:
        return json.dumps(
            obj,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as e:
        raise CanonicalizationError(str(e)) from e


def _deep_convert(obj: Any) -> Any:
    # dataclass -> dict, datetime -> iso, bytes -> base64url, tuple -> list
    if is_dataclass(obj):
        return _deep_convert(asdict(obj))
    if isinstance(obj, datetime):
        return iso_utc(obj)
    if isinstance(obj, (bytes, bytearray, memoryview)):
        raw = bytes(obj)
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    if isinstance(obj, Mapping):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            if not isinstance(k, str):
                raise CanonicalizationError("JSON object keys must be strings")
            out[k] = _deep_convert(v)
        return out
    if isinstance(obj, (list, tuple)):
        return [_deep_convert(x) for x in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    raise CanonicalizationError(f"Unsupported type for canonicalization: {type(obj).__name__}")


def _stable_hash_bytes(
    payload: bytes,
    *,
    algorithm: str,
    domain: str,
    hmac_key: Optional[bytes] = None,
) -> bytes:
    algo = (algorithm or "").strip().lower()
    if algo not in _DEFAULT_ALLOWED_HASHES:
        raise ValidationError(f"hash.algorithm not allowed: {algorithm!r}")
    if not isinstance(domain, str) or not domain:
        raise ValidationError("hash.domain must be non-empty string")

    prefix = b"DTR1:" + domain.encode("utf-8") + b"\n"  # Decision Trace v1

    if hmac_key is not None:
        mac = hmac.new(hmac_key, digestmod=algo)
        mac.update(prefix)
        mac.update(payload)
        return mac.digest()

    h = hashlib.new(algo)
    h.update(prefix)
    h.update(payload)
    return h.digest()


def _encode_digest(raw: bytes, encoding: str) -> str:
    enc = (encoding or "").strip().lower()
    if enc == "hex":
        return raw.hex()
    if enc == "base64":
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    raise ValidationError("hash.encoding must be 'hex' or 'base64'")


# ============================
# Redaction policy
# ============================

@dataclass(frozen=True, slots=True)
class RedactionPolicy:
    """
    Deterministic redaction rules for trace attributes.

    - deny_keys: exact keys that must be removed
    - deny_key_patterns: regex patterns matching keys to remove
    - max_value_bytes: if string/bytes exceed, truncate deterministically
    - replacement: replacement marker for removed values
    """
    deny_keys: Tuple[str, ...] = (
        "password",
        "pass",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "cookie",
        "set-cookie",
        "api_key",
        "private_key",
        "session",
        "session_id",
        "credit_card",
        "card_number",
        "ssn",
        "otp",
        "mfa",
    )
    deny_key_patterns: Tuple[str, ...] = (
        r"^x-.*-token$",
        r"^.*_secret$",
        r"^.*_token$",
        r"^authorization$",
        r"^cookie$",
        r"^set-cookie$",
    )
    max_value_bytes: int = 8192
    replacement: str = "[REDACTED]"

    def _compiled_patterns(self) -> Tuple[re.Pattern[str], ...]:
        compiled: List[re.Pattern[str]] = []
        for p in self.deny_key_patterns:
            compiled.append(re.compile(p, flags=re.IGNORECASE))
        return tuple(compiled)

    def should_redact_key(self, key: str) -> bool:
        k = (key or "").strip()
        if not k:
            return True
        if k.lower() in {x.lower() for x in self.deny_keys}:
            return True
        for pat in self._compiled_patterns():
            if pat.match(k):
                return True
        return False

    def sanitize_value(self, value: Any) -> Any:
        # Truncate huge strings deterministically; bytes become base64url via _deep_convert anyway.
        if isinstance(value, str):
            b = value.encode("utf-8", errors="replace")
            if len(b) <= self.max_value_bytes:
                return value
            truncated = b[: self.max_value_bytes]
            return truncated.decode("utf-8", errors="replace") + "...[TRUNCATED]"
        if isinstance(value, (bytes, bytearray, memoryview)):
            raw = bytes(value)
            if len(raw) <= self.max_value_bytes:
                return value
            return raw[: self.max_value_bytes]
        return value

    def redact_mapping(self, data: Mapping[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for k, v in data.items():
            if not isinstance(k, str):
                continue
            if self.should_redact_key(k):
                out[k] = self.replacement
                continue
            out[k] = self.sanitize_value(v)
        return out


# ============================
# Hash chain policy
# ============================

@dataclass(frozen=True, slots=True)
class TraceHashPolicy:
    """
    Integrity policy for trace append-only behavior.

    - enabled: if False, no hash chain is produced
    - algorithm: allowed digest algorithm name
    - encoding: 'hex' or 'base64'
    - domain: domain separation label
    - hmac_key: optional key for authenticated integrity
    """
    enabled: bool = True
    algorithm: str = "sha256"
    encoding: str = "hex"
    domain: str = "aethernova.decision_trace"
    hmac_key: Optional[bytes] = None

    def validate(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValidationError("hash.enabled must be bool")
        if not isinstance(self.domain, str) or not self.domain:
            raise ValidationError("hash.domain must be non-empty string")
        algo = (self.algorithm or "").strip().lower()
        if algo not in _DEFAULT_ALLOWED_HASHES:
            raise ValidationError("hash.algorithm is not allowed")
        enc = (self.encoding or "").strip().lower()
        if enc not in ("hex", "base64"):
            raise ValidationError("hash.encoding must be 'hex' or 'base64'")
        if self.hmac_key is not None and not isinstance(self.hmac_key, (bytes, bytearray, memoryview)):
            raise ValidationError("hash.hmac_key must be bytes-like or None")


# ============================
# Trace events and spans
# ============================

@dataclass(frozen=True, slots=True)
class TraceEvent:
    """
    One immutable fact in the decision trace.

    - event_id: UUID
    - at: ISO-8601 UTC
    - name: stable event name
    - level: debug|info|warn|error
    - attrs: structured metadata (redacted)
    - prev_event_hash: previous event hash in chain (optional)
    - event_hash: hash of this event canonical form (optional)
    """
    event_id: str
    at: str
    name: str
    level: str = "info"
    attrs: Mapping[str, Any] = field(default_factory=dict)
    prev_event_hash: Optional[str] = None
    event_hash: Optional[str] = None

    def validate(self) -> None:
        ensure_uuid(self.event_id, "TraceEvent.event_id")
        parse_iso_utc(self.at)
        ensure_nonempty_str(self.name, "TraceEvent.name", max_len=256)

        lvl = ensure_nonempty_str(self.level, "TraceEvent.level", max_len=16).lower()
        if lvl not in {"debug", "info", "warn", "error"}:
            raise ValidationError("TraceEvent.level must be one of: debug, info, warn, error")

        if not isinstance(self.attrs, Mapping):
            raise ValidationError("TraceEvent.attrs must be a mapping")
        if len(self.attrs) > 256:
            raise ValidationError("TraceEvent.attrs exceeds max keys 256")
        _json_dumps_canonical(_deep_convert(self.attrs))

        if self.prev_event_hash is not None:
            ensure_hex(self.prev_event_hash, "TraceEvent.prev_event_hash", min_len=32, max_len=256)
        if self.event_hash is not None:
            ensure_hex(self.event_hash, "TraceEvent.event_hash", min_len=32, max_len=256)

    def to_canonical_dict(self, *, include_hash: bool = False) -> Dict[str, Any]:
        self.validate()
        out: Dict[str, Any] = {
            "event_id": self.event_id,
            "at": self.at,
            "name": self.name,
            "level": self.level.lower(),
            "attrs": _deep_convert(self.attrs) if self.attrs else {},
            "prev_event_hash": self.prev_event_hash.lower() if self.prev_event_hash else None,
        }
        out = {k: v for k, v in out.items() if v is not None}
        if include_hash and self.event_hash is not None:
            out["event_hash"] = self.event_hash.lower()
        _json_dumps_canonical(out)
        return out

    def canonical_bytes(self, *, include_hash: bool = False) -> bytes:
        return _json_dumps_canonical(self.to_canonical_dict(include_hash=include_hash)).encode("utf-8")


@dataclass(frozen=True, slots=True)
class TraceSpan:
    """
    A span groups related events and provides duration measurement.

    - span_id: UUID
    - name: stable name (e.g., "policy_evaluation", "execution")
    - start_at, end_at: ISO UTC (end_at optional while open)
    - status: ok|rejected|failed|running
    - attrs: span-level metadata (redacted)
    - events: ordered events
    """
    span_id: str
    name: str
    start_at: str
    end_at: Optional[str] = None
    status: str = "running"
    attrs: Mapping[str, Any] = field(default_factory=dict)
    events: Tuple[TraceEvent, ...] = field(default_factory=tuple)

    def validate(self) -> None:
        ensure_uuid(self.span_id, "TraceSpan.span_id")
        ensure_nonempty_str(self.name, "TraceSpan.name", max_len=256)
        parse_iso_utc(self.start_at)
        if self.end_at is not None:
            end_dt = parse_iso_utc(self.end_at)
            start_dt = parse_iso_utc(self.start_at)
            if end_dt < start_dt:
                raise ValidationError("TraceSpan.end_at must be >= start_at")

        st = ensure_nonempty_str(self.status, "TraceSpan.status", max_len=16).lower()
        if st not in {"ok", "rejected", "failed", "running"}:
            raise ValidationError("TraceSpan.status must be one of: ok, rejected, failed, running")

        if not isinstance(self.attrs, Mapping):
            raise ValidationError("TraceSpan.attrs must be a mapping")
        if len(self.attrs) > 256:
            raise ValidationError("TraceSpan.attrs exceeds max keys 256")
        _json_dumps_canonical(_deep_convert(self.attrs))

        if len(self.events) > 10000:
            raise ValidationError("TraceSpan.events exceeds maximum 10000")
        for ev in self.events:
            ev.validate()

    def to_canonical_dict(self) -> Dict[str, Any]:
        self.validate()
        out: Dict[str, Any] = {
            "span_id": self.span_id,
            "name": self.name,
            "start_at": self.start_at,
            "end_at": self.end_at,
            "status": self.status.lower(),
            "attrs": _deep_convert(self.attrs) if self.attrs else {},
            "events": [e.to_canonical_dict(include_hash=True) for e in self.events],
        }
        out = {k: v for k, v in out.items() if v is not None}
        _json_dumps_canonical(out)
        return out


# ============================
# Decision Trace root
# ============================

@dataclass(frozen=True, slots=True)
class DecisionTrace:
    """
    Root trace object for one decision lifecycle.

    - trace_id: UUID
    - created_at: ISO UTC
    - decision_packet_id/hash: optional linkage
    - correlation_id: stable cross-service correlation id
    - spans: ordered spans
    - hash_policy: integrity policy (optional)
    - redaction: deterministic redaction policy
    - meta: additional trace metadata (redacted)
    """
    trace_id: str
    created_at: str
    correlation_id: str

    decision_packet_id: Optional[str] = None
    decision_packet_hash: Optional[str] = None

    spans: Tuple[TraceSpan, ...] = field(default_factory=tuple)

    hash_policy: TraceHashPolicy = field(default_factory=TraceHashPolicy)
    redaction: RedactionPolicy = field(default_factory=RedactionPolicy)

    meta: Mapping[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        ensure_uuid(self.trace_id, "DecisionTrace.trace_id")
        parse_iso_utc(self.created_at)
        ensure_nonempty_str(self.correlation_id, "DecisionTrace.correlation_id", max_len=256)

        if self.decision_packet_id is not None:
            ensure_uuid(self.decision_packet_id, "DecisionTrace.decision_packet_id")
        if self.decision_packet_hash is not None:
            ensure_hex(self.decision_packet_hash, "DecisionTrace.decision_packet_hash", min_len=32, max_len=256)

        if len(self.spans) > 256:
            raise ValidationError("DecisionTrace.spans exceeds max spans 256")
        for sp in self.spans:
            sp.validate()

        self.hash_policy.validate()

        if not isinstance(self.meta, Mapping):
            raise ValidationError("DecisionTrace.meta must be a mapping")
        if len(self.meta) > 256:
            raise ValidationError("DecisionTrace.meta exceeds max keys 256")
        _json_dumps_canonical(_deep_convert(self.meta))

    def to_canonical_dict(self) -> Dict[str, Any]:
        self.validate()
        out: Dict[str, Any] = {
            "trace_id": self.trace_id,
            "created_at": self.created_at,
            "correlation_id": self.correlation_id,
            "decision_packet_id": self.decision_packet_id,
            "decision_packet_hash": self.decision_packet_hash.lower() if self.decision_packet_hash else None,
            "hash_policy": {
                "enabled": self.hash_policy.enabled,
                "algorithm": self.hash_policy.algorithm.lower(),
                "encoding": self.hash_policy.encoding.lower(),
                "domain": self.hash_policy.domain,
                "hmac": self.hash_policy.hmac_key is not None,
            },
            "meta": _deep_convert(self.meta) if self.meta else {},
            "spans": [s.to_canonical_dict() for s in self.spans],
        }
        out = {k: v for k, v in out.items() if v is not None}
        _json_dumps_canonical(out)
        return out

    def to_json(self) -> str:
        return _json_dumps_canonical(self.to_canonical_dict())

    def to_bytes(self) -> bytes:
        return self.to_json().encode("utf-8")

    def to_json_lines(self) -> str:
        """
        Deterministic JSON Lines export:
        - First line: trace header
        - Then each span header line
        - Then each event line in order
        """
        self.validate()

        lines: List[str] = []
        header = {
            "type": "trace",
            "trace_id": self.trace_id,
            "created_at": self.created_at,
            "correlation_id": self.correlation_id,
            "decision_packet_id": self.decision_packet_id,
            "decision_packet_hash": self.decision_packet_hash.lower() if self.decision_packet_hash else None,
            "hash_policy": {
                "enabled": self.hash_policy.enabled,
                "algorithm": self.hash_policy.algorithm.lower(),
                "encoding": self.hash_policy.encoding.lower(),
                "domain": self.hash_policy.domain,
                "hmac": self.hash_policy.hmac_key is not None,
            },
            "meta": _deep_convert(self.meta) if self.meta else {},
        }
        header = {k: v for k, v in header.items() if v is not None}
        lines.append(_json_dumps_canonical(header))

        for sp in self.spans:
            sp_line = {
                "type": "span",
                "trace_id": self.trace_id,
                "span_id": sp.span_id,
                "name": sp.name,
                "start_at": sp.start_at,
                "end_at": sp.end_at,
                "status": sp.status.lower(),
                "attrs": _deep_convert(sp.attrs) if sp.attrs else {},
            }
            sp_line = {k: v for k, v in sp_line.items() if v is not None}
            lines.append(_json_dumps_canonical(sp_line))

            for ev in sp.events:
                ev_line = {"type": "event", "trace_id": self.trace_id, "span_id": sp.span_id}
                ev_line.update(ev.to_canonical_dict(include_hash=True))
                lines.append(_json_dumps_canonical(ev_line))

        return "\n".join(lines)


# ============================
# Trace builder (append-only)
# ============================

@dataclass(slots=True)
class DecisionTraceBuilder:
    """
    Mutable builder that produces immutable DecisionTrace.

    Safety goals:
    - Deterministic redaction for attrs/meta before sealing into trace
    - Optional event hash-chain for tamper-evidence
    - Strict bounds to prevent abuse (DoS via logging)
    """
    trace_id: str = field(default_factory=new_uuid)
    correlation_id: str = field(default_factory=lambda: new_uuid())
    created_at: str = field(default_factory=lambda: iso_utc(utc_now()))

    decision_packet_id: Optional[str] = None
    decision_packet_hash: Optional[str] = None

    redaction: RedactionPolicy = field(default_factory=RedactionPolicy)
    hash_policy: TraceHashPolicy = field(default_factory=TraceHashPolicy)

    meta: Dict[str, Any] = field(default_factory=dict)

    _spans: Dict[str, Dict[str, Any]] = field(default_factory=dict, init=False, repr=False)
    _span_order: List[str] = field(default_factory=list, init=False, repr=False)

    _last_event_hash: Optional[str] = field(default=None, init=False, repr=False)

    limits_max_spans: int = 256
    limits_max_events_per_span: int = 10000
    limits_max_total_events: int = 25000
    limits_max_meta_keys: int = 256
    limits_max_attr_keys: int = 256

    def _assert_limits(self) -> None:
        if len(self._spans) > self.limits_max_spans:
            raise ValidationError("trace exceeds max spans")
        if len(self.meta) > self.limits_max_meta_keys:
            raise ValidationError("trace meta exceeds max keys")

        total_events = 0
        for s in self._spans.values():
            total_events += len(s["events"])
        if total_events > self.limits_max_total_events:
            raise ValidationError("trace exceeds max total events")

    def link_decision_packet(self, *, packet_id: Optional[str], packet_hash: Optional[str]) -> None:
        if packet_id is not None:
            self.decision_packet_id = ensure_uuid(packet_id, "decision_packet_id")
        if packet_hash is not None:
            self.decision_packet_hash = ensure_hex(packet_hash, "decision_packet_hash", min_len=32, max_len=256)

    def set_meta(self, meta: Mapping[str, Any]) -> None:
        if not isinstance(meta, Mapping):
            raise ValidationError("meta must be a mapping")
        if len(meta) > self.limits_max_meta_keys:
            raise ValidationError("meta exceeds max keys")
        sanitized = self.redaction.redact_mapping(dict(meta))
        # Ensure canonicalizable
        _json_dumps_canonical(_deep_convert(sanitized))
        self.meta = dict(sanitized)

    def start_span(self, name: str, *, attrs: Optional[Mapping[str, Any]] = None, span_id: Optional[str] = None) -> str:
        self._assert_limits()

        sid = ensure_uuid(span_id, "span_id") if span_id else new_uuid()
        if sid in self._spans:
            raise ValidationError("span_id already exists")

        nm = ensure_nonempty_str(name, "span.name", max_len=256)
        a = dict(attrs) if attrs else {}
        if len(a) > self.limits_max_attr_keys:
            raise ValidationError("span attrs exceeds max keys")
        a = self.redaction.redact_mapping(a)
        _json_dumps_canonical(_deep_convert(a))

        self._spans[sid] = {
            "span_id": sid,
            "name": nm,
            "start_at": iso_utc(utc_now()),
            "end_at": None,
            "status": "running",
            "attrs": a,
            "events": [],
        }
        self._span_order.append(sid)
        return sid

    def end_span(self, span_id: str, *, status: str = "ok", attrs_update: Optional[Mapping[str, Any]] = None) -> None:
        sid = ensure_uuid(span_id, "span_id")
        if sid not in self._spans:
            raise ValidationError("unknown span_id")

        st = ensure_nonempty_str(status, "span.status", max_len=16).lower()
        if st not in {"ok", "rejected", "failed"}:
            raise ValidationError("status must be one of: ok, rejected, failed")

        sp = self._spans[sid]
        if sp["end_at"] is not None:
            raise ValidationError("span already ended")

        if attrs_update:
            upd = dict(attrs_update)
            if len(upd) > self.limits_max_attr_keys:
                raise ValidationError("attrs_update exceeds max keys")
            upd = self.redaction.redact_mapping(upd)
            merged = dict(sp["attrs"])
            merged.update(upd)
            _json_dumps_canonical(_deep_convert(merged))
            sp["attrs"] = merged

        sp["status"] = st
        sp["end_at"] = iso_utc(utc_now())

    def add_event(
        self,
        span_id: str,
        name: str,
        *,
        level: str = "info",
        attrs: Optional[Mapping[str, Any]] = None,
        at: Optional[str] = None,
        event_id: Optional[str] = None,
    ) -> TraceEvent:
        self._assert_limits()

        sid = ensure_uuid(span_id, "span_id")
        if sid not in self._spans:
            raise ValidationError("unknown span_id")

        sp = self._spans[sid]
        if len(sp["events"]) >= self.limits_max_events_per_span:
            raise ValidationError("span exceeds max events")

        nm = ensure_nonempty_str(name, "event.name", max_len=256)
        lvl = ensure_nonempty_str(level, "event.level", max_len=16).lower()
        if lvl not in {"debug", "info", "warn", "error"}:
            raise ValidationError("event.level must be one of: debug, info, warn, error")

        eid = ensure_uuid(event_id, "event_id") if event_id else new_uuid()

        ts = at or iso_utc(utc_now())
        parse_iso_utc(ts)

        a = dict(attrs) if attrs else {}
        if len(a) > self.limits_max_attr_keys:
            raise ValidationError("event attrs exceeds max keys")
        a = self.redaction.redact_mapping(a)
        _json_dumps_canonical(_deep_convert(a))

        prev_hash = self._last_event_hash if self.hash_policy.enabled else None

        ev = TraceEvent(
            event_id=eid,
            at=ts,
            name=nm,
            level=lvl,
            attrs=a,
            prev_event_hash=prev_hash,
            event_hash=None,
        )

        if self.hash_policy.enabled:
            self.hash_policy.validate()
            canonical = ev.canonical_bytes(include_hash=False)
            raw = _stable_hash_bytes(
                canonical,
                algorithm=self.hash_policy.algorithm,
                domain=self.hash_policy.domain,
                hmac_key=bytes(self.hash_policy.hmac_key) if self.hash_policy.hmac_key is not None else None,
            )
            digest = _encode_digest(raw, self.hash_policy.encoding)
            # For storage uniformity, normalize to hex-only when encoding=hex.
            ev = TraceEvent(
                event_id=ev.event_id,
                at=ev.at,
                name=ev.name,
                level=ev.level,
                attrs=ev.attrs,
                prev_event_hash=ev.prev_event_hash,
                event_hash=digest if self.hash_policy.encoding.lower() == "base64" else ensure_hex(digest, "event_hash", 32, 256),
            )
            self._last_event_hash = ev.event_hash

        sp["events"].append(ev)
        return ev

    def build(self) -> DecisionTrace:
        # Build immutable spans with stable order.
        self._assert_limits()

        trace_id = ensure_uuid(self.trace_id, "trace_id")
        created_at = self.created_at
        parse_iso_utc(created_at)

        corr = ensure_nonempty_str(self.correlation_id, "correlation_id", max_len=256)

        meta_sanitized = self.redaction.redact_mapping(dict(self.meta))
        _json_dumps_canonical(_deep_convert(meta_sanitized))

        spans: List[TraceSpan] = []
        for sid in self._span_order:
            sp = self._spans[sid]
            events_tuple = tuple(sp["events"])
            span = TraceSpan(
                span_id=sp["span_id"],
                name=sp["name"],
                start_at=sp["start_at"],
                end_at=sp["end_at"],
                status=sp["status"],
                attrs=sp["attrs"],
                events=events_tuple,
            )
            span.validate()
            spans.append(span)

        dt = DecisionTrace(
            trace_id=trace_id,
            created_at=created_at,
            correlation_id=corr,
            decision_packet_id=self.decision_packet_id,
            decision_packet_hash=self.decision_packet_hash,
            spans=tuple(spans),
            hash_policy=self.hash_policy,
            redaction=self.redaction,
            meta=meta_sanitized,
        )
        dt.validate()
        return dt

    def verify_integrity(self, trace: Optional[DecisionTrace] = None) -> bool:
        """
        Recomputes and checks the hash-chain (if enabled).
        Returns True if valid; otherwise raises IntegrityError.
        """
        tr = trace or self.build()
        tr.validate()

        if not tr.hash_policy.enabled:
            return True

        tr.hash_policy.validate()

        last: Optional[str] = None
        for sp in tr.spans:
            for ev in sp.events:
                # prev must match
                if (ev.prev_event_hash or None) != (last or None):
                    raise IntegrityError("event prev hash mismatch")
                # recompute hash
                canonical = TraceEvent(
                    event_id=ev.event_id,
                    at=ev.at,
                    name=ev.name,
                    level=ev.level,
                    attrs=ev.attrs,
                    prev_event_hash=ev.prev_event_hash,
                    event_hash=None,
                ).canonical_bytes(include_hash=False)

                raw = _stable_hash_bytes(
                    canonical,
                    algorithm=tr.hash_policy.algorithm,
                    domain=tr.hash_policy.domain,
                    hmac_key=bytes(tr.hash_policy.hmac_key) if tr.hash_policy.hmac_key is not None else None,
                )
                digest = _encode_digest(raw, tr.hash_policy.encoding)

                if tr.hash_policy.encoding.lower() == "hex":
                    digest = ensure_hex(digest, "event_hash", 32, 256)

                if ev.event_hash != digest:
                    raise IntegrityError("event hash mismatch")

                last = ev.event_hash

        return True


# ============================
# Convenience factory
# ============================

def new_trace_builder(
    *,
    correlation_id: Optional[str] = None,
    decision_packet_id: Optional[str] = None,
    decision_packet_hash: Optional[str] = None,
    redaction: Optional[RedactionPolicy] = None,
    hash_policy: Optional[TraceHashPolicy] = None,
) -> DecisionTraceBuilder:
    b = DecisionTraceBuilder(
        trace_id=new_uuid(),
        correlation_id=correlation_id or new_uuid(),
        created_at=iso_utc(utc_now()),
        redaction=redaction or RedactionPolicy(),
        hash_policy=hash_policy or TraceHashPolicy(),
    )
    if decision_packet_id is not None or decision_packet_hash is not None:
        b.link_decision_packet(packet_id=decision_packet_id, packet_hash=decision_packet_hash)
    return b
