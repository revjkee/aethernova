# human-sovereignty-core/approval/channels/messenger_channel.py

from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import hmac
import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Protocol, Tuple


class MessengerChannelError(Exception):
    """Base error for messenger channel operations."""


class MessengerChannelRateLimitError(MessengerChannelError):
    """Raised when rate limit is exceeded."""


class MessengerChannelDeliveryError(MessengerChannelError):
    """Raised when transport fails to deliver a message."""


def _utc_now() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


def _iso(dt: _dt.datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _consteq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _safe_str(x: Any, limit: int) -> str:
    s = str(x) if x is not None else ""
    if len(s) > limit:
        return s[:limit] + "..."
    return s


@dataclass(frozen=True)
class ChannelPolicy:
    """
    Industrial channel policy.

    Critical invariant:
    - This channel NEVER approves anything. It only sends notifications/requests.
    """

    channel_id: str = "messenger"
    enabled: bool = True

    max_payload_bytes: int = 96_000
    max_text_len: int = 8_192

    # Deduplication window
    dedupe_ttl_seconds: int = 3600

    # Rate limiting (token bucket)
    rate_limit_per_minute: int = 60
    burst: int = 20

    # Delivery behavior
    delivery_timeout_seconds: int = 10
    max_retries: int = 2
    retry_backoff_seconds: float = 0.8

    # Redaction
    redact_enabled: bool = True
    redact_fields: Tuple[str, ...] = (
        "password",
        "pass",
        "secret",
        "token",
        "authorization",
        "private_key",
        "seed",
        "mnemonic",
        "api_key",
        "cookie",
    )

    # Formatting
    include_trace: bool = True
    include_links: bool = True


@dataclass(frozen=True)
class MessageContext:
    """
    Optional context fields, intended to map to your decision packet context.
    """

    trace_id: Optional[str] = None
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    tenant_id: Optional[str] = None
    environment: Optional[str] = None


@dataclass(frozen=True)
class Notification:
    """
    Structured notification/request payload for messenger transports.

    approval_required indicates UI should show a "human approval required" state,
    but this module never creates or validates approval itself.
    """

    event_id: str
    created_at_utc: str
    severity: str  # info | warning | critical
    title: str
    message: str
    approval_required: bool = False

    policy_id: Optional[str] = None
    action_id: Optional[str] = None
    decision_packet_hash: Optional[str] = None
    matched_rule_ids: Tuple[str, ...] = ()

    context: MessageContext = field(default_factory=MessageContext)

    # Optional enrichments
    links: Dict[str, str] = field(default_factory=dict)
    tags: Tuple[str, ...] = ()
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "event_id": self.event_id,
            "created_at_utc": self.created_at_utc,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "approval_required": bool(self.approval_required),
            "policy_id": self.policy_id,
            "action_id": self.action_id,
            "decision_packet_hash": self.decision_packet_hash,
            "matched_rule_ids": list(self.matched_rule_ids),
            "context": dataclasses.asdict(self.context),
            "links": dict(self.links),
            "tags": list(self.tags),
            "extra": dict(self.extra),
        }
        # Remove None fields for cleanliness
        return {k: v for k, v in d.items() if v is not None}


class MessengerTransport(Protocol):
    """
    Transport contract: send a dict payload to a destination.

    IMPORTANT: transport must not implement any approval side effects.
    """

    def send(self, *, destination: str, payload: Mapping[str, Any], timeout_seconds: int) -> str:
        """
        Returns transport message id on success, raises on failure.
        """
        raise NotImplementedError


@dataclass
class DeliveryReceipt:
    destination: str
    message_id: str
    delivered_at_utc: str
    attempts: int
    dedupe_key: str


class InMemoryDedupeStore:
    """
    Simple in-memory dedupe store for single-process runtime.
    Replace with Redis for distributed deployments.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: Dict[str, float] = {}

    def seen_recently(self, key: str, *, ttl_seconds: int) -> bool:
        now = time.time()
        with self._lock:
            self._gc_locked(now, ttl_seconds)
            ts = self._items.get(key)
            if ts is None:
                self._items[key] = now
                return False
            return True

    def _gc_locked(self, now: float, ttl_seconds: int) -> None:
        expired = [k for k, ts in self._items.items() if (now - ts) > ttl_seconds]
        for k in expired:
            self._items.pop(k, None)


class TokenBucket:
    def __init__(self, *, rate_per_minute: int, burst: int) -> None:
        self._lock = threading.Lock()
        self._capacity = max(1, int(burst))
        self._tokens = float(self._capacity)
        self._rate_per_sec = max(0.1, float(rate_per_minute) / 60.0)
        self._last = time.time()

    def consume(self, tokens: float = 1.0) -> bool:
        with self._lock:
            now = time.time()
            elapsed = max(0.0, now - self._last)
            self._last = now
            self._tokens = min(self._capacity, self._tokens + elapsed * self._rate_per_sec)
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False


def _redact(obj: Any, *, policy: ChannelPolicy) -> Any:
    if not policy.redact_enabled:
        return obj

    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            lk = str(k).lower()
            if any(s in lk for s in policy.redact_fields):
                out[k] = "[REDACTED]"
            else:
                out[k] = _redact(v, policy=policy)
        return out

    if isinstance(obj, list):
        return [_redact(x, policy=policy) for x in obj]

    if isinstance(obj, str):
        return _safe_str(obj, policy.max_text_len)

    return obj


def _compute_dedupe_key(destination: str, payload: Mapping[str, Any]) -> str:
    # Stable dedupe key: destination + canonical payload hash
    base = {
        "destination": destination,
        "payload": payload,
    }
    return _sha256_hex(_canonical_json_bytes(base))


class MessengerChannel:
    """
    Production-grade notification channel.

    Hard constraint:
    - Does NOT approve anything (no RED approve).
    - Only sends notifications/requests to human.

    Typical usage:
    - When veto policy requires approval: send approval_required=True event
    - When veto blocks: send severity=warning/critical event
    """

    def __init__(
        self,
        *,
        transport: MessengerTransport,
        destination: str,
        policy: Optional[ChannelPolicy] = None,
        dedupe_store: Optional[InMemoryDedupeStore] = None,
    ) -> None:
        self._policy = policy or ChannelPolicy()
        self._transport = transport
        self._destination = destination
        self._dedupe = dedupe_store or InMemoryDedupeStore()
        self._bucket = TokenBucket(
            rate_per_minute=self._policy.rate_limit_per_minute,
            burst=self._policy.burst,
        )

    @property
    def policy(self) -> ChannelPolicy:
        return self._policy

    @property
    def destination(self) -> str:
        return self._destination

    def notify(self, notification: Notification) -> DeliveryReceipt:
        if not self._policy.enabled:
            raise MessengerChannelError("Channel disabled")

        payload = notification.to_dict()
        payload = _redact(payload, policy=self._policy)

        raw = _canonical_json_bytes(payload)
        if len(raw) > self._policy.max_payload_bytes:
            raise MessengerChannelError("Notification payload too large")

        if not self._bucket.consume(1.0):
            raise MessengerChannelRateLimitError("Rate limit exceeded")

        dedupe_key = _compute_dedupe_key(self._destination, payload)
        if self._dedupe.seen_recently(dedupe_key, ttl_seconds=self._policy.dedupe_ttl_seconds):
            # Idempotent behavior: treat as delivered without sending again.
            return DeliveryReceipt(
                destination=self._destination,
                message_id="deduped",
                delivered_at_utc=_iso(_utc_now()),
                attempts=0,
                dedupe_key=dedupe_key,
            )

        attempts = 0
        last_err: Optional[Exception] = None

        for attempt in range(1, self._policy.max_retries + 2):
            attempts = attempt
            try:
                msg_id = self._transport.send(
                    destination=self._destination,
                    payload=payload,
                    timeout_seconds=self._policy.delivery_timeout_seconds,
                )
                return DeliveryReceipt(
                    destination=self._destination,
                    message_id=str(msg_id),
                    delivered_at_utc=_iso(_utc_now()),
                    attempts=attempts,
                    dedupe_key=dedupe_key,
                )
            except Exception as e:
                last_err = e
                if attempt <= self._policy.max_retries:
                    time.sleep(self._policy.retry_backoff_seconds * attempt)
                    continue
                break

        raise MessengerChannelDeliveryError("Delivery failed") from last_err


class NullTransport:
    """
    Safe default transport used in tests or dry-run.
    Stores last payload in memory, never approves anything.
    """

    def __init__(self) -> None:
        self.last_destination: Optional[str] = None
        self.last_payload: Optional[Dict[str, Any]] = None

    def send(self, *, destination: str, payload: Mapping[str, Any], timeout_seconds: int) -> str:
        self.last_destination = destination
        self.last_payload = dict(payload)
        # Simulate successful delivery id
        return f"null:{uuid.uuid4()}"
