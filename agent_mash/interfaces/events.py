# agent_mash/interfaces/events.py
from __future__ import annotations

import abc
import dataclasses
import datetime as _dt
import hmac
import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    ClassVar,
    Dict,
    Iterable,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
    runtime_checkable,
)

JsonPrimitive = Union[str, int, float, bool, None]
JsonValue = Union[JsonPrimitive, Sequence["JsonValue"], Mapping[str, "JsonValue"]]
JsonObject = Dict[str, JsonValue]

TEvent = TypeVar("TEvent", bound="Event")


_EVENT_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.:-]{0,127}$")
_EVENT_SOURCE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,255}$")
_TENANT_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$")
_SUBJECT_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:@-]{0,255}$")


class EventError(Exception):
    """Base exception for event modeling and processing errors."""


class EventValidationError(EventError):
    """Raised when an event or its metadata fails validation."""


class EventSerializationError(EventError):
    """Raised when (de)serialization fails."""


class EventSignatureError(EventError):
    """Raised when signature is missing or invalid."""


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


def _isoformat_utc(dt: _dt.datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    dt = dt.astimezone(_dt.timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def _parse_iso8601_utc(value: str) -> _dt.datetime:
    # Accept RFC3339/ISO8601 with Z or offset
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        dt = _dt.datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_dt.timezone.utc)
        return dt.astimezone(_dt.timezone.utc)
    except Exception as e:
        raise EventValidationError(f"Invalid datetime format: {value!r}") from e


def _new_event_id() -> str:
    return str(uuid.uuid4())


def _ensure_str(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise EventValidationError(f"{name} must be a non-empty string")
    return value


def _ensure_mapping(name: str, value: Any) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise EventValidationError(f"{name} must be a mapping/dict")
    return value


def _json_default(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    if isinstance(obj, (_dt.datetime, _dt.date)):
        if isinstance(obj, _dt.datetime):
            return _isoformat_utc(obj)
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _canonical_json_bytes(obj: Mapping[str, Any]) -> bytes:
    # Stable canonicalization: sorted keys, compact separators, UTF-8, no NaN/Infinity.
    try:
        s = json.dumps(
            obj,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=_json_default,
            allow_nan=False,
        )
        return s.encode("utf-8")
    except Exception as e:
        raise EventSerializationError("Failed to canonicalize JSON") from e


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac_sha256_hex(secret: bytes, data: bytes) -> str:
    return hmac.new(secret, data, hashlib.sha256).hexdigest()


def _timing_safe_equal(a: str, b: str) -> bool:
    try:
        return hmac.compare_digest(a, b)
    except Exception:
        return False


@dataclass(frozen=True, slots=True)
class EventMeta:
    """
    Metadata attached to every event.

    Designed for:
    - tracing (trace_id, span_id, correlation_id, causation_id)
    - multi-tenancy (tenant_id)
    - subject identity (actor_id, subject_id)
    - routing (source, partition_key)
    - idempotency (dedup_key)
    - time correctness (occurred_at, ingested_at)
    """

    event_id: str = field(default_factory=_new_event_id)
    occurred_at: _dt.datetime = field(default_factory=_utcnow)
    ingested_at: _dt.datetime = field(default_factory=_utcnow)

    source: str = "agent_mash"
    tenant_id: Optional[str] = None

    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    correlation_id: Optional[str] = None
    causation_id: Optional[str] = None

    actor_id: Optional[str] = None
    subject_id: Optional[str] = None

    partition_key: Optional[str] = None
    dedup_key: Optional[str] = None

    schema: str = "aethernova.event/1"

    def __post_init__(self) -> None:
        _ensure_str("event_id", self.event_id)

        if not isinstance(self.occurred_at, _dt.datetime):
            raise EventValidationError("occurred_at must be datetime")
        if not isinstance(self.ingested_at, _dt.datetime):
            raise EventValidationError("ingested_at must be datetime")

        object.__setattr__(self, "occurred_at", self._normalize_dt(self.occurred_at))
        object.__setattr__(self, "ingested_at", self._normalize_dt(self.ingested_at))

        if self.source:
            if not isinstance(self.source, str) or not _EVENT_SOURCE_RE.match(self.source):
                raise EventValidationError("source has invalid format")
        else:
            raise EventValidationError("source must be non-empty")

        if self.tenant_id is not None:
            if not isinstance(self.tenant_id, str) or not _TENANT_RE.match(self.tenant_id):
                raise EventValidationError("tenant_id has invalid format")

        for k in ("trace_id", "span_id", "correlation_id", "causation_id"):
            v = getattr(self, k)
            if v is not None and not isinstance(v, str):
                raise EventValidationError(f"{k} must be a string if provided")

        for k in ("actor_id", "subject_id"):
            v = getattr(self, k)
            if v is not None:
                if not isinstance(v, str) or not _SUBJECT_RE.match(v):
                    raise EventValidationError(f"{k} has invalid format")

        for k in ("partition_key", "dedup_key"):
            v = getattr(self, k)
            if v is not None and not isinstance(v, str):
                raise EventValidationError(f"{k} must be a string if provided")

        if not isinstance(self.schema, str) or not self.schema:
            raise EventValidationError("schema must be a non-empty string")

    @staticmethod
    def _normalize_dt(dt: _dt.datetime) -> _dt.datetime:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_dt.timezone.utc)
        return dt.astimezone(_dt.timezone.utc)

    def to_wire(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "occurred_at": _isoformat_utc(self.occurred_at),
            "ingested_at": _isoformat_utc(self.ingested_at),
            "source": self.source,
            "tenant_id": self.tenant_id,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "correlation_id": self.correlation_id,
            "causation_id": self.causation_id,
            "actor_id": self.actor_id,
            "subject_id": self.subject_id,
            "partition_key": self.partition_key,
            "dedup_key": self.dedup_key,
            "schema": self.schema,
        }

    @classmethod
    def from_wire(cls, data: Mapping[str, Any]) -> "EventMeta":
        data = dict(_ensure_mapping("meta", data))
        try:
            occurred_at = _parse_iso8601_utc(str(data.get("occurred_at")))
            ingested_at = _parse_iso8601_utc(str(data.get("ingested_at")))
        except KeyError as e:
            raise EventValidationError("meta is missing required datetime fields") from e

        return cls(
            event_id=str(data.get("event_id") or _new_event_id()),
            occurred_at=occurred_at,
            ingested_at=ingested_at,
            source=str(data.get("source") or "agent_mash"),
            tenant_id=(None if data.get("tenant_id") is None else str(data.get("tenant_id"))),
            trace_id=(None if data.get("trace_id") is None else str(data.get("trace_id"))),
            span_id=(None if data.get("span_id") is None else str(data.get("span_id"))),
            correlation_id=(None if data.get("correlation_id") is None else str(data.get("correlation_id"))),
            causation_id=(None if data.get("causation_id") is None else str(data.get("causation_id"))),
            actor_id=(None if data.get("actor_id") is None else str(data.get("actor_id"))),
            subject_id=(None if data.get("subject_id") is None else str(data.get("subject_id"))),
            partition_key=(None if data.get("partition_key") is None else str(data.get("partition_key"))),
            dedup_key=(None if data.get("dedup_key") is None else str(data.get("dedup_key"))),
            schema=str(data.get("schema") or "aethernova.event/1"),
        )


@dataclass(frozen=True, slots=True)
class Event:
    """
    Immutable event envelope.

    Fields:
    - name/version identify the event type
    - meta carries tracing and tenancy
    - payload is the domain data
    - headers carry transport/system data (content-type, signature, etc.)
    """

    name: str
    version: int = 1
    meta: EventMeta = field(default_factory=EventMeta)
    payload: Mapping[str, Any] = field(default_factory=dict)
    headers: Mapping[str, str] = field(default_factory=dict)

    # Reserved header keys
    HDR_CONTENT_TYPE: ClassVar[str] = "content-type"
    HDR_SIGNATURE: ClassVar[str] = "x-signature"
    HDR_SIGNATURE_ALG: ClassVar[str] = "x-signature-alg"
    HDR_DIGEST: ClassVar[str] = "x-digest"
    HDR_DIGEST_ALG: ClassVar[str] = "x-digest-alg"

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not _EVENT_NAME_RE.match(self.name):
            raise EventValidationError("Event name has invalid format")

        if not isinstance(self.version, int) or self.version <= 0:
            raise EventValidationError("Event version must be a positive integer")

        if not isinstance(self.meta, EventMeta):
            raise EventValidationError("meta must be EventMeta")

        if not isinstance(self.payload, Mapping):
            raise EventValidationError("payload must be a mapping/dict")

        if not isinstance(self.headers, Mapping):
            raise EventValidationError("headers must be a mapping/dict")

        for k, v in self.headers.items():
            if not isinstance(k, str) or not k:
                raise EventValidationError("header keys must be non-empty strings")
            if not isinstance(v, str):
                raise EventValidationError("header values must be strings")

    def to_wire(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "meta": self.meta.to_wire(),
            "payload": dict(self.payload),
            "headers": dict(self.headers),
        }

    @classmethod
    def from_wire(cls: Type[TEvent], data: Mapping[str, Any]) -> TEvent:
        data = dict(_ensure_mapping("event", data))
        meta_raw = data.get("meta")
        payload_raw = data.get("payload")
        headers_raw = data.get("headers")

        if meta_raw is None:
            raise EventValidationError("event.meta is required")
        meta = EventMeta.from_wire(_ensure_mapping("event.meta", meta_raw))

        payload = _ensure_mapping("event.payload", payload_raw)
        headers_map = _ensure_mapping("event.headers", headers_raw)

        headers: Dict[str, str] = {}
        for k, v in headers_map.items():
            headers[str(k)] = str(v)

        name = _ensure_str("event.name", data.get("name"))
        version = int(data.get("version") or 1)

        return cls(name=name, version=version, meta=meta, payload=dict(payload), headers=headers)

    def canonical_envelope(self) -> Dict[str, Any]:
        # Canonical content excludes mutable transport headers except digest/signature.
        return {
            "name": self.name,
            "version": self.version,
            "meta": self.meta.to_wire(),
            "payload": self._normalize_payload(self.payload),
        }

    def canonical_bytes(self) -> bytes:
        return _canonical_json_bytes(self.canonical_envelope())

    def digest(self) -> str:
        return _sha256_hex(self.canonical_bytes())

    def with_digest_header(self) -> "Event":
        hdrs = dict(self.headers)
        hdrs[self.HDR_DIGEST_ALG] = "sha-256"
        hdrs[self.HDR_DIGEST] = self.digest()
        if self.HDR_CONTENT_TYPE not in hdrs:
            hdrs[self.HDR_CONTENT_TYPE] = "application/json"
        return dataclasses.replace(self, headers=hdrs)

    def sign_hmac_sha256(self, secret: Union[str, bytes]) -> "Event":
        secret_b = secret.encode("utf-8") if isinstance(secret, str) else secret
        if not isinstance(secret_b, (bytes, bytearray)) or not secret_b:
            raise EventSignatureError("secret must be non-empty bytes or string")

        data = self.canonical_bytes()
        sig = _hmac_sha256_hex(bytes(secret_b), data)

        hdrs = dict(self.headers)
        hdrs[self.HDR_SIGNATURE_ALG] = "hmac-sha256"
        hdrs[self.HDR_SIGNATURE] = sig
        if self.HDR_CONTENT_TYPE not in hdrs:
            hdrs[self.HDR_CONTENT_TYPE] = "application/json"
        # Also attach digest for observability
        if self.HDR_DIGEST not in hdrs:
            hdrs[self.HDR_DIGEST_ALG] = "sha-256"
            hdrs[self.HDR_DIGEST] = _sha256_hex(data)

        return dataclasses.replace(self, headers=hdrs)

    def verify_hmac_sha256(self, secret: Union[str, bytes]) -> None:
        secret_b = secret.encode("utf-8") if isinstance(secret, str) else secret
        if not isinstance(secret_b, (bytes, bytearray)) or not secret_b:
            raise EventSignatureError("secret must be non-empty bytes or string")

        alg = self.headers.get(self.HDR_SIGNATURE_ALG)
        sig = self.headers.get(self.HDR_SIGNATURE)
        if alg != "hmac-sha256" or not sig:
            raise EventSignatureError("missing or unsupported signature")

        expected = _hmac_sha256_hex(bytes(secret_b), self.canonical_bytes())
        if not _timing_safe_equal(sig, expected):
            raise EventSignatureError("invalid signature")

    def to_json(self) -> str:
        try:
            return json.dumps(
                self.to_wire(),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                default=_json_default,
                allow_nan=False,
            )
        except Exception as e:
            raise EventSerializationError("Failed to serialize event to JSON") from e

    @classmethod
    def from_json(cls: Type[TEvent], s: str) -> TEvent:
        if not isinstance(s, str) or not s:
            raise EventSerializationError("JSON input must be a non-empty string")
        try:
            data = json.loads(s)
        except Exception as e:
            raise EventSerializationError("Invalid JSON") from e
        return cls.from_wire(_ensure_mapping("event-json", data))

    @staticmethod
    def _normalize_payload(payload: Mapping[str, Any]) -> Dict[str, Any]:
        # Normalize nested dataclasses/datetime to JSON-friendly via json default conversion
        # without losing types at runtime; wire is JSON-centric anyway.
        def normalize(v: Any) -> Any:
            if dataclasses.is_dataclass(v):
                return {k: normalize(val) for k, val in dataclasses.asdict(v).items()}
            if isinstance(v, _dt.datetime):
                return _isoformat_utc(v)
            if isinstance(v, _dt.date):
                return v.isoformat()
            if isinstance(v, Mapping):
                return {str(k): normalize(val) for k, val in v.items()}
            if isinstance(v, (list, tuple)):
                return [normalize(x) for x in v]
            if isinstance(v, (str, int, float, bool)) or v is None:
                return v
            # Last resort: string representation for non-JSON-safe objects
            return str(v)

        return {str(k): normalize(val) for k, val in payload.items()}


@runtime_checkable
class EventHandler(Protocol):
    async def __call__(self, event: Event) -> None: ...


@runtime_checkable
class EventBus(Protocol):
    async def publish(self, event: Event) -> None: ...
    async def publish_many(self, events: Iterable[Event]) -> None: ...
    def subscribe(self, name: str, handler: EventHandler) -> None: ...
    def unsubscribe(self, name: str, handler: EventHandler) -> None: ...


@runtime_checkable
class EventSerializer(Protocol):
    content_type: str

    def dumps(self, event: Event) -> bytes: ...
    def loads(self, data: bytes) -> Event: ...


class JsonEventSerializer:
    content_type = "application/json"

    def dumps(self, event: Event) -> bytes:
        try:
            return event.to_json().encode("utf-8")
        except Exception as e:
            raise EventSerializationError("Failed to dump event") from e

    def loads(self, data: bytes) -> Event:
        if not isinstance(data, (bytes, bytearray)) or not data:
            raise EventSerializationError("data must be non-empty bytes")
        try:
            return Event.from_json(data.decode("utf-8"))
        except Exception as e:
            raise EventSerializationError("Failed to load event") from e


PayloadValidator = Callable[[Mapping[str, Any]], None]


class EventRegistry:
    """
    Registry that binds (name, version) to a validator (and optionally a subclass).

    This is intentionally lightweight and dependency-free.
    Use it to enforce payload shape at the system boundary.
    """

    def __init__(self) -> None:
        self._validators: Dict[Tuple[str, int], PayloadValidator] = {}
        self._classes: Dict[Tuple[str, int], Type[Event]] = {}

    def register(
        self,
        name: str,
        version: int = 1,
        *,
        validator: Optional[PayloadValidator] = None,
        event_cls: Optional[Type[Event]] = None,
    ) -> None:
        if not isinstance(name, str) or not _EVENT_NAME_RE.match(name):
            raise EventValidationError("Invalid event name for registry")
        if not isinstance(version, int) or version <= 0:
            raise EventValidationError("Invalid version for registry")
        key = (name, version)
        if validator is not None:
            self._validators[key] = validator
        if event_cls is not None:
            if not issubclass(event_cls, Event):
                raise EventValidationError("event_cls must be a subclass of Event")
            self._classes[key] = event_cls

    def validate(self, event: Event) -> None:
        key = (event.name, event.version)
        validator = self._validators.get(key)
        if validator is None:
            return
        validator(event.payload)

    def coerce(self, event: Event) -> Event:
        key = (event.name, event.version)
        cls = self._classes.get(key)
        if cls is None or isinstance(event, cls):
            return event
        return cls.from_wire(event.to_wire())

    def parse(self, wire: Mapping[str, Any]) -> Event:
        event = Event.from_wire(wire)
        self.validate(event)
        return self.coerce(event)


class EventStore(abc.ABC):
    """
    Minimal event store interface.
    Implementations may persist to DB, log, S3, Kafka compacted topic, etc.
    """

    @abc.abstractmethod
    async def append(self, stream: str, event: Event) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    async def append_many(self, stream: str, events: Iterable[Event]) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    async def read(
        self,
        stream: str,
        *,
        after_event_id: Optional[str] = None,
        limit: int = 1000,
    ) -> Sequence[Event]:
        raise NotImplementedError


def require_fields(payload: Mapping[str, Any], fields: Iterable[Tuple[str, type]]) -> None:
    for name, tp in fields:
        if name not in payload:
            raise EventValidationError(f"payload missing required field: {name}")
        v = payload[name]
        if tp is Any:
            continue
        if not isinstance(v, tp):
            raise EventValidationError(f"payload field {name} must be {tp.__name__}")


def optional_fields(payload: Mapping[str, Any], fields: Iterable[Tuple[str, type]]) -> None:
    for name, tp in fields:
        if name not in payload:
            continue
        v = payload[name]
        if v is None:
            continue
        if tp is Any:
            continue
        if not isinstance(v, tp):
            raise EventValidationError(f"payload field {name} must be {tp.__name__} if provided")


__all__ = [
    "JsonPrimitive",
    "JsonValue",
    "JsonObject",
    "EventError",
    "EventValidationError",
    "EventSerializationError",
    "EventSignatureError",
    "EventMeta",
    "Event",
    "EventHandler",
    "EventBus",
    "EventSerializer",
    "JsonEventSerializer",
    "PayloadValidator",
    "EventRegistry",
    "EventStore",
    "require_fields",
    "optional_fields",
]
