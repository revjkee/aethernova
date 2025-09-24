# file: policy-core/api/ws/protocols.py
from __future__ import annotations

import json
import time
import uuid
import hmac
import hashlib
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Any, Dict, List, Mapping, Optional, Tuple, Type, TypeVar, Union, Callable

try:
    # cbor2 — опционален; если недоступен, CBOR сабпротокол будет отключён
    import cbor2  # type: ignore
    _HAS_CBOR = True
except Exception:  # pragma: no cover
    _HAS_CBOR = False

from pydantic import BaseModel, Field, validator

__all__ = [
    "WS_SUBPROTOCOLS",
    "WS_VERSION",
    "MessageType",
    "CloseCode",
    "ErrorCode",
    "Envelope",
    "Hello",
    "Welcome",
    "Ping",
    "Pong",
    "EvaluateRequest",
    "DecisionResponse",
    "Subscribe",
    "Unsubscribe",
    "Event",
    "Ack",
    "Nack",
    "ErrorMessage",
    "Bye",
    "ProtocolCodec",
    "JsonCodec",
    "CborCodec",
    "select_subprotocol",
    "build_envelope",
    "parse_envelope",
    "TokenBucket",
    "next_id",
    "now_ms",
    "make_ping",
    "make_pong",
    "sign_headers",
]

# ============================================================
# Версионирование и сабпротоколы
# ============================================================

WS_VERSION = 1

# Имена сабпротоколов, которые сервер готов принять
WS_SUBPROTOCOLS: Tuple[str, ...] = tuple(
    p for p in (
        "policy.v1.json",
        "policy.v1.cbor" if _HAS_CBOR else None,
    ) if p
)

def select_subprotocol(client_offered: List[str]) -> Optional[str]:
    """
    Выбор общего сабпротокола согласно порядку предпочтений сервера.
    """
    offered = [p.strip() for p in (client_offered or []) if p]
    for preferred in WS_SUBPROTOCOLS:
        if preferred in offered:
            return preferred
    return None

# ============================================================
# Типы сообщений и коды ошибок/закрытия
# ============================================================

class MessageType(str, Enum):
    HELLO = "HELLO"           # клиент -> сервер: аутентификация/возможности
    WELCOME = "WELCOME"       # сервер -> клиент: подтверждение сессии
    PING = "PING"             # обе стороны: проверка живости канала
    PONG = "PONG"
    EVALUATE = "EVALUATE"     # запрос оценки политики
    DECISION = "DECISION"     # ответ на EVALUATE
    SUBSCRIBE = "SUBSCRIBE"   # подписка на события
    UNSUBSCRIBE = "UNSUBSCRIBE"
    EVENT = "EVENT"           # событие по подписке
    ACK = "ACK"               # подтверждение доставки/обработки
    NACK = "NACK"             # отрицательное подтверждение
    ERROR = "ERROR"           # форматированная ошибка
    BYE = "BYE"               # намеренное завершение сессии

class CloseCode(IntEnum):
    NORMAL_CLOSURE = 1000
    GOING_AWAY = 1001
    PROTOCOL_ERROR = 1002
    UNSUPPORTED_DATA = 1003
    NO_STATUS_RCVD = 1005
    ABNORMAL_CLOSURE = 1006
    INVALID_FRAME = 1007
    POLICY_VIOLATION = 1008
    MESSAGE_TOO_BIG = 1009
    MANDATORY_EXT = 1010
    INTERNAL_ERROR = 1011
    SERVICE_RESTART = 1012
    TRY_AGAIN_LATER = 1013
    BAD_GATEWAY = 1014
    TLS_HANDSHAKE = 1015

class ErrorCode(str, Enum):
    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN = "FORBIDDEN"
    RATE_LIMITED = "RATE_LIMITED"
    INVALID_MESSAGE = "INVALID_MESSAGE"
    PROTOCOL_MISMATCH = "PROTOCOL_MISMATCH"
    UNSUPPORTED_TYPE = "UNSUPPORTED_TYPE"
    TIMEOUT = "TIMEOUT"
    INTERNAL = "INTERNAL"
    BACKPRESSURE = "BACKPRESSURE"

# ============================================================
# Модели сообщений (payload)
# ============================================================

class Envelope(BaseModel):
    """
    Универсальная обертка WS-сообщений.
    """
    id: str = Field(default_factory=lambda: uuid.uuid4().hex)      # идентификатор сообщения
    ts: int = Field(default_factory=lambda: int(time.time() * 1000))  # epoch millis
    type: MessageType
    ver: int = Field(WS_VERSION, description="protocol version")
    headers: Dict[str, str] = Field(default_factory=dict)
    payload: Dict[str, Any] = Field(default_factory=dict)

    @validator("id")
    def _nonempty(cls, v: str) -> str:
        if not v:
            raise ValueError("id must be non-empty")
        return v

class Hello(BaseModel):
    client_id: str
    auth: Optional[str] = Field(None, description="Bearer <token> или иная схема")
    subprotocols: List[str] = Field(default_factory=list)
    capabilities: List[str] = Field(default_factory=list)
    accept_compression: List[str] = Field(default_factory=list)  # ["permessage-deflate"]
    # Опциональные системные параметры
    user_agent: Optional[str] = None
    locale: Optional[str] = None

class Welcome(BaseModel):
    server_id: str
    session_id: str
    negotiated_subprotocol: str
    heartbeat_interval_s: float = 20.0
    expires_at: Optional[int] = None  # epoch ms
    features: List[str] = Field(default_factory=list)

class Ping(BaseModel):
    nonce: str = Field(default_factory=lambda: uuid.uuid4().hex)
    last_ack_id: Optional[str] = None

class Pong(BaseModel):
    nonce: str
    last_ack_id: Optional[str] = None

class EvaluateRequest(BaseModel):
    correlation_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    subject: Dict[str, Any]
    resource: Dict[str, Any]
    action: Dict[str, Any]
    environment: Dict[str, Any] = Field(default_factory=dict)
    deadline_ms: Optional[int] = None

class DecisionResponse(BaseModel):
    correlation_id: str
    effect: str  # "Permit" | "Deny"
    obligations: List[Dict[str, Any]] = Field(default_factory=list)
    reasons: List[Dict[str, Any]] = Field(default_factory=list)
    cached: bool = False
    latency_ms: Optional[float] = None

class Subscribe(BaseModel):
    correlation_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    topic: str
    filter: Dict[str, Any] = Field(default_factory=dict)
    qos: int = 0  # 0 - at-most-once, 1 - at-least-once (с ACK)

class Unsubscribe(BaseModel):
    correlation_id: str
    topic: str

class Event(BaseModel):
    topic: str
    data: Dict[str, Any]
    sequence: Optional[int] = None
    retained: bool = False

class Ack(BaseModel):
    message_id: str
    reason: Optional[str] = None

class Nack(BaseModel):
    message_id: str
    reason: Optional[str] = None
    code: ErrorCode = ErrorCode.INVALID_MESSAGE
    retry_after_ms: Optional[int] = None

class ErrorMessage(BaseModel):
    code: ErrorCode
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)

class Bye(BaseModel):
    reason: Optional[str] = None

# ============================================================
# Кодеки (JSON/CBOR)
# ============================================================

class ProtocolCodec:
    """
    Абстракция кодека для сериализации/десериализации кадров.
    """
    content_type: str = "application/octet-stream"

    def encode(self, env: Envelope) -> bytes:  # pragma: no cover - интерфейс
        raise NotImplementedError

    def decode(self, data: Union[bytes, bytearray, memoryview]) -> Envelope:  # pragma: no cover - интерфейс
        raise NotImplementedError

class JsonCodec(ProtocolCodec):
    content_type = "application/json"

    def encode(self, env: Envelope) -> bytes:
        return json.dumps(env.dict(), separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def decode(self, data: Union[bytes, bytearray, memoryview]) -> Envelope:
        obj = json.loads(bytes(data).decode("utf-8"))
        return Envelope.parse_obj(obj)

class CborCodec(ProtocolCodec):
    content_type = "application/cbor"

    def encode(self, env: Envelope) -> bytes:
        if not _HAS_CBOR:
            raise RuntimeError("CBOR codec unavailable: cbor2 not installed")
        return cbor2.dumps(env.dict())

    def decode(self, data: Union[bytes, bytearray, memoryview]) -> Envelope:
        if not _HAS_CBOR:
            raise RuntimeError("CBOR codec unavailable: cbor2 not installed")
        obj = cbor2.loads(bytes(data))
        return Envelope.parse_obj(obj)

def codec_for_subprotocol(subprotocol: str) -> ProtocolCodec:
    if subprotocol == "policy.v1.json":
        return JsonCodec()
    if subprotocol == "policy.v1.cbor":
        return CborCodec()
    # по умолчанию JSON
    return JsonCodec()

# ============================================================
# Построение/парсинг конвертов
# ============================================================

T = TypeVar("T", bound=BaseModel)

_PAYLOAD_SCHEMA: Mapping[MessageType, Type[BaseModel]] = {
    MessageType.HELLO: Hello,
    MessageType.WELCOME: Welcome,
    MessageType.PING: Ping,
    MessageType.PONG: Pong,
    MessageType.EVALUATE: EvaluateRequest,
    MessageType.DECISION: DecisionResponse,
    MessageType.SUBSCRIBE: Subscribe,
    MessageType.UNSUBSCRIBE: Unsubscribe,
    MessageType.EVENT: Event,
    MessageType.ACK: Ack,
    MessageType.NACK: Nack,
    MessageType.ERROR: ErrorMessage,
    MessageType.BYE: Bye,
}

def build_envelope(msg_type: MessageType, payload: BaseModel, headers: Optional[Dict[str, str]] = None, msg_id: Optional[str] = None) -> Envelope:
    """
    Упаковать payload в Envelope с типом msg_type.
    """
    if type(payload) is not _PAYLOAD_SCHEMA[msg_type]:
        # строгая проверка соответствия модели и типа
        expected = _PAYLOAD_SCHEMA[msg_type].__name__
        raise TypeError(f"payload must be {expected} for type {msg_type}")
    return Envelope(
        id=msg_id or uuid.uuid4().hex,
        ts=now_ms(),
        type=msg_type,
        ver=WS_VERSION,
        headers=headers or {},
        payload=payload.dict(),
    )

def parse_envelope(env: Envelope) -> BaseModel:
    """
    Распаковать Envelope в конкретную модель payload согласно type.
    """
    schema = _PAYLOAD_SCHEMA.get(env.type)
    if not schema:
        raise ValueError(f"unsupported message type: {env.type}")
    try:
        return schema.parse_obj(env.payload)
    except Exception as ex:
        raise ValueError(f"invalid payload for {env.type}: {ex}") from ex

# ============================================================
# Утилиты: id, время, heartbeat, подписи, rate limiting
# ============================================================

def next_id() -> str:
    return uuid.uuid4().hex

def now_ms() -> int:
    return int(time.time() * 1000)

def make_ping(last_ack_id: Optional[str] = None) -> Envelope:
    return build_envelope(MessageType.PING, Ping(last_ack_id=last_ack_id))

def make_pong(nonce: str, last_ack_id: Optional[str] = None) -> Envelope:
    return build_envelope(MessageType.PONG, Pong(nonce=nonce, last_ack_id=last_ack_id))

def sign_headers(headers: Dict[str, str], secret: str, fields: Optional[List[str]] = None) -> Dict[str, str]:
    """
    HMAC-подпись выбранных полей заголовка (для простого channel auth).
    Добавляет 'x-signature' и 'x-signed-fields'.
    """
    fields = fields or sorted(headers.keys())
    payload = "&".join(f"{k}={headers.get(k,'')}" for k in fields)
    digest = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    signed = dict(headers)
    signed["x-signed-fields"] = ",".join(fields)
    signed["x-signature"] = digest
    return signed

@dataclass
class TokenBucket:
    """
    Простая реализация token bucket для rate-лимита.
    capacity: максимальное число токенов.
    refill_rate: сколько токенов добавляется в секунду.
    """
    capacity: int
    refill_rate: float
    tokens: float = 0.0
    last_refill: float = 0.0

    def __post_init__(self) -> None:
        self.tokens = float(self.capacity)
        self.last_refill = time.monotonic()

    def allow(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = max(0.0, now - self.last_refill)
        self.last_refill = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False

# ============================================================
# Примеры высокоуровневых конструкторов (server-side helpers)
# ============================================================

def make_welcome(server_id: str, session_id: str, subprotocol: str, heartbeat_interval_s: float = 20.0, features: Optional[List[str]] = None, ttl_s: Optional[int] = None) -> Envelope:
    expires = now_ms() + int(ttl_s * 1000) if ttl_s else None
    payload = Welcome(
        server_id=server_id,
        session_id=session_id,
        negotiated_subprotocol=subprotocol,
        heartbeat_interval_s=heartbeat_interval_s,
        expires_at=expires,
        features=features or [],
    )
    return build_envelope(MessageType.WELCOME, payload)

def make_error(code: ErrorCode, message: str, *, for_message: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> Envelope:
    headers = {}
    if for_message:
        headers["x-error-for"] = for_message
    return build_envelope(MessageType.ERROR, ErrorMessage(code=code, message=message, details=details or {}), headers=headers)

def make_ack(message_id: str, reason: Optional[str] = None) -> Envelope:
    return build_envelope(MessageType.ACK, Ack(message_id=message_id, reason=reason))

def make_nack(message_id: str, code: ErrorCode = ErrorCode.INVALID_MESSAGE, reason: Optional[str] = None, retry_after_ms: Optional[int] = None) -> Envelope:
    return build_envelope(MessageType.NACK, Nack(message_id=message_id, code=code, reason=reason, retry_after_ms=retry_after_ms))
