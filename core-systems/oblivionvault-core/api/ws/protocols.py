from __future__ import annotations

import json
import time
import uuid
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union, Protocol, runtime_checkable

from pydantic import BaseModel, Field, ValidationError, field_validator

# Опциональная телеметрия
try:
    from opentelemetry import trace  # type: ignore
    _tracer = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _tracer = None  # type: ignore


# --------------------------- Версионирование и сабпротоколы ---------------------------

class WSProtocolVersion(str, Enum):
    V1 = "v1"


class WSSubprotocol(str, Enum):
    OVC_WS_V1_JSON = "ovc.ws.v1+json"
    OVC_WS_V1_MSGPACK = "ovc.ws.v1+msgpack"


SUPPORTED_SUBPROTOCOLS: Tuple[WSSubprotocol, ...] = (
    WSSubprotocol.OVC_WS_V1_JSON,
    WSSubprotocol.OVC_WS_V1_MSGPACK,
)


def pick_subprotocol(offered: Iterable[str]) -> Optional[str]:
    """
    Выбрать лучший общий сабпротокол между клиентом и сервером.
    Возвращает строку сабпротокола или None (будет использован JSON по умолчанию без header).
    """
    offered_set = {s.lower() for s in offered}
    for sp in SUPPORTED_SUBPROTOCOLS:
        if sp.value in offered_set:
            return sp.value
    return None


# --------------------------- Ограничения и константы безопасности ---------------------------

# Жесткие лимиты, согласованные с ingress и сервером
MAX_FRAME_BYTES_HARD = 2 * 1024 * 1024  # 2 MiB
MAX_BATCH_COUNT_HARD = 256
DEFAULT_SEND_QUEUE_HARD = 1000

# Периоды heartbeat
PING_INTERVAL_SEC_DEFAULT = 30.0
PING_TIMEOUT_SEC_DEFAULT = 10.0


# --------------------------- Операции/коды ошибок ---------------------------

class OpCode(str, Enum):
    HELLO = "HELLO"              # сервер -> клиент приветствие
    AUTH = "AUTH"                # клиент -> сервер аутентификация
    AUTH_OK = "AUTH_OK"          # сервер -> клиент подтверждение
    AUTH_FAIL = "AUTH_FAIL"      # сервер -> клиент отказ
    SUBSCRIBE = "SUBSCRIBE"      # клиент -> сервер подписка на канал/топик
    UNSUBSCRIBE = "UNSUBSCRIBE"  # клиент -> сервер отписка
    EVENT = "EVENT"              # сервер -> клиент событие
    BATCH = "BATCH"              # пакет событий
    ACK = "ACK"                  # подтверждение доставки
    NACK = "NACK"                # отрицательное подтверждение
    PING = "PING"                # heartbeat
    PONG = "PONG"                # heartbeat
    ERROR = "ERROR"              # ошибка протокола
    CLOSE = "CLOSE"              # сервер -> клиент закрытие по политике


class ErrorCode(int, Enum):
    OK = 0
    BAD_REQUEST = 1000
    UNAUTHORIZED = 1001
    FORBIDDEN = 1003
    RATE_LIMIT = 1010
    PAYLOAD_TOO_LARGE = 1011
    UNSUPPORTED_OPCODE = 1020
    UNSUPPORTED_SUBPROTOCOL = 1021
    INTERNAL_ERROR = 1100
    TIMEOUT = 1108
    BACKPRESSURE = 1110


# --------------------------- Pydantic-модели кадров ---------------------------

def _now_utc_ts() -> int:
    return int(datetime.now(tz=timezone.utc).timestamp() * 1000)


class FrameHeader(BaseModel):
    ver: WSProtocolVersion = Field(default=WSProtocolVersion.V1, description="Версия протокола")
    op: OpCode = Field(..., description="Код операции")
    sid: uuid.UUID = Field(default_factory=uuid.uuid4, description="Сессионный UUID")
    seq: int = Field(default=0, ge=0, description="Секвенс в рамках сессии")
    ts: int = Field(default_factory=_now_utc_ts, description="Unix epoch ms")
    msgId: uuid.UUID = Field(default_factory=uuid.uuid4, description="UUID кадра")
    corrId: Optional[uuid.UUID] = Field(default=None, description="Для ACK/NACK/корреляции")
    chan: Optional[str] = Field(default=None, max_length=256, description="Логический канал/топик")

    @field_validator("chan")
    @classmethod
    def _no_ws_control_channels(cls, v: Optional[str]) -> Optional[str]:
        if v and v.startswith("_"):
            raise ValueError("channels starting with '_' are reserved")
        return v


class ErrorBody(BaseModel):
    code: ErrorCode = Field(default=ErrorCode.INTERNAL_ERROR)
    reason: str = Field(default="internal_error", max_length=256)
    details: Optional[Dict[str, Any]] = None


JSONValue = Union[None, bool, int, float, str, Dict[str, Any], List[Any]]


class Frame(BaseModel):
    hdr: FrameHeader
    data: Optional[JSONValue] = None
    err: Optional[ErrorBody] = None

    def require_ok(self) -> "Frame":
        if self.hdr.op in (OpCode.ERROR, OpCode.AUTH_FAIL) or self.err:
            raise ProtocolError(self.err.reason if self.err else "error_frame", self.err.code if self.err else ErrorCode.INTERNAL_ERROR)
        return self


class Batch(BaseModel):
    hdr: FrameHeader
    items: List[Frame]

    @field_validator("items")
    @classmethod
    def _limit_items(cls, v: List[Frame]) -> List[Frame]:
        if len(v) > MAX_BATCH_COUNT_HARD:
            raise ValueError("batch too large")
        return v


# --------------------------- Исключение протокола ---------------------------

class ProtocolError(RuntimeError):
    def __init__(self, msg: str, code: ErrorCode = ErrorCode.INTERNAL_ERROR):
        super().__init__(msg)
        self.code = code


# --------------------------- Кодеки кадров ---------------------------

@runtime_checkable
class FrameCodec(Protocol):
    content_type: str
    subprotocol: Optional[WSSubprotocol]

    def encode(self, obj: Union[Frame, Batch]) -> bytes: ...
    def decode(self, raw: bytes) -> Union[Frame, Batch]: ...


class JsonCodec(FrameCodec):
    content_type = "application/json"
    subprotocol = WSSubprotocol.OVC_WS_V1_JSON

    def encode(self, obj: Union[Frame, Batch]) -> bytes:
        model = obj.model_dump(mode="json")
        s = json.dumps(model, separators=(",", ":"), ensure_ascii=False)
        b = s.encode("utf-8")
        if len(b) > MAX_FRAME_BYTES_HARD:
            raise ProtocolError("payload too large", ErrorCode.PAYLOAD_TOO_LARGE)
        return b

    def decode(self, raw: bytes) -> Union[Frame, Batch]:
        if len(raw) > MAX_FRAME_BYTES_HARD:
            raise ProtocolError("payload too large", ErrorCode.PAYLOAD_TOO_LARGE)
        try:
            obj = json.loads(raw.decode("utf-8"))
            if "items" in obj:
                return Batch.model_validate(obj)
            return Frame.model_validate(obj)
        except ValidationError as ve:
            raise ProtocolError(f"bad frame schema: {ve}", ErrorCode.BAD_REQUEST) from ve
        except Exception as e:
            raise ProtocolError(f"bad json: {e}", ErrorCode.BAD_REQUEST) from e


class MsgPackCodec(FrameCodec):
    content_type = "application/msgpack"
    subprotocol = WSSubprotocol.OVC_WS_V1_MSGPACK

    def __init__(self) -> None:
        try:
            import msgpack  # type: ignore
        except Exception as e:  # pragma: no cover
            raise ProtocolError("msgpack not available", ErrorCode.UNSUPPORTED_SUBPROTOCOL) from e
        self._mp = msgpack

    def encode(self, obj: Union[Frame, Batch]) -> bytes:
        model = obj.model_dump(mode="json")
        b = self._mp.packb(model, use_bin_type=True)
        if len(b) > MAX_FRAME_BYTES_HARD:
            raise ProtocolError("payload too large", ErrorCode.PAYLOAD_TOO_LARGE)
        return b

    def decode(self, raw: bytes) -> Union[Frame, Batch]:
        if len(raw) > MAX_FRAME_BYTES_HARD:
            raise ProtocolError("payload too large", ErrorCode.PAYLOAD_TOO_LARGE)
        try:
            obj = self._mp.unpackb(raw, raw=False)
            if "items" in obj:
                return Batch.model_validate(obj)
            return Frame.model_validate(obj)
        except ValidationError as ve:
            raise ProtocolError(f"bad frame schema: {ve}", ErrorCode.BAD_REQUEST) from ve
        except Exception as e:
            raise ProtocolError(f"bad msgpack: {e}", ErrorCode.BAD_REQUEST) from e


def make_codec(subprotocol: Optional[str]) -> FrameCodec:
    """
    Выбор кодека по сабпротоколу. None -> JSON.
    """
    if not subprotocol:
        return JsonCodec()
    v = subprotocol.lower()
    if v == WSSubprotocol.OVC_WS_V1_JSON.value:
        return JsonCodec()
    if v == WSSubprotocol.OVC_WS_V1_MSGPACK.value:
        return MsgPackCodec()
    raise ProtocolError("unsupported subprotocol", ErrorCode.UNSUPPORTED_SUBPROTOCOL)


# --------------------------- Rate-limit и бэкпрешер ---------------------------

@dataclass
class TokenBucket:
    capacity: int
    refill_per_sec: float
    tokens: float = 0.0
    last_refill: float = 0.0

    def allow(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        if self.last_refill == 0.0:
            self.last_refill = now
        # пополнение
        delta = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + delta * self.refill_per_sec)
        self.last_refill = now
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


@dataclass
class BackpressureGuard:
    hard_limit: int = DEFAULT_SEND_QUEUE_HARD

    def check(self, queue_len: int) -> None:
        if queue_len > self.hard_limit:
            raise ProtocolError("send queue overflow", ErrorCode.BACKPRESSURE)


# --------------------------- Heartbeat и утилиты кадров ---------------------------

def make_hello(sid: Optional[uuid.UUID] = None, compression: Optional[str] = None) -> Frame:
    hdr = FrameHeader(op=OpCode.HELLO, sid=sid or uuid.uuid4())
    data = {
        "heartbeat": {
            "pingIntervalSec": PING_INTERVAL_SEC_DEFAULT,
            "pingTimeoutSec": PING_TIMEOUT_SEC_DEFAULT,
        },
        "compression": compression or "permessage-deflate",
        "limits": {
            "maxFrameBytes": MAX_FRAME_BYTES_HARD,
            "maxBatchCount": MAX_BATCH_COUNT_HARD,
        },
        "version": WSProtocolVersion.V1.value,
    }
    return Frame(hdr=hdr, data=data)


def make_auth_ok(sid: uuid.UUID, scopes: List[str]) -> Frame:
    hdr = FrameHeader(op=OpCode.AUTH_OK, sid=sid)
    return Frame(hdr=hdr, data={"scopes": scopes})


def make_auth_fail(sid: uuid.UUID, reason: str = "unauthorized") -> Frame:
    hdr = FrameHeader(op=OpCode.AUTH_FAIL, sid=sid)
    return Frame(hdr=hdr, err=ErrorBody(code=ErrorCode.UNAUTHORIZED, reason=reason))


def make_ack(sid: uuid.UUID, corr: uuid.UUID, ok: bool = True, note: Optional[str] = None) -> Frame:
    hdr = FrameHeader(op=OpCode.ACK if ok else OpCode.NACK, sid=sid, corrId=corr)
    data = {"note": note} if note else None
    return Frame(hdr=hdr, data=data)


def make_ping(sid: uuid.UUID, seq: int) -> Frame:
    hdr = FrameHeader(op=OpCode.PING, sid=sid, seq=seq)
    return Frame(hdr=hdr, data={"t": _now_utc_ts()})


def make_pong(req_ping: Frame) -> Frame:
    if req_ping.hdr.op != OpCode.PING:
        raise ProtocolError("not a ping", ErrorCode.BAD_REQUEST)
    hdr = FrameHeader(op=OpCode.PONG, sid=req_ping.hdr.sid, corrId=req_ping.hdr.msgId, seq=req_ping.hdr.seq)
    return Frame(hdr=hdr, data=req_ping.data or {})


def is_pong_match(ping: Frame, pong: Frame) -> bool:
    return pong.hdr.op == OpCode.PONG and pong.hdr.corrId == ping.hdr.msgId and pong.hdr.sid == ping.hdr.sid


def make_event(sid: uuid.UUID, chan: str, payload: JSONValue, corr: Optional[uuid.UUID] = None) -> Frame:
    hdr = FrameHeader(op=OpCode.EVENT, sid=sid, chan=chan, corrId=corr)
    return Frame(hdr=hdr, data=payload)


def make_batch(sid: uuid.UUID, frames: List[Frame]) -> Batch:
    hdr = FrameHeader(op=OpCode.BATCH, sid=sid)
    if len(frames) > MAX_BATCH_COUNT_HARD:
        raise ProtocolError("batch too large", ErrorCode.PAYLOAD_TOO_LARGE)
    return Batch(hdr=hdr, items=frames)


def make_error(sid: uuid.UUID, code: ErrorCode, reason: str, details: Optional[Dict[str, Any]] = None) -> Frame:
    hdr = FrameHeader(op=OpCode.ERROR, sid=sid)
    return Frame(hdr=hdr, err=ErrorBody(code=code, reason=reason, details=details))


def make_close(sid: uuid.UUID, code: ErrorCode = ErrorCode.OK, reason: str = "closing") -> Frame:
    hdr = FrameHeader(op=OpCode.CLOSE, sid=sid)
    return Frame(hdr=hdr, err=ErrorBody(code=code, reason=reason))


# --------------------------- Политика состояний рукопожатия ---------------------------

class HandshakeState(str, Enum):
    OPEN = "OPEN"           # установлено соединение, отправляем HELLO
    AUTH_PENDING = "AUTH_PENDING"
    READY = "READY"
    CLOSING = "CLOSING"
    CLOSED = "CLOSED"


@dataclass
class SessionPolicy:
    """
    Политика сеанса, которую используют WS-хэндлеры.
    """
    max_frame_bytes: int = MAX_FRAME_BYTES_HARD
    max_batch_count: int = MAX_BATCH_COUNT_HARD
    ping_interval_sec: float = PING_INTERVAL_SEC_DEFAULT
    ping_timeout_sec: float = PING_TIMEOUT_SEC_DEFAULT
    send_queue_hard_limit: int = DEFAULT_SEND_QUEUE_HARD
    recv_rate_capacity: int = 120  # операций в окно
    recv_rate_refill_per_sec: float = 30.0  # сколько токенов/сек


@dataclass
class SessionContext:
    sid: uuid.UUID
    state: HandshakeState = HandshakeState.OPEN
    seq_out: int = 0
    seq_in: int = 0
    created_at_ms: int = Field(default_factory=_now_utc_ts)  # type: ignore
    policy: SessionPolicy = Field(default_factory=SessionPolicy)  # type: ignore
    bucket: TokenBucket = Field(default_factory=lambda: TokenBucket(capacity=120, refill_per_sec=30.0))  # type: ignore
    bp_guard: BackpressureGuard = Field(default_factory=BackpressureGuard)  # type: ignore
    # пользовательские данные (идентичность, скоупы) можно подвязать здесь
    subject: Optional[str] = None
    scopes: Tuple[str, ...] = ()

    def next_seq(self) -> int:
        self.seq_out += 1
        return self.seq_out

    def allow_recv(self) -> None:
        if not self.bucket.allow():
            raise ProtocolError("rate limit", ErrorCode.RATE_LIMIT)


# --------------------------- Валидация входящих кадров ---------------------------

ALLOWED_BEFORE_AUTH: Tuple[OpCode, ...] = (OpCode.AUTH, OpCode.HELLO, OpCode.PING, OpCode.PONG, OpCode.CLOSE)
ALLOWED_AFTER_AUTH: Tuple[OpCode, ...] = (
    OpCode.SUBSCRIBE, OpCode.UNSUBSCRIBE, OpCode.EVENT, OpCode.ACK, OpCode.NACK, OpCode.PING, OpCode.PONG, OpCode.CLOSE
)


def validate_incoming_frame(sess: SessionContext, frame: Union[Frame, Batch]) -> None:
    """
    Базовая защита входящих кадров: лимит размера/батча, валидность op в текущем состоянии, rate limit.
    """
    sess.allow_recv()

    if isinstance(frame, Batch):
        if len(frame.items) > sess.policy.max_batch_count:
            raise ProtocolError("batch too large", ErrorCode.PAYLOAD_TOO_LARGE)
        for item in frame.items:
            _validate_single(sess, item)
    else:
        _validate_single(sess, frame)


def _validate_single(sess: SessionContext, frame: Frame) -> None:
    op = frame.hdr.op
    if sess.state in (HandshakeState.OPEN, HandshakeState.AUTH_PENDING):
        if op not in ALLOWED_BEFORE_AUTH:
            raise ProtocolError("operation not allowed before auth", ErrorCode.FORBIDDEN)
    elif sess.state in (HandshakeState.READY,):
        if op not in ALLOWED_AFTER_AUTH:
            raise ProtocolError("unsupported operation", ErrorCode.UNSUPPORTED_OPCODE)
    # При необходимости можно добавить проверку монотонности seq
    sess.seq_in = max(sess.seq_in, frame.hdr.seq)


# --------------------------- Компрессия полезной нагрузки ---------------------------

def deflate(payload: bytes, level: int = 6) -> bytes:
    z = zlib.compressobj(level=level, wbits=-zlib.MAX_WBITS)
    data = z.compress(payload) + z.flush()
    return data


def inflate(payload: bytes) -> bytes:
    z = zlib.decompressobj(wbits=-zlib.MAX_WBITS)
    return z.decompress(payload) + z.flush()


# --------------------------- OpenTelemetry утилиты ---------------------------

class _Span:
    def __init__(self, name: str):
        self._name = name
        self._ctx = None

    def __enter__(self):
        if _tracer:
            self._ctx = _tracer.start_as_current_span(self._name)
            return self._ctx.__enter__()
        return None

    def __exit__(self, exc_type, exc, tb):
        if self._ctx:
            self._ctx.__exit__(exc_type, exc, tb)


def trace_frame(op: OpCode) -> _Span:
    return _Span(f"ws.frame.{op.value.lower()}")


# --------------------------- Публичный API модуля ---------------------------

__all__ = [
    # версии/сабпротоколы
    "WSProtocolVersion", "WSSubprotocol", "SUPPORTED_SUBPROTOCOLS", "pick_subprotocol",
    # коды/ошибки
    "OpCode", "ErrorCode", "ProtocolError",
    # модели
    "FrameHeader", "ErrorBody", "Frame", "Batch", "JSONValue",
    # кодеки
    "FrameCodec", "JsonCodec", "MsgPackCodec", "make_codec",
    # лимиты/бэкпрешер
    "TokenBucket", "BackpressureGuard",
    # сессия/политики
    "HandshakeState", "SessionPolicy", "SessionContext",
    # утилиты кадров
    "make_hello", "make_auth_ok", "make_auth_fail",
    "make_ack", "make_ping", "make_pong", "is_pong_match",
    "make_event", "make_batch", "make_error", "make_close",
    # валидация
    "validate_incoming_frame",
    # компрессия
    "deflate", "inflate",
    # трассировка
    "trace_frame",
]
