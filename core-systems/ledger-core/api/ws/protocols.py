# ledger-core/api/ws/protocols.py
from __future__ import annotations

import asyncio
import base64
import enum
import hashlib
import hmac
import json
import os
import time
import typing as t
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from pydantic import BaseModel, Field, ConfigDict, field_validator, ValidationError

try:
    import msgpack  # type: ignore
except Exception:  # pragma: no cover
    msgpack = None  # MessagePack кодек опционален

# ======================================================================================
# Версия и константы протокола
# ======================================================================================

PROTOCOL_NAME = "ledger-ws"
PROTOCOL_VERSION = "1"
PROTOCOL_ID = f"{PROTOCOL_NAME}.v{PROTOCOL_VERSION}"

DEFAULT_MAX_FRAME_BYTES = 256 * 1024
DEFAULT_MAX_INFLIGHT = 1000
DEFAULT_RATE_LIMIT_RPS = 50
DEFAULT_RATE_LIMIT_BURST = 100
DEFAULT_PING_INTERVAL_SECONDS = 20
DEFAULT_PONG_TIMEOUT_SECONDS = 10
DEFAULT_RESUME_TTL_SECONDS = 3600
DEFAULT_ACK_TIMEOUT_SECONDS = 15

# ======================================================================================
# Опкоды и статусы
# ======================================================================================

class OpCode(str, enum.Enum):
    HELLO = "HELLO"            # Сервер -> клиент (приветствие и параметры)
    AUTH = "AUTH"              # Клиент -> сервер (токен/подпись)
    OK = "OK"                  # Сервер -> клиент (подтверждение, например, AUTH/RESUME)
    ERROR = "ERROR"            # Любая сторона -> другая (ошибка обработки)
    SUB = "SUB"                # Клиент -> сервер (подписка)
    UNSUB = "UNSUB"            # Клиент -> сервер (отписка)
    EVENT = "EVENT"            # Сервер -> клиент (событие)
    SNAPSHOT = "SNAPSHOT"      # Сервер -> клиент (начальный слепок)
    ACK = "ACK"                # Клиент -> сервер (подтверждение получения EVENT)
    PING = "PING"              # Любая сторона -> другая
    PONG = "PONG"              # Ответ на PING
    RESUME = "RESUME"          # Клиент -> сервер (возобновление с курсора)
    BYE = "BYE"                # Сервер -> клиент (завершение с причиной)

class CloseCode(int, enum.Enum):
    NORMAL = 1000
    GOING_AWAY = 1001
    PROTOCOL_ERROR = 1002
    UNSUPPORTED_DATA = 1003
    POLICY_VIOLATION = 1008
    MESSAGE_TOO_BIG = 1009
    INTERNAL_ERROR = 1011
    TRY_AGAIN_LATER = 1013

# ======================================================================================
# Вспомогательные типы
# ======================================================================================

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

def _ts_ms(dt: datetime | None = None) -> int:
    return int((dt or _utc_now()).timestamp() * 1000)

# Идентификаторы сеанса/сообщений
def new_id() -> str:
    return uuid.uuid4().hex

# ======================================================================================
# Модели фреймов (Pydantic v2)
# ======================================================================================

class BaseFrame(BaseModel):
    model_config = ConfigDict(extra="forbid")
    op: OpCode = Field(..., description="Тип фрейма")
    id: str = Field(default_factory=new_id, min_length=16, max_length=64, description="Идентификатор фрейма")
    ref: t.Optional[str] = Field(None, description="Ссылка на исходный id (корреляция/ответ)")
    ts: int = Field(default_factory=_ts_ms, description="Время формирования, мс UTC")
    # channel — логическое имя потока (например, 'audit', 'transactions', 'prices:EURUSD')
    channel: t.Optional[str] = Field(None, min_length=1, max_length=200)

class HelloFrame(BaseFrame):
    op: t.Literal[OpCode.HELLO]
    server: str = Field(..., description="Имя/версия сервера")
    session: str = Field(..., description="Идентификатор сеанса (для RESUME)")
    heartbeat_interval: int = Field(DEFAULT_PING_INTERVAL_SECONDS * 1000, ge=1000)
    max_frame_bytes: int = Field(DEFAULT_MAX_FRAME_BYTES, ge=4096)
    max_inflight: int = Field(DEFAULT_MAX_INFLIGHT, ge=1, le=100000)
    features: dict[str, t.Any] = Field(default_factory=dict)

class AuthFrame(BaseFrame):
    op: t.Literal[OpCode.AUTH]
    # Bearer токен или подпись HMAC: scheme указывает вариант
    scheme: t.Literal["bearer", "hmac"] = "bearer"
    token: t.Optional[str] = Field(None, min_length=8, max_length=8192)
    # HMAC: base64url(signature) по canonical(JSON(payload))
    hmac_key_id: t.Optional[str] = Field(None, min_length=1, max_length=256)
    hmac_signature: t.Optional[str] = Field(None, min_length=16, max_length=16384)
    nonce: t.Optional[str] = Field(None, min_length=8, max_length=256)

    @field_validator("token")
    @classmethod
    def _at_least_one(cls, v, info):
        # В bearer режиме нужен token, в hmac — подпись
        return v

class OkFrame(BaseFrame):
    op: t.Literal[OpCode.OK]
    code: int = 200
    message: str = "ok"
    data: dict[str, t.Any] | None = None

class ErrorFrame(BaseFrame):
    op: t.Literal[OpCode.ERROR]
    code: int = Field(..., ge=400, le=599)
    message: str = Field(..., min_length=1, max_length=2000)
    details: dict[str, t.Any] | None = None

class SubFrame(BaseFrame):
    op: t.Literal[OpCode.SUB]
    channel: str = Field(..., min_length=1, max_length=200)
    # позиция начала (курсор) и фильтры
    cursor: t.Optional[str] = Field(None, max_length=1024)
    filters: dict[str, t.Any] | None = Field(default=None)
    batch: int = Field(100, ge=1, le=10000, description="Размер батча SNAPSHOT/EVENT для начала")

class UnsubFrame(BaseFrame):
    op: t.Literal[OpCode.UNSUB]
    channel: str = Field(..., min_length=1, max_length=200)

class EventFrame(BaseFrame):
    op: t.Literal[OpCode.EVENT]
    channel: str = Field(..., min_length=1, max_length=200)
    # idempotency: уникальный идентификатор события (для ACK)
    event_id: str = Field(..., min_length=16, max_length=128)
    cursor: t.Optional[str] = Field(None, description="Курсор/смещение потока после этого события")
    # payload — произвольный объект (в терминах домена)
    payload: dict[str, t.Any] = Field(default_factory=dict)
    # опциональная подпись/доказательство
    proof: dict[str, t.Any] | None = None
    # срок ожидания ACK (мс), после которого событие может быть переотправлено
    ack_deadline_ms: int = Field(DEFAULT_ACK_TIMEOUT_SECONDS * 1000, ge=1000)

class SnapshotFrame(BaseFrame):
    op: t.Literal[OpCode.SNAPSHOT]
    channel: str = Field(..., min_length=1, max_length=200)
    items: list[dict[str, t.Any]] = Field(default_factory=list)
    done: bool = False
    cursor: t.Optional[str] = None

class AckFrame(BaseFrame):
    op: t.Literal[OpCode.ACK]
    channel: str = Field(..., min_length=1, max_length=200)
    event_id: str = Field(..., min_length=16, max_length=128)

class PingFrame(BaseFrame):
    op: t.Literal[OpCode.PING]
    data: dict[str, t.Any] | None = None

class PongFrame(BaseFrame):
    op: t.Literal[OpCode.PONG]
    data: dict[str, t.Any] | None = None

class ResumeFrame(BaseFrame):
    op: t.Literal[OpCode.RESUME]
    session: str = Field(..., min_length=16, max_length=128)
    # последний подтверждённый клиентом курсор по каналам
    cursors: dict[str, str] = Field(default_factory=dict)

class ByeFrame(BaseFrame):
    op: t.Literal[OpCode.BYE]
    code: CloseCode = CloseCode.NORMAL
    reason: str = Field("bye", min_length=1, max_length=200)

Frame = t.Union[
    HelloFrame,
    AuthFrame,
    OkFrame,
    ErrorFrame,
    SubFrame,
    UnsubFrame,
    EventFrame,
    SnapshotFrame,
    AckFrame,
    PingFrame,
    PongFrame,
    ResumeFrame,
    ByeFrame,
]

# ======================================================================================
# Сериализация/десериализация (JSON / MessagePack)
# ======================================================================================

class Codec(abc := type("ABC", (), {})):  # минимальная ABC без зависимостей
    name: str
    content_type: str

    def dumps(self, obj: t.Any) -> bytes: ...
    def loads(self, data: bytes) -> dict[str, t.Any]: ...

class JsonCodec(Codec):
    name = "json"
    content_type = "application/json"

    def dumps(self, obj: t.Any) -> bytes:  # noqa: D401
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def loads(self, data: bytes) -> dict[str, t.Any]:
        return json.loads(data.decode("utf-8"))

class MsgpackCodec(Codec):
    name = "msgpack"
    content_type = "application/msgpack"

    def dumps(self, obj: t.Any) -> bytes:
        if not msgpack:
            raise RuntimeError("msgpack not available")
        return msgpack.packb(obj, use_bin_type=True)

    def loads(self, data: bytes) -> dict[str, t.Any]:
        if not msgpack:
            raise RuntimeError("msgpack not available")
        return t.cast(dict[str, t.Any], msgpack.unpackb(data, raw=False))

AVAILABLE_CODECS: dict[str, Codec] = {
    "json": JsonCodec(),
    "msgpack": MsgpackCodec() if msgpack else JsonCodec(),  # graceful fallback
}

def negotiate_codec(sec_ws_protocols: list[str] | None) -> Codec:
    """
    Выбор кодека по списку подпроtokолов WebSocket.
    Клиент должен предлагать: ["ledger-ws.v1+msgpack", "ledger-ws.v1+json", ...]
    """
    offered = sec_ws_protocols or []
    for proto in offered:
        if proto == f"{PROTOCOL_ID}+msgpack" and "msgpack" in AVAILABLE_CODECS and msgpack:
            return AVAILABLE_CODECS["msgpack"]
        if proto == f"{PROTOCOL_ID}+json":
            return AVAILABLE_CODECS["json"]
    # По умолчанию — JSON
    return AVAILABLE_CODECS["json"]

# ======================================================================================
# Валидация фреймов и ограничение размера
# ======================================================================================

class FrameValidator:
    def __init__(self, max_bytes: int = DEFAULT_MAX_FRAME_BYTES) -> None:
        self.max_bytes = max_bytes

    def check_size(self, raw: bytes) -> None:
        if len(raw) > self.max_bytes:
            raise ValueError(f"frame too large ({len(raw)} > {self.max_bytes})")

    def parse(self, codec: Codec, raw: bytes) -> Frame:
        self.check_size(raw)
        obj = codec.loads(raw)
        if not isinstance(obj, dict) or "op" not in obj:
            raise ValueError("invalid frame shape")
        op = obj.get("op")
        model_map: dict[str, t.Type[Frame]] = {
            OpCode.HELLO: HelloFrame,
            OpCode.AUTH: AuthFrame,
            OpCode.OK: OkFrame,
            OpCode.ERROR: ErrorFrame,
            OpCode.SUB: SubFrame,
            OpCode.UNSUB: UnsubFrame,
            OpCode.EVENT: EventFrame,
            OpCode.SNAPSHOT: SnapshotFrame,
            OpCode.ACK: AckFrame,
            OpCode.PING: PingFrame,
            OpCode.PONG: PongFrame,
            OpCode.RESUME: ResumeFrame,
            OpCode.BYE: ByeFrame,
        }  # type: ignore
        cls = model_map.get(OpCode(op))  # type: ignore[arg-type]
        if not cls:
            raise ValueError("unknown opcode")
        try:
            return cls.model_validate(obj)  # type: ignore[return-value]
        except ValidationError as e:  # pragma: no cover
            raise ValueError(f"frame validation failed: {e}") from e

    def dump(self, codec: Codec, frame: Frame) -> bytes:
        return codec.dumps(frame.model_dump(mode="json", by_alias=False, exclude_none=True))

# ======================================================================================
# Ограничение частоты и окна потока
# ======================================================================================

@dataclass
class TokenBucket:
    rate: float = DEFAULT_RATE_LIMIT_RPS
    burst: int = DEFAULT_RATE_LIMIT_BURST
    _tokens: float = field(default=DEFAULT_RATE_LIMIT_BURST, init=False)
    _ts: float = field(default_factory=time.monotonic, init=False)

    def allow(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        delta = now - self._ts
        self._ts = now
        self._tokens = min(self.burst, self._tokens + delta * self.rate)
        if self._tokens >= cost:
            self._tokens -= cost
            return True
        return False

@dataclass
class FlowWindow:
    max_inflight: int = DEFAULT_MAX_INFLIGHT
    _inflight: int = 0

    def acquire(self, n: int = 1) -> bool:
        if self._inflight + n > self.max_inflight:
            return False
        self._inflight += n
        return True

    def release(self, n: int = 1) -> None:
        self._inflight = max(0, self._inflight - n)

# ======================================================================================
# Хранилище идемпотентности и резюмирования
# ======================================================================================

class LruTtl:
    def __init__(self, capacity: int = 10_000, ttl_seconds: int = 3600) -> None:
        self.capacity = capacity
        self.ttl = ttl_seconds
        self._store: dict[str, float] = {}

    def add(self, key: str) -> None:
        now = time.monotonic()
        self._store[key] = now + self.ttl
        if len(self._store) > self.capacity:
            # простая эвакуация по TTL
            expired = [k for k, until in self._store.items() if until <= now]
            for k in expired:
                self._store.pop(k, None)

    def seen(self, key: str) -> bool:
        now = time.monotonic()
        until = self._store.get(key)
        return bool(until and until > now)

@dataclass
class ResumeState:
    session: str
    cursors: dict[str, str]
    updated_at: float = field(default_factory=time.monotonic)

# ======================================================================================
# HMAC подпись (для внутренних каналов / веб-хуков)
# ======================================================================================

def verify_hmac_signature(
    message: bytes,
    secret: bytes,
    signature_b64url: str,
) -> bool:
    try:
        sig = base64.urlsafe_b64decode(signature_b64url + "==")
    except Exception:
        return False
    calc = hmac.new(secret, message, hashlib.sha256).digest()
    return hmac.compare_digest(calc, sig)

# ======================================================================================
# Heartbeat менеджер (серверная сторона)
# ======================================================================================

class Heartbeat:
    def __init__(self, send: t.Callable[[Frame], t.Awaitable[None]], interval_s: int = DEFAULT_PING_INTERVAL_SECONDS) -> None:
        self._send = send
        self._interval = max(1, interval_s)
        self._task: asyncio.Task | None = None
        self._last_pong: float = time.monotonic()

    def mark_pong(self) -> None:
        self._last_pong = time.monotonic()

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with contextlib.suppress(Exception):
                await self._task

    async def _loop(self) -> None:
        while True:
            await asyncio.sleep(self._interval)
            await self._send(PingFrame(op=OpCode.PING))
            # таймаут PONG проверяется внешним кодом (хендлер соединения)

# ======================================================================================
# Серверные утилиты протокола (агностичны к конкретному веб‑фреймворку)
# ======================================================================================

class ProtocolServer:
    """
    Набор утилит для обработки протокола на сервере.
    Внешний код должен передать корутины send_bytes/recv_bytes и закрытие соединения.
    """

    def __init__(
        self,
        codec: Codec,
        max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
        max_inflight: int = DEFAULT_MAX_INFLIGHT,
        rate_limit_rps: int = DEFAULT_RATE_LIMIT_RPS,
        rate_limit_burst: int = DEFAULT_RATE_LIMIT_BURST,
        ack_timeout_s: int = DEFAULT_ACK_TIMEOUT_SECONDS,
        resume_ttl_s: int = DEFAULT_RESUME_TTL_SECONDS,
        hmac_secret_resolver: t.Callable[[str], bytes] | None = None,
    ) -> None:
        self.codec = codec
        self.validator = FrameValidator(max_bytes=max_frame_bytes)
        self.flow = FlowWindow(max_inflight=max_inflight)
        self.bucket = TokenBucket(rate=rate_limit_rps, burst=rate_limit_burst)
        self.ack_timeout_s = ack_timeout_s
        self.resume_ttl_s = resume_ttl_s
        self.seen_events = LruTtl(capacity=50_000, ttl_seconds=resume_ttl_s)
        self.sessions: dict[str, ResumeState] = {}
        self.hmac_secret_resolver = hmac_secret_resolver

    # ---- рукопожатие ----

    def hello(self) -> HelloFrame:
        return HelloFrame(
            op=OpCode.HELLO,
            server=os.getenv("APP_VERSION", "ledger-core/0.0.0"),
            session=new_id(),
            heartbeat_interval=DEFAULT_PING_INTERVAL_SECONDS * 1000,
            max_frame_bytes=self.validator.max_bytes,
            max_inflight=self.flow.max_inflight,
            features={
                "resume": True,
                "ack": True,
                "msgpack": bool(msgpack),
            },
        )

    def auth(self, frame: AuthFrame) -> OkFrame | ErrorFrame:
        if frame.scheme == "bearer":
            if not frame.token:
                return ErrorFrame(op=OpCode.ERROR, code=401, message="missing_token", ref=frame.id)
            # Вставьте реальную валидацию JWT/opaque токена здесь
            return OkFrame(op=OpCode.OK, message="auth_ok", ref=frame.id, data={"principal": "admin?"})
        if frame.scheme == "hmac":
            if not (frame.hmac_key_id and frame.hmac_signature and frame.nonce):
                return ErrorFrame(op=OpCode.ERROR, code=401, message="missing_hmac_parts", ref=frame.id)
            if not self.hmac_secret_resolver:
                return ErrorFrame(op=OpCode.ERROR, code=501, message="hmac_not_supported", ref=frame.id)
            secret = self.hmac_secret_resolver(frame.hmac_key_id)
            payload = self.codec.dumps({"nonce": frame.nonce, "ts": frame.ts})
            ok = verify_hmac_signature(payload, secret, frame.hmac_signature)
            return OkFrame(op=OpCode.OK, message="auth_ok", ref=frame.id) if ok else ErrorFrame(
                op=OpCode.ERROR, code=401, message="invalid_signature", ref=frame.id
            )
        return ErrorFrame(op=OpCode.ERROR, code=400, message="unknown_scheme", ref=frame.id)

    # ---- управление курсорами/резюмом ----

    def save_resume(self, session: str, cursors: dict[str, str]) -> None:
        self.sessions[session] = ResumeState(session=session, cursors=dict(cursors))

    def load_resume(self, session: str) -> dict[str, str] | None:
        state = self.sessions.get(session)
        if not state:
            return None
        if time.monotonic() - state.updated_at > self.resume_ttl_s:
            self.sessions.pop(session, None)
            return None
        return dict(state.cursors)

    # ---- обработка входящих ----

    def parse_frame(self, raw: bytes) -> Frame:
        return self.validator.parse(self.codec, raw)

    def encode_frame(self, frame: Frame) -> bytes:
        return self.validator.dump(self.codec, frame)

    # ---- идемпотентность/ACK ----

    def should_deliver(self, event_id: str) -> bool:
        """True если событие ещё не было подтверждено этим клиентом."""
        if self.seen_events.seen(event_id):
            return False
        self.seen_events.add(event_id)
        return True

# ======================================================================================
# Пример высокоуровневого потока серверной стороны (псевдо‑код интерфейса)
# ======================================================================================

class WsIo(t.Protocol):
    async def send_bytes(self, data: bytes, subprotocol: str | None = None) -> None: ...
    async def recv_bytes(self) -> bytes: ...
    async def close(self, code: int = CloseCode.NORMAL, reason: str = "bye") -> None: ...
    def negotiated_subprotocol(self) -> str | None: ...

async def protocol_server_loop(io: WsIo, server: ProtocolServer) -> None:
    """
    Универсальный обработчик: hello -> auth/resume -> основной цикл.
    Встраивается в FastAPI/Starlette, передавая объект io, реализующий WsIo.
    """
    # negotiation
    codec = server.codec
    hello = server.hello()
    await io.send_bytes(server.encode_frame(hello), subprotocol=f"{PROTOCOL_ID}+{codec.name}")

    # ожидание AUTH/RESUME
    raw = await io.recv_bytes()
    try:
        frame = server.parse_frame(raw)
    except Exception:
        await io.close(code=CloseCode.PROTOCOL_ERROR, reason="invalid_frame")
        return

    if isinstance(frame, ResumeFrame):
        cursors = server.load_resume(frame.session)
        if cursors is None:
            await io.send_bytes(server.encode_frame(ErrorFrame(op=OpCode.ERROR, code=404, message="unknown_session", ref=frame.id)))
            await io.close(code=CloseCode.TRY_AGAIN_LATER, reason="resume_failed")
            return
        await io.send_bytes(server.encode_frame(OkFrame(op=OpCode.OK, ref=frame.id, message="resume_ok", data={"cursors": cursors})))
    elif isinstance(frame, AuthFrame):
        res = server.auth(frame)
        await io.send_bytes(server.encode_frame(res))
        if isinstance(res, ErrorFrame):
            await io.close(code=CloseCode.POLICY_VIOLATION, reason="auth_failed")
            return
    else:
        await io.send_bytes(server.encode_frame(ErrorFrame(op=OpCode.ERROR, code=400, message="expected_auth_or_resume", ref=frame.id)))
        await io.close(code=CloseCode.PROTOCOL_ERROR, reason="bad_handshake")
        return

    # основной цикл
    bucket = server.bucket
    while True:
        raw = await io.recv_bytes()
        try:
            frm = server.parse_frame(raw)
        except Exception:
            await io.send_bytes(server.encode_frame(ErrorFrame(op=OpCode.ERROR, code=400, message="invalid_frame")))
            continue

        if not bucket.allow():
            await io.send_bytes(server.encode_frame(ErrorFrame(op=OpCode.ERROR, code=429, message="rate_limited", ref=frm.id)))
            continue

        if isinstance(frm, PingFrame):
            await io.send_bytes(server.encode_frame(PongFrame(op=OpCode.PONG, ref=frm.id)))
            continue

        if isinstance(frm, SubFrame):
            # Здесь должна быть серверная логика подписки и отправки SNAPSHOT/EVENT
            await io.send_bytes(server.encode_frame(OkFrame(op=OpCode.OK, ref=frm.id, message="subscribed")))
            # server.save_resume(hello.session, {frm.channel: cursor_after_snapshot})
            continue

        if isinstance(frm, UnsubFrame):
            await io.send_bytes(server.encode_frame(OkFrame(op=OpCode.OK, ref=frm.id, message="unsubscribed")))
            continue

        if isinstance(frm, AckFrame):
            # сервер может отметить подтверждение, снять переотправку и сохранить курсор
            await io.send_bytes(server.encode_frame(OkFrame(op=OpCode.OK, ref=frm.id, message="ack")))
            continue

        # Прочие опкоды
        await io.send_bytes(server.encode_frame(ErrorFrame(op=OpCode.ERROR, code=400, message="unsupported", ref=frm.id)))

# ======================================================================================
# Публичный API модуля
# ======================================================================================

__all__ = [
    "PROTOCOL_ID",
    "PROTOCOL_NAME",
    "PROTOCOL_VERSION",
    "OpCode",
    "CloseCode",
    "BaseFrame",
    "HelloFrame",
    "AuthFrame",
    "OkFrame",
    "ErrorFrame",
    "SubFrame",
    "UnsubFrame",
    "EventFrame",
    "SnapshotFrame",
    "AckFrame",
    "PingFrame",
    "PongFrame",
    "ResumeFrame",
    "ByeFrame",
    "Frame",
    "Codec",
    "JsonCodec",
    "MsgpackCodec",
    "negotiate_codec",
    "FrameValidator",
    "TokenBucket",
    "FlowWindow",
    "LruTtl",
    "ResumeState",
    "verify_hmac_signature",
    "ProtocolServer",
    "WsIo",
    "protocol_server_loop",
]
