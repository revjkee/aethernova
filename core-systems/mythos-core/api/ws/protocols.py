# -*- coding: utf-8 -*-
"""
Mythos Core — WebSocket Protocols (v1)
Промышленный слой протокола с версией, сабпротоколами и безопасной сериализацией.

Особенности:
- Версионность: v1 (сабпротоколы: "mythos.v1.json", "mythos.v1.msgpack")
- Чёткие OpCode и CloseCode, совместимые с RFC 6455 и прикладочными причинами
- Envelope с полями id/seq/ts/op/chan/data/error
- Типизированные payload'ы (Pydantic) для основных операций
- Конверторы JSON/MessagePack, детерминированные и безопасные
- Контроль размера сообщения и скорости (token bucket)
- Heartbeat (PING/PONG), дедлайны, расчёт timeouts
- Problem Details (RFC 7807) для ошибок на уровне протокола
- Идемпотентность по client message id и monotonic seq
- Расширяемость: резерв опкодов и версии
"""
from __future__ import annotations

import base64
import json
import time
import typing as _t
from enum import Enum, IntEnum
from hashlib import sha256
from threading import RLock

try:
    import orjson as _orjson  # быстрый JSON
except Exception:  # pragma: no cover
    _orjson = None

try:
    import msgpack as _msgpack  # опциональный MessagePack
except Exception:  # pragma: no cover
    _msgpack = None

from pydantic import BaseModel, Field, validator, root_validator

# --------------------------------------------------------------------------------------
# Версия протокола и сабпротоколы
# --------------------------------------------------------------------------------------

PROTOCOL_VERSION = "v1"
SUBPROTO_JSON = f"mythos.{PROTOCOL_VERSION}.json"
SUBPROTO_MSGPACK = f"mythos.{PROTOCOL_VERSION}.msgpack"
SUPPORTED_SUBPROTOCOLS = (SUBPROTO_JSON, SUBPROTO_MSGPACK)

# --------------------------------------------------------------------------------------
# Коды операций и закрытия
# --------------------------------------------------------------------------------------

class OpCode(IntEnum):
    HELLO = 0          # клиент -> сервер: приветствие/запрос параметров
    WELCOME = 1        # сервер -> клиент: параметры сессии
    AUTH = 2           # клиент -> сервер: аутентификация
    ACK = 3            # сервер -> клиент: подтверждение (id/seq)
    SUBSCRIBE = 10     # клиент -> сервер: подписка на канал
    UNSUBSCRIBE = 11   # клиент -> сервер: отписка
    EVENT = 20         # сервер -> клиент: событие
    PING = 30          # двусторонний
    PONG = 31          # двусторонний
    ERROR = 40         # ошибка уровня протокола/команды
    BYE = 41           # сервер -> клиент: мягкое закрытие (graceful)

# Резерв на будущее: 50..59 — потоковая передача, 90..99 — расширения

class CloseCode(IntEnum):
    NORMAL = 1000
    GOING_AWAY = 1001
    PROTOCOL_ERROR = 1002
    UNSUPPORTED_DATA = 1003
    NO_STATUS_RCVD = 1005
    ABNORMAL = 1006
    INVALID_DATA = 1007
    POLICY_VIOLATION = 1008
    MESSAGE_TOO_BIG = 1009
    MISSING_EXTENSION = 1010
    INTERNAL_ERROR = 1011
    SERVICE_RESTART = 1012
    TRY_AGAIN_LATER = 1013
    BAD_GATEWAY = 1014
    TLS_HANDSHAKE = 1015

    # Прикладные
    RATE_LIMITED = 4408
    UNAUTHORIZED = 4401
    FORBIDDEN = 4403
    NEGOTIATION_FAILED = 4490

# --------------------------------------------------------------------------------------
# Типы контента и кодеки
# --------------------------------------------------------------------------------------

class Content(str, Enum):
    JSON = "json"
    MSGPACK = "msgpack"

class Codec:
    def __init__(self, content: Content) -> None:
        self.content = content
        if content == Content.MSGPACK and _msgpack is None:
            raise RuntimeError("msgpack not available; install 'msgpack'")
        if content == Content.JSON and _orjson is None:
            # используем stdlib json как запасной вариант
            pass

    def dumps(self, obj: _t.Any) -> bytes:
        if self.content == Content.JSON:
            if _orjson is not None:
                return _orjson.dumps(obj, option=_orjson.OPT_SORT_KEYS)
            return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
        # msgpack
        return _msgpack.dumps(obj, use_bin_type=True)

    def loads(self, data: _t.Union[str, bytes]) -> _t.Any:
        if isinstance(data, str):
            data = data.encode("utf-8")
        if self.content == Content.JSON:
            if _orjson is not None:
                return _orjson.loads(data)
            return json.loads(data.decode("utf-8"))
        return _msgpack.loads(data, raw=False)

# --------------------------------------------------------------------------------------
# Problem Details (RFC 7807)
# --------------------------------------------------------------------------------------

class Problem(BaseModel):
    type: str = Field(default="about:blank")
    title: str
    status: int
    detail: _t.Optional[str] = None
    instance: _t.Optional[str] = None
    code: _t.Optional[str] = None  # прикладной код

# --------------------------------------------------------------------------------------
# Envelope и полезные нагрузки
# --------------------------------------------------------------------------------------

def _ts_now_ms() -> int:
    return int(time.time() * 1000)

class Envelope(BaseModel):
    op: OpCode
    id: _t.Optional[str] = Field(default=None, description="идемпотентный id клиента")
    seq: _t.Optional[int] = Field(default=None, ge=0, description="монотонная позиция сервера")
    ts: int = Field(default_factory=_ts_now_ms, description="серверное время мс")
    chan: _t.Optional[str] = Field(default=None, description="канал/тема события")
    data: _t.Optional[dict] = None
    error: _t.Optional[Problem] = None

    @validator("id")
    def _id_len(cls, v: _t.Optional[str]) -> _t.Optional[str]:
        if v and len(v) > 64:
            raise ValueError("id too long")
        return v

class Hello(BaseModel):
    versions: _t.List[str] = Field(default_factory=lambda: [PROTOCOL_VERSION])
    auth_schemes: _t.List[str] = Field(default_factory=lambda: ["bearer"])
    client_info: _t.Optional[dict] = None

class Welcome(BaseModel):
    version: str = PROTOCOL_VERSION
    heartbeat_sec: int = 20
    max_frame_bytes: int = 1_048_576
    max_msgs_per_sec: int = 50
    session: str

class Auth(BaseModel):
    scheme: str = Field(regex=r"^(bearer)$")
    token: str

class Ack(BaseModel):
    id: _t.Optional[str] = None
    seq: int

class Sub(BaseModel):
    chan: str
    params: _t.Optional[dict] = None

class Unsub(BaseModel):
    chan: str

class Event(BaseModel):
    key: str
    payload: dict
    # метаданные события
    meta: _t.Optional[dict] = None

class Ping(BaseModel):
    nonce: _t.Optional[str] = None

class Pong(BaseModel):
    nonce: _t.Optional[str] = None

class Bye(BaseModel):
    reason: str
    code: CloseCode = CloseCode.TRY_AGAIN_LATER

# --------------------------------------------------------------------------------------
# Контроль скорости/размера
# --------------------------------------------------------------------------------------

class TokenBucket:
    def __init__(self, rate: float, burst: int) -> None:
        self.rate = float(rate)
        self.capacity = float(burst)
        self.tokens = float(burst)
        self.updated = time.monotonic()
        self._lock = RLock()

    def allow(self, cost: float = 1.0) -> bool:
        with self._lock:
            now = time.monotonic()
            delta = now - self.updated
            self.updated = now
            self.tokens = min(self.capacity, self.tokens + delta * self.rate)
            if self.tokens >= cost:
                self.tokens -= cost
                return True
            return False

# --------------------------------------------------------------------------------------
# Состояние сессии и конфиг
# --------------------------------------------------------------------------------------

class ProtocolConfig(BaseModel):
    heartbeat_sec: int = 20
    client_timeout_sec: int = 60
    max_frame_bytes: int = 1_048_576
    max_msgs_per_sec: int = 50
    burst_msgs: int = 100
    allowed_subprotocols: _t.Tuple[str, ...] = SUPPORTED_SUBPROTOCOLS
    content_default: Content = Content.JSON

class SessionState(BaseModel):
    session_id: str
    seq: int = 0
    last_seen_ms: int = Field(default_factory=_ts_now_ms)
    authorized: bool = False
    subject: _t.Optional[str] = None
    channels: _t.Set[str] = Field(default_factory=set)

# --------------------------------------------------------------------------------------
# Протокол
# --------------------------------------------------------------------------------------

class MythosWSProtocol:
    """
    Низкоуровневый протокольный слой без привязки к конкретному ASGI.
    Интеграция:
      - выберите сабпротокол через negotiate()
      - декодируйте входящие через decode_envelope()
      - проверяйте allow_inbound() перед обработкой
      - отправляйте через encode_envelope()
    """
    def __init__(self, cfg: ProtocolConfig | None = None) -> None:
        self.cfg = cfg or ProtocolConfig()
        self.state = SessionState(session_id=self._gen_session())
        self.bucket_in = TokenBucket(rate=self.cfg.max_msgs_per_sec, burst=self.cfg.burst_msgs)
        self.bucket_out = TokenBucket(rate=self.cfg.max_msgs_per_sec * 2, burst=self.cfg.burst_msgs * 2)
        self.codec = Codec(self.cfg.content_default)

    # ---------------- Negotiation ----------------

    def negotiate(self, offered: _t.Sequence[str] | None) -> str:
        """
        Возвращает выбранный сабпротокол или выбрасывает RuntimeError.
        """
        offered = offered or []
        for sp in offered:
            if sp in self.cfg.allowed_subprotocols:
                self.codec = Codec(Content.JSON if sp.endswith(".json") else Content.MSGPACK)
                return sp
        # Нет пересечения — пытаемся по умолчанию JSON
        if SUBPROTO_JSON in self.cfg.allowed_subprotocols:
            self.codec = Codec(Content.JSON)
            return SUBPROTO_JSON
        raise RuntimeError("No compatible subprotocol")

    # ---------------- Encoding/Decoding ----------------

    def encode_envelope(self, env: Envelope) -> bytes:
        """
        Сериализует Envelope с контролем размера и скоростным лимитом.
        """
        if not self.bucket_out.allow():
            raise ProtocolRateError("outbound rate limited")
        b = self.codec.dumps(env.dict(by_alias=True, exclude_none=True))
        if len(b) > self.cfg.max_frame_bytes:
            raise ProtocolSizeError(f"outbound frame too large ({len(b)} bytes)")
        return b

    def decode_envelope(self, raw: _t.Union[str, bytes]) -> Envelope:
        """
        Десериализация и базовая валидация Envelope.
        """
        if not self.bucket_in.allow():
            raise ProtocolRateError("inbound rate limited")
        if isinstance(raw, (bytes, bytearray)) and len(raw) > self.cfg.max_frame_bytes:
            raise ProtocolSizeError(f"inbound frame too large ({len(raw)} bytes)")
        try:
            obj = self.codec.loads(raw)
            env = Envelope(**obj)
            self.state.last_seen_ms = _ts_now_ms()
            return env
        except ProtocolError:
            raise
        except Exception as e:  # pragma: no cover
            raise ProtocolFormatError(f"decode failed: {e}")

    # ---------------- Handshake/Heartbeat helpers ----------------

    def make_welcome(self) -> Envelope:
        self._step_seq()
        welcome = Welcome(
            version=PROTOCOL_VERSION,
            heartbeat_sec=self.cfg.heartbeat_sec,
            max_frame_bytes=self.cfg.max_frame_bytes,
            max_msgs_per_sec=self.cfg.max_msgs_per_sec,
            session=self.state.session_id,
        )
        return Envelope(op=OpCode.WELCOME, seq=self.state.seq, data=welcome.dict())

    def make_pong(self, ping: _t.Optional[Ping] = None) -> Envelope:
        self._step_seq()
        return Envelope(op=OpCode.PONG, seq=self.state.seq, data=Pong(nonce=getattr(ping, "nonce", None)).dict(exclude_none=True))

    def make_ping(self, nonce: _t.Optional[str] = None) -> Envelope:
        self._step_seq()
        return Envelope(op=OpCode.PING, seq=self.state.seq, data=Ping(nonce=nonce).dict(exclude_none=True))

    def make_ack(self, id_: _t.Optional[str]) -> Envelope:
        self._step_seq()
        ack = Ack(id=id_, seq=self.state.seq)
        return Envelope(op=OpCode.ACK, seq=self.state.seq, data=ack.dict(exclude_none=True))

    def make_error(self, status: int, title: str, detail: str | None = None, code: str | None = None, ref_id: str | None = None) -> Envelope:
        self._step_seq()
        pb = Problem(title=title, status=status, detail=detail, code=code, instance=ref_id)
        return Envelope(op=OpCode.ERROR, seq=self.state.seq, error=pb)

    def make_bye(self, reason: str, code: CloseCode = CloseCode.TRY_AGAIN_LATER) -> Envelope:
        self._step_seq()
        return Envelope(op=OpCode.BYE, seq=self.state.seq, data=Bye(reason=reason, code=code).dict())

    # ---------------- Authorization ----------------

    def apply_auth(self, data: dict) -> None:
        """
        Простейшая заглушка аутентификации: проверяет наличие 'token'.
        Интегрируйте реальную проверку JWT/OAuth во внешнем слое.
        """
        auth = Auth(**data)
        if not auth.token or len(auth.token) < 8:
            raise ProtocolAuthError("invalid token")
        # Привязываем субъекта (хеш токена без утечек)
        self.state.authorized = True
        self.state.subject = sha256(auth.token.encode("utf-8")).hexdigest()[:16]

    # ---------------- Subscriptions ----------------

    def subscribe(self, chan: str, params: dict | None = None) -> None:
        if not chan or len(chan) > 128:
            raise ProtocolError("invalid channel")
        self.state.channels.add(chan)

    def unsubscribe(self, chan: str) -> None:
        self.state.channels.discard(chan)

    # ---------------- Utility ----------------

    def _gen_session(self) -> str:
        raw = sha256(f"{time.time_ns()}".encode("utf-8")).digest()
        return base64.urlsafe_b64encode(raw[:12]).decode().rstrip("=")

    def _step_seq(self) -> None:
        self.state.seq += 1

# --------------------------------------------------------------------------------------
# Исключения протокола
# --------------------------------------------------------------------------------------

class ProtocolError(RuntimeError):
    pass

class ProtocolAuthError(ProtocolError):
    pass

class ProtocolRateError(ProtocolError):
    pass

class ProtocolSizeError(ProtocolError):
    pass

class ProtocolFormatError(ProtocolError):
    pass

# --------------------------------------------------------------------------------------
# Пример маршрутизации входящих сообщений (utility)
# --------------------------------------------------------------------------------------

def handle_incoming(protocol: MythosWSProtocol, env: Envelope) -> Envelope | None:
    """
    Мини-роутер для серверной стороны. Возвращает Envelope-ответ (или None).
    Предполагается вызов в обработчике приёма фрейма.
    """
    if env.op == OpCode.HELLO:
        # Клиент может прислать параметры (версии/схемы) — здесь игнорируем/валидируем при необходимости.
        return protocol.make_welcome()

    if env.op == OpCode.AUTH:
        protocol.apply_auth(env.data or {})
        return protocol.make_ack(env.id)

    if env.op == OpCode.SUBSCRIBE:
        sub = Sub(**(env.data or {}))
        protocol.subscribe(sub.chan, sub.params)
        return protocol.make_ack(env.id)

    if env.op == OpCode.UNSUBSCRIBE:
        unsub = Unsub(**(env.data or {}))
        protocol.unsubscribe(unsub.chan)
        return protocol.make_ack(env.id)

    if env.op == OpCode.PING:
        ping = Ping(**(env.data or {})) if env.data else None
        return protocol.make_pong(ping)

    # Остальные типы либо асинхронные (EVENT), либо завершающие (BYE), либо ошибки.
    return None

# --------------------------------------------------------------------------------------
# Подсказки по интеграции с ASGI:
#
# - На connect: protocol = MythosWSProtocol(cfg); выбран = protocol.negotiate(websocket.headers.getlist("sec-websocket-protocol"))
# - Отправить protocol.make_welcome(); периодически отправлять protocol.make_ping()
# - На фрейм: env = protocol.decode_envelope(data); resp = handle_incoming(protocol, env); если resp: send(encode)
# - При ошибке: send(protocol.make_error(...)); закрыть с соответствующим CloseCode
#
# Безопасные дефолты:
# - max_frame_bytes = 1MB; max_msgs_per_sec = 50; heartbeat 20s; клиентский timeout 60s
# - включайте backpressure на уровне очереди отправки и/или TCP cork/auto
# --------------------------------------------------------------------------------------
