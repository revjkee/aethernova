# chronowatch-core/api/ws/protocols.py
# SPDX-License-Identifier: Apache-2.0
"""
Протоколы WebSocket для Chronowatch Core.

Функциональность:
- Версионирование и negotiation сабпротоколов (v1.json / v1.msgpack)
- Сериализация JSON/MessagePack с безопасными fallback'ами
- Строгая схема сообщений (Envelope) и типы MessageType
- Идемпотентные идентификаторы (msg_id) и correlation_id
- Централизованные коды ошибок/закрытий
- Валидатор входящих сообщений
- Token-bucket rate limiter
- Утилиты кодирования/декодирования и фабрики сообщений
- Heartbeat ping/pong

Интеграция:
- Подходит для Starlette/FastAPI/Any ASGI. Никакой прямой зависимости.
"""

from __future__ import annotations

import json
import time
import uuid
import math
from dataclasses import dataclass, field, asdict
from enum import Enum, IntEnum
from typing import Any, Dict, Optional, Tuple, Protocol, runtime_checkable, List, Union

# --- Опциональные ускорители ---
try:
    import orjson as _orjson  # type: ignore
except Exception:  # pragma: no cover
    _orjson = None

try:
    import msgpack  # type: ignore
except Exception:  # pragma: no cover
    msgpack = None


__all__ = [
    "SPEC_VERSION",
    "SUPPORTED_SUBPROTOCOLS",
    "MessageType",
    "ErrorCode",
    "CloseCode",
    "Serializer",
    "JSONSerializer",
    "MsgpackSerializer",
    "select_subprotocol",
    "Envelope",
    "ValidationError",
    "encode_envelope",
    "decode_envelope",
    "make_msg",
    "make_ack",
    "make_error",
    "make_ping",
    "make_pong",
    "TokenBucket",
]


# =========================
# Версионирование/сабпротоколы
# =========================

SPEC_VERSION = "v1"

# Имена сабпротоколов, которыми обменивается клиент/сервер через WebSocket handshake
SUBPROTO_JSON = f"chronowatch.{SPEC_VERSION}.json"
SUBPROTO_MSGPACK = f"chronowatch.{SPEC_VERSION}.msgpack"
SUPPORTED_SUBPROTOCOLS: Tuple[str, ...] = (SUBPROTO_JSON, SUBPROTO_MSGPACK)


def select_subprotocol(requested: Optional[List[str]]) -> Tuple[str, "Serializer"]:
    """
    Выбор общего сабпротокола и соответствующего сериализатора.

    :param requested: список сабпротоколов клиента (в порядке предпочтений)
    :return: (выбранный_сабпротокол, сериализатор)
    :raises: RuntimeError, если пересечения нет
    """
    requested = requested or []
    for sp in requested:
        sp = (sp or "").strip().lower()
        if sp == SUBPROTO_MSGPACK and MsgpackSerializer.is_available():
            return SUBPROTO_MSGPACK, MsgpackSerializer()
        if sp == SUBPROTO_JSON:
            return SUBPROTO_JSON, JSONSerializer()
    # Если клиент ничего не запросил или не совпало — дефолт JSON
    return SUBPROTO_JSON, JSONSerializer()


# =========================
# Сериализаторы
# =========================

@runtime_checkable
class Serializer(Protocol):
    content_type: str
    name: str

    def dumps(self, obj: Dict[str, Any]) -> bytes: ...
    def loads(self, data: Union[bytes, bytearray, memoryview, str]) -> Dict[str, Any]: ...


class JSONSerializer:
    """
    Быстрый JSON (orjson, при недоступности — стандартный json).
    """
    content_type = "application/json"
    name = "json"

    def dumps(self, obj: Dict[str, Any]) -> bytes:
        if _orjson:
            return _orjson.dumps(obj, option=_orjson.OPT_SORT_KEYS | _orjson.OPT_NON_STR_KEYS)
        return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")

    def loads(self, data: Union[bytes, bytearray, memoryview, str]) -> Dict[str, Any]:
        if isinstance(data, (bytes, bytearray, memoryview)):
            raw = bytes(data)
            if _orjson:
                return _orjson.loads(raw)
            return json.loads(raw.decode("utf-8"))
        # str
        if _orjson:
            return _orjson.loads(data)  # type: ignore[arg-type]
        return json.loads(data)  # type: ignore[arg-type]


class MsgpackSerializer:
    """
    MessagePack сериализатор. Требует msgpack-python.
    """
    content_type = "application/msgpack"
    name = "msgpack"

    @staticmethod
    def is_available() -> bool:
        return msgpack is not None

    def dumps(self, obj: Dict[str, Any]) -> bytes:
        if not msgpack:
            raise RuntimeError("msgpack is not available")
        return msgpack.dumps(obj, use_bin_type=True)

    def loads(self, data: Union[bytes, bytearray, memoryview, str]) -> Dict[str, Any]:
        if not msgpack:
            raise RuntimeError("msgpack is not available")
        if isinstance(data, str):
            data = data.encode("utf-8")
        return msgpack.loads(data, raw=False)  # type: ignore[arg-type]


# =========================
# Типы сообщений/ошибок/закрытий
# =========================

class MessageType(str, Enum):
    # Служебные
    AUTH_INIT = "auth.init"
    AUTH_OK = "auth.ok"
    AUTH_ERROR = "auth.error"
    PING = "ping"
    PONG = "pong"
    ACK = "ack"
    ERROR = "error"

    # Доменные (пример: таймеры из Chronowatch)
    SUBSCRIBE_TIMERS = "timers.subscribe"
    UNSUBSCRIBE_TIMERS = "timers.unsubscribe"
    TIMER_EVENT = "timers.event"              # сервер -> клиент
    TIMER_CONTROL = "timers.control"          # клиент -> сервер (pause/resume/etc.)
    TIMER_CONTROL_RESULT = "timers.control.result"


class ErrorCode(IntEnum):
    OK = 0
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    CONFLICT = 409
    UNPROCESSABLE = 422
    TOO_MANY_REQUESTS = 429
    INTERNAL_ERROR = 500
    NOT_IMPLEMENTED = 501
    SERVICE_UNAVAILABLE = 503


class CloseCode(IntEnum):
    # RFC6455 базовые
    NORMAL = 1000
    GOING_AWAY = 1001
    PROTOCOL_ERROR = 1002
    UNSUPPORTED_DATA = 1003
    NO_STATUS = 1005
    ABNORMAL = 1006
    INVALID_FRAME = 1007
    POLICY_VIOLATION = 1008
    MESSAGE_TOO_BIG = 1009
    MANDATORY_EXT = 1010
    INTERNAL_ERROR = 1011
    TLS_HANDSHAKE = 1015

    # Прикладные (расширение)
    UNAUTHORIZED = 4401
    FORBIDDEN = 4403
    RATE_LIMITED = 4429


# =========================
# Envelope и валидация
# =========================

@dataclass
class Envelope:
    """
    Универсальный контейнер WS-сообщения.
    """
    spec_version: str
    type: MessageType
    msg_id: str
    ts_ms: int
    payload: Dict[str, Any] = field(default_factory=dict)
    correlation_id: Optional[str] = None
    requires_ack: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "spec_version": self.spec_version,
            "type": self.type.value,
            "msg_id": self.msg_id,
            "ts_ms": self.ts_ms,
            "payload": self.payload or {},
            "correlation_id": self.correlation_id,
            "requires_ack": self.requires_ack,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Envelope":
        try:
            t = d.get("type")
            mt = MessageType(t)  # проверит валидность
        except Exception:
            raise ValidationError(f"Unknown or missing message type: {t!r}")

        msg_id = d.get("msg_id")
        if not isinstance(msg_id, str) or not msg_id:
            raise ValidationError("msg_id must be a non-empty string")

        ts_ms = d.get("ts_ms")
        if not isinstance(ts_ms, int) or ts_ms <= 0:
            raise ValidationError("ts_ms must be positive integer (milliseconds)")

        spec = d.get("spec_version")
        if spec != SPEC_VERSION:
            raise ValidationError(f"Unsupported spec_version: {spec!r}, expected {SPEC_VERSION!r}")

        payload = d.get("payload") or {}
        if not isinstance(payload, dict):
            raise ValidationError("payload must be an object")

        corr = d.get("correlation_id")
        if corr is not None and not isinstance(corr, str):
            raise ValidationError("correlation_id must be a string or null")

        req_ack = bool(d.get("requires_ack", False))

        return Envelope(
            spec_version=spec,
            type=mt,
            msg_id=msg_id,
            ts_ms=ts_ms,
            payload=payload,
            correlation_id=corr,
            requires_ack=req_ack,
        )


class ValidationError(ValueError):
    pass


# =========================
# Кодирование/декодирование и фабрики
# =========================

def _now_ms() -> int:
    return int(time.time() * 1000)


def _uuid_str() -> str:
    return uuid.uuid4().hex


def encode_envelope(env: Envelope, serializer: Serializer) -> bytes:
    """
    Кодирует Envelope в bytes выбранным сериализатором.
    """
    return serializer.dumps(env.to_dict())


def decode_envelope(data: Union[bytes, bytearray, memoryview, str], serializer: Serializer) -> Envelope:
    """
    Декодирует bytes/str в Envelope и валидирует поля.
    """
    obj = serializer.loads(data)
    return Envelope.from_dict(obj)


def make_msg(
    mtype: MessageType,
    payload: Optional[Dict[str, Any]] = None,
    *,
    correlation_id: Optional[str] = None,
    requires_ack: bool = False,
) -> Envelope:
    """
    Фабрика обычного сообщения.
    """
    return Envelope(
        spec_version=SPEC_VERSION,
        type=mtype,
        msg_id=_uuid_str(),
        ts_ms=_now_ms(),
        payload=payload or {},
        correlation_id=correlation_id,
        requires_ack=requires_ack,
    )


def make_ack(target_msg: Envelope, ok: bool = True, extra: Optional[Dict[str, Any]] = None) -> Envelope:
    """
    Фабрика ACK для входящего сообщения.
    """
    payload: Dict[str, Any] = {"ok": ok}
    if extra:
        payload.update(extra)
    return Envelope(
        spec_version=SPEC_VERSION,
        type=MessageType.ACK,
        msg_id=_uuid_str(),
        ts_ms=_now_ms(),
        payload=payload,
        correlation_id=target_msg.msg_id,
        requires_ack=False,
    )


def make_error(code: ErrorCode, message: str, *, correlation_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> Envelope:
    """
    Фабрика ERROR-сообщения.
    """
    payload: Dict[str, Any] = {"code": int(code), "message": message}
    if details:
        payload["details"] = details
    return Envelope(
        spec_version=SPEC_VERSION,
        type=MessageType.ERROR,
        msg_id=_uuid_str(),
        ts_ms=_now_ms(),
        payload=payload,
        correlation_id=correlation_id,
        requires_ack=False,
    )


def make_ping(nonce: Optional[str] = None) -> Envelope:
    return make_msg(MessageType.PING, {"nonce": nonce or _uuid_str()})


def make_pong(ping_envelope: Envelope) -> Envelope:
    return make_msg(MessageType.PONG, {"nonce": ping_envelope.payload.get("nonce")}, correlation_id=ping_envelope.msg_id)


# =========================
# Rate limiting (token bucket)
# =========================

class TokenBucket:
    """
    Простой token-bucket для ограничения частоты исходящих сообщений на соединение.
    Потокобезопасность для asyncio предполагается на уровне вызова (один writer task).
    """

    __slots__ = ("_capacity", "_tokens", "_refill_rate", "_last")

    def __init__(self, capacity: int, refill_per_sec: float):
        """
        :param capacity: максимальное число токенов в баке
        :param refill_per_sec: скорость пополнения токенов в секунду (может быть дробной)
        """
        if capacity <= 0:
            raise ValueError("capacity must be > 0")
        if refill_per_sec <= 0:
            raise ValueError("refill_per_sec must be > 0")
        self._capacity = capacity
        self._tokens = float(capacity)
        self._refill_rate = float(refill_per_sec)
        self._last = time.perf_counter()

    def _refill(self) -> None:
        now = time.perf_counter()
        delta = max(0.0, now - self._last)
        if delta > 0:
            self._tokens = min(self._capacity, self._tokens + delta * self._refill_rate)
            self._last = now

    def try_consume(self, n: int = 1) -> bool:
        """
        Пытается списать n токенов. Возвращает True при успехе, False при нехватке.
        """
        if n <= 0:
            return True
        self._refill()
        if self._tokens >= n:
            self._tokens -= n
            return True
        return False

    def time_to_avail(self, n: int = 1) -> float:
        """
        Оценивает (в секундах) сколько ждать до появления n токенов.
        """
        self._refill()
        missing = max(0.0, n - self._tokens)
        return 0.0 if missing <= 0 else (missing / self._refill_rate)


# =========================
# Примеры договорённостей payload (минимум для совместимости)
# =========================
# Эти структуры не навязывают конкретную бизнес-логику, но фиксируют обязательные поля
# для ключевых типов сообщений домена таймеров.

MANDATORY_FIELDS: Dict[MessageType, Tuple[str, ...]] = {
    MessageType.AUTH_INIT: ("token",),
    MessageType.AUTH_OK: ("subject",),
    MessageType.AUTH_ERROR: ("code", "message"),
    MessageType.SUBSCRIBE_TIMERS: ("filters",),           # пример: {"filters":{"timer_ids":["..."],"labels":{"env":"prod"}}}
    MessageType.UNSUBSCRIBE_TIMERS: ("subscription_id",),
    MessageType.TIMER_EVENT: ("event", "timer_id", "event_type", "ts_ms"),
    MessageType.TIMER_CONTROL: ("op", "timer_id"),        # пример op: "pause"|"resume"|"cancel"|"reset"
    MessageType.TIMER_CONTROL_RESULT: ("ok", "op", "timer_id"),
    MessageType.ERROR: ("code", "message"),
    MessageType.PING: ("nonce",),
    MessageType.PONG: ("nonce",),
    MessageType.ACK: ("ok",),
}


def validate_payload_shape(env: Envelope) -> None:
    """
    Дополнительная поверхностная проверка структуры payload согласно MANDATORY_FIELDS.
    Не заменяет доменную валидацию на сервере.
    """
    required = MANDATORY_FIELDS.get(env.type)
    if not required:
        return
    missing = [k for k in required if k not in env.payload]
    if missing:
        raise ValidationError(f"Payload for type={env.type.value} missing fields: {missing}")


# =========================
# Utility: safe close reason
# =========================

def close_reason_for_error(code: ErrorCode) -> Tuple[CloseCode, str]:
    """
    Проецирует ErrorCode на WebSocket CloseCode и reason.
    """
    mapping = {
        ErrorCode.UNAUTHORIZED: (CloseCode.UNAUTHORIZED, "unauthorized"),
        ErrorCode.FORBIDDEN: (CloseCode.FORBIDDEN, "forbidden"),
        ErrorCode.TOO_MANY_REQUESTS: (CloseCode.RATE_LIMITED, "rate limited"),
        ErrorCode.BAD_REQUEST: (CloseCode.PROTOCOL_ERROR, "bad request"),
        ErrorCode.UNPROCESSABLE: (CloseCode.POLICY_VIOLATION, "unprocessable"),
        ErrorCode.MESSAGE_TOO_BIG if hasattr(ErrorCode, "MESSAGE_TOO_BIG") else None: (CloseCode.MESSAGE_TOO_BIG, "too big"),  # safeguard
    }
    default = (CloseCode.INTERNAL_ERROR, "internal error")
    return mapping.get(code, default)  # type: ignore[arg-type]


# =========================
# Примеры интеграции (подсказки в коде, без жестких зависимостей)
# =========================

def negotiated_serializer_header(subprotocol: str) -> str:
    """
    Возвращает рекомендуемый Content-Type/псевдозаголовок для интеграции (например, в логах).
    """
    return "application/msgpack" if subprotocol == SUBPROTO_MSGPACK else "application/json"


# Конец файла
