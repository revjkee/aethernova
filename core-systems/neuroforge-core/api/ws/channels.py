# neuroforge-core/api/ws/channels.py
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, AsyncIterator, Dict, Iterable, List, Optional, Set, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field, ValidationError, root_validator

# Опциональные зависимости (необязательны для работы)
try:
    from opentelemetry import trace  # type: ignore
    _tracer = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _tracer = None

try:
    from prometheus_client import Counter, Histogram, Gauge  # type: ignore
    _METRICS = True
    WS_CONNECTIONS = Gauge("nf_ws_connections", "Active WS connections")
    WS_MESSAGES_RX = Counter("nf_ws_messages_rx_total", "WS messages received", ["type"])
    WS_MESSAGES_TX = Counter("nf_ws_messages_tx_total", "WS messages sent", ["type"])
    WS_LATENCY = Histogram("nf_ws_publish_latency_seconds", "Latency from publish to send")
except Exception:  # pragma: no cover
    _METRICS = False

logger = logging.getLogger("neuroforge.ws.channels")
logger.setLevel(logging.INFO)

router = APIRouter(prefix="/ws", tags=["ws"])

# ----------------------------
# Конфигурация безопасных лимитов
# ----------------------------
MAX_MSG_BYTES = 512 * 1024
MAX_SUBSCRIPTIONS_PER_CONN = 256
SEND_QUEUE_MAX = 1000
PING_INTERVAL = 20.0
PING_TIMEOUT = 15.0
IDLE_TIMEOUT = 30 * 60.0
DEFAULT_RATE_RPS = 50.0
DEFAULT_RATE_BURST = 200

CHANNEL_RE = re.compile(r"^[a-zA-Z0-9][\w:./-]{0,127}$")  # безопасные имена каналов


# ----------------------------
# Схемы сообщений
# ----------------------------

class ClientMsgType(str, Enum):
    SUBSCRIBE = "subscribe"
    UNSUBSCRIBE = "unsubscribe"
    PUBLISH = "publish"
    PING = "ping"
    PONG = "pong"
    LIST = "list"
    PRESENCE = "presence"


class ServerMsgType(str, Enum):
    WELCOME = "welcome"
    ACK = "ack"
    ERROR = "error"
    EVENT = "event"
    PONG = "pong"
    INFO = "info"
    PRESENCE = "presence"


class ClientMessage(BaseModel):
    type: ClientMsgType
    channel: Optional[str] = None
    message_id: Optional[str] = Field(None, description="Клиентский коррелятор")
    data: Optional[Any] = None

    @root_validator
    def _validate_semantics(cls, values):
        t: ClientMsgType = values.get("type")
        ch = values.get("channel")
        if t in (ClientMsgType.SUBSCRIBE, ClientMsgType.UNSUBSCRIBE, ClientMsgType.PUBLISH, ClientMsgType.PRESENCE):
            if not ch:
                raise ValueError("channel is required")
        return values


class ServerMessage(BaseModel):
    type: ServerMsgType
    channel: Optional[str] = None
    message_id: Optional[str] = None
    data: Optional[Any] = None
    ts: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    # latency полагается на наличие publish_ts в event'ах
    latency_ms: Optional[int] = None


# ----------------------------
# Аутентификация и идентичность
# ----------------------------

@dataclass(frozen=True)
class Identity:
    sub: str
    tenant: str = "public"
    roles: Tuple[str, ...] = field(default_factory=tuple)


async def default_authenticator(token: Optional[str]) -> Identity:
    """
    Простейшая заглушка. В проде замените через app.state.ws_authenticator.
    Ожидает JWT или opaque token; здесь только формируется Identity.
    """
    sub = token or "anon"
    if sub.startswith("Bearer "):
        sub = sub[7:]
    # В реальности — верификация подписи JWT и извлечение полей.
    return Identity(sub=sub[:64], tenant="public", roles=("user",))


async def get_identity(
    authorization: Optional[str] = Header(None, alias="Authorization"),
    sec_ws_protocol: Optional[str] = Header(None, alias="Sec-WebSocket-Protocol"),
    x_token: Optional[str] = Header(None, alias="X-Auth-Token"),
) -> Identity:
    # Источник токена: Authorization > Sec-WebSocket-Protocol > X-Auth-Token
    token = authorization or sec_ws_protocol or x_token
    # Возможна DI: router.app.state.ws_authenticator
    auth_func = getattr(router, "ws_authenticator", None)
    if callable(auth_func):
        return await auth_func(token)
    return await default_authenticator(token)


# ----------------------------
# Токен-бакет для anti-flood
# ----------------------------

class TokenBucket:
    def __init__(self, rate_per_sec: float, capacity: int):
        self.rate = float(rate_per_sec)
        self.capacity = int(capacity)
        self.tokens = float(capacity)
        self.updated = time.monotonic()

    def allow(self, cost: int = 1) -> bool:
        now = time.monotonic()
        elapsed = now - self.updated
        self.updated = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


# ----------------------------
# Бэкенд Pub/Sub (плагин)
# ----------------------------

class PubSubBackend:
    async def publish(self, channel: str, payload: Dict[str, Any]) -> None:
        raise NotImplementedError

    def subscribe_iter(self, channel: str) -> AsyncIterator[Dict[str, Any]]:
        raise NotImplementedError

    async def close(self) -> None:
        pass


class InMemoryPubSub(PubSubBackend):
    def __init__(self) -> None:
        self._ch_queues: Dict[str, Set[asyncio.Queue]] = {}
        self._lock = asyncio.Lock()

    async def publish(self, channel: str, payload: Dict[str, Any]) -> None:
        async with self._lock:
            qs = list(self._ch_queues.get(channel, set()))
        for q in qs:
            # Не блокируем: если очередь переполнена, пробуем non-block
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                # Backpressure: молча дропаем для конкретного подписчика
                pass

    async def _ensure(self, channel: str) -> asyncio.Queue:
        async with self._lock:
            q: asyncio.Queue = asyncio.Queue(maxsize=SEND_QUEUE_MAX)
            self._ch_queues.setdefault(channel, set()).add(q)
            return q

    async def _remove(self, channel: str, q: asyncio.Queue) -> None:
        async with self._lock:
            if channel in self._ch_queues:
                self._ch_queues[channel].discard(q)
                if not self._ch_queues[channel]:
                    del self._ch_queues[channel]

    async def _iter(self, channel: str) -> AsyncIterator[Dict[str, Any]]:
        q = await self._ensure(channel)
        try:
            while True:
                payload = await q.get()
                yield payload
        finally:
            await self._remove(channel, q)

    def subscribe_iter(self, channel: str) -> AsyncIterator[Dict[str, Any]]:
        return self._iter(channel)


# ----------------------------
# Контекст соединения и менеджер
# ----------------------------

@dataclass
class Connection:
    ws: WebSocket
    id: str
    identity: Identity
    started_at: float = field(default_factory=lambda: time.time())
    last_seen: float = field(default_factory=lambda: time.time())
    subscriptions: Set[str] = field(default_factory=set)
    send_q: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=SEND_QUEUE_MAX))
    rate: TokenBucket = field(default_factory=lambda: TokenBucket(DEFAULT_RATE_RPS, DEFAULT_RATE_BURST))
    last_ping: float = 0.0
    last_pong: float = 0.0

    def touch(self) -> None:
        self.last_seen = time.time()


class ChannelManager:
    def __init__(self, backend: Optional[PubSubBackend] = None):
        self.backend: PubSubBackend = backend or InMemoryPubSub()
        self.conns: Dict[str, Connection] = {}
        self.channels: Dict[str, Set[str]] = {}
        self._lock = asyncio.Lock()

    async def register(self, conn: Connection) -> None:
        async with self._lock:
            self.conns[conn.id] = conn
        if _METRICS:
            WS_CONNECTIONS.inc()

    async def unregister(self, conn_id: str) -> None:
        async with self._lock:
            conn = self.conns.pop(conn_id, None)
            if conn:
                for ch in list(conn.subscriptions):
                    await self.unsubscribe(conn, ch)
        if _METRICS:
            WS_CONNECTIONS.dec()

    async def subscribe(self, conn: Connection, channel: str) -> None:
        if len(conn.subscriptions) >= MAX_SUBSCRIPTIONS_PER_CONN:
            raise HTTPException(status_code=400, detail="too many subscriptions")
        if not CHANNEL_RE.match(channel):
            raise HTTPException(status_code=400, detail="invalid channel name")
        if not self._can_subscribe(conn.identity, channel):
            raise HTTPException(status_code=403, detail="forbidden for channel")

        async with self._lock:
            self.channels.setdefault(channel, set()).add(conn.id)
            conn.subscriptions.add(channel)

        # Запускаем фонового подписчика Pub/Sub для передачи сообщений в send_q
        asyncio.create_task(self._fan_in(conn, channel))

    async def _fan_in(self, conn: Connection, channel: str) -> None:
        async for payload in self.backend.subscribe_iter(channel):
            # Добавляем задержку для метрик
            publish_ts = payload.get("publish_ts")
            latency = None
            if isinstance(publish_ts, (int, float)):
                latency = max(0, time.time() - publish_ts)
            msg = ServerMessage(
                type=ServerMsgType.EVENT,
                channel=channel,
                data=payload.get("data"),
                latency_ms=int(latency * 1000) if latency is not None else None,
            )
            try:
                conn.send_q.put_nowait(msg)
                if _METRICS:
                    WS_MESSAGES_TX.labels("event").inc()
                    if latency is not None:
                        WS_LATENCY.observe(latency)
            except asyncio.QueueFull:
                # Если у конкретного клиента переполнено — дропаем событие
                pass
            # Выход, если отписался
            if channel not in conn.subscriptions:
                break

    async def unsubscribe(self, conn: Connection, channel: str) -> None:
        async with self._lock:
            if channel in self.channels:
                self.channels[channel].discard(conn.id)
                if not self.channels[channel]:
                    del self.channels[channel]
            conn.subscriptions.discard(channel)

    async def publish(self, channel: str, data: Any) -> None:
        await self.backend.publish(channel, {"data": data, "publish_ts": time.time()})

    def _can_subscribe(self, identity: Identity, channel: str) -> bool:
        # Политика доступа: здесь можно реализовать ACL/tenant-изоляцию
        # По умолчанию разрешаем все валидные каналы
        return True


manager = ChannelManager()


# ----------------------------
# Утилиты
# ----------------------------

def _trace_span(name: str):
    class _Span:
        def __enter__(self):
            if _tracer:
                self.span = _tracer.start_span(name)
            else:
                self.span = None
            return self

        def __exit__(self, exc_type, exc, tb):
            if self.span:
                self.span.end()
    return _Span()


async def _send_json(ws: WebSocket, obj: ServerMessage) -> None:
    payload = obj.json(separators=(",", ":"), ensure_ascii=False)
    await ws.send_text(payload)


# ----------------------------
# WebSocket endpoint
# ----------------------------

@router.websocket("/v1")
async def ws_entry(ws: WebSocket, identity: Identity = Depends(get_identity)):
    await ws.accept()
    conn = Connection(ws=ws, id=str(uuid.uuid4()), identity=identity)
    await manager.register(conn)

    # Приветствие
    welcome = ServerMessage(
        type=ServerMsgType.WELCOME,
        data={"session_id": conn.id, "roles": list(identity.roles), "tenant": identity.tenant},
    )
    await _send_json(ws, welcome)

    reader_task = asyncio.create_task(_reader_loop(conn))
    writer_task = asyncio.create_task(_writer_loop(conn))
    heartbeat_task = asyncio.create_task(_heartbeat_loop(conn))

    try:
        await asyncio.wait(
            {reader_task, writer_task, heartbeat_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
    finally:
        for t in (reader_task, writer_task, heartbeat_task):
            t.cancel()
        try:
            await ws.close()
        except Exception:
            pass
        await manager.unregister(conn.id)


# ----------------------------
# Циклы обработки
# ----------------------------

async def _reader_loop(conn: Connection) -> None:
    ws = conn.ws
    try:
        while True:
            raw = await ws.receive_text()
            if len(raw.encode("utf-8")) > MAX_MSG_BYTES:
                await _send_json(ws, ServerMessage(type=ServerMsgType.ERROR, data={"reason": "message too large"}))
                await ws.close(code=1009, reason="too large")
                return
            conn.touch()
            if not conn.rate.allow():
                await _send_json(ws, ServerMessage(type=ServerMsgType.ERROR, data={"reason": "rate limit"}))
                # Мягко игнорируем вместо закрытия
                continue

            if _METRICS:
                WS_MESSAGES_RX.labels("raw").inc()

            try:
                obj = ClientMessage.parse_raw(raw)
            except ValidationError as ve:
                await _send_json(ws, ServerMessage(type=ServerMsgType.ERROR, data={"reason": "validation error", "detail": json.loads(ve.json())}))
                continue

            if obj.type == ClientMsgType.PING:
                await _send_json(ws, ServerMessage(type=ServerMsgType.PONG, message_id=obj.message_id))
                continue

            if obj.type == ClientMsgType.PONG:
                conn.last_pong = time.time()
                continue

            if obj.type == ClientMsgType.LIST:
                await _send_json(ws, ServerMessage(type=ServerMsgType.INFO, data={"subscriptions": sorted(conn.subscriptions)}))
                continue

            if obj.type == ClientMsgType.SUBSCRIBE:
                with _trace_span("ws.subscribe"):
                    await manager.subscribe(conn, obj.channel)  # type: ignore[arg-type]
                await _send_json(ws, ServerMessage(type=ServerMsgType.ACK, channel=obj.channel, message_id=obj.message_id))
                continue

            if obj.type == ClientMsgType.UNSUBSCRIBE:
                with _trace_span("ws.unsubscribe"):
                    await manager.unsubscribe(conn, obj.channel)  # type: ignore[arg-type]
                await _send_json(ws, ServerMessage(type=ServerMsgType.ACK, channel=obj.channel, message_id=obj.message_id))
                continue

            if obj.type == ClientMsgType.PUBLISH:
                if obj.channel not in conn.subscriptions:
                    # Разрешаем publish без подписки? По умолчанию — да, но проверим имя и ACL.
                    if not CHANNEL_RE.match(obj.channel or ""):
                        await _send_json(ws, ServerMessage(type=ServerMsgType.ERROR, channel=obj.channel, data={"reason": "invalid channel"}))
                        continue
                with _trace_span("ws.publish"):
                    await manager.publish(obj.channel or "", obj.data)
                await _send_json(ws, ServerMessage(type=ServerMsgType.ACK, channel=obj.channel, message_id=obj.message_id))
                continue

            if obj.type == ClientMsgType.PRESENCE:
                # Простая эхо-присутствия
                await _send_json(ws, ServerMessage(type=ServerMsgType.PRESENCE, channel=obj.channel, data={"conn_id": conn.id, "ts": datetime.now(timezone.utc).isoformat()}))
                continue

    except WebSocketDisconnect:
        return
    except Exception as e:  # pragma: no cover
        logger.exception("reader error: %s", e)
        try:
            await _send_json(ws, ServerMessage(type=ServerMsgType.ERROR, data={"reason": "internal error"}))
        except Exception:
            pass
        await ws.close(code=1011, reason="internal error")


async def _writer_loop(conn: Connection) -> None:
    ws = conn.ws
    try:
        while True:
            msg: ServerMessage = await conn.send_q.get()
            await _send_json(ws, msg)
    except WebSocketDisconnect:
        return
    except Exception as e:  # pragma: no cover
        logger.exception("writer error: %s", e)
        try:
            await ws.close(code=1011, reason="internal error")
        except Exception:
            pass


async def _heartbeat_loop(conn: Connection) -> None:
    ws = conn.ws
    try:
        while True:
            await asyncio.sleep(PING_INTERVAL)
            now = time.time()
            # Пассивный idle-таймаут
            if now - conn.last_seen > IDLE_TIMEOUT:
                try:
                    await _send_json(ws, ServerMessage(type=ServerMsgType.INFO, data={"reason": "idle timeout"}))
                finally:
                    await ws.close(code=1001, reason="idle")
                    return
            conn.last_ping = now
            try:
                await _send_json(ws, ServerMessage(type=ServerMsgType.PONG))
            except WebSocketDisconnect:
                return
            # Ждем ответного трафика (PONG или любой фрейм)
            await asyncio.sleep(PING_TIMEOUT)
            if conn.last_pong < conn.last_ping:
                try:
                    await _send_json(ws, ServerMessage(type=ServerMsgType.ERROR, data={"reason": "ping timeout"}))
                finally:
                    await ws.close(code=1001, reason="ping timeout")
                    return
    except WebSocketDisconnect:
        return
    except Exception as e:  # pragma: no cover
        logger.exception("heartbeat error: %s", e)
        try:
            await ws.close(code=1011, reason="internal error")
        except Exception:
            pass


# ----------------------------
# Пример интеграции:
# ----------------------------
# from fastapi import FastAPI
# from neuroforge_core.api.ws.channels import router, manager, ChannelManager, PubSubBackend
#
# app = FastAPI()
# app.include_router(router)
#
# # Заменить аутентификатор:
# async def real_auth(token: Optional[str]) -> Identity:
#     # verify JWT, map claims -> Identity
#     return Identity(sub="user123", tenant="acme", roles=("user", "publisher"))
# router.ws_authenticator = real_auth  # type: ignore[attr-defined]
#
# # Подменить Pub/Sub backend (например, Redis/NATS) — реализуйте PubSubBackend и передайте в ChannelManager.
# # manager = ChannelManager(backend=YourRedisBackend(...))
