# zero-trust-core/api/ws/channels.py
from __future__ import annotations

import asyncio
import json
import os
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Deque, Dict, Iterable, List, Optional, Set, Tuple

from fastapi import APIRouter, Depends, Header, Query, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field, ValidationError
from starlette.websockets import WebSocketState

# ------------------------------------------------------------------------------
# Конфигурация по умолчанию (из env можно переопределить)
# ------------------------------------------------------------------------------
WS_MAX_SUBSCRIPTIONS = int(os.getenv("ZT_WS_MAX_SUBSCRIPTIONS", "50"))
WS_QUEUE_MAXSIZE = int(os.getenv("ZT_WS_QUEUE_MAXSIZE", "1000"))
WS_RETAIN_MAX = int(os.getenv("ZT_WS_RETAIN_MAX", "200"))
WS_HEARTBEAT_INTERVAL_SEC = float(os.getenv("ZT_WS_HEARTBEAT_SEC", "20"))
WS_CLIENT_PONG_TIMEOUT_SEC = float(os.getenv("ZT_WS_PONG_TIMEOUT_SEC", "30"))
WS_RATE_QPS = float(os.getenv("ZT_WS_RATE_QPS", "200"))          # отправка клиенту
WS_RATE_BURST = int(os.getenv("ZT_WS_RATE_BURST", "400"))         # burst токены
WS_MESSAGE_MAX_BYTES = int(os.getenv("ZT_WS_MESSAGE_MAX", "131072"))  # 128KiB

# ------------------------------------------------------------------------------
# Утилита JSON (orjson -> json)
# ------------------------------------------------------------------------------
try:
    import orjson as _json_lib  # type: ignore

    def _dumps(obj: Any) -> bytes:
        return _json_lib.dumps(obj)

    def _loads(data: bytes | str) -> Any:
        return _json_lib.loads(data)
except Exception:  # pragma: no cover
    def _dumps(obj: Any) -> bytes:
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def _loads(data: bytes | str) -> Any:
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        return json.loads(data)

# ------------------------------------------------------------------------------
# Модель сообщений
# ------------------------------------------------------------------------------
class MsgType(str):
    WELCOME = "welcome"
    SUBSCRIBE = "subscribe"
    UNSUBSCRIBE = "unsubscribe"
    PING = "ping"
    PONG = "pong"
    EVENT = "event"
    ACK = "ack"
    ERROR = "error"

class ServerMessage(BaseModel):
    type: str = Field(..., description="Тип сообщения сервера")
    id: Optional[str] = Field(None, description="Условный идентификатор сообщения")
    ts: float = Field(default_factory=lambda: time.time())
    topic: Optional[str] = None
    event: Optional[str] = None
    data: Any = None

class ClientMessage(BaseModel):
    type: str
    id: Optional[str] = None
    topics: Optional[List[str]] = None
    topic: Optional[str] = None
    # произвольные поля клиента
    data: Any = None

# ------------------------------------------------------------------------------
# Аутентификация/Авторизация
# ------------------------------------------------------------------------------

AuthnFn = Callable[[str], Awaitable[Dict[str, Any]]]
AuthzFn = Callable[[Dict[str, Any], str], Awaitable[bool]]

async def _noop_authn(token: str) -> Dict[str, Any]:
    # В проде заменить на верификацию OAuth2/JWT
    if not token:
        raise PermissionError("missing token")
    return {"sub": "anonymous", "scope": [], "token": token}

async def _allow_all_authz(identity: Dict[str, Any], topic: str) -> bool:
    return True

# ------------------------------------------------------------------------------
# Token Bucket для ограничения скорости отправки клиенту
# ------------------------------------------------------------------------------
@dataclass
class TokenBucket:
    rate: float
    burst: int
    tokens: float = 0.0
    ts: float = field(default_factory=lambda: time.monotonic())

    def grant(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self.ts
        self.ts = now
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False

# ------------------------------------------------------------------------------
# Внутренние объекты
# ------------------------------------------------------------------------------
@dataclass
class Subscriber:
    ws: WebSocket
    identity: Dict[str, Any]
    topics: Set[str] = field(default_factory=set)
    queue: "asyncio.Queue[ServerMessage]" = field(default_factory=lambda: asyncio.Queue(maxsize=WS_QUEUE_MAXSIZE))
    bucket: TokenBucket = field(default_factory=lambda: TokenBucket(rate=WS_RATE_QPS, burst=WS_RATE_BURST))
    last_pong_ts: float = field(default_factory=lambda: time.monotonic())

class TopicRegistry:
    """
    Реестр топиков: подписчики + кольцевой буфер последних N событий на топик.
    """
    def __init__(self) -> None:
        self.subscribers: Dict[str, Set[Subscriber]] = defaultdict(set)
        self.retain: Dict[str, Deque[ServerMessage]] = defaultdict(lambda: deque(maxlen=WS_RETAIN_MAX))
        self.authz_per_topic: Dict[str, AuthzFn] = defaultdict(lambda: _allow_all_authz)

    def set_authz(self, topic: str, fn: AuthzFn) -> None:
        self.authz_per_topic[topic] = fn

    def add_sub(self, topic: str, sub: Subscriber) -> None:
        self.subscribers[topic].add(sub)

    def remove_sub(self, topic: str, sub: Subscriber) -> None:
        self.subscribers[topic].discard(sub)

    def subs(self, topic: str) -> Iterable[Subscriber]:
        return list(self.subscribers.get(topic, set()))

    def retain_event(self, topic: str, msg: ServerMessage) -> None:
        self.retain[topic].append(msg)

    def get_retain(self, topic: str) -> Iterable[ServerMessage]:
        return list(self.retain.get(topic, []))

class ChannelsHub:
    """
    Центральный хаб публикации/подписки WS‑сообщений.
    """
    def __init__(self) -> None:
        self.registry = TopicRegistry()
        self._lock = asyncio.Lock()

    def set_topic_authz(self, topic: str, fn: AuthzFn) -> None:
        self.registry.set_authz(topic, fn)

    async def publish(self, topic: str, event: str, data: Any, *, msg_id: Optional[str] = None, retain: bool = True) -> int:
        msg = ServerMessage(type=MsgType.EVENT, id=msg_id, topic=topic, event=event, data=data)
        if retain:
            self.registry.retain_event(topic, msg)
        delivered = 0
        for sub in self.registry.subs(topic):
            try:
                sub.queue.put_nowait(msg)
                delivered += 1
            except asyncio.QueueFull:
                # backpressure: отбрасываем самое старое сообщение, помещаем новое
                try:
                    _ = sub.queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                try:
                    sub.queue.put_nowait(msg)
                    delivered += 1
                except asyncio.QueueFull:
                    # очередь критически переполнена — закрываем соединение
                    asyncio.create_task(close_ws(sub.ws, code=1013, reason="backpressure"))
        return delivered

    async def publish_json(self, topic: str, data: Dict[str, Any], *, event: str = "message", msg_id: Optional[str] = None, retain: bool = True) -> int:
        return await self.publish(topic, event=event, data=data, msg_id=msg_id, retain=retain)

    # ---- Жизненный цикл подписчика ----
    async def welcome(self, sub: Subscriber) -> None:
        await send_safe(sub.ws, ServerMessage(type=MsgType.WELCOME, data={"service": "channels", "version": "1.0"}))

    async def subscribe(self, sub: Subscriber, topic: str) -> None:
        if len(sub.topics) >= WS_MAX_SUBSCRIPTIONS and topic not in sub.topics:
            raise PermissionError("subscription limit exceeded")
        authz = self.registry.authz_per_topic.get(topic, _allow_all_authz)
        if not await authz(sub.identity, topic):
            raise PermissionError("not authorized for topic")
        self.registry.add_sub(topic, sub)
        sub.topics.add(topic)
        # отправим буфер ретеншна
        for msg in self.registry.get_retain(topic):
            await self._enqueue_or_close(sub, msg)

    async def unsubscribe(self, sub: Subscriber, topic: str) -> None:
        self.registry.remove_sub(topic, sub)
        sub.topics.discard(topic)

    async def detach(self, sub: Subscriber) -> None:
        for t in list(sub.topics):
            self.registry.remove_sub(t, sub)
        sub.topics.clear()

    async def _enqueue_or_close(self, sub: Subscriber, msg: ServerMessage) -> None:
        try:
            sub.queue.put_nowait(msg)
        except asyncio.QueueFull:
            await close_ws(sub.ws, code=1013, reason="backpressure")

# Глобальный хаб
HUB = ChannelsHub()

# Публичные функции публикации для внешних модулей
async def publish(topic: str, event: str, data: Any, *, msg_id: Optional[str] = None, retain: bool = True) -> int:
    return await HUB.publish(topic, event, data, msg_id=msg_id, retain=retain)

async def publish_json(topic: str, data: Dict[str, Any], *, event: str = "message", msg_id: Optional[str] = None, retain: bool = True) -> int:
    return await HUB.publish_json(topic, data, event=event, msg_id=msg_id, retain=retain)

# ------------------------------------------------------------------------------
# Вспомогательные отправка/закрытие
# ------------------------------------------------------------------------------
async def send_safe(ws: WebSocket, msg: ServerMessage) -> None:
    if ws.application_state != WebSocketState.CONNECTED:
        return
    payload = _dumps(msg.model_dump())
    # ограничим размер
    if len(payload) > WS_MESSAGE_MAX_BYTES:
        payload = _dumps(ServerMessage(type=MsgType.ERROR, data={"error": "message too large"}).model_dump())
    try:
        await ws.send_bytes(payload)
    except Exception:
        try:
            await ws.close(code=1011)
        except Exception:
            pass

async def close_ws(ws: WebSocket, *, code: int, reason: str = "") -> None:
    if ws.application_state == WebSocketState.CONNECTED:
        try:
            await ws.close(code=code, reason=reason)
        except Exception:
            pass

# ------------------------------------------------------------------------------
# Основной роутер WebSocket
# ------------------------------------------------------------------------------
router = APIRouter(prefix="/ws/v1", tags=["ws"])

# Инжектируемые функции аутентификации/авторизации (можно переопределить в bootstrap)
AUTHN_FN: AuthnFn = _noop_authn

def set_authn_fn(fn: AuthnFn) -> None:
    global AUTHN_FN
    AUTHN_FN = fn

def set_topic_authz(topic: str, fn: AuthzFn) -> None:
    HUB.set_topic_authz(topic, fn)

@router.websocket("/channels")
async def ws_channels(
    websocket: WebSocket,
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    topics: Optional[str] = Query(default=None, description="Начальные топики через запятую"),
) -> None:
    """
    Единая точка входа WS‑каналов.
    Протокол:
      -> клиент отправляет JSON сообщения ClientMessage (subscribe/unsubscribe/ping/ack)
      <- сервер отправляет ServerMessage (welcome/event/ping/error)
    Аутентификация: Authorization: Bearer <token>
    """
    # Примем подключение (FastAPI сам выполнит HTTP->WS апгрейд)
    await websocket.accept(subprotocol="json")
    try:
        token = ""
        if authorization and authorization.lower().startswith("bearer "):
            token = authorization.split(" ", 1)[1].strip()
        identity = await AUTHN_FN(token)
    except PermissionError:
        await close_ws(websocket, code=1008, reason="unauthorized")
        return
    except Exception:
        await close_ws(websocket, code=1011, reason="authn error")
        return

    sub = Subscriber(ws=websocket, identity=identity)

    # Стартовые подписки из query
    if topics:
        initial_topics = [t.strip() for t in topics.split(",") if t.strip()]
    else:
        initial_topics = []

    # Запустим таски: отправитель очереди и heartbeat
    sender_task = asyncio.create_task(_sender_loop(sub))
    hb_task = asyncio.create_task(_heartbeat_loop(sub))
    recv_task = asyncio.create_task(_receiver_loop(sub, initial_topics))

    # Welcome
    await HUB.welcome(sub)

    done, pending = await asyncio.wait(
        {sender_task, hb_task, recv_task},
        return_when=asyncio.FIRST_COMPLETED,
    )

    # Завершение: остановим оставшиеся задачи и отцепим подписчика
    for t in pending:
        t.cancel()
    await HUB.detach(sub)
    for t in done:
        try:
            _ = t.result()
        except Exception:
            pass
    await close_ws(websocket, code=1000, reason="normal close")

# ------------------------------------------------------------------------------
# Таски отправки/приёма/heartbeat
# ------------------------------------------------------------------------------
async def _sender_loop(sub: Subscriber) -> None:
    """
    Отправляет сообщения из очереди клиенту с учётом rate‑limit.
    """
    try:
        while True:
            msg = await sub.queue.get()
            # квота на отправку (защита от flood от сервера)
            while not sub.bucket.grant(1.0):
                await asyncio.sleep(0.005)
            await send_safe(sub.ws, msg)
    except asyncio.CancelledError:
        return
    except Exception:
        await close_ws(sub.ws, code=1011, reason="send error")

async def _receiver_loop(sub: Subscriber, initial_topics: List[str]) -> None:
    """
    Принимает команды клиента: subscribe/unsubscribe/ping/ack.
    """
    # Выполним начальные подписки
    for t in initial_topics:
        try:
            await HUB.subscribe(sub, t)
        except PermissionError as e:
            await send_safe(sub.ws, ServerMessage(type=MsgType.ERROR, data={"error": str(e), "topic": t}))

    try:
        while True:
            data = await sub.ws.receive()
            if "bytes" in data and data["bytes"] is not None:
                raw = data["bytes"]
            else:
                raw = data.get("text", "")
                if isinstance(raw, str):
                    raw = raw.encode("utf-8")

            if not raw:
                continue
            if len(raw) > WS_MESSAGE_MAX_BYTES:
                await send_safe(sub.ws, ServerMessage(type=MsgType.ERROR, data={"error": "client message too large"}))
                continue

            try:
                obj = _loads(raw)
                msg = ClientMessage.model_validate(obj)
            except ValidationError as ve:
                await send_safe(sub.ws, ServerMessage(type=MsgType.ERROR, data={"error": "invalid message", "details": ve.errors()}))
                continue
            except Exception:
                await send_safe(sub.ws, ServerMessage(type=MsgType.ERROR, data={"error": "malformed json"}))
                continue

            mtype = msg.type.lower()

            if mtype == MsgType.SUBSCRIBE:
                for t in (msg.topics or [msg.topic] if msg.topic else []):
                    if not t:
                        continue
                    try:
                        await HUB.subscribe(sub, t)
                        await send_safe(sub.ws, ServerMessage(type=MsgType.ACK, id=msg.id, data={"subscribed": t}))
                    except PermissionError as e:
                        await send_safe(sub.ws, ServerMessage(type=MsgType.ERROR, id=msg.id, data={"error": str(e), "topic": t}))

            elif mtype == MsgType.UNSUBSCRIBE:
                for t in (msg.topics or [msg.topic] if msg.topic else []):
                    if not t:
                        continue
                    await HUB.unsubscribe(sub, t)
                await send_safe(sub.ws, ServerMessage(type=MsgType.ACK, id=msg.id, data={"unsubscribed": msg.topics or msg.topic}))

            elif mtype == MsgType.PING:
                sub.last_pong_ts = time.monotonic()  # примем ping как признак жизни
                await send_safe(sub.ws, ServerMessage(type=MsgType.PONG, id=msg.id))

            elif mtype == MsgType.ACK:
                # сервер без гарантий доставки; ack можно логировать при необходимости
                pass

            else:
                await send_safe(sub.ws, ServerMessage(type=MsgType.ERROR, id=msg.id, data={"error": "unknown type"}))

    except WebSocketDisconnect:
        return
    except asyncio.CancelledError:
        return
    except Exception:
        await close_ws(sub.ws, code=1011, reason="receive error")

async def _heartbeat_loop(sub: Subscriber) -> None:
    """
    Серверный heartbeat: периодические ping, закрытие при отсутствии pong.
    """
    try:
        while True:
            await asyncio.sleep(WS_HEARTBEAT_INTERVAL_SEC)
            # отправим ping
            await send_safe(sub.ws, ServerMessage(type=MsgType.PING, data={"ts": time.time()}))
            # проверим pong по таймауту
            if (time.monotonic() - sub.last_pong_ts) > WS_CLIENT_PONG_TIMEOUT_SEC:
                await close_ws(sub.ws, code=1001, reason="pong timeout")
                return
    except asyncio.CancelledError:
        return
    except Exception:
        await close_ws(sub.ws, code=1011, reason="heartbeat error")

# ------------------------------------------------------------------------------
# Экспортируемые объекты
# ------------------------------------------------------------------------------
__all__ = [
    "router",
    "ChannelsHub",
    "HUB",
    "publish",
    "publish_json",
    "set_authn_fn",
    "set_topic_authz",
]
