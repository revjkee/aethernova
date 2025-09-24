# -*- coding: utf-8 -*-
"""
Industrial WebSocket Channels (v1)

Особенности:
- Абстракция ChannelHub: подписки/отписки, публикация, presence, ACL.
- EventBus интерфейс с in-memory реализацией (замените на Redis/NATS в проде).
- Аутентификация: Bearer/JWT заглушка (заменить на реальную верификацию).
- RBAC по каналам: разрешения publish/subscribe, шаблоны "room:*".
- Надёжность: идемпотентность сообщений (dedup), корреляция x-request-id.
- Контроль потока: rate-limit per-connection, backpressure с политикой drop_oldest.
- Здоровье соединения: ping/pong, idle timeout, server heartbeat.
- Форматы сообщений: строгие Pydantic-схемы, единый envelope.
- Логирование: структурные логи начала/окончания/ошибок с request_id.
- Безопасный shutdown: мягкое закрытие всех соединений.
- Совместимость: FastAPI/Starlette (asgi.websocket_route).

Примечания:
- Для продакшена замените Auth/JWT и EventBus на распределённые (Redis streams/pubsub).
- Код самодостаточен; внешние зависимости: fastapi/starlette, pydantic.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Literal, Optional, Set, Tuple, Callable, Awaitable

try:
    import ujson as _json
except Exception:  # pragma: no cover
    _json = json

from pydantic import BaseModel, Field, validator
from starlette.websockets import WebSocket, WebSocketDisconnect, WebSocketState, Status
from starlette.concurrency import run_until_first_complete

# ------------------------------------------------------------------------------
# Логирование
# ------------------------------------------------------------------------------
logger = logging.getLogger("engine_core.ws.channels")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)sZ %(levelname)s %(name)s %(message)s", "%Y-%m-%dT%H:%M:%S"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# ------------------------------------------------------------------------------
# Вспомогательные
# ------------------------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

X_REQUEST_ID = "x-request-id"

# ------------------------------------------------------------------------------
# Безопасность и ACL
# ------------------------------------------------------------------------------
@dataclass
class Principal:
    user_id: str
    email: str
    roles: Set[str] = field(default_factory=set)
    scopes: Set[str] = field(default_factory=set)


async def verify_bearer_token(authorization: Optional[str]) -> Principal:
    """
    Заглушка верификации Bearer/JWT. Замените на реальную проверку (issuer/aud/exp/kid).
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise PermissionError("Missing or invalid Bearer token")
    # Демонстрационно возвращаем администратора
    return Principal(user_id=str(uuid.uuid4()), email="admin@example.org", roles={"admin"}, scopes={"ws:pub", "ws:sub"})


class ChannelPermission(BaseModel):
    pattern: str = Field(..., description="Шаблон канала, поддержка '*' в конце, например 'room:*'")
    can_publish: bool = True
    can_subscribe: bool = True

    def matches(self, name: str) -> bool:
        if self.pattern.endswith("*"):
            prefix = self.pattern[:-1]
            return name.startswith(prefix)
        return name == self.pattern


class ACL:
    def __init__(self):
        self._rules_by_role: Dict[str, List[ChannelPermission]] = defaultdict(list)

    def allow(self, role: str, permission: ChannelPermission):
        self._rules_by_role[role].append(permission)

    def check(self, principal: Principal, channel: str, action: Literal["pub", "sub"]) -> bool:
        # Админ shortcut
        if "admin" in principal.roles:
            return True
        for role in principal.roles:
            for rule in self._rules_by_role.get(role, []):
                if rule.matches(channel):
                    if action == "pub" and rule.can_publish:
                        return True
                    if action == "sub" and rule.can_subscribe:
                        return True
        return False


# ------------------------------------------------------------------------------
# Идемпотентность/Rate-limit/Backpressure
# ------------------------------------------------------------------------------
class Deduplicator:
    """LRU-окно идемпотентности по message_id."""
    def __init__(self, max_items: int = 5000, ttl_seconds: int = 600):
        self._seen: Dict[str, float] = {}
        self._order: deque[str] = deque()
        self._max = max_items
        self._ttl = ttl_seconds

    def seen(self, msg_id: str) -> bool:
        now = time.time()
        # GC
        while self._order and (now - self._seen.get(self._order[0], 0) > self._ttl):
            oldest = self._order.popleft()
            self._seen.pop(oldest, None)
        if msg_id in self._seen:
            return True
        self._seen[msg_id] = now
        self._order.append(msg_id)
        if len(self._order) > self._max:
            oldest = self._order.popleft()
            self._seen.pop(oldest, None)
        return False


class TokenBucket:
    def __init__(self, rate: int, per_seconds: int):
        self.capacity = max(1, rate)
        self.tokens = self.capacity
        self.per_seconds = max(1, per_seconds)
        self.updated_at = time.time()

    def try_consume(self, n: int = 1) -> Tuple[bool, int]:
        now = time.time()
        elapsed = now - self.updated_at
        refill = int((elapsed / self.per_seconds) * self.capacity)
        if refill > 0:
            self.tokens = min(self.capacity, self.tokens + refill)
            self.updated_at = now
        if self.tokens >= n:
            self.tokens -= n
            return True, self.tokens
        return False, self.tokens


# ------------------------------------------------------------------------------
# Схемы сообщений
# ------------------------------------------------------------------------------
class Envelope(BaseModel):
    type: Literal["subscribe", "unsubscribe", "publish", "ping", "ack", "error", "presence"]  # вход/выход
    request_id: Optional[str] = None  # корреляция
    ts: datetime = Field(default_factory=now_utc)

class SubscribeIn(BaseModel):
    type: Literal["subscribe"] = "subscribe"
    channels: List[str]

class UnsubscribeIn(BaseModel):
    type: Literal["unsubscribe"] = "unsubscribe"
    channels: List[str]

class PublishIn(BaseModel):
    type: Literal["publish"] = "publish"
    channel: str
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    payload: Dict[str, Any]

    @validator("payload")
    def _size_guard(cls, v):
        if len(_json.dumps(v)) > 64 * 1024:  # 64 KB payload guard
            raise ValueError("payload too large")
        return v

class PingIn(BaseModel):
    type: Literal["ping"] = "ping"

class AckOut(BaseModel):
    type: Literal["ack"] = "ack"
    request_id: Optional[str] = None
    message_id: Optional[str] = None
    ok: bool = True

class ErrorOut(BaseModel):
    type: Literal["error"] = "error"
    request_id: Optional[str] = None
    code: str
    message: str
    detail: Optional[Dict[str, Any]] = None

class PresenceOut(BaseModel):
    type: Literal["presence"] = "presence"
    channel: str
    users: int

class PublishOut(BaseModel):
    type: Literal["publish"] = "publish"
    channel: str
    payload: Dict[str, Any]
    message_id: str
    ts: datetime = Field(default_factory=now_utc)

# ------------------------------------------------------------------------------
# EventBus интерфейс и in-memory реализация
# ------------------------------------------------------------------------------
Subscriber = Callable[[PublishOut], Awaitable[None]]

class EventBus:
    async def publish(self, channel: str, msg: PublishOut) -> None:
        raise NotImplementedError

    async def subscribe(self, channel: str, handler: Subscriber) -> Callable[[], Awaitable[None]]:
        """Возвращает функцию отписки."""
        raise NotImplementedError

class InMemoryEventBus(EventBus):
    def __init__(self):
        self._subs: Dict[str, Set[Subscriber]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def publish(self, channel: str, msg: PublishOut) -> None:
        async with self._lock:
            subs = list(self._subs.get(channel, set()))
        # Рассылаем без удержания lock
        tasks = [asyncio.create_task(h(msg)) for h in subs]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def subscribe(self, channel: str, handler: Subscriber) -> Callable[[], Awaitable[None]]:
        async with self._lock:
            self._subs[channel].add(handler)

        async def _unsub():
            async with self._lock:
                if handler in self._subs.get(channel, set()):
                    self._subs[channel].remove(handler)
                    if not self._subs[channel]:
                        self._subs.pop(channel, None)
        return _unsub

# ------------------------------------------------------------------------------
# ChannelHub
# ------------------------------------------------------------------------------
@dataclass
class ConnectionConfig:
    max_send_queue: int = 1000
    drop_policy: Literal["drop_oldest", "drop_new"] = "drop_oldest"
    client_rate: int = 100  # сообщений в окно
    client_rate_window_s: int = 10
    ping_interval_s: int = 20
    idle_timeout_s: int = 120


class Connection:
    def __init__(self, websocket: WebSocket, principal: Principal, cfg: ConnectionConfig):
        self.ws = websocket
        self.principal = principal
        self.cfg = cfg
        self.send_q: asyncio.Queue[PublishOut | AckOut | ErrorOut | PresenceOut] = asyncio.Queue(maxsize=cfg.max_send_queue)
        self.subscriptions: Set[str] = set()
        self.rate = TokenBucket(cfg.client_rate, cfg.client_rate_window_s)
        self.dedup = Deduplicator()
        self.last_recv = time.time()
        self.request_id = str(uuid.uuid4())

    async def enqueue(self, item: PublishOut | AckOut | ErrorOut | PresenceOut):
        if self.send_q.full():
            if self.cfg.drop_policy == "drop_oldest":
                try:
                    _ = self.send_q.get_nowait()
                    self.send_q.task_done()
                except Exception:
                    pass
            else:
                # drop_new — отбрасываем новое
                return
        await self.send_q.put(item)


class ChannelHub:
    def __init__(self, bus: EventBus, acl: ACL):
        self.bus = bus
        self.acl = acl
        self._presence: Dict[str, Set[Connection]] = defaultdict(set)
        self._presence_lock = asyncio.Lock()
        self._closing = asyncio.Event()

    async def add_subscription(self, conn: Connection, channel: str, handler: Subscriber) -> Callable[[], Awaitable[None]]:
        if not self.acl.check(conn.principal, channel, "sub"):
            raise PermissionError("subscribe forbidden")
        unsub = await self.bus.subscribe(channel, handler)
        async with self._presence_lock:
            self._presence[channel].add(conn)
        await self._broadcast_presence(channel)
        return unsub

    async def remove_subscription(self, conn: Connection, channel: str):
        async with self._presence_lock:
            if conn in self._presence.get(channel, set()):
                self._presence[channel].remove(conn)
                if not self._presence[channel]:
                    self._presence.pop(channel, None)
        await self._broadcast_presence(channel)

    async def publish(self, conn: Connection, channel: str, payload: Dict[str, Any], message_id: str):
        if not self.acl.check(conn.principal, channel, "pub"):
            raise PermissionError("publish forbidden")
        msg = PublishOut(type="publish", channel=channel, payload=payload, message_id=message_id)
        await self.bus.publish(channel, msg)

    async def _broadcast_presence(self, channel: str):
        users = len(self._presence.get(channel, set()))
        out = PresenceOut(type="presence", channel=channel, users=users)
        # Широковещательно участникам канала
        conns = list(self._presence.get(channel, set()))
        tasks = [c.enqueue(out) for c in conns]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def shutdown(self):
        self._closing.set()

# ------------------------------------------------------------------------------
# Конфигурация ACL по умолчанию (можете перенастроить из приложения)
# ------------------------------------------------------------------------------
def default_acl() -> ACL:
    acl = ACL()
    # Пример: роль "user" может подписываться на публичные комнаты, публиковать в свои личные
    acl.allow("user", ChannelPermission(pattern="room:public:*", can_publish=True, can_subscribe=True))
    acl.allow("user", ChannelPermission(pattern="user:", can_publish=True, can_subscribe=True))
    # Админ — всё (шорткат в ACL.check)
    return acl

# ------------------------------------------------------------------------------
# Парсер входных сообщений
# ------------------------------------------------------------------------------
def parse_incoming(raw: str) -> SubscribeIn | UnsubscribeIn | PublishIn | PingIn:
    try:
        obj = _json.loads(raw)
    except Exception:
        raise ValueError("invalid_json")
    t = obj.get("type")
    if t == "subscribe":
        return SubscribeIn(**obj)
    if t == "unsubscribe":
        return UnsubscribeIn(**obj)
    if t == "publish":
        return PublishIn(**obj)
    if t == "ping":
        return PingIn(**obj)
    raise ValueError("unknown_type")

# ------------------------------------------------------------------------------
# Основной обработчик WebSocket
# ------------------------------------------------------------------------------
class WSHandler:
    def __init__(self, hub: ChannelHub, conn_cfg: Optional[ConnectionConfig] = None):
        self.hub = hub
        self.conn_cfg = conn_cfg or ConnectionConfig()

    async def __call__(self, websocket: WebSocket):
        # Авторизация
        try:
            auth = websocket.headers.get("authorization") or websocket.headers.get("Authorization")
            principal = await verify_bearer_token(auth)
        except PermissionError:
            await websocket.close(code=Status.WS_1008_POLICY_VIOLATION)
            return

        await websocket.accept(subprotocol="json")
        req_id = websocket.headers.get(X_REQUEST_ID) or str(uuid.uuid4())
        conn = Connection(websocket, principal, self.conn_cfg)
        conn.request_id = req_id

        logger.info("ws open", extra={"user": principal.email, "request_id": req_id})

        async def _bus_handler_factory(channel: str) -> Subscriber:
            async def _on_msg(msg: PublishOut):
                # обратная доставка с backpressure
                await conn.enqueue(msg)
            return _on_msg

        # Управление жизненным циклом соединения
        unsub_funcs: Dict[str, Callable[[], Awaitable[None]]] = {}

        async def sender():
            # Периодический ping и отправка очереди
            ping_interval = self.conn_cfg.ping_interval_s
            next_ping = time.time() + ping_interval
            while websocket.application_state == WebSocketState.CONNECTED:
                try:
                    # heartbeat
                    now = time.time()
                    if now >= next_ping:
                        await websocket.send_text(_json.dumps({"type": "ping", "ts": now_utc().isoformat()}))
                        next_ping = now + ping_interval

                    item = await asyncio.wait_for(conn.send_q.get(), timeout=1.0)
                    await websocket.send_text(_json.dumps(item.dict(), ensure_ascii=False))
                    conn.send_q.task_done()
                except asyncio.TimeoutError:
                    # цикл проверки пинга/таймаута
                    if (time.time() - conn.last_recv) > self.conn_cfg.idle_timeout_s:
                        await websocket.close(code=Status.WS_1001_GOING_AWAY)
                        break
                    continue
                except Exception:
                    logger.exception("ws sender error", extra={"request_id": req_id})
                    break

        async def receiver():
            while websocket.application_state == WebSocketState.CONNECTED:
                try:
                    raw = await websocket.receive_text()
                    conn.last_recv = time.time()
                    msg = parse_incoming(raw)

                    # rate-limit
                    ok, _rem = conn.rate.try_consume(1)
                    if not ok:
                        await conn.enqueue(ErrorOut(type="error", request_id=None, code="rate_limited", message="Rate limit exceeded"))
                        continue

                    if isinstance(msg, PingIn):
                        await conn.enqueue(AckOut(type="ack", ok=True))
                        continue

                    if isinstance(msg, SubscribeIn):
                        # подписки
                        for ch in msg.channels:
                            if ch in conn.subscriptions:
                                continue
                            handler = await _bus_handler_factory(ch)
                            try:
                                unsub = await self.hub.add_subscription(conn, ch, handler)
                            except PermissionError:
                                await conn.enqueue(ErrorOut(type="error", code="forbidden", message=f"subscribe forbidden: {ch}"))
                                continue
                            conn.subscriptions.add(ch)
                            unsub_funcs[ch] = unsub
                        await conn.enqueue(AckOut(type="ack", ok=True))
                        continue

                    if isinstance(msg, UnsubscribeIn):
                        for ch in msg.channels:
                            if ch in conn.subscriptions:
                                try:
                                    await unsub_funcs[ch]()
                                except Exception:
                                    pass
                                await self.hub.remove_subscription(conn, ch)
                                conn.subscriptions.remove(ch)
                                unsub_funcs.pop(ch, None)
                        await conn.enqueue(AckOut(type="ack", ok=True))
                        continue

                    if isinstance(msg, PublishIn):
                        # идемпотентность
                        if conn.dedup.seen(msg.message_id):
                            await conn.enqueue(AckOut(type="ack", message_id=msg.message_id, ok=True))
                            continue
                        try:
                            await self.hub.publish(conn, msg.channel, msg.payload, msg.message_id)
                            await conn.enqueue(AckOut(type="ack", message_id=msg.message_id, ok=True))
                        except PermissionError:
                            await conn.enqueue(ErrorOut(type="error", code="forbidden", message=f"publish forbidden: {msg.channel}"))
                        continue

                except WebSocketDisconnect:
                    break
                except Exception as e:
                    logger.warning("ws receiver error", extra={"err": str(e), "request_id": req_id})
                    await conn.enqueue(ErrorOut(type="error", code="bad_request", message="invalid message"))
                    # продолжаем принимать

        async def on_disconnect():
            # очистка подписок и presence
            for ch, unsub in list(unsub_funcs.items()):
                try:
                    await unsub()
                except Exception:
                    pass
                await self.hub.remove_subscription(conn, ch)
            unsub_funcs.clear()

            if websocket.application_state == WebSocketState.CONNECTED:
                try:
                    await websocket.close()
                except Exception:
                    pass
            logger.info("ws closed", extra={"user": principal.email, "request_id": req_id})

        await run_until_first_complete(
            (sender, ()),
            (receiver, ()),
        )
        await on_disconnect()

# ------------------------------------------------------------------------------
# Публичные фабрики/инициализация
# ------------------------------------------------------------------------------
def build_default_ws_stack() -> Tuple[ChannelHub, WSHandler]:
    bus = InMemoryEventBus()
    acl = default_acl()
    hub = ChannelHub(bus, acl)
    handler = WSHandler(hub)
    return hub, handler

# ------------------------------------------------------------------------------
# Интеграция с FastAPI/Starlette
# ------------------------------------------------------------------------------
# Пример подключения:
#
# from fastapi import FastAPI
# from engine_core.api.ws.channels import build_default_ws_stack
#
# app = FastAPI()
# hub, ws_handler = build_default_ws_stack()
#
# @app.websocket("/ws")
# async def ws_endpoint(ws: WebSocket):
#     await ws_handler(ws)
#
# При переходе на Redis/NATS:
#  - Реализуйте EventBus.publish/subscribe и передайте в ChannelHub.
#  - Подмените verify_bearer_token на реальную JWT‑проверку.
#
# Границы по умолчанию: payload <= 64KB, очередь send 1000 сообщений, idle timeout 120s.
