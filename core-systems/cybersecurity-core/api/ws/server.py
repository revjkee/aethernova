# cybersecurity-core/api/ws/server.py
"""
Промышленный WebSocket-сервер для реального времени (FastAPI/Starlette).

Функции:
- /ws/v1: защищённый WS канал с JWT-аутентификацией (?token=...), мультиарендностью
- Подписки на топики: subscribe/unsubscribe
- Публикация в топики: publish (по разрешению в токене)
- Ограничение скорости, обратное давление, heartbeat и idle-timeout
- Структурное логирование и корректный shutdown

Переменные окружения:
- JWT_SECRET           : секрет HS256 для JWT
- WS_MAX_MSG_BYTES     : максимальный размер входящего кадра в байтах (по умолчанию 131072)
- WS_SEND_QUEUE_SIZE   : размер очереди исходящих сообщений на соединение (по умолчанию 1000)
- WS_RATE_LIMIT_QPS    : входной лимит сообщений/сек (по умолчанию 25)
- WS_IDLE_TIMEOUT_SEC  : idle-timeout, сек. (по умолчанию 120)
- WS_HEARTBEAT_SEC     : период пинга, сек. (по умолчанию 30)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field, ValidationError

# --------------------------------------------------------------------------------------
# Конфигурация и логирование
# --------------------------------------------------------------------------------------

LOG = logging.getLogger("ws")
if not LOG.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        fmt='{"ts":"%(asctime)s","lvl":"%(levelname)s","msg":"%(message)s","logger":"%(name)s"}'
    )
    handler.setFormatter(formatter)
    LOG.addHandler(handler)
LOG.setLevel(logging.INFO)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default


JWT_SECRET = os.getenv("JWT_SECRET", "")
WS_MAX_MSG_BYTES = _env_int("WS_MAX_MSG_BYTES", 128 * 1024)
WS_SEND_QUEUE_SIZE = _env_int("WS_SEND_QUEUE_SIZE", 1000)
WS_RATE_LIMIT_QPS = _env_int("WS_RATE_LIMIT_QPS", 25)
WS_IDLE_TIMEOUT_SEC = _env_int("WS_IDLE_TIMEOUT_SEC", 120)
WS_HEARTBEAT_SEC = _env_int("WS_HEARTBEAT_SEC", 30)

# --------------------------------------------------------------------------------------
# Модель аутентификации
# --------------------------------------------------------------------------------------

class Principal(BaseModel):
    sub: str
    tenant_id: str
    roles: Set[str] = Field(default_factory=set)
    can_publish: bool = False
    iat: Optional[int] = None
    exp: Optional[int] = None
    jti: Optional[str] = None


def _parse_jwt(token: str) -> Principal:
    """
    Проверка JWT HS256. Обязательные клеймы: sub, tenant_id.
    Не используйте этот код для асимметричных ключей — адаптируйте при необходимости.
    """
    if not token:
        raise ValueError("missing token")
    if not JWT_SECRET:
        # Жёстко: в проде всегда нужен секрет. В dev можно падать заранее.
        raise ValueError("JWT secret is not configured")

    try:
        import jwt  # PyJWT
    except Exception as e:
        raise ValueError(f"PyJWT is required: {e!r}")

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], options={"require": ["sub"]})
    except Exception as e:
        raise ValueError(f"invalid token: {e!r}")

    sub = payload.get("sub")
    tenant_id = payload.get("tenant_id")
    if not sub or not tenant_id:
        raise ValueError("token missing required claims: sub/tenant_id")

    roles = payload.get("roles") or []
    if not isinstance(roles, (list, set, tuple)):
        roles = []
    can_publish = bool(payload.get("can_publish") or ("publisher" in roles) or ("admin" in roles))

    return Principal(
        sub=str(sub),
        tenant_id=str(tenant_id),
        roles=set(map(str, roles)),
        can_publish=can_publish,
        iat=payload.get("iat"),
        exp=payload.get("exp"),
        jti=payload.get("jti"),
    )

# --------------------------------------------------------------------------------------
# Протокол кадров
# --------------------------------------------------------------------------------------

class BaseFrame(BaseModel):
    # Идентификатор RPC/кадра от клиента для корреляции ответов (ACK/Error)
    id: Optional[str] = None
    type: str


class SubscribeFrame(BaseFrame):
    type: str = Field(default="subscribe", const=True)
    topic: str


class UnsubscribeFrame(BaseFrame):
    type: str = Field(default="unsubscribe", const=True)
    topic: str


class PublishFrame(BaseFrame):
    type: str = Field(default="publish", const=True)
    topic: str
    payload: Any


class PingFrame(BaseFrame):
    type: str = Field(default="ping", const=True)
    ts: Optional[float] = None


class PongFrame(BaseFrame):
    type: str = Field(default="pong", const=True)
    ts: Optional[float] = None


class AckFrame(BaseModel):
    type: str = Field(default="ack", const=True)
    id: Optional[str] = None
    ok: bool = True


class ErrorFrame(BaseModel):
    type: str = Field(default="error", const=True)
    id: Optional[str] = None
    code: str
    message: str


class EventFrame(BaseModel):
    type: str = Field(default="event", const=True)
    topic: str
    payload: Any
    ts: float = Field(default_factory=lambda: datetime.now(timezone.utc).timestamp())


# --------------------------------------------------------------------------------------
# Ограничение скорости (token bucket)
# --------------------------------------------------------------------------------------

class TokenBucket:
    def __init__(self, rate_per_sec: int, capacity: Optional[int] = None) -> None:
        self.rate = max(1, rate_per_sec)
        self.capacity = capacity or self.rate
        self.tokens = float(self.capacity)
        self.ts = time.monotonic()

    def allow(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        delta = now - self.ts
        self.ts = now
        self.tokens = min(self.capacity, self.tokens + delta * self.rate)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


# --------------------------------------------------------------------------------------
# Контекст соединения и менеджер
# --------------------------------------------------------------------------------------

@dataclass
class Connection:
    ws: WebSocket
    principal: Principal
    send_q: asyncio.Queue[EventFrame | AckFrame | ErrorFrame] = field(
        default_factory=lambda: asyncio.Queue(maxsize=WS_SEND_QUEUE_SIZE)
    )
    topics: Set[str] = field(default_factory=set)
    bucket: TokenBucket = field(default_factory=lambda: TokenBucket(WS_RATE_LIMIT_QPS))
    last_seen: float = field(default_factory=lambda: time.monotonic())
    sender_task: Optional[asyncio.Task] = None
    heartbeat_task: Optional[asyncio.Task] = None
    id: str = field(default_factory=lambda: uuid.uuid4().hex)


class WSManager:
    """
    Изолирует подключения по арендаторам и топикам.
    """
    def __init__(self) -> None:
        # tenant -> topic -> set(Connection)
        self._by_topic: dict[str, dict[str, set[Connection]]] = defaultdict(lambda: defaultdict(set))
        self._lock = asyncio.Lock()

    async def register(self, conn: Connection) -> None:
        LOG.info(f'ws_connect tenant="{conn.principal.tenant_id}" sub="{conn.principal.sub}" cid="{conn.id}"')

    async def unregister(self, conn: Connection) -> None:
        async with self._lock:
            t = conn.principal.tenant_id
            for topic in list(conn.topics):
                self._by_topic[t][topic].discard(conn)
                if not self._by_topic[t][topic]:
                    self._by_topic[t].pop(topic, None)
            if not self._by_topic.get(t):
                self._by_topic.pop(t, None)
        LOG.info(f'ws_disconnect tenant="{conn.principal.tenant_id}" sub="{conn.principal.sub}" cid="{conn.id}"')

    async def subscribe(self, conn: Connection, topic: str) -> None:
        if not topic or len(topic) > 256:
            raise ValueError("invalid topic")
        async with self._lock:
            self._by_topic[conn.principal.tenant_id][topic].add(conn)
            conn.topics.add(topic)
        LOG.info(f'ws_sub tenant="{conn.principal.tenant_id}" topic="{topic}" cid="{conn.id}"')

    async def unsubscribe(self, conn: Connection, topic: str) -> None:
        async with self._lock:
            bucket = self._by_topic.get(conn.principal.tenant_id, {})
            if topic in bucket:
                bucket[topic].discard(conn)
                if not bucket[topic]:
                    bucket.pop(topic, None)
        conn.topics.discard(topic)
        LOG.info(f'ws_unsub tenant="{conn.principal.tenant_id}" topic="{topic}" cid="{conn.id}"')

    async def publish(
        self,
        tenant_id: str,
        topic: str,
        payload: Any,
    ) -> int:
        """
        Внешняя публикация событий. Возвращает кол-во доставок.
        """
        frame = EventFrame(topic=topic, payload=payload)
        delivered = 0
        async with self._lock:
            conns = list(self._by_topic.get(tenant_id, {}).get(topic, set()))
        for c in conns:
            try:
                c.send_q.put_nowait(frame)
                delivered += 1
            except asyncio.QueueFull:
                # Перегруз, корректно закрываем 1013
                LOG.warning(f'ws_queue_full tenant="{tenant_id}" cid="{c.id}" topic="{topic}"')
                await _safe_close(c.ws, code=1013, reason="overloaded")
        if delivered:
            LOG.info(f'ws_publish tenant="{tenant_id}" topic="{topic}" delivered={delivered}')
        return delivered


_manager = WSManager()

def get_ws_manager() -> WSManager:
    return _manager


# --------------------------------------------------------------------------------------
# Утилиты
# --------------------------------------------------------------------------------------

async def _safe_send_json(ws: WebSocket, data: Any) -> None:
    try:
        await ws.send_json(data)
    except Exception:
        # канал может быть уже закрыт — игнорируем
        pass


async def _safe_close(ws: WebSocket, code: int, reason: str) -> None:
    try:
        await ws.close(code=code, reason=reason)
    except Exception:
        pass


async def _sender_loop(conn: Connection) -> None:
    """
    Отдельная задача отправки, чтобы уважать backpressure.
    """
    try:
        while True:
            item = await conn.send_q.get()
            if isinstance(item, (EventFrame, AckFrame, ErrorFrame)):
                await _safe_send_json(conn.ws, json.loads(item.model_dump_json()))
            else:
                await _safe_send_json(conn.ws, item)
    except Exception as e:
        LOG.debug(f'sender_exit cid="{conn.id}" err="{e!r}"')


async def _heartbeat_loop(conn: Connection) -> None:
    try:
        while True:
            await asyncio.sleep(WS_HEARTBEAT_SEC)
            now = time.monotonic()
            if now - conn.last_seen > WS_IDLE_TIMEOUT_SEC:
                LOG.info(f'ws_idle_timeout cid="{conn.id}"')
                await _safe_close(conn.ws, code=1001, reason="idle timeout")
                return
            # Отправим ping (пользовательский)
            await _safe_send_json(conn.ws, {"type": "ping", "ts": time.time()})
    except Exception:
        pass


# --------------------------------------------------------------------------------------
# FastAPI router
# --------------------------------------------------------------------------------------

router = APIRouter()


@router.websocket("/ws/v1")
async def ws_v1(
    websocket: WebSocket,
    token: Optional[str] = Query(default=None, description="JWT HS256 token"),
    manager: WSManager = Depends(get_ws_manager),
) -> None:
    """
    Основная точка входа WebSocket. Требует валидный JWT (?token=...).
    """
    # Размер сообщения на уровне протокола Starlette не ограничивается —
    # контролируем вручную по длине текстового кадра.
    max_len = WS_MAX_MSG_BYTES

    # Аутентификация (до accept)
    try:
        principal = _parse_jwt(token or "")
    except Exception as e:
        await websocket.close(code=1008, reason=f"unauthorized: {e}")
        return

    await websocket.accept()  # subprotocol negotiation можно добавить при необходимости

    conn = Connection(ws=websocket, principal=principal)
    await manager.register(conn)

    # Задачи: отправитель и heartbeat
    conn.sender_task = asyncio.create_task(_sender_loop(conn))
    conn.heartbeat_task = asyncio.create_task(_heartbeat_loop(conn))

    # Приветствие
    await _safe_send_json(websocket, {
        "type": "welcome",
        "cid": conn.id,
        "tenant_id": principal.tenant_id,
        "sub": principal.sub,
        "ts": datetime.now(timezone.utc).isoformat(),
    })

    try:
        while True:
            try:
                msg = await websocket.receive_text()
                conn.last_seen = time.monotonic()
            except WebSocketDisconnect as e:
                LOG.info(f'ws_client_dc code={e.code} cid="{conn.id}"')
                break

            # Ограничение размера
            if len(msg.encode("utf-8", errors="ignore")) > max_len:
                await _safe_send_json(websocket, ErrorFrame(id=None, code="too_large", message="message too large").model_dump())
                await _safe_close(websocket, code=1009, reason="message too large")
                break

            # Rate limit
            if not conn.bucket.allow():
                # 1013 — try again later
                await _safe_send_json(websocket, ErrorFrame(id=None, code="rate_limited", message="too many messages").model_dump())
                await _safe_close(websocket, code=1013, reason="rate limit exceeded")
                break

            # Разбор JSON
            try:
                raw = json.loads(msg)
            except json.JSONDecodeError:
                await _safe_send_json(websocket, ErrorFrame(id=None, code="bad_json", message="invalid json").model_dump())
                continue

            ftype = raw.get("type")
            fid = raw.get("id")

            try:
                if ftype == "subscribe":
                    frame = SubscribeFrame(**raw)
                    await manager.subscribe(conn, frame.topic)
                    await conn.send_q.put(AckFrame(id=fid, ok=True))
                elif ftype == "unsubscribe":
                    frame = UnsubscribeFrame(**raw)
                    await manager.unsubscribe(conn, frame.topic)
                    await conn.send_q.put(AckFrame(id=fid, ok=True))
                elif ftype == "publish":
                    frame = PublishFrame(**raw)
                    if not conn.principal.can_publish:
                        await conn.send_q.put(ErrorFrame(id=fid, code="forbidden", message="publish not allowed"))
                        continue
                    # Публикация только в рамках своего арендатора
                    delivered = await manager.publish(conn.principal.tenant_id, frame.topic, frame.payload)
                    await conn.send_q.put(AckFrame(id=fid, ok=(delivered >= 0)))
                elif ftype == "ping":
                    # Ответим pong
                    try:
                        _ = PingFrame(**raw)
                    except ValidationError:
                        pass
                    await conn.send_q.put(PongFrame(id=fid, ts=time.time()))  # отражаем ts клиенту
                elif ftype == "pong":
                    # Клиент ответил на наш ping
                    conn.last_seen = time.monotonic()
                else:
                    await conn.send_q.put(ErrorFrame(id=fid, code="unsupported", message="unknown frame type"))
            except ValidationError as ve:
                await conn.send_q.put(ErrorFrame(id=fid, code="validation_error", message=str(ve)))
            except ValueError as ve:
                await conn.send_q.put(ErrorFrame(id=fid, code="bad_request", message=str(ve)))
            except asyncio.QueueFull:
                await _safe_close(websocket, code=1013, reason="outbound queue overflow")
                break
            except Exception as e:  # не раскрываем детали
                LOG.exception("ws_handler_error")
                await conn.send_q.put(ErrorFrame(id=fid, code="internal", message="internal error"))
                await _safe_close(websocket, code=1011, reason="internal error")
                break

    finally:
        # Уборка
        try:
            if conn.sender_task:
                conn.sender_task.cancel()
            if conn.heartbeat_task:
                conn.heartbeat_task.cancel()
            await manager.unregister(conn)
        except Exception:
            pass


# --------------------------------------------------------------------------------------
# Публичные утилиты (для внешних модулей)
# --------------------------------------------------------------------------------------

async def broadcast(tenant_id: str, topic: str, payload: Any) -> int:
    """
    Публикация события всем подписчикам данного арендатора и топика.
    Возвращает число успешных доставок.
    """
    return await _manager.publish(tenant_id=tenant_id, topic=topic, payload=payload)


__all__ = [
    "router",
    "broadcast",
    "get_ws_manager",
    "WSManager",
    "Principal",
]
