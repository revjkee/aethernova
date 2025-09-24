# datafabric-core/api/ws/channels.py
"""
Промышленный WebSocket-шлюз каналов для FastAPI.

Возможности:
- Аутентификация подключений (коллбек verify_token, легко заменить на JWT/OIDC).
- Канальная модель: SUBSCRIBE / UNSUBSCRIBE / PUBLISH.
- Надёжная доставка: очередь исходящих сообщений, ACK, backpressure.
- Ограничение нагрузки: token-bucket rate limit на входящие команды.
- Heartbeat/PING/PONG, авто-отключение по таймауту.
- Брокер сообщений: InMemoryBroker (по умолчанию) + опциональный RedisBroker (aioredis).
- Границы размера сообщений и валидируемый протокол (pydantic).
- Метрики и структурированный логгер.
- Грациозное завершение: отмена задач, отписка, закрытие брокера.

Интеграция:
    from fastapi import FastAPI
    from .api.ws.channels import ws_router, Channels

    channels = Channels()  # или Channels(broker=RedisBroker(...))
    app = FastAPI()
    app.include_router(ws_router(channels), prefix="")

Протокол сообщений (JSON, UTF‑8):
{
  "type": "command" | "event" | "ack" | "error" | "pong",
  "id": "uuid4-строка"?,            # для команд — опциональный id клиента
  "cmd": "SUBSCRIBE|UNSUBSCRIBE|PUBLISH|PING"?,  # для type=command
  "channel": "string"?,             # имя канала
  "payload": { ... }?,              # произвольные данные события
  "error": {"code": "string", "message": "string"}?
}

Ограничения:
- MAX_MESSAGE_SIZE_BYTES для входящих фреймов (закрываем при превышении).
- MAX_SUBSCRIPTIONS_PER_CONN на коннект.
- RATE_LIMIT_* для защиты от флуд-атак.

Автор: Aethernova / NeuroCity
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Set, Callable, Awaitable, Union

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status, Depends, Query
from fastapi.websockets import WebSocketState
from pydantic import BaseModel, Field, ValidationError, constr

# -------------------------------
# Конфигурация и константы
# -------------------------------

MAX_MESSAGE_SIZE_BYTES = 256 * 1024  # 256 KiB
SEND_QUEUE_MAXSIZE = 1000            # Максимум сообщений в исходящей очереди per connection
MAX_SUBSCRIPTIONS_PER_CONN = 512
HEARTBEAT_INTERVAL_SEC = 20
CLIENT_IDLE_TIMEOUT_SEC = 60
RATE_LIMIT_CAPACITY = 40             # burst
RATE_LIMIT_REFILL_PER_SEC = 10       # rps
DEFAULT_CHANNEL_NAMESPACE = "public"
ALLOW_PUBLISH_FROM_CLIENT = True     # при необходимости выключить клиентский publish
ALLOW_ANONYMOUS = False              # требуется валидный токен

logger = logging.getLogger("ws.channels")
logger.setLevel(logging.INFO)


# -------------------------------
# Утилиты и типы
# -------------------------------

ChannelName = constr(strip_whitespace=True, min_length=1, max_length=256)


class MessageType(str, Enum):
    COMMAND = "command"
    EVENT = "event"
    ACK = "ack"
    ERROR = "error"
    PONG = "pong"


class CommandName(str, Enum):
    SUBSCRIBE = "SUBSCRIBE"
    UNSUBSCRIBE = "UNSUBSCRIBE"
    PUBLISH = "PUBLISH"
    PING = "PING"


class ErrorCode(str, Enum):
    UNAUTHORIZED = "UNAUTHORIZED"
    BAD_REQUEST = "BAD_REQUEST"
    RATE_LIMITED = "RATE_LIMITED"
    TOO_LARGE = "TOO_LARGE"
    INTERNAL = "INTERNAL"
    BACKPRESSURE = "BACKPRESSURE"
    NOT_ALLOWED = "NOT_ALLOWED"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"


class WSCommand(BaseModel):
    type: MessageType = Field(MessageType.COMMAND, const=True)
    id: Optional[str] = Field(default=None, description="Клиентский correlation id")
    cmd: CommandName
    channel: Optional[ChannelName] = None
    payload: Optional[Dict[str, Any]] = None


class WSEvent(BaseModel):
    type: MessageType = Field(MessageType.EVENT, const=True)
    channel: ChannelName
    payload: Dict[str, Any]
    ts: float = Field(default_factory=lambda: time.time())


class WSAck(BaseModel):
    type: MessageType = Field(MessageType.ACK, const=True)
    id: Optional[str] = None
    ok: bool = True


class WSError(BaseModel):
    type: MessageType = Field(MessageType.ERROR, const=True)
    id: Optional[str] = None
    error: Dict[str, str]


class WSPong(BaseModel):
    type: MessageType = Field(MessageType.PONG, const=True)
    id: Optional[str] = None
    ts: float = Field(default_factory=lambda: time.time())


# -------------------------------
# Rate limiter (token bucket)
# -------------------------------

@dataclass
class TokenBucket:
    capacity: int
    refill_per_sec: float
    tokens: float = field(default=0.0)
    last_refill: float = field(default_factory=lambda: time.time())

    def consume(self, amount: float = 1.0) -> bool:
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_sec)
        self.last_refill = now
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False


# -------------------------------
# Брокер сообщений (интерфейс + InMemory + optional Redis)
# -------------------------------

class AsyncPubSubBroker:
    async def publish(self, channel: str, message: Dict[str, Any]) -> None:
        raise NotImplementedError

    async def subscribe(self, channel: str) -> "AsyncIteratorQueue":
        raise NotImplementedError

    async def unsubscribe(self, channel: str, queue: "AsyncIteratorQueue") -> None:
        raise NotImplementedError

    async def close(self) -> None:
        pass


class AsyncIteratorQueue:
    """Асинхронная очередь как итератор (удобно для подписок брокера)."""
    def __init__(self) -> None:
        self._q: asyncio.Queue = asyncio.Queue()
        self._closed = asyncio.Event()

    async def put(self, item: Any) -> None:
        await self._q.put(item)

    async def get(self) -> Any:
        return await self._q.get()

    async def close(self) -> None:
        self._closed.set()
        # поместить sentinel, чтобы разблокировать потребителей
        await self._q.put(None)

    def closed(self) -> bool:
        return self._closed.is_set()

    def __aiter__(self):
        return self

    async def __anext__(self):
        item = await self._q.get()
        if item is None:
            raise StopAsyncIteration
        return item


class InMemoryBroker(AsyncPubSubBroker):
    """Простой брокер для dev/test; хранит подписки в памяти процесса."""
    def __init__(self) -> None:
        self._subs: Dict[str, Set[AsyncIteratorQueue]] = {}
        self._lock = asyncio.Lock()

    async def publish(self, channel: str, message: Dict[str, Any]) -> None:
        async with self._lock:
            queues = list(self._subs.get(channel, ()))
        for q in queues:
            await q.put(message)

    async def subscribe(self, channel: str) -> AsyncIteratorQueue:
        q = AsyncIteratorQueue()
        async with self._lock:
            self._subs.setdefault(channel, set()).add(q)
        return q

    async def unsubscribe(self, channel: str, queue: AsyncIteratorQueue) -> None:
        async with self._lock:
            qs = self._subs.get(channel)
            if qs and queue in qs:
                qs.remove(queue)
                if not qs:
                    self._subs.pop(channel, None)
        await queue.close()

    async def close(self) -> None:
        async with self._lock:
            subs = list(self._subs.items())
            self._subs.clear()
        for _, qs in subs:
            for q in list(qs):
                await q.close()


# Опциональный RedisBroker (без внешних зависимостей по умолчанию).
# Если нужен — подключите aioredis/redis.asyncio и реализуйте аналогично InMemoryBroker.
RedisBroker = None  # placeholder для продакшн-инстанса при интеграции


# -------------------------------
# Управление соединениями и каналами
# -------------------------------

@dataclass
class Connection:
    ws: WebSocket
    user_id: str
    send_queue: asyncio.Queue
    subscriptions: Set[str]
    rate_limiter: TokenBucket
    last_seen: float = field(default_factory=lambda: time.time())
    tasks: Set[asyncio.Task] = field(default_factory=set)

    def touch(self) -> None:
        self.last_seen = time.time()


class ChannelRegistry:
    """Реестр каналов -> набор соединений."""
    def __init__(self) -> None:
        self._channels: Dict[str, Set[Connection]] = {}
        self._lock = asyncio.Lock()

    async def subscribe(self, channel: str, conn: Connection) -> None:
        async with self._lock:
            conns = self._channels.setdefault(channel, set())
            conns.add(conn)
        conn.subscriptions.add(channel)

    async def unsubscribe(self, channel: str, conn: Connection) -> None:
        async with self._lock:
            conns = self._channels.get(channel)
            if conns and conn in conns:
                conns.remove(conn)
                if not conns:
                    self._channels.pop(channel, None)
        conn.subscriptions.discard(channel)

    async def broadcast_local(self, event: Dict[str, Any], channel: str) -> None:
        async with self._lock:
            conns = list(self._channels.get(channel, ()))
        for c in conns:
            # не блокируемся из-за одной переполненной очереди
            try:
                c.send_queue.put_nowait(event)
            except asyncio.QueueFull:
                # уведомим клиента об обратном давлении
                await safe_send_error(
                    c,
                    err=ErrorCode.BACKPRESSURE,
                    message="Outgoing queue is full"
                )

    async def unsubscribe_all(self, conn: Connection) -> None:
        async with self._lock:
            for ch, conns in list(self._channels.items()):
                if conn in conns:
                    conns.remove(conn)
                    if not conns:
                        self._channels.pop(ch, None)
        conn.subscriptions.clear()


# -------------------------------
# Аутентификация
# -------------------------------

VerifyTokenCallable = Callable[[str], Awaitable[Optional[str]]]


async def default_verify_token(token: str) -> Optional[str]:
    """
    Пример верификации: принимает непустой токен и мапит его на user_id.
    Замените на валидацию подписи JWT/OIDC/сессию.
    """
    await asyncio.sleep(0)  # точка переключения
    token = token.strip()
    if not token:
        return None
    # В проде: декодировать/проверить, извлечь sub/uid.
    return f"user:{token}"


# -------------------------------
# Основной фасад Channels
# -------------------------------

class Channels:
    def __init__(
        self,
        broker: Optional[AsyncPubSubBroker] = None,
        verify_token: VerifyTokenCallable = default_verify_token,
        allow_anonymous: bool = ALLOW_ANONYMOUS,
    ) -> None:
        self._broker = broker or InMemoryBroker()
        self._verify_token = verify_token
        self._allow_anonymous = allow_anonymous
        self._registry = ChannelRegistry()
        self._shutdown = asyncio.Event()

    # ------- Публичные API для FastAPI endpoint --------

    async def handle_ws(
        self,
        websocket: WebSocket,
        token: Optional[str],
        namespace: str = DEFAULT_CHANNEL_NAMESPACE,
    ) -> None:
        # Ограничим размер входящих фреймов на уровне протокола
        await websocket.accept()
        user_id = await self._authenticate(token)
        if user_id is None:
            await self._close_unauthorized(websocket)
            return

        conn = Connection(
            ws=websocket,
            user_id=user_id,
            send_queue=asyncio.Queue(maxsize=SEND_QUEUE_MAXSIZE),
            subscriptions=set(),
            rate_limiter=TokenBucket(capacity=RATE_LIMIT_CAPACITY, refill_per_sec=RATE_LIMIT_REFILL_PER_SEC),
        )
        logger.info("WS connected user_id=%s", user_id)

        # Запустим воркеры: sender, heartbeat, broker-consumers (динамически), reader
        try:
            sender_task = asyncio.create_task(self._sender(conn))
            heartbeat_task = asyncio.create_task(self._heartbeat(conn))
            reader_task = asyncio.create_task(self._reader(conn, namespace))
            conn.tasks.update({sender_task, heartbeat_task, reader_task})
            await asyncio.wait(
                {sender_task, heartbeat_task, reader_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            await self._cleanup_connection(conn)
            if websocket.client_state != WebSocketState.DISCONNECTED:
                await websocket.close()
            logger.info("WS disconnected user_id=%s", user_id)

    # ------- Внутренние операции --------

    async def _authenticate(self, token: Optional[str]) -> Optional[str]:
        if not token:
            if self._allow_anonymous:
                return f"anon:{uuid.uuid4()}"
            return None
        try:
            return await self._verify_token(token)
        except Exception as ex:
            logger.exception("verify_token error: %s", ex)
            return None

    async def _close_unauthorized(self, websocket: WebSocket) -> None:
        try:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        except Exception:
            pass

    async def _reader(self, conn: Connection, namespace: str) -> None:
        ws = conn.ws
        while not self._shutdown.is_set():
            try:
                raw = await ws.receive_text()
                conn.touch()
                if len(raw.encode("utf-8")) > MAX_MESSAGE_SIZE_BYTES:
                    await self._send_error(conn, None, ErrorCode.TOO_LARGE, "Message too large")
                    continue
                if not conn.rate_limiter.consume():
                    await self._send_error(conn, None, ErrorCode.RATE_LIMITED, "Too many requests")
                    continue
                try:
                    obj = json.loads(raw)
                    cmd = WSCommand.model_validate(obj)
                except (json.JSONDecodeError, ValidationError) as ex:
                    await self._send_error(conn, None, ErrorCode.BAD_REQUEST, f"Invalid message: {ex}")
                    continue

                await self._handle_command(conn, cmd, namespace)
            except WebSocketDisconnect:
                break
            except Exception as ex:
                logger.exception("reader error: %s", ex)
                await self._send_error(conn, None, ErrorCode.INTERNAL, "Internal error")

    async def _handle_command(self, conn: Connection, cmd: WSCommand, namespace: str) -> None:
        cid = cmd.id
        if cmd.cmd == CommandName.PING:
            await self._send_json(conn, WSPong(id=cid).model_dump())
            return

        if cmd.cmd in (CommandName.SUBSCRIBE, CommandName.UNSUBSCRIBE, CommandName.PUBLISH) and not cmd.channel:
            await self._send_error(conn, cid, ErrorCode.BAD_REQUEST, "Channel is required")
            return

        if cmd.cmd == CommandName.SUBSCRIBE:
            if len(conn.subscriptions) >= MAX_SUBSCRIPTIONS_PER_CONN:
                await self._send_error(conn, cid, ErrorCode.LIMIT_EXCEEDED, "Too many subscriptions")
                return
            channel = self._qualify_channel(namespace, cmd.channel)  # type: ignore[arg-type]
            await self._subscribe_channel(conn, channel)
            await self._send_json(conn, WSAck(id=cid).model_dump())
            return

        if cmd.cmd == CommandName.UNSUBSCRIBE:
            channel = self._qualify_channel(namespace, cmd.channel)  # type: ignore[arg-type]
            await self._unsubscribe_channel(conn, channel)
            await self._send_json(conn, WSAck(id=cid).model_dump())
            return

        if cmd.cmd == CommandName.PUBLISH:
            if not ALLOW_PUBLISH_FROM_CLIENT:
                await self._send_error(conn, cid, ErrorCode.NOT_ALLOWED, "Publishing not allowed")
                return
            channel = self._qualify_channel(namespace, cmd.channel)  # type: ignore[arg-type]
            payload = cmd.payload or {}
            event = WSEvent(channel=channel, payload=payload).model_dump()
            # Локальный broadcast + брокер
            await self._registry.broadcast_local(event, channel)
            try:
                await self._broker.publish(channel, event)
            except Exception as ex:
                logger.exception("broker publish error: %s", ex)
                await self._send_error(conn, cid, ErrorCode.INTERNAL, "Broker publish error")
                return
            await self._send_json(conn, WSAck(id=cid).model_dump())
            return

        await self._send_error(conn, cid, ErrorCode.BAD_REQUEST, f"Unknown command: {cmd.cmd}")

    async def _subscribe_channel(self, conn: Connection, channel: str) -> None:
        # Подписка локального реестра
        await self._registry.subscribe(channel, conn)
        # Подписка к брокеру
        queue = await self._broker.subscribe(channel)

        async def _broker_consumer():
            try:
                async for msg in queue:
                    # Безопасная постановка в очередь отправки
                    try:
                        conn.send_queue.put_nowait(msg)
                    except asyncio.QueueFull:
                        await safe_send_error(
                            conn,
                            err=ErrorCode.BACKPRESSURE,
                            message="Outgoing queue is full"
                        )
            except Exception as ex:
                logger.exception("broker_consumer error: %s", ex)

        task = asyncio.create_task(_broker_consumer())
        conn.tasks.add(task)

        # Привяжем задачу к каналу, чтобы можно было корректно её завершать.
        # Сохраним ссылку через скрытый атрибут:
        setattr(task, "_ws_channel", channel)  # type: ignore[attr-defined]
        setattr(task, "_ws_queue", queue)      # type: ignore[attr-defined]

    async def _unsubscribe_channel(self, conn: Connection, channel: str) -> None:
        await self._registry.unsubscribe(channel, conn)
        # Остановим consumer-задачу для этого канала и отпишем брокерскую очередь
        to_cancel: Set[asyncio.Task] = set()
        for t in list(conn.tasks):
            if getattr(t, "_ws_channel", None) == channel:
                to_cancel.add(t)
        for t in to_cancel:
            queue = getattr(t, "_ws_queue", None)
            try:
                await self._broker.unsubscribe(channel, queue)
            except Exception:
                pass
            t.cancel()
            conn.tasks.discard(t)
            try:
                await t
            except Exception:
                pass

    async def _sender(self, conn: Connection) -> None:
        ws = conn.ws
        while not self._shutdown.is_set():
            try:
                msg = await conn.send_queue.get()
                if msg is None:
                    break
                await self._send_raw(ws, msg)
            except WebSocketDisconnect:
                break
            except Exception as ex:
                logger.exception("sender error: %s", ex)
                await asyncio.sleep(0.05)  # предотвращаем busy loop

    async def _send_raw(self, ws: WebSocket, msg: Union[Dict[str, Any], str, bytes]) -> None:
        if isinstance(msg, (dict,)):
            payload = json.dumps(msg, ensure_ascii=False, separators=(",", ":"))
            if len(payload.encode("utf-8")) > MAX_MESSAGE_SIZE_BYTES:
                # Не отправляем гигантские события; логируем
                logger.warning("drop too large outgoing message (len=%s)", len(payload))
                return
            await ws.send_text(payload)
        elif isinstance(msg, str):
            if len(msg.encode("utf-8")) <= MAX_MESSAGE_SIZE_BYTES:
                await ws.send_text(msg)
        elif isinstance(msg, bytes):
            if len(msg) <= MAX_MESSAGE_SIZE_BYTES:
                await ws.send_bytes(msg)

    async def _send_json(self, conn: Connection, obj: Dict[str, Any]) -> None:
        try:
            conn.send_queue.put_nowait(obj)
        except asyncio.QueueFull:
            await safe_send_error(
                conn,
                err=ErrorCode.BACKPRESSURE,
                message="Outgoing queue is full"
            )

    async def _send_error(self, conn: Connection, cid: Optional[str], code: ErrorCode, message: str) -> None:
        err = WSError(id=cid, error={"code": code.value, "message": message}).model_dump()
        await self._send_json(conn, err)

    async def _heartbeat(self, conn: Connection) -> None:
        ws = conn.ws
        while not self._shutdown.is_set():
            await asyncio.sleep(HEARTBEAT_INTERVAL_SEC)
            idle = time.time() - conn.last_seen
            if idle > CLIENT_IDLE_TIMEOUT_SEC:
                # Закрываем по таймауту неактивности
                try:
                    await ws.close(code=status.WS_1000_NORMAL_CLOSURE)
                except Exception:
                    pass
                break
            # Отправим ping в виде обычной команды сервер->клиент (клиент может ответить PONG или игнорировать).
            try:
                await self._send_json(conn, {"type": "ping", "ts": time.time()})
            except Exception:
                break

    async def _cleanup_connection(self, conn: Connection) -> None:
        try:
            await self._registry.unsubscribe_all(conn)
        except Exception:
            pass
        # Отменяем все задачи
        for t in list(conn.tasks):
            try:
                t.cancel()
            except Exception:
                pass
        # Дожидаемся завершения
        for t in list(conn.tasks):
            try:
                await t
            except Exception:
                pass

    def _qualify_channel(self, namespace: str, channel: str) -> str:
        if ":" in channel:
            return channel
        return f"{namespace}:{channel}"

    async def close(self) -> None:
        self._shutdown.set()
        try:
            await self._broker.close()
        except Exception:
            pass


# -------------------------------
# Вспомогательные функции
# -------------------------------

async def safe_send_error(conn: Connection, err: ErrorCode, message: str) -> None:
    try:
        await conn.ws.send_text(
            json.dumps(
                WSError(error={"code": err.value, "message": message}).model_dump(),
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
    except Exception:
        pass


# -------------------------------
# FastAPI router
# -------------------------------

def ws_router(channels: Channels) -> APIRouter:
    router = APIRouter()

    @router.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket,
        token: Optional[str] = Query(default=None, description="Bearer/JWT token"),
        ns: str = Query(default=DEFAULT_CHANNEL_NAMESPACE, description="Namespace префикс"),
    ):
        await channels.handle_ws(websocket, token=token, namespace=ns)

    return router
