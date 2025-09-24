# ledger-core/api/ws/channels.py
from __future__ import annotations

import asyncio
import contextlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, List, Mapping, Optional, Set, Tuple, Union

from fastapi import APIRouter, Depends, Header, HTTPException, WebSocket, WebSocketDisconnect, WebSocketException, status
from pydantic import BaseModel, Field, ValidationError

# Опциональные зависимости (без жёсткой привязки)
with contextlib.suppress(Exception):
    from opentelemetry import trace  # type: ignore
    _TRACER = trace.get_tracer("ledger-core.ws")
else:
    _TRACER = None  # type: ignore

try:
    from jsonschema import validate as jsonschema_validate  # type: ignore
    _HAS_JSONSCHEMA = True
except Exception:  # pragma: no cover
    _HAS_JSONSCHEMA = False

router = APIRouter(prefix="/ws", tags=["ws"])

# ------------------------------- Модели и типы -------------------------------

class WSAuthResult(BaseModel):
    user_id: str
    scopes: Set[str] = Field(default_factory=set)


AuthFunc = Callable[[str], Awaitable[WSAuthResult]]
PublishHook = Callable[[str, Mapping[str, Any]], Awaitable[None]]
OnConnectHook = Callable[[str, "WSConnection"], Awaitable[None]]
OnDisconnectHook = Callable[[str, "WSConnection"], Awaitable[None]]

@dataclass
class RateLimiter:
    capacity: int
    refill_per_sec: float
    tokens: float = field(init=False)
    last_ts: float = field(default_factory=time.monotonic)

    def __post_init__(self) -> None:
        self.tokens = float(self.capacity)

    def allow(self, n: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_ts
        self.last_ts = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_sec)
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False

@dataclass
class OutboxQueue:
    max_messages: int
    queue: asyncio.Queue = field(init=False)

    def __post_init__(self) -> None:
        self.queue = asyncio.Queue(self.max_messages)

    async def put(self, item: Tuple[str, bytes]) -> None:
        try:
            self.queue.put_nowait(item)
        except asyncio.QueueFull:
            # Старейшее сообщение вытесняем, чтобы не копить неактуальные
            with contextlib.suppress(Exception):
                _ = self.queue.get_nowait()
            await self.queue.put(item)

    async def get(self) -> Tuple[str, bytes]:
        return await self.queue.get()

    def qsize(self) -> int:
        return self.queue.qsize()

@dataclass
class ReplayBuffer:
    """Буфер переигрывания сообщений для resume по last_event_id."""
    max_events: int = 1000
    events: List[Tuple[str, bytes]] = field(default_factory=list)

    def append(self, event_id: str, payload: bytes) -> None:
        self.events.append((event_id, payload))
        if len(self.events) > self.max_events:
            self.events.pop(0)

    def iter_from(self, last_event_id: Optional[str]) -> List[Tuple[str, bytes]]:
        if not last_event_id:
            return []
        try:
            idx = next(i for i, (eid, _) in enumerate(self.events) if eid == last_event_id)
        except StopIteration:
            return []
        return self.events[idx + 1 :]

@dataclass
class WSConnection:
    ws: WebSocket
    user_id: str
    scopes: Set[str]
    channels: Set[str] = field(default_factory=set)
    outbox: OutboxQueue = field(default_factory=lambda: OutboxQueue(max_messages=1024))
    last_pong: float = field(default_factory=time.monotonic)
    limiter_send: RateLimiter = field(default_factory=lambda: RateLimiter(capacity=200, refill_per_sec=50))
    limiter_recv: RateLimiter = field(default_factory=lambda: RateLimiter(capacity=100, refill_per_sec=25))
    # ack ожидаемые идентификаторы
    awaiting_ack: Dict[str, float] = field(default_factory=dict)

# ------------------------------- Менеджер каналов ----------------------------

class ChannelManager:
    def __init__(
        self,
        *,
        auth_func: AuthFunc,
        enforce_scopes: Mapping[str, str] | None = None,
        message_schema: Optional[Mapping[str, Any]] = None,
        publish_hook: Optional[PublishHook] = None,
        on_connect: Optional[OnConnectHook] = None,
        on_disconnect: Optional[OnDisconnectHook] = None,
        heartbeat_interval: float = 15.0,
        idle_timeout: float = 300.0,
        replay_buffer_size: int = 2000,
    ) -> None:
        self._auth = auth_func
        self._enforce_scopes = enforce_scopes or {}
        self._message_schema = message_schema
        self._publish_hook = publish_hook
        self._on_connect = on_connect
        self._on_disconnect = on_disconnect
        self._heartbeat_interval = heartbeat_interval
        self._idle_timeout = idle_timeout
        self._replay = ReplayBuffer(max_events=replay_buffer_size)

        # состояние
        self._lock = asyncio.Lock()
        self._channels: Dict[str, Set[WSConnection]] = {}
        self._connections: Set[WSConnection] = set()

    # ---------------------- публичные операции ----------------------

    async def connect(
        self,
        ws: WebSocket,
        token: str,
        *,
        requested_channels: Optional[List[str]] = None,
        last_event_id: Optional[str] = None,
    ) -> WSConnection:
        auth = await self._auth(token)
        await ws.accept(subprotocol="ledger.ws.v1")
        conn = WSConnection(ws=ws, user_id=auth.user_id, scopes=auth.scopes)
        async with self._lock:
            self._connections.add(conn)
            if requested_channels:
                for ch in requested_channels:
                    await self._join_channel(conn, ch)
        if last_event_id:
            # Дошлём пропущенные сообщения
            for eid, payload in self._replay.iter_from(last_event_id):
                await conn.outbox.put((eid, payload))
        if self._on_connect:
            await self._on_connect(auth.user_id, conn)
        # Запускаем фоновые таски отправки и heartbeat
        asyncio.create_task(self._sender_loop(conn))
        asyncio.create_task(self._heartbeat_loop(conn))
        return conn

    async def disconnect(self, conn: WSConnection) -> None:
        async with self._lock:
            for ch in list(conn.channels):
                await self._leave_channel(conn, ch)
            with contextlib.suppress(KeyError):
                self._connections.remove(conn)
        if self._on_disconnect:
            await self._on_disconnect(conn.user_id, conn)
        with contextlib.suppress(Exception):
            await conn.ws.close(code=status.WS_1000_NORMAL_CLOSURE)

    async def publish(
        self,
        channel: str,
        message: Mapping[str, Any],
        *,
        require_scope: Optional[str] = None,
        event_id: Optional[str] = None,
        ack_required: bool = False,
    ) -> int:
        """
        Публикация в канал. Возвращает число получателей.
        """
        if self._message_schema and _HAS_JSONSCHEMA:
            jsonschema_validate(instance=message, schema=self._message_schema)  # type: ignore

        if require_scope:
            # Проверку делаем при доставке индивидуально.

            pass

        payload = self._encode_message(channel=channel, message=message, ack=ack_required)
        eid = event_id or self._gen_event_id()
        self._replay.append(eid, payload)

        async with self._lock:
            conns = list(self._channels.get(channel, set()))
        delivered = 0
        for c in conns:
            if require_scope and require_scope not in c.scopes:
                continue
            await c.outbox.put((eid, payload))
            if ack_required:
                c.awaiting_ack[eid] = time.monotonic()
            delivered += 1
        if self._publish_hook:
            await self._publish_hook(channel, message)
        return delivered

    async def join(self, conn: WSConnection, channel: str) -> None:
        await self._join_channel(conn, channel)

    async def leave(self, conn: WSConnection, channel: str) -> None:
        await self._leave_channel(conn, channel)

    # ---------------------- внутренние утилиты ----------------------

    async def _join_channel(self, conn: WSConnection, channel: str) -> None:
        # Проверка scope на подписку
        scope = self._enforce_scopes.get(channel)
        if scope and scope not in conn.scopes:
            raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION, reason="insufficient_scope")
        async with self._lock:
            conn.channels.add(channel)
            self._channels.setdefault(channel, set()).add(conn)

    async def _leave_channel(self, conn: WSConnection, channel: str) -> None:
        async with self._lock:
            with contextlib.suppress(KeyError):
                self._channels[channel].remove(conn)
                if not self._channels[channel]:
                    del self._channels[channel]
            conn.channels.discard(channel)

    def _gen_event_id(self) -> str:
        # lexicographically increasing (time prefix) + random suffix
        ts = int(time.time() * 1000)
        rnd = secrets.token_hex(4)
        return f"{ts}-{rnd}"

    def _encode_message(self, *, channel: str, message: Mapping[str, Any], ack: bool) -> bytes:
        envelope = {
            "channel": channel,
            "id": self._gen_event_id(),
            "ts": int(time.time() * 1000),
            "ack": bool(ack),
            "data": message,
        }
        return (json.dumps(envelope, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")

    async def _sender_loop(self, conn: WSConnection) -> None:
        try:
            while True:
                event_id, payload = await conn.outbox.get()
                if not conn.limiter_send.allow():
                    # Блокируемся коротко, чтобы не «съесть» CPU
                    await asyncio.sleep(0.02)
                await conn.ws.send_bytes(payload)
        except WebSocketDisconnect:
            await self.disconnect(conn)
        except Exception:  # noqa: BLE001
            await self.disconnect(conn)

    async def _heartbeat_loop(self, conn: WSConnection) -> None:
        try:
            while True:
                await asyncio.sleep(self._heartbeat_interval)
                # ping-pong
                await conn.ws.send_json({"type": "ping", "ts": int(time.time() * 1000)})
                # idle timeout
                if time.monotonic() - conn.last_pong > self._idle_timeout:
                    await conn.ws.close(code=status.WS_1001_GOING_AWAY)
                    break
        except WebSocketDisconnect:
            with contextlib.suppress(Exception):
                await self.disconnect(conn)
        except Exception:
            with contextlib.suppress(Exception):
                await self.disconnect(conn)

# ------------------------------- Хендлер WebSocket ----------------------------

# Конфиг по умолчанию: можно переопределить при инициализации приложения
DEFAULT_MANAGER: Optional[ChannelManager] = None

async def _default_auth(token: str) -> WSAuthResult:
    # Заглушка. Подключите свой валидатор JWT/сессии.
    if not token:
        raise HTTPException(status_code=401, detail="missing token")
    # Пример: user_id в токене и пустые скоупы
    return WSAuthResult(user_id="anon", scopes=set())

def init_default_manager(
    *,
    auth_func: AuthFunc | None = None,
    enforce_scopes: Mapping[str, str] | None = None,
    message_schema: Optional[Mapping[str, Any]] = None,
    publish_hook: Optional[PublishHook] = None,
    on_connect: Optional[OnConnectHook] = None,
    on_disconnect: Optional[OnDisconnectHook] = None,
    heartbeat_interval: float = 15.0,
    idle_timeout: float = 300.0,
    replay_buffer_size: int = 2000,
) -> ChannelManager:
    global DEFAULT_MANAGER
    DEFAULT_MANAGER = ChannelManager(
        auth_func=auth_func or _default_auth,
        enforce_scopes=enforce_scopes,
        message_schema=message_schema,
        publish_hook=publish_hook,
        on_connect=on_connect,
        on_disconnect=on_disconnect,
        heartbeat_interval=heartbeat_interval,
        idle_timeout=idle_timeout,
        replay_buffer_size=replay_buffer_size,
    )
    return DEFAULT_MANAGER

def get_manager() -> ChannelManager:
    if DEFAULT_MANAGER is None:
        return init_default_manager()
    return DEFAULT_MANAGER

# ------------------------------- Протокол сообщений ---------------------------
# Клиент -> сервер (JSON строка):
# { "type": "subscribe", "channels": ["ledger.audit.v1"] }
# { "type": "unsubscribe", "channels": ["ledger.audit.v1"] }
# { "type": "ack", "id": "<event_id>" }
# { "type": "pong", "ts": 1690000000000 }
# { "type": "publish", "channel": "ledger.chat", "data": {...}, "ack": false }
#
# Сервер -> клиент (NDJSON, одна запись на строку) уже содержит конверт с полями:
# { "channel": "...", "id": "...", "ts": 169..., "ack": false, "data": {...} }

@router.websocket("/channels")
async def ws_channels(
    ws: WebSocket,
    authorization: Optional[str] = Header(None, convert_underscores=False),
    last_event_id: Optional[str] = Header(None, alias="Last-Event-Id"),
    x_channels: Optional[str] = Header(None, alias="X-Channels"),
    manager: ChannelManager = Depends(get_manager),
) -> None:
    # Аутентификация
    token = ""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1]
    auth = await manager._auth(token)  # используем напрямую, т.к. Depends не применим к токену из Header

    # Разбор начальных каналов
    requested_channels: List[str] = []
    if x_channels:
        try:
            requested_channels = [c.strip() for c in x_channels.split(",") if c.strip()]
        except Exception:
            requested_channels = []

    # Принимаем соединение и повторяем пропущенные события
    await ws.accept(subprotocol="ledger.ws.v1")
    conn = WSConnection(ws=ws, user_id=auth.user_id, scopes=auth.scopes)
    # Присоединяемся к каналам
    for ch in requested_channels:
        await manager.join(conn, ch)

    # Дошлём пропущенные события
    if last_event_id:
        for eid, payload in manager._replay.iter_from(last_event_id):
            await conn.outbox.put((eid, payload))

    # Запускаем фоновые циклы
    asyncio.create_task(manager._sender_loop(conn))
    asyncio.create_task(manager._heartbeat_loop(conn))

    # Основной цикл приёма
    try:
        while True:
            raw = await ws.receive_text()
            conn.last_pong = time.monotonic()
            if not conn.limiter_recv.allow():
                # слишком частые сообщения от клиента
                await ws.close(code=status.WS_1011_INTERNAL_ERROR)
                break

            try:
                msg = json.loads(raw)
                mtype = msg.get("type")
            except Exception:
                raise WebSocketException(code=status.WS_1003_UNSUPPORTED_DATA, reason="invalid_json")

            if mtype == "subscribe":
                channels = msg.get("channels") or []
                if not isinstance(channels, list):
                    raise WebSocketException(code=status.WS_1007_INVALID_FRAME_PAYLOAD_DATA, reason="invalid_channels")
                for ch in channels:
                    await manager.join(conn, ch)

            elif mtype == "unsubscribe":
                channels = msg.get("channels") or []
                if not isinstance(channels, list):
                    raise WebSocketException(code=status.WS_1007_INVALID_FRAME_PAYLOAD_DATA, reason="invalid_channels")
                for ch in channels:
                    await manager.leave(conn, ch)

            elif mtype == "ack":
                eid = msg.get("id")
                if isinstance(eid, str) and eid in conn.awaiting_ack:
                    del conn.awaiting_ack[eid]

            elif mtype == "pong":
                # уже учли last_pong, ничего не делаем
                pass

            elif mtype == "publish":
                # Публикация от клиента (если разрешено политикой)
                channel = msg.get("channel")
                data = msg.get("data")
                ack = bool(msg.get("ack", False))
                if not isinstance(channel, str) or not isinstance(data, (dict, list)):
                    raise WebSocketException(code=status.WS_1007_INVALID_FRAME_PAYLOAD_DATA, reason="invalid_publish")
                # Проверка прав: клиент может публиковать только в каналы, на которые подписан и имеет scope (если нужен)
                if channel not in conn.channels:
                    raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION, reason="not_subscribed")
                require_scope = manager._enforce_scopes.get(channel)
                if require_scope and require_scope not in conn.scopes:
                    raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION, reason="insufficient_scope")
                await manager.publish(channel, data, require_scope=None, ack_required=ack)

            else:
                # неизвестный тип
                raise WebSocketException(code=status.WS_1003_UNSUPPORTED_DATA, reason="unknown_message_type")

    except WebSocketDisconnect:
        await manager.disconnect(conn)
    except WebSocketException:
        with contextlib.suppress(Exception):
            await manager.disconnect(conn)
        raise
    except Exception:
        with contextlib.suppress(Exception):
            await manager.disconnect(conn)
        raise

# ------------------------------- Пример интеграции ---------------------------
# from fastapi import FastAPI
# from ledger_core.api.ws.channels import router, init_default_manager
#
# async def my_auth(jwt: str) -> WSAuthResult:
#     # Вставьте верификацию JWT/сессии и разбор scope
#     return WSAuthResult(user_id="u123", scopes={"audit:read", "chat:write"})
#
# app = FastAPI()
# init_default_manager(
#     auth_func=my_auth,
#     enforce_scopes={"ledger.audit.v1": "audit:read", "ledger.chat": "chat:write"},
#     message_schema={  # опционально: схема для publish
#         "type": "object",
#         "properties": {"text": {"type": "string"}},
#         "required": ["text"],
#         "additionalProperties": False,
#     },
# )
# app.include_router(router)
#
# Клиент:
# const ws = new WebSocket("wss://example/ws/channels", ["ledger.ws.v1"]);
# ws.onmessage = e => console.log(e.data); // NDJSON строки
# ws.onopen = () => {
#   ws.send(JSON.stringify({ type: "subscribe", channels: ["ledger.audit.v1"] }));
# }
