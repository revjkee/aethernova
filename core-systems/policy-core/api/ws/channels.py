# policy-core/api/ws/channels.py
# Статус: НЕ ВЕРИФИЦИРОВАНО — рассчитано на FastAPI/Starlette. Адаптируйте под ваш стек при необходимости.
# Назначение: промышленная реализация WebSocket-каналов с безопасностью, QoS и наблюдаемостью.

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Set, Tuple

try:
    from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
    from fastapi import Depends
    from fastapi import Query
except Exception as e:  # pragma: no cover
    raise RuntimeError("channels.py требует FastAPI/Starlette") from e

LOG = logging.getLogger("policy_core.ws")

# ----------------------------
# Конфигурация (через ENV)
# ----------------------------
WS_ALLOWED_ORIGINS = {o.strip().lower() for o in os.getenv("WS_ALLOWED_ORIGINS", "").split(",") if o.strip()}
WS_ALLOWED_SUBPROTOCOLS = [p.strip() for p in os.getenv("WS_ALLOWED_SUBPROTOCOLS", "policy-core.v1,json").split(",")]
WS_MESSAGE_MAX_BYTES = int(os.getenv("WS_MESSAGE_MAX_BYTES", "131072"))  # 128 KiB
WS_SEND_QUEUE_MAX = int(os.getenv("WS_SEND_QUEUE_MAX", "1000"))
WS_RATE_CAPACITY = int(os.getenv("WS_RATE_CAPACITY", "120"))  # сообщений
WS_RATE_REFILL_PER_SEC = float(os.getenv("WS_RATE_REFILL_PER_SEC", "30.0"))
WS_PING_INTERVAL_SEC = float(os.getenv("WS_PING_INTERVAL_SEC", "20.0"))
WS_PONG_TIMEOUT_SEC = float(os.getenv("WS_PONG_TIMEOUT_SEC", "15.0"))
WS_CHANNEL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_\-:.]{0,127}$")

# ----------------------------
# Типы и контракты
# ----------------------------
AuthContext = Dict[str, Any]
AuthFunc = Callable[[WebSocket], Awaitable[AuthContext]]
AuthorizeFunc = Callable[[AuthContext, str, str], Awaitable[bool]]  # (auth, channel, action) -> bool
MetricsHook = Callable[[str, Mapping[str, str]], None]  # name, tags

# Структура сообщений по проволоке.
# Клиент -> сервер:
#   {"op":"subscribe","channels":["room:1", "..."], "id":"..."}
#   {"op":"unsubscribe","channels":[...], "id":"..."}
#   {"op":"publish","channel":"room:1","event":"msg","data":{...}, "id":"..."}
#   {"op":"ping","id":"..."}
# Сервер -> клиент:
#   {"op":"ack","id":"...","ok":true}
#   {"op":"event","channel":"room:1","event":"msg","data":{...}}
#   {"op":"pong","id":"...","ts":...}
#   {"op":"error","id":"...","code":"rate_limited","detail":"..."}

@dataclass
class RateLimiter:
    capacity: int
    refill_per_sec: float
    tokens: float = field(default=0.0)
    last: float = field(default_factory=time.monotonic)

    def allow(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self.last
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_sec)
        self.last = now
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


@dataclass
class Connection:
    id: str
    ws: WebSocket
    auth: AuthContext
    rate: RateLimiter
    send_q: "asyncio.Queue[str]"
    last_pong: float = field(default_factory=time.monotonic)
    subprotocol: Optional[str] = None

    @property
    def alive(self) -> bool:
        return (time.monotonic() - self.last_pong) < (WS_PING_INTERVAL_SEC + WS_PONG_TIMEOUT_SEC)


class MemoryBroker:
    """
    Простейший in-memory pub/sub для каналов.
    Не предназначен для межпроцессного горизонтального масштабирования.
    """
    def __init__(self) -> None:
        self._channels: Dict[str, Set[str]] = {}  # channel -> set(connection_id)
        self._lock = asyncio.Lock()

    async def join(self, channel: str, conn_id: str) -> None:
        async with self._lock:
            self._channels.setdefault(channel, set()).add(conn_id)

    async def leave(self, channel: str, conn_id: str) -> None:
        async with self._lock:
            if channel in self._channels:
                self._channels[channel].discard(conn_id)
                if not self._channels[channel]:
                    self._channels.pop(channel, None)

    async def members(self, channel: str) -> Set[str]:
        async with self._lock:
            return set(self._channels.get(channel, set()))

    async def member_count(self, channel: str) -> int:
        async with self._lock:
            return len(self._channels.get(channel, set()))

    async def channels_for(self, conn_id: str) -> Set[str]:
        async with self._lock:
            return {c for c, members in self._channels.items() if conn_id in members}

    async def leave_all(self, conn_id: str) -> None:
        async with self._lock:
            for c in list(self._channels.keys()):
                self._channels[c].discard(conn_id)
                if not self._channels[c]:
                    self._channels.pop(c, None)


class ChannelManager:
    """
    Управляет подключениями, подписками и публикацией событий.
    """
    def __init__(
        self,
        authorize: Optional[AuthorizeFunc] = None,
        metrics: Optional[MetricsHook] = None,
    ) -> None:
        self._broker = MemoryBroker()
        self._conns: Dict[str, Connection] = {}
        self._lock = asyncio.Lock()
        self._authorize = authorize
        self._metrics = metrics

    # ------------- Метрики и лог -------------

    def _emit(self, name: str, **tags: str) -> None:
        if self._metrics:
            try:
                self._metrics(name, {k: str(v) for k, v in tags.items()})
            except Exception:
                LOG.debug("metrics hook failed", exc_info=True)

    # ------------- Управление соединениями -------------

    async def register(self, conn: Connection) -> None:
        async with self._lock:
            self._conns[conn.id] = conn
        self._emit("ws_connect", conn_id=conn.id, subprotocol=str(conn.subprotocol))

    async def unregister(self, conn_id: str) -> None:
        await self._broker.leave_all(conn_id)
        async with self._lock:
            self._conns.pop(conn_id, None)
        self._emit("ws_disconnect", conn_id=conn_id)

    async def get(self, conn_id: str) -> Optional[Connection]:
        async with self._lock:
            return self._conns.get(conn_id)

    # ------------- Подписки -------------

    async def subscribe(self, conn: Connection, channels: Iterable[str]) -> Tuple[List[str], List[str]]:
        ok, failed = [], []
        for ch in channels:
            if not WS_CHANNEL_NAME_RE.match(ch):
                failed.append(ch)
                continue
            if self._authorize and not await self._authorize(conn.auth, ch, "subscribe"):
                failed.append(ch)
                continue
            await self._broker.join(ch, conn.id)
            ok.append(ch)
            self._emit("ws_subscribe", channel=ch)
        return ok, failed

    async def unsubscribe(self, conn: Connection, channels: Iterable[str]) -> Tuple[List[str], List[str]]:
        ok, failed = [], []
        for ch in channels:
            try:
                await self._broker.leave(ch, conn.id)
                ok.append(ch)
                self._emit("ws_unsubscribe", channel=ch)
            except Exception:
                failed.append(ch)
        return ok, failed

    # ------------- Публикация -------------

    async def publish(self, channel: str, event: str, data: Any, sender: Optional[str] = None) -> int:
        if not WS_CHANNEL_NAME_RE.match(channel):
            return 0
        members = await self._broker.members(channel)
        delivered = 0
        payload = json.dumps({"op": "event", "channel": channel, "event": event, "data": data}, separators=(",", ":"), ensure_ascii=False)
        if len(payload.encode("utf-8")) > WS_MESSAGE_MAX_BYTES:
            LOG.warning("drop publish: payload too large channel=%s bytes=%s", channel, len(payload.encode("utf-8")))
            self._emit("ws_publish_dropped", reason="too_large")
            return 0
        async with self._lock:
            for conn_id in members:
                if sender and conn_id == sender:
                    continue  # по желанию: не дублировать отправителю
                conn = self._conns.get(conn_id)
                if not conn:
                    continue
                try:
                    conn.send_q.put_nowait(payload)
                    delivered += 1
                except asyncio.QueueFull:
                    # Backpressure: дропаем сообщение для перегруженного клиента
                    self._emit("ws_backpressure_drop", conn_id=conn_id, channel=channel)
        return delivered


# ----------------------------
# Помощники по безопасности
# ----------------------------

def _check_origin(ws: WebSocket) -> bool:
    if not WS_ALLOWED_ORIGINS:
        return True
    origin = (ws.headers.get("origin") or "").lower()
    return origin in WS_ALLOWED_ORIGINS


def _negotiate_subprotocol(ws: WebSocket) -> Optional[str]:
    requested = [p.strip() for p in (ws.headers.get("sec-websocket-protocol") or "").split(",") if p.strip()]
    for p in requested:
        if p in WS_ALLOWED_SUBPROTOCOLS:
            return p
    # Если клиент ничего не запросил — можно выбрать дефолтный
    return WS_ALLOWED_SUBPROTOCOLS[0] if WS_ALLOWED_SUBPROTOCOLS else None


def _pick_request_id(ws: WebSocket) -> str:
    for h in ("x-request-id", "x-correlation-id"):
        v = ws.headers.get(h)
        if v:
            return v[:128]
    return str(uuid.uuid4())


def _json_or_error(text: str) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(text)
    except Exception:
        return None


# ----------------------------
# Основной обработчик WS
# ----------------------------

def create_ws_router(
    auth: AuthFunc,
    manager: Optional[ChannelManager] = None,
    *,
    authorize: Optional[AuthorizeFunc] = None,
    metrics: Optional[MetricsHook] = None,
    path: str = "/ws",
) -> APIRouter:
    """
    Создаёт APIRouter с WS-эндпоинтом.
    auth: async(WebSocket) -> AuthContext — обязан аутентифицировать клиента и
          при необходимости поднять исключение (или вернуть {"user_id": "..."} и т.п.).
    authorize: async(auth, channel, action) -> bool — доп. проверка прав на канал.
    """
    router = APIRouter()
    mgr = manager or ChannelManager(authorize=authorize, metrics=metrics)

    @router.websocket(path)
    async def websocket_endpoint(
        websocket: WebSocket,
        initial_channels: Optional[str] = Query(default=None, description="CSV список каналов для авто-подписки"),
    ) -> None:
        if not _check_origin(websocket):
            # Нежелательный Origin
            await websocket.close(code=4403)  # 4403 — Forbidden (non-standard)
            return

        subprotocol = _negotiate_subprotocol(websocket)

        # Аутентификация до accept() небезопасна — заголовки недоступны после апгрейда.
        # В FastAPI можно вызывать accept() позднее.
        auth_ctx: AuthContext = {}
        try:
            auth_ctx = await auth(websocket)
        except Exception:
            # Не разглашаем детали
            await websocket.close(code=4401)  # 4401 — Unauthorized (non-standard)
            return

        await websocket.accept(subprotocol=subprotocol)
        req_id = _pick_request_id(websocket)

        conn = Connection(
            id=str(uuid.uuid4()),
            ws=websocket,
            auth=auth_ctx,
            rate=RateLimiter(capacity=WS_RATE_CAPACITY, refill_per_sec=WS_RATE_REFILL_PER_SEC),
            send_q=asyncio.Queue(maxsize=WS_SEND_QUEUE_MAX),
            subprotocol=subprotocol,
        )
        await mgr.register(conn)

        # Авто-подписка
        if initial_channels:
            channels = [c.strip() for c in initial_channels.split(",") if c.strip()]
            ok, failed = await mgr.subscribe(conn, channels)
            if ok:
                await _safe_send(conn, {"op": "ack", "id": "subscribe:init", "ok": True, "channels": ok})
            if failed:
                await _safe_send(conn, {"op": "error", "id": "subscribe:init", "code": "subscribe_failed", "channels": failed})

        # Запускаем фоновые задачи: приём и отправка
        send_task = asyncio.create_task(_sender_loop(mgr, conn))
        recv_task = asyncio.create_task(_receiver_loop(mgr, conn, req_id))
        ping_task = asyncio.create_task(_heartbeat_loop(conn))

        try:
            await asyncio.wait(
                {send_task, recv_task, ping_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            for t in (send_task, recv_task, ping_task):
                if not t.done():
                    t.cancel()
            await mgr.unregister(conn.id)
            try:
                await websocket.close()
            except Exception:
                pass

    return router


# ----------------------------
# Фоновые циклы
# ----------------------------

async def _sender_loop(manager: ChannelManager, conn: Connection) -> None:
    """
    Отправляет сообщения из очереди в сокет.
    Backpressure: если клиент не успевает — сообщения дропаются на этапе put_nowait в publish().
    """
    while True:
        payload = await conn.send_q.get()
        try:
            await conn.ws.send_text(payload)
        except Exception:
            # Сокет вероятно закрыт
            return


async def _receiver_loop(manager: ChannelManager, conn: Connection, req_id: str) -> None:
    """
    Читает входящие сообщения, применяет rate limiting и маршрутизирует операции.
    """
    while True:
        try:
            text = await conn.ws.receive_text()
        except WebSocketDisconnect:
            return
        except Exception:
            return

        if len(text.encode("utf-8")) > WS_MESSAGE_MAX_BYTES:
            await _safe_send(conn, {"op": "error", "code": "payload_too_large", "detail": "message exceeds limit"})
            continue

        if not conn.rate.allow(1.0):
            await _safe_send(conn, {"op": "error", "code": "rate_limited", "detail": "too many messages"})
            continue

        msg = _json_or_error(text)
        if not isinstance(msg, dict):
            await _safe_send(conn, {"op": "error", "code": "invalid_json"})
            continue

        op = str(msg.get("op", "")).lower()
        mid = str(msg.get("id", "")) if "id" in msg else None

        if op == "ping":
            conn.last_pong = time.monotonic()  # принимаем ping как сигнал активности
            await _safe_send(conn, {"op": "pong", "id": mid or "", "ts": int(time.time() * 1000)})
            continue

        if op == "subscribe":
            channels = _normalize_channels(msg.get("channels"))
            ok, failed = await manager.subscribe(conn, channels)
            await _safe_send(conn, {"op": "ack", "id": mid or "", "ok": True, "channels": ok})
            if failed:
                await _safe_send(conn, {"op": "error", "id": mid or "", "code": "subscribe_failed", "channels": failed})
            continue

        if op == "unsubscribe":
            channels = _normalize_channels(msg.get("channels"))
            ok, failed = await manager.unsubscribe(conn, channels)
            await _safe_send(conn, {"op": "ack", "id": mid or "", "ok": True, "channels": ok})
            if failed:
                await _safe_send(conn, {"op": "error", "id": mid or "", "code": "unsubscribe_failed", "channels": failed})
            continue

        if op == "publish":
            channel = str(msg.get("channel", ""))
            event = str(msg.get("event", "message"))
            data = msg.get("data", {})
            # Авторизация публикации
            if manager._authorize and not await manager._authorize(conn.auth, channel, "publish"):
                await _safe_send(conn, {"op": "error", "id": mid or "", "code": "forbidden"})
                continue
            sent = await manager.publish(channel, event, data, sender=conn.id)
            await _safe_send(conn, {"op": "ack", "id": mid or "", "ok": True, "delivered": sent})
            continue

        await _safe_send(conn, {"op": "error", "id": mid or "", "code": "unknown_op", "detail": f"op={op}"})


async def _heartbeat_loop(conn: Connection) -> None:
    """
    Периодически посылает ping. Если долго нет pong/активности — закрывает соединение.
    """
    while True:
        await asyncio.sleep(WS_PING_INTERVAL_SEC)
        try:
            # Если клиент не отвечает — закрываем
            idle = time.monotonic() - conn.last_pong
            if idle > (WS_PING_INTERVAL_SEC + WS_PONG_TIMEOUT_SEC):
                await conn.ws.close(code=1011)  # Internal Error/timeout
                return
            # Отправляем ping как обычное сообщение по протоколу поверх текстового канала
            await _safe_send(conn, {"op": "ping", "ts": int(time.time() * 1000)})
        except Exception:
            return


# ----------------------------
# Утилиты
# ----------------------------

def _normalize_channels(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        items = [v.strip() for v in value.split(",")]
    else:
        items = [str(v).strip() for v in value if str(v).strip()]
    # Валидация имени
    return [c for c in items if WS_CHANNEL_NAME_RE.match(c)]


async def _safe_send(conn: Connection, obj: Mapping[str, Any]) -> None:
    try:
        payload = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
        if len(payload.encode("utf-8")) > WS_MESSAGE_MAX_BYTES:
            return
        await conn.ws.send_text(payload)
    except Exception:
        # Игнорируем — сокет мог закрыться
        return


# ----------------------------
# Пример интеграции (докстрока)
# ----------------------------
"""
# app_ws.py
from fastapi import FastAPI, WebSocket
from policy_core.api.ws.channels import create_ws_router, ChannelManager

app = FastAPI()

# Аутентификация: извлекаем токен из заголовка Authorization или query-параметров.
async def auth(ws: WebSocket):
    token = ws.headers.get("authorization") or ws.query_params.get("token")
    if not token:
        raise RuntimeError("no token")
    # В реальном коде: верифицируйте JWT/сессию и верните контекст.
    return {"user_id": "u123", "scopes": ["chat:read", "chat:write"]}

# Авторизация по каналам/действиям.
async def authorize(auth_ctx, channel: str, action: str) -> bool:
    # Пример: разрешаем подписку на room:* и публикацию только на room:{user_id}
    if action == "subscribe" and channel.startswith("room:"):
        return True
    if action == "publish" and channel == f"room:{auth_ctx.get('user_id')}":
        return True
    return False

router = create_ws_router(auth=auth, authorize=authorize, path="/ws")
app.include_router(router)
"""
