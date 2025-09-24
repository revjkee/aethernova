# -*- coding: utf-8 -*-
"""
VeilMind Core — WebSocket Channels (v1)
Промышленный модуль реального времени для FastAPI:
- Bearer/Query/Cookie токены, проверка Origin (CORS для WS)
- Подписки/отписки на каналы, публикации, присутствие
- Rate limiting (token bucket) и backpressure (bounded queue)
- Heartbeat (server ping) и контроль тайм-аутов
- Абстрактный брокер (in-memory; опционально Redis, если установлен redis>=4)
- Метрики Prometheus и трассировка OpenTelemetry (мягкие импорты)
- Безопасная JSON сериализация (orjson, falling back to stdlib json)

ENV:
  VEILMIND_WS_ALLOWED_ORIGINS="*" | "https://a.example,https://b.example"
  VEILMIND_WS_DISABLE_AUTH="false" | "true"
  VEILMIND_AUTH_HS256="shared-secret"   # для простого HS256 JWT (опционально)
  VEILMIND_REDIS_URL="redis://localhost:6379/0"  # если нужен RedisBroker
  VEILMIND_WS_BROKER="memory" | "redis"
  VEILMIND_WS_HEARTBEAT_SECONDS="25"
  VEILMIND_WS_MAX_MSG_SIZE="65536"       # байты
  VEILMIND_WS_QUEUE_SIZE="1000"          # элементов на клиента
  VEILMIND_WS_RATE_CAPACITY="60"         # токенов
  VEILMIND_WS_RATE_REFILL_PER_SEC="1"    # пополнение токенов/сек

Подключение:
    from veilmind_core.api.ws.channels import router
    app.include_router(router)

Автор: VeilMind Team
"""

from __future__ import annotations

import asyncio
import json as _json
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Set, Tuple

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from fastapi.websockets import WebSocketState
from pydantic import BaseModel, Field, ConfigDict

# ---------- optional deps ----------
try:
    import orjson

    def _dumps(obj: Any) -> str:
        return orjson.dumps(obj, option=orjson.OPT_NON_STR_KEYS | orjson.OPT_SERIALIZE_DATACLASS).decode()

    def _loads(data: str) -> Any:
        return orjson.loads(data)

except Exception:  # pragma: no cover
    def _dumps(obj: Any) -> str:
        return _json.dumps(obj, separators=(",", ":"), ensure_ascii=False)

    def _loads(data: str) -> Any:
        return _json.loads(data)

try:
    from prometheus_client import Counter, Gauge  # type: ignore

    _PROM = True
    WS_CONN = Gauge("veilmind_ws_connections", "Active WS connections")
    WS_SUBS = Gauge("veilmind_ws_subscriptions", "Active subscriptions")
    WS_MSG_IN = Counter("veilmind_ws_messages_in_total", "Inbound messages", ["op"])
    WS_MSG_OUT = Counter("veilmind_ws_messages_out_total", "Outbound messages", ["op"])
    WS_DROP = Counter("veilmind_ws_dropped_total", "Dropped messages", ["reason"])
    WS_AUTH_FAIL = Counter("veilmind_ws_auth_fail_total", "Auth failures", ["reason"])
    WS_RATE_LIMIT = Counter("veilmind_ws_rate_limit_total", "Rate limit exceeded", ["op"])
except Exception:  # pragma: no cover
    _PROM = False

try:
    from opentelemetry import trace  # type: ignore

    _TR = True
    _tracer = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _TR = False
    _tracer = None  # type: ignore

# ---------- config ----------
ALLOWED_ORIGINS: Optional[Set[str]] = None
_raw_origins = os.getenv("VEILMIND_WS_ALLOWED_ORIGINS", "*").strip()
if _raw_origins != "*":
    ALLOWED_ORIGINS = {o.strip().lower() for o in _raw_origins.split(",") if o.strip()}

DISABLE_AUTH = os.getenv("VEILMIND_WS_DISABLE_AUTH", "false").lower() == "true"
AUTH_HS256 = os.getenv("VEILMIND_AUTH_HS256", "").strip() or None
BROKER_KIND = os.getenv("VEILMIND_WS_BROKER", "memory").strip().lower()
REDIS_URL = os.getenv("VEILMIND_REDIS_URL", "").strip() or None

HEARTBEAT_SECONDS = int(os.getenv("VEILMIND_WS_HEARTBEAT_SECONDS", "25"))
MAX_MSG_SIZE = int(os.getenv("VEILMIND_WS_MAX_MSG_SIZE", "65536"))
QUEUE_SIZE = int(os.getenv("VEILMIND_WS_QUEUE_SIZE", "1000"))
RATE_CAPACITY = int(os.getenv("VEILMIND_WS_RATE_CAPACITY", "60"))
RATE_REFILL_PER_SEC = float(os.getenv("VEILMIND_WS_RATE_REFILL_PER_SEC", "1"))

# ---------- security helpers ----------

class AuthError(Exception):
    def __init__(self, reason: str, code: int = 4001):
        super().__init__(reason)
        self.reason = reason
        self.code = code

def _origin_ok(ws: WebSocket) -> bool:
    if ALLOWED_ORIGINS is None:
        return True
    origin = (ws.headers.get("origin") or "").lower()
    return origin in ALLOWED_ORIGINS

def _extract_token(ws: WebSocket) -> Optional[str]:
    auth = ws.headers.get("authorization") or ws.query_params.get("token") or ws.cookies.get("token")
    if not auth:
        return None
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return auth.strip()

def _validate_token(token: Optional[str]) -> Tuple[str, List[str]]:
    """
    Возвращает (subject, scopes). В выключенном режиме аутентификации — 'anon'.
    HS256: требует установленный VEILMIND_AUTH_HS256 и claim 'sub'.
    Для локальных тестов допускает префикс "test-" => sub="test".
    """
    if DISABLE_AUTH:
        return ("anon", ["*"])
    if not token:
        raise AuthError("missing_token", 4001)
    if token.startswith("test-"):
        return (token, ["*"])
    if AUTH_HS256:
        try:
            from jose import jwt  # type: ignore
        except Exception as e:  # pragma: no cover
            raise AuthError("jwt_not_available", 4001) from e
        try:
            payload = jwt.decode(token, AUTH_HS256, algorithms=["HS256"], options={"verify_aud": False})
        except Exception as e:
            raise AuthError("invalid_token", 4001) from e
        sub = payload.get("sub")
        if not sub:
            raise AuthError("no_sub", 4001)
        scopes = payload.get("scope") or payload.get("scopes") or ""
        if isinstance(scopes, str):
            scopes = scopes.split()
        return (str(sub), list(scopes))
    # Если нет секретов — отклоняем.
    raise AuthError("unsupported_auth", 4001)

def _authorize_channel(subject: str, channel: str, action: str) -> bool:
    """
    Простейший ACL: запрет приватных каналов без прав.
    Примеры каналов:
      public:news, tenant:{id}:events, user:{sub}:inbox
    """
    if channel.startswith("public:"):
        return True
    if channel.startswith("user:"):
        # user:{sub}:inbox
        m = re.match(r"^user:([^:]+):", channel)
        return bool(m and m.group(1) == subject)
    # по умолчанию разрешаем, если аутентифицирован
    return subject != "anon"

# ---------- protocol ----------

class Msg(BaseModel):
    """Стандартная обертка сообщений."""
    model_config = ConfigDict(extra="forbid")
    op: str = Field(..., description="Операция: hello|welcome|subscribe|unsubscribe|publish|message|ack|error|ping|pong|presence")
    id: Optional[str] = Field(None, description="Идентификатор сообщения (для ACK)")
    ch: Optional[str] = Field(None, description="Канал (при необходимости)")
    event: Optional[str] = Field(None, description="Имя события (для message/publish)")
    data: Optional[Any] = Field(None, description="Полезная нагрузка")
    ts: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

# ---------- rate limiter ----------

@dataclass
class TokenBucket:
    capacity: int
    refill_per_sec: float
    tokens: float = field(default=0.0)
    last: float = field(default_factory=time.monotonic)

    def allow(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = max(0.0, now - self.last)
        self.last = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_sec)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False

# ---------- broker abstraction ----------

class Broker:
    async def publish(self, channel: str, msg: Dict[str, Any]) -> None: ...
    async def subscribe(self, channel: str, consumer: Callable[[Dict[str, Any]], Awaitable[None]]) -> Any: ...
    async def unsubscribe(self, token: Any) -> None: ...
    async def close(self) -> None: ...

class MemoryBroker(Broker):
    def __init__(self) -> None:
        self._subs: Dict[str, Set[Tuple[Callable[[Dict[str, Any]], Awaitable[None]], str]]] = {}
        self._lock = asyncio.Lock()

    async def publish(self, channel: str, msg: Dict[str, Any]) -> None:
        async with self._lock:
            for consumer, _token in list(self._subs.get(channel, set())):
                # fire and forget
                asyncio.create_task(consumer(msg))

    async def subscribe(self, channel: str, consumer: Callable[[Dict[str, Any]], Awaitable[None]]) -> Any:
        token = f"mem:{uuid.uuid4().hex}"
        async with self._lock:
            self._subs.setdefault(channel, set()).add((consumer, token))
        return (channel, token)

    async def unsubscribe(self, token: Any) -> None:
        ch, tok = token
        async with self._lock:
            subs = self._subs.get(ch, set())
            self._subs[ch] = {pair for pair in subs if pair[1] != tok}

    async def close(self) -> None:
        self._subs.clear()

class RedisBroker(Broker):
    def __init__(self, url: str) -> None:
        try:
            import redis.asyncio as redis  # type: ignore
        except Exception as e:  # pragma: no cover
            raise RuntimeError("redis>=4 is required for RedisBroker") from e
        self._redis = redis.from_url(url)
        self._pubsub = None  # type: ignore
        self._tasks: Dict[str, asyncio.Task] = {}
        self._consumers: Dict[str, Callable[[Dict[str, Any]], Awaitable[None]]] = {}

    async def publish(self, channel: str, msg: Dict[str, Any]) -> None:
        await self._redis.publish(channel, _dumps(msg))

    async def subscribe(self, channel: str, consumer: Callable[[Dict[str, Any]], Awaitable[None]]) -> Any:
        import redis.asyncio as redis  # type: ignore
        if self._pubsub is None:
            self._pubsub = self._redis.pubsub()
        await self._pubsub.subscribe(channel)
        self._consumers[channel] = consumer

        async def _reader(ch: str) -> None:
            assert self._pubsub is not None
            while True:
                try:
                    message = await self._pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                    if not message:
                        await asyncio.sleep(0)
                        continue
                    if message["channel"].decode() != ch:
                        continue
                    data = message["data"]
                    if isinstance(data, (bytes, bytearray)):
                        data = data.decode()
                    try:
                        obj = _loads(data)
                    except Exception:
                        continue
                    await consumer(obj)
                except asyncio.CancelledError:
                    break
                except Exception:
                    await asyncio.sleep(0.1)

        if channel not in self._tasks:
            self._tasks[channel] = asyncio.create_task(_reader(channel))
        return channel

    async def unsubscribe(self, token: Any) -> None:
        if self._pubsub:
            await self._pubsub.unsubscribe(token)
        task = self._tasks.pop(token, None)
        if task:
            task.cancel()
        self._consumers.pop(token, None)

    async def close(self) -> None:
        for t in self._tasks.values():
            t.cancel()
        self._tasks.clear()
        if self._pubsub:
            await self._pubsub.close()
        await self._redis.close()

# ---------- connection manager ----------

@dataclass
class Client:
    ws: WebSocket
    subject: str
    scopes: List[str]
    queue: "asyncio.Queue[str]"
    subs: Set[str] = field(default_factory=set)
    rate: TokenBucket = field(default_factory=lambda: TokenBucket(RATE_CAPACITY, RATE_REFILL_PER_SEC))
    last_seen: float = field(default_factory=time.monotonic)
    writer_task: Optional[asyncio.Task] = None

class ConnectionManager:
    def __init__(self, broker: Broker) -> None:
        self._broker = broker
        self._clients: Dict[str, Client] = {}  # key=client_id
        self._ch_index: Dict[str, Set[str]] = {}  # channel -> set(client_id)
        self._lock = asyncio.Lock()

    @staticmethod
    def _cid(ws: WebSocket, subject: str) -> str:
        return f"{subject}:{id(ws)}"

    async def connect(self, ws: WebSocket, subject: str, scopes: List[str]) -> Client:
        cid = self._cid(ws, subject)
        await ws.accept()
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=QUEUE_SIZE)
        client = Client(ws=ws, subject=subject, scopes=scopes, queue=queue)
        async with self._lock:
            self._clients[cid] = client
        if _PROM:  # pragma: no cover
            WS_CONN.inc()
        # writer
        client.writer_task = asyncio.create_task(self._writer_loop(client))
        # welcome
        await self._send(client, Msg(op="welcome", data={
            "heartbeat": HEARTBEAT_SECONDS,
            "max_msg_size": MAX_MSG_SIZE,
            "queue": QUEUE_SIZE,
            "rate_capacity": RATE_CAPACITY,
            "rate_refill": RATE_REFILL_PER_SEC,
        }))
        return client

    async def _writer_loop(self, client: Client) -> None:
        ws = client.ws
        try:
            while True:
                payload = await client.queue.get()
                if ws.application_state != WebSocketState.CONNECTED:
                    return
                await ws.send_text(payload)
        except asyncio.CancelledError:
            return
        except Exception:
            try:
                await ws.close(code=1011)
            except Exception:
                pass

    async def _send(self, client: Client, msg: Msg) -> None:
        try:
            payload = _dumps(msg.model_dump(mode="json"))
            if client.queue.full():
                if _PROM:  # pragma: no cover
                    WS_DROP.labels("backpressure").inc()
                # Сбрасываем самое старое сообщение, чтобы освободить место
                try:
                    client.queue.get_nowait()
                except Exception:
                    pass
            client.queue.put_nowait(payload)
            if _PROM:  # pragma: no cover
                WS_MSG_OUT.labels(msg.op).inc()
        except Exception:
            # если очередь переполнена и нельзя отправить — закрываем
            await client.ws.close(code=1013)

    async def subscribe(self, client: Client, channel: str) -> None:
        if channel in client.subs:
            return
        if not _authorize_channel(client.subject, channel, "subscribe"):
            raise AuthError("forbidden_channel", code=4403)
        token = await self._broker.subscribe(channel, lambda m, ch=channel: self._on_broker_message(ch, m))
        async with self._lock:
            client.subs.add(channel)
            self._ch_index.setdefault(channel, set()).add(self._cid(client.ws, client.subject))
        if _PROM:  # pragma: no cover
            WS_SUBS.inc()
        # presence notice (local)
        await self._send(client, Msg(op="subscribed", ch=channel, data={"token": str(token)}))

    async def unsubscribe(self, client: Client, channel: str) -> None:
        if channel not in client.subs:
            return
        await self._broker.unsubscribe(channel)
        async with self._lock:
            client.subs.discard(channel)
            s = self._ch_index.get(channel)
            if s:
                s.discard(self._cid(client.ws, client.subject))
                if not s:
                    self._ch_index.pop(channel, None)
        if _PROM:  # pragma: no cover
            WS_SUBS.dec()
        await self._send(client, Msg(op="unsubscribed", ch=channel))

    async def publish(self, client: Client, channel: str, event: str, data: Any, msg_id: Optional[str]) -> None:
        if not _authorize_channel(client.subject, channel, "publish"):
            raise AuthError("forbidden_channel", 4403)
        envelope = Msg(op="message", ch=channel, event=event, data=data, id=msg_id)
        await self._broker.publish(channel, envelope.model_dump(mode="json"))

    async def _on_broker_message(self, channel: str, message: Mapping[str, Any]) -> None:
        # Рассылаем только подписанным локальным клиентам
        msg = Msg(**message)
        async with self._lock:
            cids = list(self._ch_index.get(channel, set()))
        for cid in cids:
            client = self._clients.get(cid)
            if not client:
                continue
            await self._send(client, msg)

    async def disconnect(self, client: Client) -> None:
        # отписка от всех каналов
        for ch in list(client.subs):
            try:
                await self.unsubscribe(client, ch)
            except Exception:
                pass
        if client.writer_task:
            client.writer_task.cancel()
        async with self._lock:
            self._clients.pop(self._cid(client.ws, client.subject), None)
        if _PROM:  # pragma: no cover
            WS_CONN.dec()

# ---------- router ----------

def _make_broker() -> Broker:
    if BROKER_KIND == "redis":
        if not REDIS_URL:
            raise RuntimeError("VEILMIND_REDIS_URL is required for Redis broker")
        return RedisBroker(REDIS_URL)
    return MemoryBroker()

broker: Broker = _make_broker()
manager = ConnectionManager(broker)

router = APIRouter(prefix="/v1/ws", tags=["ws"])


async def _server_ping(client: Client) -> None:
    interval = HEARTBEAT_SECONDS
    try:
        while True:
            await asyncio.sleep(interval)
            if time.monotonic() - client.last_seen > interval * 2:
                await client.ws.close(code=4000)
                return
            await manager._send(client, Msg(op="ping", data={"t": datetime.now(timezone.utc).isoformat()}))
    except asyncio.CancelledError:
        return

def _trace_ctx(name: str):  # pragma: no cover
    if not _TR:
        from contextlib import nullcontext
        return nullcontext()
    return _tracer.start_as_current_span(name)

@router.websocket("/channels")
async def ws_channels(ws: WebSocket) -> None:
    # Origin check
    if not _origin_ok(ws):
        if _PROM:  # pragma: no cover
            WS_AUTH_FAIL.labels("origin").inc()
        await ws.close(code=4400)
        return

    # Аутентификация
    try:
        subject, scopes = _validate_token(_extract_token(ws))
    except AuthError as e:
        if _PROM:  # pragma: no cover
            WS_AUTH_FAIL.labels(e.reason).inc()
        await ws.close(code=e.code)
        return

    # Ограничение размера сообщений (на нашей стороне)
    max_bytes = MAX_MSG_SIZE

    with _trace_ctx("ws_accept"):
        client = await manager.connect(ws, subject, scopes)

    # Фон: heartbeat
    ping_task = asyncio.create_task(_server_ping(client))

    try:
        while True:
            raw = await ws.receive_text()
            client.last_seen = time.monotonic()
            if len(raw.encode("utf-8")) > max_bytes:
                await manager._send(client, Msg(op="error", data={"code": "msg_too_large"}))
                continue

            try:
                msg = Msg(**_loads(raw))
            except Exception:
                await manager._send(client, Msg(op="error", data={"code": "bad_format"}))
                continue

            if _PROM:  # pragma: no cover
                WS_MSG_IN.labels(msg.op).inc()

            # Rate limiting
            if not client.rate.allow(1.0):
                if _PROM:  # pragma: no cover
                    WS_RATE_LIMIT.labels(msg.op).inc()
                await manager._send(client, Msg(op="error", data={"code": "rate_limited"}))
                # Не закрываем сразу — мягко ограничиваем
                continue

            # Обработка операций
            if msg.op == "ping":
                await manager._send(client, Msg(op="pong", id=msg.id))
                continue

            if msg.op == "subscribe":
                if not msg.ch:
                    await manager._send(client, Msg(op="error", data={"code": "missing_channel"}, id=msg.id))
                    continue
                try:
                    await manager.subscribe(client, msg.ch)
                    await manager._send(client, Msg(op="ack", id=msg.id, ch=msg.ch))
                except AuthError as e:
                    await manager._send(client, Msg(op="error", data={"code": e.reason}, id=msg.id))
                continue

            if msg.op == "unsubscribe":
                if not msg.ch:
                    await manager._send(client, Msg(op="error", data={"code": "missing_channel"}, id=msg.id))
                    continue
                await manager.unsubscribe(client, msg.ch)
                await manager._send(client, Msg(op="ack", id=msg.id, ch=msg.ch))
                continue

            if msg.op == "publish":
                if not msg.ch or not msg.event:
                    await manager._send(client, Msg(op="error", data={"code": "missing_params"}, id=msg.id))
                    continue
                try:
                    await manager.publish(client, msg.ch, msg.event, msg.data, msg.id)
                    await manager._send(client, Msg(op="ack", id=msg.id, ch=msg.ch))
                except AuthError as e:
                    await manager._send(client, Msg(op="error", data={"code": e.reason}, id=msg.id))
                continue

            # Неизвестная операция
            await manager._send(client, Msg(op="error", data={"code": "unknown_op", "op": msg.op}, id=msg.id))

    except WebSocketDisconnect:
        pass
    except Exception:
        try:
            await ws.close(code=1011)
        except Exception:
            pass
    finally:
        ping_task.cancel()
        await manager.disconnect(client)

# ---------- graceful shutdown hooks (для FastAPI lifespan) ----------

async def shutdown_ws_broker() -> None:
    try:
        await broker.close()
    except Exception:
        pass

__all__ = ["router", "shutdown_ws_broker"]
