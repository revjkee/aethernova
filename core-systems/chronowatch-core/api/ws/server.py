# chronowatch-core/api/ws/server.py
# -*- coding: utf-8 -*-
"""
ChronoWatch Core — WebSocket сервер событий.

Возможности:
- FastAPI/ASGI WebSocket endpoint: /ws
- Авторизация: Bearer статический токен или JWT (RS256) — на выбор через переменные окружения
- Протокол сообщений: hello, subscribe, unsubscribe, ack, event, error, heartbeat, close
- Подписки на топики: calendars, composites, slas, bindings, all
- Фильтры подписки: name_prefix, type, label_eq (map), regex_name
- Надёжная отправка: per-connection bounded asyncio.Queue (backpressure, политика DROP_OLDEST)
- Heartbeat и idle-timeout
- Ограничение скорости входящих сообщений (token bucket)
- Опциональный Redis Pub/Sub для горизонтального масштабирования (если REDIS_URL задан и aioredis доступен)
- Метрики (простые счётчики в логах), health-endpoint GET /healthz

Зависимости (минимум):
    fastapi>=0.110
    uvicorn[standard]>=0.23

Опционально:
    PyJWT>=2.8   (JWT верификация)
    redis>=5.0   (aioredis в составе redis-py для Pub/Sub)

Запуск:
    uvicorn chronowatch_core.api.ws.server:app --host 0.0.0.0 --port 8081
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import uuid
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, AsyncIterator, Dict, List, Mapping, Optional, Set, Tuple

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, BaseSettings, Field, validator

# ---- опциональные зависимости ----
try:
    import jwt  # PyJWT
    from jwt import InvalidTokenError
except Exception:  # pragma: no cover
    jwt = None
    InvalidTokenError = Exception

try:
    import redis.asyncio as aioredis  # redis>=5
except Exception:  # pragma: no cover
    aioredis = None


# =========================
# Конфигурация приложения
# =========================

class WSSettings(BaseSettings):
    app_name: str = "chronowatch-ws"
    version: str = "1.0.0"
    log_level: str = "INFO"

    auth_required: bool = True
    auth_static_token: Optional[str] = Field(default=None, description="Если задан, сравнивается как Bearer")
    jwt_public_key: Optional[str] = None  # PEM
    jwt_algorithm: str = "RS256"
    jwt_audience: Optional[str] = None
    jwt_issuer: Optional[str] = None

    redis_url: Optional[str] = None

    ws_ping_interval_s: int = 25
    ws_idle_timeout_s: int = 180
    ws_send_queue_max: int = 1000
    ws_max_subscriptions: int = 64
    ws_max_message_bytes: int = 256 * 1024

    rl_msgs_per_sec: int = 20
    rl_burst: int = 40

    filter_regex_timeout_ms: int = 20

    class Config:
        env_prefix = "CHRONO_"


settings = WSSettings()
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s:%(lineno)d - %(message)s",
)
LOG = logging.getLogger("chronowatch.ws")


# =========================
# Протокол сообщений
# =========================

TOPICS = {"calendars", "composites", "slas", "bindings", "all"}
EVENT_TYPES = {"calendar", "composite", "sla", "binding"}


class HelloMsg(BaseModel):
    type: str = "hello"
    client_version: Optional[str] = None
    protocols: Optional[List[str]] = None
    want_acks: bool = False


class SubscribeFilter(BaseModel):
    name_prefix: Optional[str] = None
    type: Optional[str] = None  # "calendar"|"composite"|"sla"|"binding"
    regex_name: Optional[str] = None
    label_eq: Optional[Dict[str, str]] = None

    @validator("type")
    def _v_type(cls, v):
        if v and v not in EVENT_TYPES:
            raise ValueError("invalid filter.type")
        return v


class SubscribeMsg(BaseModel):
    type: str = "subscribe"
    id: str
    topics: List[str]
    filter: Optional[SubscribeFilter] = None
    etag: Optional[str] = None  # позиция, с которой продолжать

    @validator("topics")
    def _v_topics(cls, v):
        if not v:
            raise ValueError("topics required")
        for t in v:
            if t not in TOPICS:
                raise ValueError(f"invalid topic: {t}")
        return v


class UnsubscribeMsg(BaseModel):
    type: str = "unsubscribe"
    id: str
    topics: List[str]


class AckMsg(BaseModel):
    type: str = "ack"
    id: Optional[str] = None
    ok: bool = True
    reason: Optional[str] = None


class ErrorMsg(BaseModel):
    type: str = "error"
    code: str
    message: str
    id: Optional[str] = None


class HeartbeatMsg(BaseModel):
    type: str = "heartbeat"
    ts: str


class EventPayload(BaseModel):
    # согласовано с schemas/proto ResourceUpdate
    name: str  # calendars/{id} | composites/{id} | slas/{id} | services/{svc}/bindings/{id}
    type: str  # "calendar" | "composite" | "sla" | "binding"
    etag: str
    update_time: str  # RFC3339
    labels: Optional[Dict[str, str]] = None
    data: Optional[Dict[str, Any]] = None  # опциональная полезная нагрузка


class EventMsg(BaseModel):
    type: str = "event"
    topic: str
    payload: EventPayload


# =========================
# Утилиты
# =========================

def utcnow_rfc3339() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def clamp(n: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, n))


class TokenBucket:
    def __init__(self, rate_per_sec: int, burst: int):
        self.rate = max(1.0, float(rate_per_sec))
        self.capacity = max(1.0, float(burst))
        self.tokens = self.capacity
        self.timestamp = time.monotonic()

    def consume(self, amount: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self.timestamp
        self.timestamp = now
        self.tokens = clamp(self.tokens + elapsed * self.rate, 0.0, self.capacity)
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False


# =========================
# Event Bus
# =========================

class EventBus:
    """
    Универсальный шина событий.
    Если REDIS_URL задан и доступен redis.asyncio — используется Redis Pub/Sub.
    Иначе — in-memory.
    """
    def __init__(self, redis_url: Optional[str]):
        self._redis_url = redis_url
        self._channels = {t: f"chronowatch.events.{t}" for t in TOPICS if t != "all"}
        self._local_queues: Dict[str, asyncio.Queue[EventMsg]] = {
            t: asyncio.Queue(maxsize=10_000) for t in self._channels
        }
        self._redis = None
        self._redis_task: Optional[asyncio.Task] = None

    async def start(self):
        if self._redis_url and aioredis is not None:
            self._redis = aioredis.from_url(self._redis_url, decode_responses=True)
            self._redis_task = asyncio.create_task(self._redis_subscribe_loop(), name="redis-subscribe")
            LOG.info("EventBus: using Redis backend at %s", self._redis_url)
        else:
            LOG.info("EventBus: using in-memory backend")

    async def stop(self):
        if self._redis_task:
            self._redis_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._redis_task
        if self._redis:
            await self._redis.close()

    # ---- публикация ----
    async def publish(self, event: EventMsg):
        if event.topic == "all":
            # рассылаем в каждый конкретный канал
            for t in self._channels:
                await self.publish(EventMsg(type="event", topic=t, payload=event.payload))
            return

        if self._redis:
            channel = self._channels.get(event.topic)
            if channel:
                await self._redis.publish(channel, event.json())
        else:
            q = self._local_queues.get(event.topic)
            if q:
                with suppress(asyncio.QueueFull):
                    q.put_nowait(event)

    # ---- подписка ----
    async def subscribe(self, topic: str) -> AsyncIterator[EventMsg]:
        if topic == "all":
            # агрегатор по всем топикам
            queues = [self._queue_for(t) async for t in self._iter_queues()]
            async for ev in _merge_queues(queues):
                yield ev
        else:
            q = self._queue_for(topic)
            while True:
                ev = await q.get()
                yield ev

    async def _iter_queues(self) -> AsyncIterator[asyncio.Queue]:
        for t in self._channels:
            yield self._queue_for(t)

    def _queue_for(self, topic: str) -> asyncio.Queue:
        if self._redis:
            # при Redis подписчики получают из redis-subscribe-loop, которое пушит в local_queues
            return self._local_queues[topic]
        return self._local_queues[topic]

    async def _redis_subscribe_loop(self):
        assert self._redis is not None
        pubsub = self._redis.pubsub()
        await pubsub.subscribe(*self._channels.values())
        try:
            async for msg in pubsub.listen():
                if msg is None or msg.get("type") != "message":
                    continue
                raw = msg.get("data")
                with suppress(Exception):
                    ev = EventMsg.parse_raw(raw)
                    q = self._local_queues.get(ev.topic)
                    if q:
                        with suppress(asyncio.QueueFull):
                            q.put_nowait(ev)
        finally:
            await pubsub.close()


async def _merge_queues(queues: List[asyncio.Queue]) -> AsyncIterator[EventMsg]:
    async def consume(q: asyncio.Queue, out: asyncio.Queue):
        while True:
            ev = await q.get()
            await out.put(ev)

    out = asyncio.Queue(maxsize=10_000)
    tasks = [asyncio.create_task(consume(q, out)) for q in queues]
    try:
        while True:
            yield await out.get()
    finally:
        for t in tasks:
            t.cancel()
            with suppress(asyncio.CancelledError):
                await t


# =========================
# Аутентификация
# =========================

class Principal(BaseModel):
    subject: Optional[str] = None
    scopes: List[str] = Field(default_factory=list)


async def authenticate(websocket: WebSocket) -> Principal:
    if not settings.auth_required:
        return Principal(subject=None, scopes=[])

    auth = websocket.headers.get("authorization") or websocket.query_params.get("token")
    if not auth:
        raise HTTPException(status_code=401, detail="Authorization required")

    # Bearer token
    token = auth.replace("Bearer ", "") if auth.startswith("Bearer ") else auth

    # static token
    if settings.auth_static_token:
        if token == settings.auth_static_token:
            return Principal(subject="static", scopes=["*"])
        raise HTTPException(status_code=403, detail="Invalid token")

    # JWT
    if settings.jwt_public_key:
        if jwt is None:
            raise HTTPException(status_code=500, detail="JWT library not available")
        try:
            options = {"verify_aud": bool(settings.jwt_audience)}
            decoded = jwt.decode(
                token,
                settings.jwt_public_key,
                algorithms=[settings.jwt_algorithm],
                audience=settings.jwt_audience,
                issuer=settings.jwt_issuer,
                options=options,
            )
            sub = decoded.get("sub")
            scopes = decoded.get("scope", "").split() if decoded.get("scope") else []
            return Principal(subject=sub, scopes=scopes)
        except InvalidTokenError as e:
            raise HTTPException(status_code=403, detail=f"Invalid JWT: {e}")
    raise HTTPException(status_code=403, detail="Auth configuration not satisfied")


# =========================
# Соединение и подписки
# =========================

@dataclass
class Subscription:
    id: str
    topics: Set[str]
    flt: Optional[SubscribeFilter]


class Connection:
    def __init__(self, ws: WebSocket, principal: Principal):
        self.ws = ws
        self.principal = principal
        self.send_q: asyncio.Queue[str] = asyncio.Queue(maxsize=settings.ws_send_queue_max)
        self.subscriptions: Dict[str, Subscription] = {}
        self.rl = TokenBucket(settings.rl_msgs_per_sec, settings.rl_burst)
        self.last_recv = time.monotonic()
        self.want_acks = False

    async def send_json(self, payload: Mapping[str, Any]) -> None:
        msg = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        if len(msg.encode("utf-8")) > settings.ws_max_message_bytes:
            # не посылаем слишком большие сообщения
            LOG.warning("drop large message to client")
            return
        try:
            self.send_q.put_nowait(msg)
        except asyncio.QueueFull:
            # Политика: DROP_OLDEST
            with suppress(asyncio.QueueEmpty):
                _ = self.send_q.get_nowait()
            self.send_q.put_nowait(msg)


# =========================
# Фильтрация событий
# =========================

class EventFilter:
    def __init__(self, flt: Optional[SubscribeFilter]):
        self.flt = flt
        self._rx = None
        if flt and flt.regex_name:
            try:
                self._rx = re.compile(flt.regex_name)
            except re.error:
                self._rx = None

    def match(self, ev: EventMsg) -> bool:
        if not self.flt:
            return True
        f = self.flt
        p = ev.payload

        if f.type and p.type != f.type:
            return False
        if f.name_prefix and not p.name.startswith(f.name_prefix):
            return False
        if self._rx:
            # ограничение по времени выполнения для безопасности
            start = time.perf_counter()
            ok = bool(self._rx.search(p.name))
            if (time.perf_counter() - start) * 1000.0 > settings.filter_regex_timeout_ms:
                return False
            if not ok:
                return False
        if f.label_eq:
            labels = p.labels or {}
            for k, v in f.label_eq.items():
                if labels.get(k) != v:
                    return False
        return True


# =========================
# Приложение FastAPI
# =========================

@asynccontextmanager
async def lifespan(app: FastAPI):
    await BUS.start()
    yield
    await BUS.stop()


BUS = EventBus(settings.redis_url)
app = FastAPI(title=settings.app_name, version=settings.version, lifespan=lifespan)


@app.get("/healthz")
async def healthz():
    return JSONResponse({"status": "ok", "ts": utcnow_rfc3339(), "version": settings.version})


@app.post("/internal/publish")
async def internal_publish(ev: EventMsg):
    """
    Внутренний хук публикации (для тестов/демо).
    В продакшене замените на интеграцию с ядром.
    """
    if ev.topic not in TOPICS:
        raise HTTPException(400, "invalid topic")
    await BUS.publish(ev)
    return {"ok": True}


@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket, principal: Principal = Depends(authenticate)):
    await websocket.accept(subprotocol="chronowatch.v1")
    conn = Connection(websocket, principal)
    LOG.info("connected: %s", principal.subject)

    # отправляем server hello
    await conn.send_json(
        {
            "type": "hello",
            "server": settings.app_name,
            "version": settings.version,
            "ts": utcnow_rfc3339(),
        }
    )

    writer = asyncio.create_task(_writer_loop(conn), name="ws-writer")
    reader = asyncio.create_task(_reader_loop(conn), name="ws-reader")

    done, pending = await asyncio.wait({writer, reader}, return_when=asyncio.FIRST_COMPLETED)
    for t in pending:
        t.cancel()
        with suppress(asyncio.CancelledError):
            await t
    LOG.info("disconnected: %s", principal.subject)


async def _writer_loop(conn: Connection):
    ws = conn.ws
    ping_interval = settings.ws_ping_interval_s
    idle_timeout = settings.ws_idle_timeout_s
    last_send = time.monotonic()

    try:
        while True:
            try:
                msg = await asyncio.wait_for(conn.send_q.get(), timeout=ping_interval)
                await ws.send_text(msg)
                last_send = time.monotonic()
            except asyncio.TimeoutError:
                # heartbeat
                hb = HeartbeatMsg(ts=utcnow_rfc3339()).dict()
                await ws.send_text(json.dumps(hb, separators=(",", ":"), ensure_ascii=False))
                # idle timeout: если давно не было входящих
                if time.monotonic() - conn.last_recv > idle_timeout:
                    await ws.close(code=1000)
                    return
    except WebSocketDisconnect:
        return
    except Exception as e:
        LOG.exception("writer error: %r", e)
        with suppress(Exception):
            await ws.close(code=1011)


async def _reader_loop(conn: Connection):
    ws = conn.ws
    try:
        while True:
            raw = await ws.receive_text()
            conn.last_recv = time.monotonic()

            if not conn.rl.consume():
                await conn.send_json(ErrorMsg(type="error", code="rate_limited", message="Too many messages").dict())
                continue

            if len(raw.encode("utf-8")) > settings.ws_max_message_bytes:
                await conn.send_json(ErrorMsg(type="error", code="frame_too_large", message="Message too large").dict())
                continue

            with suppress(Exception):
                msg = json.loads(raw)

            mtype = msg.get("type")
            if mtype == "hello":
                h = HelloMsg(**msg)
                conn.want_acks = h.want_acks
                if conn.want_acks:
                    await conn.send_json(AckMsg(id=h.client_version or None).dict())
                continue

            if mtype == "subscribe":
                try:
                    sub = SubscribeMsg(**msg)
                    await _handle_subscribe(conn, sub)
                except Exception as e:
                    await conn.send_json(ErrorMsg(type="error", code="bad_subscribe", message=str(e), id=msg.get("id")).dict())
                continue

            if mtype == "unsubscribe":
                try:
                    unsub = UnsubscribeMsg(**msg)
                    _handle_unsubscribe(conn, unsub)
                    await conn.send_json(AckMsg(id=unsub.id).dict())
                except Exception as e:
                    await conn.send_json(ErrorMsg(type="error", code="bad_unsubscribe", message=str(e), id=msg.get("id")).dict())
                continue

            # неизвестный тип
            await conn.send_json(ErrorMsg(type="error", code="bad_request", message="Unknown message type").dict())

    except WebSocketDisconnect:
        return
    except Exception as e:
        LOG.exception("reader error: %r", e)
        with suppress(Exception):
            await ws.close(code=1011)


async def _handle_subscribe(conn: Connection, sub: SubscribeMsg):
    if len(conn.subscriptions) >= settings.ws_max_subscriptions:
        raise ValueError("too many subscriptions")

    # регистрируем подписку
    topics = set(sub.topics if "all" not in sub.topics else TOPICS - {"all"})
    s = Subscription(id=sub.id, topics=topics, flt=sub.filter)
    conn.subscriptions[sub.id] = s

    # запускаем таски доставки для этой подписки
    for t in topics:
        asyncio.create_task(_deliver_topic(conn, sub.id, t, EventFilter(sub.filter)), name=f"deliver-{t}-{sub.id}")

    await conn.send_json(AckMsg(id=sub.id).dict())


async def _deliver_topic(conn: Connection, sub_id: str, topic: str, evfilter: EventFilter):
    async for ev in BUS.subscribe(topic):
        # подписка могла быть удалена
        if sub_id not in conn.subscriptions:
            return
        if not evfilter.match(ev):
            continue
        await conn.send_json(ev.dict())


def _handle_unsubscribe(conn: Connection, unsub: UnsubscribeMsg):
    # удаляем подписку полностью или частично
    s = conn.subscriptions.get(unsub.id)
    if not s:
        raise ValueError("subscription not found")
    if "all" in unsub.topics:
        conn.subscriptions.pop(unsub.id, None)
        return
    for t in unsub.topics:
        s.topics.discard(t)
    if not s.topics:
        conn.subscriptions.pop(unsub.id, None)


# ==========================================================
# Локальное тестирование (опционально)
# ==========================================================
if __name__ == "__main__":
    import uvicorn

    LOG.info("Starting %s v%s", settings.app_name, settings.version)
    uvicorn.run("chronowatch_core.api.ws.server:app", host="0.0.0.0", port=8081, reload=False)
