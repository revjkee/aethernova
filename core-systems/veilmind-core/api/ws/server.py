# path: veilmind-core/api/ws/server.py
from __future__ import annotations

import asyncio
import json
import os
import time
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Literal, Optional, Set, Tuple

from fastapi import APIRouter, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field, ValidationError, constr

# -------------------------------
# Опциональные интеграции
# -------------------------------
try:
    import redis.asyncio as aioredis  # type: ignore
except Exception:  # pragma: no cover
    aioredis = None

try:
    import jwt  # PyJWT
except Exception:  # pragma: no cover
    jwt = None  # type: ignore

try:
    from opentelemetry import trace  # type: ignore
    tracer = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    tracer = None  # type: ignore

try:
    from prometheus_client import Counter, Histogram  # type: ignore
    _WS_CONN = Counter("veilmind_ws_connections_total", "WS connections", ["tenant"])
    _WS_MSG_IN = Counter("veilmind_ws_messages_in_total", "WS inbound messages", ["tenant", "action"])
    _WS_MSG_OUT = Counter("veilmind_ws_messages_out_total", "WS outbound messages", ["tenant", "type"])
    _WS_ERRORS = Counter("veilmind_ws_errors_total", "WS errors", ["tenant", "kind"])
    _WS_LAT = Histogram("veilmind_ws_publish_latency_seconds", "Publish latency", ["tenant", "channel"])
except Exception:  # pragma: no cover
    _WS_CONN = _WS_MSG_IN = _WS_MSG_OUT = _WS_ERRORS = _WS_LAT = None  # type: ignore

# -------------------------------
# Константы/настройки
# -------------------------------

WS_MAX_MESSAGE_BYTES = int(os.getenv("WS_MAX_MESSAGE_BYTES", "131072"))  # 128 KiB
WS_SEND_QUEUE_SIZE = int(os.getenv("WS_SEND_QUEUE_SIZE", "256"))
WS_IDLE_TIMEOUT_S = float(os.getenv("WS_IDLE_TIMEOUT_S", "60"))
WS_PING_INTERVAL_S = float(os.getenv("WS_PING_INTERVAL_S", "20"))
WS_RATE_RPS = float(os.getenv("WS_RATE_RPS", "20"))          # входящие сообщения/сек
WS_RATE_BURST = float(os.getenv("WS_RATE_BURST", "40"))
WS_REDIS_URL = os.getenv("WS_REDIS_URL")                     # redis://host:6379/0
WS_JWT_SECRET = os.getenv("WS_JWT_SECRET")                   # секрет для HMAC JWT
WS_JWT_AUDIENCE = os.getenv("WS_JWT_AUD", "veilmind-ws")
WS_JWT_ISSUER = os.getenv("WS_JWT_ISS", "veilmind-core")
WS_DEV_MODE = os.getenv("WS_DEV_MODE", "0") == "1"           # разрешить dev:tenant:user:role токены

# Разрешенные каналы
ALLOWED_CHANNELS: Set[str] = {
    "detections", "incidents", "alerts"
    # поддержка custom:* ниже
}

# -------------------------------
# Модели протокола
# -------------------------------

class AuthContext(BaseModel):
    tenant_id: constr(strip_whitespace=True, min_length=1)  # type: ignore
    user_id: constr(strip_whitespace=True, min_length=1)    # type: ignore
    roles: Set[str] = Field(default_factory=set)


class ClientSubscribe(BaseModel):
    action: Literal["subscribe"]
    channels: Set[constr(strip_whitespace=True, min_length=1)]  # type: ignore
    filters: Dict[str, Any] = Field(default_factory=dict)


class ClientUnsubscribe(BaseModel):
    action: Literal["unsubscribe"]
    channels: Set[constr(strip_whitespace=True, min_length=1)]  # type: ignore


class ClientPing(BaseModel):
    action: Literal["ping"]
    ts: Optional[float] = None


class ClientEcho(BaseModel):
    action: Literal["echo"]
    payload: Dict[str, Any]


ClientMessage = ClientSubscribe | ClientUnsubscribe | ClientPing | ClientEcho


class ServerWelcome(BaseModel):
    type: Literal["welcome"] = "welcome"
    tenant: str
    user: str
    conn_id: str
    heartbeat_s: float
    max_message_bytes: int


class ServerAck(BaseModel):
    type: Literal["ack"] = "ack"
    action: str
    ok: bool = True
    detail: Optional[str] = None


class ServerError(BaseModel):
    type: Literal["error"] = "error"
    code: str
    message: str
    detail: Optional[str] = None


class ServerPong(BaseModel):
    type: Literal["pong"] = "pong"
    ts: float


class ServerEvent(BaseModel):
    type: Literal["event"] = "event"
    channel: str
    payload: Dict[str, Any]
    ts: float = Field(default_factory=lambda: time.time())


ServerMessage = ServerWelcome | ServerAck | ServerError | ServerPong | ServerEvent

# -------------------------------
# Утилиты
# -------------------------------

def _now() -> float:
    return time.monotonic()

class LeakyBucket:
    def __init__(self, rate_rps: float, burst: float):
        self.rate = float(rate_rps)
        self.capacity = float(burst)
        self.tokens = float(burst)
        self.updated = _now()

    def allow(self) -> bool:
        now = _now()
        elapsed = now - self.updated
        self.updated = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

def _is_channel_allowed(ch: str) -> bool:
    return ch in ALLOWED_CHANNELS or ch.startswith("custom:")

def _prom_inc(counter, *labels):
    if counter is not None:
        counter.labels(*labels).inc()

def _prom_obs(hist, value, *labels):
    if hist is not None:
        hist.labels(*labels).observe(value)

# -------------------------------
# Брокеры (in‑memory и Redis)
# -------------------------------

class BrokerBase:
    async def publish(self, tenant: str, channel: str, message: Dict[str, Any]) -> None: ...
    def subscriber(self, tenant: str, channels: Iterable[str]): ...  # -> AsyncIterator[Tuple[str, Dict]]

class InMemoryBroker(BrokerBase):
    def __init__(self) -> None:
        self._queues: Dict[Tuple[str, str], Set[asyncio.Queue]] = {}

    async def publish(self, tenant: str, channel: str, message: Dict[str, Any]) -> None:
        key = (tenant, channel)
        queues = list(self._queues.get(key, set()))
        for q in queues:
            with suppress(asyncio.QueueFull):
                q.put_nowait((channel, message))

    @asynccontextmanager
    async def subscriber(self, tenant: str, channels: Iterable[str]):
        queues: Dict[str, asyncio.Queue] = {}
        for ch in channels:
            q = asyncio.Queue(maxsize=WS_SEND_QUEUE_SIZE)
            queues[ch] = q
            self._queues.setdefault((tenant, ch), set()).add(q)
        try:
            async def gen():
                while True:
                    # multiplex
                    done, _ = await asyncio.wait(
                        [asyncio.create_task(q.get()) for q in queues.values()],
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    for task in done:
                        yield task.result()
            yield gen()
        finally:
            for ch, q in queues.items():
                with suppress(KeyError):
                    self._queues[(tenant, ch)].remove(q)

class RedisBroker(BrokerBase):
    def __init__(self, url: str) -> None:
        if not aioredis:
            raise RuntimeError("redis.asyncio is not available")
        self._url = url

    def _topic(self, tenant: str, ch: str) -> str:
        return f"ws:{tenant}:{ch}"

    async def _client(self):
        return aioredis.from_url(self._url, encoding="utf-8", decode_responses=True)

    async def publish(self, tenant: str, channel: str, message: Dict[str, Any]) -> None:
        client = await self._client()
        try:
            payload = json.dumps(message, separators=(",", ":"), ensure_ascii=False)
            t0 = _now()
            await client.publish(self._topic(tenant, channel), payload)
            _prom_obs(_WS_LAT, _now() - t0, tenant, channel)
        finally:
            await client.close()

    @asynccontextmanager
    async def subscriber(self, tenant: str, channels: Iterable[str]):
        client = await self._client()
        psub = client.pubsub()
        topics = [self._topic(tenant, ch) for ch in channels]
        await psub.subscribe(*topics)
        try:
            async def gen():
                async for msg in psub.listen():
                    if msg.get("type") != "message":
                        continue
                    topic = msg["channel"].split(":")[-1]
                    try:
                        payload = json.loads(msg["data"])
                    except Exception:
                        payload = {"raw": msg["data"]}
                    yield topic, payload
            yield gen()
        finally:
            with suppress(Exception):
                await psub.unsubscribe(*topics)
            await client.close()

# Глобальный выбор брокера
BROKER: BrokerBase = RedisBroker(WS_REDIS_URL) if WS_REDIS_URL else InMemoryBroker()

# -------------------------------
# Аутентификация
# -------------------------------

def _auth_from_jwt(token: str) -> AuthContext:
    if not jwt or not WS_JWT_SECRET:
        raise HTTPException(status_code=401, detail="JWT not supported")
    try:
        claims = jwt.decode(
            token,
            WS_JWT_SECRET,
            algorithms=["HS256"],
            audience=WS_JWT_AUDIENCE,
            options={"require": ["sub", "aud", "iss"]},
            issuer=WS_JWT_ISSUER,
        )
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"invalid token: {e}")
    tenant = claims.get("tenant") or claims.get("tenant_id")
    user = claims.get("sub")
    roles = set(claims.get("roles", []))
    if not tenant or not user:
        raise HTTPException(status_code=401, detail="missing tenant/sub in token")
    return AuthContext(tenant_id=str(tenant), user_id=str(user), roles=roles)

def _auth_from_dev(token: str) -> AuthContext:
    # dev:tenant:user:role1,role2
    try:
        _, tenant, user, roles = token.split(":", 3)
        return AuthContext(tenant_id=tenant, user_id=user, roles=set(filter(None, roles.split(","))))
    except Exception:
        raise HTTPException(status_code=401, detail="invalid dev token format")

def authenticate(authorization: Optional[str], token_qs: Optional[str]) -> AuthContext:
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
    elif token_qs:
        token = token_qs.strip()
    if not token:
        raise HTTPException(status_code=401, detail="missing token")

    if token.startswith("dev:"):
        if not WS_DEV_MODE:
            raise HTTPException(status_code=401, detail="dev tokens disabled")
        return _auth_from_dev(token)
    return _auth_from_jwt(token)

# -------------------------------
# Контекст соединения
# -------------------------------

@dataclass
class Connection:
    ws: WebSocket
    auth: AuthContext
    conn_id: str
    subscriptions: Set[str] = field(default_factory=set)
    send_q: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=WS_SEND_QUEUE_SIZE))
    rate: LeakyBucket = field(default_factory=lambda: LeakyBucket(WS_RATE_RPS, WS_RATE_BURST))
    last_rx: float = field(default_factory=_now)
    ping_task: Optional[asyncio.Task] = None
    recv_task: Optional[asyncio.Task] = None
    send_task: Optional[asyncio.Task] = None
    sub_task: Optional[asyncio.Task] = None

    async def send_json(self, msg: ServerMessage) -> None:
        payload = msg.model_dump() if isinstance(msg, BaseModel) else msg
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        await self.ws.send_text(data)
        _prom_inc(_WS_MSG_OUT, self.auth.tenant_id, payload.get("type", "unknown"))

# -------------------------------
# Сервер / Роутер
# -------------------------------

router = APIRouter()

@router.websocket("/ws/v1")
async def ws_v1_endpoint(
    websocket: WebSocket,
    authorization: Optional[str] = Header(default=None),
    token: Optional[str] = Query(default=None),
):
    # Ограничение размера входящего фрейма (зависит от сервера ASGI; здесь — логическая проверка ниже)
    # Аутентификация
    try:
        auth = authenticate(authorization, token)
    except HTTPException as e:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept(headers=[(b"x-tenant", auth.tenant_id.encode())])

    conn = Connection(ws=websocket, auth=auth, conn_id=f"{int(time.time()*1000)}-{id(websocket)}")
    _prom_inc(_WS_CONN, auth.tenant_id)

    # welcome
    await conn.send_json(ServerWelcome(
        tenant=auth.tenant_id,
        user=auth.user_id,
        conn_id=conn.conn_id,
        heartbeat_s=WS_PING_INTERVAL_S,
        max_message_bytes=WS_MAX_MESSAGE_BYTES,
    ))

    # Таски: отправка, прием, heartbeat
    conn.send_task = asyncio.create_task(_sender_loop(conn))
    conn.recv_task = asyncio.create_task(_receiver_loop(conn))
    conn.ping_task = asyncio.create_task(_heartbeat_loop(conn))

    try:
        await asyncio.wait(
            [conn.send_task, conn.recv_task, conn.ping_task],
            return_when=asyncio.FIRST_EXCEPTION,
        )
    except Exception:
        pass
    finally:
        for t in (conn.sub_task, conn.recv_task, conn.send_task, conn.ping_task):
            if t:
                t.cancel()
        with suppress(Exception):
            await websocket.close()

async def _sender_loop(conn: Connection) -> None:
    while True:
        channel, payload = await conn.send_q.get()
        await conn.send_json(ServerEvent(channel=channel, payload=payload))

async def _heartbeat_loop(conn: Connection) -> None:
    while True:
        await asyncio.sleep(WS_PING_INTERVAL_S)
        # idle timeout
        if (_now() - conn.last_rx) > WS_IDLE_TIMEOUT_S:
            await conn.ws.close(code=status.WS_1001_GOING_AWAY)
            return
        try:
            await conn.send_json(ServerPong(ts=time.time()))
        except Exception:
            return

async def _receiver_loop(conn: Connection) -> None:
    # Подписчик брокера — создается при первой подписке
    while True:
        try:
            raw = await conn.ws.receive_text()
        except WebSocketDisconnect:
            return
        except Exception:
            await conn.ws.close(code=status.WS_1011_INTERNAL_ERROR)
            return

        conn.last_rx = _now()
        if len(raw.encode("utf-8")) > WS_MAX_MESSAGE_BYTES:
            await conn.send_json(ServerError(code="too_large", message="message too large"))
            await conn.ws.close(code=status.WS_1009_MESSAGE_TOO_BIG)
            return

        # rate-limit
        if not conn.rate.allow():
            _prom_inc(_WS_ERRORS, conn.auth.tenant_id, "rate_limit")
            await conn.send_json(ServerError(code="rate_limit", message="too many messages"))
            continue

        # decode/validate
        try:
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("invalid payload")
            action = data.get("action")
            msg: ClientMessage
            if action == "subscribe":
                msg = ClientSubscribe(**data)
            elif action == "unsubscribe":
                msg = ClientUnsubscribe(**data)
            elif action == "ping":
                msg = ClientPing(**data)
            elif action == "echo":
                msg = ClientEcho(**data)
            else:
                raise ValueError("unknown action")
        except (ValueError, ValidationError) as e:
            _prom_inc(_WS_ERRORS, conn.auth.tenant_id, "bad_request")
            await conn.send_json(ServerError(code="bad_request", message="invalid message", detail=str(e)))
            continue

        _prom_inc(_WS_MSG_IN, conn.auth.tenant_id, msg.action)  # type: ignore

        # handle actions
        if isinstance(msg, ClientPing):
            await conn.send_json(ServerPong(ts=time.time()))
            continue

        if isinstance(msg, ClientEcho):
            # только для DEV/OPERATOR
            if "ADMIN" in conn.auth.roles or "OPERATOR" in conn.auth.roles or WS_DEV_MODE:
                await conn.send_json(ServerEvent(channel="echo", payload=msg.payload))
            else:
                await conn.send_json(ServerError(code="forbidden", message="echo not allowed"))
            continue

        if isinstance(msg, ClientSubscribe):
            allowed = {ch for ch in msg.channels if _is_channel_allowed(ch)}
            if not allowed:
                await conn.send_json(ServerError(code="bad_channel", message="no allowed channels"))
                continue
            # Проверка прав (пример: инциденты — только ANALYST/SECURITY/ADMIN)
            for ch in allowed:
                if ch == "incidents" and not (conn.auth.roles & {"ANALYST", "SECURITY_ENGINEER", "ADMIN"}):
                    await conn.send_json(ServerError(code="forbidden", message=f"forbidden channel {ch}"))
                    allowed.discard(ch)

            previous = set(conn.subscriptions)
            conn.subscriptions |= allowed
            await conn.send_json(ServerAck(action="subscribe", ok=True, detail=f"subscribed={sorted(conn.subscriptions)}"))

            # (Пере)создать подписи на брокере
            if conn.sub_task:
                conn.sub_task.cancel()
            if conn.subscriptions:
                conn.sub_task = asyncio.create_task(_broker_consumer(conn))
            continue

        if isinstance(msg, ClientUnsubscribe):
            to_drop = {ch for ch in msg.channels if ch in conn.subscriptions}
            conn.subscriptions -= to_drop
            await conn.send_json(ServerAck(action="unsubscribe", ok=True, detail=f"remaining={sorted(conn.subscriptions)}"))
            if not conn.subscriptions and conn.sub_task:
                conn.sub_task.cancel()
                conn.sub_task = None
            continue

async def _broker_consumer(conn: Connection) -> None:
    # Пересоздаётся при изменении набора подписок
    channels = sorted(conn.subscriptions)
    tenant = conn.auth.tenant_id
    async with BROKER.subscriber(tenant, channels) as stream:
        async for ch, payload in stream:
            try:
                # базовая фильтрация по severity, если передана при подписке (консервативно)
                # фильтры можно расширить, храня на стороне соединения
                await conn.send_q.put_nowait((ch, payload))
            except asyncio.QueueFull:
                await conn.send_json(ServerError(code="backpressure", message="send queue overflow"))
                await conn.ws.close(code=status.WS_1013_TRY_AGAIN_LATER)
                return

# -------------------------------
# Публикация событий из приложения
# -------------------------------

async def publish_ws_event(tenant: str, channel: str, payload: Dict[str, Any]) -> None:
    if not _is_channel_allowed(channel):
        raise ValueError(f"channel not allowed: {channel}")
    await BROKER.publish(tenant, channel, payload)

# -------------------------------
# Встраивание в FastAPI
# -------------------------------

def mount_ws(app: FastAPI) -> None:
    app.include_router(router)

# -------------------------------
# Пример самостоятельного запуска (опционально)
# uvicorn veilmind_core.api.ws.server:build_app --reload
# -------------------------------

def build_app() -> FastAPI:
    app = FastAPI(title="Veilmind WS", version=os.getenv("APP_VERSION", "1.0.0"))
    mount_ws(app)
    return app
