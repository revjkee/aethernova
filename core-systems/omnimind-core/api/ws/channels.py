# ops/api/ws/channels.py
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import secrets
import socket
import time
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Set, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field, ValidationError
from typing_extensions import Literal, Annotated

# --------------------------------------------------------------------------------------
# Конфигурация (ENV с безопасными дефолтами)
# --------------------------------------------------------------------------------------

WS_MAX_MESSAGE_BYTES = int(os.getenv("WS_MAX_MESSAGE_BYTES", str(256 * 1024)))  # 256 KiB
WS_SEND_QUEUE_SIZE = int(os.getenv("WS_SEND_QUEUE_SIZE", "512"))
WS_PING_INTERVAL_S = float(os.getenv("WS_PING_INTERVAL_S", "20.0"))
WS_PONG_TIMEOUT_S = float(os.getenv("WS_PONG_TIMEOUT_S", "10.0"))
WS_RATE_CAPACITY = int(os.getenv("WS_RATE_CAPACITY", "60"))  # событий в "ведре"
WS_RATE_REFILL_PER_SEC = float(os.getenv("WS_RATE_REFILL_PER_SEC", "30.0"))
WS_ALLOWED_ORIGINS = set(filter(None, os.getenv("WS_ALLOWED_ORIGINS", "").split(",")))

AUTH_HMAC_SECRET = os.getenv("WS_AUTH_HMAC_SECRET", "")
AUTH_TOKEN_TTL_S = int(os.getenv("WS_AUTH_TOKEN_TTL_S", "3600"))
SERVICE_NAME = os.getenv("SERVICE_NAME", "omnimind-core")
HOSTNAME = socket.gethostname()

LOG = logging.getLogger("ws.channels")
LOG.setLevel(logging.INFO)

# --------------------------------------------------------------------------------------
# Типы сообщений (строгий контракт)
# --------------------------------------------------------------------------------------

class SubMsg(BaseModel):
    op: Literal["subscribe"]
    channels: List[str] = Field(..., min_items=1, max_items=128)

class UnsubMsg(BaseModel):
    op: Literal["unsubscribe"]
    channels: List[str] = Field(..., min_items=1, max_items=128)

class PubMsg(BaseModel):
    op: Literal["publish"]
    channel: str
    data: Any

class PingMsg(BaseModel):
    op: Literal["ping"]
    ts: Optional[int] = None  # клиентский штамп

Inbound = Annotated[SubMsg | UnsubMsg | PubMsg | PingMsg, Field(discriminator="op")]

class OutAck(BaseModel):
    op: Literal["ack"]
    ref: Optional[str] = None
    msg: Optional[str] = None

class OutErr(BaseModel):
    op: Literal["error"]
    code: str
    msg: str

class OutPong(BaseModel):
    op: Literal["pong"]
    ts: int
    server: str = Field(default_factory=lambda: SERVICE_NAME)

class OutEvent(BaseModel):
    op: Literal["event"]
    channel: str
    data: Any
    ts: int = Field(default_factory=lambda: int(time.time() * 1000))

Outbound = OutAck | OutErr | OutPong | OutEvent

# --------------------------------------------------------------------------------------
# Аутентификация: HMAC токен "<user_id>.<ts>.<sig>", sig = HMAC(secret, f"{user_id}.{ts}")
# --------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Principal:
    user_id: str
    scopes: Set[str] = field(default_factory=set)

def _consttime_hmac_check(secret: str, msg: str, sig_hex: str) -> bool:
    mac = hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), sha256).hexdigest()
    return secrets.compare_digest(mac, sig_hex)

def verify_token(token: str) -> Principal:
    """
    Формат токена: "<user_id>.<ts_epoch_sec>.<hmac_hex>".
    Валидация TTL и подписи. В реальном проде замените на JWT/JWE/OIDC.
    """
    if not AUTH_HMAC_SECRET:
        raise HTTPException(status_code=500, detail="Auth secret not configured")
    try:
        user_id, ts_str, sig = token.split(".", 2)
        ts = int(ts_str)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token format")
    now = int(time.time())
    if abs(now - ts) > AUTH_TOKEN_TTL_S:
        raise HTTPException(status_code=401, detail="Token expired")
    if not _consttime_hmac_check(AUTH_HMAC_SECRET, f"{user_id}.{ts}", sig):
        raise HTTPException(status_code=401, detail="Bad signature")
    scopes: Set[str] = set()  # при необходимости парсите из токена
    return Principal(user_id=user_id, scopes=scopes)

# --------------------------------------------------------------------------------------
# Политики доступа к каналам
# --------------------------------------------------------------------------------------

def can_subscribe(principal: Principal, channel: str) -> bool:
    """
    Разрешаем:
      - личные каналы: "user:{user_id}"
      - общие комнаты: "room:{uuid|slug}"
      - публичные темы: "topic:{slug}"
    Расширяйте согласно доменной модели.
    """
    if channel.startswith(f"user:{principal.user_id}"):
        return True
    if channel.startswith("room:"):
        return True
    if channel.startswith("topic:"):
        return True
    return False

def can_publish(principal: Principal, channel: str) -> bool:
    """
    Базовая политика:
      - в "user:{id}" — только владелец
      - "room:*" и "topic:*" — разрешено (для demo). Ужесточите по ролям/скоупам.
    """
    if channel.startswith("user:"):
        return channel == f"user:{principal.user_id}"
    if channel.startswith("room:"):
        return True
    if channel.startswith("topic:"):
        return True
    return False

# --------------------------------------------------------------------------------------
# Rate limit: простой токен-бакет
# --------------------------------------------------------------------------------------

@dataclass
class TokenBucket:
    capacity: int
    refill_per_sec: float
    tokens: float = 0.0
    last_refill: float = field(default_factory=time.monotonic)

    def allow(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_sec)
        self.last_refill = now
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False

# --------------------------------------------------------------------------------------
# Соединение и Hub
# --------------------------------------------------------------------------------------

@dataclass
class Connection:
    ws: WebSocket
    principal: Principal
    send_q: asyncio.Queue[Outbound]
    rate: TokenBucket
    joined: Set[str] = field(default_factory=set)
    last_pong: float = field(default_factory=time.monotonic)
    drops: int = 0  # счетчик сброшенных сообщений из-за backpressure

class ChannelHub:
    def __init__(self) -> None:
        self._channels: Dict[str, Set[Connection]] = {}
        self._lock = asyncio.Lock()

    async def join(self, conn: Connection, channels: Iterable[str]) -> List[str]:
        joined: List[str] = []
        async with self._lock:
            for ch in channels:
                self._channels.setdefault(ch, set()).add(conn)
                conn.joined.add(ch)
                joined.append(ch)
        return joined

    async def leave(self, conn: Connection, channels: Iterable[str]) -> List[str]:
        left: List[str] = []
        async with self._lock:
            for ch in channels:
                if ch in self._channels and conn in self._channels[ch]:
                    self._channels[ch].remove(conn)
                    left.append(ch)
                conn.joined.discard(ch)
        return left

    async def leave_all(self, conn: Connection) -> None:
        async with self._lock:
            for ch in list(conn.joined):
                members = self._channels.get(ch)
                if members and conn in members:
                    members.remove(conn)
            conn.joined.clear()

    async def publish(self, channel: str, event: OutEvent) -> int:
        """
        Неблокирующая рассылка: кладем в очереди получателей; при переполнении — инкрементируем drops у получателя.
        Возвращает количество доставленных (поставленных в очередь) сообщений.
        """
        delivered = 0
        async with self._lock:
            targets = list(self._channels.get(channel, set()))
        for conn in targets:
            try:
                conn.send_q.put_nowait(event)
                delivered += 1
            except asyncio.QueueFull:
                conn.drops += 1
                # по желанию — разорвать соединение при избыточных дропах:
                # if conn.drops > 100: await conn.ws.close(code=1011)
        return delivered

HUB = ChannelHub()
router = APIRouter(prefix="/ws", tags=["ws"])

# --------------------------------------------------------------------------------------
# Вспомогательные функции
# --------------------------------------------------------------------------------------

async def _send_loop(conn: Connection) -> None:
    try:
        while True:
            msg = await conn.send_q.get()
            await conn.ws.send_text(msg.model_dump_json())
    except Exception as e:
        LOG.debug("send_loop terminated: %s", e)

async def _ping_loop(conn: Connection) -> None:
    try:
        while True:
            await asyncio.sleep(WS_PING_INTERVAL_S)
            try:
                await conn.ws.send_text(OutPong(op="pong", ts=int(time.time() * 1000)).model_dump_json())
            except RuntimeError:
                return
            # проверим pong таймаут по активности клиента (не отдельный pong, а любое получение)
            if time.monotonic() - conn.last_pong > (WS_PING_INTERVAL_S + WS_PONG_TIMEOUT_S):
                await conn.ws.close(code=1001)
                return
    except Exception as e:
        LOG.debug("ping_loop terminated: %s", e)

def _ensure_origin_allowed(ws: WebSocket) -> None:
    if not WS_ALLOWED_ORIGINS:
        return
    origin = ws.headers.get("origin") or ws.headers.get("Origin")
    if not origin or origin not in WS_ALLOWED_ORIGINS:
        raise HTTPException(status_code=403, detail="Origin not allowed")

def _validate_payload_size(raw: str) -> None:
    if len(raw.encode("utf-8")) > WS_MAX_MESSAGE_BYTES:
        raise HTTPException(status_code=1009, detail="Message too big")  # 1009: too large

def _parse_inbound(raw: str) -> Inbound:
    try:
        obj = json.loads(raw)
        op = obj.get("op")
    except Exception:
        raise HTTPException(status_code=1003, detail="Invalid JSON")
    try:
        if op == "subscribe":
            return SubMsg(**obj)
        if op == "unsubscribe":
            return UnsubMsg(**obj)
        if op == "publish":
            return PubMsg(**obj)
        if op == "ping":
            return PingMsg(**obj)
    except ValidationError as ve:
        raise HTTPException(status_code=1007, detail=f"Validation error: {ve.errors()}")  # 1007: bad data
    raise HTTPException(status_code=1008, detail="Unsupported op")  # policy violation

# --------------------------------------------------------------------------------------
# Основной endpoint
# --------------------------------------------------------------------------------------

@router.websocket("/v1")
async def ws_entrypoint(
    websocket: WebSocket,
    token: Annotated[Optional[str], Query(alias="token")] = None,
):
    """
    WebSocket endpoint:
      - аутентификация HMAC-токеном
      - политика Origins (если задана)
      - отдельные send/recv/ping корутины
    """
    try:
        _ensure_origin_allowed(websocket)
    except HTTPException as e:
        await websocket.close(code=1008)
        return

    await websocket.accept(subprotocol="json")

    if not token:
        await websocket.close(code=1008, reason="Missing token")
        return

    try:
        principal = verify_token(token)
    except HTTPException as e:
        await websocket.close(code=1008, reason=e.detail if isinstance(e.detail, str) else "Auth failed")
        return

    send_q: asyncio.Queue[Outbound] = asyncio.Queue(maxsize=WS_SEND_QUEUE_SIZE)
    conn = Connection(
        ws=websocket,
        principal=principal,
        send_q=send_q,
        rate=TokenBucket(capacity=WS_RATE_CAPACITY, refill_per_sec=WS_RATE_REFILL_PER_SEC),
    )

    send_task = asyncio.create_task(_send_loop(conn), name="ws_send")
    ping_task = asyncio.create_task(_ping_loop(conn), name="ws_ping")

    LOG.info("WS connected user=%s host=%s", principal.user_id, HOSTNAME)

    try:
        # Приветствие/ack
        await conn.send_q.put(
            OutAck(op="ack", ref="connected", msg=f"hello {principal.user_id}")
        )

        while True:
            try:
                raw = await websocket.receive_text()
            except WebSocketDisconnect:
                break
            except Exception as e:
                LOG.debug("receive error: %s", e)
                break

            conn.last_pong = time.monotonic()
            try:
                _validate_payload_size(raw)
                msg = _parse_inbound(raw)
            except HTTPException as he:
                # сопоставим HTTP кода с WS close code
                code = he.status_code if 1000 <= he.status_code <= 4999 else 1008
                await websocket.close(code=code, reason=str(he.detail))
                return

            # rate limit
            if not conn.rate.allow():
                await conn.send_q.put(OutErr(op="error", code="rate_limited", msg="Too many requests"))
                continue

            # обработка команд
            if isinstance(msg, PingMsg):
                await conn.send_q.put(OutPong(op="pong", ts=int(time.time() * 1000)))
                continue

            if isinstance(msg, SubMsg):
                ok: List[str] = []
                denied: List[str] = []
                for ch in msg.channels:
                    if can_subscribe(principal, ch):
                        ok.append(ch)
                    else:
                        denied.append(ch)
                if denied:
                    await conn.send_q.put(OutErr(op="error", code="subscribe_denied", msg=",".join(denied)))
                if ok:
                    joined = await HUB.join(conn, ok)
                    await conn.send_q.put(OutAck(op="ack", ref="subscribe", msg=",".join(joined)))
                continue

            if isinstance(msg, UnsubMsg):
                left = await HUB.leave(conn, msg.channels)
                await conn.send_q.put(OutAck(op="ack", ref="unsubscribe", msg=",".join(left)))
                continue

            if isinstance(msg, PubMsg):
                if not can_publish(principal, msg.channel):
                    await conn.send_q.put(OutErr(op="error", code="publish_denied", msg=msg.channel))
                    continue
                event = OutEvent(op="event", channel=msg.channel, data=msg.data)
                delivered = await HUB.publish(msg.channel, event)
                await conn.send_q.put(OutAck(op="ack", ref="publish", msg=str(delivered)))
                continue

    finally:
        try:
            await HUB.leave_all(conn)
        except Exception:
            pass
        for t in (send_task, ping_task):
            t.cancel()
            with contextlib.suppress(Exception):
                await t
        with contextlib.suppress(Exception):
            await websocket.close(code=1001)
        LOG.info("WS disconnected user=%s drops=%d", principal.user_id, conn.drops)

# --------------------------------------------------------------------------------------
# Точки расширения для горизонтального масштабирования (pub/sub брокер)
# --------------------------------------------------------------------------------------
# Для кластера замените HUB.publish на прокси к Redis/NATS/Kafka и подпишитесь на внешний
# канал → при получении внешнего события выполняйте HUB.publish локально.
# Схема OutEvent сохранится неизменной, а маршрутизация будет прозрачной.

# --------------------------------------------------------------------------------------
# Примечание по тестированию:
#  - проверяйте: subscribe/publish, права на user:{id}, rate limit, overflow очереди,
#    ping/pong и закрытие по тайм-ауту (WS_PONG_TIMEOUT_S).
#  - используйте WebSocketTestClient из starlette.testclient для unit/integration.
