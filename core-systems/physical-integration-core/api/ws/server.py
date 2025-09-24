# physical-integration-core/api/ws/server.py
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional, Set, List

from fastapi import APIRouter, Depends, Header, HTTPException, status
from starlette.websockets import WebSocket, WebSocketDisconnect, WebSocketState
from pydantic import BaseModel, Field, constr

logger = logging.getLogger("physical_integration_core.api.ws")

router = APIRouter(prefix="/api", tags=["WS"])

# ------------------------------- Security ------------------------------------


class Principal(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    roles: List[str] = Field(default_factory=list)
    scopes: List[str] = Field(default_factory=list)


async def get_current_principal(
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> Principal:
    """
    Заглушка для примера. В проде валидируйте JWT/API-Key и извлекайте subject/tenant/scopes.
    """
    if not authorization and not api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    return Principal(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        roles=["device", "operator"],
        scopes=["ws:connect", "telemetry:publish", "commands:receive"],
    )


# ------------------------------ Rate limiting --------------------------------


class TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int) -> None:
        self.rate = rate_per_sec
        self.capacity = burst
        self.tokens = burst
        self.last = time.monotonic()

    def allow(self) -> bool:
        now = time.monotonic()
        elapsed = now - self.last
        self.last = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


# ------------------------------- Protocol ------------------------------------


class Op(str, Enum):
    HELLO = "hello"            # handshake/resume
    WELCOME = "welcome"        # server hello
    SUBSCRIBE = "subscribe"
    UNSUBSCRIBE = "unsubscribe"
    PUBLISH = "publish"        # client->server publish
    EVENT = "event"            # server->client delivery
    ERROR = "error"
    ACK = "ack"
    PING = "ping"
    PONG = "pong"


MAX_MSG_BYTES = 64 * 1024            # 64 KiB
SEND_QUEUE_MAX = 1000                # per-connection backpressure
PING_INTERVAL = 15.0                 # seconds
IDLE_TIMEOUT = 60.0                  # seconds without any activity
CONN_RATE = 30.0                     # messages/sec per connection
CONN_BURST = 60                      # burst
TENANT_RATE = 200.0                  # messages/sec per tenant
TENANT_BURST = 400                   # burst
SUBPROTOCOL = "pi.core.v1"
TOPIC_PREFIX = "tenant"              # topic MUST be tenant/{tenant_uuid}/...

# ------------------------------ Message model --------------------------------


class Envelope(BaseModel):
    op: Op
    id: Optional[constr(strip_whitespace=True, min_length=1, max_length=64)] = None
    topic: Optional[constr(strip_whitespace=True, min_length=1, max_length=512)] = None
    data: Dict[str, Any] = Field(default_factory=dict)
    seq: Optional[int] = None  # server sequence for EVENT
    ts: Optional[str] = None   # ISO timestamp


def json_dumps(obj: Any) -> str:
    # Быстрый и совместимый сериализатор
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


# ------------------------------ Pub/Sub broker -------------------------------


class Broker:
    def __init__(self) -> None:
        self._subs: Dict[str, Set["Connection"]] = {}
        self._tenant_rate: Dict[uuid.UUID, TokenBucket] = {}

    def _tenant_bucket(self, tenant_id: uuid.UUID) -> TokenBucket:
        b = self._tenant_rate.get(tenant_id)
        if b is None:
            b = TokenBucket(TENANT_RATE, TENANT_BURST)
            self._tenant_rate[tenant_id] = b
        return b

    def _validate_topic(self, tenant_id: uuid.UUID, topic: str) -> None:
        # Топик должен быть вида tenant/{tenant_uuid}/...
        parts = topic.split("/", 2)
        if len(parts) < 2 or parts[0] != TOPIC_PREFIX:
            raise ValueError("invalid topic prefix")
        try:
            t_uuid = uuid.UUID(parts[1])
        except Exception:
            raise ValueError("invalid tenant uuid in topic")
        if t_uuid != tenant_id:
            raise ValueError("tenant mismatch in topic")

    async def subscribe(self, conn: "Connection", topic: str) -> None:
        self._validate_topic(conn.tenant_id, topic)
        s = self._subs.get(topic)
        if s is None:
            s = set()
            self._subs[topic] = s
        s.add(conn)
        conn.subscriptions.add(topic)

    async def unsubscribe(self, conn: "Connection", topic: str) -> None:
        s = self._subs.get(topic)
        if s:
            s.discard(conn)
            if not s:
                self._subs.pop(topic, None)
        conn.subscriptions.discard(topic)

    async def publish(self, conn: "Connection", topic: str, payload: Dict[str, Any]) -> int:
        self._validate_topic(conn.tenant_id, topic)
        # Tenant-wide rate limit
        if not self._tenant_bucket(conn.tenant_id).allow():
            raise RuntimeError("tenant rate limit exceeded")
        seq = conn.next_seq()
        delivered = 0
        recipients = self._subs.get(topic, set()).copy()
        if not recipients:
            return 0
        env = Envelope(op=Op.EVENT, topic=topic, data=payload, seq=seq, ts=datetime.now(timezone.utc).isoformat())
        msg = json_dumps(env.dict())
        for c in recipients:
            ok = await c.enqueue(msg)
            if ok:
                delivered += 1
        return delivered

    async def drop_connection(self, conn: "Connection") -> None:
        # Удаляем все подписки
        for topic in list(conn.subscriptions):
            await self.unsubscribe(conn, topic)


broker = Broker()


# --------------------------- Connection container ----------------------------


@dataclass
class Connection:
    ws: WebSocket
    principal_id: uuid.UUID
    tenant_id: uuid.UUID
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    send_queue: "asyncio.Queue[str]" = field(default_factory=lambda: asyncio.Queue(maxsize=SEND_QUEUE_MAX))
    connected_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    limiter: TokenBucket = field(default_factory=lambda: TokenBucket(CONN_RATE, CONN_BURST))
    subscriptions: Set[str] = field(default_factory=set)
    _seq: int = 0

    def next_seq(self) -> int:
        self._seq += 1
        return self._seq

    async def enqueue(self, msg: str) -> bool:
        """
        Пишем в очередь отправки. При переполнении — мягкая деградация:
        1) Пытаемся положить без ожидания;
        2) Если не удалось — закрываем соединение кодом 1013 (Try Again Later).
        """
        try:
            self.send_queue.put_nowait(msg)
            return True
        except asyncio.QueueFull:
            # Сообщим и закроем
            try:
                await self.ws.close(code=1013)  # Try Again Later
            except Exception:
                pass
            return False

    def touch(self) -> None:
        self.last_seen = time.time()


# ------------------------------- WS Handlers ---------------------------------


async def _send_task(conn: Connection) -> None:
    try:
        while True:
            msg = await conn.send_queue.get()
            if conn.ws.application_state != WebSocketState.CONNECTED:
                break
            await conn.ws.send_text(msg)
    except Exception:
        logger.exception("send_task failed for %s", conn.session_id)


async def _ping_task(conn: Connection) -> None:
    try:
        while True:
            await asyncio.sleep(PING_INTERVAL)
            if time.time() - conn.last_seen > IDLE_TIMEOUT:
                await conn.ws.close(code=1001)  # going away (idle)
                break
            try:
                await conn.ws.send_text(json_dumps(Envelope(op=Op.PING, ts=datetime.now(timezone.utc).isoformat()).dict()))
            except Exception:
                break
    except Exception:
        logger.exception("ping_task failed for %s", conn.session_id)


def _pick_subprotocol(ws: WebSocket) -> Optional[str]:
    # Отдаём наш подпротокол, если клиент его просит
    if ws.headers.get("sec-websocket-protocol"):
        offered = [p.strip() for p in ws.headers["sec-websocket-protocol"].split(",")]
        if SUBPROTOCOL in offered:
            return SUBPROTOCOL
    return None


def _size_guard(raw: str) -> None:
    if len(raw.encode("utf-8")) > MAX_MSG_BYTES:
        raise ValueError("message too large")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@router.websocket("/ws/v1")
async def ws_endpoint(
    websocket: WebSocket,
    principal: Principal = Depends(get_current_principal),
):
    # Handshake
    subproto = _pick_subprotocol(websocket)
    await websocket.accept(subprotocol=subproto)

    conn = Connection(ws=websocket, principal_id=principal.id, tenant_id=principal.tenant_id)
    logger.info("WS connect session=%s tenant=%s principal=%s subproto=%s",
                conn.session_id, principal.tenant_id, principal.id, subproto or "-")

    # Welcome
    await conn.enqueue(json_dumps(Envelope(
        op=Op.WELCOME,
        data={"session_id": conn.session_id, "subprotocol": subproto or "", "connected_at": _now_iso()},
        ts=_now_iso(),
    ).dict()))

    send_task = asyncio.create_task(_send_task(conn), name=f"ws-send-{conn.session_id}")
    ping_task = asyncio.create_task(_ping_task(conn), name=f"ws-ping-{conn.session_id}")

    try:
        while True:
            try:
                raw = await websocket.receive_text()
            except WebSocketDisconnect as dc:
                logger.info("WS disconnect session=%s code=%s", conn.session_id, dc.code)
                break

            conn.touch()
            try:
                _size_guard(raw)
            except ValueError:
                await websocket.close(code=1009)  # message too big
                break

            if not conn.limiter.allow():
                # 1013 Try Again Later
                await websocket.close(code=1013)
                break

            try:
                obj = json.loads(raw)
                env = Envelope(**obj)
            except Exception:
                # 1003 unsupported data
                await websocket.send_text(json_dumps(Envelope(op=Op.ERROR, data={"code": "BAD_JSON"}, ts=_now_iso()).dict()))
                await websocket.close(code=1003)
                break

            # Route ops
            if env.op == Op.HELLO:
                # Резюмирование по session_id может быть реализовано через внешний стор.
                await conn.enqueue(json_dumps(Envelope(op=Op.ACK, id=env.id, data={"session_id": conn.session_id}, ts=_now_iso()).dict()))

            elif env.op == Op.SUBSCRIBE:
                if not env.topic:
                    await conn.enqueue(json_dumps(Envelope(op=Op.ERROR, id=env.id, data={"code": "BAD_TOPIC"}, ts=_now_iso()).dict()))
                    continue
                try:
                    await broker.subscribe(conn, env.topic)
                    await conn.enqueue(json_dumps(Envelope(op=Op.ACK, id=env.id, data={"topic": env.topic}, ts=_now_iso()).dict()))
                    logger.info("WS subscribe %s -> %s", conn.session_id, env.topic)
                except ValueError as ve:
                    await conn.enqueue(json_dumps(Envelope(op=Op.ERROR, id=env.id, data={"code": "TOPIC_INVALID", "msg": str(ve)}, ts=_now_iso()).dict()))

            elif env.op == Op.UNSUBSCRIBE:
                if not env.topic:
                    await conn.enqueue(json_dumps(Envelope(op=Op.ERROR, id=env.id, data={"code": "BAD_TOPIC"}, ts=_now_iso()).dict()))
                    continue
                await broker.unsubscribe(conn, env.topic)
                await conn.enqueue(json_dumps(Envelope(op=Op.ACK, id=env.id, data={"topic": env.topic}, ts=_now_iso()).dict()))
                logger.info("WS unsubscribe %s -> %s", conn.session_id, env.topic)

            elif env.op == Op.PUBLISH:
                if not env.topic:
                    await conn.enqueue(json_dumps(Envelope(op=Op.ERROR, id=env.id, data={"code": "BAD_TOPIC"}, ts=_now_iso()).dict()))
                    continue
                try:
                    delivered = await broker.publish(conn, env.topic, env.data or {})
                    await conn.enqueue(json_dumps(Envelope(op=Op.ACK, id=env.id, data={"delivered": delivered}, ts=_now_iso()).dict()))
                except ValueError as ve:
                    await conn.enqueue(json_dumps(Envelope(op=Op.ERROR, id=env.id, data={"code": "TOPIC_INVALID", "msg": str(ve)}, ts=_now_iso()).dict()))
                except RuntimeError as re:
                    await conn.enqueue(json_dumps(Envelope(op=Op.ERROR, id=env.id, data={"code": "TENANT_RATE_LIMIT", "msg": str(re)}, ts=_now_iso()).dict()))

            elif env.op == Op.PING:
                await conn.enqueue(json_dumps(Envelope(op=Op.PONG, id=env.id, ts=_now_iso()).dict()))

            else:
                await conn.enqueue(json_dumps(Envelope(op=Op.ERROR, id=env.id, data={"code": "OP_UNSUPPORTED", "op": env.op}, ts=_now_iso()).dict()))

    except Exception:
        logger.exception("WS handler failed session=%s", conn.session_id)
        try:
            await websocket.close(code=1011)  # internal error
        except Exception:
            pass
    finally:
        # Cleanup
        try:
            await broker.drop_connection(conn)
        except Exception:
            logger.exception("broker cleanup failed for %s", conn.session_id)
        for task in (send_task, ping_task):
            if not task.done():
                task.cancel()
                try:
                    await task
                except Exception:
                    pass
        if websocket.application_state == WebSocketState.CONNECTED:
            try:
                await websocket.close(code=1000)
            except Exception:
                pass
        logger.info("WS closed session=%s", conn.session_id)
