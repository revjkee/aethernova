# physical-integration-core/api/ws/channels.py
from __future__ import annotations

import asyncio
import json
import logging
import time
import fnmatch
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from fastapi import Depends, HTTPException, status

# ============================
# Публичные контракты/интерфейсы
# ============================

@dataclass
class Principal:
    subject: str
    roles: Set[str] = field(default_factory=set)
    # произвольные клеймы
    claims: Dict[str, Any] = field(default_factory=dict)

class AuthProvider:
    async def authenticate(self, token: Optional[str]) -> Principal:
        """
        Возвращает Principal или выбрасывает HTTPException(401/403).
        """
        raise NotImplementedError

class Authorizer:
    async def can_subscribe(self, principal: Principal, topic_pattern: str) -> bool:
        raise NotImplementedError

    async def can_publish(self, principal: Principal, topic: str) -> bool:
        raise NotImplementedError

class Metrics:
    def inc(self, name: str, **labels): pass
    def observe(self, name: str, value: float, **labels): pass
    def gauge(self, name: str, value: float, **labels): pass

# ============================
# Вспомогательные структуры
# ============================

class TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int):
        self.rate = rate_per_sec
        self.burst = float(burst)
        self.tokens = float(burst)
        self.last = time.monotonic()

    async def take(self, n: float = 1.0):
        while True:
            now = time.monotonic()
            delta = now - self.last
            self.last = now
            self.tokens = min(self.burst, self.tokens + delta * self.rate)
            if self.tokens >= n:
                self.tokens -= n
                return
            await asyncio.sleep(max((n - self.tokens) / self.rate, 0.005))

class LRUIdSet:
    """Идемпотентность сообщений по msg_id с ограничением размера."""
    def __init__(self, max_items: int = 4096):
        self.max_items = max_items
        self._dq = deque()   # type: deque[str]
        self._set: Set[str] = set()

    def add(self, mid: str) -> bool:
        """True если новый, False если уже был."""
        if mid in self._set:
            return False
        self._dq.append(mid)
        self._set.add(mid)
        if len(self._dq) > self.max_items:
            old = self._dq.popleft()
            self._set.discard(old)
        return True

def now_ms() -> int:
    return int(time.time() * 1000)

# ============================
# Топики и шаблоны (* и #)
# ============================

def topic_match(pattern: str, topic: str) -> bool:
    """
    Поддержка MQTT-подобных шаблонов:
      * — один сегмент, # — 0..N сегментов.
    Также поддерживаем fnmatch как fallback.
    """
    if "#" in pattern or "*" in pattern:
        # преобразуем к fnmatch-совместимому виду
        parts = []
        for seg in pattern.split("."):
            if seg == "#":
                parts.append("*")  # многосегментный, приблизим
            elif seg == "*":
                parts.append("*")
            else:
                parts.append(seg)
        glob = ".".join(parts)
        return fnmatch.fnmatchcase(topic, glob)
    return pattern == topic

# ============================
# Сообщения/протокол
# ============================

"""
Клиент -> Сервер (JSON):
  {"op":"sub", "topics":["twins.*.state", "events.#"]}
  {"op":"unsub", "topics":["events.alerts"]}
  {"op":"pub", "topic":"commands.123.request", "data":{...}, "msg_id":"uuid-...", "ack":true}
  {"op":"pong"} / {"op":"ping"}

Сервер -> Клиент:
  {"op":"event", "topic":"...", "ts":<ms>, "seq":<int>, "data":{...}}
  {"op":"ack", "msg_id":"...", "ts":<ms>}
  {"op":"err", "code":"...", "reason":"..."}
  {"op":"ping", "ts":<ms>}
"""

# ============================
# Брокер (in-memory по умолчанию)
# ============================

class InMemoryBroker:
    """
    Простой брокер: маршрутизирует публикации по активным соединениям.
    Можно заменить на Redis/Kafka, сохранив интерфейс publish().
    """
    def __init__(self):
        self._seq_by_topic: Dict[str, int] = {}
        self._subs: Dict[int, Set[str]] = {}          # conn_id -> patterns
        self._conns: Dict[int, "Connection"] = {}     # conn_id -> Connection
        self._lock = asyncio.Lock()

    async def register(self, conn: "Connection"):
        async with self._lock:
            self._conns[conn.conn_id] = conn
            self._subs.setdefault(conn.conn_id, set())

    async def unregister(self, conn: "Connection"):
        async with self._lock:
            self._conns.pop(conn.conn_id, None)
            self._subs.pop(conn.conn_id, None)

    async def subscribe(self, conn: "Connection", patterns: Iterable[str]):
        async with self._lock:
            s = self._subs.setdefault(conn.conn_id, set())
            for p in patterns:
                s.add(p)

    async def unsubscribe(self, conn: "Connection", patterns: Iterable[str]):
        async with self._lock:
            s = self._subs.get(conn.conn_id, set())
            for p in patterns:
                s.discard(p)

    async def publish(self, topic: str, payload: Any):
        """
        Рассылает событие подписчикам.
        """
        async with self._lock:
            seq = self._seq_by_topic.get(topic, 0) + 1
            self._seq_by_topic[topic] = seq
            targets: List["Connection"] = []
            for cid, pats in self._subs.items():
                if cid not in self._conns:
                    continue
                for pat in pats:
                    if topic_match(pat, topic):
                        targets.append(self._conns[cid])
                        break

        evt = {"op":"event", "topic":topic, "ts":now_ms(), "seq":seq, "data":payload}
        # Не держим lock при отправке
        await asyncio.gather(*(c.enqueue(evt) for c in targets), return_exceptions=True)

# ============================
# Соединение и менеджер
# ============================

_CONN_ID = 0
def _next_conn_id() -> int:
    global _CONN_ID
    _CONN_ID += 1
    return _CONN_ID

@dataclass
class Connection:
    conn_id: int
    ws: WebSocket
    principal: Principal
    out_queue: asyncio.Queue
    inbound_limiter: TokenBucket
    outbound_limiter: TokenBucket
    dedupe: LRUIdSet
    last_pong: float
    logger: logging.Logger
    metrics: Metrics
    backpressure_policy: str = "close"  # "close"|"drop_oldest"

    async def enqueue(self, message: Dict[str, Any]):
        await self.outbound_limiter.take(1.0)
        try:
            self.out_queue.put_nowait(message)
            self.metrics.inc("ws_out_enqueued", op=message.get("op","event"))
        except asyncio.QueueFull:
            self.metrics.inc("ws_out_backpressure")
            if self.backpressure_policy == "drop_oldest":
                try:
                    _ = self.out_queue.get_nowait()
                except Exception:
                    pass
                self.out_queue.put_nowait(message)
            else:
                self.logger.warning("Backpressure: closing connection %s", self.conn_id)
                await self.ws.close(code=1011, reason="backpressure")

class ConnectionManager:
    def __init__(self, broker: InMemoryBroker, authorizer: Authorizer, metrics: Metrics, logger: logging.Logger):
        self.broker = broker
        self.authorizer = authorizer
        self.metrics = metrics
        self.logger = logger

    async def handle(self, ws: WebSocket, principal: Principal,
                     initial_topics: List[str],
                     inbound_rps: float, inbound_burst: int,
                     outbound_rps: float, outbound_burst: int,
                     ping_interval: float, pong_timeout: float):
        await ws.accept()

        conn = Connection(
            conn_id=_next_conn_id(),
            ws=ws,
            principal=principal,
            out_queue=asyncio.Queue(maxsize=1000),
            inbound_limiter=TokenBucket(inbound_rps, inbound_burst),
            outbound_limiter=TokenBucket(outbound_rps, outbound_burst),
            dedupe=LRUIdSet(4096),
            last_pong=time.monotonic(),
            logger=self.logger,
            metrics=self.metrics,
        )
        await self.broker.register(conn)
        self.metrics.inc("ws_connections_opened")
        self.metrics.gauge("ws_connections_active", 1)

        # начальные подписки
        if initial_topics:
            await self._subscribe_checked(conn, initial_topics)

        send_task = asyncio.create_task(self._sender(conn))
        recv_task = asyncio.create_task(self._receiver(conn))
        ping_task = asyncio.create_task(self._pinger(conn, ping_interval, pong_timeout))

        try:
            await asyncio.wait({send_task, recv_task, ping_task}, return_when=asyncio.FIRST_EXCEPTION)
        finally:
            for t in (send_task, recv_task, ping_task):
                t.cancel()
            await self.broker.unregister(conn)
            try:
                await ws.close()
            except Exception:
                pass
            self.metrics.inc("ws_connections_closed")

    async def _sender(self, conn: Connection):
        while True:
            msg = await conn.out_queue.get()
            try:
                await conn.ws.send_text(json.dumps(msg, separators=(",",":")))
                self.metrics.inc("ws_out_sent", op=msg.get("op","event"))
            except Exception as e:
                conn.logger.warning("Send failed, closing: %s", e)
                await conn.ws.close()
                return

    async def _receiver(self, conn: Connection):
        while True:
            try:
                raw = await conn.ws.receive_text()
            except WebSocketDisconnect:
                return
            except Exception as e:
                conn.logger.debug("Receive error: %s", e)
                return

            await conn.inbound_limiter.take(1.0)

            try:
                msg = json.loads(raw)
                op = msg.get("op")
            except Exception:
                await self._send_err(conn, "bad_json", "Payload must be valid JSON")
                continue

            if op == "pong":
                conn.last_pong = time.monotonic()
                continue

            if op == "ping":
                await conn.enqueue({"op":"pong", "ts":now_ms()})
                continue

            if op == "sub":
                topics = _as_list(msg.get("topics"))
                if not topics:
                    await self._send_err(conn, "bad_request", "topics required")
                    continue
                await self._subscribe_checked(conn, topics)
                continue

            if op == "unsub":
                topics = _as_list(msg.get("topics"))
                if not topics:
                    await self._send_err(conn, "bad_request", "topics required")
                    continue
                await self.broker.unsubscribe(conn, topics)
                self.metrics.inc("ws_unsubscribed", n=len(topics))
                continue

            if op == "pub":
                topic = msg.get("topic")
                if not isinstance(topic, str) or not topic:
                    await self._send_err(conn, "bad_request", "topic required")
                    continue
                if not await self.authorizer.can_publish(conn.principal, topic):
                    await self._send_err(conn, "forbidden", "publish not allowed")
                    continue

                msg_id = msg.get("msg_id")
                if msg_id and not isinstance(msg_id, str):
                    await self._send_err(conn, "bad_request", "msg_id must be string")
                    continue
                if msg_id:
                    fresh = conn.dedupe.add(msg_id)
                    if not fresh:
                        # тихо подтверждаем повтор
                        await conn.enqueue({"op":"ack", "msg_id":msg_id, "ts":now_ms()})
                        continue

                data = msg.get("data")
                await self.broker.publish(topic, data)
                self.metrics.inc("ws_published")
                if msg.get("ack"):
                    await conn.enqueue({"op":"ack", "msg_id":msg_id or "", "ts":now_ms()})
                continue

            await self._send_err(conn, "unsupported_op", f"Unsupported op: {op}")

    async def _pinger(self, conn: Connection, interval: float, timeout: float):
        if interval <= 0:
            return
        while True:
            await asyncio.sleep(interval)
            try:
                await conn.enqueue({"op":"ping", "ts":now_ms()})
            except Exception:
                return
            if time.monotonic() - conn.last_pong > timeout:
                conn.logger.info("Heartbeat timeout, closing %s", conn.conn_id)
                try:
                    await conn.ws.close(code=1011, reason="heartbeat timeout")
                finally:
                    return

    async def _subscribe_checked(self, conn: Connection, patterns: List[str]):
        allowed: List[str] = []
        for p in patterns:
            if not isinstance(p, str) or not p:
                continue
            if await self.authorizer.can_subscribe(conn.principal, p):
                allowed.append(p)
        if not allowed:
            await self._send_err(conn, "forbidden", "no topics allowed")
            return
        await self.broker.subscribe(conn, allowed)
        self.metrics.inc("ws_subscribed", n=len(allowed))

    async def _send_err(self, conn: Connection, code: str, reason: str):
        await conn.enqueue({"op":"err", "code":code, "reason":reason})

def _as_list(val: Any) -> List[str]:
    if val is None: return []
    if isinstance(val, list): return [str(x) for x in val]
    return [str(val)]

# ============================
# Простые реализации AuthZ/AuthN по умолчанию
# ============================

class DefaultAuth(AuthProvider):
    async def authenticate(self, token: Optional[str]) -> Principal:
        if not token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing access_token")
        # В реальной системе здесь верифицируется JWT/mTLS и загружаются роли
        roles = {"ot-operator","ot-maintainer"} if token else set()
        return Principal(subject="caller", roles=roles, claims={"token_len":len(token)})

class DefaultAuthorizer(Authorizer):
    async def can_subscribe(self, principal: Principal, topic_pattern: str) -> bool:
        # Примеры: оператору разрешаем телеметрию и состояние
        if "ot-operator" in principal.roles:
            return any(topic_pattern.startswith(p) for p in ("twins.", "events.", "telemetry.", "commands.*.status"))
        if "ot-maintainer" in principal.roles:
            return True
        return False

    async def can_publish(self, principal: Principal, topic: str) -> bool:
        # Публиковать команды — только maintainer/operator
        if topic.startswith("commands.") and ("ot-maintainer" in principal.roles or "ot-operator" in principal.roles):
            return True
        # Остальные топики — запрет по умолчанию
        return False

class NoopMetrics(Metrics):
    pass

# ============================
# DI фабрики
# ============================

def get_logger() -> logging.Logger:
    return logging.getLogger("pic.ws")

def get_metrics() -> Metrics:
    return NoopMetrics()

def get_auth_provider() -> AuthProvider:
    return DefaultAuth()

def get_authorizer() -> Authorizer:
    return DefaultAuthorizer()

def get_broker() -> InMemoryBroker:
    return InMemoryBroker()

def get_manager(
    broker: InMemoryBroker = Depends(get_broker),
    authorizer: Authorizer = Depends(get_authorizer),
    metrics: Metrics = Depends(get_metrics),
    logger: logging.Logger = Depends(get_logger),
) -> ConnectionManager:
    return ConnectionManager(broker, authorizer, metrics, logger)

# ============================
# FastAPI Router
# ============================

router = APIRouter(prefix="/v1/ws", tags=["ws"])

@router.websocket("")
async def ws_root(
    websocket: WebSocket,
    manager: ConnectionManager = Depends(get_manager),
    auth: AuthProvider = Depends(get_auth_provider),
    access_token: Optional[str] = Query(default=None, description="Bearer для аутентификации"),
    topics: Optional[str] = Query(default=None, description="Начальные подписки, через запятую"),
    inbound_rps: float = Query(default=50.0, ge=1.0, le=1000.0, description="Лимит входящих сообщений/сек на соединение"),
    inbound_burst: int = Query(default=100, ge=1, le=5000),
    outbound_rps: float = Query(default=500.0, ge=1.0, le=5000.0),
    outbound_burst: int = Query(default=1000, ge=1, le=20000),
    ping_interval: float = Query(default=15.0, ge=0.0, le=600.0),
    pong_timeout: float = Query(default=45.0, ge=1.0, le=1200.0),
):
    """
    Идиоматический WS-эндпоинт для подписки/публикации.
    Авторизация — через `access_token` (клиенты без заголовков WS).
    """
    principal = await auth.authenticate(access_token)
    init_topics = [t.strip() for t in (topics.split(",") if topics else []) if t.strip()]
    await manager.handle(
        websocket, principal, init_topics,
        inbound_rps, inbound_burst,
        outbound_rps, outbound_burst,
        ping_interval, pong_timeout
    )

# ============================
# Публичный API публикации для внутренних сервисов
# ============================

class ChannelsAPI:
    """Инъецируйте в фоновые задачи/обработчики HTTP для публикации событий в WS."""
    def __init__(self, broker: InMemoryBroker):
        self.broker = broker

    async def publish(self, topic: str, payload: Any):
        await self.broker.publish(topic, payload)

# Фабрика для внедрения ChannelsAPI в app.state
def create_channels_api() -> ChannelsAPI:
    return ChannelsAPI(get_broker())
