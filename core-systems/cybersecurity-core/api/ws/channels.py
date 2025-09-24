from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional, Set, Tuple

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from starlette.websockets import WebSocketState

# -----------------------------------------------------------------------------
# Конфигурация через ENV
# -----------------------------------------------------------------------------
ALLOWED_WS_ORIGINS: Set[str] = {
    o.strip()
    for o in os.getenv("ALLOWED_WS_ORIGINS", "*").split(",")
    if o.strip()
}
WS_MAX_MESSAGE_BYTES: int = int(os.getenv("WS_MAX_MESSAGE_BYTES", "131072"))  # 128 KiB
WS_IDLE_TIMEOUT_SEC: int = int(os.getenv("WS_IDLE_TIMEOUT_SEC", "90"))
WS_HEARTBEAT_SEC: int = int(os.getenv("WS_HEARTBEAT_SEC", "25"))
WS_RATE_LIMIT_RPS: int = int(os.getenv("WS_RATE_LIMIT_RPS", "30"))
WS_RATE_LIMIT_BURST: int = int(os.getenv("WS_RATE_LIMIT_BURST", "60"))
WS_MAX_SUBSCRIPTIONS: int = int(os.getenv("WS_MAX_SUBSCRIPTIONS", "32"))
BROKER_BACKLOG_MAX: int = int(os.getenv("BROKER_BACKLOG_MAX", "1000"))
BROKER_QUEUE_MAXSIZE: int = int(os.getenv("BROKER_QUEUE_MAXSIZE", "1000"))
REDIS_URL: Optional[str] = os.getenv("REDIS_URL")

LOG = logging.getLogger("ws.channels")
LOG.setLevel(logging.INFO)

router = APIRouter()


# -----------------------------------------------------------------------------
# Помощники
# -----------------------------------------------------------------------------
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def safe_json_dumps(obj: Any) -> str:
    # Каноничная сериализация для стабильных ETag/хэшей при необходимости
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def parse_uuid(maybe: Optional[str]) -> Optional[uuid.UUID]:
    if not maybe:
        return None
    try:
        return uuid.UUID(maybe)
    except Exception:
        return None


def allow_origin(origin: Optional[str]) -> bool:
    if not origin:
        return True  # для приватных клиентов без Origin
    if "*" in ALLOWED_WS_ORIGINS:
        return True
    try:
        # Сравниваем по полному значению Origin (scheme://host[:port])
        return origin in ALLOWED_WS_ORIGINS
    except Exception:
        return False


# -----------------------------------------------------------------------------
# Модель субъекта (минимальная, без JWT)
# -----------------------------------------------------------------------------
@dataclass
class Subject:
    sub: str
    scopes: Set[str]
    is_admin: bool


def extract_subject(ws: WebSocket) -> Subject:
    x_actor = ws.headers.get("x-actor") or "anonymous"
    x_scopes = ws.headers.get("x-scopes", "")
    scopes = {s.strip() for s in x_scopes.split(",") if s.strip()}
    return Subject(sub=x_actor, scopes=scopes, is_admin=("admin" in scopes))


def extract_tenant(ws: WebSocket) -> Optional[uuid.UUID]:
    return parse_uuid(ws.headers.get("x-tenant-id"))


# -----------------------------------------------------------------------------
# Token Bucket rate limiter
# -----------------------------------------------------------------------------
class TokenBucket:
    def __init__(self, rate_per_sec: int, burst: int) -> None:
        self.rate = float(rate_per_sec)
        self.capacity = float(burst)
        self.tokens = float(burst)
        self.timestamp = time.monotonic()

    def allow(self) -> bool:
        now = time.monotonic()
        delta = now - self.timestamp
        self.timestamp = now
        self.tokens = min(self.capacity, self.tokens + delta * self.rate)
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


# -----------------------------------------------------------------------------
# Broker API
# -----------------------------------------------------------------------------
class Broker:
    async def publish(self, topic: str, message: dict) -> None:  # pragma: no cover
        raise NotImplementedError

    async def subscribe(self, topic: str) -> Tuple[asyncio.Queue, AsyncIterator[dict]]:  # pragma: no cover
        raise NotImplementedError

    async def unsubscribe(self, topic: str, queue: asyncio.Queue) -> None:  # pragma: no cover
        raise NotImplementedError

    async def close(self) -> None:  # pragma: no cover
        pass


class InMemoryBroker(Broker):
    def __init__(self) -> None:
        self._topics: Dict[str, Set[asyncio.Queue]] = defaultdict(set)
        self._backlog: Dict[str, deque] = defaultdict(lambda: deque(maxlen=BROKER_BACKLOG_MAX))
        self._lock = asyncio.Lock()

    async def publish(self, topic: str, message: dict) -> None:
        async with self._lock:
            self._backlog[topic].append(message)
            consumers = list(self._topics.get(topic, set()))
        for q in consumers:
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                # Drop message for this slow consumer (backpressure handling)
                LOG.warning("Drop event due to slow consumer: topic=%s", topic)

    async def subscribe(self, topic: str) -> Tuple[asyncio.Queue, AsyncIterator[dict]]:
        q: asyncio.Queue = asyncio.Queue(maxsize=BROKER_QUEUE_MAXSIZE)
        async with self._lock:
            self._topics[topic].add(q)
        async def _aiter() -> AsyncIterator[dict]:
            while True:
                item = await q.get()
                yield item
        return q, _aiter()

    async def unsubscribe(self, topic: str, queue: asyncio.Queue) -> None:
        async with self._lock:
            consumers = self._topics.get(topic)
            if consumers and queue in consumers:
                consumers.remove(queue)
                if not consumers:
                    self._topics.pop(topic, None)

    # Реплей последних N событий
    def replay(self, topic: str, last: int) -> List[dict]:
        if last <= 0:
            return []
        buf = self._backlog.get(topic)
        if not buf:
            return []
        return list(buf)[-last:]


# Опционально: Redis Pub/Sub (только если нужен). Безопасно деградирует на InMemory.
class RedisBroker(InMemoryBroker):
    def __init__(self, url: str) -> None:
        super().__init__()
        try:
            import redis.asyncio as redis  # type: ignore
        except Exception as e:  # noqa: BLE001
            raise RuntimeError("redis.asyncio is required for RedisBroker") from e
        self._redis = redis.from_url(url, decode_responses=True)
        self._pubsub = self._redis.pubsub()
        self._listener_task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        # Запуск глобального слушателя, ретранслирующего в локальные очереди и backlog
        async def _listen() -> None:
            await self._pubsub.psubscribe("ws:*")
            async for msg in self._pubsub.listen():
                if msg.get("type") not in {"pmessage", "message"}:
                    continue
                channel = msg.get("channel") or msg.get("pattern")
                payload = msg.get("data")
                try:
                    evt = json.loads(payload)
                except Exception:
                    continue
                # channel может быть "ws:<topic>"
                topic = evt.get("topic") or (channel[3:] if channel and channel.startswith("ws:") else channel)
                await super().publish(topic, evt)
        self._listener_task = asyncio.create_task(_listen(), name="redis-broker-listener")

    async def publish(self, topic: str, message: dict) -> None:
        await super().publish(topic, message)
        try:
            await self._redis.publish(f"ws:{topic}", safe_json_dumps({**message, "topic": topic}))
        except Exception as e:  # noqa: BLE001
            LOG.warning("Redis publish failed, local only. err=%s", e)

    async def close(self) -> None:
        try:
            if self._listener_task:
                self._listener_task.cancel()
            await self._pubsub.close()
        except Exception:
            pass


# Глобальный брокер (ленивая инициализация)
_broker: Optional[Broker] = None


def get_broker() -> Broker:
    global _broker
    if _broker is None:
        if REDIS_URL:
            try:
                rb = RedisBroker(REDIS_URL)
                asyncio.create_task(rb.start())
                _broker = rb
                LOG.info("RedisBroker initialized")
                return _broker
            except Exception as e:  # noqa: BLE001
                LOG.warning("RedisBroker init failed, fallback to InMemory: %s", e)
        _broker = InMemoryBroker()
        LOG.info("InMemoryBroker initialized")
    return _broker


# -----------------------------------------------------------------------------
# Сообщения протокола
# -----------------------------------------------------------------------------
class ProtocolError(Exception):
    pass


def _b64_cursor(ts: datetime, seq: int) -> str:
    raw = f"{ts.isoformat()}|{seq}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


@dataclass
class ClientState:
    ws: WebSocket
    subject: Subject
    tenant: Optional[uuid.UUID]
    subs: Set[str]
    bucket: TokenBucket
    last_seen: float
    send_queue: asyncio.Queue  # очередь исходящих сообщений (для бэкпрешсера)


# -----------------------------------------------------------------------------
# Endpoint
# -----------------------------------------------------------------------------
@router.websocket("/v1/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    # Origin check
    origin = ws.headers.get("origin")
    if not allow_origin(origin):
        await ws.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Простейшая аутентификация от заголовков
    subject = extract_subject(ws)
    tenant = extract_tenant(ws)

    await ws.accept()
    LOG.info("WS connected sub=%s tenant=%s origin=%s", subject.sub, tenant, origin)

    # Инициализация клиентского состояния
    state = ClientState(
        ws=ws,
        subject=subject,
        tenant=tenant,
        subs=set(),
        bucket=TokenBucket(WS_RATE_LIMIT_RPS, WS_RATE_LIMIT_BURST),
        last_seen=time.monotonic(),
        send_queue=asyncio.Queue(maxsize=2048),
    )

    # Heartbeat и отправка
    tasks = [
        asyncio.create_task(_recv_loop(state), name="ws-recv"),
        asyncio.create_task(_send_loop(state), name="ws-send"),
        asyncio.create_task(_heartbeat_loop(state), name="ws-heartbeat"),
    ]
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:  # pragma: no cover
        pass
    finally:
        await _cleanup_subscriptions(state)
        for t in tasks:
            t.cancel()
        LOG.info("WS disconnected sub=%s tenant=%s", subject.sub, tenant)


# -----------------------------------------------------------------------------
# Основные циклы
# -----------------------------------------------------------------------------
async def _recv_loop(state: ClientState) -> None:
    ws = state.ws
    while True:
        # idle timeout
        if time.monotonic() - state.last_seen > WS_IDLE_TIMEOUT_SEC:
            await ws.close(code=status.WS_1000_NORMAL_CLOSURE)
            return
        try:
            raw = await asyncio.wait_for(ws.receive_bytes(), timeout=1.0)
        except asyncio.TimeoutError:
            continue
        except WebSocketDisconnect:
            return

        state.last_seen = time.monotonic()

        if len(raw) > WS_MAX_MESSAGE_BYTES:
            await _send_error(state, "message_too_large", "Message exceeds WS_MAX_MESSAGE_BYTES")
            continue

        try:
            msg = json.loads(raw.decode("utf-8"))
        except Exception:
            await _send_error(state, "bad_json", "Unable to decode JSON")
            continue

        try:
            await _handle_message(state, msg)
        except ProtocolError as e:
            await _send_error(state, "protocol_error", str(e))
        except Exception as e:  # noqa: BLE001
            LOG.exception("WS handler error: %s", e)
            await _send_error(state, "internal_error", "Unhandled server error")


async def _send_loop(state: ClientState) -> None:
    ws = state.ws
    while True:
        try:
            payload = await state.send_queue.get()
            if ws.client_state != WebSocketState.CONNECTED:
                return
            await ws.send_text(safe_json_dumps(payload))
        except WebSocketDisconnect:
            return
        except Exception as e:  # noqa: BLE001
            LOG.warning("send_loop error: %s", e)
            return


async def _heartbeat_loop(state: ClientState) -> None:
    ws = state.ws
    while True:
        await asyncio.sleep(WS_HEARTBEAT_SEC)
        if ws.client_state != WebSocketState.CONNECTED:
            return
        try:
            await ws.send_text(safe_json_dumps({"op": "pong", "ts": iso(utcnow())}))
        except WebSocketDisconnect:
            return
        except Exception:
            return


# -----------------------------------------------------------------------------
# Обработка команд протокола
# -----------------------------------------------------------------------------
async def _handle_message(state: ClientState, msg: dict) -> None:
    if not isinstance(msg, dict):
        raise ProtocolError("Message must be an object")

    op = msg.get("op")
    if not op:
        raise ProtocolError("Missing 'op'")

    if not state.bucket.allow():
        await _send_error(state, "rate_limited", "Too many requests")
        return

    if op == "ping":
        await _send(state, {"op": "pong", "ts": iso(utcnow())})
        return

    if op == "subscribe":
        await _op_subscribe(state, msg)
        return

    if op == "unsubscribe":
        await _op_unsubscribe(state, msg)
        return

    if op == "publish":
        await _op_publish(state, msg)
        return

    if op == "ack":
        # Ничего не делаем, но можем обновлять last_seen
        return

    raise ProtocolError(f"Unsupported op '{op}'")


def _normalize_channel(raw_chan: str) -> str:
    if not raw_chan or not isinstance(raw_chan, str):
        raise ProtocolError("Field 'chan' must be non-empty string")
    # Разрешаем a-z0-9._-:
    if not all(c.isalnum() or c in "._:-" for c in raw_chan):
        raise ProtocolError("Invalid characters in 'chan'")
    return raw_chan


def _topic_for(tenant: Optional[uuid.UUID], chan: str) -> str:
    # Топик с префиксом тенанта; глобальные без префикса
    return f"{tenant}:{chan}" if tenant else f"global:{chan}"


async def _op_subscribe(state: ClientState, msg: dict) -> None:
    chan = _normalize_channel(msg.get("chan"))
    replay_last = int(msg.get("replay_last") or 0)
    if len(state.subs) >= WS_MAX_SUBSCRIPTIONS and chan not in state.subs:
        raise ProtocolError("Subscriptions limit exceeded")
    topic = _topic_for(state.tenant, chan)

    broker = get_broker()
    q, it = await broker.subscribe(topic)

    # Сохраняем подписку и запускаем таск доставки
    state.subs.add(chan)
    asyncio.create_task(_pump_topic_to_client(state, chan, q, it), name=f"pump:{chan}")

    # Реплей (только InMemory/RedisBroker реализуют replay noop для Redis)
    replay_payloads: List[dict] = []
    if isinstance(broker, InMemoryBroker) and replay_last > 0:
        replay_payloads = broker.replay(topic, replay_last)

    await _send(
        state,
        {
            "op": "subscribed",
            "chan": chan,
            "topic": topic,
            "replayed": len(replay_payloads),
            "ts": iso(utcnow()),
        },
    )
    for evt in replay_payloads:
        await _emit_event(state, chan, evt)


async def _op_unsubscribe(state: ClientState, msg: dict) -> None:
    chan = _normalize_channel(msg.get("chan"))
    if chan not in state.subs:
        return
    topic = _topic_for(state.tenant, chan)
    await _unsubscribe_topic(state, chan, topic)
    await _send(state, {"op": "unsubscribed", "chan": chan, "ts": iso(utcnow())})


async def _op_publish(state: ClientState, msg: dict) -> None:
    # Только для клиентов с правами
    if not (state.subject.is_admin or ("ws:publish" in state.subject.scopes)):
        raise ProtocolError("Not allowed to publish")

    chan = _normalize_channel(msg.get("chan"))
    topic = _topic_for(state.tenant, chan)
    payload = msg.get("payload")
    if payload is None:
        raise ProtocolError("Missing 'payload'")

    event = {
        "ts": iso(utcnow()),
        "seq": int(time.time() * 1000),  # простой монотонный seq на основе времени
        "payload": payload,
    }
    await get_broker().publish(topic, event)
    await _send(state, {"op": "published", "chan": chan, "seq": event["seq"], "ts": event["ts"]})


async def _pump_topic_to_client(
    state: ClientState,
    chan: str,
    q: asyncio.Queue,
    it: AsyncIterator[dict],
) -> None:
    topic = _topic_for(state.tenant, chan)
    try:
        async for evt in it:
            # evt ожидается dict {"ts":..,"seq":..,"payload":..}
            await _emit_event(state, chan, evt)
    except asyncio.CancelledError:  # pragma: no cover
        pass
    except Exception as e:  # noqa: BLE001
        LOG.warning("pump error chan=%s topic=%s err=%s", chan, topic, e)
    finally:
        try:
            await get_broker().unsubscribe(topic, q)
        except Exception:
            pass


async def _emit_event(state: ClientState, chan: str, evt: dict) -> None:
    msg = {
        "op": "event",
        "chan": chan,
        "ts": evt.get("ts") or iso(utcnow()),
        "seq": evt.get("seq"),
        "payload": evt.get("payload"),
    }
    await _send(state, msg)


async def _send(state: ClientState, payload: dict) -> None:
    try:
        state.send_queue.put_nowait(payload)
    except asyncio.QueueFull:
        # Консьюмер крайне медленный — закрываем соединение
        LOG.warning("Outbound queue overflow, closing connection")
        await state.ws.close(code=status.WS_1011_INTERNAL_ERROR)


async def _unsubscribe_topic(state: ClientState, chan: str, topic: str) -> None:
    # Найти задачу насоса по имени и отменить — упростим, rely на broker.unsubscribe в finally
    # Здесь просто удаляем из набора
    if chan in state.subs:
        state.subs.remove(chan)
    # Брокер отписывает в _pump_topic_to_client.finally


async def _cleanup_subscriptions(state: ClientState) -> None:
    # Брокерские очереди освобождаются в pump.finally; здесь достаточно очистить set
    state.subs.clear()


# -----------------------------------------------------------------------------
# Служебная отправка ошибок
# -----------------------------------------------------------------------------
async def _send_error(state: ClientState, code: str, detail: str) -> None:
    await _send(
        state,
        {"op": "error", "code": code, "detail": detail, "ts": iso(utcnow())},
    )
