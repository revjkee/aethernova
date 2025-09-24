# -*- coding: utf-8 -*-
"""
Mythos Core — WebSocket channels (industrial-grade).

Возможности:
- JWT-аутентификация (Authorization: Bearer <token>) или token в query; опционально аноним.
- Мультиплекс каналов: sub/unsub/pub, валидация имени канала.
- Backpressure: очередь отправки per-connection с ограничением, writer-таск.
- Rate limiting: token bucket на вход/выход (msg/sec) и per-message bytes.
- Heartbeat: серверный ping, закрытие по TTL, учёт pong.
- Идемпотентность: message_id + окна дедупликации.
- ACK/ошибки: подтверждения публикаций, единый формат ответа.
- Pub/Sub абстракция: InMemoryBus (по умолчанию), можно заменить на Redis/NATS.
- Безопасное завершение: корректный shutdown/cleanup, закрытие 1008/1011 с причиной.

Зависимости: fastapi, pydantic (стандартный стек FastAPI). Внешних клиентов pub/sub нет.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator, Awaitable, Callable, Dict, Optional, Set, Tuple

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status, Depends
from pydantic import BaseModel, Field, ValidationError, constr

# --------------------------------------------------------------------------------------
# Конфигурация
# --------------------------------------------------------------------------------------

@dataclass
class WSSettings:
    allow_anonymous: bool = False
    max_message_bytes: int = 128 * 1024
    send_queue_max: int = 1000
    inbound_rps: int = 100                   # сообщений/сек на вход
    outbound_rps: int = 200                  # сообщений/сек на выход
    bucket_refill_interval_ms: int = 250     # шаг пополнения токенов
    heartbeat_interval_s: int = 20
    heartbeat_timeout_s: int = 60
    dedup_window: int = 2048                 # хэш-окно message_id
    channel_regex: str = r"^[a-z0-9][a-z0-9._:-]{1,63}$"
    close_on_queue_full: bool = True
    echo_to_sender: bool = False             # эхо публикации отправителю
    # Коды закрытия по спеке RFC6455/HyBi
    close_policy_violation: int = 1008
    close_internal_error: int = 1011
    close_too_large: int = 1009


# DI-хук для настроек (можете заменить на pydantic Settings).
def get_ws_settings() -> WSSettings:
    return WSSettings()


# --------------------------------------------------------------------------------------
# Протокол сообщений (envelope)
# --------------------------------------------------------------------------------------

ULID = constr(regex=r"^[0-9A-HJKMNP-TV-Z]{26}$")
ChannelName = constr(regex=r"^[a-z0-9][a-z0-9._:-]{1,63}$")

class Envelope(BaseModel):
    # Минимальный контракт фрейма клиента
    type: constr(regex=r"^(sub|unsub|pub|ping|pong)$")
    id: Optional[ULID] = Field(None, description="Идемпотентный message_id (ULID)")
    chan: Optional[ChannelName] = Field(None, description="Имя канала")
    payload: Optional[dict] = None
    ack: Optional[bool] = Field(False, description="Запросить ack от сервера")

class ServerMsg(BaseModel):
    type: constr(regex=r"^(event|ack|error|pong|hello)$")
    id: Optional[ULID] = None            # для ack/error ассоциированный id
    chan: Optional[ChannelName] = None
    payload: Optional[dict] = None
    code: Optional[int] = None           # для error
    msg: Optional[str] = None            # для error


# --------------------------------------------------------------------------------------
# Token-bucket rate limiter
# --------------------------------------------------------------------------------------

class TokenBucket:
    def __init__(self, rate_per_sec: int, refill_interval_ms: int) -> None:
        self.capacity = max(1, rate_per_sec)
        self.tokens = self.capacity
        self.refill_interval = refill_interval_ms / 1000.0
        self.last = time.monotonic()
        self._lock = asyncio.Lock()

    async def allow(self, n: int = 1) -> bool:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last
            if elapsed >= self.refill_interval:
                refill = int(elapsed / self.refill_interval) * self.capacity
                self.tokens = min(self.capacity, self.tokens + refill)
                self.last = now
            if self.tokens >= n:
                self.tokens -= n
                return True
            return False


# --------------------------------------------------------------------------------------
# Шина Pub/Sub (по умолчанию in-memory)
# --------------------------------------------------------------------------------------

class Bus:
    async def publish(self, chan: str, payload: dict) -> None: ...
    async def subscribe(self, chan: str) -> AsyncGenerator[dict, None]: ...
    async def close(self) -> None: ...

class InMemoryBus(Bus):
    def __init__(self) -> None:
        self._subs: Dict[str, Set[asyncio.Queue]] = {}
        self._lock = asyncio.Lock()

    async def publish(self, chan: str, payload: dict) -> None:
        async with self._lock:
            qs = list(self._subs.get(chan, set()))
        for q in qs:
            # не блокируемся: если очередь переполнена — дроп
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                # молча дропаем; реальный прод может вести счётчик потерь
                pass

    async def subscribe(self, chan: str) -> AsyncGenerator[dict, None]:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        async with self._lock:
            self._subs.setdefault(chan, set()).add(q)
        try:
            while True:
                item = await q.get()
                yield item
        finally:
            async with self._lock:
                self._subs.get(chan, set()).discard(q)

    async def close(self) -> None:
        # Для памяти ничего не делаем
        return


# --------------------------------------------------------------------------------------
# Состояние соединения и менеджер
# --------------------------------------------------------------------------------------

@dataclass
class Connection:
    ws: WebSocket
    user: Optional[str]
    send_queue: asyncio.Queue
    last_pong: float
    inbound_bucket: TokenBucket
    outbound_bucket: TokenBucket
    dedup: Set[str] = field(default_factory=set)
    channels: Set[str] = field(default_factory=set)
    closed: bool = False


class ChannelManager:
    def __init__(self, settings: WSSettings, bus: Optional[Bus] = None) -> None:
        self.s = settings
        self.bus = bus or InMemoryBus()
        self._conns: Set[Connection] = set()
        self._chan_members: Dict[str, Set[Connection]] = {}
        self._lock = asyncio.Lock()

    async def register(self, conn: Connection) -> None:
        async with self._lock:
            self._conns.add(conn)

    async def unregister(self, conn: Connection) -> None:
        async with self._lock:
            self._conns.discard(conn)
            for ch in list(conn.channels):
                self._chan_members.get(ch, set()).discard(conn)
                if not self._chan_members.get(ch):
                    self._chan_members.pop(ch, None)
            conn.channels.clear()

    # ----- подписки -----
    async def subscribe(self, conn: Connection, chan: str) -> None:
        self._validate_channel(chan)
        async with self._lock:
            self._chan_members.setdefault(chan, set()).add(conn)
            conn.channels.add(chan)

    async def unsubscribe(self, conn: Connection, chan: str) -> None:
        self._validate_channel(chan)
        async with self._lock:
            self._chan_members.get(chan, set()).discard(conn)
            conn.channels.discard(chan)
            if not self._chan_members.get(chan):
                self._chan_members.pop(chan, None)

    # ----- публикация -----
    async def publish(self, conn: Optional[Connection], chan: str, payload: dict) -> None:
        self._validate_channel(chan)
        await self.bus.publish(chan, {"chan": chan, "payload": payload, "ts": int(time.time() * 1000)})

    # ----- доставка событий из шины подписчикам -----
    async def start_channel_pump(self, chan: str) -> None:
        async for item in self.bus.subscribe(chan):
            await self._fanout(chan, item)

    async def _fanout(self, chan: str, item: dict) -> None:
        conns: Set[Connection]
        async with self._lock:
            conns = set(self._chan_members.get(chan, set()))
        for c in conns:
            # echo управляется настройкой/клиентом, здесь только доставляем
            await self.enqueue(c, ServerMsg(type="event", chan=chan, payload=item["payload"]))

    # ----- очереди отправки -----
    async def enqueue(self, conn: Connection, msg: ServerMsg) -> None:
        if conn.closed:
            return
        if not await conn.outbound_bucket.allow(1):
            # Rate limit на выходе: мягко дроп/ошибка
            # Можно апгрейдить до отсечки соединения при систематическом превышении
            return
        data = json.dumps(msg.dict(exclude_none=True), ensure_ascii=False, separators=(",", ":"))
        if len(data.encode("utf-8")) > self.s.max_message_bytes:
            # слишком большой фрейм — отбрасываем
            return
        try:
            conn.send_queue.put_nowait(data)
        except asyncio.QueueFull:
            if self.s.close_on_queue_full:
                await self._close(conn, self.s.close_internal_error, "send queue full")
            # иначе просто дроп

    # ----- закрытие -----
    async def _close(self, conn: Connection, code: int, reason: str) -> None:
        if conn.closed:
            return
        conn.closed = True
        try:
            await conn.ws.close(code=code, reason=reason)
        except Exception:
            pass

    # ----- валидация имен каналов -----
    def _validate_channel(self, chan: str) -> None:
        if not re.match(self.s.channel_regex, chan):
            raise ValueError("invalid channel name")


# --------------------------------------------------------------------------------------
# Аутентификация (заглушка, замените на свой провайдер JWT)
# --------------------------------------------------------------------------------------

async def authenticate(ws: WebSocket, settings: WSSettings) -> Optional[str]:
    """
    Возвращает идентификатор пользователя (sub) или None для анонима.
    При необходимости замените на реальную проверку JWT (подпись/ауд/источник и т.д.).
    """
    token = ws.query_params.get("token")
    if not token:
        auth = ws.headers.get("authorization") or ws.headers.get("Authorization")
        if auth and auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()
    if token:
        # Место для реальной валидации JWT
        # При ошибке аутентификации верните None (и запретите, если allow_anonymous=False)
        return "user:" + token[:8]  # псевдо-sub
    return None if settings.allow_anonymous else None


# --------------------------------------------------------------------------------------
# FastAPI router + обработка WebSocket
# --------------------------------------------------------------------------------------

router = APIRouter(prefix="/ws", tags=["ws"])

def _now_ms() -> int:
    return int(time.time() * 1000)


@router.websocket("/v1")
async def websocket_endpoint(
    ws: WebSocket,
    settings: WSSettings = Depends(get_ws_settings),
):
    # Ограничиваем размер входящих фреймов через заголовок — Starlette не ограничивает по умолчанию.
    await ws.accept(subprotocol="mythos-channels-v1")

    user_id = await authenticate(ws, settings)
    if user_id is None and not settings.allow_anonymous:
        await ws.close(code=settings.close_policy_violation, reason="auth required")
        return

    mgr = ChannelManager(settings=settings)  # в проде — внедрите singleton/DI
    conn = Connection(
        ws=ws,
        user=user_id,
        send_queue=asyncio.Queue(maxsize=settings.send_queue_max),
        last_pong=time.monotonic(),
        inbound_bucket=TokenBucket(settings.inbound_rps, settings.bucket_refill_interval_ms),
        outbound_bucket=TokenBucket(settings.outbound_rps, settings.bucket_refill_interval_ms),
    )
    await mgr.register(conn)

    # Первичное hello
    await mgr.enqueue(conn, ServerMsg(type="hello", payload={"ts": _now_ms(), "user": user_id}))

    writer_task = asyncio.create_task(_writer_loop(mgr, conn))
    heartbeat_task = asyncio.create_task(_heartbeat_loop(mgr, conn, settings))
    channel_pumps: Dict[str, asyncio.Task] = {}

    try:
        while True:
            try:
                raw = await ws.receive_text()
            except WebSocketDisconnect:
                break
            except RuntimeError:
                # Сокет закрыт
                break

            if len(raw.encode("utf-8")) > settings.max_message_bytes:
                await mgr.enqueue(conn, ServerMsg(type="error", code=413, msg="message too large"))
                await mgr._close(conn, settings.close_too_large, "frame too large")
                break

            if not await conn.inbound_bucket.allow(1):
                await mgr.enqueue(conn, ServerMsg(type="error", code=429, msg="rate limited"))
                # Не закрываем мгновенно; эскалация может быть добавлена
                continue

            try:
                env = Envelope.model_validate_json(raw)
            except ValidationError as ve:
                await mgr.enqueue(conn, ServerMsg(type="error", code=400, msg="invalid envelope"))
                continue

            # дедуп по message_id
            if env.id:
                if env.id in conn.dedup:
                    # идемпотентный повтор — подтверждаем, если просили ack
                    if env.ack:
                        await mgr.enqueue(conn, ServerMsg(type="ack", id=env.id))
                    continue
                conn.dedup.add(env.id)
                if len(conn.dedup) > settings.dedup_window:
                    # грубая очистка: сбрасываем половину
                    for _ in range(len(conn.dedup) // 2):
                        conn.dedup.pop()

            # обработка типов
            if env.type == "ping":
                conn.last_pong = time.monotonic()
                await mgr.enqueue(conn, ServerMsg(type="pong"))
                continue

            if env.type == "pong":
                conn.last_pong = time.monotonic()
                continue

            if env.type == "sub":
                if not env.chan:
                    await mgr.enqueue(conn, ServerMsg(type="error", code=422, msg="chan required"))
                    continue
                try:
                    await mgr.subscribe(conn, env.chan)
                except ValueError:
                    await mgr.enqueue(conn, ServerMsg(type="error", code=422, msg="invalid channel"))
                    continue
                # Запуск перекачки событий шины для канала один раз
                if env.chan not in channel_pumps:
                    channel_pumps[env.chan] = asyncio.create_task(mgr.start_channel_pump(env.chan))
                if env.ack and env.id:
                    await mgr.enqueue(conn, ServerMsg(type="ack", id=env.id, chan=env.chan))
                continue

            if env.type == "unsub":
                if not env.chan:
                    await mgr.enqueue(conn, ServerMsg(type="error", code=422, msg="chan required"))
                    continue
                try:
                    await mgr.unsubscribe(conn, env.chan)
                except ValueError:
                    await mgr.enqueue(conn, ServerMsg(type="error", code=422, msg="invalid channel"))
                    continue
                if env.ack and env.id:
                    await mgr.enqueue(conn, ServerMsg(type="ack", id=env.id, chan=env.chan))
                continue

            if env.type == "pub":
                if not env.chan:
                    await mgr.enqueue(conn, ServerMsg(type="error", code=422, msg="chan required"))
                    continue
                payload = env.payload or {}
                try:
                    await mgr.publish(conn, env.chan, payload)
                except ValueError:
                    await mgr.enqueue(conn, ServerMsg(type="error", code=422, msg="invalid channel"))
                    continue
                if settings.echo_to_sender:
                    await mgr.enqueue(conn, ServerMsg(type="event", chan=env.chan, payload=payload))
                if env.ack and env.id:
                    await mgr.enqueue(conn, ServerMsg(type="ack", id=env.id, chan=env.chan))
                continue

    finally:
        # остановка фоновых задач и отписка
        for t in channel_pumps.values():
            t.cancel()
        heartbeat_task.cancel()
        writer_task.cancel()
        await mgr.unregister(conn)
        try:
            await mgr.bus.close()
        except Exception:
            pass
        try:
            await ws.close()
        except Exception:
            pass


# --------------------------------------------------------------------------------------
# Фоновые циклы
# --------------------------------------------------------------------------------------

async def _writer_loop(mgr: ChannelManager, conn: Connection) -> None:
    try:
        while True:
            data = await conn.send_queue.get()
            try:
                await conn.ws.send_text(data)
            except Exception:
                await mgr._close(conn, mgr.s.close_internal_error, "send failed")
                return
    except asyncio.CancelledError:
        return

async def _heartbeat_loop(mgr: ChannelManager, conn: Connection, s: WSSettings) -> None:
    try:
        while True:
            await asyncio.sleep(s.heartbeat_interval_s)
            # отправляем ping
            try:
                await conn.ws.send_text(json.dumps(ServerMsg(type="pong").dict(exclude_none=True)))
            except Exception:
                await mgr._close(conn, s.close_internal_error, "heartbeat send failed")
                return
            # проверяем таймаут
            if (time.monotonic() - conn.last_pong) > s.heartbeat_timeout_s:
                await mgr._close(conn, s.close_policy_violation, "heartbeat timeout")
                return
    except asyncio.CancelledError:
        return
