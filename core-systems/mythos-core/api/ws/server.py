# mythos-core/api/ws/server.py
# -*- coding: utf-8 -*-
"""
Промышленный WebSocket-сервер для Mythos Core.

Особенности:
- FastAPI/Starlette WebSocket endpoint: /v1/ws
- Аутентификация: Bearer (JWT) или API-ключ (в query/subprotocol).
- Token Bucket rate limit на входящие сообщения.
- Очередь исходящих сообщений с backpressure и ограничением размера.
- Heartbeat (ping/pong) с таймаутом разрыва.
- Подтверждения доставок (ack) с ретраями (at-least-once для событий).
- Топики/подписки, Hub с безопасной широковещательной рассылкой.
- Чистое DI: app.state.ws_hub доступен любому коду ядра (publish/broadcast).
- Структурные JSON-кадры: {type,id,ts,topic,payload,...}.

Зависимости:
  - fastapi>=0.110
  - pydantic>=2
  - (опционально) pyjwt для verify_jwt() — заглушка ниже.

Лицензия: Apache-2.0
Автор: Aethernova
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Mapping, Optional, Set, Tuple

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect, WebSocketException, status
from pydantic import BaseModel, Field, ConfigDict

logger = logging.getLogger("mythos.ws")

router = APIRouter(tags=["websocket"], default_response_class=None)


# ==========================
# Конфигурация
# ==========================

@dataclass(frozen=True)
class WSConfig:
    max_message_size_bytes: int = 256 * 1024        # входящий текст
    max_send_queue: int = 1000                      # исходящая очередь
    max_subscriptions: int = 512
    heartbeat_interval_sec: float = 20.0
    heartbeat_timeout_sec: float = 45.0
    rate_limit_rps: float = 50.0
    rate_limit_burst: int = 100
    ack_timeout_sec: float = 5.0
    ack_max_retries: int = 3
    accept_subprotocols: Tuple[str, ...] = ("json",)
    allow_origins: Tuple[str, ...] = ()             # если нужно — проверяйте Origin вручную


DEFAULT_WS_CONFIG = WSConfig()


# ==========================
# Модели кадров
# ==========================

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class InFrameBase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = Field(min_length=1)
    id: Optional[str] = None


class InAuthFrame(InFrameBase):
    type: str = Field("auth", const=True)
    token: Optional[str] = None
    api_key: Optional[str] = Field(default=None, alias="apiKey")


class InSubscribeFrame(InFrameBase):
    type: str = Field("subscribe", const=True)
    topics: List[str] = Field(min_items=1)


class InUnsubscribeFrame(InFrameBase):
    type: str = Field("unsubscribe", const=True)
    topics: List[str] = Field(min_items=1)


class InPingFrame(InFrameBase):
    type: str = Field("ping", const=True)
    ts: Optional[str] = None


class InAckFrame(InFrameBase):
    type: str = Field("ack", const=True)
    ack_id: str = Field(min_length=1, alias="ackId")


class OutFrame(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str
    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    ts: str = Field(default_factory=now_iso)


class OutWelcomeFrame(OutFrame):
    type: str = Field("welcome", const=True)
    conn_id: str = Field(alias="connId")
    user_id: Optional[str] = Field(default=None, alias="userId")


class OutSubscribedFrame(OutFrame):
    type: str = Field("subscribed", const=True)
    topics: List[str]


class OutUnsubscribedFrame(OutFrame):
    type: str = Field("unsubscribed", const=True)
    topics: List[str]


class OutPongFrame(OutFrame):
    type: str = Field("pong", const=True)


class OutErrorFrame(OutFrame):
    type: str = Field("error", const=True)
    code: str
    message: str
    details: Optional[Dict[str, Any]] = None


class OutEventFrame(OutFrame):
    type: str = Field("event", const=True)
    topic: str
    payload: Dict[str, Any]


# ==========================
# Token Bucket (rate limit)
# ==========================

class _TokenBucket:
    def __init__(self, rate: float, burst: int):
        self.rate = max(0.0, rate)
        self.capacity = max(1, burst)
        self.tokens = float(self.capacity)
        self.ts = time.monotonic()

    def consume(self, n: int = 1) -> float:
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.ts) * self.rate)
        self.ts = now
        if self.tokens >= n:
            self.tokens -= n
            return 0.0
        need = n - self.tokens
        wait = need / self.rate if self.rate > 0 else float("inf")
        self.tokens = 0.0
        return wait


# ==========================
# Аутентификация (заглушки)
# ==========================

class AuthContext(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_id: Optional[str] = None
    scopes: List[str] = Field(default_factory=list)


def verify_jwt(token: str) -> AuthContext:
    """
    Заглушка проверки JWT.
    Интегрируйте ваш провайдер (PyJWT/JWKS). Бросайте ValueError при неуспехе.
    """
    if not token:
        raise ValueError("empty token")
    # Демонстрационно извлечём user_id из UUID в конце токена (пример!)
    uid = token[-36:] if len(token) >= 36 else None
    return AuthContext(user_id=uid or "user")


def verify_api_key(api_key: str) -> AuthContext:
    """
    Заглушка проверки API-ключа.
    """
    if not api_key:
        raise ValueError("empty api key")
    return AuthContext(user_id=f"key:{api_key[:6]}")


# ==========================
# Соединение и Hub
# ==========================

@dataclass
class _PendingAck:
    frame: OutEventFrame
    retries: int = 0
    last_sent: float = field(default_factory=time.monotonic)


class Connection:
    def __init__(self, ws: WebSocket, cfg: WSConfig, auth: AuthContext):
        self.ws = ws
        self.cfg = cfg
        self.auth = auth
        self.conn_id = uuid.uuid4().hex
        self.subscriptions: Set[str] = set()
        self.send_q: asyncio.Queue[OutFrame] = asyncio.Queue(maxsize=cfg.max_send_queue)
        self.pending: Dict[str, _PendingAck] = {}
        self.alive = True
        self._last_pong = time.monotonic()
        self._in_bucket = _TokenBucket(cfg.rate_limit_rps, cfg.rate_limit_burst)

    # Управление подписками
    def add_topics(self, topics: List[str]) -> List[str]:
        added = []
        for t in topics:
            if len(self.subscriptions) >= self.cfg.max_subscriptions:
                break
            if t not in self.subscriptions:
                self.subscriptions.add(t)
                added.append(t)
        return added

    def remove_topics(self, topics: List[str]) -> List[str]:
        removed = []
        for t in topics:
            if t in self.subscriptions:
                self.subscriptions.remove(t)
                removed.append(t)
        return removed

    def is_subscribed(self, topic: str) -> bool:
        # Простейшее сопоставление: полное или wildcard "prefix.*"
        if topic in self.subscriptions:
            return True
        for pat in self.subscriptions:
            if pat.endswith("*"):
                pref = pat[:-1]
                if topic.startswith(pref):
                    return True
        return False

    # Очередь исходящих
    async def enqueue(self, frame: OutFrame) -> None:
        try:
            self.send_q.put_nowait(frame)
        except asyncio.QueueFull:
            logger.warning("Send queue overflow; closing connection conn_id=%s", self.conn_id)
            await self.close(code=status.WS_1011_INTERNAL_ERROR)

    async def close(self, code: int = status.WS_1000_NORMAL_CLOSURE) -> None:
        if not self.alive:
            return
        self.alive = False
        try:
            await self.ws.close(code=code)
        except Exception:
            pass


class Hub:
    """
    Реестр подключений и маршрутизация событий.
    """
    def __init__(self, cfg: WSConfig = DEFAULT_WS_CONFIG):
        self.cfg = cfg
        self._conns: Dict[str, Connection] = {}
        self._by_topic: Dict[str, Set[str]] = {}
        self._lock = asyncio.Lock()

    async def register(self, conn: Connection) -> None:
        async with self._lock:
            self._conns[conn.conn_id] = conn

    async def unregister(self, conn: Connection) -> None:
        async with self._lock:
            self._conns.pop(conn.conn_id, None)
            # Очистить индексы подписок
            for topic, members in list(self._by_topic.items()):
                if conn.conn_id in members:
                    members.remove(conn.conn_id)
                if not members:
                    self._by_topic.pop(topic, None)

    async def subscribe(self, conn: Connection, topics: List[str]) -> List[str]:
        added = conn.add_topics(topics)
        async with self._lock:
            for t in added:
                self._by_topic.setdefault(t, set()).add(conn.conn_id)
        return added

    async def unsubscribe(self, conn: Connection, topics: List[str]) -> List[str]:
        removed = conn.remove_topics(topics)
        async with self._lock:
            for t in removed:
                members = self._by_topic.get(t)
                if members and conn.conn_id in members:
                    members.remove(conn.conn_id)
                    if not members:
                        self._by_topic.pop(t, None)
        return removed

    async def publish(self, topic: str, payload: Dict[str, Any]) -> int:
        """
        Публикация события в топик (из любого места приложения).
        Возвращает количество адресатов.
        """
        frame = OutEventFrame(topic=topic, payload=payload)
        targets: List[Connection] = []
        async with self._lock:
            # Быстрый путь: точное совпадение
            ids = set(self._by_topic.get(topic, set()))
            # Медленный путь: wildcard подписчики
            for conn in self._conns.values():
                if conn.conn_id not in ids and conn.is_subscribed(topic):
                    ids.add(conn.conn_id)
            for cid in ids:
                c = self._conns.get(cid)
                if c and c.alive:
                    targets.append(c)

        for c in targets:
            # С ack-трекингом
            c.pending[frame.id] = _PendingAck(frame=frame)
            await c.enqueue(frame)
        return len(targets)

    # Служебная информация (по необходимости)
    async def stats(self) -> Dict[str, Any]:
        async with self._lock:
            return {
                "connections": len(self._conns),
                "topics": len(self._by_topic),
            }


def get_hub(app) -> Hub:
    hub = getattr(app.state, "ws_hub", None)
    if hub is None:
        hub = Hub()
        app.state.ws_hub = hub
    return hub


# ==========================
# Обработчик соединения
# ==========================

async def _send_loop(conn: Connection) -> None:
    """
    Выгружает кадры из очереди и отправляет клиенту.
    Управляет ретраями для событий, требующих ack.
    """
    cfg = conn.cfg
    ws = conn.ws
    try:
        while conn.alive:
            try:
                frame: OutFrame = await asyncio.wait_for(conn.send_q.get(), timeout=cfg.heartbeat_interval_sec)
            except asyncio.TimeoutError:
                # Heartbeat
                await ws.send_text(OutPongFrame().model_dump_json())
                continue

            # Отправка
            await ws.send_text(frame.model_dump_json())

            # Учтём отправку события для ack-логики
            if isinstance(frame, OutEventFrame):
                pend = conn.pending.get(frame.id)
                if pend:
                    pend.last_sent = time.monotonic()

            # Проверим просроченные ack и ретраи
            now = time.monotonic()
            expired = []
            for mid, pend in list(conn.pending.items()):
                if now - pend.last_sent >= cfg.ack_timeout_sec:
                    if pend.retries < cfg.ack_max_retries:
                        pend.retries += 1
                        pend.last_sent = now
                        await conn.enqueue(pend.frame)
                    else:
                        # Откажемся от дальнейших попыток, но не рвём соединение
                        expired.append(mid)
                        logger.warning("Ack not received, giving up. conn_id=%s msg_id=%s", conn.conn_id, mid)
            for mid in expired:
                conn.pending.pop(mid, None)

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.exception("send loop error: %s", e)
    finally:
        await conn.close()


async def _recv_loop(conn: Connection, hub: Hub) -> None:
    """
    Принимает входящие кадры, применяет rate limit и обрабатывает команды.
    """
    ws = conn.ws
    cfg = conn.cfg
    try:
        while conn.alive:
            text = await ws.receive_text()
            if len(text.encode("utf-8")) > cfg.max_message_size_bytes:
                await ws.send_text(OutErrorFrame(code="MSG_TOO_LARGE", message="message too large").model_dump_json())
                await conn.close(code=status.WS_1009_MESSAGE_TOO_BIG)
                break

            # Rate limit
            wait = conn._in_bucket.consume()
            if wait > 0:
                await asyncio.sleep(wait)

            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                await ws.send_text(OutErrorFrame(code="BAD_JSON", message="invalid JSON").model_dump_json())
                continue

            ftype = data.get("type")
            if ftype == "ping":
                _ = InPingFrame(**data)  # валидация
                await ws.send_text(OutPongFrame().model_dump_json())
                conn._last_pong = time.monotonic()
            elif ftype == "subscribe":
                frm = InSubscribeFrame(**data)
                added = await hub.subscribe(conn, frm.topics)
                await ws.send_text(OutSubscribedFrame(topics=added).model_dump_json())
            elif ftype == "unsubscribe":
                frm = InUnsubscribeFrame(**data)
                removed = await hub.unsubscribe(conn, frm.topics)
                await ws.send_text(OutUnsubscribedFrame(topics=removed).model_dump_json())
            elif ftype == "ack":
                frm = InAckFrame(**data)
                conn.pending.pop(frm.ack_id, None)
            else:
                await ws.send_text(OutErrorFrame(code="UNSUPPORTED", message=f"unsupported type: {ftype}").model_dump_json())

            # Таймаут heartbeat
            if time.monotonic() - conn._last_pong > cfg.heartbeat_timeout_sec:
                await conn.close(code=status.WS_1001_GOING_AWAY)
                break

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.exception("recv loop error: %s", e)
    finally:
        await conn.close()


# ==========================
# Handshake/Auth endpoint
# ==========================

@router.websocket("/v1/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: Optional[str] = Query(default=None, description="Bearer JWT"),
    api_key: Optional[str] = Query(default=None, description="API Key"),
):
    """
    Протокол рукопожатия:
      1) Клиент подключается к /v1/ws[?token=..|api_key=..] с subprotocol=json (по желанию).
      2) Сервер подтверждает, отправляет кадр welcome.
      3) Клиент отправляет кадр {"type":"subscribe","topics":[...]}.
      4) Сервер возвращает {"type":"subscribed",...}. События приходят кадрами {"type":"event",...}.
      5) Клиент отвечает {"type":"ack","ackId":"..."} на каждый event (at-least-once с ретраями).
      6) Heartbeat: {"type":"ping"} <-> {"type":"pong"}.
    """
    # Проверка subprotocol
    subp = None
    for sp in websocket.headers.getlist("sec-websocket-protocol"):
        # Клиент может перечислить несколько через запятую
        for candidate in [s.strip() for s in sp.split(",")]:
            if candidate in DEFAULT_WS_CONFIG.accept_subprotocols:
                subp = candidate
                break
    await websocket.accept(subprotocol=subp)

    # Аутентификация (query) — также разрешите кадр "auth" сразу после welcome
    try:
        auth = await _authenticate_initial(websocket, token=token, api_key=api_key)
    except WebSocketException as we:
        await websocket.close(code=we.code)
        return

    conn = Connection(websocket, DEFAULT_WS_CONFIG, auth)
    hub = get_hub(websocket.app)
    await hub.register(conn)

    # Приветствие
    await conn.enqueue(OutWelcomeFrame(connId=conn.conn_id, userId=auth.user_id))

    # Параллельные циклы
    send_task = asyncio.create_task(_send_loop(conn), name=f"ws-send-{conn.conn_id}")
    recv_task = asyncio.create_task(_recv_loop(conn, hub), name=f"ws-recv-{conn.conn_id}")

    done, pending = await asyncio.wait({send_task, recv_task}, return_when=asyncio.FIRST_COMPLETED)
    for t in pending:
        t.cancel()
    await hub.unregister(conn)


async def _authenticate_initial(websocket: WebSocket, *, token: Optional[str], api_key: Optional[str]) -> AuthContext:
    """
    Блокирующая первичная аутентификация:
    - Сначала пробуем query token/api_key;
    - Если нет — ждём кадр {"type":"auth"}.
    """
    # Попытка 1: query
    try:
        if token:
            return verify_jwt(token)
        if api_key:
            return verify_api_key(api_key)
    except ValueError:
        # Падать не будем — шанс аутентифицироваться кадром auth
        pass

    # Попытка 2: кадр auth с таймаутом
    try:
        text = await asyncio.wait_for(websocket.receive_text(), timeout=10.0)
        data = json.loads(text)
        frm = InAuthFrame(**data)
        if frm.token:
            return verify_jwt(frm.token)
        if frm.api_key:
            return verify_api_key(frm.api_key)
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)
    except (asyncio.TimeoutError, json.JSONDecodeError):
        await websocket.send_text(OutErrorFrame(code="AUTH_REQUIRED", message="auth required").model_dump_json())
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)
    except ValueError:
        await websocket.send_text(OutErrorFrame(code="AUTH_INVALID", message="invalid credentials").model_dump_json())
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)


# ==========================
# Вспомогательные API для публикации из ядра
# ==========================

async def ws_publish(app, topic: str, payload: Dict[str, Any]) -> int:
    """
    Публикация события в топик из любого места приложения:
        await ws_publish(app, "entity.updated", {"id": "...", "version": 2})
    Возвращает число адресатов.
    """
    hub = get_hub(app)
    return await hub.publish(topic, payload)


# ==========================
# Жизненный цикл приложения (опциональные хуки)
# ==========================

async def on_startup(app):
    get_hub(app)  # инициализация
    logger.info("WS Hub initialized")

async def on_shutdown(app):
    hub: Hub = get_hub(app)
    logger.info("WS Hub shutdown stats: %s", await hub.stats())
