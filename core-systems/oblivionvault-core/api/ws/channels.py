# -*- coding: utf-8 -*-
"""
OblivionVault Core — WebSocket Channels (industrial-grade)

Особенности:
- Протокол сообщений: типизированные модели (Pydantic), версия протокола, ACK/seq
- Брокеры: Redis Pub/Sub (redis.asyncio) и Local In-Memory
- Подписки по шаблонам (wildcard: 'erasure.*', 'audit.#' — см. simple matcher)
- Backpressure: per-connection asyncio.Queue с защитой от переполнения
- Rate limit: token bucket per-connection и базовая валидация нагрузок
- Heartbeat/idle timeout: ping/pong на уровне приложения
- Безопасные ошибки: тип "error" с полями в стиле RFC 7807
- Интеграция: FastAPI/Starlette endpoint + регистрация роутов через register_ws_routes
- Логгинг/трейсинг: безопасный лог с редакцией секретов, OTel-хуки (опционально)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import traceback
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import (
    Any,
    AsyncGenerator,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

try:
    # FastAPI/Starlette (опционально, но для продакшена рекомендуется)
    from fastapi import APIRouter, WebSocket, WebSocketDisconnect
    from fastapi import status as http_status
    _HAS_FASTAPI = True
except Exception:  # pragma: no cover
    # Позволяет импортировать модуль без FastAPI (например, для тестов broker/manager)
    APIRouter = object  # type: ignore
    WebSocket = object  # type: ignore
    WebSocketDisconnect = Exception  # type: ignore
    http_status = type("status", (), {"WS_1008_POLICY_VIOLATION": 1008})  # type: ignore
    _HAS_FASTAPI = False

try:
    # Pydantic v1/v2 совместимость
    from pydantic import BaseModel, Field, validator
except Exception as e:  # pragma: no cover
    raise RuntimeError("pydantic is required for api.ws.channels") from e

# Redis (опционально)
try:
    import redis.asyncio as aioredis  # redis-py >= 4.2
    _HAS_REDIS = True
except Exception:  # pragma: no cover
    aioredis = None  # type: ignore
    _HAS_REDIS = False


# ------------------------------------------------------------------------------
# Константы и логгинг
# ------------------------------------------------------------------------------

LOG = logging.getLogger("oblivionvault.ws.channels")

PROTOCOL = "ov.ws.v1"
ENV = os.getenv("OBLIVIONVAULT_ENV", "dev").lower()  # dev|staging|prod
IS_PROD = ENV == "prod"

# Ограничения и тайминги
PING_INTERVAL = float(os.getenv("OV_WS_PING_INTERVAL_SEC", "20"))
IDLE_TIMEOUT = float(os.getenv("OV_WS_IDLE_TIMEOUT_SEC", "60"))
SEND_QUEUE_MAX = int(os.getenv("OV_WS_SEND_QUEUE_MAX", "1000"))
SEND_QUEUE_BLOCK_TIMEOUT = float(os.getenv("OV_WS_SEND_QUEUE_BLOCK_TIMEOUT", "2.0"))
RATE_TOKENS = int(os.getenv("OV_WS_RATE_TOKENS", "200"))
RATE_REFILL_PER_SEC = float(os.getenv("OV_WS_RATE_REFILL_PER_SEC", "50"))
MAX_MESSAGE_BYTES = int(os.getenv("OV_WS_MAX_MESSAGE_BYTES", "262144"))  # 256 KiB

# Безопасная редакция ключей
SENSITIVE_KEYS = ("secret", "password", "token", "key", "authorization", "cookie")


# ------------------------------------------------------------------------------
# Вспомогательные структуры
# ------------------------------------------------------------------------------

def now_rfc3339() -> str:
    return datetime.now(timezone.utc).isoformat()


def redact_map(d: Mapping[str, Any]) -> Dict[str, Any]:
    redacted: Dict[str, Any] = {}
    for k, v in d.items():
        if any(s in k.lower() for s in SENSITIVE_KEYS):
            redacted[k] = "***"
        else:
            redacted[k] = v
    return redacted


class TokenBucket:
    """Простой token bucket для rate-limit сообщений клиента."""
    __slots__ = ("capacity", "tokens", "rate", "last")

    def __init__(self, capacity: int, rate: float) -> None:
        self.capacity = capacity
        self.tokens = float(capacity)
        self.rate = float(rate)
        self.last = time.monotonic()

    def allow(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = max(0.0, now - self.last)
        self.last = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


# ------------------------------------------------------------------------------
# Протокол сообщений (Pydantic)
# ------------------------------------------------------------------------------

class BaseMsg(BaseModel):
    """Базовая модель всех сообщений."""
    type: str = Field(..., description="Тип сообщения")
    ts: str = Field(default_factory=now_rfc3339, description="Временная метка")
    ver: str = Field(default=PROTOCOL, description="Версия протокола")

    class Config:
        anystr_strip_whitespace = True


class ClientHello(BaseMsg):
    type: str = "hello"
    # Поля аутентификации в хэндшейке (альтернатива query/header)
    token: Optional[str] = None
    subscriptions: Optional[List[str]] = None
    resume_from: Optional[int] = Field(
        default=None, description="Последний подтвержденный seq для резюмирования"
    )


class Subscribe(BaseMsg):
    type: str = "subscribe"
    topics: List[str]


class Unsubscribe(BaseMsg):
    type: str = "unsubscribe"
    topics: List[str]


class Ack(BaseMsg):
    type: str = "ack"
    seq: int


class ClientPublish(BaseMsg):
    type: str = "publish"
    topic: str
    payload: Dict[str, Any]


class ServerWelcome(BaseMsg):
    type: str = "welcome"
    connection_id: str
    session_id: str
    heartbeat: float = Field(default=PING_INTERVAL)
    idle_timeout: float = Field(default=IDLE_TIMEOUT)
    allowed_publish: bool = False


class ServerEvent(BaseMsg):
    type: str = "event"
    topic: str
    seq: int
    payload: Dict[str, Any]


class ServerPong(BaseMsg):
    type: str = "pong"


class ServerError(BaseMsg):
    type: str = "error"
    status: int
    code: str
    title: str
    detail: str
    correlationId: str
    docs: Optional[str] = None
    extra: Optional[Dict[str, Any]] = None


ClientInbound = Union[ClientHello, Subscribe, Unsubscribe, Ack, ClientPublish]
ServerOutbound = Union[ServerWelcome, ServerEvent, ServerPong, ServerError]


# ------------------------------------------------------------------------------
# Авторизация
# ------------------------------------------------------------------------------

@dataclass(frozen=True)
class AuthResult:
    user_id: str
    tenant_id: Optional[str]
    roles: Tuple[str, ...]
    can_publish: bool = False


AuthProvider = Callable[[Optional[str], Mapping[str, str]], Awaitable[AuthResult]]


async def default_auth_provider(token: Optional[str], headers: Mapping[str, str]) -> AuthResult:
    """
    Дефолт для dev/staging: разрешает анонимов. В prod замените на JWT/OIDC.
    """
    if IS_PROD:
        # В проде без явного провайдера — запрет
        raise PermissionError("Authentication required")
    uid = token or headers.get("x-user-id") or "anon"
    return AuthResult(user_id=str(uid), tenant_id=headers.get("x-tenant-id"), roles=("anonymous",), can_publish=False)


# ------------------------------------------------------------------------------
# Брокер сообщений (абстракция + реализации)
# ------------------------------------------------------------------------------

class Broker:
    """
    Абстрактный брокер. Минимальные операции:
    - publish(topic, payload)
    - subscribe(pattern) -> async generator of (topic, payload)
    - close()
    """
    async def publish(self, topic: str, payload: Dict[str, Any]) -> None:
        raise NotImplementedError

    async def subscribe(self, pattern: str) -> AsyncGenerator[Tuple[str, Dict[str, Any]], None]:
        raise NotImplementedError

    async def close(self) -> None:
        return None


class LocalBroker(Broker):
    """
    Простой in-memory брокер: для локальной разработки/тестов.
    Поддержка wildcard осуществляется на стороне подписчиков.
    """
    def __init__(self) -> None:
        self._subs: List[Tuple[str, asyncio.Queue]] = []
        self._lock = asyncio.Lock()

    async def publish(self, topic: str, payload: Dict[str, Any]) -> None:
        async with self._lock:
            for pattern, q in self._subs:
                if match_topic(pattern, topic):
                    # fire-and-forget (не блокируем)
                    try:
                        q.put_nowait((topic, payload))
                    except asyncio.QueueFull:
                        # Локально пропускаем, в проде брокер должен справляться сам
                        pass

    async def subscribe(self, pattern: str) -> AsyncGenerator[Tuple[str, Dict[str, Any]], None]:
        q: asyncio.Queue = asyncio.Queue(maxsize=SEND_QUEUE_MAX)
        async with self._lock:
            self._subs.append((pattern, q))
        try:
            while True:
                yield await q.get()
        finally:
            async with self._lock:
                self._subs = [(p, qq) for (p, qq) in self._subs if qq is not q]

    async def close(self) -> None:
        async with self._lock:
            self._subs.clear()


class RedisBroker(Broker):
    """
    Redis Pub/Sub брокер. Требуется redis-py (redis.asyncio).
    Подписка через паттерны (PSUBSCRIBE).
    """
    def __init__(self, url: str) -> None:
        if not _HAS_REDIS:
            raise RuntimeError("redis.asyncio is not available")
        self._redis = aioredis.from_url(url, decode_responses=True)

    async def publish(self, topic: str, payload: Dict[str, Any]) -> None:
        msg = json.dumps({"topic": topic, "payload": payload}, ensure_ascii=False)
        await self._redis.publish(topic, msg)

    async def subscribe(self, pattern: str) -> AsyncGenerator[Tuple[str, Dict[str, Any]], None]:
        pubsub = self._redis.pubsub()
        await pubsub.psubscribe(pattern)
        try:
            async for raw in pubsub.listen():
                if raw is None:
                    continue
                if raw.get("type") not in ("pmessage", "message"):
                    continue
                topic = raw.get("channel") or raw.get("pattern") or ""
                data = raw.get("data")
                if isinstance(data, str):
                    try:
                        obj = json.loads(data)
                        yield (obj.get("topic") or topic, obj.get("payload") or {})
                    except Exception:
                        # Если публикуют plain-текст — завернём в payload
                        yield (topic, {"raw": data})
                else:
                    yield (topic, {"raw": data})
        finally:
            with contextlib.suppress(Exception):
                await pubsub.close()

    async def close(self) -> None:
        await self._redis.close()


# ------------------------------------------------------------------------------
# Топики и фильтрация
# ------------------------------------------------------------------------------

WILDCARD_STAR = re.compile(r"[.*]")
WILDCARD_HASH = re.compile(r"[.#]")

def _pattern_to_regex(pattern: str) -> re.Pattern:
    """
    Простой glob-подобный matcher:
      '*' — один сегмент; '#' — произвольное количество сегментов
    Сегменты разделены точкой: 'erasure.*', 'audit.#', 'a.b.c'
    """
    parts = pattern.split(".")
    regex = "^"
    for i, part in enumerate(parts):
        if part == "*":
            regex += r"[^.]+"
        elif part == "#":
            regex += r".+"
        else:
            regex += re.escape(part)
        if i < len(parts) - 1:
            regex += r"\."
    regex += r"$"
    return re.compile(regex)


def match_topic(pattern: str, topic: str) -> bool:
    try:
        return _pattern_to_regex(pattern).match(topic) is not None
    except Exception:
        return False


# ------------------------------------------------------------------------------
# Соединение и менеджер каналов
# ------------------------------------------------------------------------------

@dataclass
class ConnectionCtx:
    connection_id: str
    session_id: str
    auth: AuthResult
    subscriptions: List[str]
    send_seq: int = 0
    last_ack: int = 0
    last_activity: float = 0.0


class ChannelManager:
    """
    Управляет жизненным циклом WS-соединения: handshake, recv/send, подписки, ACK, heartbeat.
    """
    def __init__(self, broker: Broker, auth_provider: AuthProvider) -> None:
        self._broker = broker
        self._auth_provider = auth_provider

    # ---- Основной обработчик ----
    async def handle(self, ws: WebSocket) -> None:  # type: ignore[override]
        await ws.accept(subprotocol=PROTOCOL)
        headers = {k.lower(): v for k, v in ws.headers.items()}  # type: ignore[attr-defined]
        token = self._extract_token(ws)

        # Аутентификация
        try:
            auth = await self._auth_provider(token, headers)
        except Exception as e:
            await self._send_error_and_close(ws, status=4401, code="OV-S401", title="Unauthorized",
                                             detail="Authentication is required", exc=e)
            return

        ctx = ConnectionCtx(
            connection_id=str(uuid.uuid4()),
            session_id=str(uuid.uuid4()),
            auth=auth,
            subscriptions=[],
            last_activity=time.monotonic(),
        )

        send_q: asyncio.Queue[ServerOutbound] = asyncio.Queue(maxsize=SEND_QUEUE_MAX)
        recv_rate = TokenBucket(capacity=RATE_TOKENS, rate=RATE_REFILL_PER_SEC)

        # Приветствие
        await self._enqueue(send_q, ServerWelcome(connection_id=ctx.connection_id,
                                                  session_id=ctx.session_id,
                                                  allowed_publish=auth.can_publish))

        # Запускаем корутины
        tasks = [
            asyncio.create_task(self._recv_loop(ws, ctx, send_q, recv_rate), name="ws-recv"),
            asyncio.create_task(self._send_loop(ws, ctx, send_q), name="ws-send"),
            asyncio.create_task(self._heartbeat(ws, ctx, send_q), name="ws-heartbeat"),
        ]

        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in tasks:
                t.cancel()
            with contextlib.suppress(Exception):
                await ws.close()

    # ---- Вспомогательные циклы ----
    async def _recv_loop(
        self,
        ws: WebSocket,
        ctx: ConnectionCtx,
        send_q: asyncio.Queue[ServerOutbound],
        recv_rate: TokenBucket,
    ) -> None:
        subs_tasks: Dict[str, asyncio.Task] = {}

        while True:
            try:
                raw = await ws.receive_text()
            except WebSocketDisconnect:
                return
            except Exception as e:
                LOG.warning("receive_text error: %s", e)
                return

            if not recv_rate.allow():
                await self._send_error(ws, status=4429, code="OV-E429", title="Too Many Requests",
                                       detail="Client message rate exceeded")
                continue

            if not self._validate_size(raw):
                await self._send_error(ws, status=4413, code="OV-E413", title="Payload Too Large",
                                       detail="Maximum message size exceeded")
                continue

            ctx.last_activity = time.monotonic()
            try:
                data = json.loads(raw)
            except Exception:
                await self._send_error(ws, status=4400, code="OV-E400", title="Bad Request",
                                       detail="Invalid JSON")
                continue

            try:
                msg = self._parse_inbound(data)
            except Exception as e:
                await self._send_error(ws, status=4400, code="OV-E400", title="Bad Request",
                                       detail=f"Invalid message: {e}")
                continue

            # Обработка типов
            if isinstance(msg, ClientHello):
                if msg.subscriptions:
                    # Инициируем подписки
                    for p in msg.subscriptions:
                        if p not in ctx.subscriptions:
                            ctx.subscriptions.append(p)
                            subs_tasks[p] = asyncio.create_task(self._broker_fanout(ws, ctx, p, send_q))
                continue

            if isinstance(msg, Subscribe):
                for p in msg.topics:
                    if p not in ctx.subscriptions:
                        ctx.subscriptions.append(p)
                        subs_tasks[p] = asyncio.create_task(self._broker_fanout(ws, ctx, p, send_q))
                continue

            if isinstance(msg, Unsubscribe):
                for p in msg.topics:
                    if p in ctx.subscriptions:
                        ctx.subscriptions.remove(p)
                        task = subs_tasks.pop(p, None)
                        if task:
                            task.cancel()
                continue

            if isinstance(msg, Ack):
                ctx.last_ack = max(ctx.last_ack, msg.seq)
                continue

            if isinstance(msg, ClientPublish):
                if not ctx.auth.can_publish:
                    await self._send_error(ws, status=4403, code="OV-S403", title="Forbidden",
                                           detail="Publishing is not allowed for this principal")
                    continue
                await self._safe_publish(msg.topic, msg.payload)
                continue

            # Неизвестный тип
            await self._send_error(ws, status=4400, code="OV-E400", title="Bad Request",
                                   detail=f"Unsupported message type '{data.get('type')}'")

    async def _send_loop(self, ws: WebSocket, ctx: ConnectionCtx, q: asyncio.Queue[ServerOutbound]) -> None:
        while True:
            msg = await q.get()
            if isinstance(msg, ServerEvent):
                # присваиваем seq
                ctx.send_seq += 1
                msg.seq = ctx.send_seq  # type: ignore[assignment]

            try:
                await ws.send_text(msg.json(ensure_ascii=False))
            except WebSocketDisconnect:
                return
            except Exception as e:
                LOG.error("send_text error: %s", e)
                return

    async def _heartbeat(self, ws: WebSocket, ctx: ConnectionCtx, q: asyncio.Queue[ServerOutbound]) -> None:
        while True:
            await asyncio.sleep(PING_INTERVAL)
            # Idle disconnect
            idle = time.monotonic() - ctx.last_activity
            if idle > IDLE_TIMEOUT:
                await self._send_error(ws, status=4408, code="OV-E408", title="Request Timeout",
                                       detail="Idle timeout exceeded")
                with contextlib.suppress(Exception):
                    await ws.close(code=http_status.WS_1008_POLICY_VIOLATION)  # type: ignore[attr-defined]
                return
            # Пинг
            await self._enqueue(q, ServerPong())

    async def _broker_fanout(self, ws: WebSocket, ctx: ConnectionCtx, pattern: str,
                             q: asyncio.Queue[ServerOutbound]) -> None:
        try:
            async for topic, payload in self._broker.subscribe(pattern):
                event = ServerEvent(topic=topic, payload=self._safe_payload(payload), seq=0)
                try:
                    await asyncio.wait_for(q.put(event), timeout=SEND_QUEUE_BLOCK_TIMEOUT)
                except asyncio.TimeoutError:
                    # Очередь переполнена — закрываем соединение (backpressure защита)
                    await self._send_error(ws, status=1013, code="OV-E503A", title="Service Unavailable",
                                           detail="Send queue overflow (backpressure); reconnect later")
                    with contextlib.suppress(Exception):
                        await ws.close()
                    return
        except asyncio.CancelledError:
            return
        except Exception as e:
            LOG.error("broker_fanout error: %s", e)
            await self._send_error(ws, status=1011, code="OV-E500", title="Internal Server Error",
                                   detail="Broker fanout failure")

    # ---- Утилиты ----
    def _parse_inbound(self, data: Dict[str, Any]) -> ClientInbound:
        t = str(data.get("type", ""))
        mapping: Dict[str, Any] = {
            "hello": ClientHello,
            "subscribe": Subscribe,
            "unsubscribe": Unsubscribe,
            "ack": Ack,
            "publish": ClientPublish,
        }
        model = mapping.get(t)
        if not model:
            raise ValueError(f"unknown type '{t}'")
        return model.parse_obj(data)

    async def _enqueue(self, q: asyncio.Queue[ServerOutbound], msg: ServerOutbound) -> None:
        try:
            await asyncio.wait_for(q.put(msg), timeout=SEND_QUEUE_BLOCK_TIMEOUT)
        except asyncio.TimeoutError:
            # В редких случаях drop ping/pong
            if isinstance(msg, ServerPong):
                return
            raise

    async def _send_error_and_close(
        self, ws: WebSocket, *, status: int, code: str, title: str, detail: str, exc: Optional[Exception] = None
    ) -> None:
        await self._send_error(ws, status=status, code=code, title=title, detail=detail, exc=exc)
        with contextlib.suppress(Exception):
            await ws.close()

    async def _send_error(
        self, ws: WebSocket, *, status: int, code: str, title: str, detail: str, exc: Optional[Exception] = None
    ) -> None:
        extra: Dict[str, Any] = {}
        if exc and not IS_PROD:
            extra["stack"] = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))[-8000:]
        problem = ServerError(
            status=status,
            code=code,
            title=title,
            detail="An error occurred." if IS_PROD and any(s in detail.lower() for s in SENSITIVE_KEYS) else detail,
            correlationId=str(uuid.uuid4()),
            docs=f"https://docs.oblivionvault.io/errors/{code}",
            extra=redact_map(extra) if extra else None,
        )
        try:
            await ws.send_text(problem.json(ensure_ascii=False))
        except Exception:
            pass

    def _validate_size(self, raw: str) -> bool:
        try:
            return len(raw.encode("utf-8")) <= MAX_MESSAGE_BYTES
        except Exception:
            return False

    def _extract_token(self, ws: WebSocket) -> Optional[str]:
        # Priority: query param 'token', then 'Authorization: Bearer'
        token = None
        try:
            token = ws.query_params.get("token")  # type: ignore[attr-defined]
        except Exception:
            pass
        if not token:
            auth = ws.headers.get("authorization") if hasattr(ws, "headers") else None  # type: ignore[attr-defined]
            if auth and auth.lower().startswith("bearer "):
                token = auth.split(" ", 1)[1]
        return token

    async def _safe_publish(self, topic: str, payload: Dict[str, Any]) -> None:
        await self._broker.publish(topic, self._safe_payload(payload))

    def _safe_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            return redact_map(payload)
        except Exception:
            return {"raw": str(payload)}


# ------------------------------------------------------------------------------
# FastAPI интеграция
# ------------------------------------------------------------------------------

import contextlib

def register_ws_routes(
    app: Any,
    broker: Optional[Broker] = None,
    auth_provider: Optional[AuthProvider] = None,
    *,
    path: str = "/ws",
) -> APIRouter:
    """
    Регистрирует WebSocket endpoint на FastAPI/Starlette приложении.
    Пример:
        app = FastAPI()
        broker = RedisBroker("redis://localhost:6379/0")
        register_ws_routes(app, broker)
    """
    if not _HAS_FASTAPI:
        raise RuntimeError("FastAPI/Starlette is required to register ws routes")

    router = APIRouter()
    manager = ChannelManager(broker or LocalBroker(), auth_provider or default_auth_provider)

    @router.websocket(path)
    async def ws_entry(ws: WebSocket):
        try:
            await manager.handle(ws)
        except Exception as e:
            LOG.error("ws_entry fatal: %s", e, exc_info=not IS_PROD)
            with contextlib.suppress(Exception):
                await ws.close()

    app.include_router(router)
    return router


# ------------------------------------------------------------------------------
# Пример публикации серверных событий
# ------------------------------------------------------------------------------

async def emit_event(broker: Broker, topic: str, payload: Mapping[str, Any]) -> None:
    """
    Публикация серверного события в канал.
    """
    await broker.publish(topic, dict(payload))


# ------------------------------------------------------------------------------
# Самопроверка (dev)
# ------------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    # Простой smoke test LocalBroker matching
    assert match_topic("a.*.c", "a.b.c")
    assert match_topic("a.#", "a.b.c.d")
    assert match_topic("erasure.*", "erasure.started")
    assert not match_topic("erasure.*", "erasure.started.more")
    print("channels.py self-check OK")
