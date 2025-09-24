# security-core/api/ws/channels.py
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Awaitable, Callable, Dict, Optional, Set, Tuple, Protocol, List

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from fastapi import Depends, HTTPException
from starlette.websockets import WebSocketState

# Опционально: PyJWT и cryptography для верификации JWT по JWKS
try:  # pragma: no cover
    import jwt  # PyJWT
    _HAS_PYJWT = True
except Exception:  # pragma: no cover
    _HAS_PYJWT = False

# Опционально: Redis брокер
try:  # pragma: no cover
    import redis.asyncio as aioredis
    _HAS_REDIS = True
except Exception:  # pragma: no cover
    _HAS_REDIS = False

# ------------------------------
# Константы и настройки
# ------------------------------

WS_SUBPROTOCOL = os.getenv("SEC_CORE_WS_SUBPROTO", "sec.core.v1")
MAX_MESSAGE_BYTES = int(os.getenv("SEC_CORE_WS_MAX_MESSAGE_BYTES", "131072"))  # 128 KiB
MAX_QUEUE = int(os.getenv("SEC_CORE_WS_MAX_QUEUE", "512"))
HEARTBEAT_INTERVAL = float(os.getenv("SEC_CORE_WS_HEARTBEAT_SEC", "20"))
HEARTBEAT_GRACE = int(os.getenv("SEC_CORE_WS_HEARTBEAT_GRACE", "2"))  # допускаем N пропусков
RATE_TOKENS = int(os.getenv("SEC_CORE_WS_RATE_TOKENS", "50"))  # burst
RATE_REFILL_PER_SEC = float(os.getenv("SEC_CORE_WS_RATE_REFILL", "25"))  # tokens/sec
ALLOW_SUBSCRIBE_SELF_PUBLISH = os.getenv("SEC_CORE_WS_ALLOW_SELF_PUBLISH", "true").lower() in ("1","true","yes","on")

CHANNEL_NAME_RE = re.compile(r"^[a-zA-Z0-9:\-_/\.]{1,128}$")

# ------------------------------
# Логирование
# ------------------------------

def _get_logger() -> logging.Logger:
    logger = logging.getLogger("security_core.ws")
    if not logger.handlers:
        h = logging.StreamHandler()
        fmt = logging.Formatter('%(message)s')
        h.setFormatter(fmt)
        logger.addHandler(h)
        logger.setLevel(os.getenv("SEC_CORE_WS_LOG_LEVEL", "INFO").upper())
    return logger

log = _get_logger()

def _jlog(level: int, msg: str, **extra: Any) -> None:
    payload = {"ts": datetime.now(timezone.utc).isoformat(), "level": logging.getLevelName(level), "message": msg}
    payload.update(extra)
    log.log(level, json.dumps(payload, ensure_ascii=False, separators=(",", ":")))

# ------------------------------
# Типы аутентификации
# ------------------------------

@dataclass(frozen=True)
class AuthContext:
    tenant: str
    actor: str
    subject: str
    scopes: Set[str] = field(default_factory=set)

class AuthBackend(Protocol):
    async def authenticate(self, ws: WebSocket) -> AuthContext: ...

class HeaderAuth(AuthBackend):
    """
    Простой backend для внутренних сервисов.
    Требует: x-tenant-id, x-actor-id (или x-user-id). Для продакшена используйте JWTAuth.
    """
    async def authenticate(self, ws: WebSocket) -> AuthContext:
        tenant = ws.headers.get("x-tenant-id") or ws.headers.get("x-org-id") or "default"
        actor = ws.headers.get("x-actor-id") or ws.headers.get("x-user-id") or "anonymous"
        subject = ws.headers.get("x-subject") or actor
        if not tenant:
            raise HTTPException(status_code=status.WS_1008_POLICY_VIOLATION, detail="Missing tenant header")
        return AuthContext(tenant=tenant, actor=actor, subject=subject, scopes=set())

class JWTAuth(AuthBackend):
    """
    Производственный backend: верифицирует JWT с использованием локального JWKS файла.
    Переменные окружения:
      SEC_CORE_WS_JWT_AUDIENCE       (необязательно)
      SEC_CORE_WS_JWT_ISSUER         (необязательно)
      SEC_CORE_WS_JWKS_PATH          (путь к файлу JWKS JSON)
      SEC_CORE_WS_JWT_HEADER         (по умолчанию 'authorization')
    """
    def __init__(self) -> None:
        if not _HAS_PYJWT:
            raise RuntimeError("PyJWT is required for JWTAuth")
        self.aud = os.getenv("SEC_CORE_WS_JWT_AUDIENCE")
        self.iss = os.getenv("SEC_CORE_WS_JWT_ISSUER")
        self.jwks_path = os.getenv("SEC_CORE_WS_JWKS_PATH")
        self.header = os.getenv("SEC_CORE_WS_JWT_HEADER", "authorization").lower()
        if not self.jwks_path or not os.path.exists(self.jwks_path):
            raise RuntimeError("SEC_CORE_WS_JWKS_PATH is not set or file not found")
        with open(self.jwks_path, "rb") as f:
            data = json.load(f)
        self.jwks = {k["kid"]: k for k in data.get("keys", []) if "kid" in k}

    def _key_for_kid(self, kid: str) -> Any:
        jwk = self.jwks.get(kid)
        if not jwk:
            raise HTTPException(status_code=status.WS_1008_POLICY_VIOLATION, detail="Unknown KID")
        return jwt.algorithms.get_default_algorithms()[jwk.get("alg","RS256")].from_jwk(json.dumps(jwk))

    async def authenticate(self, ws: WebSocket) -> AuthContext:
        auth = ws.headers.get(self.header)
        if not auth or not auth.lower().startswith("bearer "):
            raise HTTPException(status_code=status.WS_1008_POLICY_VIOLATION, detail="Missing bearer token")
        token = auth.split(" ", 1)[1].strip()
        headers = jwt.get_unverified_header(token)
        kid = headers.get("kid")
        if not kid:
            raise HTTPException(status_code=status.WS_1008_POLICY_VIOLATION, detail="Token without kid")
        key = self._key_for_kid(kid)
        options = {"verify_aud": bool(self.aud), "verify_signature": True}
        decoded = jwt.decode(
            token,
            key=key,
            algorithms=[headers.get("alg","RS256")],
            audience=self.aud,
            issuer=self.iss,
            options=options,
        )
        tenant = str(decoded.get("tenant") or decoded.get("org") or decoded.get("tid") or "default")
        subject = str(decoded.get("sub") or "unknown")
        actor = str(decoded.get("preferred_username") or decoded.get("name") or subject)
        scopes = set()
        for field in ("scope","scopes"):
            val = decoded.get(field)
            if isinstance(val, str):
                scopes.update(val.split())
            elif isinstance(val, list):
                scopes.update([str(x) for x in val])
        return AuthContext(tenant=tenant, actor=actor, subject=subject, scopes=scopes)

# ------------------------------
# ACL и валидатор каналов
# ------------------------------

AclFn = Callable[[AuthContext, str, str], bool]
# action: "subscribe" | "publish"

def default_acl(ctx: AuthContext, channel: str, action: str) -> bool:
    # правило: канал должен начинаться с "{tenant}/"
    if not channel.startswith(f"{ctx.tenant}/"):
        return False
    # базовый запрет на служебные каналы
    if channel.startswith(f"{ctx.tenant}/admin/") and "ws:admin" not in ctx.scopes:
        return False
    return True

def validate_channel_name(name: str) -> None:
    if not CHANNEL_NAME_RE.match(name):
        raise ValueError("Invalid channel name")

# ------------------------------
# Сообщения
# ------------------------------

@dataclass
class Envelope:
    type: str
    channel: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None
    nonce: Optional[str] = None

    @staticmethod
    def parse(raw: str) -> "Envelope":
        if len(raw.encode("utf-8")) > MAX_MESSAGE_BYTES:
            raise ValueError("Message too large")
        try:
            data = json.loads(raw)
        except Exception:
            raise ValueError("Invalid JSON")
        if not isinstance(data, dict):
            raise ValueError("Envelope must be an object")
        t = str(data.get("type") or "")
        ch = data.get("channel")
        pl = data.get("payload")
        nc = data.get("nonce")
        if t not in {"subscribe","unsubscribe","publish","ping","pong"}:
            raise ValueError("Unsupported type")
        if t in {"subscribe","unsubscribe","publish"}:
            if not isinstance(ch, str):
                raise ValueError("Channel required")
            validate_channel_name(ch)
        if pl is not None and not isinstance(pl, dict):
            raise ValueError("Payload must be an object")
        if nc is not None and not isinstance(nc, (str, int)):
            raise ValueError("Nonce must be string or int")
        return Envelope(type=t, channel=ch, payload=pl, nonce=str(nc) if nc is not None else None)

# ------------------------------
# Rate limiter: token bucket
# ------------------------------

class TokenBucket:
    def __init__(self, capacity: int, refill_rate: float) -> None:
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate
        self.updated = time.monotonic()

    def allow(self, cost: int = 1) -> bool:
        now = time.monotonic()
        delta = now - self.updated
        self.updated = now
        self.tokens = min(self.capacity, self.tokens + delta * self.refill_rate)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False

# ------------------------------
# Брокер
# ------------------------------

class Broker(Protocol):
    async def subscribe(self, channel: str, handler: Callable[[str, Dict[str, Any]], Awaitable[None]]) -> Any: ...
    async def unsubscribe(self, subscription_id: Any) -> None: ...
    async def publish(self, channel: str, message: Dict[str, Any]) -> None: ...

class InMemoryBroker(Broker):
    def __init__(self) -> None:
        self._subs: Dict[str, Set[Callable[[str, Dict[str, Any]], Awaitable[None]]]] = {}

    async def subscribe(self, channel: str, handler: Callable[[str, Dict[str, Any]], Awaitable[None]]) -> Any:
        self._subs.setdefault(channel, set()).add(handler)
        return (channel, handler)

    async def unsubscribe(self, subscription_id: Any) -> None:
        ch, h = subscription_id
        s = self._subs.get(ch)
        if s and h in s:
            s.remove(h)
            if not s:
                self._subs.pop(ch, None)

    async def publish(self, channel: str, message: Dict[str, Any]) -> None:
        for h in list(self._subs.get(channel, ())):
            try:
                await h(channel, message)
            except Exception as e:  # логируем, но продолжаем доставку
                _jlog(logging.WARNING, "handler error", error=str(e), channel=channel)

class RedisBroker(Broker):  # pragma: no cover
    def __init__(self, url: str) -> None:
        if not _HAS_REDIS:
            raise RuntimeError("redis.asyncio is required for RedisBroker")
        self._url = url
        self._redis = aioredis.from_url(url, decode_responses=False)
        self._tasks: Dict[str, asyncio.Task] = {}
        self._handlers: Dict[str, Set[Callable[[str, Dict[str, Any]], Awaitable[None]]]] = {}

    async def subscribe(self, channel: str, handler: Callable[[str, Dict[str, Any]], Awaitable[None]]) -> Any:
        self._handlers.setdefault(channel, set()).add(handler)
        if channel in self._tasks:
            return channel
        async def reader(ch: str) -> None:
            pubsub = self._redis.pubsub()
            await pubsub.subscribe(ch)
            async for msg in pubsub.listen():
                if msg.get("type") != "message":
                    continue
                try:
                    payload = json.loads(msg["data"].decode("utf-8"))
                except Exception:
                    continue
                for h in list(self._handlers.get(ch, ())):
                    try:
                        await h(ch, payload)
                    except Exception as e:
                        _jlog(logging.WARNING, "redis handler error", error=str(e), channel=ch)
        task = asyncio.create_task(reader(channel), name=f"redis-reader:{channel}")
        self._tasks[channel] = task
        return channel

    async def unsubscribe(self, subscription_id: Any) -> None:
        ch = subscription_id
        self._handlers.pop(ch, None)
        t = self._tasks.pop(ch, None)
        if t:
            t.cancel()

    async def publish(self, channel: str, message: Dict[str, Any]) -> None:
        await self._redis.publish(channel, json.dumps(message, separators=(",", ":")).encode("utf-8"))

# ------------------------------
# Соединение
# ------------------------------

@dataclass
class Connection:
    ws: WebSocket
    ctx: AuthContext
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    subs: Dict[str, Any] = field(default_factory=dict)  # channel -> subscription_id
    send_q: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(MAX_QUEUE))
    bucket: TokenBucket = field(default_factory=lambda: TokenBucket(RATE_TOKENS, RATE_REFILL_PER_SEC))
    last_pong: float = field(default_factory=lambda: time.monotonic())

# ------------------------------
# Channel Server
# ------------------------------

class ChannelServer:
    def __init__(
        self,
        broker: Optional[Broker] = None,
        auth_backend: Optional[AuthBackend] = None,
        acl: AclFn = default_acl,
    ) -> None:
        self.broker = broker or InMemoryBroker()
        self.auth_backend = auth_backend or HeaderAuth()
        self.acl = acl
        self.active: Dict[str, Connection] = {}
        self.max_connections = int(os.getenv("SEC_CORE_WS_MAX_CONNECTIONS", "10000"))

    # FastAPI router
    def router(self) -> APIRouter:
        r = APIRouter()
        r.websocket("/ws")(self._ws_handler)
        return r

    # ---------------
    # WS handler
    # ---------------

    async def _ws_handler(self, ws: WebSocket) -> None:
        # origin проверка опционально
        await self._accept(ws)

        # аутентификация
        try:
            ctx = await self.auth_backend.authenticate(ws)
        except HTTPException as e:
            await self._close(ws, e.status_code, e.detail or "auth failed")
            return
        except Exception as e:
            await self._close(ws, status.WS_1011_INTERNAL_ERROR, "auth error")
            return

        # ограничение по количеству соединений
        if len(self.active) >= self.max_connections:
            await self._close(ws, status.WS_1013_TRY_AGAIN_LATER, "too many connections")
            return

        conn = Connection(ws=ws, ctx=ctx)
        self.active[conn.id] = conn

        _jlog(logging.INFO, "ws.connected", conn_id=conn.id, tenant=ctx.tenant, actor=ctx.actor, subprotocol=ws.headers.get("sec-websocket-protocol"))

        # приветствие
        await self._send_json(conn, {
            "type": "hello",
            "nonce": str(uuid.uuid4()),
            "server_time": datetime.now(timezone.utc).isoformat(),
            "conn": {"id": conn.id, "tenant": ctx.tenant, "actor": ctx.actor},
            "subprotocol": WS_SUBPROTOCOL,
        })

        # запуск задач пульса и писателя
        tasks = [
            asyncio.create_task(self._heartbeat(conn), name=f"ws-heartbeat:{conn.id}"),
            asyncio.create_task(self._writer(conn), name=f"ws-writer:{conn.id}"),
        ]

        try:
            await self._reader(conn)
        except WebSocketDisconnect as e:
            pass
        except Exception as e:
            _jlog(logging.ERROR, "ws.reader.error", conn_id=conn.id, error=str(e))
        finally:
            for t in tasks:
                t.cancel()
            await self._unsubscribe_all(conn)
            self.active.pop(conn.id, None)
            try:
                if ws.client_state == WebSocketState.CONNECTED:
                    await ws.close()
            except Exception:
                pass
            _jlog(logging.INFO, "ws.disconnected", conn_id=conn.id, tenant=ctx.tenant)

    async def _accept(self, ws: WebSocket) -> None:
        try:
            await ws.accept(subprotocol=WS_SUBPROTOCOL)
        except Exception:
            # если accept упал, попытаться закрыть низкоуровнево
            try:
                await ws.close(code=status.WS_1011_INTERNAL_ERROR)
            except Exception:
                pass
            raise

    async def _close(self, ws: WebSocket, code: int, reason: str) -> None:
        try:
            await ws.close(code=code, reason=reason[:120])
        except Exception:
            pass

    # ---------------
    # tasks
    # ---------------

    async def _heartbeat(self, conn: Connection) -> None:
        misses = 0
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            try:
                await self._send_json(conn, {"type":"ping","ts": datetime.now(timezone.utc).isoformat()})
            except Exception:
                break
            # проверяем отставание pong
            if time.monotonic() - conn.last_pong > (HEARTBEAT_INTERVAL * (misses + 1)):
                misses += 1
            else:
                misses = 0
            if misses > HEARTBEAT_GRACE:
                _jlog(logging.WARNING, "ws.heartbeat.timeout", conn_id=conn.id)
                await self._safe_close_conn(conn, status.WS_1001_GOING_AWAY, "heartbeat timeout")
                break

    async def _writer(self, conn: Connection) -> None:
        while True:
            msg = await conn.send_q.get()
            if msg is None:
                break
            try:
                await conn.ws.send_text(msg)
            except Exception as e:
                _jlog(logging.WARNING, "ws.writer.send_failed", conn_id=conn.id, error=str(e))
                break

    async def _reader(self, conn: Connection) -> None:
        ws = conn.ws
        while True:
            raw = await ws.receive_text()
            if len(raw.encode("utf-8")) > MAX_MESSAGE_BYTES:
                await self._send_error(conn, "message_too_large", "Message too large")
                continue
            try:
                env = Envelope.parse(raw)
            except Exception as e:
                await self._send_error(conn, "bad_request", str(e))
                continue

            if env.type == "ping":
                conn.last_pong = time.monotonic()  # принимаем как pong
                await self._send_json(conn, {"type":"pong","nonce":env.nonce})
                continue
            if env.type == "pong":
                conn.last_pong = time.monotonic()
                continue

            if not conn.bucket.allow(1):
                await self._send_error(conn, "rate_limited", "Too many messages", nonce=env.nonce)
                continue

            if env.type == "subscribe":
                await self._handle_subscribe(conn, env)
            elif env.type == "unsubscribe":
                await self._handle_unsubscribe(conn, env)
            elif env.type == "publish":
                await self._handle_publish(conn, env)

    # ---------------
    # handlers
    # ---------------

    async def _handle_subscribe(self, conn: Connection, env: Envelope) -> None:
        ch = env.channel or ""
        if not self.acl(conn.ctx, ch, "subscribe"):
            await self._send_error(conn, "forbidden", "Subscribe forbidden for this channel", nonce=env.nonce)
            return

        async def deliver(channel: str, message: Dict[str, Any]) -> None:
            payload = {
                "type": "message",
                "channel": channel,
                "payload": message,
            }
            await self._send_json(conn, payload)

        # уже подписан
        if ch in conn.subs:
            await self._send_ack(conn, env.nonce, {"status":"already_subscribed","channel":ch})
            return

        try:
            sub_id = await self.broker.subscribe(ch, deliver)
            conn.subs[ch] = sub_id
            await self._send_ack(conn, env.nonce, {"status":"subscribed","channel":ch})
            _jlog(logging.INFO, "ws.subscribed", conn_id=conn.id, channel=ch, tenant=conn.ctx.tenant)
        except Exception as e:
            await self._send_error(conn, "subscribe_failed", str(e), nonce=env.nonce)

    async def _handle_unsubscribe(self, conn: Connection, env: Envelope) -> None:
        ch = env.channel or ""
        sub = conn.subs.get(ch)
        if not sub:
            await self._send_ack(conn, env.nonce, {"status":"not_subscribed","channel":ch})
            return
        try:
            await self.broker.unsubscribe(sub)
            conn.subs.pop(ch, None)
            await self._send_ack(conn, env.nonce, {"status":"unsubscribed","channel":ch})
            _jlog(logging.INFO, "ws.unsubscribed", conn_id=conn.id, channel=ch)
        except Exception as e:
            await self._send_error(conn, "unsubscribe_failed", str(e), nonce=env.nonce)

    async def _handle_publish(self, conn: Connection, env: Envelope) -> None:
        ch = env.channel or ""
        if not self.acl(conn.ctx, ch, "publish"):
            await self._send_error(conn, "forbidden", "Publish forbidden for this channel", nonce=env.nonce)
            return

        payload = env.payload or {}
        # метаданные доставки
        payload = {
            **payload,
            "_meta": {
                "tenant": conn.ctx.tenant,
                "actor": conn.ctx.actor,
                "ts": datetime.now(timezone.utc).isoformat(),
                "conn_id": conn.id,
            }
        }

        try:
            await self.broker.publish(ch, payload)
            # по умолчанию подтверждаем публикацию
            await self._send_ack(conn, env.nonce, {"status": "published", "channel": ch})
            # опционально отправляем себе же
            if ALLOW_SUBSCRIBE_SELF_PUBLISH and ch in conn.subs:
                await self._send_json(conn, {"type":"message","channel":ch,"payload":payload})
        except Exception as e:
            await self._send_error(conn, "publish_failed", str(e), nonce=env.nonce)

    # ---------------
    # helpers
    # ---------------

    async def _unsubscribe_all(self, conn: Connection) -> None:
        for ch, sub in list(conn.subs.items()):
            try:
                await self.broker.unsubscribe(sub)
            except Exception:
                pass
        conn.subs.clear()

    async def _send_json(self, conn: Connection, obj: Dict[str, Any]) -> None:
        if conn.send_q.qsize() >= MAX_QUEUE - 1:
            _jlog(logging.WARNING, "ws.backpressure.drop", conn_id=conn.id)
            await self._safe_close_conn(conn, status.WS_1011_INTERNAL_ERROR, "backpressure")
            return
        msg = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        await conn.send_q.put(msg)

    async def _send_ack(self, conn: Connection, nonce: Optional[str], extra: Dict[str, Any]) -> None:
        payload = {"type":"ack", **extra}
        if nonce is not None:
            payload["nonce"] = nonce
        await self._send_json(conn, payload)

    async def _send_error(self, conn: Connection, code: str, message: str, nonce: Optional[str] = None) -> None:
        payload = {"type":"error","code":code,"message":message}
        if nonce is not None:
            payload["nonce"] = nonce
        await self._send_json(conn, payload)

    async def _safe_close_conn(self, conn: Connection, code: int, reason: str) -> None:
        try:
            if conn.ws.client_state == WebSocketState.CONNECTED:
                await conn.ws.close(code=code, reason=reason[:120])
        except Exception:
            pass

# ------------------------------
# Фабрики зависимостей
# ------------------------------

def provide_broker() -> Broker:
    if os.getenv("SEC_CORE_WS_BROKER", "memory").lower() == "redis":
        url = os.getenv("SEC_CORE_WS_REDIS_URL", "redis://localhost:6379/0")
        return RedisBroker(url)  # pragma: no cover
    return InMemoryBroker()

def provide_auth() -> AuthBackend:
    if os.getenv("SEC_CORE_WS_AUTH", "header").lower() == "jwt":
        return JWTAuth()
    return HeaderAuth()

def provide_server(broker: Broker = Depends(provide_broker), auth: AuthBackend = Depends(provide_auth)) -> ChannelServer:
    return ChannelServer(broker=broker, auth_backend=auth, acl=default_acl)

# ------------------------------
# Router
# ------------------------------

router = APIRouter()
_server_singleton: Optional[ChannelServer] = None

def _server() -> ChannelServer:
    global _server_singleton
    if _server_singleton is None:
        _server_singleton = ChannelServer(broker=provide_broker(), auth_backend=provide_auth(), acl=default_acl)
    return _server_singleton

@router.websocket("/ws")
async def websocket_entry(ws: WebSocket) -> None:
    await _server()._ws_handler(ws)

__all__ = [
    "router",
    "ChannelServer",
    "Broker",
    "InMemoryBroker",
    "RedisBroker",
    "AuthBackend",
    "HeaderAuth",
    "JWTAuth",
    "AuthContext",
]
