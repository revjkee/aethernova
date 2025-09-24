from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import time
import typing as t
from contextlib import suppress
from dataclasses import dataclass, field

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError

# Опционально: JWT и Prometheus
_JWT_ENABLED = os.getenv("WS_AUTH_JWT", "true").lower() == "true"
_APIKEY_ENABLED = os.getenv("WS_AUTH_APIKEY", "true").lower() == "true"
_METRICS_ENABLED = os.getenv("WS_METRICS", "true").lower() == "true"

# JWT настройки
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "")
JWT_ISSUER = os.getenv("JWT_ISSUER", "")
JWT_ALGS = tuple(a.strip() for a in os.getenv("JWT_ALGS", "RS256,ES256").split(",") if a.strip())
JWT_LEEWAY_SEC = int(os.getenv("JWT_LEEWAY_SEC", "30"))
JWT_PUBKEY = os.getenv("JWT_STATIC_PUBKEY", "")  # PEM, если нет JWKS
JWT_JWKS_URL = os.getenv("JWT_JWKS_URL", "")

# API-Key
API_KEYS = [k for k in os.getenv("WS_API_KEYS", "").split(",") if k.strip()]
API_KEY_HEADER = os.getenv("WS_API_KEY_HEADER", "x-api-key").lower()
API_KEY_QUERY = os.getenv("WS_API_KEY_QUERY", "api_key")

# Лимиты и таймауты
MAX_MESSAGE_BYTES = int(os.getenv("WS_MAX_MESSAGE_BYTES", str(256 * 1024)))  # 256 KiB
SEND_QUEUE_MAX = int(os.getenv("WS_SEND_QUEUE_MAX", "256"))
RECV_RATE_LIMIT_RPS = float(os.getenv("WS_RECV_RPS", "20"))  # token-bucket rps
RECV_RATE_LIMIT_BURST = int(os.getenv("WS_RECV_BURST", "40"))
HEARTBEAT_INTERVAL_SEC = float(os.getenv("WS_HEARTBEAT_SEC", "20"))
HEARTBEAT_TIMEOUT_SEC = float(os.getenv("WS_HEARTBEAT_TIMEOUT_SEC", "10"))
READ_TIMEOUT_SEC = float(os.getenv("WS_READ_TIMEOUT_SEC", "30"))
WRITE_TIMEOUT_SEC = float(os.getenv("WS_WRITE_TIMEOUT_SEC", "10"))

# Разрешённые субпротоколы (необязательно)
ALLOWED_SUBPROTOCOLS = [p for p in os.getenv("WS_SUBPROTOCOLS", "").split(",") if p.strip()]

# Идентификаторы сервиса
SERVICE_NAME = os.getenv("SERVICE_NAME", "engine-core")
SERVICE_ENV = os.getenv("SERVICE_ENV", "dev")

# Логгер
logger = logging.getLogger("ws.server")
if not logger.handlers:
    handler = logging.StreamHandler()
    fmt = logging.Formatter("%(asctime)s %(levelname)s ws %(message)s")
    handler.setFormatter(fmt)
    logger.addHandler(handler)
logger.setLevel(os.getenv("WS_LOG_LEVEL", "INFO"))

# Метрики (Prometheus)
_prom = None
if _METRICS_ENABLED:
    try:
        from prometheus_client import Counter, Gauge, Histogram

        class _Prom:
            def __init__(self):
                self.active = Gauge("ws_active_connections", "Active WebSocket connections", ["service", "env"])
                self.recv = Counter("ws_messages_received_total", "Incoming WS messages", ["service", "env", "type"])
                self.sent = Counter("ws_messages_sent_total", "Outgoing WS messages", ["service", "env", "type"])
                self.dropped = Counter("ws_messages_dropped_total", "Dropped messages (backpressure/limit)", ["service", "env", "reason"])
                self.ping_latency = Histogram(
                    "ws_ping_latency_seconds", "Heartbeat ping latency", ["service", "env"],
                    buckets=[0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0]
                )
        _prom = _Prom()
    except Exception:
        _prom = None


# ==========================
# Модель протокола сообщений
# ==========================

class Msg(BaseModel):
    type: str = Field(..., description="Тип сообщения")
    payload: dict = Field(default_factory=dict)

class MsgError(BaseModel):
    type: str = "error"
    payload: dict = Field(default_factory=dict)

class MsgOk(BaseModel):
    type: str = "ok"
    payload: dict = Field(default_factory=dict)

class MsgPong(BaseModel):
    type: str = "pong"
    payload: dict = Field(default_factory=dict)

class MsgPing(BaseModel):
    type: str = "ping"
    payload: dict = Field(default_factory=dict)

# ===============
# Аутентификация
# ===============

async def _validate_jwt(token: str) -> dict | None:
    if not _JWT_ENABLED or not token:
        return None
    try:
        from jwt import decode as jwt_decode, PyJWTError, algorithms  # PyJWT
        key = None
        if JWT_JWKS_URL:
            # Лёгкая JWKS-загрузка без зависимостей — опционально через aiohttp
            try:
                import aiohttp
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=2.0)) as s:
                    async with s.get(JWT_JWKS_URL) as r:
                        if r.status == 200:
                            jwks = await r.json()
                            # Пробуем первый подходящий ключ (упрощённо)
                            for jwk in jwks.get("keys", []):
                                kty = jwk.get("kty")
                                if kty == "RSA":
                                    key = algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
                                    break
                                if kty == "EC":
                                    key = algorithms.ECAlgorithm.from_jwk(json.dumps(jwk))
                                    break
            except Exception:
                key = None
        if not key and JWT_PUBKEY:
            key = JWT_PUBKEY

        options = {
            "verify_aud": bool(JWT_AUDIENCE),
            "verify_signature": True,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iat": True,
            "require": ["exp", "iat"],
        }
        claims = jwt_decode(
            token,
            key=key,
            algorithms=list(JWT_ALGS) if JWT_ALGS else None,
            audience=JWT_AUDIENCE or None,
            issuer=JWT_ISSUER or None,
            leeway=JWT_LEEWAY_SEC,
            options=options,
        )
        return claims or {}
    except Exception:
        return None

def _const_time_eq(a: str, b: str) -> bool:
    return secrets.compare_digest(a.encode(), b.encode())

async def _validate_apikey(ws: WebSocket) -> bool:
    if not _APIKEY_ENABLED:
        return False
    # priority: header, then query
    header_val = next((v for (k, v) in ws.headers.items() if k.lower() == API_KEY_HEADER), None)
    query_val = ws.query_params.get(API_KEY_QUERY)
    key = header_val or query_val
    if not key:
        return False
    for stored in API_KEYS:
        if _const_time_eq(stored.strip(), key.strip()):
            return True
    return False

async def _authenticate(ws: WebSocket) -> tuple[bool, dict]:
    # Allowed auth: JWT Bearer, API key, либо обе
    claims: dict = {}
    authz = ws.headers.get("authorization") or ws.headers.get("Authorization")
    token = ""
    if authz and authz.lower().startswith("bearer "):
        token = authz[7:].strip()
        claims = await _validate_jwt(token) or {}
    apikey_ok = await _validate_apikey(ws)
    ok = bool(claims) or apikey_ok or (not _JWT_ENABLED and not _APIKEY_ENABLED)
    return ok, claims


# ==========================
# Ограничение скорости входа
# ==========================

@dataclass
class TokenBucket:
    rate: float           # tokens per second
    burst: int            # max bucket capacity
    tokens: float = 0.0
    updated: float = field(default_factory=lambda: time.monotonic())

    def allow(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        delta = now - self.updated
        self.updated = now
        self.tokens = min(self.burst, self.tokens + delta * self.rate)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


# ==========================
# Менеджер подключений/каналов
# ==========================

@dataclass
class ClientSession:
    id: str
    ws: WebSocket
    claims: dict
    send_q: asyncio.Queue[dict] = field(default_factory=lambda: asyncio.Queue(maxsize=SEND_QUEUE_MAX))
    recv_limiter: TokenBucket = field(default_factory=lambda: TokenBucket(RECV_RATE_LIMIT_RPS, RECV_RATE_LIMIT_BURST))
    last_pong: float = field(default_factory=lambda: time.monotonic())
    channels: set[str] = field(default_factory=set)

class ChannelManager:
    def __init__(self):
        self._clients: dict[str, ClientSession] = {}
        self._channels: dict[str, set[str]] = {}
        self._lock = asyncio.Lock()

    async def add(self, cs: ClientSession):
        async with self._lock:
            self._clients[cs.id] = cs
            if _prom:
                with suppress(Exception):
                    _prom.active.labels(SERVICE_NAME, SERVICE_ENV).inc()

    async def remove(self, client_id: str):
        async with self._lock:
            cs = self._clients.pop(client_id, None)
            if cs:
                for ch in list(cs.channels):
                    members = self._channels.get(ch)
                    if members and client_id in members:
                        members.discard(client_id)
                        if not members:
                            self._channels.pop(ch, None)
            if _prom:
                with suppress(Exception):
                    _prom.active.labels(SERVICE_NAME, SERVICE_ENV).dec()

    async def subscribe(self, client_id: str, channel: str):
        async with self._lock:
            self._channels.setdefault(channel, set()).add(client_id)
            cs = self._clients.get(client_id)
            if cs:
                cs.channels.add(channel)

    async def unsubscribe(self, client_id: str, channel: str):
        async with self._lock:
            members = self._channels.get(channel)
            if members and client_id in members:
                members.remove(client_id)
                if not members:
                    self._channels.pop(channel, None)
            cs = self._clients.get(client_id)
            if cs and channel in cs.channels:
                cs.channels.remove(channel)

    async def publish(self, channel: str, message: dict):
        # Широковещательно во все сессии канала
        async with self._lock:
            members = list(self._channels.get(channel, []))
        for cid in members:
            cs = await self.get(cid)
            if cs:
                await self.enqueue(cs, message)

    async def get(self, client_id: str) -> ClientSession | None:
        async with self._lock:
            return self._clients.get(client_id)

    async def enqueue(self, cs: ClientSession, message: dict) -> bool:
        try:
            cs.send_q.put_nowait(message)
            return True
        except asyncio.QueueFull:
            if _prom:
                with suppress(Exception):
                    _prom.dropped.labels(SERVICE_NAME, SERVICE_ENV, "backpressure").inc()
            return False

manager = ChannelManager()

router = APIRouter(prefix="/ws", tags=["websocket"])


# ==========================
# Помощники отправки/приёма
# ==========================

async def _safe_send_json(cs: ClientSession, msg: dict):
    # Серилизация заранее для контроля размера
    raw = json.dumps(msg, separators=(",", ":"), ensure_ascii=False)
    if len(raw.encode("utf-8")) > MAX_MESSAGE_BYTES:
        # Слишком большой ответ — отбрасываем
        if _prom:
            with suppress(Exception):
                _prom.dropped.labels(SERVICE_NAME, SERVICE_ENV, "oversize_out").inc()
        return
    # Отправка с таймаутом
    try:
        await asyncio.wait_for(cs.ws.send_text(raw), timeout=WRITE_TIMEOUT_SEC)
        if _prom:
            with suppress(Exception):
                _prom.sent.labels(SERVICE_NAME, SERVICE_ENV, msg.get("type", "unknown")).inc()
    except Exception:
        # Соединение могло закрыться — игнорируем, пусть цикл writer завершит
        pass


async def _recv_text(ws: WebSocket) -> str | None:
    try:
        raw = await asyncio.wait_for(ws.receive_text(), timeout=READ_TIMEOUT_SEC)
        if len(raw.encode("utf-8")) > MAX_MESSAGE_BYTES:
            return None
        return raw
    except asyncio.TimeoutError:
        return None
    except WebSocketDisconnect:
        raise
    except Exception:
        return None


# ==========================
# Основной обработчик WS
# ==========================

@router.websocket("")
async def websocket_endpoint(ws: WebSocket):
    # Переговор субпротокола (при необходимости)
    if ALLOWED_SUBPROTOCOLS:
        requested = [p.strip() for p in (ws.headers.get("sec-websocket-protocol") or "").split(",") if p.strip()]
        if requested:
            # Выбираем первый совпадающий
            chosen = next((p for p in requested if p in ALLOWED_SUBPROTOCOLS), None)
            await ws.accept(subprotocol=chosen)
        else:
            await ws.accept()
    else:
        await ws.accept()

    ok, claims = await _authenticate(ws)
    if not ok:
        await ws.send_text(MsgError(payload={"code": "unauthenticated"}).model_dump_json(by_alias=True))
        await ws.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    client_id = secrets.token_hex(8)
    cs = ClientSession(id=client_id, ws=ws, claims=claims)
    await manager.add(cs)

    logger.info("Client connected id=%s sub=%s", client_id, claims.get("sub") if claims else "anon")

    # Три задачи: reader, writer, heartbeat
    reader_t = asyncio.create_task(_reader_loop(cs))
    writer_t = asyncio.create_task(_writer_loop(cs))
    hb_t = asyncio.create_task(_heartbeat_loop(cs))

    try:
        await asyncio.wait(
            [reader_t, writer_t, hb_t],
            return_when=asyncio.FIRST_EXCEPTION,
        )
    finally:
        for tsk in (reader_t, writer_t, hb_t):
            with suppress(Exception):
                tsk.cancel()
        with suppress(Exception):
            await ws.close()
        await manager.remove(client_id)
        logger.info("Client disconnected id=%s", client_id)


# ==========================
# Циклы reader / writer / heartbeat
# ==========================

async def _reader_loop(cs: ClientSession):
    while True:
        raw = await _recv_text(cs.ws)
        if raw is None:
            # таймаут/oversize — закрываем
            await _safe_send_json(cs, MsgError(payload={"code": "bad_request", "reason": "timeout_or_oversize"}).model_dump())
            # мягко закрыть за неактивность
            await cs.ws.close(code=status.WS_1000_NORMAL_CLOSURE)
            return
        # rate-limit
        if not cs.recv_limiter.allow(1.0):
            if _prom:
                with suppress(Exception):
                    _prom.dropped.labels(SERVICE_NAME, SERVICE_ENV, "rate_limit").inc()
            await _safe_send_json(cs, MsgError(payload={"code": "rate_limited"}).model_dump())
            # продолжим принимать, не закрывая сразу
            continue

        try:
            data = json.loads(raw)
            msg = Msg.model_validate(data)
        except (json.JSONDecodeError, ValidationError):
            await _safe_send_json(cs, MsgError(payload={"code": "bad_format"}).model_dump())
            continue

        if _prom:
            with suppress(Exception):
                _prom.recv.labels(SERVICE_NAME, SERVICE_ENV, msg.type).inc()

        # Диспетчеризация типов сообщений
        ttype = msg.type
        if ttype == "ping":
            cs.last_pong = time.monotonic()  # доверяем клиентскому пингу как активности
            await manager.enqueue(cs, MsgPong(payload={"ts": time.time()}).model_dump())
        elif ttype == "echo":
            await manager.enqueue(cs, MsgOk(payload={"echo": msg.payload}).model_dump())
        elif ttype == "subscribe":
            ch = str(msg.payload.get("channel", "")).strip()
            if not ch:
                await manager.enqueue(cs, MsgError(payload={"code": "invalid_channel"}).model_dump())
            else:
                await manager.subscribe(cs.id, ch)
                await manager.enqueue(cs, MsgOk(payload={"subscribed": ch}).model_dump())
        elif ttype == "unsubscribe":
            ch = str(msg.payload.get("channel", "")).strip()
            if not ch:
                await manager.enqueue(cs, MsgError(payload={"code": "invalid_channel"}).model_dump())
            else:
                await manager.unsubscribe(cs.id, ch)
                await manager.enqueue(cs, MsgOk(payload={"unsubscribed": ch}).model_dump())
        elif ttype == "publish":
            ch = str(msg.payload.get("channel", "")).strip()
            body = msg.payload.get("message")
            if not ch or body is None:
                await manager.enqueue(cs, MsgError(payload={"code": "invalid_publish"}).model_dump())
            else:
                # Пример: простая публикация (реальную авторизацию по каналам добавляйте по claims/ролям)
                await manager.publish(ch, {"type": "message", "payload": {"channel": ch, "message": body}})
                await manager.enqueue(cs, MsgOk(payload={"published": ch}).model_dump())
        elif ttype == "auth":
            # Уже аутентифицированы при connect — сообщаем статус
            sub = cs.claims.get("sub") if cs.claims else None
            await manager.enqueue(cs, MsgOk(payload={"authenticated": bool(cs.claims), "sub": sub}).model_dump())
        else:
            await manager.enqueue(cs, MsgError(payload={"code": "unsupported_type", "type": ttype}).model_dump())


async def _writer_loop(cs: ClientSession):
    while True:
        msg = await cs.send_q.get()
        await _safe_send_json(cs, msg)


async def _heartbeat_loop(cs: ClientSession):
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL_SEC)
        # серверный пинг (пользуемся приложенческим JSON ping, не WS ping, для совместимости)
        sent_ts = time.monotonic()
        await manager.enqueue(cs, MsgPing(payload={"ts": time.time()}).model_dump())
        # ждём ответа по активности
        await asyncio.sleep(HEARTBEAT_TIMEOUT_SEC)
        alive = (time.monotonic() - cs.last_pong) < (HEARTBEAT_INTERVAL_SEC + HEARTBEAT_TIMEOUT_SEC)
        if not alive:
            # не получили активность — закрываем
            await _safe_send_json(cs, MsgError(payload={"code": "heartbeat_timeout"}).model_dump())
            await cs.ws.close(code=status.WS_1001_GOING_AWAY)
            return
        else:
            if _prom:
                with suppress(Exception):
                    _prom.ping_latency.labels(SERVICE_NAME, SERVICE_ENV).observe(max(0.0, time.monotonic() - sent_ts))


# ==========================
# Вспомогательные HTTP‑маршруты (health/info) — опционально
# ==========================

@router.get("/info")
async def ws_info():
    return JSONResponse(
        {
            "service": SERVICE_NAME,
            "env": SERVICE_ENV,
            "auth": {
                "jwt": _JWT_ENABLED,
                "apikey": _APIKEY_ENABLED,
            },
            "limits": {
                "max_message_bytes": MAX_MESSAGE_BYTES,
                "send_queue_max": SEND_QUEUE_MAX,
                "recv_rps": RECV_RATE_LIMIT_RPS,
                "recv_burst": RECV_RATE_LIMIT_BURST,
            },
            "timers": {
                "heartbeat_interval_sec": HEARTBEAT_INTERVAL_SEC,
                "heartbeat_timeout_sec": HEARTBEAT_TIMEOUT_SEC,
                "read_timeout_sec": READ_TIMEOUT_SEC,
                "write_timeout_sec": WRITE_TIMEOUT_SEC,
            },
        }
    )
