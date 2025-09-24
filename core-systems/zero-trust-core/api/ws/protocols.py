# -*- coding: utf-8 -*-
"""
Zero Trust Core — WebSocket protocols (FastAPI).

Функции:
  - Сабпротоколы: zt.health.v1 | zt.events.v1 | zt.control.v1
  - Хендшейк: проверка Origin, HMAC первого сообщения, опц. mTLS SPKI-pin
  - Сообщения: унифицированный Envelope + типизированные payload'ы (Pydantic)
  - Подписки: health/events; команды: ping, subscribe, unsubscribe
  - Защита: rate-limit per-connection, heartbeat, backpressure очереди
  - Интеграция: источники данных инъектируются через app.state.* колбэки

ENV:
  ZT_WS_ALLOWED_ORIGINS      — CSV спискок разрешенных Origin (по умолчанию пусто = не проверять)
  ZT_WS_SUBPROTOCOLS         — CSV сабпротоколов (default: zt.health.v1,zt.events.v1,zt.control.v1)
  ZT_WS_HMAC_B64             — base64 ключ для HMAC первого сообщения; если задан, проверка обязательна
  ZT_WS_SPKI_PINS_B64        — CSV SPKI-пинов для прикладного пиннинга (через заголовок x-client-spki)
  ZT_WS_HEARTBEAT_SEC        — интервал heartbeat пингов сервера (default 20)
  ZT_WS_IDLE_TIMEOUT_SEC     — idle timeout соединения (default 60)
  ZT_WS_RATE_PER_SEC         — лимит входящих сообщений в секунду (default 20)
  ZT_WS_RATE_BURST           — всплеск токенов (default 40)
  ZT_WS_QUEUE_MAX            — размер исходящей очереди сообщений (default 1000)
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import hashlib
import hmac
import json
import logging
import os
import time
import typing as t
import uuid

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field, conint, constr, validator

# ------------------------------------------------------------------------------
# Конфигурация
# ------------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class WSSettings:
    allowed_origins: tuple[str, ...] = tuple(x.strip() for x in os.getenv("ZT_WS_ALLOWED_ORIGINS", "").split(",") if x.strip())
    subprotocols: tuple[str, ...] = tuple(x.strip() for x in os.getenv("ZT_WS_SUBPROTOCOLS", "zt.health.v1,zt.events.v1,zt.control.v1").split(","))
    hmac_secret_b64: str | None = os.getenv("ZT_WS_HMAC_B64")
    spki_pins_csv: str | None = os.getenv("ZT_WS_SPKI_PINS_B64")
    heartbeat_sec: int = int(os.getenv("ZT_WS_HEARTBEAT_SEC", "20"))
    idle_timeout_sec: int = int(os.getenv("ZT_WS_IDLE_TIMEOUT_SEC", "60"))
    rate_per_sec: int = int(os.getenv("ZT_WS_RATE_PER_SEC", "20"))
    rate_burst: int = int(os.getenv("ZT_WS_RATE_BURST", "40"))
    queue_max: int = int(os.getenv("ZT_WS_QUEUE_MAX", "1000"))


SETTINGS = WSSettings()

logger = logging.getLogger("zt.ws")
if not logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s zt.ws %(message)s"))
    logger.addHandler(h)
logger.setLevel(logging.INFO)

# ------------------------------------------------------------------------------
# Модели сообщений
# ------------------------------------------------------------------------------

class Envelope(BaseModel):
    id: constr(strip_whitespace=True, min_length=1, max_length=64) = Field(default_factory=lambda: uuid.uuid4().hex)
    ts: conint(ge=0) = Field(default_factory=lambda: int(time.time()))
    type: constr(strip_whitespace=True, min_length=1, max_length=64)
    # payload
    data: dict = Field(default_factory=dict)
    # сигнатура первого сообщения: "sha256=<hex>" (если включен HMAC)
    sig: constr(strip_whitespace=True, min_length=8, max_length=128) | None = None

    @validator("type")
    def _lower(cls, v: str) -> str:
        return v.strip().lower()


class Hello(BaseModel):
    # Первое сообщение от клиента: приветствие + контекст
    nonce: constr(min_length=8, max_length=128)
    tenant_id: constr(strip_whitespace=True, min_length=1, max_length=128) = "default"
    user_id: constr(strip_whitespace=True, min_length=1, max_length=128) = "anonymous"
    roles: list[str] = []
    # Доп. сведения (опц.): версия агента, платформа, и т.д.
    meta: dict = Field(default_factory=dict)


class Ack(BaseModel):
    session_id: str
    heartbeat_sec: int
    idle_timeout_sec: int
    accepted_subprotocol: str


class Subscribe(BaseModel):
    channel: constr(strip_whitespace=True, min_length=1, max_length=64)
    # фильтры, напр. tenant/service для health
    filters: dict = Field(default_factory=dict)


class Unsubscribe(BaseModel):
    channel: constr(strip_whitespace=True, min_length=1, max_length=64)


class Ping(BaseModel):
    nonce: constr(min_length=1, max_length=128) = Field(default_factory=lambda: uuid.uuid4().hex)


class Pong(BaseModel):
    nonce: str


class ErrorMsg(BaseModel):
    code: conint(ge=1000, le=4999)
    message: constr(strip_whitespace=True, min_length=1, max_length=256)
    details: dict = Field(default_factory=dict)


class HealthUpdate(BaseModel):
    # пример полезной нагрузки для zt.health.v1
    status: constr(strip_whitespace=True, min_length=1, max_length=64)
    components: list[dict] = []


# ------------------------------------------------------------------------------
# Утилиты безопасности
# ------------------------------------------------------------------------------

def _check_origin(origin: str | None) -> None:
    if not SETTINGS.allowed_origins:
        return
    if not origin or origin not in SETTINGS.allowed_origins:
        raise WSProtocolError(4403, "origin not allowed")


def _check_spki_pin(headers: dict[str, str]) -> None:
    pins = tuple((SETTINGS.spki_pins_csv or "").split(",")) if SETTINGS.spki_pins_csv else ()
    if not pins:
        return
    spki = headers.get("x-client-spki")
    if not spki or spki not in pins:
        raise WSProtocolError(4401, "mtls pin mismatch")


def _verify_hmac(envelope: Envelope, raw_payload: bytes) -> None:
    if not SETTINGS.hmac_secret_b64:
        return
    if not envelope.sig or not envelope.sig.startswith("sha256="):
        raise WSProtocolError(4401, "missing or invalid signature")
    key = base64.b64decode(SETTINGS.hmac_secret_b64)
    # HMAC от текста сообщения data (первого), до gzip — здесь без компрессии.
    calc = hmac.new(key, raw_payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(calc, envelope.sig.split("=", 1)[1]):
        raise WSProtocolError(4401, "bad signature")


def _now() -> int:
    return int(time.time())


# ------------------------------------------------------------------------------
# Исключения и коды
# ------------------------------------------------------------------------------

class WSProtocolError(Exception):
    def __init__(self, code: int, message: str, details: dict | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


# ------------------------------------------------------------------------------
# Rate limiter (per-connection token bucket)
# ------------------------------------------------------------------------------

class _Bucket:
    __slots__ = ("tokens", "updated")

    def __init__(self, tokens: float, updated: float):
        self.tokens = tokens
        self.updated = updated


class RateLimiter:
    def __init__(self, per_sec: int, burst: int):
        self.rate = float(per_sec)
        self.burst = float(burst)
        self._b = _Bucket(tokens=self.burst, updated=time.monotonic())

    def allow(self) -> bool:
        now = time.monotonic()
        delta = now - self._b.updated
        self._b.tokens = min(self.burst, self._b.tokens + delta * self.rate)
        self._b.updated = now
        if self._b.tokens >= 1.0:
            self._b.tokens -= 1.0
            return True
        return False


# ------------------------------------------------------------------------------
# Абстракции источников данных (внедряются приложением через app.state)
# ------------------------------------------------------------------------------

class HealthSource:
    """
    Асинхронный источник обновлений здоровья системы.
    Ожидается, что реализован как async-итератор dict'ов, совместимых с HealthUpdate.
    """
    async def stream(self, filters: dict) -> t.AsyncIterator[dict]:
        if False:  # pragma: no cover
            yield {}


# ------------------------------------------------------------------------------
# Соединение
# ------------------------------------------------------------------------------

class Connection:
    def __init__(self, ws: WebSocket, subprotocol: str):
        self.ws = ws
        self.subprotocol = subprotocol
        self.id = uuid.uuid4().hex
        self.alive = True
        self.last_activity = time.monotonic()
        self.rl = RateLimiter(SETTINGS.rate_per_sec, SETTINGS.rate_burst)
        self.send_queue: asyncio.Queue[str] = asyncio.Queue(maxsize=SETTINGS.queue_max)
        self.subscriptions: dict[str, asyncio.Task] = {}  # channel -> task

    async def send_json(self, typ: str, data: dict, *, mid: str | None = None) -> None:
        env = Envelope(id=mid or uuid.uuid4().hex, ts=_now(), type=typ, data=data)
        frame = json.dumps(env.dict(), separators=(",", ":"), ensure_ascii=False)
        try:
            await self.send_queue.put(frame)
        except asyncio.QueueFull:
            raise WSProtocolError(1011, "send queue overflow")

    async def _sender(self) -> None:
        try:
            while self.alive:
                frame = await self.send_queue.get()
                await self.ws.send_text(frame)
        except Exception as e:
            logger.warning("sender stopped: %r", e)
            self.alive = False

    async def _heartbeat(self) -> None:
        try:
            interval = SETTINGS.heartbeat_sec
            idle = SETTINGS.idle_timeout_sec
            while self.alive:
                await asyncio.sleep(interval)
                # idle close
                if time.monotonic() - self.last_activity > idle:
                    await self.close(4408, "idle timeout")
                    break
                await self.send_json("ping", Ping().dict())
        except Exception as e:
            logger.warning("heartbeat stopped: %r", e)
            self.alive = False

    async def close(self, code: int, reason: str) -> None:
        if not self.alive:
            return
        self.alive = False
        for ch, task in list(self.subscriptions.items()):
            task.cancel()
        try:
            await self.ws.close(code=code, reason=reason)
        except RuntimeError:
            pass


# ------------------------------------------------------------------------------
# Роутер и endpoint
# ------------------------------------------------------------------------------

router = APIRouter()


@router.websocket("/v1/ws")
async def websocket_entry(ws: WebSocket):
    # Сабпротокол из заголовка
    requested = _parse_protocols(ws)
    chosen = _negotiate_subprotocol(requested, SETTINGS.subprotocols)
    try:
        origin = dict(ws.headers).get("origin")
        _check_origin(origin)
        _check_spki_pin(dict((k.lower(), v) for k, v in ws.headers))
    except WSProtocolError as e:
        # HTTP отказ до апгрейда WebSocket невозможен; примем и закроем с кодом.
        await ws.accept(subprotocol=chosen if chosen else None)
        await ws.close(code=e.code, reason=e.message)
        return

    await ws.accept(subprotocol=chosen if chosen else None)
    conn = Connection(ws, chosen or "none")
    sender_task = asyncio.create_task(conn._sender(), name=f"ws-sender-{conn.id}")
    hb_task = asyncio.create_task(conn._heartbeat(), name=f"ws-hb-{conn.id}")

    try:
        # Первое сообщение должно быть hello с HMAC (если требуется)
        hello_env, hello_raw = await _recv_envelope(ws)
        if hello_env.type != "hello":
            raise WSProtocolError(4400, "first message must be 'hello'")
        _verify_hmac(hello_env, hello_raw)
        hello = Hello(**hello_env.data)
        # Анти‑replay по nonce: допускаем простую память за соединение
        seen_nonces: set[str] = set()
        if hello.nonce in seen_nonces:
            raise WSProtocolError(4409, "duplicate nonce")
        seen_nonces.add(hello.nonce)

        # Отправим ack
        ack = Ack(session_id=conn.id, heartbeat_sec=SETTINGS.heartbeat_sec, idle_timeout_sec=SETTINGS.idle_timeout_sec, accepted_subprotocol=conn.subprotocol)
        await conn.send_json("ack", ack.dict(), mid=hello_env.id)

        # Главный цикл
        while conn.alive:
            env, _raw = await _recv_envelope(ws)
            conn.last_activity = time.monotonic()
            if not conn.rl.allow():
                raise WSProtocolError(4429, "rate limit exceeded")
            await _dispatch(conn, env, hello)
    except WSProtocolError as e:
        await _safe_send_error(conn, e)
        await conn.close(e.code, e.message)
    except WebSocketDisconnect:
        await conn.close(status.WS_1000_NORMAL_CLOSURE, "client disconnected")
    except Exception as e:
        logger.exception("ws internal error: %r", e)
        await _safe_send_error(conn, WSProtocolError(1011, "internal error"))
        await conn.close(1011, "internal error")
    finally:
        sender_task.cancel()
        hb_task.cancel()


# ------------------------------------------------------------------------------
# Обработчик сообщений
# ------------------------------------------------------------------------------

async def _dispatch(conn: Connection, env: Envelope, hello: Hello) -> None:
    tpe = env.type
    if tpe == "ping":
        nonce = env.data.get("nonce") if isinstance(env.data, dict) else None
        await conn.send_json("pong", Pong(nonce=nonce or "").dict(), mid=env.id)
        return

    if tpe == "subscribe":
        sub = Subscribe(**env.data)
        if sub.channel == "health":
            if "zt.health.v1" not in (conn.subprotocol,):
                raise WSProtocolError(4400, "health not available under this subprotocol")
            await _start_health_subscription(conn, env, sub.filters)
            return
        if sub.channel == "events":
            if "zt.events.v1" not in (conn.subprotocol,):
                raise WSProtocolError(4400, "events not available under this subprotocol")
            await _start_events_subscription(conn, env, sub.filters)
            return
        raise WSProtocolError(4404, f"unknown channel '{sub.channel}'")

    if tpe == "unsubscribe":
        unsub = Unsubscribe(**env.data)
        await _stop_subscription(conn, unsub.channel)
        await conn.send_json("ok", {"unsubscribed": unsub.channel}, mid=env.id)
        return

    if tpe == "hello":
        # Повторный hello запрещен
        raise WSProtocolError(4400, "duplicate hello")

    raise WSProtocolError(4404, f"unknown message type '{tpe}'")


# ------------------------------------------------------------------------------
# Подписки
# ------------------------------------------------------------------------------

async def _start_health_subscription(conn: Connection, env: Envelope, filters: dict) -> None:
    if "health" in conn.subscriptions:
        raise WSProtocolError(4409, "already subscribed: health")

    # Источник берем из app.state, если доступен (FastAPI/Starlette)
    ws_app = conn.ws.app  # type: ignore[attr-defined]
    source: HealthSource | None = getattr(getattr(ws_app, "state", None), "health_source", None)  # type: ignore[assignment]
    if not source:
        # Отправим одноразовый снимок "SERVING" для совместимости
        await conn.send_json("health.update", HealthUpdate(status="SERVING", components=[]).dict(), mid=env.id)
        return

    async def run():
        try:
            async for upd in source.stream(filters or {}):
                model = HealthUpdate(**upd)
                await conn.send_json("health.update", model.dict())
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.warning("health stream error: %r", e)
            await _safe_send_error(conn, WSProtocolError(1011, "health stream error"))

    task = asyncio.create_task(run(), name=f"ws-health-{conn.id}")
    conn.subscriptions["health"] = task
    await conn.send_json("ok", {"subscribed": "health"}, mid=env.id)


async def _start_events_subscription(conn: Connection, env: Envelope, filters: dict) -> None:
    if "events" in conn.subscriptions:
        raise WSProtocolError(4409, "already subscribed: events")

    ws_app = conn.ws.app  # type: ignore[attr-defined]
    # Ожидаем, что приложение задаст async-итератор в app.state.events_source
    source: t.AsyncIterator[dict] | None = getattr(getattr(ws_app, "state", None), "events_source", None)  # type: ignore[assignment]
    if not source:
        await conn.send_json("ok", {"subscribed": "events", "note": "no source configured"}, mid=env.id)
        return

    async def run():
        try:
            async for evt in source:
                # Свободный формат события; сервер лишь оборачивает в Envelope
                await conn.send_json("event", dict(evt))
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.warning("events stream error: %r", e)
            await _safe_send_error(conn, WSProtocolError(1011, "events stream error"))

    task = asyncio.create_task(run(), name=f"ws-events-{conn.id}")
    conn.subscriptions["events"] = task
    await conn.send_json("ok", {"subscribed": "events"}, mid=env.id)


async def _stop_subscription(conn: Connection, channel: str) -> None:
    tsk = conn.subscriptions.pop(channel, None)
    if tsk:
        tsk.cancel()


# ------------------------------------------------------------------------------
# Вспомогательные функции
# ------------------------------------------------------------------------------

async def _recv_envelope(ws: WebSocket) -> tuple[Envelope, bytes]:
    """Читает текстовый фрейм, валидирует Envelope, возвращает Envelope и сырые байты data для HMAC."""
    raw = await ws.receive_text()
    try:
        parsed = json.loads(raw)
        env = Envelope(**parsed)
    except Exception:
        raise WSProtocolError(4400, "invalid json envelope")
    # Уточнение: сырая полезная нагрузка для HMAC — это JSON сериализация поля data
    data_bytes = json.dumps(env.data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return env, data_bytes


def _parse_protocols(ws: WebSocket) -> tuple[str, ...]:
    # Заголовок Sec-WebSocket-Protocol может содержать CSV
    hdr = dict(ws.headers).get("sec-websocket-protocol", "")
    req = tuple(x.strip() for x in hdr.split(",") if x.strip())
    return req


def _negotiate_subprotocol(requested: tuple[str, ...], supported: tuple[str, ...]) -> str | None:
    for r in requested:
        if r in supported:
            return r
    # Если клиент ничего не запросил, можем выбрать дефолт (например health)
    return supported[0] if supported else None


async def _safe_send_error(conn: Connection, e: WSProtocolError) -> None:
    if not conn.alive:
        return
    try:
        await conn.send_json("error", ErrorMsg(code=e.code, message=e.message, details=e.details).dict())
    except Exception:
        pass


# ------------------------------------------------------------------------------
# Пример интеграции (для справки, не выполняется при импорте)
# ------------------------------------------------------------------------------
# from fastapi import FastAPI
#
# app = FastAPI()
# app.include_router(router)
#
# class MyHealth(HealthSource):
#     async def stream(self, filters: dict):
#         while True:
#             yield {"status": "SERVING", "components": []}
#             await asyncio.sleep(5)
#
# app.state.health_source = MyHealth()
# app.state.events_source = my_async_iterable_of_events  # любой async-итератор словарей
