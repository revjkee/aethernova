# physical-integration-core/api/ws/protocols.py
from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, List

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from fastapi.websockets import WebSocketState
from prometheus_client import Counter, Histogram, Gauge

# =============== Конфигурация из окружения ===============
WS_ALLOWED_SUBPROTOCOLS = [p.strip() for p in os.getenv("PIC_WS_SUBPROTOCOLS", "pic.v1").split(",") if p.strip()]
WS_REQUIRE_AUTH = os.getenv("PIC_WS_REQUIRE_AUTH", "true").lower() == "true"
WS_JWT_ALGO = os.getenv("PIC_WS_JWT_ALGO", "RS256")            # HS256|RS256
WS_JWT_AUDIENCE = os.getenv("PIC_WS_JWT_AUD", "pic.edge")
WS_JWT_ISSUER = os.getenv("PIC_WS_JWT_ISS", "https://auth.example.local")
WS_JWT_HS_SECRET = os.getenv("PIC_WS_JWT_HS_SECRET")           # для HS256
# Примечание: для RS256 встраивание JWKS/ключа реализуйте через внешний провайдер.
# Здесь оставлен хук _verify_jwt().

WS_MAX_MESSAGE_BYTES = int(os.getenv("PIC_WS_MAX_MESSAGE_BYTES", "262144"))  # 256 KiB
WS_CONN_IDLE_TIMEOUT = float(os.getenv("PIC_WS_IDLE_TIMEOUT_SECONDS", "60"))
WS_HEARTBEAT_INTERVAL = float(os.getenv("PIC_WS_HEARTBEAT_SECONDS", "20"))
WS_SEND_QUEUE = int(os.getenv("PIC_WS_SEND_QUEUE", "1000"))

# rate limit (token bucket per connection)
WS_RPS = int(os.getenv("PIC_WS_RPS", "300"))
WS_BURST = int(os.getenv("PIC_WS_BURST", "600"))
WS_WINDOW = float(os.getenv("PIC_WS_WINDOW_SECONDS", "1.0"))

# =============== Метрики Prometheus ===============
WS_CONNECTIONS = Gauge("ws_connections", "Active WS connections", ["path", "subprotocol"])
WS_MESSAGES_IN = Counter("ws_messages_in_total", "Incoming WS messages", ["path", "subprotocol"])
WS_MESSAGES_OUT = Counter("ws_messages_out_total", "Outgoing WS messages", ["path", "subprotocol", "type"])
WS_ERRORS = Counter("ws_errors_total", "WS errors", ["path", "code", "reason"])
WS_LATENCY = Histogram("ws_message_latency_seconds", "Latency to handle WS message", ["path"], buckets=(0.005,0.01,0.025,0.05,0.1,0.25,0.5,1,2,5))

router = APIRouter(prefix="/ws", tags=["ws"])

# =============== Вспомогательные структуры ===============
@dataclass
class TokenBucket:
    tokens: float
    last_refill: float
    capacity: float
    fill_rate: float

    def allow(self) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        if elapsed > 0:
            self.tokens = min(self.capacity, self.tokens + elapsed * self.fill_rate)
            self.last_refill = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class SendQueue:
    def __init__(self, ws: WebSocket, subprotocol: str):
        self.ws = ws
        self.queue: asyncio.Queue[Tuple[str, str]] = asyncio.Queue(maxsize=WS_SEND_QUEUE)
        self.task: Optional[asyncio.Task] = None
        self.subprotocol = subprotocol
        self.closed = False

    async def start(self) -> None:
        self.task = asyncio.create_task(self._sender())

    async def stop(self) -> None:
        self.closed = True
        if self.task:
            self.task.cancel()
            with contextlib.suppress(Exception):
                await self.task

    async def send_json(self, obj: Dict[str, Any], msg_type: str = "data") -> None:
        if self.closed:
            return
        data = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
        await self.queue.put((data, msg_type))

    async def _sender(self) -> None:
        try:
            while True:
                data, msg_type = await self.queue.get()
                if self.ws.application_state != WebSocketState.CONNECTED:
                    return
                await self.ws.send_text(data)
                WS_MESSAGES_OUT.labels(self.ws.url.path, self.subprotocol, msg_type).inc()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            WS_ERRORS.labels(self.ws.url.path, "1011", "send_error").inc()
            if self.ws.application_state == WebSocketState.CONNECTED:
                await _close_ws(self.ws, 1011, "internal error")


# =============== JWT проверка (упрощенный хук) ===============
def _extract_token(ws: WebSocket) -> Optional[str]:
    # 1) query param ?access_token=...
    tok = ws.query_params.get("access_token")
    if tok:
        return tok
    # 2) Sec-WebSocket-Protocol: "bearer, <token>"
    # RFC не требует Authorization в WS, поэтому часто используют субпротокол
    sp = ws.headers.get("sec-websocket-protocol")
    if sp:
        parts = [p.strip() for p in sp.split(",")]
        if len(parts) >= 2 and parts[0].lower() == "bearer":
            return parts[1]
    # 3) cookie "auth"
    cookie = ws.cookies.get("auth")
    return cookie


def _verify_jwt(token: str) -> Tuple[bool, Dict[str, Any]]:
    """
    Хук для верификации JWT. Для HS256 доступен секрет из окружения.
    Для RS256 потребуется внешний поставщик ключей (JWKS). Здесь оставлен заглушечный путь:
    - HS256: валидируем локально при наличии секрета.
    - RS256: проверяем формат и базовые клеймы без криптопроверки (если нет провайдера).
    """
    try:
        import jwt  # PyJWT
        options = {"verify_aud": bool(WS_JWT_AUDIENCE), "verify_signature": True}
        if WS_JWT_ALGO.upper() == "HS256":
            if not WS_JWT_HS_SECRET:
                return False, {"error": "missing_hs_secret"}
            payload = jwt.decode(
                token, WS_JWT_HS_SECRET, algorithms=["HS256"],
                audience=WS_JWT_AUDIENCE, issuer=WS_JWT_ISSUER, options=options
            )
            return True, payload
        else:
            # RS256 путь без JWKS — базовая проверка без подписи
            unverified = jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
            iss_ok = not WS_JWT_ISSUER or unverified.get("iss") == WS_JWT_ISSUER
            aud_ok = not WS_JWT_AUDIENCE or (WS_JWT_AUDIENCE in unverified.get("aud", [])) or (unverified.get("aud") == WS_JWT_AUDIENCE)
            if iss_ok and aud_ok:
                return True, unverified  # В продакшне подключите JWKS-провайдер
            return False, {"error": "claims_mismatch"}
    except Exception as e:
        return False, {"error": "jwt_error", "detail": str(e)}


# =============== Общие утилиты ===============
async def _accept_ws(ws: WebSocket) -> str:
    # Выбор саб-протокола
    client_subs = ws.headers.get("sec-websocket-protocol", "")
    chosen = None
    for offered in [p.strip() for p in client_subs.split(",") if p.strip()]:
        if offered in WS_ALLOWED_SUBPROTOCOLS or offered.lower() == "bearer":
            # bearer используется для токена, но протокол данных выберем из списка
            continue
    # Если клиент явно запросил один из наших — берем его. Иначе первый допустимый.
    for offered in [p.strip() for p in client_subs.split(",") if p.strip()]:
        if offered in WS_ALLOWED_SUBPROTOCOLS:
            chosen = offered
            break
    if not chosen:
        chosen = WS_ALLOWED_SUBPROTOCOLS[0]
    await ws.accept(subprotocol=chosen)
    return chosen


async def _close_ws(ws: WebSocket, code: int, reason: str) -> None:
    if ws.application_state == WebSocketState.CONNECTED:
        await ws.close(code=code, reason=reason)


def _ack(ok: bool, ref: Optional[str], message: str = "", extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    obj = {
        "type": "ack" if ok else "nack",
        "id": ref,
        "status": "ACCEPTED" if ok else "REJECTED",
        "ts": time.time(),
        "message": message
    }
    if extra:
        obj.update(extra)
    return obj


def _problem(status_code: int, title: str, detail: str, ref: Optional[str] = None) -> Dict[str, Any]:
    return {
        "type": "problem",
        "title": title,
        "status": status_code,
        "detail": detail,
        "ts": time.time(),
        "id": ref
    }


def _fits_limit(text_data: str) -> bool:
    return len(text_data.encode("utf-8")) <= WS_MAX_MESSAGE_BYTES


# =============== Менеджер соединений ===============
class Connection:
    def __init__(self, ws: WebSocket, path: str, subprotocol: str, principal: Optional[str]):
        self.ws = ws
        self.path = path
        self.subprotocol = subprotocol
        self.principal = principal or "-"
        self.id = uuid.uuid4().hex
        self.created_at = time.time()
        self.last_seen = self.created_at
        self.recv_bucket = TokenBucket(tokens=float(WS_BURST), last_refill=time.monotonic(),
                                      capacity=float(WS_BURST), fill_rate=float(WS_RPS) / WS_WINDOW)
        self.sendq = SendQueue(ws, subprotocol)
        self.idem_cache: Dict[str, float] = {}  # id -> ts
        self._idem_ttl = 300.0

    async def start(self) -> None:
        WS_CONNECTIONS.labels(self.path, self.subprotocol).inc()
        await self.sendq.start()

    async def stop(self) -> None:
        WS_CONNECTIONS.labels(self.path, self.subprotocol).dec()
        await self.sendq.stop()

    def idempotent(self, mid: Optional[str]) -> bool:
        if not mid:
            return True
        now = time.time()
        # Очистка устаревших
        for k, v in list(self.idem_cache.items()):
            if now - v > self._idem_ttl:
                self.idem_cache.pop(k, None)
        if mid in self.idem_cache:
            return False
        self.idem_cache[mid] = now
        return True


# Глобальная карта активных подключений для /v1/commands (egress)
COMMANDS_CONNS: Dict[str, Connection] = {}  # key: twin_name


# =============== Обработчики каналов ===============
@router.websocket("/v1/echo")
async def ws_echo(ws: WebSocket):
    # Аутентификация (опциональная)
    if WS_REQUIRE_AUTH:
        tok = _extract_token(ws)
        ok, _ = _verify_jwt(tok) if tok else (False, {"error": "no_token"})
        if not ok:
            await ws.close(code=1008, reason="auth required")
            return
    sub = await _accept_ws(ws)
    conn = Connection(ws, ws.url.path, sub, principal=None)
    await conn.start()
    try:
        heartbeat = asyncio.create_task(_heartbeat(ws))
        while True:
            text = await ws.receive_text()
            conn.last_seen = time.time()
            if not _fits_limit(text):
                WS_ERRORS.labels(ws.url.path, "1009", "too_big").inc()
                await _close_ws(ws, 1009, "message too big")
                break
            WS_MESSAGES_IN.labels(ws.url.path, sub).inc()
            # Эхо с ack
            await conn.sendq.send_json({"type": "echo", "ts": time.time(), "payload": text}, "echo")
    except WebSocketDisconnect:
        pass
    finally:
        heartbeat.cancel()
        await conn.stop()


@router.websocket("/v1/telemetry/{twin_name}")
async def ws_telemetry(ws: WebSocket, twin_name: str):
    # Аутентификация
    principal = "-"
    if WS_REQUIRE_AUTH:
        tok = _extract_token(ws)
        ok, payload = _verify_jwt(tok) if tok else (False, {"error": "no_token"})
        if not ok:
            await ws.close(code=1008, reason="auth required")
            return
        principal = str(payload.get("sub", "-"))
    sub = await _accept_ws(ws)
    conn = Connection(ws, ws.url.path, sub, principal=principal)
    await conn.start()
    try:
        heartbeat = asyncio.create_task(_heartbeat(ws))
        while True:
            msg = await ws.receive_text()
            recv_started = time.perf_counter()
            conn.last_seen = time.time()

            if not conn.recv_bucket.allow():
                # 1008 policy violation для rate limit
                WS_ERRORS.labels(ws.url.path, "1008", "rate_limited").inc()
                await conn.sendq.send_json(_problem(429, "rate limit", "too many messages"), "problem")
                continue

            if not _fits_limit(msg):
                WS_ERRORS.labels(ws.url.path, "1009", "too_big").inc()
                await _close_ws(ws, 1009, "message too big")
                break

            WS_MESSAGES_IN.labels(ws.url.path, sub).inc()

            # Ожидаемый формат сообщения
            try:
                obj = json.loads(msg)
                mid = obj.get("id") or obj.get("event_id")
                stream = obj.get("stream") or "telemetry"
                payload = obj.get("payload")
                attributes = obj.get("attributes", {})
            except Exception:
                await conn.sendq.send_json(_problem(400, "bad request", "invalid json"), "problem")
                continue

            # Idempotency по id
            if not conn.idempotent(mid):
                await conn.sendq.send_json(_ack(True, mid, "duplicate ignored", {"duplicate": True}), "ack")
                continue

            # Здесь подключите ваш шинный продюсер (Kafka/AMQP). Пример — заглушка:
            # await producers.kafka.send("bus.telemetry.raw", key=twin_name, value=obj)
            await conn.sendq.send_json(_ack(True, mid, "queued"), "ack")

            WS_LATENCY.labels(ws.url.path).observe(time.perf_counter() - recv_started)
    except WebSocketDisconnect:
        pass
    finally:
        heartbeat.cancel()
        await conn.stop()


@router.websocket("/v1/commands/{twin_name}")
async def ws_commands(ws: WebSocket, twin_name: str):
    # Аутентификация
    principal = "-"
    if WS_REQUIRE_AUTH:
        tok = _extract_token(ws)
        ok, payload = _verify_jwt(tok) if tok else (False, {"error": "no_token"})
        if not ok:
            await ws.close(code=1008, reason="auth required")
            return
        principal = str(payload.get("sub", "-"))

    sub = await _accept_ws(ws)
    conn = Connection(ws, ws.url.path, sub, principal=principal)
    await conn.start()
    COMMANDS_CONNS[twin_name] = conn

    try:
        heartbeat = asyncio.create_task(_heartbeat(ws))
        # Канал исходящих команд: клиент может посылать acks, а сервер — команды
        while True:
            message = await ws.receive_text()
            conn.last_seen = time.time()

            if not _fits_limit(message):
                WS_ERRORS.labels(ws.url.path, "1009", "too_big").inc()
                await _close_ws(ws, 1009, "message too big")
                break

            WS_MESSAGES_IN.labels(ws.url.path, sub).inc()
            try:
                obj = json.loads(message)
                # Ожидаем подтверждения команд {"type":"ack","id": "...", "status":"COMPLETED"|"FAILED"|...}
                if obj.get("type") in ("ack", "nack"):
                    # Пример: доставить в backend подтверждение
                    # await producers.commands_ack.send(key=twin_name, value=obj)
                    pass
                elif obj.get("type") == "heartbeat":
                    await conn.sendq.send_json({"type": "pong", "ts": time.time()}, "pong")
                else:
                    await conn.sendq.send_json(_problem(400, "unexpected", "unexpected message type"), "problem")
            except Exception:
                await conn.sendq.send_json(_problem(400, "bad request", "invalid json"), "problem")
    except WebSocketDisconnect:
        pass
    finally:
        heartbeat.cancel()
        await conn.stop()
        COMMANDS_CONNS.pop(twin_name, None)


# =============== Server-side API для отправки команд ===============
async def push_command(twin_name: str, command: Dict[str, Any]) -> bool:
    """
    Отправить команду подключенному устройству через WS.
    Возвращает True, если соединение найдено и сообщение поставлено в очередь.
    """
    conn = COMMANDS_CONNS.get(twin_name)
    if not conn:
        return False
    cmd = {
        "type": "command",
        "id": command.get("id") or uuid.uuid4().hex,
        "ts": time.time(),
        "command": command.get("name"),
        "params": command.get("params", {}),
        "priority": command.get("priority", "NORMAL"),
    }
    await conn.sendq.send_json(cmd, "command")
    return True


# =============== Heartbeat и idle-timeout ===============
import contextlib

async def _heartbeat(ws: WebSocket):
    try:
        while True:
            await asyncio.sleep(WS_HEARTBEAT_INTERVAL)
            # Контроль простоя
            idle = getattr(ws, "_pic_last_seen", None)
            # Starlette WebSocket не дает пинг-фреймов; используем JSON pong/heartbeat.
            if ws.application_state != WebSocketState.CONNECTED:
                return
            try:
                await ws.send_text(json.dumps({"type": "ping", "ts": time.time()}))
                WS_MESSAGES_OUT.labels(ws.url.path, ws.headers.get("sec-websocket-protocol", "pic.v1"), "ping").inc()
            except Exception:
                await _close_ws(ws, 1011, "heartbeat failure")
                return
    except asyncio.CancelledError:
        return
