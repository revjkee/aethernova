# ledger-core/api/ws/server.py
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import secrets
import signal
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Optional, Set, Tuple

try:
    # Опциональная интеграция с вашим модулем ошибок
    from ledger_core.api.http.errors import HttpError  # type: ignore
except Exception:  # noqa: BLE001
    class HttpError(Exception):  # fallback
        def __init__(self, code: str, detail: str, status: int = 400) -> None:
            super().__init__(detail)
            self.code, self.detail, self.status = code, detail, status


logger = logging.getLogger(__name__)

# =========================
# Конфигурация и контракты
# =========================

@dataclass(frozen=True)
class WSConfig:
    # Ограничения и таймауты
    max_message_bytes: int = 128 * 1024
    send_queue_max: int = 1000
    heartbeat_interval_sec: float = 20.0
    heartbeat_timeout_sec: float = 10.0
    # Rate limit (token bucket)
    rate_bucket_capacity: int = 60
    rate_refill_per_sec: float = 30.0
    # Бизнес‑ограничения
    allowed_actions: Set[str] = field(default_factory=lambda: {
        "ping", "subscribe", "unsubscribe", "publish", "ack"
    })
    # Прочее
    close_code_policy_violation: int = 1008
    close_code_normal: int = 1000
    tenant_header: str = "x-tenant-id"
    request_id_header: str = "x-request-id"


# Типы колбэков
VerifyTokenFn = Callable[[str], Awaitable[Tuple[str, Dict[str, Any]]]]
OnPublishFn = Callable[[str, str, Dict[str, Any], Dict[str, Any]], Awaitable[None]]
MetricsHook = Callable[[str, Dict[str, Any]], None]


# =========================
# Утилиты
# =========================

def _now() -> float:
    return time.monotonic()

def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)

def _safe_json_loads(raw: str) -> Dict[str, Any]:
    try:
        v = json.loads(raw)
        if not isinstance(v, dict):
            raise ValueError("payload must be a JSON object")
        return v
    except Exception as e:  # noqa: BLE001
        raise HttpError("BAD_REQUEST", f"invalid JSON: {e}", status=400)


# =========================
# Менеджер подключений и топиков
# =========================

class TokenBucket:
    __slots__ = ("_capacity", "_tokens", "_rate", "_last")

    def __init__(self, capacity: int, refill_per_sec: float) -> None:
        self._capacity = capacity
        self._rate = float(refill_per_sec)
        self._tokens = float(capacity)
        self._last = _now()

    def allow(self, cost: float = 1.0) -> bool:
        now = _now()
        elapsed = max(0.0, now - self._last)
        self._last = now
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        if self._tokens >= cost:
            self._tokens -= cost
            return True
        return False


@dataclass
class ClientCtx:
    conn_id: str
    tenant_id: str
    subject: str
    meta: Dict[str, Any]
    request_id: str
    # runtime
    send_queue: "asyncio.Queue[str]" = field(default_factory=asyncio.Queue)
    topics: Set[str] = field(default_factory=set)
    bucket: TokenBucket = field(default_factory=lambda: TokenBucket(60, 30))


class TopicHub:
    """Потокобезопасный хаб подписок."""
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._topics: Dict[str, Set[str]] = defaultdict(set)     # topic -> set(conn_id)
        self._conns: Dict[str, ClientCtx] = {}                   # conn_id -> ctx

    async def add_conn(self, ctx: ClientCtx) -> None:
        async with self._lock:
            self._conns[ctx.conn_id] = ctx

    async def remove_conn(self, conn_id: str) -> None:
        async with self._lock:
            ctx = self._conns.pop(conn_id, None)
            if not ctx:
                return
            for t in list(ctx.topics):
                subs = self._topics.get(t)
                if subs:
                    subs.discard(conn_id)
                    if not subs:
                        self._topics.pop(t, None)

    async def subscribe(self, conn_id: str, topic: str) -> None:
        async with self._lock:
            ctx = self._conns[conn_id]
            ctx.topics.add(topic)
            self._topics[topic].add(conn_id)

    async def unsubscribe(self, conn_id: str, topic: str) -> None:
        async with self._lock:
            ctx = self._conns.get(conn_id)
            if not ctx:
                return
            ctx.topics.discard(topic)
            subs = self._topics.get(topic)
            if subs:
                subs.discard(conn_id)
                if not subs:
                    self._topics.pop(topic, None)

    async def publish(self, tenant_id: str, topic: str, message: Dict[str, Any]) -> int:
        """Рассылает сообщение всем подписчикам топика в пределах того же tenant."""
        async with self._lock:
            subs = self._topics.get(topic)
            if not subs:
                return 0
            delivered = 0
            payload = _json_dumps(message)
            for conn_id in list(subs):
                ctx = self._conns.get(conn_id)
                if not ctx or ctx.tenant_id != tenant_id:
                    continue
                try:
                    ctx.send_queue.put_nowait(payload)
                    delivered += 1
                except asyncio.QueueFull:
                    # Бэкап‑политика: отсоединяем медленного клиента (защита от backpressure)
                    logger.warning("ws backpressure: disconnecting conn=%s topic=%s", conn_id, topic)
                    # пометим на удаление вне lock
                    asyncio.create_task(self._kick(conn_id))
            return delivered

    async def _kick(self, conn_id: str) -> None:
        await self.remove_conn(conn_id)


# =========================
# Ядро WS‑сервера
# =========================

class WSServer:
    """
    Ядро WebSocket сервера: не привязано к конкретному фреймворку.
    Требует адаптера транспорта, предоставляющего:
      - recv_text() -> str
      - send_text(text: str)
      - close(code:int, reason:str)
      - headers: Dict[str,str]
      - query_params: Dict[str,str]
    """
    def __init__(
        self,
        *,
        verify_token: VerifyTokenFn,
        on_publish: Optional[OnPublishFn] = None,
        metrics_hook: Optional[MetricsHook] = None,
        config: Optional[WSConfig] = None,
    ) -> None:
        self.cfg = config or WSConfig()
        self.verify_token = verify_token
        self.on_publish = on_publish or (lambda t, x, m, meta: asyncio.create_task(asyncio.sleep(0)))
        self.metrics = metrics_hook or (lambda name, labels: None)
        self.hub = TopicHub()

    # ---- обработка одного соединения ----

    async def handle(self, transport: "Transport") -> None:
        # handshake/auth
        tenant = transport.headers.get(self.cfg.tenant_header) or transport.query_params.get("tenant", "")
        req_id = transport.headers.get(self.cfg.request_id_header) or secrets.token_hex(8)
        token = (
            transport.query_params.get("token")
            or transport.headers.get("authorization", "").replace("Bearer ", "")
        )
        if not token:
            await self._close_policy(transport, "missing token", req_id)
            return

        try:
            subject, claims = await self.verify_token(token)
        except Exception as e:  # noqa: BLE001
            await self._close_policy(transport, f"auth failed: {e}", req_id)
            return

        conn_id = f"{int(time.time())}-{secrets.token_hex(6)}"
        ctx = ClientCtx(conn_id=conn_id, tenant_id=tenant or claims.get("tenant", "default"),
                        subject=subject, meta={"claims": claims}, request_id=req_id,
                        send_queue=asyncio.Queue(self.cfg.send_queue_max),
                        bucket=TokenBucket(self.cfg.rate_bucket_capacity, self.cfg.rate_refill_per_sec))

        await self.hub.add_conn(ctx)
        self.metrics("ws_connected", {"tenant": ctx.tenant_id})
        logger.info("ws connected conn=%s tenant=%s subject=%s rid=%s", conn_id, ctx.tenant_id, subject, req_id)

        # фоновые задачи: отправка, heartbeat
        sender = asyncio.create_task(self._sender_loop(transport, ctx))
        heart = asyncio.create_task(self._heartbeat_loop(transport, ctx))

        try:
            await self._recv_loop(transport, ctx)
        except Exception as e:  # noqa: BLE001
            logger.exception("ws connection error conn=%s: %s", conn_id, e)
        finally:
            sender.cancel()
            heart.cancel()
            with contextlib.suppress(Exception):
                await self.hub.remove_conn(conn_id)
            self.metrics("ws_disconnected", {"tenant": ctx.tenant_id})
            logger.info("ws disconnected conn=%s", conn_id)

    async def _recv_loop(self, transport: "Transport", ctx: ClientCtx) -> None:
        while True:
            raw = await transport.recv_text(max_bytes=self.cfg.max_message_bytes)
            msg = _safe_json_loads(raw)

            # rate limit
            if not ctx.bucket.allow():
                await self._send_error(ctx, "RATE_LIMITED", "rate limit exceeded")
                continue

            action = str(msg.get("type") or msg.get("action") or "")
            if action not in self.cfg.allowed_actions:
                await self._send_error(ctx, "BAD_REQUEST", f"unsupported action: {action}")
                continue

            if action == "ping":
                await ctx.send_queue.put(_json_dumps({"type": "pong", "ts": int(time.time() * 1000)}))
                continue

            if action == "subscribe":
                topic = str(msg.get("topic") or "")
                if not topic:
                    await self._send_error(ctx, "BAD_REQUEST", "topic required")
                    continue
                await self.hub.subscribe(ctx.conn_id, topic)
                await ctx.send_queue.put(_json_dumps({"type": "subscribed", "topic": topic}))
                self.metrics("ws_subscribe", {"tenant": ctx.tenant_id, "topic": topic})
                continue

            if action == "unsubscribe":
                topic = str(msg.get("topic") or "")
                if not topic:
                    await self._send_error(ctx, "BAD_REQUEST", "topic required")
                    continue
                await self.hub.unsubscribe(ctx.conn_id, topic)
                await ctx.send_queue.put(_json_dumps({"type": "unsubscribed", "topic": topic}))
                self.metrics("ws_unsubscribe", {"tenant": ctx.tenant_id, "topic": topic})
                continue

            if action == "publish":
                # безопасность: публиковать разрешаем по вашему verify_token (роль), здесь — через claims.role
                if "publisher" not in (ctx.meta["claims"].get("roles") or []):
                    await self._send_error(ctx, "FORBIDDEN", "not allowed to publish")
                    continue
                topic = str(msg.get("topic") or "")
                payload = msg.get("message")
                if not topic or not isinstance(payload, dict):
                    await self._send_error(ctx, "BAD_REQUEST", "topic and message are required")
                    continue
                # пользовательский хук (например, запись в БД/брокер)
                await self.on_publish(ctx.tenant_id, topic, payload, {"subject": ctx.subject, "rid": ctx.request_id})
                # локальная рассылка
                await self.hub.publish(ctx.tenant_id, topic, {
                    "type": "event",
                    "topic": topic,
                    "data": payload,
                    "ts": int(time.time() * 1000),
                })
                continue

            if action == "ack":
                # идемпотентный ack для приложений
                await ctx.send_queue.put(_json_dumps({"type": "ack", "id": msg.get("id")}))
                continue

    async def _sender_loop(self, transport: "Transport", ctx: ClientCtx) -> None:
        # Единая точка отправки: следим за backpressure
        while True:
            text = await ctx.send_queue.get()
            try:
                await transport.send_text(text)
            except Exception as e:  # noqa: BLE001
                logger.warning("ws send failed conn=%s: %s", ctx.conn_id, e)
                await transport.close(self.cfg.close_code_normal, "send failed")
                return

    async def _heartbeat_loop(self, transport: "Transport", ctx: ClientCtx) -> None:
        # простая схема ping/pong — клиент отвечает "pong" на "ping" (в _recv_loop)
        last_ok = _now()
        while True:
            await asyncio.sleep(self.cfg.heartbeat_interval_sec)
            try:
                await ctx.send_queue.put(_json_dumps({"type": "ping", "ts": int(time.time() * 1000)}))
            except Exception:
                pass
            # проверим время последнего успешного отправленного сообщения — ориентир на отсутствие ошибок отправки
            if (_now() - last_ok) > (self.cfg.heartbeat_interval_sec + self.cfg.heartbeat_timeout_sec):
                logger.info("ws heartbeat timeout, closing conn=%s", ctx.conn_id)
                with contextlib.suppress(Exception):
                    await transport.close(self.cfg.close_code_normal, "heartbeat timeout")
                return
            last_ok = _now()

    async def _send_error(self, ctx: ClientCtx, code: str, detail: str) -> None:
        await ctx.send_queue.put(_json_dumps({"type": "error", "code": code, "detail": detail}))

    async def _close_policy(self, transport: "Transport", reason: str, request_id: str) -> None:
        logger.info("ws reject: %s rid=%s", reason, request_id)
        try:
            await transport.send_text(_json_dumps({"type": "error", "code": "AUTHENTICATION_FAILED", "detail": reason}))
        except Exception:
            pass
        with contextlib.suppress(Exception):
            await transport.close(self.cfg.close_code_policy_violation, reason)


# =========================
# Адаптеры транспорта
# =========================

class Transport:
    """Минимальный протокол транспорта для ядра."""
    headers: Dict[str, str]
    query_params: Dict[str, str]

    async def recv_text(self, *, max_bytes: int) -> str: ...
    async def send_text(self, text: str) -> None: ...
    async def close(self, code: int, reason: str) -> None: ...


# ---- Starlette/FastAPI адаптер (опциональный) ----
class StarletteTransport(Transport):  # pragma: no cover
    def __init__(self, ws) -> None:
        self.ws = ws
        # Нормализуем заголовки и квери
        self.headers = {k.lower(): v for k, v in ws.headers.items()}
        self.query_params = dict(ws.query_params)

    async def recv_text(self, *, max_bytes: int) -> str:
        msg = await self.ws.receive_text()
        if len(msg.encode("utf-8")) > max_bytes:
            raise HttpError("BAD_REQUEST", "message too large", 400)
        return msg

    async def send_text(self, text: str) -> None:
        await self.ws.send_text(text)

    async def close(self, code: int, reason: str) -> None:
        await self.ws.close(code=code)


async def starlette_endpoint(server: WSServer, websocket) -> None:  # pragma: no cover
    await websocket.accept(subprotocol=None)
    await server.handle(StarletteTransport(websocket))


# ---- Standalone сервер на websockets (опционально) ----
async def _ws_handler(websocket, path, server: WSServer):  # pragma: no cover
    class WSlibTransport(Transport):
        def __init__(self, ws) -> None:
            self.ws = ws
            # Библиотека websockets не хранит заголовки запроса напрямую: используем request_headers
            self.headers = {k.lower(): v for k, v in dict(ws.request_headers).items()}
            # query params
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(path).query)
            self.query_params = {k: v[-1] for k, v in qs.items()}

        async def recv_text(self, *, max_bytes: int) -> str:
            msg = await self.ws.recv()
            if isinstance(msg, bytes):
                raise HttpError("BAD_REQUEST", "binary not supported", 400)
            if len(msg.encode("utf-8")) > max_bytes:
                raise HttpError("BAD_REQUEST", "message too large", 400)
            return msg

        async def send_text(self, text: str) -> None:
            await self.ws.send(text)

        async def close(self, code: int, reason: str) -> None:
            await self.ws.close(code=code)

    await server.handle(WSlibTransport(websocket))


def run_standalone(
    server: WSServer,
    host: str = "0.0.0.0",
    port: int = 8081,
) -> None:  # pragma: no cover
    """
    Запуск без фреймворков, если установлен websockets>=10.
    """
    try:
        import websockets  # type: ignore
    except Exception as e:  # noqa: BLE001
        raise RuntimeError("install 'websockets' to use standalone mode") from e

    loop = asyncio.get_event_loop()
    stop = loop.create_future()

    def _stop(*_):
        if not stop.done():
            stop.set_result(True)

    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, _stop)

    async def _main():
        async with websockets.serve(lambda ws, p: _ws_handler(ws, p, server), host, port):
            logger.info("WebSocket server started on %s:%d", host, port)
            await stop

    loop.run_until_complete(_main())


# =========================
# Пример встраивания (FastAPI)
# =========================
"""
Пример:

from fastapi import FastAPI, WebSocket
from ledger_core.api.ws.server import WSServer, starlette_endpoint

async def verify_token(token: str):
    # Возвращаем (subject, claims). Бросаем исключение при невалидности.
    return "user:123", {"roles": ["subscriber", "publisher"], "tenant": "acme"}

async def on_publish(tenant: str, topic: str, payload: dict, meta: dict):
    # Сюда можно писать в брокер/БД
    pass

server = WSServer(verify_token=verify_token, on_publish=on_publish)

app = FastAPI()
@app.websocket("/ws")
async def ws_handler(ws: WebSocket):
    await starlette_endpoint(server, ws)
"""

# =========================
# Пример запуска standalone
# =========================
"""
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    async def verify_token(token: str):
        if token != os.getenv("WS_TOKEN", "dev"):
            raise ValueError("bad token")
        return "demo-user", {"roles": ["subscriber", "publisher"], "tenant": "demo"}

    async def on_publish(tenant: str, topic: str, payload: dict, meta: dict):
        print(f"[{tenant}] {topic} <- {payload} ({meta})")

    srv = WSServer(verify_token=verify_token, on_publish=on_publish)
    run_standalone(srv, host="127.0.0.1", port=8081)
"""
