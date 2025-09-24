# SPDX-License-Identifier: Apache-2.0
"""
Industrial WebSocket server for Omnimind Core.

Features:
- ASGI endpoint on Starlette (`/ws`)
- Token auth (e.g., Bearer JWT) with pluggable verifier
- Connection/topic registry with subscribe/unsubscribe/publish
- Message envelope (id, type, topic, payload, ts, correlation_id)
- Backpressure via per-connection asyncio.Queue (bounded)
- Rate limiting (token bucket) on incoming messages
- Heartbeat (server ping + idle timeout)
- Graceful shutdown and structured logging (JSON)
- No hard dependency on uvicorn (only for __main__)

Message schema (JSON):
{
  "id": "<client-msg-id>",                # optional
  "type": "subscribe|unsubscribe|publish|ping|pong|echo",
  "topic": "<string>",                    # required for sub/unsub/publish
  "payload": <any>,                       # publish payload
  "ts": "<RFC3339 UTC ISO8601>",          # server fills on replies
  "correlation_id": "<string>"            # optional
}

Server replies:
- "ack" for successful operations
- "nack" with "error" object for failures
- "message" for published/broadcasted items

Close codes follow RFC 6455 semantics where possible.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import os
import signal
import sys
import time
import traceback
import typing as t
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from starlette.applications import Starlette
from starlette.endpoints import WebSocketEndpoint
from starlette.routing import WebSocketRoute
from starlette.types import Scope
from starlette.websockets import WebSocket, WebSocketDisconnect

# ------------------------------ Config (tune for prod) ------------------------------

WS_PATH = "/ws"

MAX_INBOUND_MSG_BYTES = int(os.getenv("WS_MAX_INBOUND_BYTES", "131072"))  # 128 KiB
SEND_QUEUE_SIZE = int(os.getenv("WS_SEND_QUEUE_SIZE", "1000"))
HEARTBEAT_INTERVAL_SEC = float(os.getenv("WS_HEARTBEAT_INTERVAL", "20"))
IDLE_TIMEOUT_SEC = float(os.getenv("WS_IDLE_TIMEOUT", "120"))
RATE_LIMIT_CAPACITY = int(os.getenv("WS_RATE_LIMIT_CAPACITY", "60"))  # tokens
RATE_LIMIT_REFILL_PER_SEC = float(os.getenv("WS_RATE_LIMIT_RPS", "20"))  # tokens/sec
ALLOWED_TOPICS_PREFIX = os.getenv("WS_TOPICS_PREFIX", "")  # optional topic namespace guard
ALLOW_CLIENT_PUBLISH = os.getenv("WS_ALLOW_CLIENT_PUBLISH", "true").lower() == "true"

LOGGER_NAME = "ops.api.ws"
JSON_LOGS = os.getenv("WS_JSON_LOGS", "true").lower() == "true"

# ------------------------------ Correlation Context ------------------------------

_corr_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("correlation_id", default=None)

def set_correlation_id(value: str | None) -> None:
    _corr_id.set(value)

def get_correlation_id() -> str | None:
    return _corr_id.get()

# ------------------------------ Logging ------------------------------

def _setup_logging() -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        if JSON_LOGS:
            formatter = logging.Formatter("%(message)s")
        else:
            formatter = logging.Formatter("[%(levelname)s] %(asctime)s %(name)s: %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger

log = _setup_logging()

def _log_json(event: str, **kwargs: t.Any) -> None:
    payload = {"event": event, "ts": _ts(), "correlation_id": get_correlation_id(), **kwargs}
    try:
        log.info(json.dumps(payload, ensure_ascii=False))
    except Exception:
        log.info(f"{event} {kwargs}")

# ------------------------------ Utilities ------------------------------

def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()

def _uuid() -> str:
    return str(uuid.uuid4())

def _safe_json_loads(data: str) -> dict[str, t.Any]:
    if len(data.encode("utf-8", "ignore")) > MAX_INBOUND_MSG_BYTES:
        raise ValueError("message too large")
    obj = json.loads(data)
    if not isinstance(obj, dict):
        raise ValueError("message must be a JSON object")
    return t.cast(dict[str, t.Any], obj)

def _ensure_topic(topic: str) -> str:
    if not isinstance(topic, str) or not topic:
        raise ValueError("topic must be a non-empty string")
    if ALLOWED_TOPICS_PREFIX and not topic.startswith(ALLOWED_TOPICS_PREFIX):
        raise PermissionError("topic not allowed")
    return topic

# ------------------------------ Rate Limiter ------------------------------

class RateLimiter:
    """Simple token bucket."""
    __slots__ = ("capacity", "refill_per_sec", "_tokens", "_last")

    def __init__(self, capacity: int, refill_per_sec: float) -> None:
        self.capacity = capacity
        self.refill_per_sec = refill_per_sec
        self._tokens = capacity
        self._last = time.monotonic()

    def allow(self, cost: int = 1) -> bool:
        now = time.monotonic()
        elapsed = now - self._last
        self._last = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self.refill_per_sec)
        if self._tokens >= cost:
            self._tokens -= cost
            return True
        return False

# ------------------------------ Security (auth) ------------------------------

@dataclass(frozen=True)
class Principal:
    sub: str
    roles: tuple[str, ...] = field(default_factory=tuple)

def verify_bearer_token(token: str) -> Principal:
    """
    Placeholder verifier. Replace with real JWT/OIDC verification.
    The function MUST raise ValueError on invalid token.

    Example integration:
      - Decode and verify JWT signature and 'exp', 'aud', 'iss'
      - Return Principal(sub=claims['sub'], roles=tuple(claims.get('roles', [])))
    """
    if not token or len(token) < 8:
        raise ValueError("invalid token")
    return Principal(sub=token[:12])  # deterministic stub without secrets

def _extract_token(headers: dict[str, str]) -> str | None:
    auth = headers.get("authorization") or headers.get("Authorization")
    if not auth:
        return None
    if auth.startswith("Bearer "):
        return auth.split(" ", 1)[1].strip()
    return None

# ------------------------------ Connection & Manager ------------------------------

@dataclass
class Client:
    id: str
    principal: Principal
    ws: WebSocket
    send_q: asyncio.Queue[str]
    last_seen: float
    topics: set[str]
    limiter: RateLimiter

class ConnectionManager:
    def __init__(self) -> None:
        self._clients: dict[str, Client] = {}
        self._topics: dict[str, set[str]] = {}
        self._lock = asyncio.Lock()
        self._shutdown = asyncio.Event()

    async def register(self, client: Client) -> None:
        async with self._lock:
            self._clients[client.id] = client
        _log_json("ws_connected", client_id=client.id, user=client.principal.sub)

    async def unregister(self, client_id: str) -> None:
        async with self._lock:
            client = self._clients.pop(client_id, None)
            if client:
                for tpc in list(client.topics):
                    subs = self._topics.get(tpc)
                    if subs and client_id in subs:
                        subs.discard(client_id)
                        if not subs:
                            self._topics.pop(tpc, None)
        _log_json("ws_disconnected", client_id=client_id)

    async def subscribe(self, client_id: str, topic: str) -> None:
        topic = _ensure_topic(topic)
        async with self._lock:
            self._topics.setdefault(topic, set()).add(client_id)
            if client_id in self._clients:
                self._clients[client_id].topics.add(topic)
        _log_json("ws_subscribe", client_id=client_id, topic=topic)

    async def unsubscribe(self, client_id: str, topic: str) -> None:
        topic = _ensure_topic(topic)
        async with self._lock:
            subs = self._topics.get(topic)
            if subs and client_id in subs:
                subs.discard(client_id)
                if not subs:
                    self._topics.pop(topic, None)
            if client_id in self._clients:
                self._clients[client_id].topics.discard(topic)
        _log_json("ws_unsubscribe", client_id=client_id, topic=topic)

    async def publish(self, topic: str, payload: t.Any, *, sender: str | None = None) -> int:
        topic = _ensure_topic(topic)
        message = json.dumps(
            {
                "id": _uuid(),
                "type": "message",
                "topic": topic,
                "payload": payload,
                "ts": _ts(),
                "correlation_id": get_correlation_id(),
                "sender": sender,
            },
            ensure_ascii=False,
        )
        count = 0
        async with self._lock:
            subs = set(self._topics.get(topic, set()))
        for cid in subs:
            client = self._clients.get(cid)
            if not client:
                continue
            try:
                client.send_q.put_nowait(message)
                count += 1
            except asyncio.QueueFull:
                # Backpressure policy: drop message for that client
                _log_json("ws_backpressure_drop", client_id=cid, topic=topic)
        return count

    async def shutdown(self) -> None:
        self._shutdown.set()
        async with self._lock:
            clients = list(self._clients.values())
        for c in clients:
            try:
                await c.ws.close(code=1001)
            except Exception:
                pass

manager = ConnectionManager()

# ------------------------------ Endpoint ------------------------------

class WsServer(WebSocketEndpoint):
    encoding = "text"  # we'll do our own JSON validation

    async def on_connect(self, websocket: WebSocket) -> None:
        headers = {k.decode().lower(): v.decode() for k, v in websocket.scope.get("headers", [])}
        corr = headers.get("x-correlation-id") or headers.get("x-request-id") or _uuid()
        set_correlation_id(corr)

        token = _extract_token(headers)
        if not token:
            await websocket.close(code=4401)  # 4401 Unauthorized (custom)
            _log_json("ws_reject_noauth")
            return
        try:
            principal = verify_bearer_token(token)
        except Exception:
            await websocket.close(code=4401)
            _log_json("ws_reject_badauth")
            return

        await websocket.accept(headers=[(b"x-correlation-id", corr.encode())])

        client = Client(
            id=_uuid(),
            principal=principal,
            ws=websocket,
            send_q=asyncio.Queue(maxsize=SEND_QUEUE_SIZE),
            last_seen=time.time(),
            topics=set(),
            limiter=RateLimiter(RATE_LIMIT_CAPACITY, RATE_LIMIT_REFILL_PER_SEC),
        )
        await manager.register(client)

        # Start background tasks for this connection
        reader = asyncio.create_task(self._reader_loop(client))
        writer = asyncio.create_task(self._writer_loop(client))
        heartbeat = asyncio.create_task(self._heartbeat_loop(client))

        # Wait for connection termination
        try:
            done, pending = await asyncio.wait(
                {reader, writer, heartbeat},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
        finally:
            await manager.unregister(client.id)
            try:
                await websocket.close(code=1000)
            except Exception:
                pass

    async def _reader_loop(self, client: Client) -> None:
        ws = client.ws
        while True:
            try:
                data = await ws.receive_text()
            except WebSocketDisconnect:
                break
            except Exception as e:
                _log_json("ws_receive_error", error=str(e))
                break

            client.last_seen = time.time()

            # Rate limiting
            if not client.limiter.allow():
                await self._send_nack(client, "rate_limit", "rate limit exceeded", status=429)
                continue

            try:
                msg = _safe_json_loads(data)
            except Exception as e:
                await self._send_nack(client, "bad_json", str(e), status=400)
                continue

            mtype = str(msg.get("type", "")).lower()
            mid = str(msg.get("id") or _uuid())
            correlation_id = msg.get("correlation_id")
            if correlation_id:
                set_correlation_id(str(correlation_id))

            try:
                if mtype == "ping":
                    await self._send(client, {"id": mid, "type": "pong"})
                elif mtype == "echo":
                    await self._send(client, {"id": mid, "type": "echo", "payload": msg.get("payload")})
                elif mtype == "subscribe":
                    topic = _ensure_topic(str(msg.get("topic") or ""))
                    await manager.subscribe(client.id, topic)
                    await self._send_ack(client, mid, "subscribed", {"topic": topic})
                elif mtype == "unsubscribe":
                    topic = _ensure_topic(str(msg.get("topic") or ""))
                    await manager.unsubscribe(client.id, topic)
                    await self._send_ack(client, mid, "unsubscribed", {"topic": topic})
                elif mtype == "publish":
                    if not ALLOW_CLIENT_PUBLISH and "admin" not in client.principal.roles:
                        raise PermissionError("publishing not allowed")
                    topic = _ensure_topic(str(msg.get("topic") or ""))
                    published = await manager.publish(topic, msg.get("payload"), sender=client.principal.sub)
                    await self._send_ack(client, mid, "published", {"topic": topic, "delivered": published})
                else:
                    await self._send_nack(client, "bad_type", f"unsupported type: {mtype}", status=400)
            except PermissionError as pe:
                await self._send_nack(client, "forbidden", str(pe), status=403)
            except Exception as e:
                # Do not leak internals
                await self._send_nack(client, "server_error", "internal error", status=500)
                _log_json("ws_handler_error", error=str(e), traceback="".join(traceback.format_exc().splitlines()[-5:]))

    async def _writer_loop(self, client: Client) -> None:
        ws = client.ws
        while True:
            try:
                msg = await client.send_q.get()
            except asyncio.CancelledError:
                break
            try:
                await ws.send_text(msg)
            except Exception as e:
                _log_json("ws_send_error", error=str(e))
                break

    async def _heartbeat_loop(self, client: Client) -> None:
        ws = client.ws
        while True:
            try:
                # Idle timeout
                if time.time() - client.last_seen > IDLE_TIMEOUT_SEC:
                    await ws.close(code=1001)
                    _log_json("ws_idle_close", client_id=client.id)
                    break
                # Server ping (logical, via JSON)
                await self._send(client, {"type": "ping"})
                await asyncio.sleep(HEARTBEAT_INTERVAL_SEC)
            except asyncio.CancelledError:
                break
            except Exception as e:
                _log_json("ws_heartbeat_error", error=str(e))
                break

    # ------------------ Reply helpers ------------------

    async def _send(self, client: Client, obj: dict[str, t.Any]) -> None:
        # Enrich with server metadata
        obj.setdefault("id", _uuid())
        obj.setdefault("ts", _ts())
        if get_correlation_id():
            obj.setdefault("correlation_id", get_correlation_id())
        data = json.dumps(obj, ensure_ascii=False)
        try:
            client.send_q.put_nowait(data)
        except asyncio.QueueFull:
            # Backpressure policy: close connection to protect server
            _log_json("ws_queue_full_close", client_id=client.id)
            await client.ws.close(code=1013)  # Try again later
            raise

    async def _send_ack(self, client: Client, mid: str, msg: str, extra: dict[str, t.Any] | None = None) -> None:
        payload = {"id": mid, "type": "ack", "message": msg}
        if extra:
            payload.update(extra)
        await self._send(client, payload)

    async def _send_nack(self, client: Client, code: str, detail: str, *, status: int) -> None:
        await self._send(
            client,
            {
                "type": "nack",
                "error": {
                    "code": code,
                    "detail": detail,
                    "status": status,
                },
            },
        )

# ------------------------------ Application Factory ------------------------------

def create_app() -> Starlette:
    routes = [WebSocketRoute(WS_PATH, WsServer)]
    app = Starlette(routes=routes, on_startup=[_on_startup], on_shutdown=[_on_shutdown])
    return app

async def _on_startup() -> None:
    _log_json("ws_startup", path=WS_PATH)

async def _on_shutdown() -> None:
    await manager.shutdown()
    _log_json("ws_shutdown")

# ------------------------------ Entrypoint ------------------------------

if __name__ == "__main__":
    # Optional: run with uvicorn if present
    app = create_app()
    try:
        import uvicorn  # type: ignore
    except Exception:
        print("Install uvicorn to run: pip install uvicorn[standard]")
        sys.exit(2)

    host = os.getenv("WS_HOST", "0.0.0.0")
    port = int(os.getenv("WS_PORT", "8081"))

    # Graceful signals for local run
    def _handle_sigterm(signo, frame):
        try:
            loop = asyncio.get_event_loop()
            loop.create_task(_on_shutdown())
        except Exception:
            pass

    signal.signal(signal.SIGTERM, _handle_sigterm)  # type: ignore[arg-type]
    signal.signal(signal.SIGINT, _handle_sigterm)   # type: ignore[arg-type]

    uvicorn.run(app, host=host, port=port, log_level="info")
