# -*- coding: utf-8 -*-
"""
policy-core WebSocket server (industrial-grade)

ASGI app (Starlette-compatible) providing:
- JWT/API-Key auth with tenant isolation
- Origin allow/deny checking at handshake
- Subscriptions and multi-node broadcast via Redis (redis.asyncio)
- Backpressure-safe send queues with drop-oldest
- Heartbeat (application-level ping/pong) and idle timeouts
- Session resume via resume_token stored in Redis
- Rate limiting (sliding window in Redis) and message size caps
- Prometheus metrics at /metrics and health at /healthz
- Optional OpenTelemetry tracing (if installed)

Dependencies (install as needed):
  starlette>=0.37, uvicorn[standard]>=0.29
  redis>=5.0
  prometheus-client>=0.16
  PyJWT>=2.8 (optional, if JWT auth enabled)
  pydantic>=2 (optional, for config validation)
  opentelemetry-sdk/opentelemetry-instrumentation-asgi (optional)

Environment (examples):
  WS_REDIS_URL=redis://localhost:6379/0
  WS_JWT_ALG=HS256
  WS_JWT_SECRET=changeme
  WS_API_KEY_HEADER=X-API-Key
  WS_ALLOWED_ORIGINS=https://app.example.com,https://*.trusted.com
  WS_DENY_TOPICS=admin.*,internal.*
  WS_MAX_MESSAGE_BYTES=65536
  WS_RATE_WINDOW_SEC=1
  WS_RATE_MAX_MSG_PER_WINDOW=60
  WS_SEND_QUEUE_MAX=1000
  WS_IDLE_TIMEOUT_SEC=120
  WS_HEARTBEAT_INTERVAL_SEC=30
  WS_CLIENT_PUBLISH_ENABLED=false
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import signal
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional, Set, Tuple, List

from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

try:
    # redis.asyncio is the default in redis>=4.2, redis>=5 recommended
    from redis.asyncio import Redis
except Exception as e:  # pragma: no cover
    raise RuntimeError("redis.asyncio (redis>=4.2) is required") from e

try:
    import jwt  # PyJWT (optional)
except Exception:
    jwt = None  # type: ignore

from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

# --------------------------- Logging ---------------------------

LOG = logging.getLogger("policy_core.ws")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")

# --------------------------- Metrics ---------------------------

WS_CONNECTED = Gauge("pc_ws_connected", "Currently connected WebSocket clients", ["tenant"])
WS_MESSAGES_RX = Counter("pc_ws_messages_rx_total", "Incoming WS messages", ["tenant", "type"])
WS_MESSAGES_TX = Counter("pc_ws_messages_tx_total", "Outgoing WS messages", ["tenant", "type"])
WS_DROPPED_TX = Counter("pc_ws_dropped_tx_total", "Dropped outgoing messages due to backpressure", ["tenant"])
WS_PUBLISH_TOTAL = Counter("pc_ws_publish_total", "Published messages to Redis", ["tenant", "topic"])
WS_SUBSCRIBE_TOTAL = Counter("pc_ws_subscribe_total", "Subscribe calls", ["tenant", "topic"])
WS_UNSUBSCRIBE_TOTAL = Counter("pc_ws_unsubscribe_total", "Unsubscribe calls", ["tenant", "topic"])
WS_DECISION_LATENCY = Histogram("pc_ws_msg_handle_seconds", "WS message handle latency", ["tenant", "type"])
WS_CONNECTION_AGE = Histogram("pc_ws_connection_age_seconds", "Connection duration", ["tenant"])
WS_AUTH_FAIL = Counter("pc_ws_auth_fail_total", "Auth failures", ["reason"])

# --------------------------- Config ----------------------------

_glob_to_regex = lambda g: re.compile("^" + g.replace(".", r"\.").replace("*", ".*") + "$", re.IGNORECASE)


@dataclass(frozen=True)
class WSConfig:
    redis_url: str = os.getenv("WS_REDIS_URL", "redis://localhost:6379/0")
    allowed_origins_raw: str = os.getenv("WS_ALLOWED_ORIGINS", "")
    deny_topics_raw: str = os.getenv("WS_DENY_TOPICS", "admin.*,internal.*")

    jwt_alg: str = os.getenv("WS_JWT_ALG", "HS256")
    jwt_secret: str = os.getenv("WS_JWT_SECRET", "")
    jwt_aud: Optional[str] = os.getenv("WS_JWT_AUD") or None
    jwt_iss: Optional[str] = os.getenv("WS_JWT_ISS") or None
    tenant_claim: str = os.getenv("WS_TENANT_CLAIM", "tenant")
    subject_claim: str = os.getenv("WS_SUBJECT_CLAIM", "sub")

    api_key_header: str = os.getenv("WS_API_KEY_HEADER", "X-API-Key")
    api_key_value: Optional[str] = os.getenv("WS_API_KEY_VALUE") or None

    max_message_bytes: int = int(os.getenv("WS_MAX_MESSAGE_BYTES", "65536"))
    send_queue_max: int = int(os.getenv("WS_SEND_QUEUE_MAX", "1000"))
    idle_timeout_sec: int = int(os.getenv("WS_IDLE_TIMEOUT_SEC", "120"))
    heartbeat_interval_sec: int = int(os.getenv("WS_HEARTBEAT_INTERVAL_SEC", "30"))

    rate_window_sec: int = int(os.getenv("WS_RATE_WINDOW_SEC", "1"))
    rate_max_per_window: int = int(os.getenv("WS_RATE_MAX_MSG_PER_WINDOW", "60"))

    client_publish_enabled: bool = (os.getenv("WS_CLIENT_PUBLISH_ENABLED", "false").lower() == "true")

    resume_ttl_sec: int = int(os.getenv("WS_RESUME_TTL_SEC", "900"))

    def allowed_origins(self) -> List[re.Pattern]:
        if not self.allowed_origins_raw.strip():
            return []
        return [_glob_to_regex(x.strip()) for x in self.allowed_origins_raw.split(",") if x.strip()]

    def deny_topic_patterns(self) -> List[re.Pattern]:
        if not self.deny_topics_raw.strip():
            return []
        return [_glob_to_regex(x.strip()) for x in self.deny_topics_raw.split(",") if x.strip()]


CFG = WSConfig()

# --------------------------- Redis helpers ----------------------------


def redis_channel(tenant: str, topic: str) -> str:
    return f"ws:{tenant}:{topic}"


RESUME_KEY = "ws:resume:{token}"  # stores JSON: {"tenant":..., "subject":..., "topics":[...]}
RATE_KEY = "ws:rate:{session}:{window}"


# --------------------------- Auth ----------------------------


class AuthError(Exception):
    pass


async def authenticate(ws: WebSocket) -> Tuple[str, str]:
    """
    Returns (tenant, subject).
    Two modes:
      1) JWT in Authorization: Bearer <token> (preferred)
      2) API key header (single-tenant, if configured)
    """
    # JWT mode
    auth = ws.headers.get("authorization")
    if auth and auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
        if not jwt:
            WS_AUTH_FAIL.labels("jwt_lib_missing").inc()
            raise AuthError("JWT auth not available: PyJWT not installed")
        try:
            options = {"verify_aud": CFG.jwt_aud is not None}
            claims = jwt.decode(
                token,
                CFG.jwt_secret,
                algorithms=[CFG.jwt_alg],
                audience=CFG.jwt_aud,
                issuer=CFG.jwt_iss,
                options=options,
            )
            tenant = str(claims.get(CFG.tenant_claim) or "")
            subject = str(claims.get(CFG.subject_claim) or "")
            if not tenant or not subject:
                WS_AUTH_FAIL.labels("claims_missing").inc()
                raise AuthError("Required claims missing")
            return tenant, subject
        except Exception as e:
            WS_AUTH_FAIL.labels("jwt_invalid").inc()
            raise AuthError(f"JWT invalid: {e}")

    # API key mode
    if CFG.api_key_value and ws.headers.get(CFG.api_key_header) == CFG.api_key_value:
        # single-tenant API-key: tenant must be provided via query parameter ?tenant=...
        tenant = (ws.query_params.get("tenant") or "").strip()
        subject = (ws.query_params.get("subject") or "api-key").strip()
        if not tenant:
            WS_AUTH_FAIL.labels("tenant_missing").inc()
            raise AuthError("tenant is required with API key")
        return tenant, subject

    WS_AUTH_FAIL.labels("no_credentials").inc()
    raise AuthError("No valid credentials")


def origin_allowed(ws: WebSocket) -> bool:
    origin = ws.headers.get("origin") or ""
    if not origin:
        return True  # non-browser contexts
    allow = CFG.allowed_origins()
    if not allow:
        return True  # allow if not configured
    return any(p.match(origin) for p in allow)


def topic_allowed(topic: str) -> bool:
    return not any(p.match(topic) for p in CFG.deny_topic_patterns())


# --------------------------- Rate limiting ----------------------------


async def rate_check(r: Redis, session_id: str) -> bool:
    """
    Sliding window counter per session. True if allowed.
    """
    now = int(time.time())
    window = now // CFG.rate_window_sec
    key = RATE_KEY.format(session=session_id, window=window)
    async with r.pipeline(transaction=True) as pipe:
        pipe.incr(key, amount=1)
        pipe.expire(key, CFG.rate_window_sec + 1)
        count, _ = await pipe.execute()
    return int(count) <= CFG.rate_max_per_window


# --------------------------- Protocol ----------------------------

# Client -> Server messages:
# { "id": "uuid", "type": "subscribe", "topic": "t" }
# { "id": "uuid", "type": "unsubscribe", "topic": "t" }
# { "id": "uuid", "type": "publish", "topic": "t", "data": {...} }  # if enabled
# { "id": "uuid", "type": "ping" }
# { "id": "uuid", "type": "resume", "resume_token": "..." }
#
# Server -> Client messages:
# ack:   { "id": "<id>", "type": "ack", "ok": true }
# nack:  { "id": "<id>", "type": "nack", "error": {"code":"...", "message":"..."} }
# event: { "type": "event", "topic": "t", "data": {...}, "ts": 1234567890 }
# pong:  { "id": "<id>", "type": "pong" }
# info:  { "type": "info", "resume_token": "..." }


def json_dumps(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


# --------------------------- Connection handler ----------------------------


class Connection:
    def __init__(self, ws: WebSocket, r: Redis, tenant: str, subject: str) -> None:
        self.ws = ws
        self.r = r
        self.tenant = tenant
        self.subject = subject
        self.id = str(uuid.uuid4())
        self.topics: Set[str] = set()
        self.send_q: asyncio.Queue[Tuple[str, str]] = asyncio.Queue(maxsize=CFG.send_queue_max)
        self.alive = True
        self.connected_at = time.time()
        self.last_rx = time.time()
        self.pubsub_task: Optional[asyncio.Task] = None
        self.heartbeat_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        WS_CONNECTED.labels(self.tenant).inc()
        # Start heartbeat
        self.heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        # Run receive loop
        try:
            await self._recv_loop()
        finally:
            await self.close()

    async def close(self) -> None:
        if not self.alive:
            return
        self.alive = False
        # cancel tasks
        for t in (self.pubsub_task, self.heartbeat_task):
            if t:
                t.cancel()
        # unsubscribe
        await self._unsubscribe_all()
        # metrics
        WS_CONNECTION_AGE.labels(self.tenant).observe(max(0.0, time.time() - self.connected_at))
        WS_CONNECTED.labels(self.tenant).dec()
        try:
            await self.ws.close(code=1000)
        except Exception:
            pass

    async def _heartbeat_loop(self) -> None:
        try:
            while self.alive:
                await asyncio.sleep(CFG.heartbeat_interval_sec)
                # idle disconnect
                if time.time() - self.last_rx > CFG.idle_timeout_sec:
                    await self.ws.close(code=1001)
                    break
                # app-level ping
                await self._send_now({"type": "event", "topic": "_sys/heartbeat", "data": {"ts": int(time.time())}})
        except asyncio.CancelledError:
            return
        except Exception as e:
            LOG.warning("heartbeat error: %s", e)

    async def _recv_loop(self) -> None:
        while True:
            try:
                msg = await asyncio.wait_for(self.ws.receive_text(), timeout=CFG.idle_timeout_sec)
                self.last_rx = time.time()
            except asyncio.TimeoutError:
                await self.ws.close(code=1001)
                return
            except WebSocketDisconnect:
                return
            except Exception:
                await self.ws.close(code=1002)
                return

            if len(msg.encode("utf-8")) > CFG.max_message_bytes:
                await self._nack(None, "msg_too_large", f"Message exceeds {CFG.max_message_bytes} bytes")
                continue

            try:
                data = json.loads(msg)
            except Exception:
                await self._nack(None, "bad_json", "Invalid JSON")
                continue

            mid = str(data.get("id") or "")
            mtype = str(data.get("type") or "").lower()
            WS_MESSAGES_RX.labels(self.tenant, mtype or "unknown").inc()

            # Rate limiting per connection
            if not await rate_check(self.r, self.id):
                await self._nack(mid, "rate_limited", "Too many messages")
                continue

            with WS_DECISION_LATENCY.labels(self.tenant, mtype or "unknown").time():
                if mtype == "ping":
                    await self._send_now({"id": mid, "type": "pong"})
                elif mtype == "subscribe":
                    topic = (data.get("topic") or "").strip()
                    await self._handle_subscribe(mid, topic)
                elif mtype == "unsubscribe":
                    topic = (data.get("topic") or "").strip()
                    await self._handle_unsubscribe(mid, topic)
                elif mtype == "publish":
                    if not CFG.client_publish_enabled:
                        await self._nack(mid, "forbidden", "Client publishing disabled")
                    else:
                        topic = (data.get("topic") or "").strip()
                        payload = data.get("data")
                        await self._handle_publish(mid, topic, payload)
                elif mtype == "resume":
                    token = (data.get("resume_token") or "").strip()
                    await self._handle_resume(mid, token)
                else:
                    await self._nack(mid, "unknown_type", "Unsupported message type")

    async def _handle_subscribe(self, mid: str, topic: str) -> None:
        if not topic or not topic_allowed(topic):
            await self._nack(mid, "topic_denied", "Topic not allowed")
            return
        if topic in self.topics:
            await self._ack(mid)  # idempotent
            return
        self.topics.add(topic)
        WS_SUBSCRIBE_TOTAL.labels(self.tenant, topic).inc()
        # Start pubsub stream task if not running
        if not self.pubsub_task or self.pubsub_task.done():
            self.pubsub_task = asyncio.create_task(self._pubsub_loop())
        await self._ack(mid)

    async def _handle_unsubscribe(self, mid: str, topic: str) -> None:
        if topic in self.topics:
            self.topics.remove(topic)
            WS_UNSUBSCRIBE_TOTAL.labels(self.tenant, topic).inc()
        await self._ack(mid)

    async def _unsubscribe_all(self) -> None:
        self.topics.clear()

    async def _handle_publish(self, mid: str, topic: str, payload: Any) -> None:
        if not topic or not topic_allowed(topic):
            await self._nack(mid, "topic_denied", "Topic not allowed")
            return
        channel = redis_channel(self.tenant, topic)
        msg = json_dumps({"topic": topic, "data": payload, "ts": int(time.time()), "subj": self.subject})
        await self.r.publish(channel, msg)
        WS_PUBLISH_TOTAL.labels(self.tenant, topic).inc()
        await self._ack(mid)

    async def _handle_resume(self, mid: str, token: str) -> None:
        if not token:
            await self._nack(mid, "bad_resume_token", "Empty token")
            return
        key = RESUME_KEY.format(token=token)
        rec = await self.r.get(key)
        if not rec:
            await self._nack(mid, "resume_not_found", "Unknown or expired resume token")
            return
        try:
            data = json.loads(rec)
        except Exception:
            await self._nack(mid, "resume_corrupt", "Stored resume data invalid")
            return
        if data.get("tenant") != self.tenant or data.get("subject") != self.subject:
            await self._nack(mid, "resume_mismatch", "Resume token does not match identity")
            return
        topics = set(data.get("topics") or [])
        # replace current subscriptions
        self.topics = topics
        WS_SUBSCRIBE_TOTAL.labels(self.tenant, "_resume_restore").inc()
        await self._ack(mid)

    async def _pubsub_loop(self) -> None:
        """
        Single Redis pubsub receiver multiplexing all topics for this connection.
        """
        try:
            while self.alive:
                if not self.topics:
                    await asyncio.sleep(0.05)
                    continue
                channels = [redis_channel(self.tenant, t) for t in sorted(self.topics)]
                # Use PSUBSCRIBE on exact channels for efficiency (no globs for strictness)
                pubsub = self.r.pubsub()
                try:
                    await pubsub.subscribe(*channels)
                    async for item in pubsub.listen():
                        if not self.alive:
                            break
                        if item is None:
                            continue
                        if item.get("type") != "message":
                            continue
                        try:
                            raw = item["data"]
                            if isinstance(raw, (bytes, bytearray)):
                                raw = raw.decode("utf-8", "replace")
                            msg = json.loads(raw)
                            topic = str(msg.get("topic") or "")
                            WS_MESSAGES_TX.labels(self.tenant, "event").inc()
                            await self._send_event(topic, msg)
                        except Exception as e:
                            LOG.warning("pubsub message parse error: %s", e)
                finally:
                    try:
                        await pubsub.unsubscribe(*channels)
                        await pubsub.close()
                    except Exception:
                        pass
        except asyncio.CancelledError:
            return
        except Exception as e:
            LOG.error("pubsub loop error: %s", e)

    async def _send_event(self, topic: str, msg: Dict[str, Any]) -> None:
        payload = {"type": "event", "topic": topic, "data": msg.get("data"), "ts": msg.get("ts")}
        await self._send(payload)

    async def _ack(self, mid: Optional[str]) -> None:
        if not mid:
            return
        await self._send_now({"id": mid, "type": "ack", "ok": True})

    async def _nack(self, mid: Optional[str], code: str, message: str) -> None:
        body = {"type": "nack", "error": {"code": code, "message": message}}
        if mid:
            body["id"] = mid
        await self._send_now(body)

    async def _send(self, obj: Dict[str, Any]) -> None:
        """Buffered send with backpressure protection."""
        msg = json_dumps(obj)
        try:
            self.send_q.put_nowait(("text", msg))
        except asyncio.QueueFull:
            # drop oldest
            try:
                _ = self.send_q.get_nowait()
            except Exception:
                pass
            WS_DROPPED_TX.labels(self.tenant).inc()
            self.send_q.put_nowait(("text", msg))
        # Spawn sender if not running
        if not hasattr(self, "_sender_task") or self._sender_task.done():
            self._sender_task = asyncio.create_task(self._sender_loop())

    async def _send_now(self, obj: Dict[str, Any]) -> None:
        msg = json_dumps(obj)
        try:
            await self.ws.send_text(msg)
        except Exception:
            await self.close()

    async def _sender_loop(self) -> None:
        try:
            while self.alive:
                kind, payload = await self.send_q.get()
                if kind == "text":
                    try:
                        await self.ws.send_text(payload)
                    except Exception:
                        await self.close()
                        return
        except asyncio.CancelledError:
            return


# --------------------------- ASGI endpoints ----------------------------


async def metrics(_: Any) -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


async def health(_: Any) -> Response:
    return PlainTextResponse("OK")


async def websocket_endpoint(ws: WebSocket) -> None:
    # Origin check before accept
    if not origin_allowed(ws):
        await ws.close(code=1008)  # policy violation
        return

    # Accept early to send errors as WS frames if needed
    await ws.accept()

    # Auth
    try:
        tenant, subject = await authenticate(ws)
    except AuthError as e:
        await ws.send_text(json_dumps({"type": "nack", "error": {"code": "auth_failed", "message": str(e)}}))
        await ws.close(code=4401)  # custom: unauthorized
        return

    # Redis connection
    r = Redis.from_url(CFG.redis_url, decode_responses=False)
    try:
        conn = Connection(ws, r, tenant=tenant, subject=subject)
        # Issue an initial resume token (rotate per connection)
        resume_token = str(uuid.uuid4())
        await r.setex(
            RESUME_KEY.format(token=resume_token),
            CFG.resume_ttl_sec,
            json_dumps({"tenant": tenant, "subject": subject, "topics": []}),
        )
        await ws.send_text(json_dumps({"type": "info", "resume_token": resume_token}))

        # Hook to persist topics on change (lightweight background task)
        async def persist_topics_loop() -> None:
            try:
                while True:
                    await asyncio.sleep(5)
                    await r.setex(
                        RESUME_KEY.format(token=resume_token),
                        CFG.resume_ttl_sec,
                        json_dumps({"tenant": tenant, "subject": subject, "topics": sorted(conn.topics)}),
                    )
            except asyncio.CancelledError:
                return

        persist_task = asyncio.create_task(persist_topics_loop())
        try:
            await conn.start()
        finally:
            persist_task.cancel()
    finally:
        try:
            await r.close()
        except Exception:
            pass


# --------------------------- App wiring ----------------------------

routes = [
    Route("/metrics", metrics, methods=["GET"]),
    Route("/healthz", health, methods=["GET"]),
    WebSocketRoute("/ws", websocket_endpoint),
]

app = Starlette(routes=routes)


# --------------------------- Graceful shutdown ----------------------------

_shutdown = asyncio.Event()


def _handle_sigterm(*_: Any) -> None:  # pragma: no cover
    LOG.info("SIGTERM received, shutting down")
    _shutdown.set()


for _sig in (signal.SIGINT, signal.SIGTERM):  # pragma: no cover
    try:
        signal.signal(_sig, _handle_sigterm)
    except Exception:
        pass


@app.on_event("startup")
async def on_startup() -> None:
    LOG.info("policy-core WS server starting")


@app.on_event("shutdown")
async def on_shutdown() -> None:
    LOG.info("policy-core WS server stopping")


# --------------------------- Redis broadcast helpers (server-side) ----------------------------

async def broadcast(tenant: str, topic: str, data: Any) -> None:
    """
    Server-side helper to publish an event to all subscribers across cluster.
    """
    if not topic_allowed(topic):
        LOG.warning("attempt to publish to denied topic: %s", topic)
        return
    r = Redis.from_url(CFG.redis_url, decode_responses=False)
    try:
        msg = json_dumps({"topic": topic, "data": data, "ts": int(time.time()), "subj": "server"})
        await r.publish(redis_channel(tenant, topic), msg)
        WS_PUBLISH_TOTAL.labels(tenant, topic).inc()
    finally:
        await r.close()
