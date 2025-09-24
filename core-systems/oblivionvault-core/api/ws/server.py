from __future__ import annotations

import asyncio
import base64
import fnmatch
import hashlib
import hmac
import json
import logging
import os
import re
import signal
import time
import typing as t
from collections import defaultdict, deque
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Response
from fastapi.responses import PlainTextResponse
from starlette.concurrency import run_in_threadpool
from starlette.websockets import WebSocketState

# --- Pydantic v1/v2 compatibility ------------------------------------------------
try:
    from pydantic import BaseModel, Field, ValidationError, BaseSettings
    from pydantic import validator as field_validator
    PYD_VER = 1
except Exception:  # pragma: no cover
    from pydantic import BaseModel, Field, ValidationError
    from pydantic_settings import BaseSettings  # pydantic v2
    from pydantic import field_validator
    PYD_VER = 2


# ============================= Settings =========================================

def _split_csv(v: str | None) -> list[str]:
    if not v:
        return []
    return [x.strip() for x in v.split(",") if x.strip()]

class WSSettings(BaseSettings):
    # Security
    ws_enabled: bool = Field(default=True, env="WS_ENABLED")
    allowed_origins: list[str] = Field(default_factory=list, env="WS_ALLOWED_ORIGINS")
    allowed_origin_patterns: list[str] = Field(default_factory=list, env="WS_ALLOWED_ORIGIN_PATTERNS")
    allowed_origin_regexes: list[str] = Field(default_factory=list, env="WS_ALLOWED_ORIGIN_REGEXES")
    denylist_origins: list[str] = Field(default_factory=list, env="WS_DENYLIST_ORIGINS")

    allowed_ip_cidrs: list[str] = Field(default_factory=list, env="WS_ALLOWED_IP_CIDRS")  # optional
    denylist_ip_cidrs: list[str] = Field(default_factory=list, env="WS_DENYLIST_IP_CIDRS")

    api_tokens: list[str] = Field(default_factory=list, env="WS_TOKENS")  # Bearer tokens
    hmac_secret: str | None = Field(default=None, env="WS_HMAC_SECRET")   # for X-Signature

    origin_required: bool = Field(default=True, env="WS_ORIGIN_REQUIRED")
    deny_on_missing_auth: bool = Field(default=True, env="WS_DENY_ON_MISSING_AUTH")

    # Limits / Timeouts
    max_msg_bytes: int = Field(default=1_000_000, env="WS_MAX_MSG_BYTES")  # 1 MB
    outbound_queue_size: int = Field(default=1000, env="WS_OUTBOUND_QUEUE_SIZE")
    replay_depth_per_topic: int = Field(default=100, env="WS_REPLAY_DEPTH")
    heartbeat_interval_sec: int = Field(default=20, env="WS_HEARTBEAT_INTERVAL_SEC")
    idle_timeout_sec: int = Field(default=180, env="WS_IDLE_TIMEOUT_SEC")

    # Rate limiting (token bucket)
    rl_conn_rate: int = Field(default=50, env="WS_RL_CONN_RATE")            # tokens per interval per connection
    rl_conn_burst: int = Field(default=100, env="WS_RL_CONN_BURST")
    rl_ip_rate: int = Field(default=200, env="WS_RL_IP_RATE")               # per IP
    rl_ip_burst: int = Field(default=400, env="WS_RL_IP_BURST")
    rl_interval_sec: float = Field(default=1.0, env="WS_RL_INTERVAL_SEC")

    # Misc
    metrics_enabled: bool = Field(default=True, env="WS_METRICS_ENABLED")

    @field_validator("allowed_origins", pre=True)
    def _co1(cls, v):  # type: ignore
        return _split_csv(v) if isinstance(v, str) else v

    @field_validator("allowed_origin_patterns", pre=True)
    def _co2(cls, v):  # type: ignore
        return _split_csv(v) if isinstance(v, str) else v

    @field_validator("allowed_origin_regexes", pre=True)
    def _co3(cls, v):  # type: ignore
        return _split_csv(v) if isinstance(v, str) else v

    @field_validator("denylist_origins", pre=True)
    def _co4(cls, v):  # type: ignore
        return _split_csv(v) if isinstance(v, str) else v

    @field_validator("api_tokens", pre=True)
    def _co5(cls, v):  # type: ignore
        return _split_csv(v) if isinstance(v, str) else v

    @field_validator("allowed_ip_cidrs", pre=True)
    def _co6(cls, v):  # type: ignore
        return _split_csv(v) if isinstance(v, str) else v

    @field_validator("denylist_ip_cidrs", pre=True)
    def _co7(cls, v):  # type: ignore
        return _split_csv(v) if isinstance(v, str) else v

    @classmethod
    def from_env(cls) -> "WSSettings":
        return cls()  # env-aware


# ============================= Logging / Metrics ================================

class JsonLoggerAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        extra = kwargs.pop("extra", {})
        payload = {"msg": msg, **extra}
        return json.dumps(payload, ensure_ascii=False), {}

logger = JsonLoggerAdapter(logging.getLogger("oblivion.ws"), extra={})
logging.basicConfig(level=logging.INFO)

@dataclass
class Metrics:
    conns_current: int = 0
    conns_total: int = 0
    recv_messages_total: int = 0
    sent_messages_total: int = 0
    dropped_outbound_total: int = 0
    rejected_auth_total: int = 0
    rejected_origin_total: int = 0
    rejected_ip_total: int = 0
    rate_limit_drops_total: int = 0

    def to_prometheus(self) -> str:
        lines = [
            "# HELP ov_ws_conns_current Current active WS connections",
            "# TYPE ov_ws_conns_current gauge",
            f"ov_ws_conns_current {self.conns_current}",
            "# HELP ov_ws_conns_total Total WS connections since start",
            "# TYPE ov_ws_conns_total counter",
            f"ov_ws_conns_total {self.conns_total}",
            "# HELP ov_ws_recv_messages_total Total received messages",
            "# TYPE ov_ws_recv_messages_total counter",
            f"ov_ws_recv_messages_total {self.recv_messages_total}",
            "# HELP ov_ws_sent_messages_total Total sent messages",
            "# TYPE ov_ws_sent_messages_total counter",
            f"ov_ws_sent_messages_total {self.sent_messages_total}",
            "# HELP ov_ws_dropped_outbound_total Outbound messages dropped due to backpressure",
            "# TYPE ov_ws_dropped_outbound_total counter",
            f"ov_ws_dropped_outbound_total {self.dropped_outbound_total}",
            "# HELP ov_ws_rejected_auth_total Connections rejected by auth",
            "# TYPE ov_ws_rejected_auth_total counter",
            f"ov_ws_rejected_auth_total {self.rejected_auth_total}",
            "# HELP ov_ws_rejected_origin_total Connections rejected by origin",
            "# TYPE ov_ws_rejected_origin_total counter",
            f"ov_ws_rejected_origin_total {self.rejected_origin_total}",
            "# HELP ov_ws_rejected_ip_total Connections rejected by IP",
            "# TYPE ov_ws_rejected_ip_total counter",
            f"ov_ws_rejected_ip_total {self.rejected_ip_total}",
            "# HELP ov_ws_rate_limit_drops_total Messages dropped by rate limit",
            "# TYPE ov_ws_rate_limit_drops_total counter",
            f"ov_ws_rate_limit_drops_total {self.rate_limit_drops_total}",
        ]
        return "\n".join(lines) + "\n"

metrics = Metrics()


# ============================= Security helpers =================================

@dataclass
class OriginRules:
    exact: set[str]
    patterns: list[str]
    regexes: list[re.Pattern]
    wildcard: bool
    denylist: set[str]

def compile_origin_rules(s: WSSettings) -> OriginRules:
    exact = set(s.allowed_origins)
    wildcard = "*" in exact
    exact.discard("*")
    regexes = [re.compile(rx) for rx in s.allowed_origin_regexes]
    return OriginRules(
        exact=exact,
        patterns=s.allowed_origin_patterns,
        regexes=regexes,
        wildcard=wildcard,
        denylist=set(s.denylist_origins),
    )

def origin_allowed(origin: str | None, rules: OriginRules, origin_required: bool) -> bool:
    if not origin:
        return not origin_required
    if origin in rules.denylist:
        return False
    if origin in rules.exact:
        return True
    for p in rules.patterns:
        if fnmatch.fnmatch(origin, p):
            return True
    for r in rules.regexes:
        if r.match(origin):
            return True
    return rules.wildcard

def ip_allowed(peer_ip: str | None, allow_cidrs: list[str], deny_cidrs: list[str]) -> bool:
    if not peer_ip:
        return True
    try:
        ip = ip_address(peer_ip)
    except ValueError:
        return False
    for c in deny_cidrs:
        if ip in ip_network(c, strict=False):
            return False
    if not allow_cidrs:
        return True
    for c in allow_cidrs:
        if ip in ip_network(c, strict=False):
            return True
    return False

def constant_time_compare(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)

def validate_hmac(ts: str | None, sig_b64: str | None, secret: str | None, method: str, path: str) -> bool:
    if not secret:
        return True
    if not ts or not sig_b64:
        return False
    try:
        ts_i = int(ts)
    except ValueError:
        return False
    # Reject old timestamps (>5 min skew)
    if abs(int(time.time()) - ts_i) > 300:
        return False
    msg = f"{method.upper()}|{path}|{ts}".encode()
    mac = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    try:
        provided = base64.b64decode(sig_b64)
    except Exception:
        return False
    return constant_time_compare(mac, provided)

def extract_bearer_token(ws: WebSocket) -> str | None:
    # Header or query param ?token=
    auth = ws.headers.get("authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    token = ws.query_params.get("token")
    return token


# ============================= Rate Limiter =====================================

class TokenBucket:
    __slots__ = ("rate", "burst", "tokens", "last")

    def __init__(self, rate: int, burst: int) -> None:
        self.rate = float(rate)
        self.burst = float(burst)
        self.tokens = float(burst)
        self.last = time.perf_counter()

    def allow(self, cost: float = 1.0) -> bool:
        now = time.perf_counter()
        elapsed = now - self.last
        self.last = now
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False

class RateLimiter:
    def __init__(self, s: WSSettings) -> None:
        self.s = s
        self._by_ip: dict[str, TokenBucket] = defaultdict(lambda: TokenBucket(s.rl_ip_rate, s.rl_ip_burst))

    def allow_conn(self, ip: str | None) -> TokenBucket:
        # Return per-connection bucket as well
        return TokenBucket(self.s.rl_conn_rate, self.s.rl_conn_burst)

    def allow_ip(self, ip: str | None) -> bool:
        if not ip:
            return True
        return self._by_ip[ip].allow()


# ============================= Message Models ===================================

TOPIC_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")

class Msg(BaseModel):
    # Envelope
    type: str = Field(..., description="Message type: subscribe|unsubscribe|publish|ping|echo|ack|error")
    id: str | None = Field(None, description="Client message id for ACK correlation")
    topic: str | None = Field(None, description="Topic for pub/sub")
    payload: dict | None = Field(default=None, description="Arbitrary JSON payload")

    @field_validator("type")
    def _vt(cls, v):  # type: ignore
        allowed = {"subscribe", "unsubscribe", "publish", "ping", "echo", "ack"}
        if v not in allowed:
            raise ValueError(f"type must be one of {sorted(allowed)}")
        return v

    @field_validator("topic")
    def _vtopic(cls, v):  # type: ignore
        if v is None:
            return v
        if not TOPIC_RE.match(v):
            raise ValueError("invalid topic format")
        return v


# ============================= Pub/Sub Manager ==================================

@dataclass
class Client:
    ws: WebSocket
    ip: str | None
    origin: str | None
    conn_bucket: TokenBucket
    outbound: asyncio.Queue[bytes]
    last_activity: float = field(default_factory=lambda: time.time())
    subs: set[str] = field(default_factory=set)
    request_id: str | None = None

class PubSub:
    def __init__(self, s: WSSettings) -> None:
        self.s = s
        self.topics: dict[str, set[Client]] = defaultdict(set)
        self.replay: dict[str, deque[bytes]] = defaultdict(lambda: deque(maxlen=self.s.replay_depth_per_topic))
        self._lock = asyncio.Lock()

    async def subscribe(self, client: Client, topic: str, replay: bool = True) -> None:
        async with self._lock:
            self.topics[topic].add(client)
        client.subs.add(topic)
        if replay:
            # send replay from buffer
            for msg in list(self.replay[topic]):
                await self._safe_send(client, msg)

    async def unsubscribe(self, client: Client, topic: str) -> None:
        async with self._lock:
            self.topics[topic].discard(client)
        client.subs.discard(topic)

    async def publish(self, topic: str, data: dict, msg_id: str | None) -> None:
        payload = {
            "type": "publish",
            "topic": topic,
            "payload": data,
            "id": msg_id,
            "ts": int(time.time() * 1000),
        }
        raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
        # keep in replay
        self.replay[topic].append(raw)
        # fanout
        recipients = list(self.topics.get(topic, ()))
        for client in recipients:
            await self._safe_send(client, raw)

    async def drop_client(self, client: Client) -> None:
        async with self._lock:
            for topic in list(client.subs):
                self.topics[topic].discard(client)

    async def _safe_send(self, client: Client, raw: bytes) -> None:
        try:
            client.outbound.put_nowait(raw)
        except asyncio.QueueFull:
            metrics.dropped_outbound_total += 1
            # Drop oldest to keep the pipe moving
            try:
                _ = client.outbound.get_nowait()
            except asyncio.QueueEmpty:
                pass
            try:
                client.outbound.put_nowait(raw)
            except asyncio.QueueFull:
                # give up silently
                pass


# ============================= Server ===========================================

class WSServer:
    def __init__(self, s: WSSettings) -> None:
        self.s = s
        self.app = FastAPI()
        self.rules = compile_origin_rules(s)
        self.rl = RateLimiter(s)
        self.pubsub = PubSub(s)
        self._shutdown = asyncio.Event()

        if s.metrics_enabled:
            @self.app.get("/metrics")
            async def metrics_endpoint() -> Response:
                return PlainTextResponse(metrics.to_prometheus())

        @self.app.websocket("/ws")
        async def ws_endpoint(websocket: WebSocket):
            await self.handle_ws(websocket)

        @self.app.on_event("shutdown")
        async def on_shutdown():
            self._shutdown.set()

    # --- Auth / Origin / IP checks ------------------------------------------------
    def _auth_ok(self, ws: WebSocket) -> bool:
        tok = extract_bearer_token(ws)
        if self.s.api_tokens and (tok in self.s.api_tokens):
            return True
        if self.s.deny_on_missing_auth:
            return False
        return True

    def _hmac_ok(self, ws: WebSocket) -> bool:
        return validate_hmac(
            ts=ws.headers.get("x-timestamp"),
            sig_b64=ws.headers.get("x-signature"),
            secret=self.s.hmac_secret,
            method="GET",  # WS upgrade handshake is GET /ws
            path=str(ws.url.path),
        )

    async def handle_ws(self, ws: WebSocket) -> None:
        origin = ws.headers.get("origin")
        peer = ws.client.host if ws.client else None

        if not origin_allowed(origin, self.rules, self.s.origin_required):
            metrics.rejected_origin_total += 1
            await ws.close(code=1008)  # policy violation
            return

        if not ip_allowed(peer, self.s.allowed_ip_cidrs, self.s.denylist_ip_cidrs):
            metrics.rejected_ip_total += 1
            await ws.close(code=1008)
            return

        if not self._auth_ok(ws) or not self._hmac_ok(ws):
            metrics.rejected_auth_total += 1
            await ws.close(code=4401)  # custom "unauthorized"
            return

        # Rate limit new connection by IP
        if not self.rl.allow_ip(peer):
            metrics.rate_limit_drops_total += 1
            await ws.close(code=1013)  # try again later
            return

        # Accept and set limits
        await ws.accept(subprotocol="json")
        conn_bucket = self.rl.allow_conn(peer)
        outbound: asyncio.Queue[bytes] = asyncio.Queue(self.s.outbound_queue_size)
        client = Client(ws=ws, ip=peer, origin=origin, conn_bucket=conn_bucket, outbound=outbound, request_id=ws.headers.get("x-request-id"))

        metrics.conns_current += 1
        metrics.conns_total += 1
        logger.info("WS_CONNECTED", extra={"ip": peer, "origin": origin, "rid": client.request_id})

        try:
            await self._session_loop(client)
        finally:
            await self.pubsub.drop_client(client)
            if ws.application_state != WebSocketState.DISCONNECTED:
                with contextlib_suppress():
                    await ws.close(code=1000)
            metrics.conns_current -= 1
            logger.info("WS_DISCONNECTED", extra={"ip": peer, "rid": client.request_id})

    async def _session_loop(self, client: Client) -> None:
        ws = client.ws
        send_task = asyncio.create_task(self._sender(client))
        recv_task = asyncio.create_task(self._receiver(client))
        hb_task = asyncio.create_task(self._heartbeat(client))

        done, pending = await asyncio.wait(
            {send_task, recv_task, hb_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
        for t in done:
            with contextlib_suppress():
                await t

    async def _sender(self, client: Client) -> None:
        while True:
            raw = await client.outbound.get()
            if client.ws.application_state != WebSocketState.CONNECTED:
                break
            await client.ws.send_bytes(raw)
            metrics.sent_messages_total += 1

    async def _receiver(self, client: Client) -> None:
        ws = client.ws
        max_bytes = self.s.max_msg_bytes
        while True:
            try:
                data = await ws.receive_text()
            except WebSocketDisconnect:
                break
            except Exception:
                break

            client.last_activity = time.time()

            if len(data.encode()) > max_bytes:
                await self._send_error(ws, "message_too_large")
                continue

            if not client.conn_bucket.allow():
                metrics.rate_limit_drops_total += 1
                # Deliberately drop without closing; optionally soft warn
                continue

            try:
                msg = Msg.model_validate_json(data) if hasattr(Msg, "model_validate_json") else Msg.parse_raw(data)
            except ValidationError as e:
                await self._send_error(ws, "invalid_message", details=e.errors())
                continue

            metrics.recv_messages_total += 1
            await self._dispatch(client, msg)

    async def _heartbeat(self, client: Client) -> None:
        ws = client.ws
        interval = self.s.heartbeat_interval_sec
        idle_to = self.s.idle_timeout_sec
        while True:
            await asyncio.sleep(interval)
            # idle timeout
            if time.time() - client.last_activity > idle_to:
                with contextlib_suppress():
                    await ws.close(code=1001)  # going away
                break
            # ping as userland message (compatible with JSON client)
            ping = {
                "type": "ping",
                "ts": int(time.time() * 1000),
            }
            raw = json.dumps(ping, separators=(",", ":"), ensure_ascii=False).encode()
            await self.pubsub._safe_send(client, raw)

    async def _dispatch(self, client: Client, msg: Msg) -> None:
        ws = client.ws
        if msg.type == "ping":
            await self._send(ws, {"type": "ack", "id": msg.id, "pong": int(time.time() * 1000)})
            return
        if msg.type == "echo":
            await self._send(ws, {"type": "echo", "id": msg.id, "payload": msg.payload})
            return
        if msg.type == "subscribe":
            if not msg.topic:
                await self._send_error(ws, "topic_required", id=msg.id)
                return
            await self.pubsub.subscribe(client, msg.topic, replay=True)
            await self._send(ws, {"type": "ack", "id": msg.id, "subscribed": msg.topic})
            return
        if msg.type == "unsubscribe":
            if not msg.topic:
                await self._send_error(ws, "topic_required", id=msg.id)
                return
            await self.pubsub.unsubscribe(client, msg.topic)
            await self._send(ws, {"type": "ack", "id": msg.id, "unsubscribed": msg.topic})
            return
        if msg.type == "publish":
            if not msg.topic:
                await self._send_error(ws, "topic_required", id=msg.id)
                return
            await self.pubsub.publish(msg.topic, msg.payload or {}, msg_id=msg.id)
            # optional ack to publisher
            await self._send(ws, {"type": "ack", "id": msg.id, "published": msg.topic})
            return

    async def _send(self, ws: WebSocket, obj: dict) -> None:
        raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode()
        await ws.send_bytes(raw)
        metrics.sent_messages_total += 1

    async def _send_error(self, ws: WebSocket, reason: str, *, id: str | None = None, details: t.Any = None) -> None:
        obj = {"type": "error", "id": id, "reason": reason}
        if details is not None:
            obj["details"] = details
        await self._send(ws, obj)


# ============================= Utilities ========================================

class contextlib_suppress:
    def __init__(self, *exceptions):
        self.exceptions = exceptions or (Exception,)

    def __enter__(self):  # pragma: no cover
        return self

    def __exit__(self, exc_type, exc, tb):  # pragma: no cover
        return exc_type is not None and issubclass(exc_type, self.exceptions)


# ============================= App factory ======================================

def create_app() -> FastAPI:
    settings = WSSettings.from_env()
    server = WSServer(settings)
    return server.app


# ============================= Dev runner (optional) =============================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(create_app(), host="0.0.0.0", port=int(os.getenv("PORT", "8081")))
