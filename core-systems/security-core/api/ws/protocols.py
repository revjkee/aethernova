# security-core/api/ws/protocols.py
# Copyright (c) Aethernova.
# SPDX-License-Identifier: Apache-2.0
#
# Industrial-grade WebSocket protocol helpers for security-core.
# - Subprotocol negotiation (sec-core.v1.json / sec-core.v1.msgpack)
# - Origin allow-list, auth (bearer token + optional HMAC), anti-replay (nonce + TTL)
# - JSON (default) and MsgPack (optional) serialization with stable envelope
# - Heartbeats (server ping) and liveness timeout, robust close codes
# - Token-bucket rate limiting (inbound)
# - Backpressure-safe send queue with bounded size
# - Structured errors with request_id and audit-friendly logging hooks

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
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Literal, Optional, Protocol, Tuple, Union

try:
    import msgpack  # optional
except Exception:  # pragma: no cover
    msgpack = None  # type: ignore

from starlette.websockets import WebSocket, WebSocketDisconnect

logger = logging.getLogger("security_core.ws")

# ------------------------------ Constants ------------------------------

SUBPROTO_JSON = "sec-core.v1.json"
SUBPROTO_MSGP = "sec-core.v1.msgpack"

# RFC6455 close codes + operational
WS_CLOSE_NORMAL = 1000
WS_CLOSE_GOING_AWAY = 1001
WS_CLOSE_PROTOCOL_ERROR = 1002
WS_CLOSE_UNSUPPORTED = 1003
WS_CLOSE_POLICY_VIOLATION = 1008
WS_CLOSE_MESSAGE_TOO_BIG = 1009
WS_CLOSE_MANDATORY_EXT = 1010
WS_CLOSE_INTERNAL_ERROR = 1011
WS_CLOSE_SERVICE_RESTART = 1012
WS_CLOSE_TRY_AGAIN = 1013
WS_CLOSE_BAD_GATEWAY = 1014

# ------------------------------ Types & envelopes ------------------------------

EnvelopeType = Literal["auth", "ack", "event", "error", "ping", "pong", "close"]

@dataclass(slots=True)
class Envelope:
    type: EnvelopeType
    id: str
    ts: int  # epoch ms
    # payload semantics:
    #  - "auth": {"token":"...", "nonce":"...", "ts":ms, "sig":"base64(hmac-sha256(token|nonce|ts))"} (optional sig)
    #  - "event": {"name":"...", "data":{...}}
    #  - "ack": {"ref":"<id>"}
    #  - "error": {"code": "string", "message":"...", "ref": "<id_optional>"}
    #  - "ping"/"pong": {"data":"optional"}
    #  - "close": {"code": int, "reason": "string"}
    payload: Dict[str, Any] = field(default_factory=dict)
    trace: Dict[str, Any] = field(default_factory=dict)  # {"request_id": "...", "...": ...}

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

# ------------------------------ Serialization ------------------------------

class Serializer(Protocol):
    content_type: str
    subprotocol: str

    def dumps(self, obj: Dict[str, Any]) -> bytes: ...
    def loads(self, data: Union[str, bytes]) -> Dict[str, Any]: ...

class JSONSerializer:
    content_type = "application/json"
    subprotocol = SUBPROTO_JSON

    def dumps(self, obj: Dict[str, Any]) -> bytes:
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def loads(self, data: Union[str, bytes]) -> Dict[str, Any]:
        if isinstance(data, bytes):
            return json.loads(data.decode("utf-8"))
        return json.loads(data)

class MsgPackSerializer:
    content_type = "application/msgpack"
    subprotocol = SUBPROTO_MSGP

    def dumps(self, obj: Dict[str, Any]) -> bytes:
        if not msgpack:
            raise RuntimeError("msgpack is not available")
        return msgpack.packb(obj, use_bin_type=True)

    def loads(self, data: Union[str, bytes]) -> Dict[str, Any]:
        if not msgpack:
            raise RuntimeError("msgpack is not available")
        if isinstance(data, str):
            data = data.encode("utf-8")
        return msgpack.unpackb(data, raw=False)

# ------------------------------ Security helpers ------------------------------

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s, validate=True)

def hmac_ok(secret: bytes, token: str, nonce: str, ts_ms: int, signature_b64: str) -> bool:
    mac = hmac.new(secret, digestmod=hashlib.sha256)
    mac.update(token.encode("utf-8"))
    mac.update(b"|")
    mac.update(nonce.encode("utf-8"))
    mac.update(b"|")
    mac.update(str(ts_ms).encode("ascii"))
    try:
        sig = b64d(signature_b64)
    except Exception:
        return False
    return hmac.compare_digest(mac.digest(), sig)

# ------------------------------ Rate limiter ------------------------------

class TokenBucket:
    __slots__ = ("_capacity", "_tokens", "_refill_rate", "_last")

    def __init__(self, capacity: int, refill_per_sec: float) -> None:
        self._capacity = capacity
        self._tokens = float(capacity)
        self._refill_rate = float(refill_per_sec)
        self._last = time.monotonic()

    def allow(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        delta = now - self._last
        self._last = now
        self._tokens = min(self._capacity, self._tokens + delta * self._refill_rate)
        if self._tokens >= cost:
            self._tokens -= cost
            return True
        return False

# ------------------------------ Config & Auth ------------------------------

@dataclass(slots=True)
class WSAuthResult:
    subject_id: str
    scopes: List[str] = field(default_factory=list)
    tenant_id: Optional[str] = None
    project_id: Optional[str] = None
    # raw token (if needed downstream)
    token: Optional[str] = None

AuthCallback = Callable[[str], Awaitable[Optional[WSAuthResult]]]

@dataclass(slots=True)
class WSConfig:
    # security
    allowed_origins: List[str] = field(default_factory=list)  # exact match; empty => allow all
    require_auth: bool = True
    shared_hmac_secret_b64: Optional[str] = None  # if set, require sig in auth payload
    replay_window_sec: int = 120  # nonce TTL for anti-replay
    # protocol
    supported_subprotocols: List[str] = field(default_factory=lambda: [SUBPROTO_JSON, SUBPROTO_MSGP])
    prefer_msgpack: bool = False
    # limits
    max_message_bytes: int = 256 * 1024
    send_queue_max: int = 1000
    heartbeat_interval_sec: int = 20
    liveness_timeout_sec: int = 60
    # rate limit (inbound events)
    rl_capacity: int = 60
    rl_refill_per_sec: float = 20.0
    # logging/telemetry hooks
    on_event: Optional[Callable[[Envelope, WSAuthResult], None]] = None
    on_error: Optional[Callable[[Dict[str, Any]], None]] = None

# ------------------------------ Replay cache ------------------------------

class NonceCache:
    """Simple in-memory nonce store with TTL."""
    def __init__(self) -> None:
        self._cache: Dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def add_if_new(self, nonce: str, ttl_sec: int) -> bool:
        now = time.time()
        exp = now + ttl_sec
        async with self._lock:
            # purge some old entries opportunistically
            if len(self._cache) > 50000:  # pragmatic bound
                cutoff = now - 5
                for k, v in list(self._cache.items())[:10000]:
                    if v < cutoff:
                        self._cache.pop(k, None)
            if nonce in self._cache and self._cache[nonce] > now:
                return False
            self._cache[nonce] = exp
            return True

_NONCE_CACHE = NonceCache()

# ------------------------------ Session ------------------------------

class WSSession:
    """Backpressure-safe WebSocket session with negotiated subprotocol and heartbeat management."""

    def __init__(
        self,
        ws: WebSocket,
        cfg: WSConfig,
        auth_cb: Optional[AuthCallback] = None,
    ) -> None:
        self.ws = ws
        self.cfg = cfg
        self.auth_cb = auth_cb
        self.serializer: Serializer = JSONSerializer()
        self.subprotocol: str = SUBPROTO_JSON
        self.auth: Optional[WSAuthResult] = None
        self._send_q: asyncio.Queue[Envelope] = asyncio.Queue(maxsize=cfg.send_queue_max)
        self._hb_task: Optional[asyncio.Task] = None
        self._send_task: Optional[asyncio.Task] = None
        self._alive = True
        self._last_rx = time.monotonic()
        self._rl = TokenBucket(cfg.rl_capacity, cfg.rl_refill_per_sec)

    # ------------------ Handshake ------------------

    async def handshake(self) -> None:
        origin = self.ws.headers.get("origin")
        if self.cfg.allowed_origins and origin not in self.cfg.allowed_origins:
            await self._close(WS_CLOSE_POLICY_VIOLATION, "Origin not allowed")
            raise WebSocketDisconnect(WS_CLOSE_POLICY_VIOLATION)

        # Subprotocol negotiation
        client_offered = [p.strip() for p in (self.ws.headers.get("sec-websocket-protocol") or "").split(",") if p.strip()]
        selected = self._select_subprotocol(client_offered)
        self.subprotocol = selected
        self.serializer = MsgPackSerializer() if (selected == SUBPROTO_MSGP) else JSONSerializer()

        await self.ws.accept(subprotocol=selected)

        # Expect initial 'auth' envelope from client if auth required
        if self.cfg.require_auth:
            env = await self._recv_envelope()
            if env.type != "auth":
                await self._error_and_close(env, "protocol_error", "Expected 'auth' as first frame", WS_CLOSE_PROTOCOL_ERROR)
                raise WebSocketDisconnect(WS_CLOSE_PROTOCOL_ERROR)
            await self._authenticate(env)

        # Start background tasks
        self._send_task = asyncio.create_task(self._send_loop(), name="ws_send_loop")
        self._hb_task = asyncio.create_task(self._heartbeat_loop(), name="ws_heartbeat")

    def _select_subprotocol(self, offered: List[str]) -> str:
        supported = [p for p in self.cfg.supported_subprotocols if (p != SUBPROTO_MSGP or msgpack is not None)]
        if not offered:
            # If client didn't offer, choose preferred default (server still sets subprotocol for clarity)
            return SUBPROTO_MSGP if (self.cfg.prefer_msgpack and (msgpack is not None) and SUBPROTO_MSGP in supported) else SUBPROTO_JSON
        # Intersection preserving client order
        for p in offered:
            if p in supported:
                return p
        # Fallback to JSON if nothing matched
        return SUBPROTO_JSON

    async def _authenticate(self, env: Envelope) -> None:
        payload = env.payload
        token = str(payload.get("token") or "")
        nonce = str(payload.get("nonce") or "")
        ts_ms = int(payload.get("ts") or 0)
        sig = payload.get("sig")  # optional, required if shared_hmac_secret_b64 set

        # Basic checks
        now_ms = int(time.time() * 1000)
        if not token or not nonce or ts_ms <= 0:
            await self._error_and_close(env, "auth_invalid", "Missing token/nonce/ts", WS_CLOSE_POLICY_VIOLATION)
            raise WebSocketDisconnect(WS_CLOSE_POLICY_VIOLATION)

        # Anti-replay
        if not await _NONCE_CACHE.add_if_new(nonce, self.cfg.replay_window_sec):
            await self._error_and_close(env, "auth_replay", "Nonce already used", WS_CLOSE_POLICY_VIOLATION)
            raise WebSocketDisconnect(WS_CLOSE_POLICY_VIOLATION)

        # Clock skew tolerance: ±replay_window_sec
        skew = abs(now_ms - ts_ms)
        if skew > self.cfg.replay_window_sec * 1000:
            await self._error_and_close(env, "auth_ts_skew", "Timestamp skew too large", WS_CLOSE_POLICY_VIOLATION)
            raise WebSocketDisconnect(WS_CLOSE_POLICY_VIOLATION)

        # HMAC if configured
        if self.cfg.shared_hmac_secret_b64:
            try:
                secret = base64.b64decode(self.cfg.shared_hmac_secret_b64)
            except Exception:
                await self._error_and_close(env, "server_misconfig", "Invalid HMAC secret", WS_CLOSE_INTERNAL_ERROR)
                raise WebSocketDisconnect(WS_CLOSE_INTERNAL_ERROR)
            if not isinstance(sig, str) or not hmac_ok(secret, token, nonce, ts_ms, sig):
                await self._error_and_close(env, "auth_hmac_failed", "Invalid signature", WS_CLOSE_POLICY_VIOLATION)
                raise WebSocketDisconnect(WS_CLOSE_POLICY_VIOLATION)

        if not self.auth_cb:
            # Minimal auth: accept token as subject_id
            self.auth = WSAuthResult(subject_id=token, token=token)
            return

        # App-provided authentication (e.g., lookup session)
        res = await self.auth_cb(token)
        if not res:
            await self._error_and_close(env, "auth_rejected", "Unauthorized", WS_CLOSE_POLICY_VIOLATION)
            raise WebSocketDisconnect(WS_CLOSE_POLICY_VIOLATION)
        self.auth = res

        # Emit ACK for successful auth
        await self.send(Envelope(type="ack", id=str(uuid.uuid4()), ts=now_ms, payload={"ref": env.id}, trace=env.trace))

    # ------------------ Receive/Send primitives ------------------

    async def recv(self, *, expect_type: Optional[EnvelopeType] = None) -> Envelope:
        env = await self._recv_envelope()
        if expect_type and env.type != expect_type:
            await self._error_and_close(env, "protocol_error", f"Expected '{expect_type}' frame", WS_CLOSE_PROTOCOL_ERROR)
            raise WebSocketDisconnect(WS_CLOSE_PROTOCOL_ERROR)
        return env

    async def _recv_envelope(self) -> Envelope:
        try:
            if self.subprotocol == SUBPROTO_JSON:
                raw = await self.ws.receive_text()
                obj = self.serializer.loads(raw)  # type: ignore[arg-type]
            else:
                raw = await self.ws.receive_bytes()
                if len(raw) > self.cfg.max_message_bytes:
                    await self._close(WS_CLOSE_MESSAGE_TOO_BIG, "Message too big")
                    raise WebSocketDisconnect(WS_CLOSE_MESSAGE_TOO_BIG)
                obj = self.serializer.loads(raw)
        except WebSocketDisconnect:
            raise
        except Exception as e:
            logger.warning("WS receive parse error: %s", e)
            await self._close(WS_CLOSE_PROTOCOL_ERROR, "Invalid frame")
            raise WebSocketDisconnect(WS_CLOSE_PROTOCOL_ERROR)

        self._last_rx = time.monotonic()
        env = self._coerce_envelope(obj)

        # Rate limiting on inbound events
        if env.type == "event" and not self._rl.allow():
            await self.send_error("rate_limited", "Too many events", ref=env.id)
            return await self._recv_envelope()  # drop & continue

        return env

    def _coerce_envelope(self, obj: Dict[str, Any]) -> Envelope:
        try:
            etype = obj["type"]
            eid = obj.get("id") or str(uuid.uuid4())
            ets = int(obj.get("ts") or int(time.time() * 1000))
            payload = obj.get("payload") or {}
            trace = obj.get("trace") or {}
            if not isinstance(payload, dict) or not isinstance(trace, dict):
                raise ValueError("payload/trace must be objects")
            return Envelope(type=etype, id=eid, ts=ets, payload=payload, trace=trace)
        except Exception as e:
            logger.debug("Envelope coerce failed: %s ; obj=%r", e, obj)
            return Envelope(type="error", id=str(uuid.uuid4()), ts=int(time.time() * 1000),
                            payload={"code": "bad_envelope", "message": "Malformed envelope"}, trace={})

    async def send(self, env: Envelope) -> None:
        if not self._alive:
            return
        try:
            self._send_q.put_nowait(env)
        except asyncio.QueueFull:
            logger.error("WS backpressure: send queue full; closing")
            await self._close(WS_CLOSE_TRY_AGAIN, "Send queue overflow")
            raise WebSocketDisconnect(WS_CLOSE_TRY_AGAIN)

    async def _send_loop(self) -> None:
        try:
            while self._alive:
                env = await self._send_q.get()
                try:
                    data = self.serializer.dumps(env.to_dict())
                    if self.subprotocol == SUBPROTO_JSON:
                        await self.ws.send_text(data.decode("utf-8"))
                    else:
                        await self.ws.send_bytes(data)
                except Exception as e:
                    logger.warning("WS send error: %s", e)
                    await self._close(WS_CLOSE_INTERNAL_ERROR, "Send failed")
                    break
        except asyncio.CancelledError:
            pass

    # ------------------ Heartbeat ------------------

    async def _heartbeat_loop(self) -> None:
        try:
            while self._alive:
                await asyncio.sleep(self.cfg.heartbeat_interval_sec)
                # server ping with random data
                ping = Envelope(
                    type="ping",
                    id=str(uuid.uuid4()),
                    ts=int(time.time() * 1000),
                    payload={"data": os.urandom(8).hex()},
                )
                try:
                    await self.send(ping)
                except WebSocketDisconnect:
                    break
                # liveness check
                if time.monotonic() - self._last_rx > self.cfg.liveness_timeout_sec:
                    logger.info("WS liveness timeout; closing")
                    await self._close(WS_CLOSE_GOING_AWAY, "Liveness timeout")
                    break
        except asyncio.CancelledError:
            pass

    # ------------------ Convenience API ------------------

    async def send_event(self, name: str, data: Dict[str, Any], *, request_id: Optional[str] = None) -> str:
        eid = str(uuid.uuid4())
        env = Envelope(
            type="event",
            id=eid,
            ts=int(time.time() * 1000),
            payload={"name": name, "data": data},
            trace={"request_id": request_id} if request_id else {},
        )
        await self.send(env)
        return eid

    async def send_ack(self, ref: str) -> None:
        await self.send(Envelope(type="ack", id=str(uuid.uuid4()), ts=int(time.time() * 1000), payload={"ref": ref}))

    async def send_error(self, code: str, message: str, *, ref: Optional[str] = None, request_id: Optional[str] = None) -> None:
        payload = {"code": code, "message": message}
        if ref:
            payload["ref"] = ref
        env = Envelope(type="error", id=str(uuid.uuid4()), ts=int(time.time() * 1000), payload=payload,
                       trace={"request_id": request_id} if request_id else {})
        await self.send(env)
        if self.cfg.on_error:
            try:
                self.cfg.on_error({"code": code, "message": message, "ref": ref, "request_id": request_id})
            except Exception:
                pass

    async def _error_and_close(self, env: Envelope, code: str, message: str, close_code: int) -> None:
        await self.send_error(code, message, ref=env.id, request_id=env.trace.get("request_id"))
        await self._close(close_code, message)

    async def _close(self, code: int, reason: str) -> None:
        if not self._alive:
            return
        self._alive = False
        try:
            await self.ws.close(code=code)
        except Exception:
            pass
        for t in (self._hb_task, self._send_task):
            if t and not t.done():
                t.cancel()

# ------------------------------ Helpers for routers ------------------------------

async def negotiate_and_handshake(
    websocket: WebSocket,
    cfg: WSConfig,
    auth_cb: Optional[AuthCallback] = None,
) -> WSSession:
    """
    Typical use in FastAPI router:
        @app.websocket("/ws")
        async def ws_endpoint(ws: WebSocket):
            session = await negotiate_and_handshake(ws, WSConfig(allowed_origins=["https://app.example.com"]), auth_cb=resolve_token)
            try:
                while True:
                    env = await session.recv()
                    ...
            except WebSocketDisconnect:
                pass
    """
    sess = WSSession(websocket, cfg, auth_cb=auth_cb)
    await sess.handshake()
    return sess

# ------------------------------ Minimal example callbacks (optional) ------------------------------

async def demo_auth_cb(token: str) -> Optional[WSAuthResult]:  # pragma: no cover
    """
    Example of application-level token resolver. Replace with your implementation.
    """
    # Reject empty or 'invalid'
    if not token or token == "invalid":
        return None
    # In real life: look up session, verify scopes, tenant/project bindings, etc.
    return WSAuthResult(subject_id=f"user:{token}", scopes=["ws.read", "ws.write"], token=token)
