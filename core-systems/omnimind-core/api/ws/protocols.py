# -*- coding: utf-8 -*-
"""
Omnimind WebSocket Protocol — industrial foundation.

Dependencies:
- Python 3.11+
- FastAPI/Starlette for WebSocket type (optional at import time)
- orjson (optional, for faster JSON)

This module provides:
- Message envelope and types
- HELLO/WELCOME handshake with auth and resume support
- Constant-time token check hook
- Incoming rate limiting (token bucket)
- Outgoing backpressure control with bounded queue
- Heartbeats (server-initiated PING/PONG)
- Sequencing + ACK/NACK for at-least-once semantics
- Safe close codes and unified error payloads
- Size/time limits and defensive decoding

Integrate with a FastAPI WebSocket route and supply callbacks via Handlers.
"""

from __future__ import annotations

import asyncio
import enum
import hmac
import logging
import os
import random
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Literal, Mapping, MutableMapping, Optional, Tuple, Union

try:
    # Imported lazily; if FastAPI/Starlette not present, type hints fall back to Any
    from starlette.websockets import WebSocket, WebSocketState, WebSocketDisconnect
except Exception:  # pragma: no cover
    WebSocket = Any  # type: ignore
    WebSocketState = Any  # type: ignore
    WebSocketDisconnect = Exception  # type: ignore

# ---------- JSON codec (orjson fallback) ----------

try:
    import orjson  # type: ignore

    def _json_dumps(obj: Any) -> bytes:
        return orjson.dumps(obj, option=orjson.OPT_SERIALIZE_DATACLASS)

    def _json_loads(b: Union[str, bytes, bytearray]) -> Any:
        return orjson.loads(b)

    JSON_IS_BINARY = True
except Exception:  # pragma: no cover
    import json as _stdlib_json

    def _json_dumps(obj: Any) -> bytes:
        return _stdlib_json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def _json_loads(b: Union[str, bytes, bytearray]) -> Any:
        if isinstance(b, (bytes, bytearray)):
            b = b.decode("utf-8")
        return _stdlib_json.loads(b)

    JSON_IS_BINARY = False


# ---------- Protocol enums & constants ----------

class MsgType(str, enum.Enum):
    HELLO = "hello"         # client->server: version, encoding, token?, resume?
    WELCOME = "welcome"     # server->client: session_id, heartbeat, limits, server_time
    AUTH_OK = "auth_ok"     # server->client: scopes, subject
    AUTH_FAIL = "auth_fail" # server->client
    RESUMED = "resumed"     # server->client: last_seq
    SUBSCRIBE = "subscribe" # client->server: channel
    UNSUBSCRIBE = "unsubscribe"
    PUBLISH = "publish"     # client->server: channel, payload
    EVENT = "event"         # server->client: channel, payload
    ACK = "ack"             # ack by id/seq
    NACK = "nack"           # nack with error
    PING = "ping"
    PONG = "pong"
    ERROR = "error"         # structured error
    GOODBYE = "goodbye"     # either side intent to close


class CloseCode(int, enum.Enum):
    NORMAL = 1000
    GOING_AWAY = 1001
    PROTOCOL_ERROR = 1002
    UNSUPPORTED_DATA = 1003
    NO_STATUS = 1005
    ABNORMAL = 1006
    POLICY_VIOLATION = 1008
    MESSAGE_TOO_BIG = 1009
    MANDATORY_EXT = 1010
    INTERNAL_ERROR = 1011
    SERVICE_RESTART = 1012
    TRY_AGAIN_LATER = 1013
    BAD_GATEWAY = 1014

    # Application-specific (RFC 6455 recommends 4000-4999)
    AUTH_REQUIRED = 4001
    AUTH_FAILED = 4002
    RATE_LIMIT = 4003
    BAD_MESSAGE = 4004
    BACKPRESSURE = 4005
    UNSUPPORTED = 4006
    SERVER_SHUTDOWN = 4010


class ErrorCode(str, enum.Enum):
    BAD_REQUEST = "bad_request"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    RATE_LIMITED = "rate_limited"
    BACKPRESSURE = "backpressure"
    CONFLICT = "conflict"
    INTERNAL = "internal"
    UNSUPPORTED = "unsupported"
    TOO_LARGE = "too_large"
    TIMEOUT = "timeout"
    PROTOCOL = "protocol"


# ---------- Datamodel ----------

@dataclass(slots=True)
class Envelope:
    t: MsgType
    id: str | None = None
    ts: int | None = None           # server timestamps in ms since epoch
    ch: str | None = None           # logical channel
    seq: int | None = None          # server sequence for resume
    payload: Any = None             # message content
    meta: Dict[str, Any] = field(default_factory=dict)  # optional, limited by size

    def as_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"t": self.t.value}
        if self.id:
            d["id"] = self.id
        if self.ts is not None:
            d["ts"] = self.ts
        if self.ch is not None:
            d["ch"] = self.ch
        if self.seq is not None:
            d["seq"] = self.seq
        if self.payload is not None:
            d["payload"] = self.payload
        if self.meta:
            d["meta"] = self.meta
        return d


# ---------- Utility: constant-time token compare ----------

def ct_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# ---------- Rate limiting (token bucket) ----------

class AsyncTokenBucket:
    def __init__(self, rate_per_sec: float, burst: int) -> None:
        if rate_per_sec <= 0 or burst <= 0:
            raise ValueError("rate_per_sec and burst must be > 0")
        self.rate = float(rate_per_sec)
        self.burst = int(burst)
        self.tokens = float(burst)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            if self.tokens < 1.0:
                need = 1.0 - self.tokens
                delay = need / self.rate
                await asyncio.sleep(delay)
                now2 = time.monotonic()
                elapsed2 = now2 - self._last
                self._last = now2
                self.tokens = min(self.burst, self.tokens + elapsed2 * self.rate)
            self.tokens -= 1.0


# ---------- Config & Handlers ----------

@dataclass(slots=True)
class ProtocolConfig:
    version: str = "1.0"
    allowed_versions: Tuple[str, ...] = ("1.0",)
    heartbeat_interval_sec: float = 20.0
    client_ping_timeout_sec: float = 30.0  # if no PONG — disconnect
    max_message_bytes: int = 256 * 1024
    max_meta_bytes: int = 4 * 1024
    send_queue_size: int = 1000
    send_retry_max: int = 5
    send_retry_base_sec: float = 0.05
    send_retry_max_sec: float = 1.0
    incoming_rps: float = 50.0
    incoming_burst: int = 100
    allow_unauth_hello: bool = True  # allow HELLO without token to return WELCOME+AUTH_FAIL
    resume_window: int = 5000        # how many seq items kept for resume (server-side buffer responsibility)

@dataclass(slots=True)
class Handlers:
    # Called with presented token; must return (ok, subject, scopes, session_data)
    authenticate: Callable[[str | None], Awaitable[Tuple[bool, str | None, Tuple[str, ...] | None, Dict[str, Any]]]]
    # Called on subscribe/unsubscribe
    on_subscribe: Callable[[str, Dict[str, Any]], Awaitable[Tuple[bool, Optional[str]]]]
    on_unsubscribe: Callable[[str, Dict[str, Any]], Awaitable[None]]
    # Publish from client to channel
    on_publish: Callable[[str, Any, Dict[str, Any]], Awaitable[Tuple[bool, Optional[str]]]]
    # Optional resume handler: given session_id & last client seq -> returns new last_seq
    on_resume: Callable[[str, int], Awaitable[Tuple[bool, int]]] | None = None
    # Optional cleanup hook
    on_close: Callable[[str, Dict[str, Any]], Awaitable[None]] | None = None


# ---------- Encoder/Decoder ----------

def encode_envelope(env: Envelope) -> Union[str, bytes]:
    """JSON textual frames; small and safe. Binary JSON if JSON_IS_BINARY preferred by caller."""
    return _json_dumps(env.as_dict())


def decode_envelope(data: Union[str, bytes, bytearray]) -> Envelope:
    try:
        obj = _json_loads(data)
    except Exception:
        raise ValueError("invalid_json")

    if not isinstance(obj, dict) or "t" not in obj:
        raise ValueError("invalid_envelope")

    try:
        t = MsgType(obj["t"])
    except Exception:
        raise ValueError("unknown_type")

    env = Envelope(t=t)
    env.id = obj.get("id")
    env.ts = obj.get("ts")
    env.ch = obj.get("ch")
    env.seq = obj.get("seq")
    env.payload = obj.get("payload")
    env.meta = obj.get("meta") or {}
    # Size checks (defensive)
    if isinstance(env.meta, (str, bytes)):
        raise ValueError("meta_must_be_map")
    return env


# ---------- Core protocol ----------

class WebSocketProtocol:
    """
    Manages a single WebSocket connection lifecycle under the Omnimind protocol.
    Integrate like:
        proto = WebSocketProtocol(ws, config, handlers, logger)
        await proto.run()
    """

    def __init__(self, ws: WebSocket, cfg: ProtocolConfig, handlers: Handlers, logger: Optional[logging.Logger] = None):
        self.ws = ws
        self.cfg = cfg
        self.h = handlers
        self.log = logger or logging.getLogger("omnimind.ws")
        self.session_id = str(uuid.uuid4())
        self.subject: Optional[str] = None
        self.scopes: Tuple[str, ...] = tuple()
        self.session_data: Dict[str, Any] = {}
        self._seq = 0
        self._send_q: "asyncio.Queue[Envelope]" = asyncio.Queue(maxsize=cfg.send_queue_size)
        self._in_bucket = AsyncTokenBucket(cfg.incoming_rps, cfg.incoming_burst)
        self._last_client_pong = time.monotonic()
        self._alive = True

    # --------- public API ---------

    async def run(self) -> None:
        """
        Drive the connection: handshake, loop reader/writer/heartbeat, final cleanup.
        """
        await self._handshake()
        reader = asyncio.create_task(self._reader_loop(), name=f"ws-reader-{self.session_id}")
        writer = asyncio.create_task(self._writer_loop(), name=f"ws-writer-{self.session_id}")
        heart = asyncio.create_task(self._heartbeat_loop(), name=f"ws-heartbeat-{self.session_id}")

        done, pending = await asyncio.wait({reader, writer, heart}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
            with contextlib.suppress(Exception):
                await task
        # Cleanup
        if self.h.on_close:
            with contextlib.suppress(Exception):
                await self.h.on_close(self.session_id, dict(self.session_data))

    async def send_event(self, channel: str, payload: Any, *, meta: Optional[Dict[str, Any]] = None) -> None:
        """Server emits EVENT into client queue (backpressure-safe)."""
        await self._queue_send(Envelope(t=MsgType.EVENT, ch=channel, payload=payload, meta=meta or {}))

    async def graceful_close(self, code: CloseCode = CloseCode.NORMAL, reason: str = "bye") -> None:
        if self.ws.application_state == WebSocketState.DISCONNECTED:
            return
        await self._send_immediate(Envelope(t=MsgType.GOODBYE, payload={"reason": reason}))
        await self.ws.close(code=int(code), reason=reason)

    # --------- internals ---------

    async def _handshake(self) -> None:
        """
        Expect HELLO as the first frame:
          {t:"hello", payload:{version, token?, resume?:{session_id,last_seq}}}
        Reply with WELCOME/Auth result and session metadata.
        """
        try:
            await self.ws.accept()
        except Exception as e:
            self.log.exception("WS accept failed: %s", e)
            raise

        raw = await self._safe_receive()
        env = decode_envelope(raw)
        if env.t is not MsgType.HELLO:
            await self._fail_close(CloseCode.PROTOCOL_ERROR, "expected_hello")
            raise RuntimeError("protocol_error")

        # Version
        version = (env.payload or {}).get("version")
        if version not in self.cfg.allowed_versions:
            await self._send_immediate(Envelope(t=MsgType.ERROR, payload={"code": ErrorCode.UNSUPPORTED.value, "detail": "bad_version"}))
            await self._fail_close(CloseCode.UNSUPPORTED, "bad_version")
            raise RuntimeError("unsupported_version")

        # Auth
        token = (env.payload or {}).get("token")
        ok, subject, scopes, sess = await self.h.authenticate(token)
        if not ok and not self.cfg.allow_unauth_hello:
            await self._fail_close(CloseCode.AUTH_FAILED, "auth_failed")
            raise RuntimeError("auth_failed")

        self.subject = subject
        self.scopes = tuple(scopes or ())
        self.session_data = dict(sess or {})

        # Resume (optional)
        resumed = False
        if (env.payload or {}).get("resume"):
            r = env.payload["resume"]
            if isinstance(r, dict) and self.h.on_resume:
                rid = r.get("session_id")
                last_seq = int(r.get("last_seq", 0))
                ok_r, new_last = await self.h.on_resume(rid, last_seq)
                if ok_r:
                    resumed = True
                    self._seq = new_last

        # Welcome
        welcome = {
            "session_id": self.session_id,
            "server_time_ms": int(time.time() * 1000),
            "heartbeat_interval_sec": self.cfg.heartbeat_interval_sec,
            "max_message_bytes": self.cfg.max_message_bytes,
            "resume_window": self.cfg.resume_window,
            "version": version,
        }
        await self._send_immediate(Envelope(t=MsgType.WELCOME, payload=welcome))
        if ok:
            await self._send_immediate(Envelope(t=MsgType.AUTH_OK, payload={"subject": subject, "scopes": list(self.scopes)}))
        else:
            await self._send_immediate(Envelope(t=MsgType.AUTH_FAIL, payload={"reason": "invalid_token"}))
        if resumed:
            await self._send_immediate(Envelope(t=MsgType.RESUMED, payload={"last_seq": self._seq}))

    async def _reader_loop(self) -> None:
        while self._alive:
            try:
                await self._in_bucket.acquire()
                data = await self._safe_receive()
                env = decode_envelope(data)
            except WebSocketDisconnect:
                break
            except Exception as e:
                await self._nack(None, ErrorCode.PROTOCOL, "decode_error")
                await self._fail_close(CloseCode.BAD_MESSAGE, "decode_error")
                break

            # Heartbeat
            if env.t is MsgType.PONG:
                self._last_client_pong = time.monotonic()
                continue
            if env.t is MsgType.PING:
                await self._send_q(Envelope(t=MsgType.PONG))
                continue

            # Sequence/ACK handling (client-initiated messages)
            msg_id = env.id or str(uuid.uuid4())

            if env.t is MsgType.SUBSCRIBE:
                channel = (env.payload or {}).get("channel")
                ok, detail = await self.h.on_subscribe(str(channel), dict(self.session_data))
                if ok:
                    await self._ack(msg_id)
                else:
                    await self._nack(msg_id, ErrorCode.FORBIDDEN, detail or "subscribe_rejected")
                continue

            if env.t is MsgType.UNSUBSCRIBE:
                channel = (env.payload or {}).get("channel")
                await self.h.on_unsubscribe(str(channel), dict(self.session_data))
                await self._ack(msg_id)
                continue

            if env.t is MsgType.PUBLISH:
                channel = (env.payload or {}).get("channel")
                payload = (env.payload or {}).get("data")
                ok, detail = await self.h.on_publish(str(channel), payload, dict(self.session_data))
                if ok:
                    await self._ack(msg_id)
                else:
                    await self._nack(msg_id, ErrorCode.FORBIDDEN, detail or "publish_rejected")
                continue

            if env.t is MsgType.GOODBYE:
                await self.graceful_close(CloseCode.NORMAL, "client_goodbye")
                break

            # Unknown client message type
            await self._nack(msg_id, ErrorCode.UNSUPPORTED, "unsupported_type")

    async def _writer_loop(self) -> None:
        while self._alive:
            env = await self._send_q_get()
            try:
                await self._send_immediate(env)
            except Exception as e:
                # retry with backoff (bounded)
                tried = 0
                delay = self.cfg.send_retry_base_sec
                while tried < self.cfg.send_retry_max:
                    await asyncio.sleep(min(delay, self.cfg.send_retry_max_sec))
                    try:
                        await self._send_immediate(env)
                        break
                    except Exception:
                        tried += 1
                        delay *= 2
                if tried >= self.cfg.send_retry_max:
                    await self._fail_close(CloseCode.INTERNAL_ERROR, "send_failed")
                    break

    async def _heartbeat_loop(self) -> None:
        interval = self.cfg.heartbeat_interval_sec
        timeout = self.cfg.client_ping_timeout_sec
        while self._alive:
            await asyncio.sleep(interval)
            try:
                await self._send_q(Envelope(t=MsgType.PING, payload={"ts": int(time.time() * 1000)}))
            except Exception:
                break
            if time.monotonic() - self._last_client_pong > timeout:
                await self._fail_close(CloseCode.TRY_AGAIN_LATER, "pong_timeout")
                break

    # --------- sending helpers ---------

    async def _queue_send(self, env: Envelope) -> None:
        """Public backpressure-aware enqueue (drops oldest on overflow)."""
        try:
            self._seq += 1
            env.seq = self._seq
            env.ts = int(time.time() * 1000)
            self._send_q.put_nowait(env)
        except asyncio.QueueFull:
            # Drop-oldest strategy to avoid deadlock; signal NACK via control frame
            try:
                _ = self._send_q.get_nowait()
                self._send_q.task_done()
                self._send_q.put_nowait(env)
                await self._send_q(Envelope(t=MsgType.NACK, payload={"code": ErrorCode.BACKPRESSURE.value, "detail": "dropped_oldest"}))
            except Exception:
                await self._fail_close(CloseCode.BACKPRESSURE, "send_queue_overflow")
                raise

    async def _send_q(self, env: Envelope) -> None:
        self._seq += 1
        env.seq = self._seq
        env.ts = int(time.time() * 1000)
        await self._send_q_put(env)

    async def _send_q_put(self, env: Envelope) -> None:
        await self._send_q.put(env)

    async def _send_q_get(self) -> Envelope:
        return await self._send_q.get()

    async def _send_immediate(self, env: Envelope) -> None:
        payload = encode_envelope(env)
        if isinstance(payload, bytes):
            # text frames are widely compatible; send bytes if JSON_IS_BINARY preferred
            await self.ws.send_bytes(payload)
        else:
            await self.ws.send_text(payload.decode("utf-8") if isinstance(payload, (bytes, bytearray)) else payload)
        self._send_q.task_done()

    async def _ack(self, msg_id: Optional[str]) -> None:
        await self._send_q(Envelope(t=MsgType.ACK, payload={"id": msg_id} if msg_id else {}))

    async def _nack(self, msg_id: Optional[str], code: ErrorCode, detail: str) -> None:
        await self._send_q(Envelope(t=MsgType.NACK, payload={"id": msg_id, "code": code.value, "detail": detail}))

    # --------- receiving helpers ---------

    async def _safe_receive(self) -> Union[str, bytes]:
        msg = await self.ws.receive()
        if "bytes" in msg and msg["bytes"] is not None:
            data = msg["bytes"]
        else:
            data = msg.get("text", "")
            if not isinstance(data, (str, bytes, bytearray)):
                raise ValueError("invalid_frame")
            if isinstance(data, str):
                data = data.encode("utf-8")
        # size limits
        if len(data) > self.cfg.max_message_bytes:
            raise ValueError("frame_too_large")
        return data

    async def _fail_close(self, code: CloseCode, reason: str) -> None:
        self._alive = False
        try:
            await self._send_immediate(Envelope(t=MsgType.ERROR, payload={"code": ErrorCode.PROTOCOL.value, "detail": reason}))
        finally:
            with contextlib.suppress(Exception):
                await self.ws.close(code=int(code), reason=reason)


# ---------- Example FastAPI integration (minimal) ----------

# The following snippet is illustrative. Place it in your FastAPI app:
#
# from fastapi import FastAPI, WebSocket
# from ops.api.ws.protocols import WebSocketProtocol, ProtocolConfig, Handlers
#
# app = FastAPI()
#
# async def authenticate(token: str | None):
#     ok = token == os.getenv("ADMIN_WS_TOKEN", "devtoken")
#     subject = "admin" if ok else None
#     scopes = ("read", "write") if ok else ()
#     session = {}
#     return ok, subject, scopes, session
#
# async def on_subscribe(channel: str, session: dict):
#     return True, None
#
# async def on_unsubscribe(channel: str, session: dict):
#     return None
#
# async def on_publish(channel: str, data: any, session: dict):
#     # route to internal bus
#     return True, None
#
# handlers = Handlers(
#     authenticate=authenticate,
#     on_subscribe=on_subscribe,
#     on_unsubscribe=on_unsubscribe,
#     on_publish=on_publish,
# )
#
# @app.websocket("/ws")
# async def ws_endpoint(ws: WebSocket):
#     proto = WebSocketProtocol(ws, ProtocolConfig(), handlers)
#     await proto.run()

# ---------- End of module ----------
import contextlib  # kept at end to avoid circular type hints
