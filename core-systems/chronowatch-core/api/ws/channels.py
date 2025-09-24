from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Optional, Set, Tuple

try:
    # Optional; gives strict validation and JSON schema for clients
    from pydantic import BaseModel, Field, ValidationError
    _HAS_PYDANTIC = True
except Exception:  # pragma: no cover
    BaseModel = object  # type: ignore
    Field = lambda *a, **k: None  # type: ignore
    ValidationError = Exception  # type: ignore
    _HAS_PYDANTIC = False

try:
    # starlette is the minimal ASGI runtime dependency for FastAPI too
    from starlette.websockets import WebSocket, WebSocketDisconnect
    from starlette.types import Receive, Scope, Send
except Exception as e:  # pragma: no cover
    raise RuntimeError("starlette must be installed for ws channels") from e


# =============================================================================
# Configuration & Constants
# =============================================================================

CHANNEL_NAME_RE = re.compile(r"^[a-z][a-z0-9\-.:/]{2,64}$")
DEFAULT_HEARTBEAT_INTERVAL = 15.0  # seconds
DEFAULT_IDLE_TIMEOUT = 60.0        # seconds
DEFAULT_MAX_QUEUE = 1000           # per-connection send queue depth
DEFAULT_RX_RPS = 100.0             # frame/s
DEFAULT_TX_RPS = 200.0             # frame/s
DEFAULT_MAX_CHANNELS_PER_CONN = 128
DEFAULT_MESSAGE_MAX_BYTES = 256 * 1024  # 256 KiB


# =============================================================================
# Utilities
# =============================================================================

def utc_ts_ms() -> int:
    return int(time.time() * 1000)


class TokenBucket:
    """
    Simple token bucket rate-limiter.
    capacity: max tokens (burst)
    rate: tokens per second (refill)
    """
    __slots__ = ("capacity", "rate", "_tokens", "_last")

    def __init__(self, capacity: float, rate: float) -> None:
        self.capacity = float(capacity)
        self.rate = float(rate)
        self._tokens = float(capacity)
        self._last = time.perf_counter()

    def allow(self, cost: float = 1.0) -> bool:
        now = time.perf_counter()
        delta = now - self._last
        self._last = now
        self._tokens = min(self.capacity, self._tokens + delta * self.rate)
        if self._tokens >= cost:
            self._tokens -= cost
            return True
        return False


# =============================================================================
# Message Models
# =============================================================================

class MsgType:
    SUBSCRIBE = "subscribe"
    UNSUBSCRIBE = "unsubscribe"
    PUBLISH = "publish"
    EVENT = "event"
    ACK = "ack"
    ERROR = "error"
    PING = "ping"
    PONG = "pong"
    PRESENCE = "presence"


if _HAS_PYDANTIC:

    class ClientFrame(BaseModel):
        """Inbound frames from client."""
        type: str = Field(..., description="subscribe | unsubscribe | publish | ping | ack")
        id: Optional[str] = Field(None, description="client-generated id for at-least-once ack")
        channel: Optional[str] = Field(None, description="channel name for sub/unsub/publish")
        payload: Optional[Any] = Field(None, description="data for publish/ack bodies")
        ts: Optional[int] = Field(None, description="client timestamp ms")

    class ServerFrame(BaseModel):
        """Outbound frames to client."""
        type: str = Field(..., description="event | ack | error | pong | presence")
        id: Optional[str] = Field(None, description="server-assigned id or echo of client id")
        channel: Optional[str] = Field(None)
        payload: Optional[Any] = Field(None)
        ts: int = Field(default_factory=utc_ts_ms)
        seq: Optional[int] = Field(None, description="monotonic sequence per channel")

else:
    # Minimal soft validation when Pydantic not present
    class ClientFrame:  # pragma: no cover
        def __init__(self, **data: Any) -> None:
            self.type = str(data.get("type"))
            self.id = data.get("id")
            self.channel = data.get("channel")
            self.payload = data.get("payload")
            self.ts = int(data["ts"]) if "ts" in data and isinstance(data["ts"], (int, float)) else None

        @classmethod
        def model_validate_json(cls, raw: str) -> "ClientFrame":
            try:
                data = json.loads(raw)
            except Exception as e:
                raise ValidationError(str(e))  # type: ignore
            return cls(**data)

    class ServerFrame:  # pragma: no cover
        def __init__(self, **data: Any) -> None:
            self.type = data.get("type")
            self.id = data.get("id")
            self.channel = data.get("channel")
            self.payload = data.get("payload")
            self.ts = data.get("ts", utc_ts_ms())
            self.seq = data.get("seq")

        def model_dump_json(self) -> str:
            return json.dumps(
                {
                    "type": self.type,
                    "id": self.id,
                    "channel": self.channel,
                    "payload": self.payload,
                    "ts": self.ts,
                    "seq": self.seq,
                },
                separators=(",", ":"),
                ensure_ascii=False,
            )


# =============================================================================
# AuthN/AuthZ contracts
# =============================================================================

AuthResult = Dict[str, Any]
Authenticator = Callable[[Optional[str]], Awaitable[AuthResult]]
Authorizer = Callable[[AuthResult, str, str], Awaitable[bool]]
# authorizer(subject, action, channel) -> bool


async def default_authenticator(token: Optional[str]) -> AuthResult:
    """
    Default permissive authenticator:
    Accepts missing token, issues anonymous subject with random session id.
    Replace in production with JWT/JWKS validation.
    """
    return {
        "sub": f"anon:{secrets.token_hex(8)}" if not token else f"tok:{hash(token)}",
        "scopes": [],
        "is_anonymous": token is None,
    }


async def default_authorizer(subject: AuthResult, action: str, channel: str) -> bool:
    """
    Default ACL:
    - subscribe/unsubscribe allowed for channels matching regex
    - publish allowed only for channels that don't start with 'sys.'
    """
    if not CHANNEL_NAME_RE.match(channel):
        return False
    if action == "publish" and channel.startswith("sys."):
        return False
    return True


# =============================================================================
# Connection & Hub
# =============================================================================

@dataclass(slots=True)
class Connection:
    id: str
    websocket: WebSocket
    subject: AuthResult
    rx_limiter: TokenBucket
    tx_limiter: TokenBucket
    send_queue: asyncio.Queue[bytes]
    channels: Set[str] = field(default_factory=set)
    last_seen: float = field(default_factory=time.monotonic)
    alive: bool = True


class ChannelsHub:
    """
    In-memory channels hub with optional pluggable AuthN/AuthZ.
    Works with Starlette/FastAPI WebSocket endpoint.

    Integration example (FastAPI):
        hub = ChannelsHub()
        @app.websocket("/ws")
        async def ws(ws: WebSocket):
            await hub.serve(ws)
    """

    def __init__(
        self,
        *,
        authenticator: Authenticator = default_authenticator,
        authorizer: Authorizer = default_authorizer,
        heartbeat_interval: float = DEFAULT_HEARTBEAT_INTERVAL,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
        max_queue: int = DEFAULT_MAX_QUEUE,
        rx_rps: float = DEFAULT_RX_RPS,
        tx_rps: float = DEFAULT_TX_RPS,
        max_channels_per_conn: int = DEFAULT_MAX_CHANNELS_PER_CONN,
        message_max_bytes: int = DEFAULT_MESSAGE_MAX_BYTES,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._authn = authenticator
        self._authz = authorizer
        self._hb_interval = float(heartbeat_interval)
        self._idle_timeout = float(idle_timeout)
        self._max_queue = int(max_queue)
        self._rx_rps = float(rx_rps)
        self._tx_rps = float(tx_rps)
        self._max_channels_per_conn = int(max_channels_per_conn)
        self._message_max_bytes = int(message_max_bytes)

        self._log = logger or logging.getLogger("chronowatch.ws")
        self._connections: Dict[str, Connection] = {}
        self._members: Dict[str, Set[str]] = {}     # channel -> set(conn_id)
        self._seq: Dict[str, int] = {}              # channel -> seq

        # Presence channel (system)
        self._presence_channel = "sys.presence"

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    async def serve(self, ws: WebSocket) -> None:
        """
        Main entrypoint: accepts WebSocket, performs handshake,
        spawns reader/writer coroutines, manages lifecycle.
        """
        await ws.accept(subprotocol="chronowatch.ws.v1")

        token = _extract_bearer(ws)
        subject = await self._authn(token)

        conn_id = secrets.token_urlsafe(12)
        conn = Connection(
            id=conn_id,
            websocket=ws,
            subject=subject,
            rx_limiter=TokenBucket(capacity=max(5.0, self._rx_rps), rate=self._rx_rps),
            tx_limiter=TokenBucket(capacity=max(10.0, self._tx_rps), rate=self._tx_rps),
            send_queue=asyncio.Queue(self._max_queue),
        )
        self._connections[conn_id] = conn
        self._log.info("ws.connect", extra={"conn_id": conn_id, "sub": subject.get("sub")})

        # announce presence join
        await self._emit_presence("join", conn)

        writer = asyncio.create_task(self._writer(conn), name=f"ws-writer-{conn_id}")
        reader = asyncio.create_task(self._reader(conn), name=f"ws-reader-{conn_id}")
        hb = asyncio.create_task(self._heartbeat(conn), name=f"ws-heartbeat-{conn_id}")

        try:
            await asyncio.wait({reader, writer, hb}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in (reader, writer, hb):
                task.cancel()
                with contextlib.suppress(Exception):
                    await task
            await self._disconnect(conn)

    async def publish(self, channel: str, payload: Any) -> None:
        """Server-side publish to a channel (system events, etc.)."""
        if not CHANNEL_NAME_RE.match(channel):
            self._log.warning("publish.invalid_channel", extra={"channel": channel})
            return
        seq = self._next_seq(channel)
        frame = ServerFrame(type=MsgType.EVENT, channel=channel, payload=payload, seq=seq)  # type: ignore
        await self._broadcast(channel, frame)

    # -------------------------------------------------------------------------
    # Internals
    # -------------------------------------------------------------------------

    async def _reader(self, conn: Connection) -> None:
        while conn.alive:
            try:
                raw = await asyncio.wait_for(conn.websocket.receive_text(), timeout=self._idle_timeout)
                conn.last_seen = time.monotonic()
            except asyncio.TimeoutError:
                await self._send_error(conn, "idle_timeout")
                break
            except WebSocketDisconnect:
                break

            if len(raw.encode("utf-8", errors="ignore")) > self._message_max_bytes:
                await self._send_error(conn, "frame_too_large")
                continue

            if not conn.rx_limiter.allow():
                await self._send_error(conn, "rate_limited_rx")
                continue

            try:
                msg = ClientFrame.model_validate_json(raw) if _HAS_PYDANTIC else ClientFrame.model_validate_json(raw)  # type: ignore
            except ValidationError as e:
                await self._send_error(conn, f"bad_frame:{e}")
                continue

            t = msg.type
            if t == MsgType.SUBSCRIBE:
                await self._on_subscribe(conn, msg)
            elif t == MsgType.UNSUBSCRIBE:
                await self._on_unsubscribe(conn, msg)
            elif t == MsgType.PUBLISH:
                await self._on_publish(conn, msg)
            elif t == MsgType.PING:
                await self._send(conn, ServerFrame(type=MsgType.PONG, id=msg.id))  # type: ignore
            elif t == MsgType.ACK:
                # Currently noop; place for durable delivery tracking
                pass
            else:
                await self._send_error(conn, "unknown_type", ref=msg.id)

    async def _writer(self, conn: Connection) -> None:
        while conn.alive:
            try:
                data = await conn.send_queue.get()
                if not conn.tx_limiter.allow():
                    # backpressure: wait minimal time slice to let tokens refill
                    await asyncio.sleep(0.01)
                await conn.websocket.send_text(data.decode("utf-8"))
            except WebSocketDisconnect:
                break
            except Exception as e:  # pragma: no cover
                self._log.exception("ws.send_error", extra={"conn_id": conn.id, "err": str(e)})
                break

    async def _heartbeat(self, conn: Connection) -> None:
        while conn.alive:
            await asyncio.sleep(self._hb_interval)
            try:
                # server-side soft ping (clients may rely on application ping too)
                await self._send(conn, ServerFrame(type=MsgType.PING))  # type: ignore
                # hard idle check
                if time.monotonic() - conn.last_seen > self._idle_timeout:
                    await self._send_error(conn, "idle_timeout")
                    break
            except WebSocketDisconnect:
                break
            except Exception:  # pragma: no cover
                break

    async def _on_subscribe(self, conn: Connection, msg: ClientFrame) -> None:
        channel = (msg.channel or "").strip()
        if not CHANNEL_NAME_RE.match(channel):
            await self._send_error(conn, "invalid_channel", ref=msg.id)
            return
        if len(conn.channels) >= self._max_channels_per_conn:
            await self._send_error(conn, "too_many_channels", ref=msg.id)
            return
        if not await self._authz(conn.subject, "subscribe", channel):
            await self._send_error(conn, "forbidden", ref=msg.id)
            return

        members = self._members.setdefault(channel, set())
        if conn.id not in members:
            members.add(conn.id)
            conn.channels.add(channel)
            await self._send(conn, ServerFrame(type=MsgType.ACK, id=msg.id, channel=channel))  # type: ignore
            # presence notify
            await self._presence_broadcast(channel, "join", conn)

    async def _on_unsubscribe(self, conn: Connection, msg: ClientFrame) -> None:
        channel = (msg.channel or "").strip()
        if not CHANNEL_NAME_RE.match(channel):
            await self._send_error(conn, "invalid_channel", ref=msg.id)
            return
        self._leave_channel(conn, channel)
        await self._send(conn, ServerFrame(type=MsgType.ACK, id=msg.id, channel=channel))  # type: ignore
        await self._presence_broadcast(channel, "leave", conn)

    async def _on_publish(self, conn: Connection, msg: ClientFrame) -> None:
        channel = (msg.channel or "").strip()
        if not CHANNEL_NAME_RE.match(channel):
            await self._send_error(conn, "invalid_channel", ref=msg.id)
            return
        if not await self._authz(conn.subject, "publish", channel):
            await self._send_error(conn, "forbidden", ref=msg.id)
            return
        seq = self._next_seq(channel)
        frame = ServerFrame(type=MsgType.EVENT, id=msg.id, channel=channel, payload=msg.payload, seq=seq)  # type: ignore
        await self._broadcast(channel, frame)

    async def _send(self, conn: Connection, frame: ServerFrame) -> None:
        try:
            data = frame.model_dump_json() if _HAS_PYDANTIC else frame.model_dump_json()  # type: ignore
        except Exception:
            # As a last resort, do a safe JSON dump
            data = json.dumps(
                {"type": getattr(frame, "type", "event"),
                 "id": getattr(frame, "id", None),
                 "channel": getattr(frame, "channel", None),
                 "payload": getattr(frame, "payload", None),
                 "ts": getattr(frame, "ts", utc_ts_ms()),
                 "seq": getattr(frame, "seq", None)},
                separators=(",", ":"),
                ensure_ascii=False,
            )
        encoded = data.encode("utf-8", errors="ignore")
        # Drop-Oldest backpressure policy: keep queue bounded
        if conn.send_queue.full():
            with contextlib.suppress(Exception):
                _ = conn.send_queue.get_nowait()
        await conn.send_queue.put(encoded)

    async def _broadcast(self, channel: str, frame: ServerFrame) -> None:
        # local broadcast to all members
        conns = [self._connections[cid] for cid in self._members.get(channel, set()) if cid in self._connections]
        for c in conns:
            await self._send(c, frame)

    async def _presence_broadcast(self, channel: str, kind: str, conn: Connection) -> None:
        payload = {"kind": kind, "channel": channel, "conn_id": conn.id, "sub": conn.subject.get("sub"), "ts": utc_ts_ms()}
        frame = ServerFrame(type=MsgType.PRESENCE, channel=self._presence_channel, payload=payload)  # type: ignore
        await self._broadcast(self._presence_channel, frame)

    async def _emit_presence(self, kind: str, conn: Connection) -> None:
        payload = {"kind": kind, "conn_id": conn.id, "sub": conn.subject.get("sub"), "ts": utc_ts_ms()}
        await self.publish(self._presence_channel, payload)

    async def _send_error(self, conn: Connection, reason: str, *, ref: Optional[str] = None) -> None:
        await self._send(conn, ServerFrame(type=MsgType.ERROR, id=ref, payload={"reason": reason}))  # type: ignore

    async def _disconnect(self, conn: Connection) -> None:
        if not conn.alive:
            return
        conn.alive = False

        # leave all channels
        for ch in list(conn.channels):
            self._leave_channel(conn, ch)

        # presence leave
        await self._emit_presence("leave", conn)

        with contextlib.suppress(Exception):
            await conn.websocket.close()
        self._connections.pop(conn.id, None)
        self._log.info("ws.disconnect", extra={"conn_id": conn.id})

    def _leave_channel(self, conn: Connection, channel: str) -> None:
        members = self._members.get(channel)
        if members and conn.id in members:
            members.discard(conn.id)
        conn.channels.discard(channel)

    def _next_seq(self, channel: str) -> int:
        cur = self._seq.get(channel, 0) + 1
        self._seq[channel] = cur
        return cur


# =============================================================================
# Helpers
# =============================================================================

def _extract_bearer(ws: WebSocket) -> Optional[str]:
    """
    Try to extract bearer token from:
      - "Authorization: Bearer <token>"
      - query param "token"
    """
    # headers
    auth = ws.headers.get("authorization") or ws.headers.get("Authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip() or None
    # query
    try:
        token = ws.query_params.get("token")
        if token:
            return token
    except Exception:
        pass
    return None


# =============================================================================
# ASGI App (optional): mountable endpoint
# =============================================================================

class ChannelsASGI:
    """
    Minimal ASGI adapter to mount hub at a given path without FastAPI/Starlette routers.

    Usage:
        hub = ChannelsHub()
        app = ChannelsASGI(hub)
        # add to an ASGI stack/router that dispatches to this at "/ws"
    """

    def __init__(self, hub: ChannelsHub):
        self._hub = hub

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "websocket":  # pragma: no cover
            await send({"type": "http.response.start", "status": 404, "headers": []})
            await send({"type": "http.response.body", "body": b"not found"})
            return

        ws = WebSocket(scope=scope, receive=receive, send=send)
        await self._hub.serve(ws)
