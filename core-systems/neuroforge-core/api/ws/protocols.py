# neuroforge-core/api/ws/protocols.py
# Industrial WebSocket protocol primitives for NeuroForge Core
from __future__ import annotations

import asyncio
import base64
import json
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Protocol, Tuple, Union

# msgpack is optional; JSON is the default codec
try:
    import msgpack  # type: ignore
except Exception:  # pragma: no cover
    msgpack = None  # type: ignore


# ======================================================================================
# Constants & Limits
# ======================================================================================

PROTOCOL_NAME = "neuroforge.ws"
PROTOCOL_VERSION = (1, 0)  # (major, minor)

DEFAULT_HEARTBEAT_INTERVAL_SEC = 20
DEFAULT_HEARTBEAT_TIMEOUT_SEC = 60
DEFAULT_MAX_MESSAGE_BYTES = 1 * 1024 * 1024  # 1 MiB
DEFAULT_MAX_STREAMS = 256
DEFAULT_MAX_INFLIGHT = 1024

# ======================================================================================
# WebSocket-like abstraction (Starlette/FastAPI adapter compatible)
# ======================================================================================

class WebSocketLike(Protocol):
    async def accept(self, subprotocol: Optional[str] = None) -> None: ...
    async def send_text(self, data: str) -> None: ...
    async def send_bytes(self, data: bytes) -> None: ...
    async def receive_text(self) -> str: ...
    async def receive_bytes(self) -> bytes: ...
    async def close(self, code: int = 1000, reason: str = "") -> None: ...


# ======================================================================================
# Enums, error codes, codecs
# ======================================================================================

class MessageType(str, Enum):
    HELLO = "HELLO"
    SERVER_HELLO = "SERVER_HELLO"
    ACK = "ACK"
    NACK = "NACK"
    REQUEST = "REQUEST"
    STREAM_START = "STREAM_START"
    STREAM_CHUNK = "STREAM_CHUNK"
    STREAM_END = "STREAM_END"
    FLOW_CREDIT = "FLOW_CREDIT"
    HEARTBEAT = "HEARTBEAT"
    ERROR = "ERROR"
    CLOSE = "CLOSE"

class ErrorCode(int, Enum):
    # 4xxx — протокольные
    MALFORMED = 4000
    UNSUPPORTED = 4001
    UNAUTHORIZED = 4002
    RATE_LIMITED = 4003
    TOO_LARGE = 4004
    CONFLICT = 4009
    # 5xxx — серверные
    INTERNAL = 5000
    OVERLOADED = 5003
    TIMEOUT = 5040

class AuthMode(str, Enum):
    NONE = "none"
    API_KEY = "apiKey"
    JWT = "jwt"

class CodecName(str, Enum):
    JSON = "json"
    MSGPACK = "msgpack"

class CloseReason(str, Enum):
    NORMAL = "normal"
    SERVER_SHUTDOWN = "server_shutdown"
    POLICY = "policy"
    ERROR = "error"

# ======================================================================================
# Serialization Codecs
# ======================================================================================

class Codec(Protocol):
    name: CodecName
    content_type: str

    def encode(self, obj: Dict[str, Any]) -> bytes: ...
    def decode(self, data: bytes) -> Dict[str, Any]: ...

class JsonCodecImpl:
    name: CodecName = CodecName.JSON
    content_type = "application/json"

    def encode(self, obj: Dict[str, Any]) -> bytes:
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def decode(self, data: bytes) -> Dict[str, Any]:
        return json.loads(data.decode("utf-8"))

class MsgpackCodecImpl:
    name: CodecName = CodecName.MSGPACK
    content_type = "application/msgpack"

    def encode(self, obj: Dict[str, Any]) -> bytes:
        if not msgpack:
            raise RuntimeError("msgpack not available")
        return msgpack.packb(obj, use_bin_type=True)

    def decode(self, data: bytes) -> Dict[str, Any]:
        if not msgpack:
            raise RuntimeError("msgpack not available")
        return msgpack.unpackb(data, raw=False)

JSON_CODEC: Codec = JsonCodecImpl()
MSGPACK_CODEC: Optional[Codec] = MsgpackCodecImpl() if msgpack else None

# ======================================================================================
# Helper utils
# ======================================================================================

def now_ms() -> int:
    return int(time.time() * 1000)

def gen_id() -> str:
    return str(uuid.uuid4())

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

# ======================================================================================
# Message schema (dict-based for speed; validated at boundaries)
# ======================================================================================

def base_envelope(t: MessageType, **kwargs: Any) -> Dict[str, Any]:
    env = {
        "type": t.value,
        "id": kwargs.pop("id", gen_id()),
        "ts": kwargs.pop("ts", now_ms()),
    }
    env.update(kwargs)
    return env

# ---- HELLO / SERVER_HELLO ----
def msg_client_hello(
    token: Optional[str],
    auth_mode: AuthMode = AuthMode.NONE,
    codecs: Optional[List[CodecName]] = None,
    heartbeat_interval_sec: int = DEFAULT_HEARTBEAT_INTERVAL_SEC,
    max_msg_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
) -> Dict[str, Any]:
    return base_envelope(
        MessageType.HELLO,
        proto={"name": PROTOCOL_NAME, "versions": [f"{PROTOCOL_VERSION[0]}.{PROTOCOL_VERSION[1]}"]},
        auth={"mode": auth_mode.value, "token": token},
        codecs=[c.value for c in (codecs or [CodecName.JSON, CodecName.MSGPACK])],
        params={"heartbeat_interval_sec": heartbeat_interval_sec, "max_message_bytes": max_msg_bytes},
    )

def msg_server_hello(
    session_id: str,
    codec: CodecName,
    heartbeat_interval_sec: int,
    max_msg_bytes: int,
    features: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return base_envelope(
        MessageType.SERVER_HELLO,
        session={"id": session_id},
        selected={"codec": codec.value},
        params={"heartbeat_interval_sec": heartbeat_interval_sec, "max_message_bytes": max_msg_bytes},
        features=features or {},
    )

# ---- REQUEST ----
def msg_request(route: str, payload: Dict[str, Any], request_id: Optional[str] = None) -> Dict[str, Any]:
    return base_envelope(MessageType.REQUEST, route=route, payload=payload, req=request_id or gen_id())

# ---- STREAMING ----
def msg_stream_start(stream_id: Optional[str], route: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return base_envelope(MessageType.STREAM_START, stream=stream_id or gen_id(), route=route, meta=meta or {})

def msg_stream_chunk(stream_id: str, seq: int, data: Union[str, bytes], final: bool = False) -> Dict[str, Any]:
    # if bytes, base64-encode with marker
    if isinstance(data, bytes):
        return base_envelope(MessageType.STREAM_CHUNK, stream=stream_id, seq=seq, bin=True, data=b64e(data), final=final)
    return base_envelope(MessageType.STREAM_CHUNK, stream=stream_id, seq=seq, data=data, final=final)

def msg_stream_end(stream_id: str, status: str = "ok", metrics: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return base_envelope(MessageType.STREAM_END, stream=stream_id, status=status, metrics=metrics or {})

# ---- FLOW CONTROL ----
def msg_flow_credit(stream_id: str, credits: int) -> Dict[str, Any]:
    return base_envelope(MessageType.FLOW_CREDIT, stream=stream_id, credits=max(0, int(credits)))

# ---- HEARTBEAT ----
def msg_heartbeat(ping: bool, seq: int, rtt_ms: Optional[int] = None) -> Dict[str, Any]:
    return base_envelope(MessageType.HEARTBEAT, ping=ping, seq=seq, rtt_ms=rtt_ms)

# ---- ACK/NACK ----
def msg_ack(message_id: str, request_id: Optional[str] = None) -> Dict[str, Any]:
    return base_envelope(MessageType.ACK, ack=message_id, req=request_id)

def msg_nack(message_id: str, code: ErrorCode, reason: str, request_id: Optional[str] = None) -> Dict[str, Any]:
    return base_envelope(MessageType.NACK, ack=message_id, code=int(code), reason=reason, req=request_id)

# ---- ERROR/CLOSE ----
def msg_error(code: ErrorCode, message: str, details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return base_envelope(MessageType.ERROR, code=int(code), message=message, details=details or {})

def msg_close(reason: CloseReason = CloseReason.NORMAL, code: int = 1000) -> Dict[str, Any]:
    return base_envelope(MessageType.CLOSE, reason=reason.value, code=code)

# ======================================================================================
# Protocol spec & negotiation
# ======================================================================================

@dataclass(frozen=True)
class ProtocolSpec:
    name: str = PROTOCOL_NAME
    version: Tuple[int, int] = PROTOCOL_VERSION
    codecs: Tuple[CodecName, ...] = (CodecName.JSON, CodecName.MSGPACK)
    heartbeat_interval_sec: int = DEFAULT_HEARTBEAT_INTERVAL_SEC
    heartbeat_timeout_sec: int = DEFAULT_HEARTBEAT_TIMEOUT_SEC
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES
    max_streams: int = DEFAULT_MAX_STREAMS
    max_inflight: int = DEFAULT_MAX_INFLIGHT

    def choose_codec(self, offered: List[str]) -> Codec:
        offered_set = [CodecName(o) for o in offered if o in (c.value for c in self.codecs)]
        for pref in self.codecs:
            if pref.value in [o.value for o in offered_set]:
                if pref is CodecName.JSON:
                    return JSON_CODEC
                if pref is CodecName.MSGPACK and MSGPACK_CODEC:
                    return MSGPACK_CODEC
        return JSON_CODEC

# ======================================================================================
# Flow control
# ======================================================================================

class FlowController:
    """
    Credit-based flow control per stream.
    Sender decrements available credits when emitting chunks.
    Receiver replenishes credits by sending FLOW_CREDIT.
    """
    def __init__(self) -> None:
        self._credits: Dict[str, int] = {}
        self._events: Dict[str, asyncio.Event] = {}

    def offer(self, stream_id: str, credits: int) -> None:
        if credits <= 0:
            return
        self._credits[stream_id] = self._credits.get(stream_id, 0) + credits
        self._events.setdefault(stream_id, asyncio.Event()).set()

    async def acquire(self, stream_id: str, amount: int = 1, timeout: Optional[float] = None) -> None:
        deadline = None if timeout is None else (time.monotonic() + timeout)
        while True:
            cur = self._credits.get(stream_id, 0)
            if cur >= amount:
                self._credits[stream_id] = cur - amount
                return
            # wait for credits
            evt = self._events.setdefault(stream_id, asyncio.Event())
            evt.clear()
            remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
            try:
                await asyncio.wait_for(evt.wait(), timeout=remaining)
            except asyncio.TimeoutError:
                raise TimeoutError("flow control: acquire timeout")

    def reset(self, stream_id: str) -> None:
        self._credits.pop(stream_id, None)
        evt = self._events.pop(stream_id, None)
        if evt:
            evt.set()

# ======================================================================================
# Session (handshake, send/recv, heartbeat, size checks)
# ======================================================================================

class ProtocolError(Exception): ...

class WsSession:
    """
    High-level session wrapper:
      - performs HELLO negotiation
      - (de)serializes messages via selected codec
      - enforces max message size
      - maintains heartbeats
      - provides flow control interface
    """
    def __init__(self, ws: WebSocketLike, spec: ProtocolSpec = ProtocolSpec()):
        self.ws = ws
        self.spec = spec
        self.codec: Codec = JSON_CODEC
        self.session_id = str(uuid.uuid4())
        self._hb_seq = 0
        self._hb_task: Optional[asyncio.Task] = None
        self._hb_last_rx = time.monotonic()
        self.flow = FlowController()
        self._closed = False

    async def handshake_server(self, require_auth: bool = False) -> Dict[str, Any]:
        """
        Server-side handshake:
          1) accept()
          2) read HELLO (bytes/text)
          3) choose codec & reply SERVER_HELLO
        """
        await self.ws.accept(subprotocol=f"{self.spec.name};v={self.spec.version[0]}.{self.spec.version[1]}")
        hello = await self._recv_any()
        if hello.get("type") != MessageType.HELLO.value:
            raise ProtocolError("expected HELLO")
        # Validate protocol name/version
        proto = hello.get("proto", {})
        if proto.get("name") != self.spec.name:
            raise ProtocolError("unsupported protocol")
        # Auth (transport-level auth should be done at HTTP layer; here accept metadata)
        auth = hello.get("auth", {}) or {}
        if require_auth and (auth.get("mode") in (None, "none", "")):
            await self.send(msg_error(ErrorCode.UNAUTHORIZED, "auth required"))
            raise ProtocolError("auth required")

        offered_codecs = hello.get("codecs") or [CodecName.JSON.value]
        self.codec = self.spec.choose_codec(offered_codecs)

        # negotiated params (use server defaults; may clamp)
        hb = min(int(hello.get("params", {}).get("heartbeat_interval_sec", self.spec.heartbeat_interval_sec)),
                 self.spec.heartbeat_interval_sec)
        mx = min(int(hello.get("params", {}).get("max_message_bytes", self.spec.max_message_bytes)),
                 self.spec.max_message_bytes)

        reply = msg_server_hello(
            session_id=self.session_id,
            codec=CodecName(self.codec.name),
            heartbeat_interval_sec=hb,
            max_msg_bytes=mx,
            features={"flow_control": "credits", "chunking": True},
        )
        await self.send(reply)

        # start heartbeat
        self._hb_last_rx = time.monotonic()
        self._hb_task = asyncio.create_task(self._heartbeat_loop(hb))
        return hello

    async def close(self, reason: CloseReason = CloseReason.NORMAL, code: int = 1000) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            await self.send(msg_close(reason=reason, code=code))
        except Exception:
            pass
        if self._hb_task:
            self._hb_task.cancel()
        await self.ws.close(code=code, reason=reason.value)

    # --------------- Send/Receive ---------------

    async def send(self, message: Dict[str, Any]) -> None:
        data = self.codec.encode(message)
        if len(data) > self.spec.max_message_bytes:
            raise ProtocolError("message exceeds max_message_bytes")
        # prefer binary for msgpack, text for json
        if self.codec.name == CodecName.JSON:
            await self.ws.send_text(data.decode("utf-8"))
        else:
            await self.ws.send_bytes(data)

    async def recv(self, *, timeout: Optional[float] = None) -> Dict[str, Any]:
        if timeout is not None:
            return await asyncio.wait_for(self._recv_any(), timeout=timeout)
        return await self._recv_any()

    async def _recv_any(self) -> Dict[str, Any]:
        # try bytes first (some clients always send binary)
        raw: Optional[bytes] = None
        try:
            raw = await self.ws.receive_bytes()
        except Exception:
            text = await self.ws.receive_text()
            raw = text.encode("utf-8")
        if len(raw) > self.spec.max_message_bytes:
            await self.send(msg_error(ErrorCode.TOO_LARGE, "frame too large"))
            raise ProtocolError("frame too large")
        obj = self.codec.decode(raw)
        # heartbeat bookkeeping
        if obj.get("type") == MessageType.HEARTBEAT.value:
            self._hb_last_rx = time.monotonic()
        return obj

    # --------------- Heartbeat ---------------

    async def _heartbeat_loop(self, interval_sec: int) -> None:
        try:
            while True:
                await asyncio.sleep(interval_sec)
                self._hb_seq += 1
                ping = msg_heartbeat(ping=True, seq=self._hb_seq)
                await self.send(ping)
                # timeout detection
                if (time.monotonic() - self._hb_last_rx) > self.spec.heartbeat_timeout_sec:
                    await self.close(reason=CloseReason.ERROR, code=1011)
                    return
        except asyncio.CancelledError:  # graceful exit
            return

    # --------------- Flow helpers ---------------

    async def send_stream_with_flow(
        self,
        stream_id: str,
        chunks: List[Union[str, bytes]],
        chunk_timeout_sec: Optional[float] = None,
    ) -> None:
        """
        Send STREAM_CHUNKs obeying credits for given stream.
        The peer must replenish credits via FLOW_CREDIT.
        """
        for i, ch in enumerate(chunks, start=1):
            await self.flow.acquire(stream_id, 1, timeout=chunk_timeout_sec)
            await self.send(msg_stream_chunk(stream_id, i, ch, final=False))
        await self.send(msg_stream_end(stream_id, status="ok"))

# ======================================================================================
# Minimal server-side usage (example)
# ======================================================================================
"""
Пример интеграции с FastAPI/Starlette:

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from neuroforge_core.api.ws.protocols import WsSession, ProtocolSpec, msg_flow_credit, MessageType

router = APIRouter()

@router.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    session = WsSession(ws, ProtocolSpec())
    try:
        await session.handshake_server(require_auth=False)
        # ожидание сообщений
        while True:
            msg = await session.recv()
            t = msg.get("type")
            if t == MessageType.FLOW_CREDIT.value:
                session.flow.offer(msg["stream"], int(msg.get("credits", 0)))
            elif t == MessageType.REQUEST.value and msg.get("route") == "echo":
                stream_id = str(uuid.uuid4())
                await session.send(msg_stream_start(stream_id, route="echo"))
                payload = msg.get("payload", {})
                data = (payload.get("text") or "ok").encode("utf-8")
                # выдадим 1 чанк; ждём кредит от клиента
                await session.flow.acquire(stream_id, 1, timeout=5.0)
                await session.send(msg_stream_chunk(stream_id, 1, data, final=True))
                await session.send(msg_stream_end(stream_id))
            elif t == MessageType.HEARTBEAT.value and msg.get("ping"):
                # ответим pong
                await session.send(msg_heartbeat(ping=False, seq=msg.get("seq", 0)))
    except WebSocketDisconnect:
        pass
    except Exception:
        await session.close()
"""

# ======================================================================================
# Validation helpers (optional, lightweight)
# ======================================================================================

def validate_message_basic(msg: Dict[str, Any]) -> None:
    """
    Lightweight, allocation-friendly validation for critical fields.
    Raises ProtocolError if invalid.
    """
    t = msg.get("type")
    if not isinstance(t, str):
        raise ProtocolError("missing type")
    if t not in {mt.value for mt in MessageType}:
        raise ProtocolError(f"unknown type {t}")
    if "id" in msg and not isinstance(msg["id"], str):
        raise ProtocolError("id must be string")
    if "ts" in msg and not isinstance(msg["ts"], int):
        raise ProtocolError("ts must be int")

# ======================================================================================
# Public API surface
# ======================================================================================

__all__ = [
    "PROTOCOL_NAME",
    "PROTOCOL_VERSION",
    "ProtocolSpec",
    "WsSession",
    "FlowController",
    "MessageType",
    "ErrorCode",
    "AuthMode",
    "CodecName",
    "CloseReason",
    "Codec",
    "JSON_CODEC",
    "MSGPACK_CODEC",
    # message builders
    "msg_client_hello",
    "msg_server_hello",
    "msg_request",
    "msg_stream_start",
    "msg_stream_chunk",
    "msg_stream_end",
    "msg_flow_credit",
    "msg_heartbeat",
    "msg_ack",
    "msg_nack",
    "msg_error",
    "msg_close",
    # validation
    "validate_message_basic",
    # utils
    "now_ms",
    "gen_id",
    "b64e",
    "b64d",
]
