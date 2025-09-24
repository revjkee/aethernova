# datafabric-core/api/ws/protocols.py
# -*- coding: utf-8 -*-
"""
Industrial-grade WebSocket protocols layer for DataFabric.

Features:
- Protocol negotiation & registry (versioned)
- Deterministic JSON serialization, optional MessagePack (if available)
- HMAC-SHA256 message signing (optional), replay & freshness guards
- Rate limiting (token bucket) and backpressure awareness
- Heartbeat (ping/pong) with timeouts
- Structured error model & close codes
- Tracing hooks (on_encode/on_decode/on_send/on_receive)
- Framework-agnostic WebSocket adapter (compatible with Starlette/FastAPI)
- Two reference protocols:
    * DataFabric v1 (enveloped messages)
    * JSON-RPC 2.0

This module has no hard external deps; msgpack is optional.
"""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    Mapping,
    MutableMapping,
    Optional,
    Protocol as TypingProtocol,
    Tuple,
    Type,
    Union,
    runtime_checkable,
)

# ---- Constants & Version ----

BUILD_VERSION = "1.0.0"
DEFAULT_PROTOCOL = "df.v1"
DEFAULT_ENCODING = "json"
DEFAULT_HEARTBEAT_INTERVAL = 25.0  # seconds
DEFAULT_HEARTBEAT_TIMEOUT = 10.0   # seconds
DEFAULT_MAX_MESSAGE_BYTES = 1_000_000  # 1 MB safe default
DEFAULT_RATE_LIMIT_RPS = 50.0
DEFAULT_RATE_BURST = 100

# ---- Optional msgpack support (no hard dep) ----
try:
    import msgpack  # type: ignore
    _MSGPACK_AVAILABLE = True
except Exception:  # pragma: no cover
    msgpack = None  # type: ignore
    _MSGPACK_AVAILABLE = False


# ---- WebSocket adapter protocol (duck-typed for Starlette/FastAPI) ----

@runtime_checkable
class WebSocketLike(TypingProtocol):
    """Minimal interface compatible with starlette.websockets.WebSocket."""

    async def accept(self, subprotocol: Optional[str] = None) -> None: ...
    async def close(self, code: int = 1000) -> None: ...
    async def send_text(self, data: str) -> None: ...
    async def send_bytes(self, data: bytes) -> None: ...
    async def receive_text(self) -> str: ...
    async def receive_bytes(self) -> bytes: ...
    # Optional ping/pong (Starlette exposes it via send/receive bytes only)
    # We will emulate ping/pong inside the protocol using messages if needed.


# ---- Enums & error codes ----

class Encoding(str, Enum):
    JSON = "json"
    MSGPACK = "msgpack"


class Compression(str, Enum):
    NONE = "none"
    # Placeholders for future permessage-deflate negotiation, etc.
    # PERMESSAGE_DEFLATE = "permessage-deflate"


class CloseCode(IntEnum):
    NORMAL = 1000
    GOING_AWAY = 1001
    PROTOCOL_ERROR = 1002
    UNSUPPORTED_DATA = 1003
    NO_STATUS_RCVD = 1005
    ABNORMAL_CLOSURE = 1006
    INVALID_FRAME = 1007
    POLICY_VIOLATION = 1008
    MESSAGE_TOO_BIG = 1009
    MANDATORY_EXT = 1010
    INTERNAL_ERROR = 1011
    SERVICE_RESTART = 1012
    TRY_AGAIN_LATER = 1013
    BAD_GATEWAY = 1014
    TLS_HANDSHAKE = 1015


class ErrorCode(IntEnum):
    OK = 0
    INVALID_REQUEST = 10001
    UNAUTHORIZED = 10002
    FORBIDDEN = 10003
    METHOD_NOT_FOUND = 10004
    TIMEOUT = 10005
    RATE_LIMITED = 10006
    UNSUPPORTED_PROTOCOL = 10007
    UNSUPPORTED_ENCODING = 10008
    MESSAGE_TOO_LARGE = 10009
    DECODE_ERROR = 10010
    ENCODE_ERROR = 10011
    INTERNAL_ERROR = 10012
    HEARTBEAT_TIMEOUT = 10013
    SIGNATURE_INVALID = 10014
    REPLAY_DETECTED = 10015


# ---- Exceptions ----

class ProtocolError(Exception):
    def __init__(self, code: ErrorCode, message: str, data: Optional[dict] = None):
        super().__init__(message)
        self.code = int(code)
        self.data = data or {}


# ---- Tracing hooks ----

TraceContext = contextvars.ContextVar("trace_context", default={})


@dataclass
class TraceHooks:
    on_encode: Optional[Callable[[str, Any], None]] = None
    on_decode: Optional[Callable[[str, Any], None]] = None
    on_send: Optional[Callable[[Mapping[str, Any]], None]] = None
    on_receive: Optional[Callable[[Mapping[str, Any]], None]] = None


# ---- Utilities ----

def _deterministic_json_dumps(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def _utc_ms() -> int:
    return int(time.time() * 1000)


def _gen_id() -> str:
    return uuid.uuid4().hex


def _hmac_sha256(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()


# ---- Token bucket rate limiter ----

class TokenBucket:
    def __init__(self, rate: float, burst: int):
        self.rate = float(rate)
        self.capacity = int(burst)
        self.tokens = float(burst)
        self.updated = time.monotonic()

    def allow(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = max(0.0, now - self.updated)
        self.updated = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


# ---- Codecs ----

class Codec(TypingProtocol):
    encoding: Encoding

    def encode(self, payload: Mapping[str, Any]) -> Union[str, bytes]: ...
    def decode(self, data: Union[str, bytes]) -> Mapping[str, Any]: ...


class JsonCodec:
    encoding: Encoding = Encoding.JSON

    def encode(self, payload: Mapping[str, Any]) -> str:
        try:
            return _deterministic_json_dumps(payload)
        except Exception as exc:
            raise ProtocolError(ErrorCode.ENCODE_ERROR, f"JSON encode failed: {exc}")

    def decode(self, data: Union[str, bytes]) -> Mapping[str, Any]:
        try:
            if isinstance(data, bytes):
                data = data.decode("utf-8")
            return json.loads(data)
        except Exception as exc:
            raise ProtocolError(ErrorCode.DECODE_ERROR, f"JSON decode failed: {exc}")


class MsgpackCodec:
    encoding: Encoding = Encoding.MSGPACK

    def __init__(self) -> None:
        if not _MSGPACK_AVAILABLE:
            raise ProtocolError(ErrorCode.UNSUPPORTED_ENCODING, "msgpack is not available")

    def encode(self, payload: Mapping[str, Any]) -> bytes:
        try:
            assert msgpack is not None
            return msgpack.packb(payload, use_bin_type=True)
        except Exception as exc:
            raise ProtocolError(ErrorCode.ENCODE_ERROR, f"msgpack encode failed: {exc}")

    def decode(self, data: Union[str, bytes]) -> Mapping[str, Any]:
        try:
            assert msgpack is not None
            if isinstance(data, str):
                data = data.encode("utf-8")
            obj = msgpack.unpackb(data, raw=False)
            if not isinstance(obj, dict):
                raise ValueError("top-level object must be a map")
            return obj
        except Exception as exc:
            raise ProtocolError(ErrorCode.DECODE_ERROR, f"msgpack decode failed: {exc}")


def make_codec(encoding: Union[str, Encoding]) -> Codec:
    enc = Encoding(encoding)
    if enc is Encoding.JSON:
        return JsonCodec()
    if enc is Encoding.MSGPACK:
        return MsgpackCodec()
    raise ProtocolError(ErrorCode.UNSUPPORTED_ENCODING, f"Unsupported encoding: {encoding}")


# ---- Base protocol ----

@dataclass
class SecurityConfig:
    hmac_key: Optional[bytes] = None
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES
    freshness_ms: int = 60_000  # anti-replay freshness window


@dataclass
class FlowPolicy:
    rate_rps: float = DEFAULT_RATE_LIMIT_RPS
    burst: int = DEFAULT_RATE_BURST
    backpressure_high: int = 100  # queued outgoing messages threshold
    backpressure_low: int = 20


@dataclass
class HeartbeatPolicy:
    interval: float = DEFAULT_HEARTBEAT_INTERVAL
    timeout: float = DEFAULT_HEARTBEAT_TIMEOUT


@dataclass
class Negotiation:
    protocol: str = DEFAULT_PROTOCOL
    version: str = "1"
    encoding: Encoding = Encoding.JSON
    compression: Compression = Compression.NONE
    subprotocol: Optional[str] = None


@dataclass
class BaseProtocol:
    """Base class for all WebSocket protocols."""

    ws: WebSocketLike
    negotiation: Negotiation
    security: SecurityConfig = field(default_factory=SecurityConfig)
    flow: FlowPolicy = field(default_factory=FlowPolicy)
    heartbeat: HeartbeatPolicy = field(default_factory=HeartbeatPolicy)
    trace: TraceHooks = field(default_factory=TraceHooks)

    # runtime state
    _codec: Codec = field(init=False)
    _limiter: TokenBucket = field(init=False)
    _outgoing_queue: asyncio.Queue = field(init=False, repr=False)
    _closed: bool = field(default=False, init=False)
    _last_seen_ts: int = field(default_factory=_utc_ms, init=False)
    _recent_nonces: MutableMapping[str, int] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        self._codec = make_codec(self.negotiation.encoding)
        self._limiter = TokenBucket(self.flow.rate_rps, self.flow.burst)
        self._outgoing_queue = asyncio.Queue(maxsize=self.flow.backpressure_high)

    # ---- Lifecycle ----

    async def accept(self) -> None:
        # Subprotocol is optional; can be used for "df.v1-json" style
        sub = self.negotiation.subprotocol or f"{self.negotiation.protocol}+{self.negotiation.encoding.value}"
        await self.ws.accept(subprotocol=sub)

    async def close(self, code: CloseCode = CloseCode.NORMAL) -> None:
        if not self._closed:
            self._closed = True
            await self.ws.close(int(code))

    # ---- Heartbeat ----

    async def start_heartbeat(self) -> None:
        async def _hb():
            while not self._closed:
                await asyncio.sleep(self.heartbeat.interval)
                if self._closed:
                    return
                now = _utc_ms()
                if now - self._last_seen_ts > int((self.heartbeat.interval + self.heartbeat.timeout) * 1000):
                    await self.error_close(ErrorCode.HEARTBEAT_TIMEOUT, "Heartbeat timeout", CloseCode.ABNORMAL_CLOSURE)
                    return
                # Protocol-level ping can be a control event/message
                try:
                    await self.send_control({"op": "ping", "ts": now})
                except Exception:
                    await self.error_close(ErrorCode.INTERNAL_ERROR, "Heartbeat send failed", CloseCode.ABNORMAL_CLOSURE)
                    return
        asyncio.create_task(_hb())

    # ---- Send/Receive primitives ----

    async def send_payload(self, payload: Mapping[str, Any]) -> None:
        """Encode and send payload via selected codec with flow control."""
        if not self._limiter.allow():
            raise ProtocolError(ErrorCode.RATE_LIMITED, "Outgoing rate limited")

        if self.trace.on_encode:
            self.trace.on_encode(self.negotiation.encoding.value, payload)

        encoded = self._codec.encode(payload)
        size = len(encoded.encode("utf-8")) if isinstance(encoded, str) else len(encoded)
        if size > self.security.max_message_bytes:
            raise ProtocolError(ErrorCode.MESSAGE_TOO_LARGE, f"Message too large: {size} bytes")

        if self.trace.on_send:
            self.trace.on_send(payload)

        # Backpressure-aware queueing
        try:
            self._outgoing_queue.put_nowait((encoded, isinstance(encoded, str)))
        except asyncio.QueueFull:
            raise ProtocolError(ErrorCode.RATE_LIMITED, "Backpressure: outgoing queue full")

        # drain in background
        asyncio.create_task(self._drain_outgoing())

    async def _drain_outgoing(self) -> None:
        while not self._outgoing_queue.empty():
            data, is_text = await self._outgoing_queue.get()
            if self._closed:
                return
            if is_text:
                await self.ws.send_text(data)  # type: ignore[arg-type]
            else:
                await self.ws.send_bytes(data)  # type: ignore[arg-type]
            # Dynamic backpressure relief could adjust limiter capacity, omitted for brevity

    async def receive_payload(self) -> Mapping[str, Any]:
        """Receive and decode payload; autodetect text/bytes."""
        # No pull-based rate limit here; rely on application or push backpressure
        data: Union[str, bytes]
        try:
            # Prefer text path; Starlette raises if frame type mismatches
            try:
                data = await self.ws.receive_text()
            except Exception:
                data = await self.ws.receive_bytes()
        except Exception as exc:
            raise ProtocolError(ErrorCode.INTERNAL_ERROR, f"Receive failed: {exc}")

        self._last_seen_ts = _utc_ms()
        decoded = self._codec.decode(data)

        if self.trace.on_decode:
            self.trace.on_decode(self.negotiation.encoding.value, decoded)
        if self.trace.on_receive:
            self.trace.on_receive(decoded)

        self._verify_envelope(decoded)
        return decoded

    # ---- Envelope security ----

    def _verify_envelope(self, msg: Mapping[str, Any]) -> None:
        """Verify base fields, size, freshness and optional signature."""
        # Mandatory fields (id, ts) in reference protocols; JSON-RPC differs
        mid = msg.get("id")
        ts = msg.get("ts")
        nonce = msg.get("nonce")
        sig = msg.get("sig")

        # Freshness only when ts present (df.v1)
        if ts is not None:
            if not isinstance(ts, int):
                raise ProtocolError(ErrorCode.INVALID_REQUEST, "ts must be int(utc_ms)")
            if abs(_utc_ms() - ts) > self.security.freshness_ms:
                raise ProtocolError(ErrorCode.REPLAY_DETECTED, "stale message")

        if nonce is not None:
            if not isinstance(nonce, str) or len(nonce) < 8:
                raise ProtocolError(ErrorCode.INVALID_REQUEST, "invalid nonce")
            # keep a tiny LRU window to avoid unbounded growth
            if nonce in self._recent_nonces:
                raise ProtocolError(ErrorCode.REPLAY_DETECTED, "replay nonce")
            self._recent_nonces[nonce] = _utc_ms()
            # cleanup old nonces
            if len(self._recent_nonces) > 2048:
                cutoff = _utc_ms() - self.security.freshness_ms
                for k in list(self._recent_nonces.keys()):
                    if self._recent_nonces[k] < cutoff:
                        del self._recent_nonces[k]

        if sig is not None:
            if not self.security.hmac_key:
                raise ProtocolError(ErrorCode.UNAUTHORIZED, "signature provided but HMAC key not configured")
            payload_for_sig = dict(msg)
            payload_for_sig.pop("sig", None)
            raw = _deterministic_json_dumps(payload_for_sig).encode("utf-8")
            expected = _hmac_sha256(self.security.hmac_key, raw)
            if not hmac.compare_digest(expected, str(sig)):
                raise ProtocolError(ErrorCode.SIGNATURE_INVALID, "HMAC verification failed")

        # Optional check for id shape
        if mid is not None and (not isinstance(mid, str) or len(mid) < 8):
            raise ProtocolError(ErrorCode.INVALID_REQUEST, "invalid id")

    # ---- Protocol-specific hooks (to override) ----

    async def on_connect(self) -> None:
        """Called after accept(); perform auth/handshake here."""
        return

    async def on_message(self, msg: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
        """Process a decoded message and optionally return a response."""
        raise NotImplementedError

    async def send_control(self, payload: Mapping[str, Any]) -> None:
        """Send control envelope (op codes); default wraps as df.v1 control."""
        control = {
            "id": _gen_id(),
            "ts": _utc_ms(),
            "nonce": _gen_id(),
            "op": "control",
            "ctrl": payload,
            "v": self.negotiation.version,
            "p": self.negotiation.protocol,
        }
        if self.security.hmac_key:
            sig_raw = dict(control)
            raw = _deterministic_json_dumps({k: sig_raw[k] for k in sorted(sig_raw) if k != "sig"}).encode("utf-8")
            control["sig"] = _hmac_sha256(self.security.hmac_key, raw)
        await self.send_payload(control)

    async def send_error(self, code: ErrorCode, message: str, data: Optional[dict] = None) -> None:
        err = {
            "id": _gen_id(),
            "ts": _utc_ms(),
            "nonce": _gen_id(),
            "op": "error",
            "error": {"code": int(code), "message": message, "data": data or {}},
            "v": self.negotiation.version,
            "p": self.negotiation.protocol,
        }
        if self.security.hmac_key:
            sig_raw = dict(err)
            raw = _deterministic_json_dumps({k: sig_raw[k] for k in sorted(sig_raw) if k != "sig"}).encode("utf-8")
            err["sig"] = _hmac_sha256(self.security.hmac_key, raw)
        await self.send_payload(err)

    async def error_close(self, code: ErrorCode, message: str, ws_code: CloseCode = CloseCode.PROTOCOL_ERROR) -> None:
        try:
            await self.send_error(code, message)
        finally:
            await self.close(ws_code)


# ---- DataFabric v1 Protocol ----

class DataFabricV1Protocol(BaseProtocol):
    """
    Envelope:
    {
      "id": "<uuid4-hex>",
      "ts": <utc_ms>,
      "nonce": "<uuid4-hex>",
      "op": "<command|event|control|error>",
      "chan": "orders/submit",     # optional channel
      "data": {...},               # payload
      "v": "1",
      "p": "df.v1",
      "sig": "<hex hmac>"          # optional
    }
    """

    async def on_connect(self) -> None:
        await self.start_heartbeat()
        # Example welcome control
        await self.send_control({"op": "welcome", "build": BUILD_VERSION})

    async def on_message(self, msg: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
        op = str(msg.get("op") or "")
        if op not in {"command", "event", "control"}:
            raise ProtocolError(ErrorCode.INVALID_REQUEST, f"unsupported op: {op}")

        # Example echo for command
        if op == "command":
            data = msg.get("data") or {}
            response = {
                "id": msg.get("id") or _gen_id(),
                "ts": _utc_ms(),
                "nonce": _gen_id(),
                "op": "event",
                "chan": msg.get("chan") or "echo/response",
                "data": {"ok": True, "echo": data},
                "v": self.negotiation.version,
                "p": self.negotiation.protocol,
            }
            if self.security.hmac_key:
                sig_raw = dict(response)
                raw = _deterministic_json_dumps({k: sig_raw[k] for k in sorted(sig_raw) if k != "sig"}).encode("utf-8")
                response["sig"] = _hmac_sha256(self.security.hmac_key, raw)
            return response

        # For 'event' or 'control' we might not respond
        return None


# ---- JSON-RPC 2.0 Protocol ----

class JsonRpc2Protocol(BaseProtocol):
    """
    Minimal JSON-RPC 2.0 over WebSocket.

    Request:
      {"jsonrpc":"2.0","id":<str|int|null>,"method":"sum","params":[1,2,3]}

    Response:
      {"jsonrpc":"2.0","id":1,"result":6}
      or
      {"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid Request"}}

    Heartbeat/control messages are wrapped in df.v1 control envelopes via send_control().
    """

    async def on_connect(self) -> None:
        await self.start_heartbeat()
        await self.send_control({"op": "welcome-jsonrpc", "build": BUILD_VERSION})

    def _validate_request(self, msg: Mapping[str, Any]) -> None:
        if msg.get("jsonrpc") != "2.0":
            raise ProtocolError(ErrorCode.INVALID_REQUEST, "jsonrpc must be '2.0'")
        if "method" not in msg or not isinstance(msg["method"], str):
            raise ProtocolError(ErrorCode.INVALID_REQUEST, "method must be a string")

    async def on_message(self, msg: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
        # JSON-RPC has different envelope; override verification gently
        # Still leverage base freshness/replay if present
        try:
            self._validate_request(msg)
        except ProtocolError:
            # Map to JSON-RPC error shape
            return {
                "jsonrpc": "2.0",
                "id": msg.get("id"),
                "error": {"code": -32600, "message": "Invalid Request"},
            }

        method = msg["method"]
        params = msg.get("params", [])

        # Simple method router example
        if method == "ping":
            return {"jsonrpc": "2.0", "id": msg.get("id"), "result": {"ts": _utc_ms()}}
        elif method == "sum":
            try:
                total = sum(params if isinstance(params, list) else [])
                return {"jsonrpc": "2.0", "id": msg.get("id"), "result": total}
            except Exception:
                return {"jsonrpc": "2.0", "id": msg.get("id"), "error": {"code": -32602, "message": "Invalid params"}}
        else:
            return {"jsonrpc": "2.0", "id": msg.get("id"), "error": {"code": -32601, "message": "Method not found"}}


# ---- Protocol registry & factory ----

class ProtocolFactory(TypingProtocol):
    def __call__(self, ws: WebSocketLike, negotiation: Negotiation, **kwargs: Any) -> BaseProtocol: ...


class ProtocolRegistry:
    _protocols: Dict[Tuple[str, str], ProtocolFactory] = {}

    @classmethod
    def register(cls, name: str, version: str, factory: ProtocolFactory) -> None:
        key = (name, version)
        cls._protocols[key] = factory

    @classmethod
    def create(cls, name: str, version: str, ws: WebSocketLike, **kwargs: Any) -> BaseProtocol:
        key = (name, version)
        if key not in cls._protocols:
            raise ProtocolError(ErrorCode.UNSUPPORTED_PROTOCOL, f"Unknown protocol {name} v{version}")
        negotiation = Negotiation(protocol=name, version=version, encoding=kwargs.pop("encoding", Encoding.JSON))
        return cls._protocols[key](ws, negotiation, **kwargs)

    @classmethod
    def negotiate_from_headers(
        cls,
        ws: WebSocketLike,
        requested: Iterable[str],
        default: str = DEFAULT_PROTOCOL,
        encoding: str = DEFAULT_ENCODING,
        **kwargs: Any,
    ) -> BaseProtocol:
        """
        requested: iterable of proposed subprotocols from client (Sec-WebSocket-Protocol).
        Expected formats: "df.v1+json", "jsonrpc2+json", plain "df.v1".
        """
        chosen: Optional[Tuple[str, str, Encoding]] = None

        def parse(sp: str) -> Tuple[str, str, Encoding]:
            if "+" in sp:
                proto, enc = sp.split("+", 1)
                return proto, "1" if "." not in proto else proto.split(".")[-1], Encoding(enc)
            else:
                # fallback assumes version after dot
                ver = "1"
                if "." in sp:
                    try:
                        ver = sp.split(".")[-1]
                        int(ver)
                    except Exception:
                        ver = "1"
                return sp, ver, Encoding(encoding)

        for sp in requested:
            try:
                p, v, enc_enum = parse(sp)
                key = (p, v)
                if key in cls._protocols:
                    chosen = (p, v, enc_enum)
                    break
            except Exception:
                continue

        if not chosen:
            # fallback to default
            if (default, "1") not in cls._protocols:
                raise ProtocolError(ErrorCode.UNSUPPORTED_PROTOCOL, "No compatible protocol found")
            chosen = (default, "1", Encoding(encoding))

        p, v, enc_enum = chosen
        neg = Negotiation(protocol=p, version=v, encoding=enc_enum, subprotocol=f"{p}+{enc_enum.value}")
        factory = cls._protocols[(p, v)]
        return factory(ws, neg, **kwargs)


# Register built-in protocols
ProtocolRegistry.register("df.v1", "1", lambda ws, neg, **kw: DataFabricV1Protocol(ws, neg, **kw))
ProtocolRegistry.register("jsonrpc2", "1", lambda ws, neg, **kw: JsonRpc2Protocol(ws, neg, **kw))


# ---- High-level session loop helper ----

async def serve_protocol(
    proto: BaseProtocol,
    handler: Optional[Callable[[Mapping[str, Any]], Awaitable[Optional[Mapping[str, Any]]]]] = None,
) -> None:
    """
    Generic receive/process/send loop:
      - Accept & on_connect
      - Receive messages
      - Route to protocol.on_message (or external handler)
      - Send responses (if any)
      - Structured error handling and close
    """
    try:
        await proto.accept()
        await proto.on_connect()

        while True:
            try:
                msg = await proto.receive_payload()
                responder = handler or proto.on_message
                resp = await responder(msg)
                if resp is not None:
                    await proto.send_payload(resp)
            except ProtocolError as pe:
                await proto.send_error(ErrorCode(pe.code), str(pe), getattr(pe, "data", {}))
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                await proto.send_error(ErrorCode.INTERNAL_ERROR, f"Unhandled error: {exc}")
    except asyncio.CancelledError:
        await proto.close(CloseCode.GOING_AWAY)
        raise
    except ProtocolError as pe:
        await proto.error_close(ErrorCode(pe.code), str(pe), CloseCode.PROTOCOL_ERROR)
    except Exception as exc:
        await proto.error_close(ErrorCode.INTERNAL_ERROR, f"Fatal error: {exc}", CloseCode.INTERNAL_ERROR)


# ---- FastAPI/Starlette integration example (reference) ----
# This is reference-only and can be used in the FastAPI route:
#
# from fastapi import APIRouter, WebSocket, WebSocketDisconnect
# router = APIRouter()
#
# @router.websocket("/ws")
# async def ws_endpoint(ws: WebSocket):
#     await ws.accept(subprotocol=None)  # preliminary accept; some ASGI stacks require it
#     # In Starlette, requested_subprotocols are provided by headers, not parsed automatically.
#     # If you have the raw Sec-WebSocket-Protocol headers, pass them here.
#     requested = []  # e.g., ["df.v1+json", "jsonrpc2+json"]
#     proto = ProtocolRegistry.negotiate_from_headers(
#         ws,
#         requested=requested or ["df.v1+json"],
#         encoding="json",
#         security=SecurityConfig(hmac_key=None),
#         flow=FlowPolicy(),
#         heartbeat=HeartbeatPolicy(),
#     )
#     await serve_protocol(proto)
#
# Note: If your server auto-negotiates subprotocol during accept(), adapt the flow:
#       1) Parse headers manually
#       2) Build proto via Registry
#       3) Call proto.accept() (which will sub-accept with chosen subprotocol)


# ---- End of module ----
