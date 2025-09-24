# cybersecurity-core/api/ws/protocols.py
# Industrial WebSocket protocol utilities for cybersecurity-core
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, List, Optional, Set, Tuple, Union
from uuid import UUID, uuid4

try:
    # Starlette/FastAPI types
    from starlette.websockets import WebSocket, WebSocketDisconnect
except Exception as e:  # pragma: no cover
    raise RuntimeError("starlette.websockets is required") from e

try:
    # Project settings & principal (provided elsewhere)
    from cybersecurity_core.settings import Settings, get_settings  # noqa: F401
except Exception:  # pragma: no cover
    @dataclass
    class Settings:
        ws_allowed_subprotocols: Tuple[str, ...] = ("aethernova.ws.v1", "json")
        ws_heartbeat_interval_sec: int = 20
        ws_client_timeout_sec: int = 60
        ws_max_message_bytes: int = 1_000_000
        ws_out_queue_max: int = 10_000
        ws_in_rate_per_sec: int = 50
        ws_in_burst: int = 200
        ws_hmac_secret: Optional[str] = None
        api_etag_salt: str = "etag-salt"

    async def get_settings() -> Settings:
        return Settings()

try:
    from cybersecurity_core.auth.models import Principal  # org_id: Optional[UUID], roles: List[str], sub: str
except Exception:  # pragma: no cover
    @dataclass
    class Principal:
        sub: str
        org_id: Optional[UUID] = None
        roles: List[str] = None  # type: ignore


logger = logging.getLogger("cybersecurity_core.api.ws.protocols")


# =========================
# Protocol primitives
# =========================

class WSOp(str, Enum):
    HELLO = "hello"          # <- client
    WELCOME = "welcome"      # -> server
    SUBSCRIBE = "subscribe"  # <- client
    UNSUBSCRIBE = "unsubscribe"  # <- client
    EVENT = "event"          # -> server
    ACK = "ack"              # -> server
    NACK = "nack"            # -> server
    ERROR = "error"          # -> server
    PING = "ping"            # <-> both
    PONG = "pong"            # <-> both
    BYE = "bye"              # -> server (graceful shutdown notice)


class Channel(str, Enum):
    scans = "scans"
    findings = "findings"
    alerts = "alerts"
    metrics = "metrics"


CloseCode = int  # RFC 6455 codes


def utc_now_ts_ms() -> int:
    return int(time.time() * 1000)


def json_dumps(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False, default=str)


# =========================
# Message schema (envelope)
# =========================

class ValidationError(Exception):
    pass


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise ValidationError(msg)


def validate_envelope(data: Dict[str, Any]) -> None:
    _require(isinstance(data, dict), "payload must be object")
    _require("op" in data and isinstance(data["op"], str), "op missing or invalid")
    # Optional fields
    if "cid" in data:
        _require(isinstance(data["cid"], str) and 1 <= len(data["cid"]) <= 64, "cid invalid")
    if "chan" in data:
        _require(isinstance(data["chan"], str) and 1 <= len(data["chan"]) <= 64, "chan invalid")
    if "ts" in data:
        _require(isinstance(data["ts"], int) and 0 <= data["ts"] <= 10**13, "ts invalid")
    if "ver" in data:
        _require(data["ver"] in ("1", "v1"), "ver invalid")
    # payload may be any JSON type (object recommended)


def validate_subscribe_payload(payload: Any) -> Tuple[Channel, Dict[str, Any]]:
    if not isinstance(payload, dict):
        raise ValidationError("subscribe payload must be object")
    chan = payload.get("channel")
    _require(isinstance(chan, str), "channel must be string")
    try:
        channel = Channel(chan)
    except ValueError:
        raise ValidationError("unknown channel")
    # optional filters
    flt = payload.get("filters") or {}
    _require(isinstance(flt, dict), "filters must be object")
    return channel, flt


def validate_unsubscribe_payload(payload: Any) -> Channel:
    if not isinstance(payload, dict):
        raise ValidationError("unsubscribe payload must be object")
    chan = payload.get("channel")
    _require(isinstance(chan, str), "channel must be string")
    try:
        return Channel(chan)
    except ValueError:
        raise ValidationError("unknown channel")


# =========================
# Token bucket rate limiter
# =========================

class TokenBucket:
    def __init__(self, rate_per_sec: int, burst: int) -> None:
        self.rate = max(1, rate_per_sec)
        self.burst = max(1, burst)
        self.tokens = float(burst)
        self.updated = time.monotonic()

    def consume(self, amount: float = 1.0) -> bool:
        now = time.monotonic()
        delta = now - self.updated
        self.updated = now
        self.tokens = min(self.burst, self.tokens + delta * self.rate)
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False


# =========================
# Public callback interfaces
# =========================

OnAuthorize = Callable[[WebSocket], Awaitable[Principal]]
OnSubscribe = Callable[[Channel, Dict[str, Any], Principal], Awaitable[None]]
OnUnsubscribe = Callable[[Channel, Principal], Awaitable[None]]
OnClientMessage = Callable[[Dict[str, Any], Principal], Awaitable[None]]
OnDisconnect = Callable[[Principal], Awaitable[None]]


# =========================
# Protocol class
# =========================

class WsProtocol:
    """
    High-level WebSocket protocol for cybersecurity-core.

    Usage (FastAPI endpoint):

        async def authorize(ws: WebSocket) -> Principal:
            token = ws.headers.get("authorization", "").removeprefix("Bearer ").strip()
            # ... verify token, return Principal
            return principal

        async def on_subscribe(channel: Channel, filters: Dict[str, Any], principal: Principal) -> None:
            # register subscription in hub, attach filters to connection id
            ...

        async def on_unsubscribe(channel: Channel, principal: Principal) -> None:
            ...

        async def on_client_message(msg: Dict[str, Any], principal: Principal) -> None:
            # optional custom messages
            ...

        async def on_disconnect(principal: Principal) -> None:
            ...

        @app.websocket("/api/ws")
        async def ws_endpoint(ws: WebSocket):
            settings = await get_settings()
            proto = WsProtocol(ws, settings=settings, allowed_subprotocols=settings.ws_allowed_subprotocols)
            await proto.accept()
            principal = await proto.authorize(authorizer=authorize)
            await proto.run_loop(on_subscribe, on_unsubscribe, on_client_message, on_disconnect)
    """

    def __init__(
        self,
        ws: WebSocket,
        *,
        settings: Settings,
        allowed_subprotocols: Tuple[str, ...] = ("aethernova.ws.v1", "json"),
        hmac_secret: Optional[str] = None,
        connection_id: Optional[str] = None,
    ) -> None:
        self.ws = ws
        self.settings = settings
        self.allowed_subprotocols = allowed_subprotocols
        self.hmac_secret = hmac_secret or getattr(settings, "ws_hmac_secret", None)
        self.connection_id = connection_id or str(uuid4())
        self.accepted_subprotocol: Optional[str] = None

        # State
        self._principal: Optional[Principal] = None
        self._subscriptions: Set[Channel] = set()
        self._filters: Dict[Channel, Dict[str, Any]] = {}
        self._closed = False

        # Flow control
        self._out_queue: asyncio.Queue[Tuple[str, Dict[str, Any]]] = asyncio.Queue(
            maxsize=getattr(settings, "ws_out_queue_max", 10_000)
        )
        self._in_rate = TokenBucket(getattr(settings, "ws_in_rate_per_sec", 50),
                                    getattr(settings, "ws_in_burst", 200))

        # Housekeeping
        self._last_recv_ts: float = time.monotonic()
        self._ping_task: Optional[asyncio.Task] = None
        self._send_task: Optional[asyncio.Task] = None
        self._recv_task: Optional[asyncio.Task] = None

    # ----- Negotiation & accept -----

    def _choose_subprotocol(self) -> Optional[str]:
        hdr = self.ws.headers.get("sec-websocket-protocol", "")
        requested = [s.strip() for s in hdr.split(",") if s.strip()]
        for sp in requested:
            if sp in self.allowed_subprotocols:
                return sp
        # Fallback to first allowed if client did not offer any acceptable subprotocols
        return self.allowed_subprotocols[0] if self.allowed_subprotocols else None

    async def accept(self) -> None:
        chosen = self._choose_subprotocol()
        await self.ws.accept(subprotocol=chosen)
        self.accepted_subprotocol = chosen
        logger.debug("WS accepted, subprotocol=%s, conn_id=%s", chosen, self.connection_id)

    # ----- Authorization -----

    async def authorize(self, *, authorizer: OnAuthorize) -> Principal:
        principal = await authorizer(self.ws)
        if not isinstance(principal, Principal):
            raise RuntimeError("authorize() must return Principal")
        self._principal = principal
        await self._send_welcome()
        return principal

    # ----- Public API for sending server events -----

    async def publish_event(self, channel: Channel, payload: Dict[str, Any]) -> None:
        """
        Publish event to client if subscribed to channel.
        """
        if channel not in self._subscriptions:
            return
        envelope = self._make_envelope(op=WSOp.EVENT, chan=channel.value, payload=payload)
        await self._queue_send(envelope)

    # ----- Main loop -----

    async def run_loop(
        self,
        on_subscribe: OnSubscribe,
        on_unsubscribe: OnUnsubscribe,
        on_client_message: Optional[OnClientMessage] = None,
        on_disconnect: Optional[OnDisconnect] = None,
    ) -> None:
        self._ensure_authorized()
        # Start background tasks
        self._ping_task = asyncio.create_task(self._heartbeat_loop(), name=f"ws-heartbeat-{self.connection_id}")
        self._send_task = asyncio.create_task(self._sender_loop(), name=f"ws-sender-{self.connection_id}")
        self._recv_task = asyncio.create_task(self._receiver_loop(on_subscribe, on_unsubscribe, on_client_message))

        try:
            await self._recv_task
        except WebSocketDisconnect as e:
            logger.info("WS disconnected code=%s conn_id=%s", getattr(e, "code", None), self.connection_id)
        except Exception:
            logger.exception("WS receiver error conn_id=%s", self.connection_id)
        finally:
            await self._graceful_shutdown(on_disconnect)

    # =========================
    # Internal: loops
    # =========================

    async def _sender_loop(self) -> None:
        try:
            while not self._closed:
                op, envelope = await self._out_queue.get()
                # Re-check close after awaiting
                if self._closed:
                    break
                await self._send_json(envelope)
        except Exception:
            logger.exception("WS sender failed conn_id=%s", self.connection_id)
            await self._safe_close(1011, "sender failure")

    async def _receiver_loop(
        self,
        on_subscribe: OnSubscribe,
        on_unsubscribe: OnUnsubscribe,
        on_client_message: Optional[OnClientMessage],
    ) -> None:
        while not self._closed:
            msg = await self._receive_json()
            self._last_recv_ts = time.monotonic()
            try:
                validate_envelope(msg)
                op = WSOp(msg["op"])
            except Exception as e:
                await self._send_error("invalid_message", str(e))
                await self._safe_close(1003, "invalid message")
                return

            try:
                if op == WSOp.HELLO:
                    await self._send_ack(msg)
                elif op == WSOp.SUBSCRIBE:
                    channel, flt = validate_subscribe_payload(msg.get("payload"))
                    self._subscriptions.add(channel)
                    self._filters[channel] = flt
                    await on_subscribe(channel, flt, self._principal)  # type: ignore[arg-type]
                    await self._send_ack(msg)
                elif op == WSOp.UNSUBSCRIBE:
                    channel = validate_unsubscribe_payload(msg.get("payload"))
                    self._subscriptions.discard(channel)
                    self._filters.pop(channel, None)
                    await on_unsubscribe(channel, self._principal)  # type: ignore[arg-type]
                    await self._send_ack(msg)
                elif op == WSOp.PING:
                    await self._queue_send(self._make_envelope(op=WSOp.PONG, payload={"ts": utc_now_ts_ms()}))
                else:
                    if on_client_message:
                        await on_client_message(msg, self._principal)  # type: ignore[arg-type]
                    else:
                        await self._send_nack(msg, reason="unsupported op")
            except ValidationError as ve:
                await self._send_nack(msg, reason=str(ve))
            except Exception as e:
                logger.exception("WS message handling failed")
                await self._send_error("internal_error", "handler failed")
                await self._safe_close(1011, "handler failure")
                return

    async def _heartbeat_loop(self) -> None:
        interval = getattr(self.settings, "ws_heartbeat_interval_sec", 20)
        timeout = getattr(self.settings, "ws_client_timeout_sec", 60)
        while not self._closed:
            await asyncio.sleep(interval)
            # Idle timeout
            if time.monotonic() - self._last_recv_ts > timeout:
                await self._send_error("timeout", "idle timeout")
                await self._safe_close(1001, "going away (idle)")
                return
            # Application-level ping
            await self._queue_send(self._make_envelope(op=WSOp.PING, payload={"ts": utc_now_ts_ms()}))

    # =========================
    # Internal: send/receive
    # =========================

    def _sign(self, payload_str: str) -> Optional[str]:
        if not self.hmac_secret:
            return None
        digest = hmac.new(self.hmac_secret.encode("utf-8"), payload_str.encode("utf-8"), hashlib.sha256).digest()
        return "sha256=" + base64.b64encode(digest).decode("ascii")

    def _verify(self, payload_str: str, signature: Optional[str]) -> bool:
        if not self.hmac_secret:
            return True  # signature not required
        if not signature or not signature.startswith("sha256="):
            return False
        try:
            provided = base64.b64decode(signature.split("=", 1)[1])
            expected = hmac.new(self.hmac_secret.encode("utf-8"), payload_str.encode("utf-8"), hashlib.sha256).digest()
            return hmac.compare_digest(provided, expected)
        except Exception:
            return False

    async def _queue_send(self, envelope: Dict[str, Any]) -> None:
        if self._out_queue.full():
            logger.error("WS out queue overflow conn_id=%s", self.connection_id)
            await self._safe_close(1011, "backpressure")
            return
        await self._out_queue.put((envelope.get("op", ""), envelope))

    async def _send_json(self, data: Dict[str, Any]) -> None:
        if self._closed:
            return
        txt = json_dumps(data)
        # Optional HMAC on outbound
        sig = self._sign(txt)
        headers = {}
        if sig:
            # Starlette does not support per-message headers; include in envelope
            data["sig"] = sig
            txt = json_dumps(data)
        await self.ws.send_text(txt)

    async def _receive_json(self) -> Dict[str, Any]:
        if not self._in_rate.consume(1.0):
            await self._send_error("rate_limited", "too many messages")
            await self._safe_close(1008, "rate limited")
            raise WebSocketDisconnect(1008)

        msg = await self.ws.receive()
        if "text" in msg and msg["text"] is not None:
            raw = msg["text"]
        elif "bytes" in msg and msg["bytes"] is not None:
            try:
                raw = msg["bytes"].decode("utf-8")
            except Exception:
                await self._send_error("unsupported_binary", "only UTF-8 text allowed")
                await self._safe_close(1003, "binary not supported")
                raise WebSocketDisconnect(1003)
        else:
            # e.g., close
            raise WebSocketDisconnect(1000)

        if len(raw.encode("utf-8")) > getattr(self.settings, "ws_max_message_bytes", 1_000_000):
            await self._send_error("payload_too_large", "message exceeds limit")
            await self._safe_close(1009, "message too big")
            raise WebSocketDisconnect(1009)

        try:
            data = json.loads(raw)
        except Exception:
            await self._send_error("invalid_json", "failed to decode JSON")
            await self._safe_close(1003, "bad json")
            raise WebSocketDisconnect(1003)

        # Optional HMAC verification (client -> server): expect 'sig' in envelope
        sig = data.pop("sig", None)
        if not self._verify(json_dumps(data), sig):
            await self._send_error("bad_signature", "invalid HMAC signature")
            await self._safe_close(1008, "bad signature")
            raise WebSocketDisconnect(1008)

        return data

    # =========================
    # Internal: helpers
    # =========================

    def _ensure_authorized(self) -> None:
        if not self._principal:
            raise RuntimeError("not authorized")

    def _make_envelope(
        self,
        *,
        op: WSOp,
        chan: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        cid: Optional[str] = None,
    ) -> Dict[str, Any]:
        env: Dict[str, Any] = {
            "op": op.value,
            "ts": utc_now_ts_ms(),
            "ver": "1",
            "sid": self.connection_id,
        }
        if chan:
            env["chan"] = chan
        if cid:
            env["cid"] = cid
        if payload is not None:
            env["payload"] = payload
        return env

    async def _send_ack(self, msg: Dict[str, Any]) -> None:
        await self._queue_send(self._make_envelope(op=WSOp.ACK, cid=msg.get("cid")))

    async def _send_nack(self, msg: Dict[str, Any], *, reason: str) -> None:
        await self._queue_send(
            self._make_envelope(op=WSOp.NACK, cid=msg.get("cid"), payload={"reason": reason})
        )

    async def _send_error(self, code: str, message: str) -> None:
        await self._queue_send(
            self._make_envelope(op=WSOp.ERROR, payload={"code": code, "message": message})
        )

    async def _send_welcome(self) -> None:
        principal = self._principal
        payload = {
            "connection_id": self.connection_id,
            "subprotocol": self.accepted_subprotocol,
            "user": getattr(principal, "sub", None),
            "org_id": str(getattr(principal, "org_id", "")) if getattr(principal, "org_id", None) else None,
            "roles": list(getattr(principal, "roles", []) or []),
            "server_time": datetime.now(timezone.utc).isoformat(),
        }
        await self._queue_send(self._make_envelope(op=WSOp.WELCOME, payload=payload))

    async def _safe_close(self, code: CloseCode, reason: str) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            await self.ws.close(code=code)
        except Exception:
            pass
        logger.info("WS closed code=%s reason=%s conn_id=%s", code, reason, self.connection_id)

    async def _graceful_shutdown(self, on_disconnect: Optional[OnDisconnect]) -> None:
        self._closed = True
        # Cancel tasks
        for task in (self._ping_task, self._send_task, self._recv_task):
            if task and not task.done():
                task.cancel()
        # Drain queue to free memory
        try:
            while not self._out_queue.empty():
                _ = self._out_queue.get_nowait()
        except Exception:
            pass
        # Call disconnect hook
        try:
            if on_disconnect and self._principal:
                await on_disconnect(self._principal)
        except Exception:
            logger.exception("on_disconnect hook failed")


# =========================
# Utility functions
# =========================

def compute_etag(updated_at: datetime, salt: str) -> str:
    base = f"{updated_at.replace(microsecond=0).isoformat()}|{salt}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


async def simple_bearer_authorizer(ws: WebSocket, verifier: Callable[[str], Awaitable[Principal]]) -> Principal:
    """
    Extract Bearer token from headers/query/cookie and verify it.
    """
    token = None
    auth = ws.headers.get("authorization") or ws.headers.get("Authorization")
    if auth and auth.lower().startswith("bearer "):
        token = auth[7:].strip()
    if not token:
        # Try query param
        scope = getattr(ws, "scope", {}) or {}
        query_string = scope.get("query_string", b"").decode("utf-8")
        for kv in query_string.split("&"):
            if not kv:
                continue
            k, _, v = kv.partition("=")
            if k == "access_token" and v:
                token = v
                break
    if not token:
        # Try cookie
        cookie = ws.headers.get("cookie", "")
        for pair in cookie.split(";"):
            k, _, v = pair.strip().partition("=")
            if k == "access_token" and v:
                token = v
                break
    if not token:
        raise WebSocketDisconnect(4401)  # 4401 Unauthorized (SignalR-like)
    principal = await verifier(token)
    return principal


# =========================
# Example no-op handlers (can be reused in tests)
# =========================

async def noop_subscribe(_c: Channel, _f: Dict[str, Any], _p: Principal) -> None:
    return None


async def noop_unsubscribe(_c: Channel, _p: Principal) -> None:
    return None


async def noop_client_message(_m: Dict[str, Any], _p: Principal) -> None:
    return None


async def noop_disconnect(_p: Principal) -> None:
    return None
