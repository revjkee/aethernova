# engine-core/api/ws/protocols.py
"""
Industrial-grade WebSocket protocol utilities for engine-core.

Key features:
- Handshake & negotiation:
  - Version negotiation via query/header
  - Subprotocol selection with server-side preference
  - Capability flags
- Authentication hook during handshake (pluggable, sync/async)
- Heartbeats:
  - Application-level ping/pong with monotonic timestamps
  - Watchdog for missed heartbeats and slow clients
  - Graceful close with specific WS close codes
- Backpressure & flow-control:
  - Send queue with max size & timeouts
  - Token-bucket rate limiter (messages/sec, burst)
- Structured close semantics with reasons and codes
- Observability hooks (metrics/tracing ready; no hard deps)
- Compatible with Starlette/FastAPI WebSocket interface

This module avoids framework lock-in by accepting any object that
behaves like starlette.websockets.WebSocket (has .headers, .query_params,
.accept(), .close(), .send_text(), .send_bytes(), .receive_text()/bytes()).

ENV (optional):
  WS_DEFAULT_VERSIONS=1,2
  WS_DEFAULT_SUBPROTOCOLS=json.v1,json.v2,msgpack.v1
  WS_HEARTBEAT_INTERVAL_S=20
  WS_HEARTBEAT_TIMEOUT_S=30
  WS_MAX_SEND_QUEUE=1024
  WS_SEND_TIMEOUT_S=10
  WS_RATE_LIMIT_RPS=50
  WS_RATE_LIMIT_BURST=200
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple, Union

# ---- Constants & Close Codes ----

WS_CLOSE_NORMAL = 1000
WS_CLOSE_GOING_AWAY = 1001
WS_CLOSE_PROTOCOL_ERROR = 1002
WS_CLOSE_UNSUPPORTED_DATA = 1003
WS_CLOSE_POLICY_VIOLATION = 1008
WS_CLOSE_TOO_LARGE = 1009
WS_CLOSE_EXTENSION_NEGOTIATION = 1010
WS_CLOSE_UNEXPECTED_CONDITION = 1011

DEFAULT_VERSIONS = tuple(
    int(v.strip()) for v in os.getenv("WS_DEFAULT_VERSIONS", "1,2").split(",") if v.strip()
)
DEFAULT_SUBPROTOCOLS = tuple(
    s.strip() for s in os.getenv("WS_DEFAULT_SUBPROTOCOLS", "json.v1,json.v2").split(",") if s.strip()
)

HEARTBEAT_INTERVAL_S = float(os.getenv("WS_HEARTBEAT_INTERVAL_S", "20"))
HEARTBEAT_TIMEOUT_S = float(os.getenv("WS_HEARTBEAT_TIMEOUT_S", "30"))

MAX_SEND_QUEUE = int(os.getenv("WS_MAX_SEND_QUEUE", "1024"))
SEND_TIMEOUT_S = float(os.getenv("WS_SEND_TIMEOUT_S", "10"))

RATE_LIMIT_RPS = float(os.getenv("WS_RATE_LIMIT_RPS", "50"))
RATE_LIMIT_BURST = float(os.getenv("WS_RATE_LIMIT_BURST", "200"))

PING_TYPE = "ping"
PONG_TYPE = "pong"


# ---- Exceptions ----

class ProtocolError(Exception):
    """Raised on fatal protocol violations (results in WS close)."""


class AuthError(Exception):
    """Raised when authentication fails during handshake."""


# ---- Types & Data ----

AuthCallback = Callable[[Dict[str, Any]], Union[bool, Awaitable[bool]]]
TraceHook = Callable[[str, Dict[str, Any]], None]  # event_name, attributes
MetricHook = Callable[[str, Dict[str, Any]], None]  # metric_name, labels/values


@dataclass(frozen=True)
class NegotiationResult:
    version: int
    subprotocol: Optional[str]
    capabilities: Dict[str, Any]


# ---- Rate Limiter (Token Bucket) ----

class TokenBucket:
    def __init__(self, rate_per_sec: float, burst: float) -> None:
        self.rate = max(rate_per_sec, 0.0)
        self.burst = max(burst, 0.0)
        self._tokens = self.burst
        self._last = time.monotonic()

    def consume(self, amount: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self._last
        self._last = now
        self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
        if self._tokens >= amount:
            self._tokens -= amount
            return True
        return False


# ---- Send Queue with Backpressure ----

class SendQueue:
    def __init__(self, maxsize: int = MAX_SEND_QUEUE) -> None:
        self._q: asyncio.Queue[Tuple[str, Any]] = asyncio.Queue(maxsize=maxsize)

    def __len__(self) -> int:
        return self._q.qsize()

    async def put(self, kind: str, payload: Any, timeout: float = SEND_TIMEOUT_S) -> None:
        try:
            await asyncio.wait_for(self._q.put((kind, payload)), timeout=timeout)
        except asyncio.TimeoutError as e:
            raise ProtocolError("send queue full/timeout") from e

    async def get(self) -> Tuple[str, Any]:
        return await self._q.get()

    def task_done(self) -> None:
        self._q.task_done()


# ---- Negotiator ----

class ProtocolNegotiator:
    """
    Performs version and subprotocol negotiation.

    Sources:
      - Query param: v=<int> (e.g., ?v=2)
      - Header: X-WS-Version: <int>
      - Framework-advertised subprotocols (Sec-WebSocket-Protocol)
    """

    def __init__(
        self,
        supported_versions: Iterable[int] = DEFAULT_VERSIONS,
        preferred_subprotocols: Iterable[str] = DEFAULT_SUBPROTOCOLS,
        trace: Optional[TraceHook] = None,
        metrics: Optional[MetricHook] = None,
    ) -> None:
        self.supported_versions = tuple(sorted(set(int(v) for v in supported_versions)))
        self.preferred_subprotocols = tuple(preferred_subprotocols)
        self.trace = trace
        self.metrics = metrics

    async def negotiate(self, ws: Any) -> NegotiationResult:
        # Collect advertised subprotocols by client (framework-dependent)
        client_subprotocols: Tuple[str, ...] = tuple(ws.scope.get("subprotocols") or ())

        # Version preference: query -> header -> default max
        v_param = None
        try:
            # Starlette WebSocket has .query_params (Mapping)
            v_param = ws.query_params.get("v")
        except Exception:
            pass

        version_header = None
        try:
            headers = {k.decode().lower(): v.decode() for k, v in ws.headers}
            version_header = headers.get("x-ws-version")
        except Exception:
            pass

        chosen_version: int
        if v_param and v_param.isdigit():
            chosen_version = int(v_param)
        elif version_header and version_header.isdigit():
            chosen_version = int(version_header)
        else:
            chosen_version = max(self.supported_versions) if self.supported_versions else 1

        if chosen_version not in self.supported_versions:
            if self.trace:
                self.trace("ws.negotiation.version_unsupported", {"requested": chosen_version})
            if self.metrics:
                self.metrics("ws_handshake_fail_total", {"reason": "version"})
            raise ProtocolError(f"unsupported version {chosen_version}")

        # Subprotocol selection: server preference order intersect client set
        chosen_sub: Optional[str] = None
        if client_subprotocols:
            for sp in self.preferred_subprotocols:
                if sp in client_subprotocols:
                    chosen_sub = sp
                    break

        caps = {
            "heartbeat": True,
            "rate_limit": True,
            "version": chosen_version,
            "subprotocol": chosen_sub,
        }

        if self.trace:
            self.trace("ws.negotiation.success", {"version": chosen_version, "subprotocol": chosen_sub})

        if self.metrics:
            self.metrics("ws_handshake_success_total", {"version": str(chosen_version), "subprotocol": chosen_sub or "-"})

        return NegotiationResult(version=chosen_version, subprotocol=chosen_sub, capabilities=caps)


# ---- Heartbeat Manager ----

class HeartbeatManager:
    """
    Application-level heartbeat using JSON ping/pong frames:
      {"type": "ping", "ts": <monotonic>}
      {"type": "pong", "ts": <monotonic>}
    """

    def __init__(
        self,
        ws: Any,
        interval_s: float = HEARTBEAT_INTERVAL_S,
        timeout_s: float = HEARTBEAT_TIMEOUT_S,
        send_queue: Optional[SendQueue] = None,
        trace: Optional[TraceHook] = None,
        metrics: Optional[MetricHook] = None,
    ) -> None:
        self.ws = ws
        self.interval_s = float(interval_s)
        self.timeout_s = float(timeout_s)
        self.last_pong = time.monotonic()
        self._task: Optional[asyncio.Task] = None
        self._stopped = asyncio.Event()
        self._send_queue = send_queue
        self.trace = trace
        self.metrics = metrics

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run(), name="ws-heartbeat")
        if self.trace:
            self.trace("ws.heartbeat.start", {})

    async def stop(self) -> None:
        self._stopped.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            finally:
                self._task = None
        if self.trace:
            self.trace("ws.heartbeat.stop", {})

    async def on_pong(self, ts: float) -> None:
        self.last_pong = time.monotonic()
        if self.metrics:
            self.metrics("ws_pong_total", {})

    async def _run(self) -> None:
        try:
            while not self._stopped.is_set():
                await asyncio.sleep(self.interval_s)
                now = time.monotonic()
                ping_frame = json.dumps({"type": PING_TYPE, "ts": now})
                # Use send queue if present to respect backpressure
                try:
                    if self._send_queue:
                        await self._send_queue.put("text", ping_frame)
                    else:
                        await asyncio.wait_for(self.ws.send_text(ping_frame), timeout=SEND_TIMEOUT_S)
                    if self.metrics:
                        self.metrics("ws_ping_total", {})
                except Exception:
                    # On send failure, let watchdog close by timeout
                    pass

                # Watchdog
                if (now - self.last_pong) > self.timeout_s:
                    if self.trace:
                        self.trace("ws.heartbeat.timeout", {"idle_s": now - self.last_pong})
                    if self.metrics:
                        self.metrics("ws_heartbeat_timeouts_total", {})
                    # Close with policy violation to hint client watchdog
                    await safe_close(self.ws, WS_CLOSE_POLICY_VIOLATION, "heartbeat timeout")
                    break
        except asyncio.CancelledError:
            # Normal shutdown
            return


# ---- Helpers ----

async def safe_accept(ws: Any, subprotocol: Optional[str] = None) -> None:
    """Accept connection; tolerate double-accept in some servers."""
    try:
        await ws.accept(subprotocol=subprotocol)
    except RuntimeError:
        # Already accepted in some frameworks; ignore
        pass


async def safe_close(ws: Any, code: int = WS_CLOSE_NORMAL, reason: str = "") -> None:
    try:
        await ws.close(code=code)
    except Exception:
        pass


def _is_json_like(obj: Any) -> bool:
    return isinstance(obj, (dict, list, str, int, float, type(None), bool))


# ---- Session ----

class WebSocketSession:
    """
    High-level session wrapper providing:
      - negotiation + (optional) auth
      - heartbeat management
      - send queue worker (backpressure)
      - rate limiting on inbound messages
      - simple JSON message helpers (type-based)

    Usage (FastAPI/Starlette handler):
        negotiator = ProtocolNegotiator()
        async def auth(info): return True  # or validate token in headers

        async def handler(ws: WebSocket):
            session = WebSocketSession(ws, negotiator=negotiator, auth_cb=auth)
            await session.handshake()
            await session.run(loop=your_message_loop)

    The 'loop' callable receives the session as argument and is expected to
    read messages with 'await session.recv_json()' and respond via 'await session.send_json(...)'.
    """

    def __init__(
        self,
        ws: Any,
        negotiator: ProtocolNegotiator,
        auth_cb: Optional[AuthCallback] = None,
        trace: Optional[TraceHook] = None,
        metrics: Optional[MetricHook] = None,
        heartbeat_interval_s: float = HEARTBEAT_INTERVAL_S,
        heartbeat_timeout_s: float = HEARTBEAT_TIMEOUT_S,
        rate_limit_rps: float = RATE_LIMIT_RPS,
        rate_limit_burst: float = RATE_LIMIT_BURST,
        send_queue_size: int = MAX_SEND_QUEUE,
    ) -> None:
        self.ws = ws
        self.negotiator = negotiator
        self.auth_cb = auth_cb
        self.trace = trace
        self.metrics = metrics
        self.nego: Optional[NegotiationResult] = None

        self.sendq = SendQueue(maxsize=send_queue_size)
        self.hb = HeartbeatManager(
            ws=self.ws,
            interval_s=heartbeat_interval_s,
            timeout_s=heartbeat_timeout_s,
            send_queue=self.sendq,
            trace=self.trace,
            metrics=self.metrics,
        )
        self.in_rl = TokenBucket(rate_per_sec=rate_limit_rps, burst=rate_limit_burst)

        self._sender_task: Optional[asyncio.Task] = None
        self._closed = False

    # -------- Handshake --------

    async def handshake(self) -> NegotiationResult:
        self.nego = await self.negotiator.negotiate(self.ws)

        # Optional auth
        if self.auth_cb:
            info = self._make_auth_info()
            ok = self.auth_cb(info)
            if asyncio.iscoroutine(ok):
                ok = await ok  # type: ignore
            if not ok:
                if self.metrics:
                    self.metrics("ws_auth_fail_total", {})
                raise AuthError("authentication failed")

        # Accept with chosen subprotocol
        await safe_accept(self.ws, subprotocol=self.nego.subprotocol)
        if self.metrics:
            self.metrics("ws_accept_total", {"subprotocol": self.nego.subprotocol or "-"})

        # Start heartbeat & sender
        await self.hb.start()
        self._sender_task = asyncio.create_task(self._sender_loop(), name="ws-sender")
        if self.trace:
            self.trace("ws.session.start", {"version": self.nego.version, "subprotocol": self.nego.subprotocol})
        return self.nego

    def _make_auth_info(self) -> Dict[str, Any]:
        headers: Dict[str, str] = {}
        try:
            headers = {k.decode().lower(): v.decode() for k, v in self.ws.headers}
        except Exception:
            pass
        query: Dict[str, str] = {}
        try:
            query = dict(self.ws.query_params)
        except Exception:
            pass
        client = self.ws.client if hasattr(self.ws, "client") else None
        return {"headers": headers, "query": query, "client": client, "scope": getattr(self.ws, "scope", {})}

    # -------- Sender / Receiver --------

    async def _sender_loop(self) -> None:
        try:
            while True:
                kind, payload = await self.sendq.get()
                try:
                    if kind == "text":
                        await asyncio.wait_for(self.ws.send_text(payload), timeout=SEND_TIMEOUT_S)
                    elif kind == "bytes":
                        await asyncio.wait_for(self.ws.send_bytes(payload), timeout=SEND_TIMEOUT_S)
                    else:
                        raise ProtocolError(f"unknown send kind: {kind}")
                finally:
                    self.sendq.task_done()
        except (asyncio.CancelledError, RuntimeError):
            # Task cancelled or connection closed underneath
            return
        except Exception:
            # Stop on persistent errors; heartbeat watchdog will close
            return

    async def send_text(self, data: str) -> None:
        await self.sendq.put("text", data)

    async def send_bytes(self, data: bytes) -> None:
        await self.sendq.put("bytes", data)

    async def send_json(self, obj: Any) -> None:
        if not _is_json_like(obj):
            raise ValueError("send_json expects JSON-serializable object")
        await self.send_text(json.dumps(obj, separators=(",", ":")))

    async def recv_json(self, max_bytes: Optional[int] = None) -> Dict[str, Any]:
        """
        Receives next text frame and parses JSON.
        Applies inbound rate limiting.
        Intercepts application-level pong frames to feed heartbeat.
        """
        if not self.in_rl.consume():
            await safe_close(self.ws, WS_CLOSE_POLICY_VIOLATION, "rate limit exceeded")
            raise ProtocolError("rate limit exceeded")

        msg = await self.ws.receive_text()
        if max_bytes is not None and len(msg.encode("utf-8")) > max_bytes:
            await safe_close(self.ws, WS_CLOSE_TOO_LARGE, "message too large")
            raise ProtocolError("message too large")

        try:
            data = json.loads(msg)
        except Exception as e:
            await safe_close(self.ws, WS_CLOSE_UNSUPPORTED_DATA, "invalid json")
            raise ProtocolError("invalid json") from e

        # Heartbeat handling
        if isinstance(data, dict) and data.get("type") == PONG_TYPE:
            ts = float(data.get("ts", 0.0) or 0.0)
            await self.hb.on_pong(ts)
            # Return a minimal event to the caller to optionally ignore
            return {"type": PONG_TYPE, "ts": ts}

        return data

    # -------- Lifecycle --------

    async def run(self, loop: Callable[["WebSocketSession"], Awaitable[None]]) -> None:
        """
        Runs the provided message loop until completion or connection failure.
        Ensures graceful shutdown.
        """
        try:
            await loop(self)
        except AuthError:
            await safe_close(self.ws, WS_CLOSE_POLICY_VIOLATION, "auth failed")
            raise
        except ProtocolError:
            # Already closed with specific code inside helpers
            raise
        except (asyncio.CancelledError, RuntimeError):
            # Connection aborted by peer/server
            raise
        except Exception:
            await safe_close(self.ws, WS_CLOSE_UNEXPECTED_CONDITION, "server error")
            raise
        finally:
            await self.close()

    async def close(self, code: int = WS_CLOSE_NORMAL, reason: str = "") -> None:
        if self._closed:
            return
        self._closed = True
        await self.hb.stop()
        if self._sender_task:
            self._sender_task.cancel()
            try:
                await self._sender_task
            except asyncio.CancelledError:
                pass
        await safe_close(self.ws, code=code, reason=reason)
        if self.trace:
            self.trace("ws.session.stop", {"code": code, "reason": reason})


# ---- Example-compatible loop (can be replaced by application logic) ----

async def echo_loop(session: WebSocketSession) -> None:
    """
    Minimal reference loop: echoes inbound messages except pong.
    Demonstrates heartbeat coexistence and rate limiting.
    """
    while True:
        data = await session.recv_json()
        if data.get("type") == PONG_TYPE:
            # Ignore; heartbeat manager already updated last_pong
            continue
        # Business logic example: echo with server timestamp
        await session.send_json({"type": "echo", "at": time.time(), "data": data})


# ---- Factory for FastAPI/Starlette route integration ----

def make_ws_handler(
    negotiator: Optional[ProtocolNegotiator] = None,
    auth_cb: Optional[AuthCallback] = None,
    loop: Callable[[WebSocketSession], Awaitable[None]] = echo_loop,
    trace: Optional[TraceHook] = None,
    metrics: Optional[MetricHook] = None,
) -> Callable[[Any], Awaitable[None]]:
    """
    Returns an ASGI-compatible websocket endpoint function:

        from fastapi import FastAPI, WebSocket
        app = FastAPI()
        ws_handler = make_ws_handler()

        @app.websocket("/ws")
        async def ws_endpoint(websocket: WebSocket):
            await ws_handler(websocket)

    Replace 'loop' with your production message loop.
    """
    negotiator = negotiator or ProtocolNegotiator(trace=trace, metrics=metrics)

    async def endpoint(ws: Any) -> None:
        session = WebSocketSession(
            ws=ws,
            negotiator=negotiator,
            auth_cb=auth_cb,
            trace=trace,
            metrics=metrics,
        )
        try:
            await session.handshake()
        except AuthError:
            await safe_close(ws, WS_CLOSE_POLICY_VIOLATION, "auth failed")
            return
        except ProtocolError:
            await safe_close(ws, WS_CLOSE_PROTOCOL_ERROR, "handshake failed")
            return
        await session.run(loop)

    return endpoint
