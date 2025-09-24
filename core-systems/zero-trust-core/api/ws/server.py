# zero-trust-core/api/ws/server.py
# -*- coding: utf-8 -*-
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from http import HTTPStatus
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple, List, Mapping, Union, Iterable

# -------- Optional deps (safe fallbacks) --------
try:
    from starlette.websockets import WebSocket, WebSocketDisconnect, WebSocketState  # type: ignore
    from starlette.types import Scope, Receive, Send  # type: ignore
    from starlette.applications import Starlette  # type: ignore
    from starlette.routing import WebSocketRoute  # type: ignore
except Exception:  # pragma: no cover
    WebSocket = Any  # type: ignore
    WebSocketDisconnect = Exception  # type: ignore
    WebSocketState = Any  # type: ignore
    Scope = Any  # type: ignore
    Receive = Any  # type: ignore
    Send = Any  # type: ignore
    Starlette = None  # type: ignore
    WebSocketRoute = None  # type: ignore

try:
    import aioredis  # type: ignore
except Exception:  # pragma: no cover
    aioredis = None  # type: ignore

try:
    import jwt  # PyJWT (optional)
except Exception:  # pragma: no cover
    jwt = None  # type: ignore

# -------- Internal HTTP error helpers --------
try:
    # Reuse RFC7807 + correlation from HTTP layer
    from zero_trust_core.api.http.errors import (  # prefer absolute import for prod
        AppError,
        ErrorCode,
        ProblemDetails,
        ensure_correlation_id,
        redact,
        problem_response,  # not used directly here, but kept for parity
    )
except Exception:  # pragma: no cover
    # Fallback mini definitions if HTTP layer is not importable in isolation
    class ErrorCode(str, Enum):
        UNAUTHENTICATED = "UNAUTHENTICATED"
        FORBIDDEN = "FORBIDDEN"
        NOT_FOUND = "NOT_FOUND"
        INVALID_INPUT = "INVALID_INPUT"
        CONFLICT = "CONFLICT"
        RATE_LIMITED = "RATE_LIMITED"
        INTERNAL = "INTERNAL"
        TENANT_MISMATCH = "TENANT_MISMATCH"
        POLICY_VIOLATION = "POLICY_VIOLATION"
        STEP_UP_REQUIRED = "STEP_UP_REQUIRED"
        MFA_ENROLL_REQUIRED = "MFA_ENROLL_REQUIRED"
        DEPENDENCY_FAILURE = "DEPENDENCY_FAILURE"
        BAD_GATEWAY = "BAD_GATEWAY"
        SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
        TIMEOUT = "TIMEOUT"

    class AppError(Exception):
        def __init__(self, code: ErrorCode, detail: str = "", http_status: int = 500, **kw: Any) -> None:
            self.code = code
            self.detail = detail
            self.http_status = http_status
            self.title = code.value
            self.correlation_id = kw.get("correlation_id")
            self.tenant_id = kw.get("tenant_id")
            self.fields = kw.get("fields")
            self.retryable = kw.get("retryable", False)
            super().__init__(str(self))

    class ProblemDetails(dict):
        pass

    def ensure_correlation_id(request: Optional[Any] = None) -> str:
        return str(uuid.uuid4())

    def redact(obj: Any, sensitive_keys: Iterable[str] = ("authorization", "cookie", "token", "password")) -> Any:
        return obj


# -------- Logger --------
logger = logging.getLogger("zero_trust.ws.server")


# -------- Protocol types --------
class WsMsgType(str, Enum):
    PING = "ping"
    PONG = "pong"
    ACK = "ack"
    NACK = "nack"
    SUBSCRIBE = "subscribe"
    UNSUBSCRIBE = "unsubscribe"
    EVENT = "event"
    EVAL_AUTHORIZE = "evalAuthorize"
    LOG_AUDIT = "logAudit"
    RECORD_RISK = "recordRisk"
    ERROR = "error"


@dataclass
class WsEnvelope:
    type: str
    id: Optional[str] = None
    channel: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None
    ts: float = field(default_factory=lambda: time.time())

    @staticmethod
    def from_json(raw: str, *, max_size: int = 256 * 1024) -> "WsEnvelope":
        if len(raw) > max_size:
            raise AppError(ErrorCode.INVALID_INPUT, detail="Message too large", http_status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        try:
            data = json.loads(raw)
        except Exception:
            raise AppError(ErrorCode.INVALID_INPUT, detail="Invalid JSON", http_status=HTTPStatus.BAD_REQUEST)
        if not isinstance(data, dict) or "type" not in data:
            raise AppError(ErrorCode.INVALID_INPUT, detail="Envelope must be an object with 'type'")
        return WsEnvelope(
            type=str(data["type"]),
            id=str(data["id"]) if data.get("id") is not None else None,
            channel=str(data["channel"]) if data.get("channel") is not None else None,
            payload=data.get("payload") if isinstance(data.get("payload"), dict) else None,
            ts=float(data.get("ts") or time.time()),
        )

    def to_json(self) -> str:
        return json.dumps({k: v for k, v in asdict(self).items() if v is not None}, separators=(",", ":"))


# -------- Connection context --------
@dataclass
class IdentityContext:
    tenant_id: str
    subject_id: str
    session_id: Optional[str]
    roles: List[str] = field(default_factory=list)
    trust: int = 0  # 0..100
    risk: str = "UNKNOWN"
    attributes: Dict[str, Any] = field(default_factory=dict)


# -------- Token Bucket Rate Limiter --------
class TokenBucket:
    def __init__(self, rate: float, capacity: int) -> None:
        self.rate = float(rate)
        self.capacity = int(capacity)
        self.tokens = float(capacity)
        self.updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def allow(self, cost: float = 1.0) -> bool:
        async with self._lock:
            now = time.monotonic()
            delta = now - self.updated
            self.updated = now
            self.tokens = min(self.capacity, self.tokens + delta * self.rate)
            if self.tokens >= cost:
                self.tokens -= cost
                return True
            return False


# -------- PubSub abstraction (Redis or in-memory) --------
class PubSub:
    async def subscribe(self, channel: str, callback: Callable[[str, Dict[str, Any]], Awaitable[None]]) -> Callable[[], Awaitable[None]]:
        raise NotImplementedError

    async def publish(self, channel: str, message: Dict[str, Any]) -> None:
        raise NotImplementedError


class InMemoryPubSub(PubSub):
    def __init__(self) -> None:
        self._subs: Dict[str, List[Callable[[str, Dict[str, Any]], Awaitable[None]]]] = {}
        self._lock = asyncio.Lock()

    async def subscribe(self, channel: str, callback: Callable[[str, Dict[str, Any]], Awaitable[None]]) -> Callable[[], Awaitable[None]]:
        async with self._lock:
            self._subs.setdefault(channel, []).append(callback)

        async def _unsub() -> None:
            async with self._lock:
                items = self._subs.get(channel, [])
                if callback in items:
                    items.remove(callback)
        return _unsub

    async def publish(self, channel: str, message: Dict[str, Any]) -> None:
        # Best-effort fanout
        callbacks = list(self._subs.get(channel, []))
        for cb in callbacks:
            try:
                await cb(channel, message)
            except Exception as e:
                logger.warning("pubsub_callback_error: %s", e)


class RedisPubSub(PubSub):
    def __init__(self, redis_url: str) -> None:
        if aioredis is None:
            raise RuntimeError("aioredis is not available")
        self._url = redis_url
        self._conn: Optional[aioredis.Redis] = None  # type: ignore
        self._tasks: List[asyncio.Task] = []

    async def _ensure(self) -> aioredis.Redis:  # type: ignore
        if self._conn is None:
            self._conn = await aioredis.from_url(self._url, decode_responses=True)  # type: ignore
        return self._conn  # type: ignore

    async def subscribe(self, channel: str, callback: Callable[[str, Dict[str, Any]], Awaitable[None]]) -> Callable[[], Awaitable[None]]:
        conn = await self._ensure()
        pubsub = conn.pubsub()
        await pubsub.subscribe(channel)

        async def _reader() -> None:
            async for msg in pubsub.listen():  # type: ignore
                if msg.get("type") == "message":
                    data = msg.get("data")
                    try:
                        payload = json.loads(data)
                        await callback(channel, payload)
                    except Exception as e:
                        logger.warning("redis_pubsub_parse_error: %s", e)

        task = asyncio.create_task(_reader(), name=f"redis-sub-{channel}")
        self._tasks.append(task)

        async def _unsub() -> None:
            try:
                await pubsub.unsubscribe(channel)
            finally:
                task.cancel()
        return _unsub

    async def publish(self, channel: str, message: Dict[str, Any]) -> None:
        conn = await self._ensure()
        await conn.publish(channel, json.dumps(message, separators=(",", ":")))  # type: ignore


# -------- Authorizer/Policy hooks --------
PolicyDecision = Dict[str, Any]
PolicyEvaluator = Callable[[IdentityContext, Dict[str, Any]], Awaitable[PolicyDecision]]


# -------- WebSocket Server --------
class ZeroTrustWsServer:
    def __init__(
        self,
        *,
        allowed_origins: Optional[List[str]] = None,
        jwt_public_key: Optional[str] = None,
        jwt_algorithms: Optional[List[str]] = None,
        authenticator: Optional[Callable[[str], Awaitable[IdentityContext]]] = None,
        authorizer: Optional[Callable[[IdentityContext, str, str], Awaitable[None]]] = None,
        policy_evaluator: Optional[PolicyEvaluator] = None,
        pubsub: Optional[PubSub] = None,
        heartbeat_interval: float = 25.0,
        max_msg_size: int = 256 * 1024,
        send_queue_limit: int = 1000,
        per_conn_rate: Tuple[float, int] = (50.0, 200),  # tokens/sec, capacity
        per_type_rates: Optional[Mapping[str, Tuple[float, int]]] = None,
    ) -> None:
        self.allowed_origins = set(allowed_origins or [])
        self.jwt_public_key = jwt_public_key or os.getenv("ZTC_JWT_PUBLIC_KEY")
        self.jwt_algorithms = jwt_algorithms or ["RS256", "EdDSA", "ES256"]
        self.authenticator = authenticator
        self.authorizer = authorizer
        self.policy_evaluator = policy_evaluator
        self.pubsub = pubsub or InMemoryPubSub()
        self.heartbeat_interval = float(heartbeat_interval)
        self.max_msg_size = int(max_msg_size)
        self.send_queue_limit = int(send_queue_limit)
        self.per_conn_bucket = TokenBucket(*per_conn_rate)
        self.per_type_rates = dict(per_type_rates or {
            WsMsgType.SUBSCRIBE.value: (10.0, 20),
            WsMsgType.UNSUBSCRIBE.value: (10.0, 20),
            WsMsgType.EVAL_AUTHORIZE.value: (20.0, 50),
            WsMsgType.LOG_AUDIT.value: (10.0, 50),
            WsMsgType.RECORD_RISK.value: (10.0, 50),
            WsMsgType.PING.value: (5.0, 5),
        })
        self.per_type_buckets: Dict[str, TokenBucket] = {
            t: TokenBucket(rate, cap) for t, (rate, cap) in self.per_type_rates.items()
        }

    # ----- Handshake / Auth -----
    async def _authenticate(self, ws: WebSocket) -> IdentityContext:
        token = None
        try:
            auth = ws.headers.get("authorization") or ws.headers.get("Authorization")
            if auth and auth.lower().startswith("bearer "):
                token = auth.split(" ", 1)[1].strip()
            if not token:
                token = ws.query_params.get("token")  # type: ignore[attr-defined]
        except Exception:
            token = None
        if not token:
            raise AppError(ErrorCode.UNAUTHENTICATED, detail="Missing access token", http_status=HTTPStatus.UNAUTHORIZED)

        if self.authenticator is not None:
            return await self.authenticator(token)

        # Default JWT decode path (PyJWT), minimal verification
        if jwt is None or not self.jwt_public_key:
            raise AppError(ErrorCode.UNAUTHENTICATED, detail="JWT verification not available", http_status=HTTPStatus.UNAUTHORIZED)

        try:
            claims = jwt.decode(token, self.jwt_public_key, algorithms=self.jwt_algorithms, options={"require": ["exp", "iat", "sub"]})  # type: ignore
        except Exception as e:
            raise AppError(ErrorCode.UNAUTHENTICATED, detail="Invalid token", http_status=HTTPStatus.UNAUTHORIZED) from e

        tenant = str(claims.get("tenant") or claims.get("tid") or claims.get("org") or "")
        if not tenant:
            raise AppError(ErrorCode.TENANT_MISMATCH, detail="Tenant claim required", http_status=HTTPStatus.FORBIDDEN)
        subject = str(claims.get("sub"))
        session_id = claims.get("sid")
        roles = list(claims.get("roles") or [])
        trust = int(claims.get("trust", 0))
        risk = str(claims.get("risk", "UNKNOWN"))
        attrs = {k: v for k, v in claims.items() if k not in {"sub", "sid", "exp", "iat", "nbf", "iss", "aud", "tenant", "tid", "org"}}
        return IdentityContext(tenant_id=tenant, subject_id=subject, session_id=session_id, roles=roles, trust=trust, risk=risk, attributes=attrs)

    def _check_origin(self, ws: WebSocket) -> None:
        if not self.allowed_origins:
            return
        origin = ws.headers.get("origin") or ws.headers.get("Origin")
        if origin and origin in self.allowed_origins:
            return
        raise AppError(ErrorCode.FORBIDDEN, detail="Origin not allowed", http_status=HTTPStatus.FORBIDDEN)

    # ----- Connection lifecycle -----
    async def handle(self, ws: WebSocket) -> None:
        correlation_id = ensure_correlation_id(None)
        try:
            self._check_origin(ws)
            await ws.accept(subprotocol="ztr-v1")  # type: ignore[attr-defined]
            identity = await self._authenticate(ws)
            # Attach context for downstream handlers
            ws.scope.setdefault("state", {})  # type: ignore[attr-defined]
            ws.scope["state"]["identity"] = identity  # type: ignore[index]
            ws.scope["state"]["correlation_id"] = correlation_id  # type: ignore[index]
            await self._send_ack(ws, None, {"connected": True, "tenant": identity.tenant_id, "subject": identity.subject_id, "session": identity.session_id})

            send_task = asyncio.create_task(self._sender(ws), name="ws-sender")
            recv_task = asyncio.create_task(self._receiver(ws), name="ws-receiver")
            hb_task = asyncio.create_task(self._heartbeat(ws), name="ws-heartbeat")
            done, pending = await asyncio.wait({send_task, recv_task, hb_task}, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
        except WebSocketDisconnect:
            pass
        except AppError as e:
            await self._safe_send_error(ws, e, correlation_id)
            await self._safe_close(ws, code=4403 if e.http_status == HTTPStatus.FORBIDDEN else 4401)
        except Exception as e:
            err = AppError(ErrorCode.INTERNAL, detail="Unhandled WS error", http_status=HTTPStatus.INTERNAL_SERVER_ERROR)
            await self._safe_send_error(ws, err, correlation_id, cause=e)
            await self._safe_close(ws, code=1011)

    # ----- Queues and backpressure -----
    def _send_queue(self, ws: WebSocket) -> asyncio.Queue:
        q = ws.scope.setdefault("_send_queue", asyncio.Queue(self.send_queue_limit))  # type: ignore[attr-defined]
        return q  # type: ignore

    async def _enqueue(self, ws: WebSocket, env: WsEnvelope) -> None:
        q = self._send_queue(ws)
        try:
            q.put_nowait(env)
        except asyncio.QueueFull:
            # Backpressure violation → close
            await self._safe_close(ws, code=1013)  # Try again later
            raise

    async def _sender(self, ws: WebSocket) -> None:
        q: asyncio.Queue = self._send_queue(ws)
        while True:
            env: WsEnvelope = await q.get()
            if ws.client_state != WebSocketState.CONNECTED:  # type: ignore[attr-defined]
                return
            data = env.to_json()
            await ws.send_text(data)  # type: ignore[attr-defined]

    async def _receiver(self, ws: WebSocket) -> None:
        while True:
            msg = await ws.receive_text()  # type: ignore[attr-defined]
            try:
                if not await self.per_conn_bucket.allow(1.0):
                    raise AppError(ErrorCode.RATE_LIMITED, detail="Global rate limit exceeded", http_status=HTTPStatus.TOO_MANY_REQUESTS)

                env = WsEnvelope.from_json(msg, max_size=self.max_msg_size)
                bucket = self.per_type_buckets.get(env.type)
                if bucket and not await bucket.allow(1.0):
                    raise AppError(ErrorCode.RATE_LIMITED, detail=f"Rate limit for type={env.type} exceeded", http_status=HTTPStatus.TOO_MANY_REQUESTS)

                await self._dispatch(ws, env)
            except AppError as e:
                await self._send_nack(ws, env.id, e)
            except Exception as e:
                err = AppError(ErrorCode.INTERNAL, detail="Message processing error", http_status=HTTPStatus.INTERNAL_SERVER_ERROR)
                await self._send_nack(ws, getattr(env, "id", None), err)

    async def _heartbeat(self, ws: WebSocket) -> None:
        interval = self.heartbeat_interval
        while True:
            await asyncio.sleep(interval)
            if ws.client_state != WebSocketState.CONNECTED:  # type: ignore[attr-defined]
                return
            await self._enqueue(ws, WsEnvelope(type=WsMsgType.PING.value))

    # ----- Dispatch -----
    async def _dispatch(self, ws: WebSocket, env: WsEnvelope) -> None:
        if env.type == WsMsgType.PING.value:
            await self._enqueue(ws, WsEnvelope(type=WsMsgType.PONG.value, id=env.id))
            return
        if env.type == WsMsgType.SUBSCRIBE.value:
            await self._handle_subscribe(ws, env)
            return
        if env.type == WsMsgType.UNSUBSCRIBE.value:
            await self._handle_unsubscribe(ws, env)
            return
        if env.type == WsMsgType.EVAL_AUTHORIZE.value:
            await self._handle_eval_authorize(ws, env)
            return
        if env.type == WsMsgType.LOG_AUDIT.value:
            await self._handle_log_audit(ws, env)
            return
        if env.type == WsMsgType.RECORD_RISK.value:
            await self._handle_record_risk(ws, env)
            return
        raise AppError(ErrorCode.INVALID_INPUT, detail=f"Unsupported type: {env.type}", http_status=HTTPStatus.BAD_REQUEST)

    # ----- Handlers -----
    def _identity(self, ws: WebSocket) -> IdentityContext:
        return ws.scope["state"]["identity"]  # type: ignore[index]

    async def _handle_subscribe(self, ws: WebSocket, env: WsEnvelope) -> None:
        ident = self._identity(ws)
        ch = env.channel or (env.payload or {}).get("channel")
        if not ch:
            raise AppError(ErrorCode.INVALID_INPUT, detail="channel is required")
        if self.authorizer:
            await self.authorizer(ident, "subscribe", ch)

        async def _fanout(_channel: str, message: Dict[str, Any]) -> None:
            payload = {"channel": _channel, "data": message}
            await self._enqueue(ws, WsEnvelope(type=WsMsgType.EVENT.value, channel=_channel, payload=payload))

        unsub = await self.pubsub.subscribe(ch, _fanout)
        subs: Dict[str, Callable[[], Awaitable[None]]] = ws.scope.setdefault("_subs", {})  # type: ignore[attr-defined]
        # Unsubscribe previous if any
        if ch in subs:
            try:
                await subs[ch]()
            except Exception:
                pass
        subs[ch] = unsub
        await self._send_ack(ws, env.id, {"subscribed": ch})

    async def _handle_unsubscribe(self, ws: WebSocket, env: WsEnvelope) -> None:
        ch = env.channel or (env.payload or {}).get("channel")
        if not ch:
            raise AppError(ErrorCode.INVALID_INPUT, detail="channel is required")
        subs: Dict[str, Callable[[], Awaitable[None]]] = ws.scope.get("_subs", {})  # type: ignore[attr-defined]
        if ch in subs:
            try:
                await subs[ch]()
            finally:
                subs.pop(ch, None)
        await self._send_ack(ws, env.id, {"unsubscribed": ch})

    async def _handle_eval_authorize(self, ws: WebSocket, env: WsEnvelope) -> None:
        ident = self._identity(ws)
        payload = env.payload or {}
        if self.policy_evaluator is None:
            raise AppError(ErrorCode.DEPENDENCY_FAILURE, detail="Policy evaluator not configured", http_status=HTTPStatus.FAILED_DEPENDENCY)
        decision = await self.policy_evaluator(ident, payload)
        await self._send_ack(ws, env.id, {"decision": decision})

    async def _handle_log_audit(self, ws: WebSocket, env: WsEnvelope) -> None:
        ident = self._identity(ws)
        payload = env.payload or {}
        try:
            # Basic schema
            category = str(payload.get("category") or "ws")
            action = str(payload.get("action") or "WRITE")
            result = str(payload.get("result") or "OK")
            data = redact(payload.get("attributes") or {})
            msg = {"tenantId": ident.tenant_id, "subjectId": ident.subject_id, "category": category, "action": action, "result": result, "attributes": data}
            await self.pubsub.publish("audit", msg)
        except Exception as e:
            raise AppError(ErrorCode.INTERNAL, detail="Failed to log audit") from e
        await self._send_ack(ws, env.id, {"logged": True})

    async def _handle_record_risk(self, ws: WebSocket, env: WsEnvelope) -> None:
        ident = self._identity(ws)
        payload = env.payload or {}
        severity = str(payload.get("severity") or "INFO")
        score_delta = int(payload.get("scoreDelta") or 0)
        attrs = redact(payload.get("attributes") or {})
        msg = {"tenantId": ident.tenant_id, "subjectId": ident.subject_id, "severity": severity, "scoreDelta": score_delta, "attributes": attrs}
        await self.pubsub.publish("risk", msg)
        await self._send_ack(ws, env.id, {"recorded": True})

    # ----- Send helpers -----
    async def _send_ack(self, ws: WebSocket, req_id: Optional[str], payload: Dict[str, Any]) -> None:
        await self._enqueue(ws, WsEnvelope(type=WsMsgType.ACK.value, id=req_id, payload=payload))

    async def _send_nack(self, ws: WebSocket, req_id: Optional[str], err: AppError) -> None:
        problem = {
            "type": "about:blank",
            "title": err.title if hasattr(err, "title") else err.code.value,
            "status": getattr(err, "http_status", 500),
            "detail": getattr(err, "detail", None),
            "code": err.code.value,
        }
        await self._enqueue(ws, WsEnvelope(type=WsMsgType.NACK.value, id=req_id, payload={"error": problem}))

    async def _safe_send_error(self, ws: WebSocket, err: AppError, correlation_id: Optional[str], cause: Optional[BaseException] = None) -> None:
        if cause:
            logger.error("ws_fatal_error", extra={"code": err.code.value, "detail": err.detail, "correlation_id": correlation_id, "cause": str(cause)})
        env = WsEnvelope(type=WsMsgType.ERROR.value, payload={
            "problem": {
                "type": "about:blank",
                "title": err.title if hasattr(err, "title") else err.code.value,
                "status": getattr(err, "http_status", 500),
                "detail": getattr(err, "detail", None),
                "code": err.code.value,
                "correlationId": correlation_id,
            }
        })
        try:
            await self._enqueue(ws, env)
        except Exception:
            pass

    async def _safe_close(self, ws: WebSocket, code: int = 1000) -> None:
        try:
            await ws.close(code=code)  # type: ignore[attr-defined]
        except Exception:
            pass

    # ----- Integration helpers for Starlette/FastAPI -----
    def as_asgi_app(self, path: str = "/ws") -> Any:
        if Starlette is None or WebSocketRoute is None:
            raise RuntimeError("Starlette is not available")

        async def _endpoint(ws: WebSocket) -> None:
            await self.handle(ws)

        return Starlette(routes=[WebSocketRoute(path, _endpoint)])  # type: ignore

    def route(self, path: str = "/ws") -> Any:
        """
        Returns a Starlette WebSocketRoute to be mounted into an existing app.
        """
        if WebSocketRoute is None:
            raise RuntimeError("Starlette is not available")
        async def _endpoint(ws: WebSocket) -> None:
            await self.handle(ws)
        return WebSocketRoute(path, _endpoint)


# -------- Factory --------
def build_server() -> ZeroTrustWsServer:
    """
    Opinionated factory with env overrides:
      ZTC_ALLOWED_ORIGINS = "https://app.example.com,https://admin.example.com"
      ZTC_JWT_PUBLIC_KEY  = "-----BEGIN PUBLIC KEY-----..."
      ZTC_REDIS_URL       = "redis://localhost:6379/0"
    """
    origins = [o.strip() for o in os.getenv("ZTC_ALLOWED_ORIGINS", "").split(",") if o.strip()]
    redis_url = os.getenv("ZTC_REDIS_URL")
    pubsub: PubSub
    if redis_url and aioredis is not None:
        pubsub = RedisPubSub(redis_url)
    else:
        pubsub = InMemoryPubSub()

    server = ZeroTrustWsServer(
        allowed_origins=origins,
        jwt_public_key=os.getenv("ZTC_JWT_PUBLIC_KEY"),
        pubsub=pubsub,
    )
    return server


# -------- Optional runnable example --------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)
    if Starlette is None:
        print("Starlette is not installed. Install starlette/uvicorn to run the WS server.")
        sys.exit(0)

    import uvicorn  # type: ignore

    server = build_server()
    app = server.as_asgi_app("/ws")
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
