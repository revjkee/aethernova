# security-core/api/ws/server.py
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Protocol, Tuple

try:
    import orjson  # безопасный и быстрый парсер
except Exception:  # pragma: no cover
    orjson = None  # type: ignore

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, status
from starlette.websockets import WebSocketState
from pydantic import BaseModel, Field, ConfigDict, constr

logger = logging.getLogger("security_core.ws")

# -------------------- Внешние интеграции (опционально) --------------------
try:
    from redis.asyncio import Redis
except Exception:  # pragma: no cover
    Redis = None  # type: ignore

# Попытка переиспользовать RedisTokenBucket из HTTP middleware (если файл присутствует)
try:  # pragma: no cover
    from security_core.api.http.middleware.ratelimit import RedisTokenBucket as _HTTPRedisTokenBucket
except Exception:  # pragma: no cover
    _HTTPRedisTokenBucket = None  # type: ignore


# ========================== Протоколы DI ==========================

class KeyService(Protocol):
    async def sign(self, tenant: str, key: str, version: int, payload: "SignIn") -> bytes: ...
    async def verify(self, tenant: str, payload: "VerifyIn", name_ref: Optional[str]) -> bool: ...
    async def encrypt(self, tenant: str, name_ref: str, payload: "EncryptIn") -> Dict[str, bytes]: ...
    async def decrypt(self, tenant: str, name_ref: str, payload: "DecryptIn") -> bytes: ...
    async def wrap_key(self, tenant: str, name_ref: str, payload: "WrapIn") -> bytes: ...
    async def unwrap_key(self, tenant: str, name_ref: str, payload: "UnwrapIn") -> bytes: ...
    async def get_jwks(self, tenant: str, flt: Optional[str], include_inactive: bool) -> "Jwks": ...


class AuthContext(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant: str
    subject: str
    scopes: List[str] = Field(default_factory=list)
    # Доп. сведения для ABAC
    attributes: Dict[str, str] = Field(default_factory=dict)


class AuthProvider(Protocol):
    async def authenticate(self, ws: WebSocket) -> AuthContext: ...


# ========================== Модели сообщений ==========================

b64url = constr(pattern=r"^[A-Za-z0-9_-]+$")  # base64url без padding

class EnvelopeType(str, Enum):
    PING = "ping"
    PONG = "pong"
    SUBSCRIBE = "subscribe"
    UNSUBSCRIBE = "unsubscribe"
    SIGN = "sign"
    VERIFY = "verify"
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    WRAP = "wrap"
    UNWRAP = "unwrap"
    JWKS = "jwks"
    ERROR = "error"
    ACK = "ack"
    EVENT = "event"


class Envelope(BaseModel):
    """
    Унифицированный конверт сообщений WS.
    """
    model_config = ConfigDict(extra="forbid")
    id: str = Field(..., min_length=8, max_length=128, description="Клиентский уникальный ID сообщения")
    type: EnvelopeType
    ts: int = Field(..., description="Клиентское время Unix (sec)")
    # opt поля по типам:
    op: Optional[Dict[str, Any]] = None   # полезная нагрузка операции
    token: Optional[str] = None           # подпись/токен сообщения (опционально)
    idem: Optional[str] = None            # Idempotency-Key (anti-replay)
    chan: Optional[str] = None            # канал подписки (subscribe/unsubscribe)


class Ack(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ok: bool
    id: str
    detail: Optional[str] = None


class ErrorOut(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: Optional[str] = None
    code: str
    message: str


# -------- Параметры крипто‑операций (минимальные, согласованы с HTTP слоем) --------

class SignIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name_ref: str = Field(..., description="keys/{key} или keys/{key}/versions/{version}")
    signature_algorithm: str
    digest: Optional[b64url] = None
    plaintext: Optional[b64url] = None
    salt: Optional[b64url] = None
    context: Dict[str, str] = Field(default_factory=dict)


class VerifyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name_ref: Optional[str] = Field(None, description="если public_key не задан")
    signature_algorithm: str
    digest: Optional[b64url] = None
    plaintext: Optional[b64url] = None
    signature: b64url


class EncryptIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name_ref: str
    encryption_algorithm: str
    plaintext: b64url
    aad: Optional[b64url] = None


class DecryptIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name_ref: str
    encryption_algorithm: str
    ciphertext: b64url
    aad: Optional[b64url] = None
    iv: Optional[b64url] = None
    tag: Optional[b64url] = None


class WrapIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name_ref: str
    algorithm: str
    target_key_material: b64url
    aad: Optional[b64url] = None


class UnwrapIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name_ref: str
    algorithm: str
    wrapped_key: b64url
    aad: Optional[b64url] = None


class Jwk(BaseModel):
    model_config = ConfigDict(extra="allow")
    kty: str
    kid: Optional[str] = None


class Jwks(BaseModel):
    model_config = ConfigDict(extra="forbid")
    keys: List[Jwk]


# ========================== Конфигурация сервера ==========================

@dataclass
class WSRateRule:
    name: str
    limit_per_sec: int = 20
    burst: int = 40


@dataclass
class WSConfig:
    path: str = "/api/v1/ws"
    subprotocols: Tuple[str, ...] = ("sec-core.v1",)
    allowed_origins: Tuple[str, ...] = ("*",)  # при проде лучше конкретные источники
    trust_forwarded: bool = True
    max_msg_bytes: int = 256 * 1024
    recv_timeout_sec: int = 30
    idle_timeout_sec: int = 120
    heartbeat_interval_sec: int = 20
    send_queue_max: int = 1024
    max_connections_per_tenant: int = 10_000
    max_connections_per_ip: int = 1_000
    anti_replay_ttl_sec: int = 600
    rate_rule: WSRateRule = field(default_factory=lambda: WSRateRule(name="ws-per-conn", limit_per_sec=20, burst=40))
    # Redis
    redis_prefix: str = "ws"
    include_metrics_headers: bool = False


# ========================== Утилиты ==========================

def _json_dumps(obj: Any) -> bytes:
    if orjson:
        return orjson.dumps(obj)  # type: ignore
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _json_loads(data: str) -> Dict[str, Any]:
    if orjson:
        return orjson.loads(data)  # type: ignore
    return json.loads(data)


def _now_s() -> int:
    return int(time.time())


def _remote_addr(ws: WebSocket, trust_forwarded: bool) -> str:
    if trust_forwarded:
        xfwd = ws.headers.get("x-forwarded-for")
        if xfwd:
            return xfwd.split(",")[0].strip()
        xreal = ws.headers.get("x-real-ip")
        if xreal:
            return xreal.strip()
    return ws.client.host if ws.client else "0.0.0.0"


def _origin_allowed(origin: Optional[str], allowed: Tuple[str, ...]) -> bool:
    if not origin:
        return True
    if "*" in allowed:
        return True
    return origin in allowed


# ========================== Rate limit + Anti-replay ==========================

class _InMemoryTokenBucket:
    __slots__ = ("capacity", "tokens", "rate_per_ms", "ts")

    def __init__(self, capacity: int, rate_per_ms: float) -> None:
        self.capacity = capacity
        self.tokens = capacity
        self.rate_per_ms = rate_per_ms
        self.ts = time.time() * 1000.0

    def take(self, n: int = 1) -> Tuple[bool, int]:
        now = time.time() * 1000.0
        elapsed = max(0.0, now - self.ts)
        self.ts = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate_per_ms)
        if self.tokens >= n:
            self.tokens -= n
            return True, int(self.tokens)
        return False, int(self.tokens)


class _RedisTokenBucketWS:
    """
    Минималистичный Lua‑бакет для WS, чтобы не тянуть весь HTTP‑middleware.
    """
    _LUA = """
    local bucket = KEYS[1]
    local cap = tonumber(ARGV[1])
    local rate = tonumber(ARGV[2]) -- tokens per ms * 1000 (micro tokens)
    local now = tonumber(ARGV[3])
    local req = tonumber(ARGV[4])
    local ttl_ms = tonumber(ARGV[5])

    local data = redis.call("HMGET", bucket, "t", "ts")
    local tokens = tonumber(data[1])
    local ts = tonumber(data[2])

    if not tokens or not ts then
      tokens = cap * 1000
      ts = now
    else
      if now > ts then
        local delta = now - ts
        tokens = tokens + delta * rate
        local max_micro = cap * 1000
        if tokens > max_micro then tokens = max_micro end
      end
    end

    local allowed = 0
    if tokens >= req * 1000 then
      tokens = tokens - req * 1000
      allowed = 1
    end

    redis.call("HMSET", bucket, "t", math.floor(tokens), "ts", now)
    redis.call("PEXPIRE", bucket, ttl_ms)

    return {allowed, math.floor(tokens/1000)}
    """

    def __init__(self, redis: Redis, prefix: str) -> None:  # type: ignore[type-arg]
        self.r = redis
        self.prefix = prefix
        self._sha: Optional[str] = None
        self._lock = asyncio.Lock()

    async def _ensure(self) -> str:
        if self._sha:
            return self._sha
        async with self._lock:
            if self._sha:
                return self._sha
            self._sha = await self.r.script_load(self._LUA)
            return self._sha

    async def take(self, key: str, cap: int, rate_per_sec: int, ttl_ms: int) -> Tuple[bool, int]:
        sha = await self._ensure()
        now = int(time.time() * 1000)
        # rate_micro_per_ms = (rate_per_sec * 1000) / 1000 = rate_per_sec
        res = await self.r.evalsha(sha, 1, key, cap, rate_per_sec, now, 1, ttl_ms)
        allowed = bool(int(res[0]))
        remaining = int(res[1])
        return allowed, remaining


# ========================== Сервер ==========================

class SecCoreWebSocketServer:
    def __init__(
        self,
        cfg: WSConfig,
        key_service_provider: Callable[[], Awaitable[KeyService]],
        auth_provider: Callable[[], Awaitable[AuthProvider]],
        redis: Optional[Redis] = None,  # type: ignore[type-arg]
        metrics_hook: Optional[Callable[[str, Mapping[str, Any]], None]] = None,
    ) -> None:
        self.cfg = cfg
        self._get_key_service = key_service_provider
        self._get_auth = auth_provider
        self.redis = redis
        self.metrics = metrics_hook

        # Token bucket фабрика
        if redis:
            if _HTTPRedisTokenBucket:  # можно переиспользовать HTTP версию
                self.bucket = _HTTPRedisTokenBucket(redis, prefix=f"{cfg.redis_prefix}:tb")  # type: ignore
            else:
                self.bucket = _RedisTokenBucketWS(redis, prefix=f"{cfg.redis_prefix}:tb")  # type: ignore
        else:
            self.bucket = None

        # Anti‑replay ключи
        self.replay_prefix = f"{cfg.redis_prefix}:idem"
        self._local_idem: Dict[str, float] = {}

        # Коннект‑счетчики
        self.conn_prefix = f"{cfg.redis_prefix}:conn"

        self.router = APIRouter()

        @self.router.websocket(self.cfg.path)
        async def ws_endpoint(ws: WebSocket) -> None:  # noqa: N803
            await self._handle_ws(ws)

    # --------------- Внешняя точка подключения роутера ---------------
    def get_router(self) -> APIRouter:
        return self.router

    # --------------- Метрики ---------------
    def _metric(self, name: str, tags: Mapping[str, Any]) -> None:
        try:
            if self.metrics:
                self.metrics(name, tags)
        except Exception as e:
            logger.debug("metrics hook error: %s", e)

    # --------------- Валидации и лимиты ---------------
    async def _check_connection_limits(self, tenant: str, ip: str) -> None:
        if not self.redis:
            return  # без Redis — не считаем глобально
        tkey = f"{self.conn_prefix}:tenant:{tenant}"
        ikey = f"{self.conn_prefix}:ip:{ip}"
        pipe = self.redis.pipeline()  # type: ignore
        pipe.incr(tkey)
        pipe.expire(tkey, 300)
        pipe.incr(ikey)
        pipe.expire(ikey, 300)
        tval, _, ival, _ = await pipe.execute()
        if int(tval) > self.cfg.max_connections_per_tenant:
            await self.redis.decr(tkey)  # type: ignore
            raise ConnectionRefusedError("too_many_tenant_connections")
        if int(ival) > self.cfg.max_connections_per_ip:
            await self.redis.decr(ikey)  # type: ignore
            raise ConnectionRefusedError("too_many_ip_connections")

    async def _release_connection_limits(self, tenant: str, ip: str) -> None:
        if not self.redis:
            return
        try:
            await self.redis.decr(f"{self.conn_prefix}:tenant:{tenant}")  # type: ignore
            await self.redis.decr(f"{self.conn_prefix}:ip:{ip}")  # type: ignore
        except Exception:
            pass

    async def _rate_take(self, key: str, rule: WSRateRule) -> Tuple[bool, int]:
        if self.bucket is None:
            # в памяти — точка на процесс
            b = _InMemoryTokenBucket(capacity=rule.burst, rate_per_ms=rule.limit_per_sec / 1000.0)
            allowed, remaining = b.take(1)
            return allowed, remaining
        ttl_ms = int((rule.burst / max(1, rule.limit_per_sec)) * 1000) + 2000
        if hasattr(self.bucket, "consume"):  # HTTP‑bucket API
            allowed, remaining_micro, *_ = await self.bucket.consume(  # type: ignore
                key=key,
                capacity_micro=rule.burst * 1000,
                rate_micro_per_ms=max(1, int(rule.limit_per_sec)),  # 1 токен = 1000 микротокенов
                now_ms=int(time.time() * 1000),
                request_micro=1000,
                ttl_ms=ttl_ms,
                idem_key="",
                idem_ttl_ms=0,
            )
            remaining = max(0, remaining_micro // 1000)
            return allowed, remaining
        else:  # WS‑bucket API
            allowed, remaining = await self.bucket.take(key, rule.burst, rule.limit_per_sec, ttl_ms)  # type: ignore
            return allowed, remaining

    async def _replay_check_and_mark(self, tenant: str, idem: str) -> bool:
        if not idem:
            return False
        now = time.time()
        # Redis предпочтительно
        if self.redis:
            key = f"{self.replay_prefix}:{tenant}:{idem}"
            ok = await self.redis.setnx(key, "1")  # type: ignore
            if ok:
                await self.redis.expire(key, self.cfg.anti_replay_ttl_sec)  # type: ignore
                return False
            return True
        # локальный фоллбек на процесс
        stale_before = now - self.cfg.anti_replay_ttl_sec
        self._local_idem = {k: v for k, v in self._local_idem.items() if v >= stale_before}
        if idem in self._local_idem:
            return True
        self._local_idem[idem] = now
        return False

    # --------------- Основной обработчик WS ---------------
    async def _handle_ws(self, ws: WebSocket) -> None:  # noqa: C901
        # Проверка Origin и субпротокола
        origin = ws.headers.get("origin")
        if not _origin_allowed(origin, self.cfg.allowed_origins):
            await ws.close(code=1008, reason="Origin not allowed")
            return

        # Аутентификация
        try:
            auth = await self._get_auth()(ws)  # AuthProvider.authenticate
        except Exception as e:
            await ws.close(code=4401, reason="Unauthorized")
            self._metric("ws_auth_failed", {"reason": str(e)})
            return

        ip = _remote_addr(ws, self.cfg.trust_forwarded)
        try:
            await self._check_connection_limits(auth.tenant, ip)
        except ConnectionRefusedError as e:
            code = 1013 if "tenant" in str(e) else 1013
            await ws.close(code=code, reason=str(e))
            return

        # Принятие соединения с согласованием субпротокола
        subproto = None
        req_protos = [p.strip() for p in ws.headers.get("sec-websocket-protocol", "").split(",") if p.strip()]
        for p in req_protos:
            if p in self.cfg.subprotocols:
                subproto = p
                break
        await ws.accept(subprotocol=subproto)

        self._metric("ws_connected", {"tenant": auth.tenant, "ip": ip, "subproto": subproto or ""})

        # Инициализация очереди отправки
        send_queue: asyncio.Queue[bytes] = asyncio.Queue(self.cfg.send_queue_max)
        alive = True

        async def sender() -> None:
            nonlocal alive
            try:
                while alive and ws.application_state == WebSocketState.CONNECTED:
                    data = await send_queue.get()
                    await ws.send_bytes(data)
            except Exception as e:
                logger.debug("ws sender stopped: %s", e)

        async def heartbeat() -> None:
            nonlocal alive
            try:
                while alive and ws.application_state == WebSocketState.CONNECTED:
                    await asyncio.sleep(self.cfg.heartbeat_interval_sec)
                    if ws.application_state != WebSocketState.CONNECTED:
                        break
                    await ws.send_text(json.dumps({"type": "ping", "ts": _now_s()}))
            except Exception:
                pass

        sender_task = asyncio.create_task(sender(), name="ws-sender")
        hb_task = asyncio.create_task(heartbeat(), name="ws-heartbeat")

        # Основной цикл приема
        try:
            while ws.application_state == WebSocketState.CONNECTED:
                try:
                    msg = await asyncio.wait_for(ws.receive_text(), timeout=self.cfg.recv_timeout_sec)
                except asyncio.TimeoutError:
                    # idle timeout
                    if (time.time() - ws.client_state.connect_time) > self.cfg.idle_timeout_sec if hasattr(ws.client_state, "connect_time") else False:  # type: ignore[attr-defined]
                        await ws.close(code=1001, reason="Idle timeout")
                        break
                    # посылаем ping; heartbeat тоже работает
                    continue
                except WebSocketDisconnect:
                    break

                if len(msg.encode("utf-8")) > self.cfg.max_msg_bytes:
                    await ws.close(code=1009, reason="Message too big")
                    break

                try:
                    raw = _json_loads(msg)
                    env = Envelope(**raw)
                except Exception as e:
                    await self._send_error(send_queue, None, "bad_request", f"Invalid payload: {e}")
                    continue

                # Проверка сдвига времени (доверяем скользящее окно)
                now = _now_s()
                if abs(now - env.ts) > 600:
                    await self._send_error(send_queue, env.id, "clock_skew", "Timestamp skew too large")
                    continue

                # Anti‑replay (idem)
                if await self._replay_check_and_mark(auth.tenant, env.idem or env.id):
                    await self._send_error(send_queue, env.id, "replay", "Duplicate id/idempotency key")
                    continue

                # Per‑connection rate limiting (распределённый при наличии Redis)
                rate_key = f"{self.cfg.redis_prefix}:rate:{auth.tenant}:{ip}"
                allowed, remaining = await self._rate_take(rate_key, self.cfg.rate_rule)
                if not allowed:
                    await self._send_error(send_queue, env.id, "rate_limited", "Too many messages")
                    continue

                # Диспетчеризация
                try:
                    if env.type == EnvelopeType.PING:
                        await self._enqueue(send_queue, {"type": "pong", "id": env.id, "ts": now})
                    elif env.type == EnvelopeType.SIGN:
                        await self._handle_sign(send_queue, auth, env)
                    elif env.type == EnvelopeType.VERIFY:
                        await self._handle_verify(send_queue, auth, env)
                    elif env.type == EnvelopeType.ENCRYPT:
                        await self._handle_encrypt(send_queue, auth, env)
                    elif env.type == EnvelopeType.DECRYPT:
                        await self._handle_decrypt(send_queue, auth, env)
                    elif env.type == EnvelopeType.WRAP:
                        await self._handle_wrap(send_queue, auth, env)
                    elif env.type == EnvelopeType.UNWRAP:
                        await self._handle_unwrap(send_queue, auth, env)
                    elif env.type == EnvelopeType.JWKS:
                        await self._handle_jwks(send_queue, auth, env)
                    elif env.type in (EnvelopeType.SUBSCRIBE, EnvelopeType.UNSUBSCRIBE):
                        # Заглушки для подписок — реализуйте шину событий
                        await self._enqueue(send_queue, {"type": "ack", "id": env.id, "ok": True})
                    else:
                        await self._send_error(send_queue, env.id, "unsupported", f"Unsupported type {env.type}")
                except Exception as e:
                    logger.exception("ws op failed: %s", e)
                    await self._send_error(send_queue, env.id, "internal", "Internal error")

        finally:
            alive = False
            sender_task.cancel()
            hb_task.cancel()
            await self._release_connection_limits(auth.tenant, ip)
            self._metric("ws_disconnected", {"tenant": auth.tenant, "ip": ip})

    # --------------- Обработчики операций ---------------
    async def _handle_sign(self, q: asyncio.Queue[bytes], auth: AuthContext, env: Envelope) -> None:
        svc = await self._get_key_service()
        op = SignIn(**(env.op or {}))
        key, version = self._split_name_ref(op.name_ref)
        sig = await svc.sign(auth.tenant, key, version, op)
        await self._enqueue(q, {"type": "ack", "id": env.id, "ok": True, "signature": self._maybe_str(sig)})

    async def _handle_verify(self, q: asyncio.Queue[bytes], auth: AuthContext, env: Envelope) -> None:
        svc = await self._get_key_service()
        op = VerifyIn(**(env.op or {}))
        ok = await svc.verify(auth.tenant, op, op.name_ref)
        await self._enqueue(q, {"type": "ack", "id": env.id, "ok": bool(ok)})

    async def _handle_encrypt(self, q: asyncio.Queue[bytes], auth: AuthContext, env: Envelope) -> None:
        svc = await self._get_key_service()
        op = EncryptIn(**(env.op or {}))
        out = await svc.encrypt(auth.tenant, op.name_ref, op)
        await self._enqueue(q, {"type": "ack", "id": env.id, "ok": True, **self._bytes_to_str(out)})

    async def _handle_decrypt(self, q: asyncio.Queue[bytes], auth: AuthContext, env: Envelope) -> None:
        svc = await self._get_key_service()
        op = DecryptIn(**(env.op or {}))
        pt = await svc.decrypt(auth.tenant, op.name_ref, op)
        await self._enqueue(q, {"type": "ack", "id": env.id, "ok": True, "plaintext": self._maybe_str(pt)})

    async def _handle_wrap(self, q: asyncio.Queue[bytes], auth: AuthContext, env: Envelope) -> None:
        svc = await self._get_key_service()
        op = WrapIn(**(env.op or {}))
        wrapped = await svc.wrap_key(auth.tenant, op.name_ref, op)
        await self._enqueue(q, {"type": "ack", "id": env.id, "ok": True, "wrapped_key": self._maybe_str(wrapped)})

    async def _handle_unwrap(self, q: asyncio.Queue[bytes], auth: AuthContext, env: Envelope) -> None:
        svc = await self._get_key_service()
        op = UnwrapIn(**(env.op or {}))
        keymat = await svc.unwrap_key(auth.tenant, op.name_ref, op)
        await self._enqueue(q, {"type": "ack", "id": env.id, "ok": True, "key_material": self._maybe_str(keymat)})

    async def _handle_jwks(self, q: asyncio.Queue[bytes], auth: AuthContext, env: Envelope) -> None:
        svc = await self._get_key_service()
        jwks = await svc.get_jwks(auth.tenant, flt=None, include_inactive=False)
        await self._enqueue(q, {"type": "ack", "id": env.id, "ok": True, "jwks": jwks.model_dump()})

    # --------------- Хелперы отправки ---------------
    async def _enqueue(self, q: asyncio.Queue[bytes], obj: Mapping[str, Any]) -> None:
        payload = _json_dumps(obj)
        try:
            q.put_nowait(payload)
        except asyncio.QueueFull:
            # backpressure: честно закрываем
            raise WebSocketDisconnect(code=1013)

    async def _send_error(self, q: asyncio.Queue[bytes], msg_id: Optional[str], code: str, message: str) -> None:
        err = {"type": "error", "id": msg_id, "code": code, "message": message}
        await self._enqueue(q, err)

    def _bytes_to_str(self, d: Mapping[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for k, v in d.items():
            if isinstance(v, bytes):
                out[k] = v.decode("utf-8")
            else:
                out[k] = v
        return out

    def _maybe_str(self, v: Any) -> Any:
        return v.decode("utf-8") if isinstance(v, bytes) else v

    def _split_name_ref(self, name_ref: str) -> Tuple[str, int]:
        """
        Преобразует:
          - 'keys/mykey' -> ('mykey', 0)  # 0 = использовать primary
          - 'keys/mykey/versions/3' -> ('mykey', 3)
        """
        parts = name_ref.split("/")
        if len(parts) == 2 and parts[0] == "keys":
            return parts[1], 0
        if len(parts) == 4 and parts[0] == "keys" and parts[2] == "versions":
            try:
                return parts[1], int(parts[3])
            except ValueError:
                pass
        raise ValueError("invalid name_ref format")


# ========================== Фабрики DI (подмените в приложении) ==========================

async def get_key_service() -> KeyService:
    raise RuntimeError("KeyService is not configured")


class _SimpleAuth(AuthProvider):
    async def authenticate(self, ws: WebSocket) -> AuthContext:
        # Пример: извлекаем тенанта и токен
        tenant = ws.headers.get("x-tenant-id") or "default"
        authz = ws.headers.get("authorization") or ""
        if not authz.lower().startswith("bearer "):
            raise PermissionError("missing bearer token")
        token = authz[7:].strip()
        # В реальном коде — верификация JWT/OPA/MTLS
        sub = hashlib.sha256(token.encode()).hexdigest()[:16]
        return AuthContext(tenant=tenant, subject=sub, scopes=["ws:use"])

async def get_auth_provider() -> AuthProvider:
    return _SimpleAuth()


# ========================== Фабрика сервера и роутер ==========================

def build_ws_router(
    cfg: Optional[WSConfig] = None,
    key_service_provider: Callable[[], Awaitable[KeyService]] = get_key_service,
    auth_provider: Callable[[], Awaitable[AuthProvider]] = get_auth_provider,
    redis: Optional[Redis] = None,  # type: ignore[type-arg]
    metrics_hook: Optional[Callable[[str, Mapping[str, Any]], None]] = None,
) -> APIRouter:
    """
    Возвращает APIRouter с маршрутом WS. Пример подключения:

        app = FastAPI()
        router = build_ws_router(cfg=WSConfig(), key_service_provider=di_key_service, auth_provider=di_auth, redis=redis)
        app.include_router(router)
    """
    server = SecCoreWebSocketServer(
        cfg=cfg or WSConfig(),
        key_service_provider=key_service_provider,
        auth_provider=auth_provider,
        redis=redis,
        metrics_hook=metrics_hook,
    )
    return server.get_router()
