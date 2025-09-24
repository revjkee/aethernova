# zero-trust-core/api/http/middleware/ratelimit.py
# -*- coding: utf-8 -*-
"""
Промышленный ASGI middleware для лимитирования запросов (rate limiting).

Возможности:
- Политики по маршрутам (regex/prefix), методам, окружению.
- Ключи: IP, X-Forwarded-For, Client-Id (заголовок), JWT.sub (без валидации, опционально), пользователь из request.state.user.
- Алгоритмы: token_bucket (по умолчанию), sliding_window.
- Бэкенды: Redis (атомарно через Lua), InMemory (fallback, для dev/test).
- Shadow mode: не блокируем, но считаем и пишем заголовки/логи.
- Защита от падения Redis: деградация в память или в shadow на configurable TTL.
- Заголовки: RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset (RFC 9238) + X-RateLimit-* и Retry-After.
- Allowlist/Denylist, исключения для health-checks.
- Наблюдаемость: хуки метрик/логов, reason-коды.

Зависимости: redis.asyncio (опционально), Starlette/FastAPI (ASGI совместимость).
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import json
import logging
import os
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.responses import JSONResponse, Response
from starlette.middleware.middleware import Middleware

# Попытка загрузить redis.asyncio
_HAS_REDIS = False
try:  # pragma: no cover
    from redis.asyncio import Redis  # type: ignore
    _HAS_REDIS = True
except Exception:  # pragma: no cover
    _HAS_REDIS = False

logger = logging.getLogger("ratelimit")
logger.setLevel(logging.INFO)

# -----------------------------
# Политика и результаты
# -----------------------------

@dataclass
class RateLimitPolicy:
    """Описывает лимиты для набора запросов."""
    id: str
    limit: int                 # максимально разрешённых событий за окно
    window_seconds: float      # длина окна в секундах (для SW) / расчётная скорость (для TB)
    burst: int | None = None   # вместимость ведра (TB), по умолчанию = limit
    algorithm: str = "token_bucket"  # "token_bucket" | "sliding_window"
    methods: set[str] = field(default_factory=lambda: {"GET","HEAD","POST","PUT","PATCH","DELETE"})
    path_regex: str | None = None    # если задан — должен совпасть
    path_startswith: str | None = None
    key_type: str = "ip"       # "ip"|"client"|"user"|"jwt_sub"|"ip_user"|"custom"
    key_custom: Optional[Callable[[Scope], str]] = None
    enforce: bool = True       # если False — shadow mode на уровне политики
    response_status: int = 429
    retry_after_seconds: int | None = None
    headers: Mapping[str, str] | None = None  # дополнительные заголовки при 429
    include_headers: bool = True  # выдавать RateLimit-* заголовки
    # опции извлечения идентификаторов
    client_id_header: str = "x-client-id"
    trust_proxy: bool = True
    real_ip_header: str = "x-forwarded-for"  # берём первый IP из списка
    # исключения/Allow/Deny
    allowlist: Iterable[str] = field(default_factory=list)  # ключи, которые пропускаем
    denylist: Iterable[str] = field(default_factory=list)   # ключи, которые блокируем
    # jitter/против штормов
    jitter_seconds: float = 0.0

    def compiled(self) -> "CompiledPolicy":
        return CompiledPolicy(self)

@dataclass
class CompiledPolicy:
    policy: RateLimitPolicy
    _regex: Optional[re.Pattern] = None
    def __post_init__(self):
        if self.policy.path_regex:
            self._regex = re.compile(self.policy.path_regex)

    def matches(self, scope: Scope) -> bool:
        if scope["type"] != "http":
            return False
        method = scope.get("method", "GET").upper()
        if method not in self.policy.methods:
            return False
        path = scope.get("path", "/")
        if self._regex and not self._regex.search(path):
            return False
        if self.policy.path_startswith and not path.startswith(self.policy.path_startswith):
            return False
        return True

@dataclass
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    reset_epoch_ms: int
    key: str
    policy_id: str
    reason: str = "ok"  # ok|shadow|denylist|over_limit|backend_error|disabled
    retry_after_seconds: int | None = None

# -----------------------------
# Backend интерфейс
# -----------------------------

class RateLimitBackend(ABC):
    @abstractmethod
    async def acquire(self, key: str, policy: RateLimitPolicy, now_ms: int) -> RateLimitDecision:
        ...

    @abstractmethod
    async def close(self) -> None:
        ...

# -----------------------------
# Redis backend (Lua)
# -----------------------------

_TOKEN_BUCKET_LUA = """
-- KEYS[1] = bucket key
-- ARGV: now_ms, refill_rate_per_ms, capacity, cost
-- Модель: сохраняем кол-во токенов и timestamp последнего обновления.
local key = KEYS[1]
local now = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local capacity = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])

local data = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(data[1])
local ts = tonumber(data[2])

if tokens == nil then
  tokens = capacity
  ts = now
else
  local delta = math.max(now - ts, 0)
  tokens = math.min(capacity, tokens + delta * rate)
  ts = now
end

local allowed = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
end

redis.call('HMSET', key, 'tokens', tokens, 'ts', ts)
-- TTL чуть больше окна, чтобы не копить мусор.
local ttl = math.ceil((capacity / rate) / 1000) + 5
redis.call('EXPIRE', key, ttl)

-- remaining = floor(tokens)
local remaining = math.floor(tokens)
-- reset: до полного восстановления до capacity
local reset_ms = math.floor((capacity - tokens) / rate)

return {allowed, remaining, reset_ms}
"""

_SLIDING_WINDOW_LUA = """
-- KEYS[1] = window key
-- ARGV: now_ms, window_ms, limit, jitter_ms
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local jitter = tonumber(ARGV[4])

local start = now - window
-- удалим старые события
redis.call('ZREMRANGEBYSCORE', key, 0, start)
-- текущее количество
local count = redis.call('ZCARD', key)
local allowed = 0
if count < limit then
  allowed = 1
  redis.call('ZADD', key, now, tostring(now) .. "-" .. redis.sha1hex(key))
end
-- TTL = окно + джиттер
redis.call('PEXPIRE', key, window + jitter)

local remaining = limit - math.min(count + (allowed == 1 and 1 or 0), limit)
-- до окончания окна
local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
local reset_ms = 0
if oldest and oldest[2] then
  local oldest_score = tonumber(oldest[2])
  reset_ms = math.max(0, (oldest_score + window) - now)
end
return {allowed, remaining, reset_ms}
"""

class RedisBackend(RateLimitBackend):
    def __init__(self, redis: "Redis", namespace: str = "rl:", algorithm_default: str = "token_bucket"):
        if not _HAS_REDIS:
            raise RuntimeError("redis.asyncio is not available")
        self.r = redis
        self.ns = namespace
        self.algorithm_default = algorithm_default
        self._tb_sha: Optional[str] = None
        self._sw_sha: Optional[str] = None

    async def _ensure_scripts(self):
        if self._tb_sha is None:
            self._tb_sha = await self.r.script_load(_TOKEN_BUCKET_LUA)
        if self._sw_sha is None:
            self._sw_sha = await self.r.script_load(_SLIDING_WINDOW_LUA)

    def _key(self, raw: str) -> str:
        h = sha256(raw.encode("utf-8")).hexdigest()
        return f"{self.ns}{h}"

    async def acquire(self, key: str, policy: RateLimitPolicy, now_ms: int) -> RateLimitDecision:
        await self._ensure_scripts()
        storage_key = self._key(f"{policy.id}:{key}")
        try:
            if (policy.algorithm or self.algorithm_default) == "sliding_window":
                args = [now_ms, int(policy.window_seconds * 1000), policy.limit, int(policy.jitter_seconds * 1000)]
                res: List[int] = await self.r.evalsha(self._sw_sha, 1, storage_key, *args)  # type: ignore
                allowed, remaining, reset_ms = (int(res[0]), int(res[1]), int(res[2]))
            else:
                capacity = policy.burst if policy.burst is not None else policy.limit
                # refill_rate_per_ms = capacity / (window_seconds*1000)
                refill = float(capacity) / max(policy.window_seconds * 1000.0, 1.0)
                args = [now_ms, refill, int(capacity), 1]
                res: List[float] = await self.r.evalsha(self._tb_sha, 1, storage_key, *args)  # type: ignore
                allowed, remaining, reset_ms = (int(res[0]), int(res[1]), int(res[2]))
            decision = RateLimitDecision(
                allowed=bool(allowed),
                limit=policy.limit,
                remaining=max(0, remaining),
                reset_epoch_ms=now_ms + max(0, reset_ms),
                key=key,
                policy_id=policy.id,
                reason="ok" if allowed else "over_limit",
                retry_after_seconds=policy.retry_after_seconds or int(max(1, round(reset_ms / 1000.0))),
            )
            return decision
        except Exception as e:
            logger.exception("Redis backend error: %s", e)
            # В случае ошибок — мягкая деградация (разрешаем, но помечаем reason)
            return RateLimitDecision(
                allowed=True,
                limit=policy.limit,
                remaining=policy.limit,
                reset_epoch_ms=now_ms + int(policy.window_seconds * 1000),
                key=key,
                policy_id=policy.id,
                reason="backend_error",
                retry_after_seconds=1,
            )

    async def close(self) -> None:
        try:
            await self.r.close()
        except Exception:
            pass

# -----------------------------
# In-memory backend (token bucket)
# -----------------------------

class MemoryBucket:
    __slots__ = ("tokens", "ts")
    def __init__(self, capacity: int, ts_ms: int):
        self.tokens = float(capacity)
        self.ts = ts_ms

class InMemoryBackend(RateLimitBackend):
    def __init__(self, algorithm_default: str = "token_bucket"):
        self._buckets: Dict[str, MemoryBucket] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        self.algorithm_default = algorithm_default

    def _lock_for(self, key: str) -> asyncio.Lock:
        lock = self._locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key] = lock
        return lock

    async def acquire(self, key: str, policy: RateLimitPolicy, now_ms: int) -> RateLimitDecision:
        if (policy.algorithm or self.algorithm_default) == "sliding_window":
            # Для компактности: имитируем скользящее окно через TB (приближенно)
            # Рекомендуется использовать Redis для точного SW.
            pass  # нативная поддержка SW в памяти опущена — TB достаточно для fallback
        capacity = policy.burst if policy.burst is not None else policy.limit
        refill = float(capacity) / max(policy.window_seconds * 1000.0, 1.0)

        storage_key = f"{policy.id}:{key}"
        lock = self._lock_for(storage_key)
        async with lock:
            b = self._buckets.get(storage_key)
            if b is None:
                b = MemoryBucket(capacity, now_ms)
                self._buckets[storage_key] = b
            # refill
            delta = max(0, now_ms - b.ts)
            b.tokens = min(float(capacity), b.tokens + delta * refill)
            b.ts = now_ms
            allowed = False
            if b.tokens >= 1.0:
                b.tokens -= 1.0
                allowed = True
            remaining = int(b.tokens)
            reset_ms = int(max(0.0, (capacity - b.tokens) / refill))
        return RateLimitDecision(
            allowed=allowed,
            limit=policy.limit,
            remaining=max(0, remaining),
            reset_epoch_ms=now_ms + reset_ms,
            key=key,
            policy_id=policy.id,
            reason="ok" if allowed else "over_limit",
            retry_after_seconds=policy.retry_after_seconds or max(1, int(round(reset_ms / 1000.0))),
        )

    async def close(self) -> None:
        self._buckets.clear()
        self._locks.clear()

# -----------------------------
# Утилиты и извлечение ключа
# -----------------------------

def _first_ip_from_xff(header_val: str | None) -> str | None:
    if not header_val:
        return None
    # формат: "ip1, ip2, ip3"
    return header_val.split(",")[0].strip()

def _b64url_decode(s: str) -> bytes:
    try:
        pad = "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s + pad)
    except Exception:
        return b""

def _jwt_sub(header_val: str | None) -> str | None:
    if not header_val or not header_val.lower().startswith("bearer "):
        return None
    token = header_val.split(" ", 1)[1].strip()
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = json.loads(_b64url_decode(parts[1]) or b"{}")
        sub = payload.get("sub")
        if isinstance(sub, str) and sub:
            return sub
    except Exception:
        return None
    return None

def _hash_key(s: str) -> str:
    return sha256(s.encode("utf-8")).hexdigest()

def build_key(scope: Scope, pol: RateLimitPolicy) -> str:
    headers = dict(scope.get("headers") or [])
    # переведём байты в нижний регистр ключей
    h: Dict[str, str] = {}
    for k, v in headers.items():
        if isinstance(k, bytes):
            k = k.decode("latin-1")
        if isinstance(v, bytes):
            v = v.decode("latin-1")
        h[k.lower()] = v

    path = scope.get("path", "/")
    client = scope.get("client")
    client_ip = client[0] if client else None
    if pol.trust_proxy:
        fwd = _first_ip_from_xff(h.get(pol.real_ip_header.lower()))
        if fwd:
            client_ip = fwd

    match pol.key_type:
        case "ip":
            raw = client_ip or "unknown"
        case "client":
            raw = h.get(pol.client_id_header.lower(), "") or "unknown"
        case "user":
            # ожидаем наличие request.state.user.id (если прокидывается)
            state = scope.get("state") or {}
            user = getattr(state, "user", None) or state.get("user")
            user_id = getattr(user, "id", None) if user else None
            raw = str(user_id) if user_id else "anonymous"
        case "jwt_sub":
            raw = _jwt_sub(h.get("authorization")) or "anonymous"
        case "ip_user":
            sub = _jwt_sub(h.get("authorization")) or "anon"
            raw = f"{client_ip or 'unknown'}|{sub}"
        case "custom":
            if pol.key_custom:
                try:
                    raw = pol.key_custom(scope)
                except Exception:
                    raw = "custom_error"
            else:
                raw = "custom_undefined"
        case _:
            raw = client_ip or "unknown"
    # В ключ включаем базовые атрибуты маршрута для изоляции
    method = scope.get("method", "GET").upper()
    return _hash_key(f"{pol.id}:{method}:{path}:{raw}")

# -----------------------------
# Middleware
# -----------------------------

@dataclass
class RateLimitConfig:
    backend: RateLimitBackend
    policies: List[CompiledPolicy]
    default_policy: Optional[CompiledPolicy] = None
    shadow_mode: bool = False               # глобальный shadow (поверх per-policy)
    deny_on_backend_error: bool = False     # если True — 503 при ошибках бэкенда
    backend_error_shadow_ttl_sec: int = 30  # на сколько секунд включать shadow после ошибки
    metrics_hook: Optional[Callable[[RateLimitDecision, Scope], Awaitable[None]]] = None

class RateLimitMiddleware:
    """
    ASGI middleware: применяет первую подходящую политику из списка; если нет — default_policy.
    """

    def __init__(self, app: ASGIApp, config: RateLimitConfig):
        self.app = app
        self.cfg = config
        self._shadow_until = 0.0  # глобальная деградация при аварии бэкенда

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        now_ms = int(time.time() * 1000)
        pol = self._select_policy(scope)
        if not pol:
            await self.app(scope, receive, send)
            return

        key = build_key(scope, pol.policy)

        # Denylist/Allowlist на уровне ключей
        if key in set(pol.policy.denylist):
            await self._reject(scope, send, pol.policy, key, now_ms, reason="denylist")
            return
        if key in set(pol.policy.allowlist):
            # пропускаем и не считаем лимит
            await self._pass_through(scope, receive, send, pol.policy, key, now_ms, bypass=True)
            return

        # Глобальная деградация или shadow
        effective_shadow = self.cfg.shadow_mode or (not pol.policy.enforce) or (time.time() < self._shadow_until)

        decision = await self.cfg.backend.acquire(key, pol.policy, now_ms)

        # При ошибке backenda — либо шадоуем, либо 503/деградация
        if decision.reason == "backend_error":
            if self.cfg.deny_on_backend_error:
                await self._error_503(scope, send)
                return
            # включаем shadow на N секунд
            self._shadow_until = time.time() + max(1, self.cfg.backend_error_shadow_ttl_sec)
            effective_shadow = True

        if decision.allowed or effective_shadow:
            await self._pass_through(scope, receive, send, pol.policy, key, now_ms, decision)
        else:
            await self._reject(scope, send, pol.policy, key, now_ms, decision)

        # Метрики/хуки
        if self.cfg.metrics_hook:
            try:
                await self.cfg.metrics_hook(decision, scope)
            except Exception:
                logger.exception("metrics_hook failed")

    def _select_policy(self, scope: Scope) -> Optional[CompiledPolicy]:
        for p in self.cfg.policies:
            if p.matches(scope):
                return p
        return self.cfg.default_policy

    async def _pass_through(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        policy: RateLimitPolicy,
        now_ms: int,
        decision: Optional[RateLimitDecision] = None,
        bypass: bool = False,
    ) -> None:
        # Оборачиваем send, чтобы добавить заголовки после ответа
        async def send_wrapper(message: Dict[str, Any]) -> None:
            if message["type"] == "http.response.start" and policy.include_headers:
                headers = []
                if "headers" in message and message["headers"] is not None:
                    headers = list(message["headers"])
                # Вычислим remaining/reset
                if decision:
                    limit = str(policy.limit)
                    remaining = str(max(0, decision.remaining))
                    reset = str(max(0, int((decision.reset_epoch_ms - int(time.time()*1000)) / 1000)))
                else:
                    # bypass/allowlist
                    limit = str(policy.limit)
                    remaining = str(policy.limit)
                    reset = str(int(policy.window_seconds))

                # RFC 9238 заголовки
                headers.extend([
                    (b"ratelimit-limit", limit.encode()),
                    (b"ratelimit-remaining", remaining.encode()),
                    (b"ratelimit-reset", reset.encode()),
                ])
                # Совместимость с X-RateLimit-*
                headers.extend([
                    (b"x-ratelimit-limit", limit.encode()),
                    (b"x-ratelimit-remaining", remaining.encode()),
                    (b"x-ratelimit-reset", reset.encode()),
                ])
                message["headers"] = headers
            await send(message)
        await self.app(scope, receive, send_wrapper)

    async def _reject(
        self,
        scope: Scope,
        send: Send,
        policy: RateLimitPolicy,
        key: str,
        now_ms: int,
        decision: Optional[RateLimitDecision] = None,
        reason: str = "over_limit",
    ) -> None:
        status = policy.response_status
        retry_after = (decision.retry_after_seconds if decision and decision.retry_after_seconds is not None
                       else (policy.retry_after_seconds or max(1, int(policy.window_seconds))))
        body = {
            "error": "rate_limited",
            "policy_id": policy.id,
            "reason": decision.reason if decision else reason,
            "retry_after": retry_after,
        }
        headers: List[Tuple[bytes, bytes]] = []
        if policy.include_headers:
            limit = str(policy.limit)
            remaining = str(max(0, (decision.remaining if decision else 0)))
            reset = str(max(0, int(((decision.reset_epoch_ms if decision else (now_ms + int(policy.window_seconds*1000))) - int(time.time()*1000)) / 1000)))
            headers.extend([
                (b"content-type", b"application/json"),
                (b"ratelimit-limit", limit.encode()),
                (b"ratelimit-remaining", remaining.encode()),
                (b"ratelimit-reset", reset.encode()),
                (b"x-ratelimit-limit", limit.encode()),
                (b"x-ratelimit-remaining", remaining.encode()),
                (b"x-ratelimit-reset", reset.encode()),
                (b"retry-after", str(retry_after).encode()),
            ])
        if policy.headers:
            for k, v in policy.headers.items():
                headers.append((k.encode("latin-1"), v.encode("latin-1")))
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": headers
        })
        await send({
            "type": "http.response.body",
            "body": json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
            "more_body": False
        })

    async def _error_503(self, scope: Scope, send: Send) -> None:
        await send({
            "type": "http.response.start",
            "status": 503,
            "headers": [(b"content-type", b"application/json")]
        })
        await send({
            "type": "http.response.body",
            "body": b'{"error":"rate_limiter_unavailable"}',
            "more_body": False
        })

# -----------------------------
# Фабрики и удобные конфиги
# -----------------------------

def compile_policies(policies: Iterable[RateLimitPolicy]) -> List[CompiledPolicy]:
    return [p.compiled() for p in policies]

async def build_redis_backend_from_env() -> Optional[RedisBackend]:
    if not _HAS_REDIS:
        return None
    url = os.getenv("RATE_LIMIT_REDIS_URL", "redis://localhost:6379/0")
    socket_timeout = float(os.getenv("RATE_LIMIT_REDIS_TIMEOUT", "0.05"))  # 50ms
    try:
        r = Redis.from_url(url, encoding="utf-8", decode_responses=False, socket_timeout=socket_timeout)
        # Лёгкая проверка соединения
        await r.ping()
        return RedisBackend(r)
    except Exception as e:
        logger.warning("Redis unavailable (%s), falling back to in-memory backend", e)
        return None

async def default_backend() -> RateLimitBackend:
    rb = await build_redis_backend_from_env()
    if rb:
        return rb
    return InMemoryBackend()

def default_policies() -> List[RateLimitPolicy]:
    """
    Пример дефолтных политик:
    - /healthz и /metrics исключены (через специфичный middleware-стек).
    - Чтение: 300 r/m, запись: 60 r/m, админ: 30 r/m, по ключу ip_user.
    """
    return [
        RateLimitPolicy(
            id="read",
            limit=300, window_seconds=60, burst=300,
            algorithm="token_bucket",
            methods={"GET","HEAD"},
            path_startswith="/",
            key_type="ip_user",
            enforce=True,
            jitter_seconds=0.0,
        ),
        RateLimitPolicy(
            id="write",
            limit=60, window_seconds=60, burst=60,
            algorithm="token_bucket",
            methods={"POST","PUT","PATCH"},
            path_startswith="/",
            key_type="ip_user",
            enforce=True,
        ),
        RateLimitPolicy(
            id="admin",
            limit=30, window_seconds=60, burst=30,
            algorithm="sliding_window",
            methods={"DELETE"},
            path_startswith="/admin",
            key_type="jwt_sub",
            enforce=True,
            retry_after_seconds=60,
        ),
    ]

# -----------------------------
# Интеграция с FastAPI/Starlette
# -----------------------------

def asgi_middleware(app: ASGIApp,
                    policies: Optional[List[RateLimitPolicy]] = None,
                    default: Optional[RateLimitPolicy] = None,
                    shadow_mode: bool = False,
                    deny_on_backend_error: bool = False,
                    metrics_hook: Optional[Callable[[RateLimitDecision, Scope], Awaitable[None]]] = None
                    ) -> RateLimitMiddleware:
    compiled = compile_policies(policies or default_policies())
    default_c = default.compiled() if default else None
    # backend создаём синхронно как in-memory; Redis можно подключить позже
    backend = InMemoryBackend()
    cfg = RateLimitConfig(
        backend=backend,
        policies=compiled,
        default_policy=default_c,
        shadow_mode=shadow_mode,
        deny_on_backend_error=deny_on_backend_error,
        metrics_hook=metrics_hook,
    )
    return RateLimitMiddleware(app, cfg)

# -----------------------------
# Пример подключения в FastAPI:
# -----------------------------
# from fastapi import FastAPI
# app = FastAPI()
# policies = [
#     RateLimitPolicy(id="public-read", limit=300, window_seconds=60, methods={"GET"}, path_startswith="/", key_type="ip", enforce=True),
#     RateLimitPolicy(id="mutations", limit=60, window_seconds=60, methods={"POST","PUT","PATCH"}, path_startswith="/api", key_type="ip_user", enforce=True),
# ]
# rl = asgi_middleware(app, policies=policies)
# app.add_middleware(type(rl), config=rl.cfg)  # или вручную: app = rl(app)
#
# Для прод Redis:
# backend = await default_backend()
# rl.cfg.backend = backend
#
# Health/metrics эндпоинты лучше исключать отдельной политикой/стеком middleware.
