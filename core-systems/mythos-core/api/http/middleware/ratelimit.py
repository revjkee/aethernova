# -*- coding: utf-8 -*-
"""
Mythos Core — HTTP Rate Limiting Middleware (industrial)

Поддерживаемые возможности:
- Распределённый лимит на Redis (token bucket, атомарный Lua-скрипт).
- Локальный in-memory fallback (token bucket) с asyncio.Lock и монолитными часами.
- Политики на дефолт/маршрут/метод, исключения путей, «стоимость» запроса (cost).
- Извлечение идентичности: пользователь/ключ/IP, учёт X-Forwarded-For и доверенных прокси.
- Корректные заголовки: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, Retry-After.
- Поведение при сбоях Redis: allow_on_error=True|False.
- Хуки телеметрии (metrics_hook) для интеграции с наблюдаемостью.

Требования:
- Python 3.11+
- Starlette/FastAPI (для типов и BaseHTTPMiddleware).
- Опционально redis-py >= 4.6 (redis.asyncio) для Redis-бэкенда.

Пример подключения (FastAPI):
    from fastapi import FastAPI
    from mythos_core.api.http.middleware.ratelimit import (
        RateLimitMiddleware, RateLimitPolicy, RedisTokenBucketBackend
    )
    import redis.asyncio as aioredis

    app = FastAPI()

    redis = aioredis.from_url("redis://redis:6379/0", encoding="utf-8", decode_responses=False)

    default_policy = RateLimitPolicy(capacity=100, refill_amount=100, refill_interval=60.0)  # 100 req/мин
    backend = RedisTokenBucketBackend(redis, namespace="mythos:rl", ttl_seconds=600)

    app.add_middleware(
        RateLimitMiddleware,
        backend=backend,
        default_policy=default_policy,
        allow_on_error=True,
        trusted_proxies=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        exclude_paths={"/health", "/metrics"},
    )

Архитектурные примечания:
- Лимит считается для ключа (subject), который определяется функцией key_func(request), по умолчанию:
  X-API-Key -> request.state.user_id -> Authorization (только токен-строка) -> клиентский IP.
- Политика может быть переопределена на маршрут/метод через policy_resolver(request) -> RateLimitPolicy|None.
- Стоимость запроса (cost) аналогично определяется cost_func(request) -> int (по умолчанию 1).
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Iterable, Mapping, MutableMapping, Optional

try:
    # Lazy import типов Starlette (не падаем при статическом анализе вне рантайма)
    from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
    from starlette.types import ASGIApp
except Exception as _e:  # pragma: no cover
    raise RuntimeError("RateLimitMiddleware requires Starlette/FastAPI installed") from _e


# ---------- Политика (token bucket) ----------

@dataclass(frozen=True)
class RateLimitPolicy:
    """
    Политика токен-бакета.

    capacity: максимальное число токенов (размер бакета, равен пику допуска).
    refill_amount: сколько токенов добавляется раз в refill_interval секунд.
    refill_interval: период пополнения в секундах (float).
    """
    capacity: int
    refill_amount: int
    refill_interval: float

    def tokens_per_second(self) -> float:
        return self.refill_amount / self.refill_interval

    def validate(self) -> None:
        if self.capacity <= 0 or self.refill_amount <= 0 or self.refill_interval <= 0:
            raise ValueError("All policy parameters must be positive")


# ---------- Абстрактный backend ----------

class RateLimitDecision(Response):
    """
    Обёртка вокруг Response для совместимости; фактическая проверка возвращается из backend.
    Используем как DTO через обычные поля, а не HTTP-ответ.
    """
    def __init__(self, allowed: bool, remaining: int, limit: int, reset_seconds: float):
        # Response не используется; наследуемся только ради сигнатур. Не вызываем super().__init__.
        self.allowed = allowed
        self.remaining = max(0, remaining)
        self.limit = limit
        self.reset_seconds = max(0.0, reset_seconds)


class RateLimitBackend:
    async def allow(
        self,
        key: str,
        policy: RateLimitPolicy,
        cost: int = 1,
        now_ms: Optional[int] = None,
    ) -> RateLimitDecision:
        raise NotImplementedError


# ---------- Redis backend (token bucket via Lua) ----------

class RedisTokenBucketBackend(RateLimitBackend):
    """
    Атомарная реализация token bucket на Redis через Lua-скрипт.
    Хранение: HASH {t: tokens(float), u: last_ms(int)} с TTL.
    """

    LUA_SCRIPT = """
    -- KEYS[1] = key
    -- ARGV = capacity, refill_amount, refill_interval_s, cost, now_ms, ttl_seconds
    local k = KEYS[1]
    local capacity = tonumber(ARGV[1])
    local refill_amount = tonumber(ARGV[2])
    local refill_interval = tonumber(ARGV[3])
    local cost = tonumber(ARGV[4])
    local now_ms = tonumber(ARGV[5])
    local ttl_seconds = tonumber(ARGV[6])

    local data = redis.call('HMGET', k, 't', 'u')
    local tokens = tonumber(data[1])
    local last_ms = tonumber(data[2])

    if not tokens or not last_ms then
        tokens = capacity
        last_ms = now_ms
    end

    -- refill
    local delta_ms = now_ms - last_ms
    if delta_ms > 0 then
        local refill_tokens = (delta_ms / 1000.0) * (refill_amount / refill_interval)
        tokens = math.min(capacity, tokens + refill_tokens)
        last_ms = now_ms
    end

    local allowed = 0
    if tokens >= cost then
        tokens = tokens - cost
        allowed = 1
    end

    -- compute reset_seconds: сколько секунд до полного восстановления стоимости cost
    local deficit = math.max(0, cost - tokens)
    local per_sec = (refill_amount / refill_interval)
    local reset_seconds = 0.0
    if deficit > 0 then
        reset_seconds = deficit / per_sec
    end

    redis.call('HMSET', k, 't', tokens, 'u', last_ms)
    if ttl_seconds and ttl_seconds > 0 then
        redis.call('EXPIRE', k, ttl_seconds)
    end

    local remaining = math.floor(tokens + 0.000001) -- целая часть как приблизительный remaining
    return {allowed, remaining, reset_seconds}
    """

    def __init__(self, redis_client: "Any", namespace: str = "rl", ttl_seconds: int = 900) -> None:
        """
        redis_client: экземпляр redis.asyncio.Redis.
        namespace: префикс ключей Redis.
        ttl_seconds: TTL бакета (сек) при бездействии.
        """
        self.redis = redis_client
        self.ns = namespace.rstrip(":")
        self.ttl_seconds = int(ttl_seconds)
        self._sha: Optional[str] = None
        self._sha_lock = asyncio.Lock()

    def _key(self, subject: str) -> str:
        return f"{self.ns}:bucket:{subject}"

    async def _load_script(self) -> str:
        if self._sha:
            return self._sha
        async with self._sha_lock:
            if self._sha:
                return self._sha
            sha = await self.redis.script_load(self.LUA_SCRIPT)
            self._sha = sha
            return sha

    async def allow(
        self,
        key: str,
        policy: RateLimitPolicy,
        cost: int = 1,
        now_ms: Optional[int] = None,
    ) -> RateLimitDecision:
        policy.validate()
        if cost <= 0:
            cost = 1
        if cost > policy.capacity:
            # Стоимость запроса не может превышать ёмкость бакета
            return RateLimitDecision(False, 0, policy.capacity, reset_seconds=float("inf"))

        now_ms = now_ms or int(time.time() * 1000)
        sha = await self._load_script()
        try:
            res = await self.redis.evalsha(
                sha,
                1,
                self._key(key),
                policy.capacity,
                policy.refill_amount,
                policy.refill_interval,
                cost,
                now_ms,
                self.ttl_seconds,
            )
            # res: [allowed, remaining, reset_seconds]
            allowed = bool(res[0])
            remaining = int(res[1])
            reset_seconds = float(res[2])
            return RateLimitDecision(allowed, remaining, policy.capacity, reset_seconds)
        except Exception:
            # Пробросим исключение наружу: решение о fallback принимает middleware
            raise


# ---------- In-memory backend (fallback) ----------

class InMemoryTokenBucketBackend(RateLimitBackend):
    """
    Потокобезопасный in-memory токен-бакет.
    Использует time.monotonic() и asyncio.Lock на ключ.
    """

    def __init__(self, ttl_seconds: int = 900) -> None:
        self._store: MutableMapping[str, tuple[float, float]] = {}  # key -> (tokens, last_monotonic)
        self._locks: MutableMapping[str, asyncio.Lock] = {}
        self._ttl = float(ttl_seconds)
        self._last_access: MutableMapping[str, float] = {}

    def _lock(self, key: str) -> asyncio.Lock:
        lock = self._locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key] = lock
        return lock

    async def allow(
        self,
        key: str,
        policy: RateLimitPolicy,
        cost: int = 1,
        now_ms: Optional[int] = None,
    ) -> RateLimitDecision:
        policy.validate()
        if cost <= 0:
            cost = 1
        if cost > policy.capacity:
            return RateLimitDecision(False, 0, policy.capacity, reset_seconds=float("inf"))

        now = time.monotonic()
        async with self._lock(key):
            tokens, last = self._store.get(key, (float(policy.capacity), now))
            # refill
            dt = max(0.0, now - last)
            tokens = min(float(policy.capacity), tokens + dt * (policy.refill_amount / policy.refill_interval))
            last = now

            allowed = tokens >= cost
            if allowed:
                tokens -= cost

            # housekeeping
            self._store[key] = (tokens, last)
            self._last_access[key] = now

            deficit = max(0.0, cost - tokens)
            per_sec = (policy.refill_amount / policy.refill_interval)
            reset_seconds = (deficit / per_sec) if deficit > 0 else 0.0
            remaining = int(tokens + 1e-6)
            return RateLimitDecision(allowed, remaining, policy.capacity, reset_seconds)

    async def cleanup(self) -> None:
        """Мягкая очистка «старых» бакетов по TTL; можно вызывать периодически из фонового задания."""
        now = time.monotonic()
        keys = [k for k, ts in self._last_access.items() if (now - ts) > self._ttl]
        for k in keys:
            self._store.pop(k, None)
            self._last_access.pop(k, None)
            self._locks.pop(k, None)


# ---------- Утилиты идентичности/ключей ----------

def _compile_cidrs(cidrs: Iterable[str]) -> list[ipaddress._BaseNetwork]:
    nets: list[ipaddress._BaseNetwork] = []
    for c in cidrs or []:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except Exception:
            continue
    return nets


def _ip_from_request(request: "Request", trusted: list[ipaddress._BaseNetwork]) -> str:
    """
    Извлекает реальный клиентский IP с учётом доверенных прокси.
    Алгоритм: если remote_addr попадает в trusted, пробуем X-Forwarded-For (правый-налево),
    иначе используем напрямую client.host.
    """
    client_host = (request.client.host if request.client else "") or ""
    try:
        client_ip = ipaddress.ip_address(client_host)
    except Exception:
        client_ip = None

    if client_ip and any(client_ip in n for n in trusted):
        xff = request.headers.get("x-forwarded-for", "")
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            # Берём самый левый внешний IP (оригинал)
            return parts[0]
    # Альтернативные заголовки (best-effort)
    for h in ("true-client-ip", "cf-connecting-ip"):
        v = request.headers.get(h)
        if v:
            return v
    return client_host or "unknown"


async def default_key_func(request: "Request", trusted_proxies: list[ipaddress._BaseNetwork]) -> str:
    """
    Приоритет: X-API-Key -> request.state.user_id -> Authorization (сырая строка) -> IP.
    """
    api_key = request.headers.get("x-api-key")
    if api_key:
        return f"ak:{api_key}"
    user_id = getattr(getattr(request, "state", object()), "user_id", None)
    if user_id:
        return f"user:{user_id}"
    auth = request.headers.get("authorization")
    if auth:
        return f"auth:{auth}"
    return f"ip:{_ip_from_request(request, trusted_proxies)}"


async def default_cost_func(_: "Request") -> int:
    return 1


# ---------- Middleware ----------

MetricsHook = Callable[[Mapping[str, Any]], Awaitable[None] | None]
PolicyResolver = Callable[["Request"], Awaitable[Optional[RateLimitPolicy]] | Optional[RateLimitPolicy]]
KeyFunc = Callable[["Request", list[ipaddress._BaseNetwork]], Awaitable[str] | str]
CostFunc = Callable[["Request"], Awaitable[int] | int]


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Starlette/FastAPI middleware с гибкими политиками и Redis/in-memory backend.

    Параметры:
      backend: RateLimitBackend (RedisTokenBucketBackend | InMemoryTokenBucketBackend)
      default_policy: RateLimitPolicy
      policy_resolver: функция, возвращающая политику для конкретного запроса (или None)
      key_func: способ построения ключа лимита (по умолчанию default_key_func)
      cost_func: «стоимость» запроса (по умолчанию 1)
      allow_on_error: продолжать запрос при ошибке backend (True) или отвечать 429 (False)
      exclude_paths: множество путей для исключения из лимитов
      trusted_proxies: список CIDR строк для корректной обработки X-Forwarded-For
      metrics_hook: асинхронный хук телеметрии, получает словарь меток/значений
    """

    def __init__(
        self,
        app: "ASGIApp",
        *,
        backend: RateLimitBackend,
        default_policy: RateLimitPolicy,
        policy_resolver: Optional[PolicyResolver] = None,
        key_func: Optional[KeyFunc] = None,
        cost_func: Optional[CostFunc] = None,
        allow_on_error: bool = True,
        exclude_paths: Optional[Iterable[str]] = None,
        trusted_proxies: Optional[Iterable[str]] = None,
        metrics_hook: Optional[MetricsHook] = None,
    ) -> None:
        super().__init__(app)
        self.backend = backend
        self.default_policy = default_policy
        self.policy_resolver = policy_resolver
        self.key_func = key_func or default_key_func
        self.cost_func = cost_func or default_cost_func
        self.allow_on_error = bool(allow_on_error)
        self.exclude_paths = set(exclude_paths or [])
        self.trusted_proxies = _compile_cidrs(trusted_proxies or [])
        self.metrics_hook = metrics_hook

    async def dispatch(self, request: "Request", call_next: RequestResponseEndpoint) -> "Response":
        path = request.url.path
        if path in self.exclude_paths:
            return await call_next(request)

        # Политика (per-route/per-method, если задан policy_resolver)
        policy = self.default_policy
        if self.policy_resolver:
            pr = self.policy_resolver(request)
            policy = await pr if asyncio.iscoroutine(pr) else pr or self.default_policy

        # Ключ и стоимость
        kf = self.key_func(request, self.trusted_proxies)
        key = await kf if asyncio.iscoroutine(kf) else kf
        cf = self.cost_func(request)
        cost = await cf if asyncio.iscoroutine(cf) else cf
        now_ms = int(time.time() * 1000)

        # Разрешение бакетом
        allowed: bool
        remaining: int
        reset_seconds: float
        limit = policy.capacity
        backend_error: Optional[str] = None

        try:
            decision = await self.backend.allow(key=key, policy=policy, cost=cost, now_ms=now_ms)
            allowed, remaining, reset_seconds = decision.allowed, decision.remaining, decision.reset_seconds
        except Exception as e:
            backend_error = e.__class__.__name__
            if self.allow_on_error:
                allowed, remaining, reset_seconds = True, max(0, limit - cost), 0.0
            else:
                allowed, remaining, reset_seconds = False, 0, 60.0

        # Заголовки (добавляем в любом случае)
        headers = {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(max(0, remaining)),
            "X-RateLimit-Reset": f"{int(reset_seconds)}",
        }

        # Телеметрия (не блокируем основной путь)
        if self.metrics_hook:
            payload = {
                "key": key,
                "allowed": allowed,
                "remaining": remaining,
                "limit": limit,
                "reset_seconds": reset_seconds,
                "path": path,
                "method": request.method,
                "backend_error": backend_error,
                "cost": cost,
            }
            try:
                maybe_coro = self.metrics_hook(payload)
                if asyncio.iscoroutine(maybe_coro):
                    asyncio.create_task(maybe_coro)  # fire-and-forget
            except Exception:
                pass

        if not allowed:
            # 429 с Retry-After
            retry_after = max(1, int(reset_seconds))
            return JSONResponse(
                status_code=429,
                content={"detail": "Too Many Requests"},
                headers={**headers, "Retry-After": str(retry_after)},
            )

        # Продолжаем цепочку
        response = await call_next(request)
        # Дописываем заголовки в успешный ответ, но не перезаписываем существующие
        for k, v in headers.items():
            if k not in response.headers:
                response.headers[k] = v
        return response


# ---------- Удобные резолверы политики ----------

def method_route_policy_resolver(
    *,
    defaults: RateLimitPolicy,
    by_method: Optional[Mapping[str, RateLimitPolicy]] = None,
    by_path_prefix: Optional[Mapping[str, RateLimitPolicy]] = None,
) -> PolicyResolver:
    """
    Возвращает PolicyResolver, выбирающий политику по HTTP-методу или префиксу пути.
    Приоритет: by_path_prefix (длиннейший матч) -> by_method -> defaults.
    """
    path_map = by_path_prefix or {}
    method_map = {k.upper(): v for k, v in (by_method or {}).items()}

    def longest_prefix_match(path: str) -> Optional[RateLimitPolicy]:
        candidate: Optional[RateLimitPolicy] = None
        max_len = -1
        for prefix, pol in path_map.items():
            if path.startswith(prefix) and len(prefix) > max_len:
                candidate, max_len = pol, len(prefix)
        return candidate

    def resolver(request: "Request") -> Optional[RateLimitPolicy]:
        p = longest_prefix_match(request.url.path)
        if p:
            return p
        return method_map.get(request.method, defaults)

    return resolver
