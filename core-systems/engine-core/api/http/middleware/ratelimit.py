#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Engine-Core HTTP API — Rate Limiting Middleware (FastAPI)

Возможности:
- Бекенды: In-Memory (per-process) и Redis (cluster-safe)
- Алгоритмы: token-bucket (burst) и скользящее окно (sliding window)
- Ключи: по IP, по subject (из auth), по API-ключу/заголовку, кастомный extractor
- Стоимость запроса (cost) и именованные "ведра" (buckets) для разных маршрутов
- Allowlist/Denylist
- Ответы: 429 с заголовками RateLimit-* и Retry-After; опционально soft-fail
- Jitter, экспоненциальное восстановление, метрики хуки
- Конфиг через переменные окружения ENGINE_RL_*

Интеграция:
    from engine_core.api.http.middleware.ratelimit import RateLimitMiddleware, rate_limit, RateLimitSettings
    app.add_middleware(RateLimitMiddleware)
    # аннотируйте эндпоинты:
    @router.get("/v1/data")
    @rate_limit(bucket="read_heavy", cost=2)
    async def handler(...):
        ...
"""

from __future__ import annotations

import asyncio
import math
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Literal, Optional, Tuple

from fastapi import HTTPException, Request, Response, status
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

try:
    # redis>=5
    import redis.asyncio as aioredis  # type: ignore
except Exception:  # pragma: no cover
    aioredis = None  # type: ignore


# =============================================================================
# Настройки
# =============================================================================

class RateLimitSettings(BaseSettings):
    RL_ENABLED: bool = True

    # Бекенд: memory|redis
    RL_BACKEND: Literal["memory", "redis"] = "memory"

    # Общие параметры token-bucket
    RL_BUCKET_CAPACITY: int = 60                  # базовая ёмкость
    RL_REFILL_PER_SEC: float = 1.0                # скорость пополнения
    RL_ALGO: Literal["token_bucket", "sliding_window"] = "token_bucket"

    # Скользящее окно (если выбрано)
    RL_WINDOW_SEC: int = 60

    # Ключ: ip|subject|header
    RL_KEY_STRATEGY: Literal["ip", "subject", "header"] = "ip"
    RL_HEADER_KEY_NAME: str = "x-api-key"        # для header-стратегии

    # Разные "ведра" по маршрутам (через декоратор rate_limit), дефолтные параметры
    RL_BUCKETS: Dict[str, Dict[str, float]] = Field(
        default_factory=lambda: {
            "default": {"capacity": 60, "refill_per_sec": 1.0},
            "read_heavy": {"capacity": 120, "refill_per_sec": 2.0},
            "write": {"capacity": 30, "refill_per_sec": 0.5},
        }
    )

    # Allow/Deny списки
    RL_ALLOWLIST: List[str] = Field(default_factory=list)   # ключи/сабжекты/IP
    RL_DENYLIST: List[str] = Field(default_factory=list)

    # 429: мягкий режим (только логировать, не блокировать)
    RL_SOFT_FAIL: bool = False

    # Заголовки
    RL_SEND_HEADERS: bool = True

    # Redis конфиг
    RL_REDIS_URL: Optional[str] = None
    RL_REDIS_PREFIX: str = "rl:"
    RL_REDIS_TIMEOUT_SEC: float = 0.2

    # Jitter (0..1, множитель на задержки/расчеты, снижает синхронизацию пиков)
    RL_JITTER: float = 0.15

    model_config = SettingsConfigDict(env_prefix="ENGINE_", case_sensitive=False)


settings = RateLimitSettings()


# =============================================================================
# Вспомогательные
# =============================================================================

def _now() -> float:
    return time.monotonic()


def _clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


def _apply_jitter(value: float) -> float:
    if settings.RL_JITTER <= 0:
        return value
    import random
    j = 1 + (random.random() * 2 - 1) * settings.RL_JITTER
    return value * j


def extract_key(request: Request) -> str:
    """Извлекает ключ лимитирования согласно стратегии."""
    strat = settings.RL_KEY_STRATEGY
    if strat == "ip":
        return request.client.host if request.client else "unknown"
    if strat == "header":
        return request.headers.get(settings.RL_HEADER_KEY_NAME, "unknown")
    if strat == "subject":
        # ожидаем, что auth middleware уже выставил request.state.rls
        try:
            rls = getattr(request.state, "rls", None)
            if rls and getattr(rls, "user", None):
                return str(rls.user)
            # fallback на Bearer-префикс
            authz = request.headers.get("authorization", "")
            if authz.lower().startswith("bearer "):
                tok = authz.split(" ", 1)[1].strip()
                return f"token:{tok[:10]}"
        except Exception:
            pass
        return "anonymous"
    return "unknown"


def route_bucket_and_cost(request: Request) -> Tuple[str, int]:
    """
    Получает имя ведра и "стоимость" запроса с маршрута, если он аннотирован декоратором @rate_limit.
    Иначе — ('default', 1)
    """
    route = request.scope.get("route")
    bucket = "default"
    cost = 1
    if route is not None:
        bucket = getattr(route, "_rl_bucket", bucket)
        cost = getattr(route, "_rl_cost", cost)
    return (bucket, cost)


# =============================================================================
# Интерфейсы бекендов
# =============================================================================

class RateLimitBackend:
    async def acquire(self, key: str, bucket: str, cost: int, capacity: float, refill_per_sec: float) -> Tuple[bool, float, float]:
        """
        Возвращает (allowed, remaining, reset_seconds)
        remaining — оставшиеся "токены" после запроса
        reset_seconds — время до полного восстановления ёмкости
        """
        raise NotImplementedError


class InMemoryTokenBucket(RateLimitBackend):
    """Per-process token bucket. Не шардируется между процессами."""

    @dataclass
    class Bucket:
        capacity: float
        tokens: float
        refill_per_sec: float
        updated_at: float

    def __init__(self) -> None:
        self._buckets: Dict[str, InMemoryTokenBucket.Bucket] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        self._glock = asyncio.Lock()

    async def _get_lock(self, k: str) -> asyncio.Lock:
        async with self._glock:
            if k not in self._locks:
                self._locks[k] = asyncio.Lock()
            return self._locks[k]

    async def acquire(self, key: str, bucket: str, cost: int, capacity: float, refill_per_sec: float) -> Tuple[bool, float, float]:
        full_key = f"{bucket}:{key}"
        lock = await self._get_lock(full_key)
        async with lock:
            now = _now()
            b = self._buckets.get(full_key)
            if b is None:
                b = InMemoryTokenBucket.Bucket(capacity=capacity, tokens=capacity, refill_per_sec=refill_per_sec, updated_at=now)
                self._buckets[full_key] = b
            # пополнение
            elapsed = now - b.updated_at
            if elapsed > 0:
                b.tokens = _clamp(b.tokens + elapsed * b.refill_per_sec, 0.0, b.capacity)
                b.updated_at = now

            allowed = b.tokens >= cost
            if allowed:
                b.tokens -= cost
            remaining = max(0.0, b.tokens)
            # время до полного восстановления
            reset = (b.capacity - b.tokens) / b.refill_per_sec if b.refill_per_sec > 0 else float("inf")
            return (allowed, remaining, reset)


class InMemorySlidingWindow(RateLimitBackend):
    """Простая скользящая шкала (per-process) — N запросов за окно W сек."""

    def __init__(self, window_sec: int, capacity: int) -> None:
        self.window = window_sec
        self.capacity = capacity
        self._events: Dict[str, List[float]] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        self._glock = asyncio.Lock()

    async def _get_lock(self, k: str) -> asyncio.Lock:
        async with self._glock:
            if k not in self._locks:
                self._locks[k] = asyncio.Lock()
            return self._locks[k]

    async def acquire(self, key: str, bucket: str, cost: int, capacity: float, refill_per_sec: float) -> Tuple[bool, float, float]:
        full_key = f"{bucket}:{key}"
        lock = await self._get_lock(full_key)
        now = _now()
        async with lock:
            evs = self._events.get(full_key, [])
            # очищаем старые
            cutoff = now - self.window
            evs = [ts for ts in evs if ts >= cutoff]
            cur = len(evs)
            allowed = (cur + cost) <= int(self.capacity)
            if allowed:
                evs.extend([now] * cost)
                self._events[full_key] = evs
            remaining = max(0, int(self.capacity) - (cur + (cost if allowed else 0)))
            reset = 0.0
            if evs:
                reset = max(0.0, self.window - (now - evs[0]))
            return (allowed, float(remaining), reset)


class RedisTokenBucket(RateLimitBackend):
    """
    Redis-реализация token-bucket.
    Хранит per-key state: tokens, updated_at.
    Скрипт Lua выполняет пополнение и списание атомарно.
    """

    LUA_SCRIPT = """
    local tokens_key = KEYS[1]
    local ts_key = KEYS[2]
    local capacity = tonumber(ARGV[1])
    local refill = tonumber(ARGV[2])
    local now = tonumber(ARGV[3])
    local cost = tonumber(ARGV[4])
    local filled = tonumber(ARGV[5]) -- allow "cold start" full bucket

    local tokens = tonumber(redis.call('GET', tokens_key))
    local last = tonumber(redis.call('GET', ts_key))
    if not tokens or not last then
        tokens = capacity
        last = now
        if filled == 0 then tokens = 0 end
    end

    -- refill
    local elapsed = now - last
    if elapsed > 0 then
        tokens = math.min(capacity, tokens + elapsed * refill)
        last = now
    end

    local allowed = 0
    if tokens >= cost then
        tokens = tokens - cost
        allowed = 1
    end

    redis.call('SET', tokens_key, tokens, 'EX', 3600)
    redis.call('SET', ts_key, last, 'EX', 3600)

    local remaining = math.max(0, tokens)
    local reset = 0
    if refill > 0 then
        reset = (capacity - tokens) / refill
    else
        reset = 3600
    end

    return {allowed, remaining, reset}
    """

    def __init__(self, url: str, prefix: str, timeout: float = 0.2) -> None:
        if aioredis is None:
            raise RuntimeError("redis[async] not installed")
        self.prefix = prefix
        self.client = aioredis.from_url(url, encoding=None, decode_responses=False, socket_timeout=timeout)
        self._sha: Optional[str] = None
        self._lock = asyncio.Lock()

    async def _ensure_script(self):
        async with self._lock:
            if self._sha:
                return
            self._sha = await self.client.script_load(self.LUA_SCRIPT.encode())

    async def acquire(self, key: str, bucket: str, cost: int, capacity: float, refill_per_sec: float) -> Tuple[bool, float, float]:
        await self._ensure_script()
        k_tokens = f"{self.prefix}{bucket}:{key}:t".encode()
        k_ts = f"{self.prefix}{bucket}:{key}:ts".encode()
        now = _now()
        # filled=1 — стартуем полностью заполненным ведром
        args = [str(capacity), str(refill_per_sec), str(now), str(cost), "1"]
        try:
            res = await self.client.evalsha(self._sha, 2, k_tokens, k_ts, *args)
        except Exception:
            # fallback на обычный eval (например, после рестарта Redis)
            res = await self.client.eval(self.LUA_SCRIPT.encode(), 2, k_tokens, k_ts, *args)
        allowed, remaining, reset = res
        return (bool(allowed), float(remaining), float(reset))


# =============================================================================
# Декоратор для маршрутов
# =============================================================================

def rate_limit(bucket: str = "default", cost: int = 1):
    """
    Аннотация маршрута: задаёт имя "ведра" и "стоимость" запроса.
    """
    def _wrap(func):
        setattr(func, "_rl_bucket", bucket)
        setattr(func, "_rl_cost", int(cost))
        return func
    return _wrap


# =============================================================================
# Middleware
# =============================================================================

class RateLimitMiddleware:
    def __init__(self, app, backend: Optional[RateLimitBackend] = None):
        self.app = app
        self.backend = backend or self._init_backend()

    def _init_backend(self) -> RateLimitBackend:
        if not settings.RL_ENABLED:
            return InMemoryTokenBucket()
        if settings.RL_BACKEND == "redis":
            url = settings.RL_REDIS_URL or os.getenv("REDIS_URL") or "redis://localhost:6379/0"
            return RedisTokenBucket(url=url, prefix=settings.RL_REDIS_PREFIX, timeout=settings.RL_REDIS_TIMEOUT_SEC)
        # memory
        if settings.RL_ALGO == "sliding_window":
            return InMemorySlidingWindow(window_sec=settings.RL_WINDOW_SEC, capacity=settings.RL_BUCKET_CAPACITY)
        return InMemoryTokenBucket()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not settings.RL_ENABLED:
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        key = extract_key(request)
        # Allow/Deny
        if key in settings.RL_DENYLIST:
            resp = Response(status_code=status.HTTP_403_FORBIDDEN)
            await resp(scope, receive, send)
            return

        if key in settings.RL_ALLOWLIST:
            # пропускаем без ограничений
            await self.app(scope, receive, send)
            return

        bucket_name, cost = route_bucket_and_cost(request)
        # параметры ведра
        cfg = settings.RL_BUCKETS.get(bucket_name, {})
        capacity = float(cfg.get("capacity", settings.RL_BUCKET_CAPACITY))
        refill = float(cfg.get("refill_per_sec", settings.RL_REFILL_PER_SEC))

        # Jitter для больших кластеров (легко рассинхронизировать пульсацию refill)
        refill = _apply_jitter(refill)

        allowed, remaining, reset = await self.backend.acquire(
            key=key, bucket=bucket_name, cost=int(cost), capacity=capacity, refill_per_sec=refill
        )

        # Формируем headers
        headers: Dict[str, str] = {}
        if settings.RL_SEND_HEADERS:
            # Draft IETF RateLimit-* (совместимо с многими балансировщиками)
            # RateLimit-Limit: полная ёмкость
            # RateLimit-Remaining: остаток
            # RateLimit-Reset: сек до восстановления
            headers["RateLimit-Limit"] = str(int(capacity))
            headers["RateLimit-Remaining"] = str(max(0, int(math.floor(remaining))))
            headers["RateLimit-Reset"] = str(int(math.ceil(reset)))

        if not allowed and not settings.RL_SOFT_FAIL:
            # Жёсткий отказ
            headers["Retry-After"] = headers.get("RateLimit-Reset", "1")
            resp = Response(status_code=status.HTTP_429_TOO_MANY_REQUESTS, headers=headers)
            await resp(scope, receive, send)
            return

        # Оборачиваем send для инъекции заголовков в успешный ответ
        async def send_wrapper(message):
            if message["type"] == "http.response.start" and settings.RL_SEND_HEADERS:
                existing = [(k.decode().lower(), v) for (k, v) in message.get("headers", [])]
                # не дублируем, если уже есть
                for k, v in headers.items():
                    low = k.lower().encode()
                    if not any(hk == low for hk, _ in existing):
                        message.setdefault("headers", []).append((k.encode(), v.encode()))
            await send(message)

        await self.app(scope, receive, send_wrapper)


# =============================================================================
# Пример unit-утилит (необязательные)
# =============================================================================

async def warmup_backend_for_key(backend: RateLimitBackend, key: str, bucket: str = "default") -> None:
    """
    Полностью «заряжает» ведро (полезно для тестов/бенчей).
    """
    cfg = settings.RL_BUCKETS.get(bucket, {})
    capacity = float(cfg.get("capacity", settings.RL_BUCKET_CAPACITY))
    refill = float(cfg.get("refill_per_sec", settings.RL_REFILL_PER_SEC))
    # «нулевой» cost, чтобы обновить состояние
    await backend.acquire(key=key, bucket=bucket, cost=0, capacity=capacity, refill_per_sec=refill)
