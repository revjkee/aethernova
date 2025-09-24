# SPDX-License-Identifier: Apache-2.0
"""
genius_core.security.self_inhibitor.strategies.rate_limiter

Промышленный rate limiter c многими стратегиями и бэкендами (in-memory, Redis).
Подходит для self-inhibitor слоя ИИ-агентов и HTTP/API входа.

Зависимости:
  - стандартная библиотека
  - опционально: redis>=4 (для RedisBackend), асинхронный клиент redis.asyncio

Возможности:
  - Стратегии: TokenBucket, SlidingWindow, Concurrency
  - Агрегатор MultiLimiter (AND-логика: deny любой стратегии -> deny целиком)
  - InMemoryBackend (локальный, потокобезопасный для asyncio)
  - RedisBackend (Lua-скрипты, атомарность, k/v с TTL)
  - Sync/Async API: allow(), allow_sync(); декоратор @rate_limited и контекст-менеджер
  - Прецизионный retry_after, remaining, reset_at, причины блокировки
  - Инъекция источника времени для тестов; структурное логирование и исключения

Ключевые концепции:
  - keys: составные ключи вида "tenant:user:ip:tool:model"
  - cost: стоимость операции, целое (для TokenBucket)
  - concurrency TTL: страховка от "забытых" релизов при сбоях

Примечание: для RedisBackend требуется настроенный Redis и установленный пакет redis.
"""

from __future__ import annotations

import asyncio
import logging
import math
import random
import time
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Iterable, List, Mapping, Optional, Protocol, Tuple

# ----------------------------- Время/логирование -----------------------------

class TimeProvider(Protocol):
    def now(self) -> float:  # монотонные секунды
        ...

    def wall(self) -> float:  # epoch сек
        ...

class _DefaultTime(TimeProvider):
    def now(self) -> float:
        return time.monotonic()

    def wall(self) -> float:
        return time.time()

# ----------------------------- Модель решения --------------------------------

@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    key: str
    strategy: str
    reason: str
    limit: int
    remaining: int
    reset_at: float  # epoch seconds, когда окно/бакет гарантированно обновится
    retry_after: float  # секунды до следующей попытки
    meta: Mapping[str, Any] = field(default_factory=dict)

class RateLimitError(RuntimeError):
    pass

class RateLimitExceeded(RateLimitError):
    def __init__(self, decision: RateLimitDecision):
        super().__init__(f"rate limited: {decision.strategy} reason={decision.reason} key={decision.key} "
                         f"retry_after={decision.retry_after:.3f}s")
        self.decision = decision

# -------------------------------- Бэкенды ------------------------------------

class Backend(ABC):
    """Интерфейс для хранилища состояния стратегий."""

    @abstractmethod
    async def token_bucket_acquire(
        self, key: str, capacity: int, refill_rate_per_s: float, cost: int, now: float
    ) -> Tuple[bool, int, float, float]:
        """
        Возвращает (allowed, remaining_tokens, reset_at_epoch, retry_after_sec).
        """
        raise NotImplementedError

    @abstractmethod
    async def sliding_window_acquire(
        self, key: str, window_seconds: int, limit: int, now: float
    ) -> Tuple[bool, int, float, float]:
        """
        Возвращает (allowed, remaining, reset_at_epoch, retry_after_sec).
        remaining = max(limit - current, 0)
        """
        raise NotImplementedError

    @abstractmethod
    async def concurrency_try_acquire(
        self, key: str, limit: int, ttl_seconds: int, now: float
    ) -> Tuple[bool, int, float]:
        """
        Возвращает (allowed, current, retry_after_sec).
        При allow — увеличивает счётчик и устанавливает TTL.
        """
        raise NotImplementedError

    @abstractmethod
    async def concurrency_release(self, key: str) -> None:
        """Уменьшает счётчик in-flight до минимума 0."""
        raise NotImplementedError


class InMemoryBackend(Backend):
    """
    Локальная реализация. Для asyncio — использует per-key Lock.
    Память очищается лениво по TTL/старости.
    """

    def __init__(self, time_provider: Optional[TimeProvider] = None, logger: Optional[logging.Logger] = None):
        self.t = time_provider or _DefaultTime()
        self.log = logger or logging.getLogger("rate_limiter.mem")

        # TokenBucket: key -> (tokens: float, last_refill: float, capacity, rate)
        self._tb: Dict[str, Tuple[float, float, int, float]] = {}
        # SlidingWindow: key -> deque[timestamps]; очищается по мере использования
        self._sw: Dict[str, Deque[float]] = {}
        # Concurrency: key -> (count: int, expiry: float)
        self._cc: Dict[str, Tuple[int, float]] = {}

        self._locks: Dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    def _gc_concurrency(self, now: float) -> None:
        stale = [k for k, (_, exp) in self._cc.items() if exp < now]
        for k in stale:
            self._cc.pop(k, None)

    async def token_bucket_acquire(
        self, key: str, capacity: int, refill_rate_per_s: float, cost: int, now: float
    ) -> Tuple[bool, int, float, float]:
        lock = self._locks[key]
        async with lock:
            tokens, last_refill, cap, rate = self._tb.get(key, (float(capacity), now, capacity, refill_rate_per_s))
            # Рефил
            dt = max(0.0, now - last_refill)
            tokens = min(capacity, tokens + rate * dt)
            allowed = tokens >= cost
            if allowed:
                tokens -= cost
                retry_after = 0.0
            else:
                # время до накопления нужного количества токенов
                need = max(0.0, cost - tokens)
                retry_after = need / max(1e-9, rate)
            self._tb[key] = (tokens, now, capacity, refill_rate_per_s)
            remaining = int(math.floor(tokens))
            # reset_at — когда бакет гарантированно будет полон при отсутствии трафика
            fill_to_full = (capacity - tokens) / max(1e-9, rate)
            reset_at = self.t.wall() + fill_to_full
            return allowed, remaining, reset_at, retry_after

    async def sliding_window_acquire(
        self, key: str, window_seconds: int, limit: int, now: float
    ) -> Tuple[bool, int, float, float]:
        lock = self._locks[key]
        async with lock:
            q = self._sw.get(key)
            if q is None:
                q = deque()
                self._sw[key] = q
            # очистка старых событий
            window_start = now - window_seconds
            while q and q[0] <= window_start:
                q.popleft()
            allowed = len(q) < limit
            if allowed:
                q.append(now)
                remaining = limit - len(q)
                retry_after = 0.0
                reset_at = self.t.wall() + window_seconds
            else:
                remaining = 0
                # до выхода из окна первой записи
                retry_after = max(0.0, (q[0] + window_seconds) - now)
                reset_at = self.t.wall() + retry_after
            return allowed, remaining, reset_at, retry_after

    async def concurrency_try_acquire(
        self, key: str, limit: int, ttl_seconds: int, now: float
    ) -> Tuple[bool, int, float]:
        self._gc_concurrency(now)
        lock = self._locks[key]
        async with lock:
            count, expiry = self._cc.get(key, (0, now + ttl_seconds))
            if count < limit:
                count += 1
                expiry = now + ttl_seconds
                self._cc[key] = (count, expiry)
                return True, count, 0.0
            else:
                retry_after = max(0.0, expiry - now)
                return False, count, retry_after

    async def concurrency_release(self, key: str) -> None:
        lock = self._locks[key]
        async with lock:
            count, expiry = self._cc.get(key, (0, self.t.now()))
            count = max(0, count - 1)
            if count == 0:
                self._cc.pop(key, None)
            else:
                self._cc[key] = (count, expiry)

# ---------------------------- Redis Backend (опц.) ---------------------------

class RedisBackend(Backend):
    """
    Redis-реализация, обеспечивающая атомарность через Lua.
    Требует redis>=4; клиент: redis.asyncio.
    """

    _TB_LUA = """
    -- KEYS[1] = state key
    -- ARGV: capacity, rate, cost, now_sec
    local cap = tonumber(ARGV[1])
    local rate = tonumber(ARGV[2])
    local cost = tonumber(ARGV[3])
    local now = tonumber(ARGV[4])

    local state = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
    local tokens = tonumber(state[1])
    local ts = tonumber(state[2])

    if not tokens or not ts then
      tokens = cap
      ts = now
    end

    local elapsed = math.max(0, now - ts)
    tokens = math.min(cap, tokens + rate * elapsed)

    local allowed = 0
    local retry_after = 0
    if tokens >= cost then
      tokens = tokens - cost
      allowed = 1
    else
      local need = math.max(0, cost - tokens)
      if rate > 0 then
        retry_after = need / rate
      else
        retry_after = 3600
      end
    end

    redis.call('HMSET', KEYS[1], 'tokens', tokens, 'ts', now, 'cap', cap, 'rate', rate)
    -- TTL: чтобы ключи не росли бесконечно (в 10x от времени полного наполнения)
    local ttl = math.floor((cap / math.max(rate, 0.001)) * 10)
    if ttl < 60 then ttl = 60 end
    redis.call('EXPIRE', KEYS[1], ttl)

    local remaining = math.floor(tokens)
    local fill_to_full = (cap - tokens) / math.max(rate, 0.001)
    local reset_at = now + fill_to_full
    return {allowed, remaining, reset_at, retry_after}
    """

    _SW_LUA = """
    -- KEYS[1] = zset key (timestamps)
    -- ARGV: window_seconds, limit, now_sec
    local win = tonumber(ARGV[1])
    local limit = tonumber(ARGV[2])
    local now = tonumber(ARGV[3])
    local start = now - win

    redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, start)
    local cur = redis.call('ZCARD', KEYS[1])
    if cur < limit then
      redis.call('ZADD', KEYS[1], now, tostring(now) .. "-" .. tostring(math.random()))
      redis.call('EXPIRE', KEYS[1], win * 2)
      local remaining = limit - (cur + 1)
      return {1, remaining, now + win, 0}
    else
      local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
      local oldest_ts = tonumber(oldest[2])
      local retry_after = math.max(0, oldest_ts + win - now)
      redis.call('EXPIRE', KEYS[1], win * 2)
      return {0, 0, now + retry_after, retry_after}
    end
    """

    _CC_LUA = """
    -- KEYS[1] = counter key
    -- ARGV: limit, ttl_seconds, now_sec
    local limit = tonumber(ARGV[1])
    local ttl = tonumber(ARGV[2])
    local now = tonumber(ARGV[3])

    local cur = tonumber(redis.call('GET', KEYS[1]) or '0')
    if cur < limit then
      cur = cur + 1
      redis.call('SET', KEYS[1], cur, 'EX', ttl)
      return {1, cur, 0}
    else
      local ttl_left = redis.call('TTL', KEYS[1])
      if ttl_left < 0 then ttl_left = ttl end
      return {0, cur, ttl_left}
    end
    """

    def __init__(self, client, namespace: str = "rl", time_provider: Optional[TimeProvider] = None, logger: Optional[logging.Logger] = None):
        """
        client: redis.asyncio.Redis
        """
        self.r = client
        self.ns = namespace
        self.t = time_provider or _DefaultTime()
        self.log = logger or logging.getLogger("rate_limiter.redis")

        # Предзагрузка Lua-скриптов
        self._tb_sha = None
        self._sw_sha = None
        self._cc_sha = None

    def _key(self, kind: str, key: str) -> str:
        return f"{self.ns}:{kind}:{key}"

    async def _ensure_scripts(self) -> None:
        if self._tb_sha is None:
            self._tb_sha = await self.r.script_load(self._TB_LUA)
        if self._sw_sha is None:
            self._sw_sha = await self.r.script_load(self._SW_LUA)
        if self._cc_sha is None:
            self._cc_sha = await self.r.script_load(self._CC_LUA)

    async def token_bucket_acquire(
        self, key: str, capacity: int, refill_rate_per_s: float, cost: int, now: float
    ) -> Tuple[bool, int, float, float]:
        await self._ensure_scripts()
        full_key = self._key("tb", key)
        res = await self.r.evalsha(self._tb_sha, 1, full_key, capacity, refill_rate_per_s, cost, now)
        allowed, remaining, reset_at, retry_after = res
        # reset_at пришёл в монотонных секундах; приведём к epoch
        wall = self.t.wall()
        delta = reset_at - now
        return bool(allowed), int(remaining), wall + max(0.0, float(delta)), float(retry_after)

    async def sliding_window_acquire(
        self, key: str, window_seconds: int, limit: int, now: float
    ) -> Tuple[bool, int, float, float]:
        await self._ensure_scripts()
        full_key = self._key("sw", key)
        res = await self.r.evalsha(self._sw_sha, 1, full_key, window_seconds, limit, now)
        allowed, remaining, reset_at, retry_after = res
        wall = self.t.wall()
        delta = reset_at - now
        return bool(allowed), int(remaining), wall + max(0.0, float(delta)), float(retry_after)

    async def concurrency_try_acquire(
        self, key: str, limit: int, ttl_seconds: int, now: float
    ) -> Tuple[bool, int, float]:
        await self._ensure_scripts()
        full_key = self._key("cc", key)
        allowed, current, retry = await self.r.evalsha(self._cc_sha, 1, full_key, limit, ttl_seconds, now)
        return bool(allowed), int(current), float(retry)

    async def concurrency_release(self, key: str) -> None:
        full_key = self._key("cc", key)
        # атомарного декремента с запретом уйти ниже 0 достаточно:
        pipe = self.r.pipeline()
        pipe.get(full_key)
        vals = await pipe.execute()
        cur = int(vals[0] or 0)
        if cur <= 1:
            await self.r.delete(full_key)
        else:
            await self.r.decr(full_key)
            await self.r.expire(full_key, 30)  # продлеваем на разумный TTL

# -------------------------------- Стратегии ----------------------------------

class Strategy(ABC):
    name: str

    @abstractmethod
    async def acquire(self, key: str) -> RateLimitDecision:
        ...

@dataclass
class TokenBucketConfig:
    capacity: int = 60
    refill_rate_per_s: float = 1.0  # токенов в секунду
    cost: int = 1
    limit_label: str = "requests/minute"

class TokenBucket(Strategy):
    """
    Классический Token Bucket.
    """
    def __init__(self, backend: Backend, cfg: TokenBucketConfig, time_provider: Optional[TimeProvider] = None, name: str = "token_bucket"):
        self.backend = backend
        self.cfg = cfg
        self.name = name
        self.t = time_provider or _DefaultTime()

    async def acquire(self, key: str) -> RateLimitDecision:
        now = self.t.now()
        allowed, remaining, reset_at, retry = await self.backend.token_bucket_acquire(
            key, self.cfg.capacity, self.cfg.refill_rate_per_s, self.cfg.cost, now
        )
        reason = "ok" if allowed else "insufficient_tokens"
        return RateLimitDecision(
            allowed=allowed,
            key=key,
            strategy=self.name,
            reason=reason,
            limit=self.cfg.capacity,
            remaining=remaining,
            reset_at=reset_at,
            retry_after=retry,
            meta={"limit_label": self.cfg.limit_label, "cost": self.cfg.cost},
        )

@dataclass
class SlidingWindowConfig:
    window_seconds: int = 60
    limit: int = 60
    limit_label: str = "requests/window"

class SlidingWindow(Strategy):
    """
    Скользящее окно: не более limit событий за window_seconds.
    """
    def __init__(self, backend: Backend, cfg: SlidingWindowConfig, time_provider: Optional[TimeProvider] = None, name: str = "sliding_window"):
        self.backend = backend
        self.cfg = cfg
        self.name = name
        self.t = time_provider or _DefaultTime()

    async def acquire(self, key: str) -> RateLimitDecision:
        now = self.t.now()
        allowed, remaining, reset_at, retry = await self.backend.sliding_window_acquire(
            key, self.cfg.window_seconds, self.cfg.limit, now
        )
        reason = "ok" if allowed else "window_exhausted"
        return RateLimitDecision(
            allowed=allowed,
            key=key,
            strategy=self.name,
            reason=reason,
            limit=self.cfg.limit,
            remaining=remaining,
            reset_at=reset_at,
            retry_after=retry,
            meta={"limit_label": self.cfg.limit_label, "window": self.cfg.window_seconds},
        )

@dataclass
class ConcurrencyConfig:
    limit: int = 10
    ttl_seconds: int = 30  # защита от забытых релизов
    limit_label: str = "concurrency"

class Concurrency(Strategy):
    """
    Ограничение одновременных операций. Используйте как асинхронный контекст.
    """
    def __init__(self, backend: Backend, cfg: ConcurrencyConfig, time_provider: Optional[TimeProvider] = None, name: str = "concurrency"):
        self.backend = backend
        self.cfg = cfg
        self.name = name
        self.t = time_provider or _DefaultTime()

    async def acquire(self, key: str) -> RateLimitDecision:
        now = self.t.now()
        allowed, current, retry = await self.backend.concurrency_try_acquire(key, self.cfg.limit, self.cfg.ttl_seconds, now)
        reason = "ok" if allowed else "concurrency_limit"
        reset_at = (_DefaultTime().wall() + retry) if retry > 0 else _DefaultTime().wall()
        remaining = max(0, self.cfg.limit - current)
        return RateLimitDecision(
            allowed=allowed,
            key=key,
            strategy=self.name,
            reason=reason,
            limit=self.cfg.limit,
            remaining=remaining,
            reset_at=reset_at,
            retry_after=retry,
            meta={"limit_label": self.cfg.limit_label},
        )

    async def release(self, key: str) -> None:
        await self.backend.concurrency_release(key)

    # Асинхронный контекст-менеджер для удобства
    def context(self, key: str):
        limiter = self
        class _Ctx:
            async def __aenter__(self_inner):
                d = await limiter.acquire(key)
                if not d.allowed:
                    raise RateLimitExceeded(d)
                self_inner._key = key
                return d
            async def __aexit__(self_inner, exc_type, exc, tb):
                await limiter.release(self_inner._key)
        return _Ctx()

# -------------------------- Агрегатор стратегий ------------------------------

@dataclass
class MultiLimiter:
    """
    AND-агрегатор: если любая стратегия вернёт deny — блокируем.
    """
    strategies: List[Tuple[Strategy, str]]  # (strategy, key_template)
    backoff_jitter: Tuple[float, float] = (0.85, 1.15)  # множитель для retry_after

    def render_key(self, template: str, **ctx: Any) -> str:
        # Небезопасная, но простая подстановка; ожидается, что template контролируем
        out = template
        for k, v in ctx.items():
            out = out.replace("{" + k + "}", str(v))
        return out

    async def allow(self, *, ctx: Mapping[str, Any]) -> RateLimitDecision:
        """
        Проверка набора стратегий. Вернёт первый deny с наибольшим retry_after, чтобы не «дёргать» систему.
        """
        denies: List[RateLimitDecision] = []
        last_ok: Optional[RateLimitDecision] = None
        for strat, tmpl in self.strategies:
            key = self.render_key(tmpl, **ctx)
            d = await strat.acquire(key)
            if not d.allowed:
                denies.append(d)
            else:
                last_ok = d
        if denies:
            # Выбираем самый строгий (максимальный retry_after) и добавляем джиттер
            worst = max(denies, key=lambda x: x.retry_after)
            jitter = random.uniform(*self.backoff_jitter)
            ra = max(0.0, worst.retry_after * jitter)
            return RateLimitDecision(
                allowed=False,
                key=worst.key,
                strategy=worst.strategy,
                reason=worst.reason,
                limit=worst.limit,
                remaining=worst.remaining,
                reset_at=worst.reset_at,
                retry_after=ra,
                meta={"denies": [d.strategy for d in denies]},
            )
        # Если все ок — возвращаем последнюю ok (для remaining/limit метаданных)
        assert last_ok is not None
        return last_ok

    # Sync-обёртка для удобства использования в синхронном коде
    def allow_sync(self, *, ctx: Mapping[str, Any], loop: Optional[asyncio.AbstractEventLoop] = None) -> RateLimitDecision:
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running and running.is_running():
            raise RuntimeError("allow_sync() нельзя вызывать из уже запущенного event loop")
        return asyncio.run(self.allow(ctx=ctx))

# ----------------------------- Декоратор/утилиты -----------------------------

def rate_limited(limiter: MultiLimiter, *, context_builder):
    """
    Декоратор для асинхронных функций.

    Пример:
        limiter = build_default_limiter(...)
        @rate_limited(limiter, context_builder=lambda *a, **kw: {"user": kw["user_id"]})
        async def handler(user_id: str): ...
    """
    def deco(fn):
        async def wrapper(*args, **kwargs):
            ctx = context_builder(*args, **kwargs)
            d = await limiter.allow(ctx=ctx)
            if not d.allowed:
                raise RateLimitExceeded(d)
            return await fn(*args, **kwargs)
        return wrapper
    return deco

# ------------------------ Удобные конструкторы (presets) ---------------------

def build_inmemory_default(
    *,
    per_user_rpm: int = 120,
    per_ip_rps: int = 10,
    global_concurrency: int = 100,
    window_s: int = 60,
    time_provider: Optional[TimeProvider] = None,
    logger: Optional[logging.Logger] = None,
) -> MultiLimiter:
    """
    Быстрый преднастрой: per-user RPM (token bucket), per-IP RPS (sliding window), глобальная конкуррентность.
    """
    tp = time_provider or _DefaultTime()
    be = InMemoryBackend(tp, logger)
    tb = TokenBucket(be, TokenBucketConfig(capacity=per_user_rpm, refill_rate_per_s=per_user_rpm / 60, cost=1, limit_label=f"{per_user_rpm}/min"), tp, name="user_rpm")
    sw = SlidingWindow(be, SlidingWindowConfig(window_seconds=1, limit=per_ip_rps, limit_label=f"{per_ip_rps}/sec"), tp, name="ip_rps")
    cc = Concurrency(be, ConcurrencyConfig(limit=global_concurrency, ttl_seconds=max(2, window_s)), tp, name="global_concurrency")
    strategies = [
        (tb, "user:{user}"),
        (sw, "ip:{ip}"),
        (cc, "global"),
    ]
    return MultiLimiter(strategies=strategies)

async def build_redis_default(
    redis_client,
    *,
    namespace: str = "rl",
    per_user_rpm: int = 120,
    per_ip_rps: int = 10,
    global_concurrency: int = 100,
    window_s: int = 60,
    time_provider: Optional[TimeProvider] = None,
    logger: Optional[logging.Logger] = None,
) -> MultiLimiter:
    """
    Преднастрой с Redis backend.
    """
    tp = time_provider or _DefaultTime()
    be = RedisBackend(redis_client, namespace, tp, logger)
    tb = TokenBucket(be, TokenBucketConfig(capacity=per_user_rpm, refill_rate_per_s=per_user_rpm / 60, cost=1, limit_label=f"{per_user_rpm}/min"), tp, name="user_rpm")
    sw = SlidingWindow(be, SlidingWindowConfig(window_seconds=1, limit=per_ip_rps, limit_label=f"{per_ip_rps}/sec"), tp, name="ip_rps")
    cc = Concurrency(be, ConcurrencyConfig(limit=global_concurrency, ttl_seconds=max(2, window_s)), tp, name="global_concurrency")
    return MultiLimiter(strategies=[(tb, "user:{user}"), (sw, "ip:{ip}"), (cc, "global")])

# ----------------------------- Пример использования --------------------------

if __name__ == "__main__":  # простая самопроверка
    import asyncio

    async def demo():
        logging.basicConfig(level=logging.INFO)
        limiter = build_inmemory_default(per_user_rpm=5, per_ip_rps=3, global_concurrency=2)

        async def one(i: int):
            try:
                d = await limiter.allow(ctx={"user": "u1", "ip": "1.2.3.4"})
                print(f"{i}: allowed, remaining={d.remaining}, strategy={d.strategy}")
                await asyncio.sleep(0.2)
            except RateLimitExceeded as e:
                print(f"{i}: DENY retry_after={e.decision.retry_after:.2f}s reason={e.decision.reason} by {e.decision.strategy}")

        # Параллельные вызовы
        await asyncio.gather(*(one(i) for i in range(10)))

        # Пример с Concurrency контекстом:
        inm = InMemoryBackend()
        cc = Concurrency(inm, ConcurrencyConfig(limit=1, ttl_seconds=5))
        async with cc.context("task:build"):
            print("running critical section")
            await asyncio.sleep(0.5)
        print("released")

    asyncio.run(demo())
