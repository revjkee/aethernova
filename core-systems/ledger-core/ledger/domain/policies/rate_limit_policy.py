# ledger-core/ledger/domain/policies/rate_limit_policy.py
from __future__ import annotations

import asyncio
import dataclasses as dc
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# ==============================
# Конфигурация и типы ответов
# ==============================

@dc.dataclass(frozen=True)
class RateLimitConfig:
    """Параметры token bucket."""
    capacity: int = 60              # максимальный «ведёрный» запас токенов
    refill_per_sec: float = 30.0    # скорость восстановления (токенов/сек)
    window_hint_sec: int = 60       # подсказка верхнему уровню для Retry-After
    # Семантика ключей
    namespace: str = "ledger-core"
    # TTL состояния в бекенде: ≈ 2 окна по умолчанию
    state_ttl_sec: int = 120


@dc.dataclass(frozen=True)
class LimitKey:
    """Идентификатор лимита: tenant/subject/action [+ произвольный суффикс]."""
    tenant: str
    subject: str
    action: str
    extra: Optional[str] = None

    def as_str(self, ns: str) -> str:
        parts = [ns, self.tenant or "-", self.subject or "-", self.action or "-"]
        if self.extra:
            parts.append(self.extra)
        return ":".join(parts)


@dc.dataclass(frozen=True)
class RateDecision:
    allowed: bool
    # метаданные лимита
    remaining: int
    limit: int
    reset_after_ms: int
    retry_after_ms: int
    # для логирования/заголовков
    key: str

    def as_headers(self) -> Dict[str, str]:
        """
        Заголовки в стиле X-RateLimit-*, совместимы с REST/WS протоколами.
        """
        h = {
            "x-ratelimit-limit": str(self.limit),
            "x-ratelimit-remaining": str(max(0, self.remaining)),
            "x-ratelimit-reset": str(self.reset_after_ms // 1000),
        }
        if not self.allowed and self.retry_after_ms > 0:
            h["retry-after"] = str(max(1, self.retry_after_ms // 1000))
        return h


class RateLimitExceeded(Exception):
    """Доменная ошибка превышения лимита."""
    def __init__(self, decision: RateDecision) -> None:
        super().__init__("rate limit exceeded")
        self.decision = decision


# ===================================
# Абстрактный интерфейс rate limiter
# ===================================

class AsyncRateLimiter(ABC):
    """
    Абстракция «ведра» с атомарной операцией try_consume(cost).
    Возвращает (allowed, remaining, reset_after_ms).
    """
    def __init__(self, cfg: RateLimitConfig) -> None:
        self.cfg = cfg

    @abstractmethod
    async def try_consume(self, key: str, cost: int = 1, now_ms: Optional[int] = None) -> Tuple[bool, int, int]:
        """
        :return: (allowed, remaining, reset_after_ms)
        """
        raise NotImplementedError


# ===================================
# In-memory реализация (per-process)
# ===================================

class _BucketState:
    __slots__ = ("tokens", "updated_ms")
    def __init__(self, tokens: float, updated_ms: int) -> None:
        self.tokens = tokens
        self.updated_ms = updated_ms


class InMemoryTokenBucket(AsyncRateLimiter):
    """
    Безопасная для конкурентного доступа реализация на asyncio.
    Подходит для dev/test, как фолбэк в проде при деградации Redis.
    """
    def __init__(self, cfg: RateLimitConfig) -> None:
        super().__init__(cfg)
        self._states: Dict[str, _BucketState] = {}
        self._lock = asyncio.Lock()

    async def try_consume(self, key: str, cost: int = 1, now_ms: Optional[int] = None) -> Tuple[bool, int, int]:
        if cost < 0:
            cost = 0
        now_ms = now_ms or int(time.time() * 1000)
        refill_rate = self.cfg.refill_per_sec  # tokens per second
        capacity = float(self.cfg.capacity)

        async with self._lock:
            st = self._states.get(key)
            if st is None:
                st = _BucketState(tokens=capacity, updated_ms=now_ms)
                self._states[key] = st
            # восстановление токенов
            elapsed = max(0.0, (now_ms - st.updated_ms) / 1000.0)
            st.tokens = min(capacity, st.tokens + elapsed * refill_rate)
            st.updated_ms = now_ms

            if st.tokens >= cost:
                st.tokens -= cost
                remaining = int(st.tokens)
                reset_after_ms = int(1000 * max(0.0, (capacity - st.tokens) / max(1e-9, refill_rate)))
                return True, remaining, reset_after_ms
            else:
                # когда токенов не хватило
                deficit = cost - st.tokens
                reset_after_ms = int(1000 * deficit / max(1e-9, refill_rate))
                remaining = int(max(0.0, st.tokens))
                return False, remaining, reset_after_ms


# ===================================
# Redis реализация (атомарная)
# ===================================

class RedisTokenBucket(AsyncRateLimiter):
    """
    Атомарная реализация на Redis. Использует Lua-скрипт для O(1) обновления.
    Заводит два ключа на ведро: <key>:tokens и <key>:ts.
    """
    _LUA = """
    -- KEYS[1] = tokens key
    -- KEYS[2] = ts key
    -- ARGV[1] = capacity
    -- ARGV[2] = refill_per_sec
    -- ARGV[3] = now_ms
    -- ARGV[4] = cost
    -- ARGV[5] = state_ttl_sec
    local capacity = tonumber(ARGV[1])
    local refill = tonumber(ARGV[2])
    local now = tonumber(ARGV[3])
    local cost = tonumber(ARGV[4])
    local ttl = tonumber(ARGV[5])

    local tokens = tonumber(redis.call("GET", KEYS[1]))
    local ts = tonumber(redis.call("GET", KEYS[2]))
    if tokens == nil then
      tokens = capacity
      ts = now
    end

    if now > ts then
      local elapsed = (now - ts) / 1000.0
      tokens = math.min(capacity, tokens + elapsed * refill)
      ts = now
    end

    local allowed = 0
    if tokens >= cost then
      tokens = tokens - cost
      allowed = 1
    end

    redis.call("SET", KEYS[1], tokens, "EX", ttl)
    redis.call("SET", KEYS[2], ts, "EX", ttl)

    local remaining = math.floor(tokens)
    local reset_after_ms
    if tokens >= capacity then
      reset_after_ms = 0
    else
      reset_after_ms = math.floor(1000 * (capacity - tokens) / math.max(1e-9, refill))
    end

    return {allowed, remaining, reset_after_ms}
    """.strip()

    def __init__(self, cfg: RateLimitConfig, redis_client: Any) -> None:
        """
        :param redis_client: aioredis/redis.asyncio совместимый клиент, имеющий eval(...)
        """
        super().__init__(cfg)
        self._r = redis_client

    async def try_consume(self, key: str, cost: int = 1, now_ms: Optional[int] = None) -> Tuple[bool, int, int]:
        now_ms = now_ms or int(time.time() * 1000)
        cap = self.cfg.capacity
        refill = float(self.cfg.refill_per_sec)
        ttl = int(self.cfg.state_ttl_sec)
        k_tokens = f"{key}:tokens"
        k_ts = f"{key}:ts"

        # redis-py (>=4) async: eval(script, numkeys, *keys_and_args)
        res = await self._r.eval(
            self._LUA,
            2,
            k_tokens,
            k_ts,
            cap,
            refill,
            now_ms,
            max(0, int(cost)),
            ttl,
        )
        # res = [allowed, remaining, reset_after_ms]
        allowed = bool(res[0])
        remaining = int(res[1])
        reset_after_ms = int(res[2])
        return allowed, remaining, reset_after_ms


# ===================================
# Политика поверх лимитера
# ===================================

class RateLimitPolicy:
    """
    Высокоуровневая политика лимитирования для домена.
    Возвращает RateDecision или бросает RateLimitExceeded (по выбору вызывающего кода).
    """

    def __init__(self, limiter: AsyncRateLimiter) -> None:
        self.limiter = limiter
        self.cfg = limiter.cfg

    def _build_key(self, tenant: str, subject: str, action: str, extra: Optional[str] = None) -> str:
        lk = LimitKey(tenant=tenant or "-", subject=subject or "-", action=action or "-", extra=extra)
        return lk.as_str(self.cfg.namespace)

    async def check(
        self,
        *,
        tenant: str,
        subject: str,
        action: str,
        cost: int = 1,
        extra: Optional[str] = None,
        now_ms: Optional[int] = None,
        raise_on_exceed: bool = False,
    ) -> RateDecision:
        """
        Основная точка входа. Вычисляет решение по лимиту.

        :param cost: «стоимость» операции (например, размер запроса или количество RPC).
        :param extra: дополнительный компонент ключа (например, topic, chainId).
        :param raise_on_exceed: если True — бросает RateLimitExceeded при отказе.
        """
        key = self._build_key(tenant, subject, action, extra)
        allowed, remaining, reset_after_ms = await self.limiter.try_consume(
            key=key, cost=max(0, int(cost)), now_ms=now_ms
        )
        # retry_after: для отказа равен reset_after_ms; для успеха — 0
        retry_after_ms = 0 if allowed else max(0, reset_after_ms)
        decision = RateDecision(
            allowed=allowed,
            remaining=remaining,
            limit=self.cfg.capacity,
            reset_after_ms=max(0, reset_after_ms),
            retry_after_ms=retry_after_ms,
            key=key,
        )

        if not allowed and raise_on_exceed:
            raise RateLimitExceeded(decision)
        return decision


# ===================================
# Хелперы создания политик
# ===================================

def make_inmemory_policy(
    capacity: int = 60,
    refill_per_sec: float = 30.0,
    namespace: str = "ledger-core",
) -> RateLimitPolicy:
    cfg = RateLimitConfig(capacity=capacity, refill_per_sec=refill_per_sec, namespace=namespace)
    return RateLimitPolicy(InMemoryTokenBucket(cfg))


def make_redis_policy(
    redis_client: Any,
    capacity: int = 60,
    refill_per_sec: float = 30.0,
    namespace: str = "ledger-core",
    state_ttl_sec: int = 120,
) -> RateLimitPolicy:
    cfg = RateLimitConfig(
        capacity=capacity,
        refill_per_sec=refill_per_sec,
        namespace=namespace,
        state_ttl_sec=state_ttl_sec,
    )
    return RateLimitPolicy(RedisTokenBucket(cfg, redis_client))


# ===================================
# Пример интеграции (WS/HTTP)
# ===================================

"""
Пример (WS):
-------------
# Инициализация
policy = make_inmemory_policy(capacity=100, refill_per_sec=50.0)

# В обработчике сообщения (tenant/subject/action известны из токена/контекста)
dec = await policy.check(
    tenant=tenant_id, subject=subject_id, action="ws.publish", cost=1, extra=topic
)
if not dec.allowed:
    # отправьте клиенту код ошибки и заголовки из dec.as_headers()
    ...

Пример (HTTP, FastAPI):
-----------------------
from fastapi import FastAPI, Request, Response
from ledger_core.ledger.domain.policies.rate_limit_policy import make_redis_policy, RateLimitExceeded

app = FastAPI()
policy = make_redis_policy(redis_client=redis, capacity=60, refill_per_sec=30.0)

@app.middleware("http")
async def rl_mw(request: Request, call_next):
    tenant = request.headers.get("x-tenant-id", "-")
    subject = request.headers.get("x-subject-id", "-")
    action = f"http:{request.method}:{request.url.path}"
    try:
        dec = await policy.check(tenant=tenant, subject=subject, action=action, cost=1, raise_on_exceed=True)
    except RateLimitExceeded as e:
        headers = e.decision.as_headers()
        return Response(status_code=429, content='{"error":"rate limited"}', media_type="application/json", headers=headers)
    resp = await call_next(request)
    for k, v in dec.as_headers().items():
        resp.headers.setdefault(k, v)
    return resp
"""

# ===================================
# Простой smoke-тест (ручной запуск)
# ===================================

if __name__ == "__main__":  # pragma: no cover
    async def demo():
        policy = make_inmemory_policy(capacity=5, refill_per_sec=1)
        t, s, a = "tenant-a", "user-1", "op.test"
        for i in range(7):
            d = await policy.check(tenant=t, subject=s, action=a, cost=1)
            print(i, d.allowed, d.remaining, d.retry_after_ms)
            await asyncio.sleep(0.2)
    asyncio.run(demo())
