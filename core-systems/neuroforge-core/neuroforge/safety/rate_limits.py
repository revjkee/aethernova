# -*- coding: utf-8 -*-
"""
neuroforge.safety.rate_limits
Промышленный модуль ограничений скорости для HTTP/WebSocket/фоновых задач.

Возможности:
- Стратегии: Token Bucket (burst + refill), Fixed Window, Sliding Window (логовая).
- Бэкенды: InMemory (по умолчанию), Redis (redis.asyncio; атомарные операции).
- Мульти-правила: одно решение учитывает все правила (AND), выбирается «строжайшее».
- Иерархические ключи: шаблоны с контекстом {tenant}/{user}/{route}/{method}/{ip}.
- Временная абстракция: инъекция TimeSource для тестов и контроля сдвига часов.
- Заголовки: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, Retry-After.
- Решение: allowed, remaining, limit, reset_after_s, retry_after_s, next_allowed_at, per_rule.
- ASGI middleware: для FastAPI/Starlette без внешних зависимостей (чистый ASGI).
- Потокобезопасность: страйповые asyncio.Lock для in-memory; атомарные Lua/INCR/ZSET в Redis.
- Стоимость запроса (cost) > 1, динамическая стоимость через коллбек.
- Конкурентные лимиты (optional): семафор на ключ.

Пример (FastAPI):
    limiter = AsyncRateLimiter(
        rules=[
            TokenBucketRule(name="per_user", capacity=100, refill_rate=10, key_template="u:{user}"),
            FixedWindowRule(name="per_route", limit=1000, window=60, key_template="r:{route}"),
            SlidingWindowRule(name="global", limit=5000, window=60, key_template="g:*"),
        ],
        backend=InMemoryBackend(),  # либо RedisBackend(redis_client)
    )

    app.add_middleware(RateLimitMiddleware, limiter=limiter)

    # В обработчике можно вручную:
    decision = await limiter.check({"user": uid, "route": request.url.path, "ip": ip}, cost=1)
    if not decision.allowed: ... вернуть 429
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import math
import time
import uuid
from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Iterable, List, Mapping, MutableMapping, Optional, Protocol, Sequence, Tuple, Union, Callable

# =========================
# Время и константы
# =========================

class TimeSource(Protocol):
    def now(self) -> float: ...


class MonotonicTime:
    def now(self) -> float:
        return time.monotonic()


DEFAULT_TIME: TimeSource = MonotonicTime()

HDR_LIMIT = "X-RateLimit-Limit"
HDR_REMAIN = "X-RateLimit-Remaining"
HDR_RESET = "X-RateLimit-Reset"
HDR_RETRY_AFTER = "Retry-After"

# =========================
# Правила
# =========================

@dataclass(frozen=True)
class TokenBucketRule:
    name: str
    capacity: int
    refill_rate: float  # tokens per second
    key_template: str  # пример: "tenant:{tenant}:user:{user}:route:{route}"
    # Максимальный TTL состояния (секунды) – для Redis/GC in-memory
    state_ttl: int = 3600


@dataclass(frozen=True)
class FixedWindowRule:
    name: str
    limit: int
    window: int  # сек
    key_template: str
    jitter: int = 0  # до ±jitter/2 добавится к EXPIRE


@dataclass(frozen=True)
class SlidingWindowRule:
    name: str
    limit: int
    window: int  # сек
    key_template: str
    # Максимальная агрегированная точность: события могут группироваться по 1/collapse_hz
    collapse_hz: int = 10  # объединяем события с одинаковыми квантами времени


Rule = Union[TokenBucketRule, FixedWindowRule, SlidingWindowRule]

# =========================
# Решение и ошибки
# =========================

@dataclass
class RuleDecision:
    rule: str
    allowed: bool
    limit: int
    remaining: int
    reset_after_s: float
    retry_after_s: Optional[float] = None


@dataclass
class Decision:
    allowed: bool
    limit: int
    remaining: int
    reset_after_s: float
    retry_after_s: Optional[float]
    next_allowed_at: Optional[float]
    per_rule: List[RuleDecision] = field(default_factory=list)

    def headers(self) -> Dict[str, str]:
        h = {
            HDR_LIMIT: str(self.limit),
            HDR_REMAIN: str(max(0, self.remaining)),
            HDR_RESET: str(int(math.ceil(self.reset_after_s))),
        }
        if self.retry_after_s is not None and self.retry_after_s > 0:
            h[HDR_RETRY_AFTER] = str(int(math.ceil(self.retry_after_s)))
        return h


class BackendError(RuntimeError):
    pass


# =========================
# Бэкенды: интерфейс
# =========================

class Backend(Protocol):
    async def tb_consume(self, key: str, capacity: int, refill_rate: float, cost: int, now: float, ttl: int) -> Tuple[bool, int, float]:
        """
        Возвращает (allowed, remaining, reset_after_s)
        remaining — оценка оставшихся токенов (>=0), reset_after_s — до полного восстановления (или до появления следующего токена).
        """
        ...

    async def fw_consume(self, key: str, limit: int, window: int, cost: int, now: float, jitter: int) -> Tuple[bool, int, float]:
        """
        Fixed Window: (allowed, remaining, reset_after_s)
        """
        ...

    async def sw_consume(self, key: str, limit: int, window: int, cost: int, now: float, collapse_hz: int) -> Tuple[bool, int, float]:
        """
        Sliding Window: (allowed, remaining, reset_after_s)
        """
        ...


# =========================
# InMemory Backend
# =========================

class InMemoryBackend(Backend):
    """
    В памяти, с полосными замками для снижения конкуренции.
    """

    def __init__(self, stripes: int = 1024, time_source: TimeSource = DEFAULT_TIME) -> None:
        self._time = time_source
        self._locks = [asyncio.Lock() for _ in range(stripes)]
        self._stripes = stripes
        # TokenBucket: key -> (tokens: float, ts: float)
        self._tb: Dict[str, Tuple[float, float]] = {}
        # FixedWindow: key -> (window_start: float, count: int)
        self._fw: Dict[str, Tuple[float, int]] = {}
        # SlidingWindow: key -> deque[(bucket_ts: float, count: int)]
        self._sw: Dict[str, Deque[Tuple[float, int]]] = {}

    def _lock(self, key: str) -> asyncio.Lock:
        return self._locks[hash(key) % self._stripes]

    async def tb_consume(self, key: str, capacity: int, refill_rate: float, cost: int, now: float, ttl: int) -> Tuple[bool, int, float]:
        if cost > capacity:
            # Никогда не разрешим — вернем отказ сразу
            return (False, 0, max(0.0, (cost - capacity) / max(1e-9, refill_rate)))
        async with self._lock(key):
            tokens, ts = self._tb.get(key, (float(capacity), now))
            # Рефилл
            delta = max(0.0, now - ts)
            tokens = min(float(capacity), tokens + delta * max(0.0, refill_rate))
            allowed = tokens >= cost
            if allowed:
                tokens -= cost
                remaining = int(math.floor(tokens))
                # время до восполнения 1 токена (или полного капа)
                next_token_in = 0.0 if refill_rate <= 0 else (1.0 / refill_rate)
                # до полного восстановления
                reset_after = 0.0 if tokens >= capacity else (capacity - tokens) / max(1e-9, refill_rate)
            else:
                need = cost - tokens
                next_token_in = need / max(1e-9, refill_rate)
                reset_after = (capacity - tokens) / max(1e-9, refill_rate)
                remaining = 0
            self._tb[key] = (tokens, now)
        return (allowed, remaining, max(0.0, next_token_in if not allowed else reset_after))

    async def fw_consume(self, key: str, limit: int, window: int, cost: int, now: float, jitter: int) -> Tuple[bool, int, float]:
        w = float(window)
        async with self._lock(key):
            start, cnt = self._fw.get(key, (now, 0))
            if now - start >= w:
                start = now
                cnt = 0
            new = cnt + cost
            allowed = new <= limit
            cnt = new if allowed else cnt
            self._fw[key] = (start, cnt)
            remaining = max(0, limit - cnt)
            reset_after = max(0.0, w - (now - start))
        return (allowed, remaining, reset_after)

    async def sw_consume(self, key: str, limit: int, window: int, cost: int, now: float, collapse_hz: int) -> Tuple[bool, int, float]:
        win = float(window)
        bucket = math.floor(now * collapse_hz) / float(collapse_hz)
        async with self._lock(key):
            dq = self._sw.get(key)
            if dq is None:
                dq = deque()
                self._sw[key] = dq
            # Удаляем устаревшие
            while dq and (now - dq[0][0] >= win):
                dq.popleft()
            # Текущая сумма
            current = sum(c for _, c in dq)
            allowed = (current + cost) <= limit
            if allowed:
                if dq and dq[-1][0] == bucket:
                    ts, c = dq[-1]
                    dq[-1] = (ts, c + cost)
                else:
                    dq.append((bucket, cost))
                remaining = max(0, limit - (current + cost))
            else:
                remaining = max(0, limit - current)
            # Время до сброса — до истечения самого старого элемента
            reset_after = 0.0 if not dq else max(0.0, win - (now - dq[0][0]))
        return (allowed, remaining, reset_after)


# =========================
# Redis Backend (опционально)
# =========================

try:
    import redis.asyncio as aioredis  # type: ignore
    _HAS_REDIS = True
except Exception:
    aioredis = None  # type: ignore
    _HAS_REDIS = False


class RedisBackend(Backend):
    """
    Redis-бэкенд. Требует redis.asyncio Redis.
    Ключи:
      TB: HSET {key} fields: tokens(float), ts(float); Lua-скрипт атомарно рефиллит и снимает cost.
      FW: INCRBY {key} + EXPIRE window с джиттером.
      SW: ZSET {key}: score=timestamp, member=uuid, ZREMRANGEBYSCORE, ZCARD.
    """

    _LUA_TB = """
    -- KEYS[1]=key, ARGV: capacity, refill_rate, cost, now, ttl
    local k = KEYS[1]
    local capacity = tonumber(ARGV[1])
    local refill = tonumber(ARGV[2])
    local cost = tonumber(ARGV[3])
    local now = tonumber(ARGV[4])
    local ttl = tonumber(ARGV[5])

    if cost > capacity then
        return {0, 0, cost - capacity}  -- not allowed, remaining, need_tokens
    end

    local h = redis.call('HGETALL', k)
    local tokens = capacity
    local ts = now
    if next(h) ~= nil then
        for i=1,#h,2 do
            if h[i] == 'tokens' then tokens = tonumber(h[i+1]) end
            if h[i] == 'ts' then ts = tonumber(h[i+1]) end
        end
        if tokens == nil then tokens = capacity end
        if ts == nil then ts = now end
    end

    local delta = math.max(0.0, now - ts)
    tokens = math.min(capacity, tokens + delta * math.max(0.0, refill))
    local allowed = 0
    local need_tokens = 0.0
    if tokens >= cost then
        tokens = tokens - cost
        allowed = 1
    else
        need_tokens = cost - tokens
    end

    redis.call('HSET', k, 'tokens', tokens, 'ts', now)
    redis.call('EXPIRE', k, ttl)

    if allowed == 1 then
        -- remaining = floor(tokens); reset = time to full refill
        local remaining = math.floor(tokens)
        local reset = 0.0
        if tokens < capacity and refill > 0 then
            reset = (capacity - tokens) / refill
        end
        return {1, remaining, reset}
    else
        -- not allowed; remaining=0; retry_after = need_tokens/refill
        local retry_after = 0.0
        if refill > 0 then
            retry_after = need_tokens / refill
        end
        return {0, 0, retry_after}
    end
    """

    def __init__(self, client: "aioredis.Redis", time_source: TimeSource = DEFAULT_TIME) -> None:
        if not _HAS_REDIS:
            raise RuntimeError("redis.asyncio не установлен")
        self._r = client
        self._time = time_source
        self._tb_sha: Optional[str] = None

    async def _ensure_lua(self) -> None:
        if not self._tb_sha:
            self._tb_sha = await self._r.script_load(self._LUA_TB)

    async def tb_consume(self, key: str, capacity: int, refill_rate: float, cost: int, now: float, ttl: int) -> Tuple[bool, int, float]:
        await self._ensure_lua()
        assert self._tb_sha is not None
        try:
            res = await self._r.evalsha(self._tb_sha, 1, key, capacity, refill_rate, cost, now, ttl)
            allowed = bool(int(res[0]))
            remaining = int(res[1])
            metric = float(res[2])
            # metric: либо время до полного refill (allowed), либо retry_after (denied)
            if allowed:
                reset_after = max(0.0, metric)
                return (True, remaining, reset_after)
            else:
                retry_after = max(0.0, metric)
                return (False, 0, retry_after)
        except Exception as e:
            raise BackendError(f"Redis tb_consume failed: {e}") from e

    async def fw_consume(self, key: str, limit: int, window: int, cost: int, now: float, jitter: int) -> Tuple[bool, int, float]:
        pipe = self._r.pipeline(transaction=True)
        try:
            new = await pipe.incrby(key, cost).expire(key, window + int(jitter // 2)).execute()
            count = int(new[0])
            allowed = count <= limit
            remaining = max(0, limit - min(count, limit))
            ttl = await self._r.ttl(key)
            reset_after = float(max(0, ttl))
            return (allowed, remaining, reset_after)
        except Exception as e:
            raise BackendError(f"Redis fw_consume failed: {e}") from e

    async def sw_consume(self, key: str, limit: int, window: int, cost: int, now: float, collapse_hz: int) -> Tuple[bool, int, float]:
        try:
            zkey = key
            oldest = now - float(window)
            # удалить старые
            await self._r.zremrangebyscore(zkey, "-inf", oldest)
            # текущая сумма = количество элементов; учитываем cost как количество точек
            current = await self._r.zcard(zkey)
            allowed = (current + cost) <= limit
            if allowed:
                pipe = self._r.pipeline(transaction=False)
                for _ in range(cost):
                    member = f"{now}:{uuid.uuid4().hex}"
                    pipe.zadd(zkey, {member: now})
                pipe.expire(zkey, window)
                await pipe.execute()
                remaining = max(0, limit - (current + cost))
            else:
                remaining = max(0, limit - current)
            # reset — пока есть элементы
            ttl = await self._r.ttl(zkey)
            reset_after = float(max(0, ttl))
            return (allowed, remaining, reset_after)
        except Exception as e:
            raise BackendError(f"Redis sw_consume failed: {e}") from e


# =========================
# Вспомогательные функции
# =========================

def render_key(template: str, ctx: Mapping[str, Any]) -> str:
    """
    Безопасный форматтер ключа. Неизвестные плейсхолдеры -> '*'.
    """
    class SafeDict(dict):
        def __missing__(self, key):
            return "*"
    return template.format_map(SafeDict(**ctx))


def _choose_strictest(per_rule: List[RuleDecision]) -> Tuple[int, int, float, Optional[float]]:
    """
    Выбираем лимит/остаток/сброс для заголовков: берем правило с минимальным remaining,
    при равенстве — с максимальным reset_after.
    """
    if not per_rule:
        return (0, 0, 0.0, None)
    strict = sorted(per_rule, key=lambda r: (r.remaining, -r.reset_after_s))[0]
    retry = None
    if not strict.allowed:
        retry = strict.retry_after_s if strict.retry_after_s is not None else strict.reset_after_s
    return (strict.limit, strict.remaining, strict.reset_after_s, retry)


# =========================
# Лимитер
# =========================

class AsyncRateLimiter:
    def __init__(
        self,
        rules: Sequence[Rule],
        backend: Backend,
        time_source: TimeSource = DEFAULT_TIME,
        cost_fn: Optional[Callable[[Mapping[str, Any]], int]] = None,
        concurrent_limits: Optional[int] = None,  # если задано — семафор на ключ
    ) -> None:
        self._rules = list(rules)
        self._backend = backend
        self._time = time_source
        self._cost_fn = cost_fn
        self._concurrency = concurrent_limits
        # Семафоры по ключам (опционально)
        self._semaphores: Dict[str, asyncio.Semaphore] = {}
        self._sem_lock = asyncio.Lock()

    async def _acquire_concurrency(self, key: str) -> Optional[asyncio.Semaphore]:
        if self._concurrency is None:
            return None
        async with self._sem_lock:
            sem = self._semaphores.get(key)
            if sem is None:
                sem = asyncio.Semaphore(self._concurrency)
                self._semaphores[key] = sem
        await sem.acquire()
        return sem

    @staticmethod
    def _rule_key(rule: Rule, ctx: Mapping[str, Any]) -> str:
        return render_key(getattr(rule, "key_template"), ctx)

    async def check(self, ctx: Mapping[str, Any], cost: Optional[int] = None) -> Decision:
        now = self._time.now()
        c = cost if cost is not None else (self._cost_fn(ctx) if self._cost_fn else 1)
        per: List[RuleDecision] = []
        sem_to_release: List[asyncio.Semaphore] = []

        try:
            # Конкурентные лимиты (если нужны) — учитываем как отдельное "правило"
            if self._concurrency is not None:
                key = f"cc:{ctx.get('tenant','*')}:{ctx.get('user','*')}:{ctx.get('route','*')}"
                sem = await self._acquire_concurrency(key)
                if sem:
                    sem_to_release.append(sem)

            overall_allowed = True
            for rule in self._rules:
                key = self._rule_key(rule, ctx)
                if isinstance(rule, TokenBucketRule):
                    allowed, remaining, metric = await self._backend.tb_consume(key, rule.capacity, rule.refill_rate, c, now, rule.state_ttl)
                    # metric: если отказ — это retry_after, иначе — до полного восстановления
                    reset = metric if allowed else metric
                    retry = None if allowed else metric
                    per.append(RuleDecision(rule=rule.name, allowed=allowed, limit=rule.capacity, remaining=remaining, reset_after_s=float(max(0.0, reset)), retry_after_s=None if allowed else float(max(0.0, retry))))
                    overall_allowed = overall_allowed and allowed
                elif isinstance(rule, FixedWindowRule):
                    allowed, remaining, reset = await self._backend.fw_consume(key, rule.limit, rule.window, c, now, rule.jitter)
                    per.append(RuleDecision(rule=rule.name, allowed=allowed, limit=rule.limit, remaining=remaining, reset_after_s=float(max(0.0, reset)), retry_after_s=None if allowed else float(max(0.0, reset)))))
                    overall_allowed = overall_allowed and allowed
                elif isinstance(rule, SlidingWindowRule):
                    allowed, remaining, reset = await self._backend.sw_consume(key, rule.limit, rule.window, c, now, rule.collapse_hz)
                    per.append(RuleDecision(rule=rule.name, allowed=allowed, limit=rule.limit, remaining=remaining, reset_after_s=float(max(0.0, reset)), retry_after_s=None if allowed else float(max(0.0, reset)))))
                    overall_allowed = overall_allowed and allowed
                else:
                    raise ValueError(f"Unknown rule type: {type(rule)}")

            limit, remaining, reset_after, retry_after = _choose_strictest(per)
            next_allowed_at = None
            if not overall_allowed:
                next_allowed_at = now + (retry_after if retry_after is not None else reset_after)

            return Decision(
                allowed=overall_allowed,
                limit=limit,
                remaining=remaining,
                reset_after_s=reset_after,
                retry_after_s=retry_after if not overall_allowed else None,
                next_allowed_at=next_allowed_at,
                per_rule=per,
            )
        finally:
            # Освобождаем семафоры для конкурентных лимитов после выхода из критической секции
            # Примечание: если нужен жизненный цикл «на время обработки запроса» — используйте middleware (см. ниже).
            for s in sem_to_release:
                try:
                    s.release()
                except Exception:
                    pass


# =========================
# ASGI middleware
# =========================

class RateLimitMiddleware:
    """
    Чистый ASGI middleware.

    Аргументы:
      limiter: AsyncRateLimiter
      context_fn(scope) -> Mapping[str, Any]: как построить контекст ключей
      cost_fn(scope) -> int: динамическая стоимость запроса (опционально)
      on_reject(scope, send, decision): как вернуть 429 (кастомизация)

    Значения по умолчанию:
      - context_fn: ip, user из header X-User-Id/X-Forwarded-For, route=path, method.
      - on_reject: 429, text/plain.
    """

    def __init__(
        self,
        app,
        limiter: AsyncRateLimiter,
        context_fn: Optional[Callable[[Mapping[str, Any]], Mapping[str, Any]]] = None,
        cost_fn: Optional[Callable[[Mapping[str, Any]], int]] = None,
        on_reject: Optional[Callable[[Mapping[str, Any], Callable, Decision], Any]] = None,
    ) -> None:
        self.app = app
        self.limiter = limiter
        self.context_fn = context_fn
        self.cost_fn = cost_fn
        self.on_reject = on_reject

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http",):
            await self.app(scope, receive, send)
            return

        # Собираем контекст
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        ctx = {
            "tenant": headers.get("x-tenant-id") or "*",
            "user": headers.get("x-user-id") or "*",
            "ip": (headers.get("x-forwarded-for") or headers.get("x-real-ip") or scope.get("client", ("", ""))[0] or "*").split(",")[0].strip(),
            "route": scope.get("path") or "*",
            "method": scope.get("method") or "*",
        }
        if self.context_fn:
            try:
                ctx = dict(self.context_fn({"scope": scope, "headers": headers, "ctx": ctx}))
            except Exception:
                ctx = ctx

        # Стоимость
        cost = 1
        if self.cost_fn:
            try:
                cost = int(max(1, self.cost_fn({"scope": scope, "headers": headers, "ctx": ctx})))
            except Exception:
                cost = 1

        decision = await self.limiter.check(ctx, cost=cost)
        if not decision.allowed:
            if self.on_reject:
                return await self.on_reject({"scope": scope, "headers": headers, "ctx": ctx}, send, decision)
            # Значение по умолчанию
            async def _send_resp(status: int, headers: Dict[str, str], body: str):
                await send({
                    "type": "http.response.start",
                    "status": status,
                    "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
                })
                await send({"type": "http.response.body", "body": body.encode()})

            hdrs = decision.headers()
            hdrs.setdefault("Content-Type", "text/plain; charset=utf-8")
            msg = "Too Many Requests"
            if decision.retry_after_s is not None:
                msg += f"; retry after {int(math.ceil(decision.retry_after_s))}s"
            return await _send_resp(429, hdrs, msg)

        # Оборачиваем send, чтобы добавить заголовки в ответ сервера
        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                raw_headers = dict(decision.headers())
                message_headers = dict((k.decode().lower(), (k, v)) for (k, v) in message.get("headers", []))
                for hk, hv in raw_headers.items():
                    if hk.lower().encode() not in message_headers:
                        (message.setdefault("headers", [])).append((hk.encode(), hv.encode()))
            await send(message)

        await self.app(scope, receive, send_with_headers)


# =========================
# Удобные фабрики правил
# =========================

def per_user_token_bucket(name: str, capacity: int, refill_rate: float) -> TokenBucketRule:
    return TokenBucketRule(name=name, capacity=capacity, refill_rate=refill_rate, key_template="u:{user}")


def per_route_fixed_window(name: str, limit: int, window_s: int) -> FixedWindowRule:
    return FixedWindowRule(name=name, limit=limit, window=window_s, key_template="r:{route}")


def global_sliding_window(name: str, limit: int, window_s: int) -> SlidingWindowRule:
    return SlidingWindowRule(name=name, limit=limit, window=window_s, key_template="g:*")


# =========================
# __all__
# =========================

__all__ = [
    # Константы/время
    "TimeSource", "MonotonicTime", "DEFAULT_TIME",
    # Правила
    "TokenBucketRule", "FixedWindowRule", "SlidingWindowRule", "Rule",
    # Решения/исключения
    "RuleDecision", "Decision", "BackendError",
    # Бэкенды
    "Backend", "InMemoryBackend", "RedisBackend",
    # Лимитер и middleware
    "AsyncRateLimiter", "RateLimitMiddleware",
    # Фабрики правил
    "per_user_token_bucket", "per_route_fixed_window", "global_sliding_window",
    # Заголовки
    "HDR_LIMIT", "HDR_REMAIN", "HDR_RESET", "HDR_RETRY_AFTER",
]
