# physical-integration-core/physical_integration/safety/rate_limits.py
"""
Production-grade rate limiting primitives for Physical Integration Core.

Возможности:
- Token Bucket (RPS) и Bandwidth (bytes/sec), без фоновых задач (lazy refill, monotonic time)
- Sliding Window (точный счетчик окон)
- Пер-ключ конкуренция (весовой семафор) с ограничением одновременных работ
- Композитные лимитеры (AND/OR) и Registry для именованных политик
- Метрики Prometheus (опционально), структурные ошибки
- Контекст-менеджеры и декораторы для синхронного и асинхронного кода
- Интерфейсы хранения состояния: in-memory реализация и возможность заменить на Redis

Python >= 3.10
Опциональные зависимости:
  prometheus_client>=0.19
"""

from __future__ import annotations

import asyncio
import math
import os
import random
import time
from collections import deque, defaultdict
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Deque, Dict, Iterable, Optional, Tuple, Protocol

# =========================
# Метрики (опционально)
# =========================
try:
    from prometheus_client import Counter, Histogram, Gauge

    RL_DECISIONS = Counter("rl_decisions_total", "Rate limit decisions", ["name", "key", "decision"])
    RL_WAIT = Histogram("rl_wait_seconds", "Wait time in acquire()", ["name"])
    RL_TOKENS = Gauge("rl_tokens", "Current tokens in bucket", ["name", "key"])
    RL_CONCURRENCY = Gauge("rl_concurrency", "Current concurrency by key", ["name", "key"])
except Exception:  # pragma: no cover
    class _N:
        def labels(self, *_, **__): return self
        def inc(self, *_): pass
        def set(self, *_): pass
        def observe(self, *_): pass
    RL_DECISIONS = RL_WAIT = RL_TOKENS = RL_CONCURRENCY = _N()

# =========================
# Исключения
# =========================
class RateLimitError(Exception):
    pass

class RateLimitExceeded(RateLimitError):
    """Запрос отклонен политикой лимитирования (без ожидания)."""

class ConcurrencyExceeded(RateLimitError):
    """Достигнут предел конкурентности (без ожидания)."""

# =========================
# Интерфейсы хранения
# =========================
class BucketStore(Protocol):
    async def get(self, name: str, key: str) -> Tuple[float, float]:
        """
        Получить состояние (tokens, last_refill) для ведра.
        Возвращает (tokens, last_refill_monotonic_seconds).
        """
        ...

    async def set(self, name: str, key: str, tokens: float, last_refill: float) -> None:
        """Сохранить состояние для ведра."""
        ...

class InMemoryBucketStore(BucketStore):
    def __init__(self) -> None:
        self._state: Dict[Tuple[str, str], Tuple[float, float]] = {}
        self._lock = asyncio.Lock()

    async def get(self, name: str, key: str) -> Tuple[float, float]:
        async with self._lock:
            return self._state.get((name, key), (math.inf, time.monotonic()))

    async def set(self, name: str, key: str, tokens: float, last_refill: float) -> None:
        async with self._lock:
            self._state[(name, key)] = (tokens, last_refill)

# =========================
# Базовый интерфейс лимитера
# =========================
class AsyncLimiter(Protocol):
    name: str
    async def allow(self, key: str, permits: float = 1.0) -> bool: ...
    async def acquire(self, key: str, permits: float = 1.0, timeout: Optional[float] = None) -> None: ...
    @asynccontextmanager
    async def guard(self, key: str, permits: float = 1.0, timeout: Optional[float] = None):
        """Контекст ожидания/удержания лимита (для совместимости различных лимитеров)."""
        ...

# =========================
# Token Bucket (RPS)
# =========================
@dataclass
class TokenBucketLimiter:
    """
    Классический токен-бакет с ленивым пополнением.

    rate: пополнение в токенах за window_sec (обычно 1 сек).
    burst: максимальная емкость ведра (спайки).
    window_sec: период пополнения, по умолчанию 1.0.
    """
    name: str
    rate: float
    burst: float
    window_sec: float = 1.0
    store: BucketStore = field(default_factory=InMemoryBucketStore)

    def __post_init__(self) -> None:
        self._locks: Dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def _refill(self, key: str) -> Tuple[float, float]:
        tokens, last = await self.store.get(self.name, key)
        now = time.monotonic()
        if tokens is math.inf:
            tokens, last = self.burst, now
        elapsed = max(0.0, now - last)
        if elapsed > 0:
            add = (self.rate / self.window_sec) * elapsed
            tokens = min(self.burst, tokens + add)
            last = now
            await self.store.set(self.name, key, tokens, last)
        RL_TOKENS.labels(self.name, key).set(tokens if tokens != math.inf else self.burst)
        return tokens, last

    async def allow(self, key: str, permits: float = 1.0) -> bool:
        lock = self._locks[key]
        async with lock:
            tokens, _ = await self._refill(key)
            if tokens >= permits:
                await self.store.set(self.name, key, tokens - permits, time.monotonic())
                RL_TOKENS.labels(self.name, key).set(max(0.0, tokens - permits))
                RL_DECISIONS.labels(self.name, key, "allow").inc()
                return True
            RL_DECISIONS.labels(self.name, key, "deny").inc()
            return False

    async def acquire(self, key: str, permits: float = 1.0, timeout: Optional[float] = None) -> None:
        start = time.monotonic()
        lock = self._locks[key]
        while True:
            async with lock:
                tokens, _ = await self._refill(key)
                if tokens >= permits:
                    await self.store.set(self.name, key, tokens - permits, time.monotonic())
                    RL_TOKENS.labels(self.name, key).set(max(0.0, tokens - permits))
                    RL_DECISIONS.labels(self.name, key, "acquire").inc()
                    RL_WAIT.labels(self.name).observe(max(0.0, time.monotonic() - start))
                    return
            if timeout is not None and (time.monotonic() - start) >= timeout:
                RL_DECISIONS.labels(self.name, key, "timeout").inc()
                raise RateLimitExceeded(f"timeout acquiring tokens: name={self.name} key={key}")
            # Экономный сон: время до следующего токена
            sleep_for = max(0.005, permits / (self.rate / self.window_sec)) * 0.25
            await asyncio.sleep(sleep_for)

    @asynccontextmanager
    async def guard(self, key: str, permits: float = 1.0, timeout: Optional[float] = None):
        await self.acquire(key, permits, timeout)
        try:
            yield
        finally:
            # Token-bucket не «возвращает» токены после использования
            pass

# =========================
# BandwidthLimiter (bytes/sec)
# =========================
@dataclass
class BandwidthLimiter(TokenBucketLimiter):
    """
    Лимитер пропускной способности. permits = байты.
    rate — байт/сек, burst — максимальный «запас» байт.
    """
    # Наследует логику TokenBucketLimiter; семантика permits — bytes.

# =========================
# Sliding Window Limiter
# =========================
@dataclass
class SlidingWindowLimiter:
    """
    Точный счетчик в скользящем окне.
    capacity: максимум событий за window_sec.
    """
    name: str
    capacity: int
    window_sec: float = 1.0

    def __post_init__(self) -> None:
        self._events: Dict[str, Deque[float]] = defaultdict(deque)
        self._locks: Dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def allow(self, key: str, permits: float = 1.0) -> bool:
        if permits != 1.0:
            raise ValueError("SlidingWindowLimiter supports permits=1 only")
        lock = self._locks[key]
        now = time.monotonic()
        async with lock:
            dq = self._events[key]
            # очистка
            while dq and (now - dq[0]) >= self.window_sec:
                dq.popleft()
            if len(dq) < self.capacity:
                dq.append(now)
                RL_DECISIONS.labels(self.name, key, "allow").inc()
                return True
            RL_DECISIONS.labels(self.name, key, "deny").inc()
            return False

    async def acquire(self, key: str, permits: float = 1.0, timeout: Optional[float] = None) -> None:
        start = time.monotonic()
        while True:
            if await self.allow(key, permits):
                RL_WAIT.labels(self.name).observe(max(0.0, time.monotonic() - start))
                return
            if timeout is not None and (time.monotonic() - start) >= timeout:
                raise RateLimitExceeded(f"timeout sliding-window: name={self.name} key={key}")
            await asyncio.sleep(0.005)

    @asynccontextmanager
    async def guard(self, key: str, permits: float = 1.0, timeout: Optional[float] = None):
        await self.acquire(key, permits, timeout)
        try:
            yield
        finally:
            pass

# =========================
# Ограничение конкурентности (весовой семафор)
# =========================
@dataclass
class WeightedConcurrencyLimiter:
    """
    Пер-ключ ограничитель параллелизма.
    capacity — общее число «весов» на key. permits — вес операции.
    """
    name: str
    capacity: int

    def __post_init__(self) -> None:
        self._locks: Dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._used: Dict[str, int] = defaultdict(int)

    async def allow(self, key: str, permits: float = 1.0) -> bool:
        if int(permits) != permits:
            raise ValueError("Concurrency permits must be integer")
        p = int(permits)
        lock = self._locks[key]
        async with lock:
            used = self._used[key]
            if used + p <= self.capacity:
                self._used[key] = used + p
                RL_CONCURRENCY.labels(self.name, key).set(self._used[key])
                RL_DECISIONS.labels(self.name, key, "allow").inc()
                return True
            RL_DECISIONS.labels(self.name, key, "deny").inc()
            return False

    async def acquire(self, key: str, permits: float = 1.0, timeout: Optional[float] = None) -> None:
        start = time.monotonic()
        while True:
            if await self.allow(key, permits):
                RL_WAIT.labels(self.name).observe(max(0.0, time.monotonic() - start))
                return
            if timeout is not None and (time.monotonic() - start) >= timeout:
                raise ConcurrencyExceeded(f"timeout concurrency: name={self.name} key={key}")
            await asyncio.sleep(0.005)

    async def release(self, key: str, permits: float = 1.0) -> None:
        if int(permits) != permits:
            raise ValueError("Concurrency permits must be integer")
        p = int(permits)
        lock = self._locks[key]
        async with lock:
            self._used[key] = max(0, self._used[key] - p)
            RL_CONCURRENCY.labels(self.name, key).set(self._used[key])

    @asynccontextmanager
    async def guard(self, key: str, permits: float = 1.0, timeout: Optional[float] = None):
        await self.acquire(key, permits, timeout)
        try:
            yield
        finally:
            await self.release(key, permits)

# =========================
# Композитные политики (AND/OR)
# =========================
@dataclass
class CompositeLimiter:
    """
    Комбинирует несколько лимитеров: mode='AND' (все) или 'OR' (любой).
    """
    name: str
    limiters: Iterable[AsyncLimiter]
    mode: str = "AND"

    async def allow(self, key: str, permits: float = 1.0) -> bool:
        checks = []
        for lim in self.limiters:
            ok = await lim.allow(key, permits)
            checks.append(ok)
        if self.mode == "AND":
            return all(checks)
        return any(checks)

    async def acquire(self, key: str, permits: float = 1.0, timeout: Optional[float] = None) -> None:
        start = time.monotonic()
        if self.mode == "AND":
            # По очереди удерживаем; при неудаче откатываем ранее удержанные guard'ы
            guards = []
            try:
                for lim in self.limiters:
                    rem = None if timeout is None else max(0.0, timeout - (time.monotonic() - start))
                    g = lim.guard(key, permits, rem)
                    await g.__aenter__()
                    guards.append(g)
                RL_WAIT.labels(self.name).observe(max(0.0, time.monotonic() - start))
            except Exception:
                # откат
                for g in reversed(guards):
                    with contextmanager(lambda: (yield))():
                        try:
                            await g.__aexit__(None, None, None)
                        except Exception:
                            pass
                raise
        else:
            # OR: пытаемся по очереди до успеха
            last_error: Optional[Exception] = None
            for lim in self.limiters:
                try:
                    rem = None if timeout is None else max(0.0, timeout - (time.monotonic() - start))
                    await lim.acquire(key, permits, rem)
                    RL_WAIT.labels(self.name).observe(max(0.0, time.monotonic() - start))
                    return
                except Exception as e:
                    last_error = e
                    continue
            raise last_error or RateLimitExceeded("no limiter allowed (OR mode)")

    @asynccontextmanager
    async def guard(self, key: str, permits: float = 1.0, timeout: Optional[float] = None):
        if self.mode == "AND":
            guards = []
            try:
                start = time.monotonic()
                for lim in self.limiters:
                    rem = None if timeout is None else max(0.0, timeout - (time.monotonic() - start))
                    g = lim.guard(key, permits, rem)
                    await g.__aenter__()
                    guards.append(g)
                yield
            finally:
                for g in reversed(guards):
                    with contextmanager(lambda: (yield))():
                        try:
                            await g.__aexit__(None, None, None)
                        except Exception:
                            pass
        else:
            # Удерживаем только первый успешно взятый
            entered = None
            start = time.monotonic()
            for lim in self.limiters:
                try:
                    rem = None if timeout is None else max(0.0, timeout - (time.monotonic() - start))
                    g = lim.guard(key, permits, rem)
                    await g.__aenter__()
                    entered = g
                    break
                except Exception:
                    continue
            if not entered:
                raise RateLimitExceeded("no limiter allowed (OR mode)")
            try:
                yield
            finally:
                with contextmanager(lambda: (yield))():
                    try:
                        await entered.__aexit__(None, None, None)
                    except Exception:
                        pass

# =========================
# Реестр политик
# =========================
class RateLimitRegistry:
    def __init__(self) -> None:
        self._map: Dict[str, AsyncLimiter] = {}

    def register(self, name: str, limiter: AsyncLimiter) -> None:
        self._map[name] = limiter

    def get(self, name: str) -> AsyncLimiter:
        if name not in self._map:
            raise KeyError(f"limiter '{name}' not found")
        return self._map[name]

REGISTRY = RateLimitRegistry()

# =========================
# Утилиты: backoff с джиттером
# =========================
def backoff_delay(base: float, factor: float, attempt: int, max_delay: float, jitter: str = "full") -> float:
    if attempt <= 1:
        d = base
    else:
        d = min(max_delay, base * (factor ** (attempt - 1)))
    if jitter == "full":
        return random.uniform(0, d)
    if jitter == "equal":
        return d * 0.5 + random.uniform(0, d * 0.5)
    return d

# =========================
# Декораторы
# =========================
def rate_limited(
    name: str,
    key: Callable[..., str] | str,
    permits: float = 1.0,
    timeout: Optional[float] = None,
) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    """
    Асинхронный декоратор для функций/эндпойнтов.

    Пример:
        @rate_limited("api_rps", key=lambda req: req.client.host)
        async def handler(req): ...
    """
    def _decorator(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
        async def _wrapped(*args: Any, **kwargs: Any) -> Any:
            lim = REGISTRY.get(name)
            k = key(*args, **kwargs) if callable(key) else str(key)
            async with lim.guard(k, permits=permits, timeout=timeout):
                return await fn(*args, **kwargs)
        return _wrapped
    return _decorator

# =========================
# Примеры конфигурации (можно удалить/перенастроить в бою)
# =========================
def default_setup() -> None:
    """
    Референсная инициализация реестра:
      - api_rps: 500 rps, burst 1000 по IP
      - api_bw: 5 MiB/s, burst 10 MiB по токенам байтов
      - api_conc: конкурентность 200 на ключ
      - api_combo: AND(api_rps, api_conc)
    """
    REGISTRY.register("api_rps", TokenBucketLimiter(name="api_rps", rate=500.0, burst=1000.0))
    REGISTRY.register("api_bw", BandwidthLimiter(name="api_bw", rate=5 * 1024 * 1024, burst=10 * 1024 * 1024))
    REGISTRY.register("api_conc", WeightedConcurrencyLimiter(name="api_conc", capacity=200))
    REGISTRY.register("api_combo",
        CompositeLimiter(name="api_combo", limiters=[REGISTRY.get("api_rps"), REGISTRY.get("api_conc")], mode="AND"))

# =========================
# Синхронные обертки (при необходимости)
# =========================
@contextmanager
def sync_guard(limiter: TokenBucketLimiter, key: str, permits: float = 1.0, timeout: Optional[float] = None):
    """
    Для редких синхронных сценариев (например, внутри потокового кода).
    Блокирующие ожидания через asyncio.run() использовать нельзя в активном loop.
    Рекомендуется только в скриптах/утилитах.
    """
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(limiter.acquire(key, permits, timeout))
        yield
    finally:
        loop.close()

# =========================
# Пример локального прогона
# =========================
if __name__ == "__main__":
    async def main():
        default_setup()
        rps = REGISTRY.get("api_rps")
        conc = REGISTRY.get("api_conc")
        key = "127.0.0.1"

        # Демонстрация параллельного запуска с ограничениями
        async def worker(i: int):
            try:
                async with rps.guard(key, permits=1.0, timeout=0.5):
                    async with conc.guard("pool", permits=1, timeout=1.0):
                        await asyncio.sleep(0.02)
                        return i
            except RateLimitError as e:
                return f"denied:{i}"

        results = await asyncio.gather(*[worker(i) for i in range(50)])
        print("done", results.count("denied:"))

    asyncio.run(main())
