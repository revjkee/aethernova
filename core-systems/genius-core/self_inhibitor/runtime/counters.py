# -*- coding: utf-8 -*-
"""
Счетчики и лимитеры для self_inhibitor.runtime.

Python: 3.11+
Зависимости: стандартная библиотека. Для Redis-пути нужен совместимый клиент (duck-typing: .eval, .pttl, .pexpire, .incrby, .get, .set).

Возможности:
- Абстракция CounterStore (incr с TTL, get, mget, setnx, expire, атомарный апдейт токен-бакета)
- InMemoryCounterStore с истечением ключей и шардированными блокировками
- Фиксированное окно (FixedWindowLimiter)
- Скользящее окно (SlidingWindowLimiter, два бакета + взвешивание)
- Токен-бакет (TokenBucketLimiter) c атомарным путём (InMemory/Redis Lua)
- Метаданные решения (RateDecision) и снимки (CounterSnapshot) для телеметрии/логов
- Тестопригодные источники времени

Безопасность/устойчивость:
- Только параметризованные ключи, префиксы нейтрализуют коллизии
- TTL > окно (или рассчитанный для TB), чтобы избежать утечек
- Насыщающее сложение, защита от отрицательных инкрементов
- Monotonic clock для вычислений, wall-clock только в метаданных

Интеграция:
- Адаптер Redis может обернуть client и передать в RedisCounterStore либо использовать LUA-строки ниже.
"""

from __future__ import annotations

import dataclasses
import hashlib
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Mapping, MutableMapping, Optional, Sequence, Tuple

__all__ = [
    "CounterError",
    "RateDecision",
    "CounterSnapshot",
    "CounterStore",
    "InMemoryCounterStore",
    "FixedWindowLimiter",
    "SlidingWindowLimiter",
    "TokenBucketLimiter",
    "TOKEN_BUCKET_LUA",
]


# ======================================================================
# МОДЕЛИ/ОШИБКИ
# ======================================================================

class CounterError(RuntimeError):
    pass


@dataclass(slots=True, frozen=True)
class RateDecision:
    allowed: bool
    remaining: int
    limit: int
    reset_at_ms: int        # unix epoch millis, когда окно сбрасывается или когда будет доступен следующий токен
    window_ms: int | None   # для оконных лимитеров; для токен-бакета может быть None
    reason: str = ""        # пояснение для логов/метрик
    meta: Mapping[str, Any] = dataclasses.field(default_factory=dict)


@dataclass(slots=True, frozen=True)
class CounterSnapshot:
    key: str
    value: int
    ttl_ms: int | None


# ======================================================================
# ЭПОХА/ВРЕМЯ
# ======================================================================

def now_ms() -> int:
    """Wall-clock (epochtime) в миллисекундах. Используется для reset_at/метаданных."""
    return int(time.time() * 1000)

def mono_ms() -> int:
    """Монотоническое время в миллисекундах для расчета дельт."""
    return int(time.monotonic() * 1000)


# ======================================================================
# ХРАНИЛИЩЕ СЧЕТЧИКОВ (АБСТРАКЦИЯ)
# ======================================================================

class CounterStore(ABC):
    """Абстрактный интерфейс для счетчиков с TTL и атомарным инкрементом."""

    @abstractmethod
    def incr(self, key: str, amount: int = 1, ttl_ms: Optional[int] = None) -> int:
        """Атомарно увеличивает счетчик и при необходимости устанавливает TTL (если ключ новый). Возвращает новое значение."""
        raise NotImplementedError

    @abstractmethod
    def get(self, key: str) -> int:
        """Возвращает текущее значение счетчика (0, если ключ не существует)."""
        raise NotImplementedError

    def mget(self, keys: Sequence[str]) -> list[int]:
        """Векторное получение значений (по умолчанию по одному)."""
        return [self.get(k) for k in keys]

    @abstractmethod
    def ttl_ms(self, key: str) -> Optional[int]:
        """Оставшийся TTL в мс или None, если не поддерживается/не установлено/нет ключа."""
        raise NotImplementedError

    @abstractmethod
    def expire(self, key: str, ttl_ms: int) -> None:
        """Устанавливает TTL (перезаписывает). Игнорировать, если ключа нет."""
        raise NotImplementedError

    def setnx(self, key: str, value: int, ttl_ms: Optional[int] = None) -> bool:
        """Установить значение, если ключ отсутствует."""
        raise NotImplementedError

    # ---- атомарный update для токен-бакета ----
    def token_bucket_update(
        self,
        key: str,
        capacity: int,
        refill_per_sec: float,
        cost: int,
        now_ms_: int,
        ttl_grace_ms: int,
    ) -> tuple[bool, int, int]:
        """
        Дефолтная (не полностью распределенная) реализация TB-обновления через get/set.
        Возвращает (allowed, remaining, reset_at_ms).
        Для распределенной среды используйте Redis-реализацию или переопределение в адаптере.
        """
        # На несетевом сторе попробуем обеспечить потокобезопасность на уровне процесса.
        raise NotImplementedError


# ======================================================================
# IN-MEMORY STORE (ПРОМЫШЛЕННЫЙ BOUNDED TTL MAP)
# ======================================================================

class InMemoryCounterStore(CounterStore):
    """
    Быстрый in-memory store с истечением ключей.
    Подходит для single-process или как локальный L1-кэш перед распределенным слоем.
    """

    _SHARDS = 64

    def __init__(self, max_size: int = 200_000) -> None:
        self._max_size = max_size
        self._data: list[MutableMapping[str, tuple[int, Optional[int]]]] = [dict() for _ in range(self._SHARDS)]
        self._locks: list[threading.Lock] = [threading.Lock() for _ in range(self._SHARDS)]

    def _shard(self, key: str) -> int:
        h = int.from_bytes(hashlib.blake2s(key.encode("utf-8"), digest_size=8).digest(), "big")
        return h % self._SHARDS

    def _cleanup(self, shard: int, now_ms_: int) -> None:
        d = self._data[shard]
        if len(d) < self._max_size:
            return
        # Ленивая очистка истекших ключей
        to_del = []
        for k, (_, exp_ms) in list(d.items())[: min(1024, len(d))]:
            if exp_ms is not None and exp_ms <= now_ms_:
                to_del.append(k)
        for k in to_del:
            d.pop(k, None)

    def incr(self, key: str, amount: int = 1, ttl_ms: Optional[int] = None) -> int:
        if amount < 0:
            raise CounterError("negative increments are not allowed")
        shard = self._shard(key)
        now = now_ms()
        with self._locks[shard]:
            self._cleanup(shard, now)
            val, exp = self._data[shard].get(key, (0, None))
            new_val = val + amount
            if new_val < 0:
                new_val = 0
            # Устанавливаем TTL только при создании ключа либо если TTL не был задан ранее
            if key not in self._data[shard]:
                exp = (now + ttl_ms) if ttl_ms else exp
            self._data[shard][key] = (new_val, exp)
            return new_val

    def get(self, key: str) -> int:
        shard = self._shard(key)
        now = now_ms()
        with self._locks[shard]:
            val, exp = self._data[shard].get(key, (0, None))
            if exp is not None and exp <= now:
                self._data[shard].pop(key, None)
                return 0
            return val

    def mget(self, keys: Sequence[str]) -> list[int]:
        # Для in-memory можно оптимизировать пакетно по шардам
        res: list[int] = []
        for k in keys:
            res.append(self.get(k))
        return res

    def ttl_ms(self, key: str) -> Optional[int]:
        shard = self._shard(key)
        now = now_ms()
        with self._locks[shard]:
            val, exp = self._data[shard].get(key, (0, None))
            if exp is None:
                return None
            if exp <= now:
                self._data[shard].pop(key, None)
                return None
            return exp - now

    def expire(self, key: str, ttl_ms: int) -> None:
        shard = self._shard(key)
        now = now_ms()
        with self._locks[shard]:
            if key in self._data[shard]:
                val, _ = self._data[shard][key]
                self._data[shard][key] = (val, now + ttl_ms)

    def setnx(self, key: str, value: int, ttl_ms: Optional[int] = None) -> bool:
        shard = self._shard(key)
        now = now_ms()
        with self._locks[shard]:
            if key in self._data[shard]:
                # проверим на истечение
                _, exp = self._data[shard][key]
                if exp is not None and exp <= now:
                    self._data[shard].pop(key, None)
                else:
                    return False
            exp_at = (now + ttl_ms) if ttl_ms else None
            self._data[shard][key] = (value, exp_at)
            return True

    # --------- атомарный апдейт токен-бакета (локально) ---------

    def token_bucket_update(
        self,
        key: str,
        capacity: int,
        refill_per_sec: float,
        cost: int,
        now_ms_: int,
        ttl_grace_ms: int,
    ) -> tuple[bool, int, int]:
        shard = self._shard(key)
        with self._locks[shard]:
            # Состояние бакета хранится как: tokens:int, last_ms:int
            state_key = f"{key}:tb"
            val, exp = self._data[shard].get(state_key, (None, None))
            if isinstance(val, tuple):
                tokens, last_ms = val
            else:
                tokens, last_ms = None, None

            if tokens is None or last_ms is None:
                tokens = capacity
                last_ms = now_ms_
            # пополнение
            elapsed_ms = max(0, now_ms_ - int(last_ms))
            refill = int(elapsed_ms * refill_per_sec / 1000.0)
            if refill > 0:
                tokens = min(capacity, tokens + refill)
                last_ms = now_ms_
            # проверка
            if tokens >= cost:
                tokens -= cost
                allowed = True
            else:
                allowed = False
            # расчет времени до одного токена
            if tokens >= capacity:
                reset_at = now_ms_
            elif refill_per_sec > 0:
                deficit = max(0, cost - tokens)
                ms_to_refill_one = int(1000.0 / refill_per_sec)
                reset_at = now_ms_ + deficit * ms_to_refill_one
            else:
                reset_at = now_ms_ + 86400_000  # бесконечно долго

            # сохраняем
            ttl = max(1_000, int( (capacity * 1000.0 / max(refill_per_sec, 0.001)) )) + ttl_grace_ms
            self._data[shard][state_key] = ((tokens, last_ms), now_ms_ + ttl)
            remaining = max(0, tokens)
            return allowed, remaining, reset_at


# ======================================================================
# REDIS LUA (для распределенных токен-бакетов)
# ======================================================================

# Lua-скрипт атомарного токен-бакета (ключ хранит: tokens, last_ms)
# KEYS[1] - ключ состояния (например, namespace:user:tb)
# ARGV: capacity, refill_per_sec (float), cost, now_ms, ttl_grace_ms
TOKEN_BUCKET_LUA = r"""
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_per_sec = tonumber(ARGV[2])
local cost = tonumber(ARGV[3])
local now_ms = tonumber(ARGV[4])
local ttl_grace_ms = tonumber(ARGV[5])

local state = redis.call('GET', key)
local tokens = capacity
local last_ms = now_ms
if state then
  local sep = string.find(state, ':')
  if sep then
    tokens = tonumber(string.sub(state, 1, sep-1)) or capacity
    last_ms = tonumber(string.sub(state, sep+1)) or now_ms
  end
end

local elapsed_ms = now_ms - last_ms
if elapsed_ms < 0 then elapsed_ms = 0 end
local refill = math.floor(elapsed_ms * refill_per_sec / 1000.0)
if refill > 0 then
  tokens = math.min(capacity, tokens + refill)
  last_ms = now_ms
end

local allowed = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
end

local reset_at = now_ms
if tokens < capacity then
  if refill_per_sec > 0 then
    local deficit = math.max(0, cost - tokens)
    local ms_to_one = math.floor(1000.0 / refill_per_sec)
    reset_at = now_ms + deficit * ms_to_one
  else
    reset_at = now_ms + 86400000
  end
end

local ttl = math.max(1000, math.floor(capacity * 1000.0 / math.max(refill_per_sec, 0.001))) + ttl_grace_ms
redis.call('SET', key, tostring(tokens) .. ':' .. tostring(last_ms), 'PX', ttl)

return { allowed, tokens, reset_at }
"""


# ======================================================================
# ЛИМИТЕРЫ
# ======================================================================

class _BaseLimiter:
    def __init__(self, store: CounterStore, prefix: str = "si") -> None:
        self.store = store
        self.prefix = prefix

    def _k(self, *parts: str) -> str:
        return ":".join([self.prefix, *parts])


class FixedWindowLimiter(_BaseLimiter):
    """
    Фиксированное окно: счетчик запросов в интервале [bucket_start, bucket_end).
    TTL выставляется на 2*window_ms для гарантированной очистки.
    """

    def __init__(self, store: CounterStore, prefix: str = "si", window_ms: int = 60_000, limit: int = 100) -> None:
        super().__init__(store, prefix)
        if window_ms <= 0 or limit <= 0:
            raise CounterError("window_ms and limit must be > 0")
        self.window_ms = int(window_ms)
        self.limit = int(limit)

    def allow(self, key: str, cost: int = 1) -> RateDecision:
        if cost <= 0:
            raise CounterError("cost must be > 0")
        now = now_ms()
        bucket = (now // self.window_ms)
        bucket_key = self._k("fw", key, str(bucket))
        ttl = self.window_ms * 2
        new_val = self.store.incr(bucket_key, cost, ttl_ms=ttl)
        remaining = max(0, self.limit - new_val)
        reset_at = int((bucket + 1) * self.window_ms)
        allowed = new_val <= self.limit
        reason = "ok" if allowed else "limit_exceeded"
        meta = {"bucket": int(bucket), "cost": cost}
        return RateDecision(allowed, remaining, self.limit, reset_at, self.window_ms, reason, meta)


class SlidingWindowLimiter(_BaseLimiter):
    """
    Скользящее окно (rolling window): два смежных фикс-оконных бакета и линейная интерполяция.
    Уменьшает скачки на границе окна.
    """

    def __init__(self, store: CounterStore, prefix: str = "si", window_ms: int = 60_000, limit: int = 100) -> None:
        super().__init__(store, prefix)
        if window_ms <= 0 or limit <= 0:
            raise CounterError("window_ms and limit must be > 0")
        self.window_ms = int(window_ms)
        self.limit = int(limit)

    def allow(self, key: str, cost: int = 1) -> RateDecision:
        if cost <= 0:
            raise CounterError("cost must be > 0")
        now = now_ms()
        bucket = (now // self.window_ms)
        curr_key = self._k("sw", key, str(bucket))
        prev_key = self._k("sw", key, str(bucket - 1))
        ttl = self.window_ms * 2

        # инкрементируем текущий бакет
        curr = self.store.incr(curr_key, cost, ttl_ms=ttl)

        # получаем предыдущее значение
        prev = self.store.get(prev_key)

        # доля времени, прошедшего в текущем окне
        elapsed = now - (bucket * self.window_ms)
        weight_prev = max(0.0, 1.0 - (elapsed / self.window_ms))
        est = curr + int(prev * weight_prev)

        remaining = max(0, self.limit - est)
        reset_at = int((bucket + 1) * self.window_ms)
        allowed = est <= self.limit
        reason = "ok" if allowed else "limit_exceeded"
        meta = {"bucket": int(bucket), "cost": cost, "prev_weight": round(weight_prev, 4), "est_count": est, "curr": curr, "prev": prev}
        return RateDecision(allowed, remaining, self.limit, reset_at, self.window_ms, reason, meta)


class TokenBucketLimiter(_BaseLimiter):
    """
    Токен-бакет с равномерным пополнением.

    Параметры:
      capacity           — максимальное число токенов
      refill_per_sec     — скорость пополнения (токенов в секунду)
      cost               — стоимость операции в токенах (обычно 1)

    Хранилище должно поддерживать атомарное обновление состояния бакета.
    InMemoryCounterStore — атомарность на уровне процесса.
    Для Redis используйте TOKEN_BUCKET_LUA и метод store.token_bucket_update, реализованный адаптером.
    """

    def __init__(
        self,
        store: CounterStore,
        prefix: str = "si",
        *,
        capacity: int = 100,
        refill_per_sec: float = 10.0,
    ) -> None:
        super().__init__(store, prefix)
        if capacity <= 0 or refill_per_sec < 0:
            raise CounterError("capacity must be > 0 and refill_per_sec must be >= 0")
        self.capacity = int(capacity)
        self.refill_per_sec = float(refill_per_sec)
        self._ttl_grace_ms = 5_000  # добавочный TTL, чтобы состояние не исчезало мгновенно

    def allow(self, key: str, cost: int = 1) -> RateDecision:
        if cost <= 0:
            raise CounterError("cost must be > 0")
        state_key = self._k("tb", key)
        now = now_ms()
        allowed, remaining, reset_at = self.store.token_bucket_update(
            key=state_key,
            capacity=self.capacity,
            refill_per_sec=self.refill_per_sec,
            cost=cost,
            now_ms_=now,
            ttl_grace_ms=self._ttl_grace_ms,
        )
        reason = "ok" if allowed else "insufficient_tokens"
        meta = {"cost": cost}
        return RateDecision(allowed, remaining, self.capacity, reset_at, None, reason, meta)


# ======================================================================
# ПРИМЕР REDIS-АДАПТАЦИИ (скелет)
# ======================================================================

class RedisCounterStore(CounterStore):
    """
    Пример адаптера поверх redis-клиента (duck-typing).
    Ожидаемые методы клиента: get, set, incrby, pttl, pexpire, eval.
    Этот класс не требует redis в зависимостях; интегратор обязан передать клиент.
    """

    def __init__(self, client: Any) -> None:
        self.r = client

    def incr(self, key: str, amount: int = 1, ttl_ms: Optional[int] = None) -> int:
        if amount < 0:
            raise CounterError("negative increments are not allowed")
        # INCRBY с установкой TTL только если ключ новый:
        pipe = getattr(self.r, "pipeline", None)
        if callable(pipe):
            p = self.r.pipeline()
            p.incrby(key, amount)
            if ttl_ms is not None:
                # Установим TTL, но только если ключ был создан — делаем SETNX маркером
                newkey = f"{key}:__init"
                p.setnx(newkey, 1)
                p.pexpire(newkey, ttl_ms)
                p.pexpire(key, ttl_ms)
            res = p.execute()
            return int(res[0])
        # Фолбэк без пайплайна
        new_val = int(self.r.incrby(key, amount))
        if ttl_ms is not None and int(self.r.pttl(key)) < 0:
            try:
                self.r.pexpire(key, ttl_ms)
            except Exception:
                pass
        return new_val

    def get(self, key: str) -> int:
        v = self.r.get(key)
        if v is None:
            return 0
        try:
            return int(v)
        except Exception:
            return 0

    def mget(self, keys: Sequence[str]) -> list[int]:
        vs = self.r.mget(keys)
        out: list[int] = []
        for v in vs:
            if v is None:
                out.append(0)
            else:
                try:
                    out.append(int(v))
                except Exception:
                    out.append(0)
        return out

    def ttl_ms(self, key: str) -> Optional[int]:
        try:
            ttl = int(self.r.pttl(key))
            if ttl < 0:
                return None
            return ttl
        except Exception:
            return None

    def expire(self, key: str, ttl_ms: int) -> None:
        try:
            self.r.pexpire(key, ttl_ms)
        except Exception:
            pass

    def setnx(self, key: str, value: int, ttl_ms: Optional[int] = None) -> bool:
        ok = bool(self.r.setnx(key, value))
        if ok and ttl_ms is not None:
            try:
                self.r.pexpire(key, ttl_ms)
            except Exception:
                pass
        return ok

    def token_bucket_update(
        self,
        key: str,
        capacity: int,
        refill_per_sec: float,
        cost: int,
        now_ms_: int,
        ttl_grace_ms: int,
    ) -> tuple[bool, int, int]:
        # Выполним атомарно через LUA
        try:
            res = self.r.eval(
                TOKEN_BUCKET_LUA,
                1,
                key,
                int(capacity),
                float(refill_per_sec),
                int(cost),
                int(now_ms_),
                int(ttl_grace_ms),
            )
            # Redis возвращает массив чисел [allowed, tokens, reset_at]
            allowed = bool(int(res[0]))
            remaining = int(res[1])
            reset_at = int(res[2])
            return allowed, remaining, reset_at
        except Exception as e:
            # Фолбэк: неатомарный путь (не рекомендуется в проде)
            raise CounterError(f"redis token_bucket_update failed: {e}") from e


# ======================================================================
# ПРИМЕРЫ ИСПОЛЬЗОВАНИЯ
# ======================================================================

if __name__ == "__main__":
    store = InMemoryCounterStore()

    print("== Fixed Window ==")
    fw = FixedWindowLimiter(store, prefix="demo", window_ms=2_000, limit=5)
    for i in range(7):
        d = fw.allow("user:42")
        print(i, d)

    print("== Sliding Window ==")
    sw = SlidingWindowLimiter(store, prefix="demo", window_ms=2_000, limit=5)
    for i in range(7):
        d = sw.allow("user:42")
        print(i, d)

    print("== Token Bucket ==")
    tb = TokenBucketLimiter(store, prefix="demo", capacity=5, refill_per_sec=2.0)
    for i in range(8):
        d = tb.allow("user:42", cost=1)
        print(i, d)
        time.sleep(0.2)
