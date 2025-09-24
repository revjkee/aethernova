# -*- coding: utf-8 -*-
"""
veilmind-core.dp.accountant
Промышленный «бухгалтер» для учёта и ограничения запросов:
  - Типы лимитов: TOKEN_BUCKET, FIXED_WINDOW, CONCURRENCY
  - Идемпотентность: Idempotency-Key с TTL, возврат последнего решения
  - Бэкенды: InMemory (по умолчанию), Redis (опционально, атомарно через Lua)
  - Асинхронный API, безопасное форматирование ключей, trace_id
Совместим с Zero Trust PEP/посредниками принятия решений.

Зависимости: стандартная библиотека; опционально redis.asyncio для RedisBackend.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from string import Formatter
from typing import Any, Dict, Optional, Tuple, Union

log = logging.getLogger(__name__)


# ============================== ВСПОМОГАТЕЛЬНОЕ ==============================

class LimitType(str, Enum):
    TOKEN_BUCKET = "token_bucket"
    FIXED_WINDOW = "fixed_window"
    CONCURRENCY = "concurrency"


@dataclass(frozen=True)
class QuotaRule:
    """
    Описание лимита.
    - TOKEN_BUCKET: capacity (burst), refill_rate_per_sec (скорость пополнения), charge=amount
    - FIXED_WINDOW: limit (штучный лимит), window_seconds (длина окна)
    - CONCURRENCY: limit (максимум одновременных владений), ttl_seconds (макс. время владения)
    key_template задаёт ключ агрегирования (напр. "{tenant}:{subject}:{action}").
    """
    name: str
    type: LimitType
    key_template: str

    # Общие поля
    description: str = ""
    labels: Dict[str, str] = field(default_factory=dict)

    # TOKEN_BUCKET
    capacity: Optional[float] = None
    refill_rate_per_sec: Optional[float] = None  # tokens per second

    # FIXED_WINDOW
    limit: Optional[int] = None
    window_seconds: Optional[int] = None

    # CONCURRENCY
    ttl_seconds: Optional[int] = None

    strict: bool = True  # если True, deny при ошибках бэкенда; иначе allow+reason=backend_error_allow


@dataclass
class ChargeRequest:
    tenant: str
    subject: Optional[str] = None
    action: Optional[str] = None
    resource: Optional[str] = None
    amount: float = 1.0  # стоимость списания для token_bucket/fixed_window
    trace_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    labels: Dict[str, str] = field(default_factory=dict)


@dataclass
class AccountingDecision:
    allowed: bool
    reason: str
    remaining: Optional[float] = None
    retry_after_seconds: Optional[float] = None
    reset_at_epoch: Optional[float] = None
    # Для CONCURRENCY
    hold_token: Optional[str] = None
    # Служебное
    trace_id: Optional[str] = None
    idempotent_replay: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_jsonable(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "remaining": self.remaining,
            "retry_after_seconds": self.retry_after_seconds,
            "reset_at_epoch": self.reset_at_epoch,
            "hold_token": self.hold_token,
            "trace_id": self.trace_id,
            "idempotent_replay": self.idempotent_replay,
            "metadata": self.metadata,
        }


class TimeProvider:
    """Выделение источника времени для тестов."""
    @staticmethod
    def now() -> float:
        return time.time()

    @staticmethod
    def monotonic() -> float:
        return time.monotonic()


def _safe_format(template: str, **kwargs: Any) -> str:
    """Безопасный .format: пропуская неизвестные поля как {name}."""
    # Поддержка {name} и условий отсутствия ключей
    formatter = Formatter()
    parts = []
    for literal_text, field_name, format_spec, conversion in formatter.parse(template):
        parts.append(literal_text)
        if field_name is not None:
            value = kwargs.get(field_name, f"{{{field_name}}}")
            parts.append(format(value, format_spec) if format_spec else f"{value}")
    return "".join(parts)


# ============================== АБСТРАКТНЫЙ БЭКЕНД ============================

class CounterBackend(ABC):
    """Абстрактный бэкенд хранения/атомарных операций."""
    def __init__(self, time_provider: Optional[TimeProvider] = None) -> None:
        self.time = time_provider or TimeProvider()

    # ---------- TOKEN BUCKET ----------
    @abstractmethod
    async def token_bucket_consume(
        self,
        key: str,
        amount: float,
        capacity: float,
        refill_rate_per_sec: float,
    ) -> Tuple[bool, float, float]:
        """
        Возвращает: (allowed, remaining_tokens, retry_after_seconds).
        Если deny, retry_after_seconds >= 0.
        """
        ...

    # ---------- FIXED WINDOW ----------
    @abstractmethod
    async def fixed_window_consume(
        self,
        key: str,
        amount: int,
        window_seconds: int,
        limit: int,
    ) -> Tuple[bool, int, float]:
        """
        Возвращает: (allowed, remaining_in_window, reset_at_epoch).
        """
        ...

    # ---------- CONCURRENCY ----------
    @abstractmethod
    async def concurrency_acquire(
        self,
        key: str,
        limit: int,
        ttl_seconds: int,
    ) -> Tuple[bool, int, Optional[str]]:
        """
        Возвращает: (granted, current, hold_token).
        """
        ...

    @abstractmethod
    async def concurrency_release(self, key: str, hold_token: str) -> None:
        ...

    # ---------- IDEMPOTENCY ----------
    @abstractmethod
    async def idempotency_get(self, key: str) -> Optional[Dict[str, Any]]:
        ...

    @abstractmethod
    async def idempotency_put(self, key: str, decision: Dict[str, Any], ttl_seconds: int) -> None:
        ...

    @abstractmethod
    async def close(self) -> None:
        ...


# ============================== IN-MEMORY BACKEND =============================

class InMemoryBackend(CounterBackend):
    """Потокобезопасный асинхронный in-memory бэкенд для dev/одиночного инстанса."""
    def __init__(self, time_provider: Optional[TimeProvider] = None) -> None:
        super().__init__(time_provider)
        self._locks: Dict[str, asyncio.Lock] = {}
        self._buckets: Dict[str, Tuple[float, float]] = {}            # key -> (tokens, last_refill_ts)
        self._windows: Dict[str, Tuple[int, float]] = {}              # key -> (count, window_reset_epoch)
        self._conc: Dict[str, Dict[str, float]] = {}                  # key -> {hold_token: expire_ts}
        self._idem: Dict[str, Tuple[float, Dict[str, Any]]] = {}      # idk -> (expire_ts, decision)

        # GC таск не создаём — чистим по обращению

    def _lock(self, key: str) -> asyncio.Lock:
        lk = self._locks.get(key)
        if lk is None:
            lk = asyncio.Lock()
            self._locks[key] = lk
        return lk

    async def token_bucket_consume(
        self, key: str, amount: float, capacity: float, refill_rate_per_sec: float
    ) -> Tuple[bool, float, float]:
        now = self.time.now()
        async with self._lock(f"tb:{key}"):
            tokens, last = self._buckets.get(key, (capacity, now))
            # пополнение
            elapsed = max(0.0, now - last)
            tokens = min(capacity, tokens + elapsed * max(0.0, refill_rate_per_sec))
            allowed = tokens >= amount
            if allowed:
                tokens -= amount
                retry_after = 0.0
            else:
                deficit = amount - tokens
                retry_after = deficit / (refill_rate_per_sec if refill_rate_per_sec > 0 else 1e-9)
            self._buckets[key] = (tokens, now)
        remaining = max(0.0, tokens)
        return allowed, remaining, retry_after

    async def fixed_window_consume(
        self, key: str, amount: int, window_seconds: int, limit: int
    ) -> Tuple[bool, int, float]:
        now = self.time.now()
        window_len = max(1, window_seconds)
        window_start = math.floor(now / window_len) * window_len
        window_reset = window_start + window_len
        async with self._lock(f"fw:{key}"):
            count, reset_at = self._windows.get(key, (0, window_reset))
            # если окно сменилось — сброс
            if reset_at <= now:
                count = 0
                reset_at = window_reset
            new_count = count + amount
            if new_count <= limit:
                count = new_count
                allowed = True
            else:
                allowed = False
            self._windows[key] = (count, reset_at)
        remaining = max(0, limit - count)
        return allowed, remaining, reset_at

    async def concurrency_acquire(self, key: str, limit: int, ttl_seconds: int) -> Tuple[bool, int, Optional[str]]:
        now = self.time.now()
        ttl = max(1, ttl_seconds)
        async with self._lock(f"cc:{key}"):
            holds = self._conc.get(key)
            if holds is None:
                holds = {}
                self._conc[key] = holds
            # очистка просроченных
            expired = [h for h, exp in holds.items() if exp <= now]
            for h in expired:
                holds.pop(h, None)
            if len(holds) < limit:
                token = f"{int(now*1000)}-{len(holds)+1}"
                holds[token] = now + ttl
                current = len(holds)
                return True, current, token
            else:
                return False, len(holds), None

    async def concurrency_release(self, key: str, hold_token: str) -> None:
        async with self._lock(f"cc:{key}"):
            holds = self._conc.get(key)
            if holds:
                holds.pop(hold_token, None)

    async def idempotency_get(self, key: str) -> Optional[Dict[str, Any]]:
        now = self.time.now()
        entry = self._idem.get(key)
        if not entry:
            return None
        exp, dec = entry
        if exp <= now:
            self._idem.pop(key, None)
            return None
        return dec

    async def idempotency_put(self, key: str, decision: Dict[str, Any], ttl_seconds: int) -> None:
        exp = self.time.now() + max(1, ttl_seconds)
        self._idem[key] = (exp, decision)

    async def close(self) -> None:
        # Ничего
        return


# ============================== REDIS BACKEND (опц.) ==========================

class RedisBackend(CounterBackend):
    """
    Redis-бэкенд на redis.asyncio.* (опционален).
    Реализация критичных операций атомарно через Lua.
    """
    _HAVE_REDIS = True

    def __init__(self, redis_client: Any, time_provider: Optional[TimeProvider] = None, namespace: str = "vm") -> None:
        super().__init__(time_provider)
        # redis_client: redis.asyncio.Redis
        try:
            from redis.asyncio import Redis  # noqa: F401
        except Exception as e:  # pragma: no cover
            self._HAVE_REDIS = False
            raise RuntimeError("RedisBackend requires redis>=4.2 with asyncio support") from e
        self.r = redis_client
        self.ns = namespace.rstrip(":")
        # Lua для токен‑бакета
        self._lua_tb = None
        self._lua_cc_acquire = None
        self._lua_cc_release = None

    async def _load_scripts(self) -> None:
        if self._lua_tb is None:
            self._lua_tb = await self.r.script_load("""
-- Args: capacity, refill_rate_per_sec, amount, now_ms
-- Keys: key_tokens, key_last
local cap = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local amt = tonumber(ARGV[3])
local now = tonumber(ARGV[4])

local t = tonumber(redis.call('GET', KEYS[1]) or cap)
local last = tonumber(redis.call('GET', KEYS[2]) or now)

if now < last then
  last = now
end

local elapsed = math.max(0, now - last) / 1000.0
t = math.min(cap, t + (elapsed * rate))

local allowed = 0
local retry_after = 0.0

if t >= amt then
  t = t - amt
  allowed = 1
else
  local deficit = amt - t
  if rate > 0 then
    retry_after = deficit / rate
  else
    retry_after = 999999
  end
end

redis.call('SET', KEYS[1], t)
redis.call('SET', KEYS[2], now)
-- TTL на ключи не выставляем — состояние долгоживущее
return {allowed, t, retry_after}
""")
        if self._lua_cc_acquire is None:
            self._lua_cc_acquire = await self.r.script_load("""
-- Args: limit, ttl_sec, now_ms
-- Keys: set_holds
local limit = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

-- Удалим просроченные
local members = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', now)
if #members > 0 then
  redis.call('ZREM', KEYS[1], unpack(members))
end

local current = tonumber(redis.call('ZCARD', KEYS[1]) or 0)
if current < limit then
  local token = tostring(now) .. ":" .. tostring(current + 1)
  redis.call('ZADD', KEYS[1], now + (ttl*1000), token)
  return {1, current + 1, token}
else
  return {0, current, ''}
end
""")
        if self._lua_cc_release is None:
            self._lua_cc_release = await self.r.script_load("""
-- Args: token
-- Keys: set_holds
redis.call('ZREM', KEYS[1], ARGV[1])
return 1
""")

    def _k(self, suffix: str) -> str:
        return f"{self.ns}:{suffix}"

    async def token_bucket_consume(
        self, key: str, amount: float, capacity: float, refill_rate_per_sec: float
    ) -> Tuple[bool, float, float]:
        await self._load_scripts()
        now_ms = int(self.time.now() * 1000)
        k_tokens = self._k(f"tb:{key}:tokens")
        k_last = self._k(f"tb:{key}:last")
        res = await self.r.evalsha(self._lua_tb, 2, k_tokens, k_last, capacity, refill_rate_per_sec, amount, now_ms)
        allowed = bool(res[0])
        remaining = float(res[1])
        retry_after = float(res[2])
        return allowed, remaining, retry_after

    async def fixed_window_consume(
        self, key: str, amount: int, window_seconds: int, limit: int
    ) -> Tuple[bool, int, float]:
        now = self.time.now()
        window_len = max(1, window_seconds)
        window_start = math.floor(now / window_len) * window_len
        window_reset = window_start + window_len
        k = self._k(f"fw:{key}:{int(window_start)}")
        # INCRBY + EXPIRE
        p = self.r.pipeline()
        p.incrby(k, amount)
        p.expireat(k, int(window_reset))
        new_count, _ = await p.execute()
        new_count = int(new_count)
        allowed = new_count <= limit
        remaining = max(0, limit - min(new_count, limit))
        return allowed, remaining, window_reset

    async def concurrency_acquire(self, key: str, limit: int, ttl_seconds: int) -> Tuple[bool, int, Optional[str]]:
        await self._load_scripts()
        now_ms = int(self.time.now() * 1000)
        k = self._k(f"cc:{key}:holds")
        allowed, current, token = await self.r.evalsha(self._lua_cc_acquire, 1, k, limit, ttl_seconds, now_ms)
        return bool(allowed), int(current), (token or None)

    async def concurrency_release(self, key: str, hold_token: str) -> None:
        await self._load_scripts()
        k = self._k(f"cc:{key}:holds")
        await self.r.evalsha(self._lua_cc_release, 1, k, hold_token)

    async def idempotency_get(self, key: str) -> Optional[Dict[str, Any]]:
        raw = await self.r.get(self._k(f"idem:{key}"))
        if not raw:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return None

    async def idempotency_put(self, key: str, decision: Dict[str, Any], ttl_seconds: int) -> None:
        await self.r.set(self._k(f"idem:{key}"), json.dumps(decision), ex=max(1, ttl_seconds))

    async def close(self) -> None:
        # Клиент закрывает вызывающая сторона (обычно shared)
        return


# ============================== ОСНОВНОЙ «БУХГАЛТЕР» ==========================

@dataclass
class AccountantConfig:
    idempotency_ttl_seconds: int = 300
    # Максимальная «задержка» времени, после которой retry_after округляется вверх
    min_retry_after_floor_ms: int = 50


class Accountant:
    """Оркестратор применения правил квотирования над выбранным бэкендом."""

    def __init__(self, backend: CounterBackend, cfg: Optional[AccountantConfig] = None) -> None:
        self.backend = backend
        self.cfg = cfg or AccountantConfig()

    def _build_key(self, rule: QuotaRule, req: ChargeRequest) -> str:
        return _safe_format(
            rule.key_template,
            tenant=req.tenant,
            subject=req.subject or "anonymous",
            action=req.action or "unknown",
            resource=req.resource or "unknown",
            rule=rule.name,
        )

    async def check_and_consume(self, rule: QuotaRule, req: ChargeRequest) -> AccountingDecision:
        """
        Применяет правило и списывает «стоимость» при успехе.
        Для CONCURRENCY возвращает hold_token — нужно освободить release_concurrency().
        """
        trace_id = req.trace_id
        idem = req.idempotency_key

        # Идемпотентность: возврат последнего решения
        if idem:
            cached = await self.backend.idempotency_get(idem)
            if cached:
                dec = AccountingDecision(**cached)
                dec.idempotent_replay = True
                dec.trace_id = dec.trace_id or trace_id
                return dec

        key = self._build_key(rule, req)
        try:
            if rule.type is LimitType.TOKEN_BUCKET:
                capacity = float(rule.capacity or 0.0)
                rate = float(rule.refill_rate_per_sec or 0.0)
                amount = float(max(0.0, req.amount))
                allowed, remaining, retry_after = await self.backend.token_bucket_consume(
                    key, amount, capacity, rate
                )
                # Округлим retry_after вверх до разумного минимума
                if not allowed and retry_after is not None:
                    retry_after = max(retry_after, self.cfg.min_retry_after_floor_ms / 1000.0)
                decision = AccountingDecision(
                    allowed=allowed,
                    reason="ok" if allowed else "rate_limited",
                    remaining=remaining,
                    retry_after_seconds=retry_after if not allowed else 0.0,
                    reset_at_epoch=None,
                    trace_id=trace_id,
                    metadata={"type": rule.type.value, "key": key, "amount": amount, "capacity": capacity, "rate": rate},
                )

            elif rule.type is LimitType.FIXED_WINDOW:
                win = int(rule.window_seconds or 0)
                limit = int(rule.limit or 0)
                amount = int(max(0, int(req.amount)))
                allowed, remaining, reset_at = await self.backend.fixed_window_consume(
                    key, amount, win, limit
                )
                retry_after = max(0.0, reset_at - TimeProvider.now())
                decision = AccountingDecision(
                    allowed=allowed,
                    reason="ok" if allowed else "rate_limited",
                    remaining=float(remaining),
                    retry_after_seconds=(retry_after if not allowed else 0.0),
                    reset_at_epoch=reset_at,
                    trace_id=trace_id,
                    metadata={"type": rule.type.value, "key": key, "amount": amount, "limit": limit, "window": win},
                )

            elif rule.type is LimitType.CONCURRENCY:
                limit = int(rule.limit or 0)
                ttl = int(rule.ttl_seconds or 0)
                granted, current, token = await self.backend.concurrency_acquire(key, limit, ttl)
                decision = AccountingDecision(
                    allowed=granted,
                    reason="ok" if granted else "concurrency_exceeded",
                    remaining=float(max(0, limit - current)),
                    retry_after_seconds=None,
                    reset_at_epoch=None,
                    hold_token=token,
                    trace_id=trace_id,
                    metadata={"type": rule.type.value, "key": key, "limit": limit, "current": current, "ttl": ttl},
                )

            else:
                raise ValueError(f"Unsupported limit type: {rule.type}")

            # Запись идемпотентного решения
            if idem:
                await self.backend.idempotency_put(idem, decision.to_jsonable(), self.cfg.idempotency_ttl_seconds)

            return decision

        except Exception as e:
            log.exception("accountant backend error (rule=%s, key=%s)", rule.name, key)
            if rule.strict:
                return AccountingDecision(
                    allowed=False,
                    reason="backend_error_deny",
                    remaining=None,
                    retry_after_seconds=None,
                    reset_at_epoch=None,
                    trace_id=trace_id,
                    metadata={"error": str(e)},
                )
            else:
                return AccountingDecision(
                    allowed=True,
                    reason="backend_error_allow",
                    remaining=None,
                    retry_after_seconds=None,
                    reset_at_epoch=None,
                    trace_id=trace_id,
                    metadata={"error": str(e)},
                )

    async def release_concurrency(self, rule: QuotaRule, req: ChargeRequest, hold_token: str) -> None:
        if rule.type is not LimitType.CONCURRENCY:
            return
        key = self._build_key(rule, req)
        try:
            await self.backend.concurrency_release(key, hold_token)
        except Exception:
            log.exception("failed to release concurrency (rule=%s, key=%s)", rule.name, key)

    async def close(self) -> None:
        await self.backend.close()


# ============================== ПРИМЕР КОНФИГУРАЦИИ ===========================

DEFAULT_TOKEN_BUCKET = QuotaRule(
    name="pep-global",
    type=LimitType.TOKEN_BUCKET,
    key_template="{tenant}:pep:{action}",
    capacity=100.0,              # максимум токенов (burst)
    refill_rate_per_sec=50.0,    # скорость пополнения
    description="Глобальный лимит PEP по действию",
)

DEFAULT_FIXED_WINDOW = QuotaRule(
    name="login-per-user",
    type=LimitType.FIXED_WINDOW,
    key_template="{tenant}:login:{subject}",
    limit=10,
    window_seconds=60,
    description="До 10 логинов в минуту на пользователя",
)

DEFAULT_CONCURRENCY = QuotaRule(
    name="export-job",
    type=LimitType.CONCURRENCY,
    key_template="{tenant}:job:export",
    limit=5,
    ttl_seconds=600,
    description="Не более 5 одновременных экспортов",
)


# ============================== ПРИМЕР ИСПОЛЬЗОВАНИЯ ==========================

# Пример:
# backend = InMemoryBackend()
# acct = Accountant(backend)
# req = ChargeRequest(tenant="acme", subject="alice", action="write", amount=3.0, idempotency_key="X123")
# dec = await acct.check_and_consume(DEFAULT_TOKEN_BUCKET, req)
# if dec.allowed: ... else: sleep(dec.retry_after_seconds)
#
# Для Redis:
#   import redis.asyncio as redis
#   r = redis.from_url("redis://localhost:6379/0")
#   backend = RedisBackend(r, namespace="vm")
#   acct = Accountant(backend)
