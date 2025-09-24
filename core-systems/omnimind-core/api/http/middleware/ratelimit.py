# ops/api/http/middleware/ratelimit.py
"""
ASGI Rate Limiting Middleware (production-grade)

Основные возможности:
- Несколько правил на запрос (например, 100 r/m per-user + 1000 r/h per-ip).
- Два алгоритма:
  1) RedisTokenBucket: распределенный токен-бакет с Lua (атомарно, быстрый).
  2) InMemorySlidingWindow: резервный (для single-process, тест/дев).
- Ключ лимита: из пользователя, IP, заголовка, cookie или произвольной функции.
- Интеграция за reverse proxy (X-Forwarded-For, Forwarded).
- CIDR allowlist/denylist (в обход лимита или жесткая блокировка).
- Совместимые заголовки: RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset,
  Retry-After (для 429), X-RateLimit-* (настраивается).
- Soft mode: только метрики и заголовки, без блокировки.
- Опциональные метрики Prometheus, если установлен prometheus_client.

Пример использования (FastAPI/Starlette):
    from fastapi import FastAPI
    from ops.api.http.middleware.ratelimit import (
        RateLimitMiddleware, RateLimitRule, RedisTokenBucket, KeyBuilders
    )

    app = FastAPI()

    rules = [
        RateLimitRule(name="user_100rpm", capacity=100, refill_rate_per_sec=100/60, window_hint_sec=60, key="user"),
        RateLimitRule(name="ip_1000rph", capacity=1000, refill_rate_per_sec=1000/3600, window_hint_sec=3600, key="ip"),
    ]

    backend = RedisTokenBucket(url="redis://localhost:6379/0")  # или без параметров -> auto из REDIS_URL
    app.add_middleware(
        RateLimitMiddleware,
        backend=backend,
        rules=rules,
        key_builder=KeyBuilders.composite(user_header="X-User-Id"),
        trust_proxy=True,
        allow_cidrs=["10.0.0.0/8", "192.168.0.0/16"],
        deny_cidrs=[],
        soft=False,
        add_legacy_headers=True
    )

Зависимости:
- Redis backend: redis>=4.2 (модуль redis.asyncio). Если недоступен — будет предупреждение и fallback на InMemory.
- Prometheus: prometheus_client (опционально).

Замечание:
- InMemory бэкенд适 only для одного процесса/воркера. Для нескольких воркеров/инстансов используйте RedisTokenBucket.

Автор: OmniMind Core
Лицензия: Apache-2.0
"""
from __future__ import annotations

import asyncio
import json
import os
import time
import ipaddress
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union

try:
    # Опциональные зависимости
    from prometheus_client import Counter, Histogram
    _PROM = True
except Exception:  # pragma: no cover
    _PROM = False

try:
    import redis.asyncio as aioredis  # type: ignore
    _HAS_REDIS = True
except Exception:  # pragma: no cover
    _HAS_REDIS = False


# ----------------------------- Правило лимита ----------------------------- #

@dataclass(frozen=True)
class RateLimitRule:
    """
    Описание одного правила лимита.

    capacity: емкость токен-бакета (сколько запросов можно "всплеском").
    refill_rate_per_sec: скорость пополнения токенов в секунду.
    window_hint_sec: окно для заголовков RateLimit-Reset (подсказка клиенту).
    name: имя правила (для метрик и диагностики).
    key: логическое имя ключа ("user", "ip", "custom:<name>" и т.п.).
    cost: стоимость запроса в токенах (обычно 1).
    """
    name: str
    capacity: int
    refill_rate_per_sec: float
    window_hint_sec: int
    key: str
    cost: float = 1.0


# ----------------------------- Результат проверки ----------------------------- #

@dataclass
class RateLimitCheck:
    allowed: bool
    remaining: int
    reset_seconds: int
    rule: RateLimitRule
    retry_after: float  # секунды до появления следующего токена (минимальное)
    # Внутренние поля для формирования заголовков:
    limit: int
    now_epoch: int


# ----------------------------- Помощники ключей ----------------------------- #

class KeyBuilders:
    @staticmethod
    def ip(scope: Dict[str, Any], headers: Dict[bytes, bytes], trust_proxy: bool = False) -> str:
        return _extract_ip(scope, headers, trust_proxy=trust_proxy)

    @staticmethod
    def user_header(header: str = "X-User-Id", fallback_ip: bool = True, trust_proxy: bool = False) -> Callable:
        header_bytes = header.lower().encode()

        def _builder(scope: Dict[str, Any], headers: Dict[bytes, bytes]) -> str:
            val = headers.get(header_bytes)
            if val:
                return f"user:{val.decode().strip()}"
            if fallback_ip:
                return f"ip:{_extract_ip(scope, headers, trust_proxy=trust_proxy)}"
            return "anon"
        return _builder

    @staticmethod
    def composite(user_header: str = "X-User-Id", trust_proxy: bool = False) -> Callable:
        """
        Соединяет user и ip в один ключ: user:<id> или ip:<addr>, что пришло первым.
        """
        uh = KeyBuilders.user_header(user_header, fallback_ip=True, trust_proxy=trust_proxy)

        def _builder(scope: Dict[str, Any], headers: Dict[bytes, bytes]) -> str:
            return uh(scope, headers)
        return _builder


def _extract_ip(scope: Dict[str, Any], headers: Dict[bytes, bytes], trust_proxy: bool) -> str:
    # Попытаться получить реальный IP за прокси
    if trust_proxy:
        fwd = headers.get(b"x-forwarded-for")
        if fwd:
            # Берём первый IP из списка
            first = fwd.decode().split(",")[0].strip()
            return first
        fwd2 = headers.get(b"forwarded")
        if fwd2:
            # Формат: for=1.2.3.4;proto=https;by=...
            parts = [p.strip() for p in fwd2.decode().split(";")]
            for p in parts:
                if p.lower().startswith("for="):
                    return p.split("=", 1)[1].strip().strip('"')
    client = scope.get("client")
    if client and isinstance(client, (list, tuple)) and client:
        return str(client[0])
    return "0.0.0.0"


# ----------------------------- Бэкенды лимита ----------------------------- #

class BaseLimiter:
    async def check_and_consume(self, key: str, rule: RateLimitRule) -> RateLimitCheck:
        raise NotImplementedError


class InMemorySlidingWindow(BaseLimiter):
    """
    Скользящее окно в памяти процесса.
    Предназначен для разработки/тестов или single-worker. Не распределенный.

    Алгоритм: поддерживаем на ключ список "ведер" секундной детализации длиной window_hint_sec,
    считаем сумму и решаем, можно ли пропускать запрос. Стоимость запроса cost.
    """
    def __init__(self) -> None:
        self._buckets: Dict[Tuple[str, str], List[int]] = {}
        self._locks: Dict[Tuple[str, str], asyncio.Lock] = {}

    async def check_and_consume(self, key: str, rule: RateLimitRule) -> RateLimitCheck:
        now = int(time.time())
        k = (key, rule.name)
        if k not in self._locks:
            self._locks[k] = asyncio.Lock()

        async with self._locks[k]:
            window = self._buckets.get(k)
            if window is None or len(window) != rule.window_hint_sec:
                window = [0] * rule.window_hint_sec
                self._buckets[k] = window
            idx = now % rule.window_hint_sec
            # Вытесняем старое ведро
            window[idx] = 0
            # Сумма запросов за окно
            total = sum(window)
            allowed = total + int(rule.cost) <= rule.capacity
            if allowed:
                window[idx] += int(rule.cost)
            remaining = max(0, rule.capacity - sum(window))
            reset = rule.window_hint_sec - (now % rule.window_hint_sec)
            retry_after = 0.0 if allowed else float(reset)
            return RateLimitCheck(
                allowed=allowed,
                remaining=remaining,
                reset_seconds=reset,
                rule=rule,
                retry_after=retry_after,
                limit=rule.capacity,
                now_epoch=now,
            )


class RedisTokenBucket(BaseLimiter):
    """
    Токен-бакет на Redis с Lua-скриптом (атомарно и быстро).
    - capacity: максимальное количество токенов (размер бакета)
    - refill_rate_per_sec: сколько токенов добавляется в секунду
    - cost: стоимость запроса (обычно 1)

    Ключ в Redis: rl:{rule.name}:{key}
    Хранение: Hash { tokens: float, ts: int(ms) } + PEXPIRE на период опустошения.
    """
    LUA = """
    -- KEYS[1] = key
    -- ARGV[1] = capacity
    -- ARGV[2] = refill_rate_per_sec
    -- ARGV[3] = now_ms
    -- ARGV[4] = cost
    -- Возвращает: allowed (0/1), tokens_after (float), retry_after_sec (float)
    local k       = KEYS[1]
    local cap     = tonumber(ARGV[1])
    local rate    = tonumber(ARGV[2])
    local now_ms  = tonumber(ARGV[3])
    local cost    = tonumber(ARGV[4])

    local tokens = 0.0
    local ts = now_ms

    local h = redis.call('HGETALL', k)
    if h and #h > 0 then
        for i=1,#h,2 do
            local field = h[i]
            local val = h[i+1]
            if field == 'tokens' then tokens = tonumber(val) end
            if field == 'ts' then ts = tonumber(val) end
        end
    else
        tokens = cap
        ts = now_ms
    end

    local elapsed = math.max(0, now_ms - ts) / 1000.0
    tokens = math.min(cap, tokens + elapsed * rate)

    local allowed = 0
    local retry_after = 0.0

    if tokens >= cost then
        tokens = tokens - cost
        allowed = 1
    else
        allowed = 0
        -- Сколько секунд до появления хотя бы одного токена
        retry_after = (cost - tokens) / rate
    end

    redis.call('HSET', k, 'tokens', tokens, 'ts', now_ms)
    -- TTL: время полного восстановления бакета (cap/rate)
    local ttl_ms = math.ceil((cap / rate) * 1000)
    redis.call('PEXPIRE', k, ttl_ms)

    return { allowed, tostring(tokens), tostring(retry_after) }
    """

    def __init__(self, url: Optional[str] = None, client: Any = None, namespace: str = "rl") -> None:
        if client:
            self._r = client
        else:
            if not _HAS_REDIS:
                raise RuntimeError("redis.asyncio is not available. Install redis>=4.2")
            url = url or os.getenv("REDIS_URL") or os.getenv("OMNIMIND_REDIS_URL") or "redis://localhost:6379/0"
            self._r = aioredis.from_url(url, encoding=None, decode_responses=False)
        self._ns = namespace
        self._sha = None  # будет загружен при первом вызове
        self._lock = asyncio.Lock()

    async def _ensure_script(self):
        if self._sha is not None:
            return
        async with self._lock:
            if self._sha is None:
                self._sha = await self._r.script_load(self.LUA)

    def _key(self, rule: RateLimitRule, key: str) -> str:
        return f"{self._ns}:{rule.name}:{key}"

    async def check_and_consume(self, key: str, rule: RateLimitRule) -> RateLimitCheck:
        await self._ensure_script()
        now_ms = int(time.time() * 1000)
        capacity = max(1, int(rule.capacity))
        rate = float(rule.refill_rate_per_sec)
        cost = float(rule.cost)
        try:
            res = await self._r.evalsha(
                self._sha,
                1,
                self._key(rule, key),
                str(capacity),
                str(rate),
                str(now_ms),
                str(cost),
            )
            # res: [allowed(int), tokens(str), retry_after(str)]
            allowed = bool(int(res[0]))
            tokens_after = float(res[1].decode() if isinstance(res[1], (bytes, bytearray)) else res[1])
            retry_after = float(res[2].decode() if isinstance(res[2], (bytes, bytearray)) else res[2])
        except aioredis.ResponseError:
            # Скрипт ещё не загружен на этот инстанс (реплика/шард). Повторно загрузим.
            self._sha = None
            return await self.check_and_consume(key, rule)

        remaining = max(0, int(tokens_after))
        # Подсказка сброса — ближайшие window_hint_sec или время до полного восстановления, что меньше
        reset = max(1, int(min(rule.window_hint_sec, (rule.capacity / max(rule.refill_rate_per_sec, 1e-6)))))
        return RateLimitCheck(
            allowed=allowed,
            remaining=remaining,
            reset_seconds=reset,
            rule=rule,
            retry_after=retry_after,
            limit=rule.capacity,
            now_epoch=int(now_ms / 1000),
        )


# ----------------------------- Middleware ----------------------------- #

class RateLimitMiddleware:
    """
    ASGI middleware для rate limiting.

    Параметры:
      backend: BaseLimiter — RedisTokenBucket (рекомендуется) или InMemorySlidingWindow.
      rules: список RateLimitRule (проверяются все; отказ любого — 429).
      key_builder: функция (scope, headers) -> str. По умолчанию composite(user/ip).
      trust_proxy: доверять X-Forwarded-For / Forwarded.
      allow_cidrs: список CIDR, которые обходят лимит (allowlist).
      deny_cidrs: список CIDR, которые блокируются до лимита (denylist).
      soft: если True — не блокируем, только выставляем заголовки и метрики.
      add_legacy_headers: добавить X-RateLimit-* помимо новых RateLimit-*.

    Заголовки ответа при успехе:
      RateLimit-Limit: "<capacity>;w=<window_hint_sec>;policy=\"<rule-name>\""
      RateLimit-Remaining: "<min(remaining among rules)>"
      RateLimit-Reset: "<seconds>"
    При отказе:
      429 Too Many Requests + Retry-After: "<seconds>"
    """
    def __init__(
        self,
        app: Callable,
        backend: Optional[BaseLimiter] = None,
        rules: Optional[Sequence[RateLimitRule]] = None,
        key_builder: Optional[Callable] = None,
        trust_proxy: bool = False,
        allow_cidrs: Optional[Sequence[str]] = None,
        deny_cidrs: Optional[Sequence[str]] = None,
        soft: bool = False,
        add_legacy_headers: bool = True,
    ) -> None:
        self.app = app
        self.backend = backend or self._default_backend()
        self.rules = list(rules or self._default_rules())
        self.key_builder = key_builder or KeyBuilders.composite(trust_proxy=trust_proxy)
        self.trust_proxy = trust_proxy
        self.allow_cidrs = [_cidr(o) for o in (allow_cidrs or [])]
        self.deny_cidrs = [_cidr(o) for o in (deny_cidrs or [])]
        self.soft = bool(os.getenv("OMNIMIND_RL_SOFT", str(soft)).lower() in ("1", "true", "yes"))
        self.add_legacy = add_legacy_headers

        if _PROM:
            self._m_allowed = Counter(
                "omnimind_ratelimit_allowed_total",
                "Allowed requests by rule",
                ["rule"])
            self._m_blocked = Counter(
                "omnimind_ratelimit_blocked_total",
                "Blocked requests by rule",
                ["rule"])
            self._m_latency = Histogram(
                "omnimind_ratelimit_check_seconds",
                "Latency of rate limit checks",
                ["rule"])
        else:
            self._m_allowed = self._m_blocked = self._m_latency = None

    def _default_backend(self) -> BaseLimiter:
        # Попробуем Redis, иначе InMemory
        if _HAS_REDIS:
            try:
                return RedisTokenBucket()
            except Exception:
                pass
        return InMemorySlidingWindow()

    def _default_rules(self) -> List[RateLimitRule]:
        # Базовый дефолт: 120 r/m per IP
        return [
            RateLimitRule(
                name="ip_120rpm",
                capacity=120,
                refill_rate_per_sec=120 / 60.0,
                window_hint_sec=60,
                key="ip",
                cost=1.0,
            )
        ]

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        # Быстрые deny/allow по IP
        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        ip = _extract_ip(scope, headers, trust_proxy=self.trust_proxy)
        if self._ip_in(self.deny_cidrs, ip):
            await self._send_429(send, retry_after=60, body=b"Forbidden by policy\n")
            return
        bypass = self._ip_in(self.allow_cidrs, ip)

        # Ключ для правил
        key_base = self.key_builder(scope, headers)
        checks: List[RateLimitCheck] = []
        blocked: Optional[RateLimitCheck] = None

        for rule in self.rules:
            # Уточняем ключ по названию правила, чтобы иметь независимые бакеты
            if rule.key == "ip":
                k = f"ip:{ip}"
            elif rule.key == "user":
                # Перестроим через user_header, если builder не вернул user
                if key_base.startswith("user:"):
                    k = key_base
                else:
                    k = f"ip:{ip}"
            else:
                # custom
                k = f"{rule.key}:{key_base}"

            t0 = time.perf_counter()
            ch = await self.backend.check_and_consume(k, rule)
            t1 = time.perf_counter()
            if self._m_latency:
                self._m_latency.labels(rule=rule.name).observe(max(0.0, t1 - t0))
            checks.append(ch)
            if not ch.allowed and not bypass and not self.soft:
                blocked = ch
                if self._m_blocked:
                    self._m_blocked.labels(rule=rule.name).inc()
                break
            else:
                if self._m_allowed:
                    self._m_allowed.labels(rule=rule.name).inc()

        # Формируем заголовки
        headers_out = self._build_headers(checks)

        if blocked and not bypass and not self.soft:
            # 429
            await self._send_429(send, retry_after=max(1, int(round(blocked.retry_after))), headers=headers_out)
            return

        # Оборачиваем send, чтобы добавить заголовки в ответ
        async def send_wrapped(event):
            if event["type"] == "http.response.start":
                event_headers = event.setdefault("headers", [])
                for k, v in headers_out:
                    event_headers.append((k, v))
            await send(event)

        return await self.app(scope, receive, send_wrapped)

    def _build_headers(self, checks: Sequence[RateLimitCheck]) -> List[Tuple[bytes, bytes]]:
        if not checks:
            return []
        # Берем минимальный remaining и минимальный reset, суммарный limit не суммируем, показываем первое правило.
        min_remaining = min(c.remaining for c in checks)
        min_reset = max(1, min(c.reset_seconds for c in checks))
        # Берем "наиболее строгую" политику для RateLimit-Limit — первую по списку
        rule0 = checks[0].rule
        ratelimit_limit = f"{rule0.capacity};w={rule0.window_hint_sec};policy=\"{rule0.name}\""
        out = [
            (b"ratelimit-limit", str(ratelimit_limit).encode()),
            (b"ratelimit-remaining", str(min_remaining).encode()),
            (b"ratelimit-reset", str(min_reset).encode()),
        ]
        if self.add_legacy:
            out.extend([
                (b"x-ratelimit-limit", str(rule0.capacity).encode()),
                (b"x-ratelimit-remaining", str(min_remaining).encode()),
                (b"x-ratelimit-reset", str(min_reset).encode()),
            ])
        return out

    async def _send_429(self, send, retry_after: int, headers: Optional[List[Tuple[bytes, bytes]]] = None, body: bytes = b"Too Many Requests\n"):
        hdrs = headers or []
        hdrs = hdrs + [(b"retry-after", str(retry_after).encode())]
        await send({
            "type": "http.response.start",
            "status": 429,
            "headers": hdrs,
        })
        await send({
            "type": "http.response.body",
            "body": body,
            "more_body": False,
        })

    def _ip_in(self, cidrs: Sequence[ipaddress._BaseNetwork], ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for n in cidrs:
            if ip_obj in n:
                return True
        return False


def _cidr(s: str) -> ipaddress._BaseNetwork:
    return ipaddress.ip_network(s, strict=False)


# ----------------------------- Утилита: загрузка правил из env ----------------------------- #

def rules_from_env(env_var: str = "OMNIMIND_RL_RULES") -> List[RateLimitRule]:
    """
    Поддержка декларативной конфигурации правил в ENV как JSON.
    Пример:
      export OMNIMIND_RL_RULES='[
        {"name":"user_100rpm","capacity":100,"refill_rate_per_sec":1.6667,"window_hint_sec":60,"key":"user"},
        {"name":"ip_1000rph","capacity":1000,"refill_rate_per_sec":0.2778,"window_hint_sec":3600,"key":"ip"}
      ]'
    """
    raw = os.getenv(env_var)
    if not raw:
        return []
    data = json.loads(raw)
    out: List[RateLimitRule] = []
    for d in data:
        out.append(RateLimitRule(
            name=d["name"],
            capacity=int(d["capacity"]),
            refill_rate_per_sec=float(d["refill_rate_per_sec"]),
            window_hint_sec=int(d["window_hint_sec"]),
            key=d.get("key", "ip"),
            cost=float(d.get("cost", 1.0)),
        ))
    return out


# ----------------------------- Простой фабричный конструктор ----------------------------- #

def build_middleware(app, redis_url: Optional[str] = None, trust_proxy: bool = True) -> RateLimitMiddleware:
    """
    Быстрый конструктор для типового кейса:
    - user: 100 r/m
    - ip:   1000 r/h
    """
    rules = rules_from_env() or [
        RateLimitRule("user_100rpm", 100, 100/60, 60, "user"),
        RateLimitRule("ip_1000rph", 1000, 1000/3600, 3600, "ip"),
    ]
    backend: BaseLimiter
    if _HAS_REDIS:
        backend = RedisTokenBucket(url=redis_url)
    else:
        backend = InMemorySlidingWindow()
    return RateLimitMiddleware(
        app=app,
        backend=backend,
        rules=rules,
        key_builder=KeyBuilders.composite(trust_proxy=trust_proxy),
        trust_proxy=trust_proxy,
    )
