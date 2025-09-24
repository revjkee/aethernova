# -*- coding: utf-8 -*-
"""
Production-grade ASGI rate limiting middleware (token bucket with Redis Lua).
Unverified: внешние параметры окружения/интеграции я не могу подтвердить. I cannot verify this.

Совместимо с: Starlette/FastAPI/любым ASGI.
Алгоритм: Token Bucket (ёмкость, скорость долива, стоимостные вызовы).

Фичи:
- Атомарная реализация в Redis (Lua), in-memory фоллбек (на один процесс).
- Гибкие правила по пути/методу/заголовкам; поддержка cost (стоимость запроса).
- Корректные заголовки: RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset, Retry-After.
- Извлечение client_id c учётом доверенных прокси (X-Forwarded-For).
- Fail-open: при сбое Redis, по умолчанию пропускаем трафик (конфигурируемо).
- Метрики: абстрактный интерфейс emitter.increment(...) / emitter.observe(...).

Пример использования (FastAPI):
    from fastapi import FastAPI
    from neuroforge_core.api.http.middleware.ratelimit import RateLimitMiddleware, RateLimitRule, RateLimitConfig
    app = FastAPI()
    app.add_middleware(
        RateLimitMiddleware,
        config=RateLimitConfig(
            redis_url="redis://localhost:6379/0",
            default_rule=RateLimitRule(capacity=100, refill_per_sec=50.0),  # среднее 50 rps, всплеск до 100
            rules=[
                RateLimitRule(path_pattern=r"^/api/v1/admin", methods={"POST","PUT","DELETE"},
                              capacity=20, refill_per_sec=5.0, cost=2),
                RateLimitRule(path_pattern=r"^/api/v1/heavy", capacity=30, refill_per_sec=3.0, cost=5),
            ],
            trusted_proxies={"10.0.0.0/8", "192.168.0.0/16"},
            fail_open=True,
        )
    )

Автор: Aethernova / Neuroforge
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Iterable, Mapping, Optional, Sequence

from starlette.types import ASGIApp, Receive, Scope, Send

try:
    # Redis 4.x: asyncio-клиент
    from redis.asyncio import Redis as _Redis
    from redis.asyncio.client import Redis as RedisClient  # type: ignore
    from redis.asyncio import from_url as redis_from_url
except Exception:  # pragma: no cover
    _Redis = None
    RedisClient = None
    redis_from_url = None  # type: ignore

logger = logging.getLogger(__name__)

# ---------- Конфигурация правил ----------


@dataclass(slots=True)
class RateLimitRule:
    """
    Описание одного правила токен-бакета.

    capacity: максимальный объём бакета (целые токены)
    refill_per_sec: скорость долива в токенах/сек
    cost: стоимость запроса в токенах
    path_pattern: regex для матчинга пути
    methods: ограничение по HTTP методам (если None — любые)
    header_match: необязательный матч по заголовкам (regex по значению)
    key_extra: произвольная добавка к ключу (например, 'tenant:{id}')
    """
    capacity: int
    refill_per_sec: float
    cost: int = 1
    path_pattern: Optional[str] = None
    methods: Optional[Iterable[str]] = None
    header_match: Optional[tuple[str, str]] = None
    key_extra: Optional[str] = None

    def compiled(self) -> "CompiledRateLimitRule":
        return CompiledRateLimitRule(
            capacity=self.capacity,
            refill_per_sec=self.refill_per_sec,
            cost=self.cost,
            path_re=re.compile(self.path_pattern) if self.path_pattern else None,
            methods=set(m.upper() for m in self.methods) if self.methods else None,
            header_match=(
                (self.header_match[0].lower(), re.compile(self.header_match[1]))
                if self.header_match else None
            ),
            key_extra=self.key_extra or "",
        )


@dataclass(slots=True)
class CompiledRateLimitRule:
    capacity: int
    refill_per_sec: float
    cost: int
    path_re: Optional[re.Pattern]
    methods: Optional[set[str]]
    header_match: Optional[tuple[str, re.Pattern]]
    key_extra: str

    def matches(self, scope: Scope) -> bool:
        if self.methods and scope.get("method", "").upper() not in self.methods:
            return False
        path = scope.get("path", "") or scope.get("raw_path", b"").decode("utf-8", "ignore")
        if self.path_re and not self.path_re.search(path):
            return False
        if self.header_match:
            name, rx = self.header_match
            for k, v in (scope.get("headers") or []):
                if k.decode().lower() == name:
                    try:
                        if rx.search(v.decode()):
                            return True
                        return False
                    except Exception:
                        return False
            return False
        return True


# ---------- Интерфейсы хранилища ----------


class RateLimitStorage:
    async def acquire(
        self, key: str, capacity: int, refill_per_sec: float, cost: int
    ) -> tuple[bool, int, float]:
        """
        Пытается списать cost токенов.

        Возврат: (allowed, remaining, reset_after_sec)
          remaining — оставшееся целое число токенов после операции (>=0)
          reset_after_sec — через сколько секунд будет доступен следующий токен
        """
        raise NotImplementedError

    async def close(self) -> None:
        pass


class InMemoryTokenBucket(RateLimitStorage):
    """
    Нить/процесс-локальная реализация. Подходит только как фоллбек/тест.
    """
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._state: dict[str, tuple[float, float]] = {}
        # key -> (tokens, last_ts)

    async def acquire(self, key: str, capacity: int, refill_per_sec: float, cost: int) -> tuple[bool, int, float]:
        now = time.monotonic()
        async with self._lock:
            tokens, last = self._state.get(key, (float(capacity), now))
            elapsed = max(0.0, now - last)
            if refill_per_sec > 0:
                tokens = min(float(capacity), tokens + elapsed * refill_per_sec)
            # else refill_per_sec == 0 => одноразовый бакет без долива
            allowed = tokens >= cost
            if allowed:
                tokens -= cost
                remaining = int(tokens)
                reset_after = 0.0 if tokens >= 1.0 else (1.0 - tokens) / refill_per_sec if refill_per_sec > 0 else float("inf")
            else:
                remaining = int(max(0.0, tokens))
                deficit = max(0.0, cost - tokens)
                reset_after = deficit / refill_per_sec if refill_per_sec > 0 else float("inf")
            self._state[key] = (tokens, now)
            return allowed, remaining, reset_after


class RedisTokenBucket(RateLimitStorage):
    """
    Атомарный токен-бакет на Redis с Lua.

    Хранение: HASH <prefix>:<key> => { "tokens": float, "ts": float }
    TTL ключа подстраивается под время полного восстановления бакета.
    """
    LUA = """
    -- KEYS[1] = hash key
    -- ARGV[1] = capacity (int)
    -- ARGV[2] = refill_per_sec (float)
    -- ARGV[3] = cost (int)
    -- ARGV[4] = now (float seconds)
    -- ARGV[5] = ttl_hint (int seconds)

    local key = KEYS[1]
    local cap = tonumber(ARGV[1])
    local rate = tonumber(ARGV[2])
    local cost = tonumber(ARGV[3])
    local now = tonumber(ARGV[4])
    local ttl = tonumber(ARGV[5])

    local h = redis.call('HGETALL', key)
    local tokens = cap
    local ts = now

    if next(h) ~= nil then
      for i=1,#h,2 do
        if h[i] == 'tokens' then tokens = tonumber(h[i+1]) end
        if h[i] == 'ts' then ts = tonumber(h[i+1]) end
      end
      if rate > 0 then
        local elapsed = math.max(0.0, now - ts)
        tokens = math.min(cap, tokens + elapsed * rate)
      end
    end

    local allowed = 0
    if tokens >= cost then
      tokens = tokens - cost
      allowed = 1
    end

    local reset_after = 0.0
    if rate > 0 then
      if tokens >= 1.0 then
        reset_after = 0.0
      else
        reset_after = (1.0 - tokens) / rate
        if allowed == 0 then
          local deficit = math.max(0.0, cost - tokens)
          reset_after = deficit / rate
        end
      end
    else
      reset_after = 1e12  -- "бесконечность" как заглушка
    end

    redis.call('HMSET', key, 'tokens', tokens, 'ts', now)
    if ttl > 0 then
      redis.call('EXPIRE', key, ttl)
    end

    -- return: allowed, remaining(int), reset_after(float)
    local remaining = math.floor(math.max(0.0, tokens))
    return {allowed, remaining, reset_after}
    """

    def __init__(self, redis: RedisClient, key_prefix: str = "ratelimit:bucket") -> None:
        self._r = redis
        self._key_prefix = key_prefix
        self._script = self._r.register_script(self.LUA)

    def _key(self, logical: str) -> str:
        return f"{self._key_prefix}:{logical}"

    @staticmethod
    def _ttl_hint(capacity: int, refill_per_sec: float) -> int:
        if refill_per_sec <= 0:
            return 24 * 3600
        # время полного восстановления + запас
        return int(capacity / refill_per_sec) + 60

    async def acquire(self, key: str, capacity: int, refill_per_sec: float, cost: int) -> tuple[bool, int, float]:
        now = time.monotonic()
        ttl = self._ttl_hint(capacity, refill_per_sec)
        try:
            res = await self._script(
                keys=[self._key(key)],
                args=[capacity, float(refill_per_sec), cost, float(now), ttl],
            )
            # Redis возвращает список байтов/чисел; нормализуем
            allowed = bool(int(res[0]))
            remaining = int(res[1])
            reset_after = float(res[2])
            return allowed, remaining, reset_after
        except Exception as e:  # pragma: no cover
            logger.warning("RedisTokenBucket.acquire failed: %s", e)
            raise

    async def close(self) -> None:
        try:
            await self._r.close()
        except Exception:
            pass


# ---------- КонфигурацияMiddleware ----------


@dataclass(slots=True)
class RateLimitConfig:
    redis_url: Optional[str] = None
    redis_client: Optional[RedisClient] = None
    key_prefix: str = "rl"
    enabled: bool = True
    default_rule: RateLimitRule = field(
        default_factory=lambda: RateLimitRule(capacity=100, refill_per_sec=50.0)
    )
    rules: Sequence[RateLimitRule] = field(default_factory=list)
    exempt_path_patterns: Sequence[str] = field(default_factory=lambda: [r"^/metrics$", r"^/healthz$", r"^/readyz$"])
    trusted_proxies: set[str] = field(default_factory=set)
    identity_headers: Sequence[str] = field(default_factory=lambda: ["x-api-key", "x-user-id", "authorization"])
    fail_open: bool = True  # при сбое Redis пропускать
    add_headers: bool = True  # добавлять RateLimit-* заголовки
    metrics_emitter: Optional[object] = None  # должен поддерживать increment(name, **labels), observe(name, value, **labels)

    # Функция извлечения client_id: (scope) -> str
    identity_func: Optional[Callable[[Scope], str]] = None


# ---------- Вспомогательные утилиты ----------


def _compile_rules(cfg: RateLimitConfig) -> list[CompiledRateLimitRule]:
    compiled = [cfg.default_rule.compiled()]
    compiled.extend(r.compiled() for r in cfg.rules)
    return compiled


def _get_path(scope: Scope) -> str:
    return scope.get("path") or scope.get("raw_path", b"").decode("utf-8", "ignore")


def _headers_dict(scope: Scope) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in scope.get("headers") or []:
        out.setdefault(k.decode().lower(), v.decode())
    return out


def _is_exempt(path: str, patterns: Sequence[str]) -> bool:
    return any(re.search(p, path) for p in patterns)


def _first_non_proxy_ip(xff_value: str, trusted_proxies: set[ipaddress._BaseNetwork]) -> Optional[str]:
    """
    Возвращает первый адрес слева, не принадлежащий списку доверенных прокси.
    """
    parts = [p.strip() for p in xff_value.split(",")]
    for p in parts:
        try:
            ip = ipaddress.ip_address(p)
            if not any(ip in net for net in trusted_proxies):
                return p
        except Exception:
            continue
    return None


def _client_identity_from_scope(scope: Scope, cfg: RateLimitConfig) -> str:
    if cfg.identity_func:
        return cfg.identity_func(scope)
    headers = _headers_dict(scope)
    # 1) Идентификаторы из заголовков
    for name in cfg.identity_headers:
        v = headers.get(name.lower())
        if v:
            # Не помещаем сырое Authorization, берём только хэш-safe субстринг
            if name.lower() == "authorization":
                return f"auth:{hash(v) & 0xFFFFFFFF:x}"
            return f"h:{name.lower()}:{v}"
    # 2) X-Forwarded-For с учётом доверенных прокси
    xff = headers.get("x-forwarded-for")
    if xff and cfg.trusted_proxies:
        nets = {ipaddress.ip_network(n) for n in cfg.trusted_proxies}
        nip = _first_non_proxy_ip(xff, nets)
        if nip:
            return f"ip:{nip}"
    # 3) REMOTE_ADDR из клиентского сокета
    client = scope.get("client")
    if isinstance(client, (tuple, list)) and client:
        return f"ip:{client[0]}"
    # 4) Фоллбек
    return "anonymous"


def _select_rule(compiled_rules: Sequence[CompiledRateLimitRule], scope: Scope) -> CompiledRateLimitRule:
    for r in compiled_rules[1:]:
        if r.matches(scope):
            return r
    return compiled_rules[0]


def _policy_header(capacity: int, refill_per_sec: float) -> str:
    """
    Строка политики для заголовка RateLimit-Policy: "<limit>;w=<window>"
    Здесь window ~= время восполнения полного бакета.
    """
    if refill_per_sec <= 0:
        # нет восполнения: считаем окно большим
        return f"{capacity};w=86400"
    w = max(1, int(capacity / refill_per_sec))
    return f"{capacity};w={w}"


# ---------- Middleware ----------


class RateLimitMiddleware:
    def __init__(self, app: ASGIApp, config: RateLimitConfig) -> None:
        self.app = app
        self.cfg = config
        self.rules = _compile_rules(config)
        self.exempt_res = [re.compile(p) for p in config.exempt_path_patterns]
        self._storage: RateLimitStorage = InMemoryTokenBucket()  # fallback
        self._ready = False
        self._init_lock = asyncio.Lock()

    async def _ensure_storage(self) -> None:
        if self._ready:
            return
        async with self._init_lock:
            if self._ready:
                return
            st: RateLimitStorage = self._storage
            if self.cfg.redis_client and RedisClient is not None:
                st = RedisTokenBucket(self.cfg.redis_client, key_prefix=f"{self.cfg.key_prefix}:tb")
            elif self.cfg.redis_url and redis_from_url is not None:
                try:
                    r = redis_from_url(self.cfg.redis_url, encoding=None, decode_responses=False)
                    st = RedisTokenBucket(r, key_prefix=f"{self.cfg.key_prefix}:tb")
                except Exception as e:  # pragma: no cover
                    logger.warning("RateLimitMiddleware: cannot init Redis, using in-memory: %s", e)
            self._storage = st
            self._ready = True

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not self.cfg.enabled or scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = _get_path(scope)
        if _is_exempt(path, self.cfg.exempt_path_patterns):
            await self.app(scope, receive, send)
            return

        await self._ensure_storage()

        rule = _select_rule(self.rules, scope)
        client_id = _client_identity_from_scope(scope, self.cfg)

        key_parts = [
            self.cfg.key_prefix,
            "v1",
            f"rid:{rule.key_extra}" if rule.key_extra else "rid:default",
            f"cid:{client_id}",
            f"m:{scope.get('method','').upper()}",
            f"p:{rule.path_re.pattern if rule.path_re else '*'}",
        ]
        logical_key = "|".join(key_parts)

        allowed: bool
        remaining: int
        reset_after: float

        t0 = time.perf_counter()
        try:
            allowed, remaining, reset_after = await self._storage.acquire(
                key=logical_key,
                capacity=rule.capacity,
                refill_per_sec=rule.refill_per_sec,
                cost=rule.cost,
            )
            dt = (time.perf_counter() - t0) * 1000.0
            self._metric("observe", "ratelimit_acquire_ms", dt, labels=dict(backend=self._backend_name()))
        except Exception as e:
            self._metric("increment", "ratelimit_errors", 1, labels=dict(kind="backend", backend=self._backend_name()))
            if self.cfg.fail_open:
                allowed, remaining, reset_after = True, rule.capacity, 0.0
                logger.warning("RateLimit backend failed; fail_open=True, allowing request: %s", e)
            else:
                await self._reject(scope, send, limit=rule.capacity, remaining=0, reset_after=1.0)
                return

        if not allowed:
            self._metric("increment", "ratelimit_rejected", 1, labels=dict(rule="match"))
            await self._reject(scope, send, limit=rule.capacity, remaining=remaining, reset_after=reset_after)
            return

        # Оборачиваем send, чтобы инжектировать заголовки в ответ
        async def send_wrapper(message):
            if message["type"] == "http.response.start" and self.cfg.add_headers:
                headers = message.setdefault("headers", [])
                # Добавляем RateLimit поля
                self._add_header(headers, "ratelimit-limit", str(rule.capacity))
                self._add_header(headers, "ratelimit-remaining", str(max(0, remaining)))
                # reset округляем вверх до целой секунды
                reset_sec = int(reset_after + 0.999)
                self._add_header(headers, "ratelimit-reset", str(reset_sec))
                self._add_header(headers, "ratelimit-policy", _policy_header(rule.capacity, rule.refill_per_sec))
            await send(message)

        await self.app(scope, receive, send_wrapper)

    def _backend_name(self) -> str:
        return "redis" if isinstance(self._storage, RedisTokenBucket) else "memory"

    async def _reject(self, scope: Scope, send: Send, limit: int, remaining: int, reset_after: float) -> None:
        reset_sec = int(reset_after + 0.999) if reset_after != float("inf") else 86400
        body_obj = {
            "error": "rate_limited",
            "message": "Too Many Requests",
            "limit": limit,
            "remaining": remaining,
            "reset_after_seconds": reset_sec,
        }
        body = json.dumps(body_obj).encode("utf-8")
        headers = [
            (b"content-type", b"application/json; charset=utf-8"),
            (b"retry-after", str(reset_sec).encode("ascii")),
            (b"ratelimit-limit", str(limit).encode("ascii")),
            (b"ratelimit-remaining", str(max(0, remaining)).encode("ascii")),
            (b"ratelimit-reset", str(reset_sec).encode("ascii")),
            (b"ratelimit-policy", _policy_header(limit, self.rules[0].refill_per_sec).encode("ascii")),
        ]
        await send({"type": "http.response.start", "status": 429, "headers": headers})
        await send({"type": "http.response.body", "body": body})
        self._metric("increment", "ratelimit_http_429", 1, labels={})

    @staticmethod
    def _add_header(headers: list[tuple[bytes, bytes]], name: str, value: str) -> None:
        headers.append((name.encode("ascii"), value.encode("ascii")))

    def _metric(self, kind: str, name: str, value: float, labels: Mapping[str, str] | None = None) -> None:
        emitter = self.cfg.metrics_emitter
        if not emitter:
            return
        try:
            if kind == "increment" and hasattr(emitter, "increment"):
                emitter.increment(name, value=value, **(labels or {}))
            elif kind == "observe" and hasattr(emitter, "observe"):
                emitter.observe(name, value=value, **(labels or {}))
        except Exception:  # глушим метрики, чтобы они не ломали запрос
            pass
