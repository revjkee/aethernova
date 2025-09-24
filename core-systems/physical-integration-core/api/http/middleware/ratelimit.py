from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Literal, Optional, Pattern, Tuple, Union

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

try:
    # Redis 4.x+ (официальный async-клиент)
    from redis.asyncio import Redis  # type: ignore
except Exception:  # pragma: no cover
    Redis = None  # type: ignore

# Метрики (безопасно, если импорт отсутствует — фоллбэк на no-op)
try:
    from prometheus_client import Counter, Histogram
except Exception:  # pragma: no cover
    class _Noop:
        def labels(self, *_, **__):
            return self

        def observe(self, *_):
            return

        def inc(self, *_):
            return

    Counter = Histogram = _Noop  # type: ignore

# ---------------------------
# Конфигурация и модели
# ---------------------------

Method = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
IdentityStrategy = Literal["ip", "x_api_key", "authorization_bearer", "custom"]

@dataclass(frozen=True)
class RateLimitRule:
    name: str
    # Регулярка пути (матчится целиком через re.search)
    path_pattern: Pattern[str]
    methods: Tuple[Method, ...] = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
    # Параметры токен-бакета
    capacity: int = 100
    refill_per_second: float = 50.0
    # Доп. множитель стоимости запроса по методу
    method_cost: Dict[Method, int] = None  # type: ignore
    # Фиксированная стоимость запроса (если >0, перекрывает method_cost)
    fixed_cost: int = 0
    # Взвешивание по Content-Length (байты/делитель => доб. стоимость)
    content_length_divisor: int = 0
    # Идентичность включает путь?
    key_include_path: bool = False
    # Явное отключение лимита (для отладки/белых списков на уровень правила)
    disabled: bool = False

    def __post_init__(self):
        if self.method_cost is None:
            object.__setattr__(self, "method_cost", {"GET": 1, "HEAD": 1, "OPTIONS": 1, "POST": 2, "PUT": 2, "PATCH": 2, "DELETE": 2})  # type: ignore
        if self.capacity <= 0:
            raise ValueError(f"capacity must be > 0 for rule {self.name}")
        if self.refill_per_second <= 0:
            raise ValueError(f"refill_per_second must be > 0 for rule {self.name}")


@dataclass(frozen=True)
class RateLimitConfig:
    enabled: bool = True
    identity_strategy: IdentityStrategy = "ip"
    # Разбор реального клиента из X-Forwarded-For
    trust_forwarded_for: bool = True
    forwarded_for_depth: int = 1  # 1 — последний добавленный прокси виден первым слева
    # Префикс ключей в Redis
    redis_prefix: str = "rl"
    # TTL ключа (сек): >= времени полного восстановления бакета + запас
    key_ttl_seconds: int = 3600
    # Глобальные allow/deny
    ip_allowlist: Tuple[str, ...] = tuple()
    ip_denylist: Tuple[str, ...] = tuple()
    identity_allowlist: Tuple[str, ...] = tuple()
    identity_denylist: Tuple[str, ...] = tuple()
    # Пути, которые не лимитируем (регулярки)
    bypass_paths: Tuple[Pattern[str], ...] = (re.compile(r"^/healthz$"), re.compile(r"^/metrics$"))
    # Дедуп по Idempotency-Key: если ключ повторяется недавно — стоимость 0
    idempotency_dedup_ttl_seconds: int = 600
    # Заголовок с API-ключом
    api_key_header: str = "X-API-Key"
    # Пользовательская функция извлечения идентичности (если identity_strategy='custom')
    custom_identity_fn: Optional[Callable[[Request], Awaitable[str]]] = None
    # Поведение при недоступности Redis
    fail_open: bool = False  # true — пропускать запросы (но писать предупреждение)
    # Локальный фоллбэк (in-memory)
    enable_local_fallback: bool = True
    # Лимиты для локального фоллбэка (по умолчанию зеркалят выбранное правило)
    local_fallback_capacity: int = 50
    local_fallback_refill_per_second: float = 25.0
    # Логирование
    log_json: bool = True

# ---------------------------
# Утилиты
# ---------------------------

def _now_ms() -> int:
    return int(time.time() * 1000)


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _match_rule(rules: List[RateLimitRule], path: str, method: str) -> Optional[RateLimitRule]:
    # Возвращаем первый наиболее специфичный (длинная регулярка) подходящий rule
    candidates: List[Tuple[int, RateLimitRule]] = []
    for r in rules:
        if method.upper() not in r.methods:
            continue
        if r.path_pattern.search(path):
            candidates.append((len(r.path_pattern.pattern), r))
    if not candidates:
        return None
    candidates.sort(key=lambda t: t[0], reverse=True)
    return candidates[0][1]


def _ip_in_cidrs(ip: str, cidrs: Iterable[str]) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs:
        try:
            if ip_obj in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def _extract_client_ip(req: Request, trust_forwarded_for: bool, hop: int) -> str:
    if trust_forwarded_for:
        xff = req.headers.get("x-forwarded-for")
        if xff:
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            if parts:
                # Берём нужный hop с правого края (ближайший к origin клиенту)
                idx = -hop
                try:
                    return parts[idx]
                except Exception:
                    return parts[-1]
    # Fallback на peername
    client = req.client
    return client.host if client else "0.0.0.0"


async def _default_custom_identity(_: Request) -> str:
    return "anonymous"

# ---------------------------
# Redis атомарный лимитер (Lua)
# ---------------------------

# KEYS[1] — ключ бакета
# ARGV: now_ms, capacity, refill_per_sec, cost, ttl_seconds
# Логика: классический token bucket. Возвращаем:
# allowed (1/0), remaining (int), reset_ms_to_full (int), retry_after_ms (int)
REDIS_TOKEN_BUCKET_LUA = """
local key = KEYS[1]
local now_ms = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local refill_per_sec = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local ttl_seconds = tonumber(ARGV[5])

local state = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(state[1])
local ts = tonumber(state[2])

if not tokens or not ts then
  tokens = capacity
  ts = now_ms
else
  local delta_ms = math.max(0, now_ms - ts)
  local refill = (delta_ms / 1000.0) * refill_per_sec
  tokens = math.min(capacity, tokens + refill)
  ts = now_ms
end

local allowed = 0
local retry_after_ms = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
else
  local deficit = cost - tokens
  retry_after_ms = math.ceil((deficit / refill_per_sec) * 1000.0)
end

local reset_ms = math.ceil(((capacity - tokens) / refill_per_sec) * 1000.0)

redis.call('HMSET', key, 'tokens', tokens, 'ts', ts)
redis.call('EXPIRE', key, ttl_seconds)

return {allowed, math.floor(tokens + 0.0), reset_ms, retry_after_ms}
"""

# Дедуп по Idempotency-Key (0 стоимость, если ключ уже видели)
# KEYS[1] — dedup:<hash>, ARGV[1]=ttl_seconds
REDIS_IDEMPOTENCY_LUA = """
local key = KEYS[1]
local ttl_seconds = tonumber(ARGV[1])
local exists = redis.call('EXISTS', key)
if exists == 1 then
  return 1
else
  redis.call('SET', key, '1', 'EX', ttl_seconds)
  return 0
end
"""

# ---------------------------
# Локальный in-memory фоллбэк
# ---------------------------

class _LocalBucket:
    __slots__ = ("capacity", "refill_per_sec", "tokens", "ts", "lock")

    def __init__(self, capacity: int, refill_per_sec: float) -> None:
        self.capacity = capacity
        self.refill_per_sec = refill_per_sec
        self.tokens = float(capacity)
        self.ts = _now_ms()
        self.lock = asyncio.Lock()

    async def take(self, cost: int) -> Tuple[bool, int, int, int]:
        async with self.lock:
            now = _now_ms()
            delta_ms = max(0, now - self.ts)
            self.tokens = min(self.capacity, self.tokens + (delta_ms / 1000.0) * self.refill_per_sec)
            self.ts = now
            if self.tokens >= cost:
                self.tokens -= cost
                allowed = True
                retry = 0
            else:
                allowed = False
                deficit = cost - self.tokens
                retry = int((deficit / self.refill_per_sec) * 1000.0 + 0.999)
            reset = int(((self.capacity - self.tokens) / self.refill_per_sec) * 1000.0 + 0.999)
            return allowed, int(self.tokens), reset, retry


class _LocalLimiter:
    def __init__(self, capacity: int, refill_per_sec: float) -> None:
        self.capacity = capacity
        self.refill = refill_per_sec
        self._buckets: Dict[str, _LocalBucket] = {}
        self._lock = asyncio.Lock()

    async def take(self, key: str, cost: int) -> Tuple[bool, int, int, int]:
        b = self._buckets.get(key)
        if not b:
            async with self._lock:
                b = self._buckets.get(key)
                if not b:
                    b = _LocalBucket(self.capacity, self.refill)
                    self._buckets[key] = b
        return await b.take(cost)

# ---------------------------
# Основной middleware
# ---------------------------

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Промышленный rate limiting для Starlette/FastAPI.
    Особенности:
      - Redis-based токен-бакет (атомарный Lua), per-identity + per-rule scope
      - Взвешенная стоимость: метод/Content-Length/фиксированная
      - Дедуп по Idempotency-Key (стоимость 0 при повторе ключа в TTL)
      - Заголовки RateLimit-* и X-RateLimit-* + Retry-After
      - Белые/чёрные списки IP/идентичностей; bypass для health/metrics
      - Наблюдаемость: счётчики/гистограммы Prometheus, JSON-логирование
      - Fallback: локальный in-memory лимитер при падении Redis (опционально)
    """

    def __init__(
        self,
        app: ASGIApp,
        rules: List[RateLimitRule],
        config: RateLimitConfig = RateLimitConfig(),
        redis: Optional[Redis] = None,  # type: ignore
        logger: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        super().__init__(app)
        self.rules = rules
        self.cfg = config
        self.redis = redis
        self.logger = logger or self._default_logger

        self._lua_sha_bucket: Optional[str] = None
        self._lua_sha_idempotency: Optional[str] = None

        # Fallback локальный
        self._local = (
            _LocalLimiter(self.cfg.local_fallback_capacity, self.cfg.local_fallback_refill_per_second)
            if self.cfg.enable_local_fallback
            else None
        )

        # Прекомпиляция: ничего, т.к. правила уже имеют compiled regex

        # Метрики
        self.m_req_allowed = Counter(
            "http_ratelimit_allowed_total",
            "Allowed requests passing rate limiter",
            ["rule", "decision"],
        )
        self.m_wait_ms = Histogram(
            "http_ratelimit_retry_after_ms",
            "Retry-After milliseconds suggested by limiter (0 if allowed)",
            ["rule"],
        )

    # ------------- Вспомогательные методы -------------

    async def _ensure_scripts(self) -> None:
        if not self.redis:
            return
        try:
            if not self._lua_sha_bucket:
                self._lua_sha_bucket = await self.redis.script_load(REDIS_TOKEN_BUCKET_LUA)  # type: ignore
            if not self._lua_sha_idempotency:
                self._lua_sha_idempotency = await self.redis.script_load(REDIS_IDEMPOTENCY_LUA)  # type: ignore
        except Exception as e:  # pragma: no cover
            self._warn("redis_script_load_failed", {"error": str(e)})
            # оставляем sha=None -> будем вызывать EVAL

    def _default_logger(self, record: Dict[str, Any]) -> None:  # pragma: no cover
        if self.cfg.log_json:
            print(json.dumps(record, ensure_ascii=False))
        else:
            print(record)

    def _info(self, msg: str, extra: Dict[str, Any]) -> None:
        self.logger({"level": "info", "msg": msg, **extra})

    def _warn(self, msg: str, extra: Dict[str, Any]) -> None:
        self.logger({"level": "warn", "msg": msg, **extra})

    # ------------- Идентичность и стоимость -------------

    async def _identity(self, req: Request) -> str:
        # Чёрный список IP приоритетнее
        ip = _extract_client_ip(req, self.cfg.trust_forwarded_for, self.cfg.forwarded_for_depth)
        if self.cfg.ip_denylist and _ip_in_cidrs(ip, self.cfg.ip_denylist):
            return f"!denied-ip:{ip}"

        if self.cfg.identity_strategy == "ip":
            ident = ip
        elif self.cfg.identity_strategy == "x_api_key":
            api_key = req.headers.get(self.cfg.api_key_header, "")
            ident = f"key:{api_key}" if api_key else "key:anonymous"
        elif self.cfg.identity_strategy == "authorization_bearer":
            auth = req.headers.get("authorization", "")
            token = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") and len(auth.split(" ", 1)) == 2 else ""
            # Хешируем токен, чтобы не хранить его целиком
            ident = f"bearer:{_sha256(token) if token else 'anonymous'}"
        elif self.cfg.identity_strategy == "custom" and self.cfg.custom_identity_fn:
            ident = await self.cfg.custom_identity_fn(req)
        else:
            ident = "anonymous"

        # Белые/чёрные списки идентичностей
        if self.cfg.identity_denylist and ident in self.cfg.identity_denylist:
            return f"!denied-identity:{ident}"
        if self.cfg.identity_allowlist and ident in self.cfg.identity_allowlist:
            return f"!allowed-identity:{ident}"

        # Белый список IP встраиваем явным маркером
        if self.cfg.ip_allowlist and _ip_in_cidrs(ip, self.cfg.ip_allowlist):
            return f"!allowed-ip:{ip}"

        return ident

    def _request_cost(self, req: Request, rule: RateLimitRule) -> int:
        if rule.fixed_cost > 0:
            return rule.fixed_cost
        cost = rule.method_cost.get(req.method.upper(), 1)
        if rule.content_length_divisor and rule.content_length_divisor > 0:
            try:
                clen = int(req.headers.get("content-length", "0"))
                cost += max(0, clen // rule.content_length_divisor)
            except Exception:
                pass
        return max(1, int(cost))

    def _rule_key(self, ident: str, rule: RateLimitRule, req: Request) -> str:
        # Ключ формируется детерминированно; запрещаем двоеточие в user-части для простоты
        base = f"{self.cfg.redis_prefix}:{rule.name}:{ident.replace(':','_')}"
        if rule.key_include_path:
            base += f":{hashlib.blake2b(req.url.path.encode(), digest_size=8).hexdigest()}"
        return base

    # ------------- Основной обработчик -------------

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        if not self.cfg.enabled:
            return await call_next(request)

        # Bypass для сервисных путей
        path = request.url.path
        for p in self.cfg.bypass_paths:
            if p.search(path):
                return await call_next(request)

        # Подбор правила
        rule = _match_rule(self.rules, path, request.method)
        if not rule or rule.disabled:
            return await call_next(request)

        ident = await self._identity(request)

        # Политики allow/deny
        if ident.startswith("!denied-"):
            return self._reject(request, rule, retry_after_ms=60_000, reason="denied_by_policy")
        if ident.startswith("!allowed-"):
            # Полный bypass для белых
            response = await call_next(request)
            self._set_headers(response, rule, limit=rule.capacity, remaining=rule.capacity, reset_ms=0, retry_after_ms=0)
            return response

        now_ms = _now_ms()

        # Дедуп по Idempotency-Key
        cost = self._request_cost(request, rule)
        idemp_key = request.headers.get("idempotency-key")
        seen_before = False
        if idemp_key:
            seen_before = await self._idempotency_seen(idemp_key)

        effective_cost = 0 if seen_before else cost

        # Основной лимитер на Redis / локальный фоллбэк
        try:
            allowed, remaining, reset_ms, retry_ms = await self._redis_take(
                key=self._rule_key(ident, rule, request),
                capacity=rule.capacity,
                refill_per_sec=rule.refill_per_second,
                cost=effective_cost,
            )
        except Exception as e:
            self._warn("redis_limiter_error", {"error": str(e)})
            if self.cfg.fail_open:
                # Пропускаем, но отдаем максимально информативные заголовки
                response = await call_next(request)
                self._set_headers(response, rule, limit=rule.capacity, remaining=rule.capacity - effective_cost, reset_ms=0, retry_after_ms=0)
                return response
            # Fallback на локальный лимитер
            if self._local:
                allowed, remaining, reset_ms, retry_ms = await self._local.take(
                    key=self._rule_key(ident, rule, request), cost=effective_cost
                )
            else:
                return self._reject(request, rule, retry_after_ms=60_000, reason="limiter_unavailable")

        # Метрики
        self.m_req_allowed.labels(rule=rule.name, decision="allow" if allowed else "reject").inc()
        self.m_wait_ms.labels(rule=rule.name).observe(float(retry_ms))

        if not allowed:
            return self._reject(request, rule, retry_after_ms=retry_ms, reason="rate_limited")

        # Пропуск запроса
        response = await call_next(request)
        self._set_headers(response, rule, limit=rule.capacity, remaining=max(0, remaining), reset_ms=reset_ms, retry_after_ms=0)
        return response

    # ------------- Redis операции -------------

    async def _redis_take(self, key: str, capacity: int, refill_per_sec: float, cost: int) -> Tuple[bool, int, int, int]:
        if not self.redis:
            raise RuntimeError("Redis client is not configured")

        await self._ensure_scripts()

        now = _now_ms()
        args = [now, capacity, float(refill_per_sec), cost, self.cfg.key_ttl_seconds]
        try:
            if self._lua_sha_bucket:
                res = await self.redis.evalsha(self._lua_sha_bucket, 1, key, *args)  # type: ignore
            else:
                res = await self.redis.eval(REDIS_TOKEN_BUCKET_LUA, 1, key, *args)  # type: ignore
        except Exception:
            # Если evalsha не найден — пробуем обычный eval единожды
            res = await self.redis.eval(REDIS_TOKEN_BUCKET_LUA, 1, key, *args)  # type: ignore

        # res: [allowed, remaining, reset_ms, retry_after_ms]
        allowed = bool(int(res[0]))
        remaining = int(res[1])
        reset_ms = int(res[2])
        retry_ms = int(res[3])
        return allowed, remaining, reset_ms, retry_ms

    async def _idempotency_seen(self, key: str) -> bool:
        if not self.redis:
            # Локальная метка: безопаснее считать, что ключ не встречался, чтобы не "обнулять" стоимость.
            return False
        await self._ensure_scripts()
        rkey = f"{self.cfg.redis_prefix}:idemp:{_sha256(key)}"
        args = [self.cfg.idempotency_dedup_ttl_seconds]
        try:
            if self._lua_sha_idempotency:
                res = await self.redis.evalsha(self._lua_sha_idempotency, 1, rkey, *args)  # type: ignore
            else:
                res = await self.redis.eval(REDIS_IDEMPOTENCY_LUA, 1, rkey, *args)  # type: ignore
        except Exception:
            res = await self.redis.eval(REDIS_IDEMPOTENCY_LUA, 1, rkey, *args)  # type: ignore
        return bool(int(res) == 1)

    # ------------- Ответы и заголовки -------------

    def _set_headers(self, resp: Response, rule: RateLimitRule, limit: int, remaining: int, reset_ms: int, retry_after_ms: int) -> None:
        # Современные заголовки семейства RateLimit-*, и совместимость с X-RateLimit-*
        # Значения округляем консервативно.
        reset_sec = max(0, int((reset_ms + 999) / 1000))
        resp.headers["RateLimit-Limit"] = str(limit)
        resp.headers["RateLimit-Remaining"] = str(max(0, remaining))
        resp.headers["RateLimit-Reset"] = str(reset_sec)

        resp.headers["X-RateLimit-Limit"] = str(limit)
        resp.headers["X-RateLimit-Remaining"] = str(max(0, remaining))
        resp.headers["X-RateLimit-Reset"] = str(reset_sec)

        if retry_after_ms > 0:
            resp.headers["Retry-After"] = str(max(1, int((retry_after_ms + 999) / 1000)))

        # Информационный заголовок с именем правила
        resp.headers["RateLimit-Rule"] = rule.name

    def _reject(self, req: Request, rule: RateLimitRule, retry_after_ms: int, reason: str) -> Response:
        body = {
            "error": "too_many_requests",
            "detail": "Rate limit exceeded",
            "rule": rule.name,
            "retry_after_ms": max(0, int(retry_after_ms)),
        }
        self._warn("rate_limit_reject", {"path": req.url.path, "method": req.method, **body})
        resp = JSONResponse(status_code=429, content=body)
        self._set_headers(resp, rule, limit=rule.capacity, remaining=0, reset_ms=retry_after_ms, retry_after_ms=retry_after_ms)
        return resp

# ---------------------------
# Хелперы для интеграции
# ---------------------------

def make_default_rules() -> List[RateLimitRule]:
    """
    Рекомендованный набор правил по умолчанию:
      - Жёстче на write-эндпойнтах /api/v1/
      - Мягче для чтения и статических ресурсов
    """
    return [
        RateLimitRule(
            name="api_reads",
            path_pattern=re.compile(r"^/api/v1/.*$"),
            methods=("GET", "HEAD", "OPTIONS"),
            capacity=300,
            refill_per_second=150.0,
            method_cost={"GET": 1, "HEAD": 1, "OPTIONS": 1},
        ),
        RateLimitRule(
            name="api_writes",
            path_pattern=re.compile(r"^/api/v1/.*$"),
            methods=("POST", "PUT", "PATCH", "DELETE"),
            capacity=100,
            refill_per_second=50.0,
            method_cost={"POST": 2, "PUT": 2, "PATCH": 2, "DELETE": 2},
            content_length_divisor=1_000_000,  # +1 токен на каждый ~1MB
        ),
        RateLimitRule(
            name="auth",
            path_pattern=re.compile(r"^/api/v1/auth/.*$"),
            methods=("POST",),
            capacity=30,
            refill_per_second=10.0,
            fixed_cost=3,
        ),
        RateLimitRule(
            name="static_assets",
            path_pattern=re.compile(r"^/(assets|static)/.*$"),
            methods=("GET", "HEAD"),
            capacity=1000,
            refill_per_second=500.0,
            key_include_path=False,
        ),
    ]


def build_redis_from_env() -> Optional[Redis]:  # type: ignore
    """
    Создание Redis-клиента из переменных окружения:
      RATE_LIMIT_REDIS_URL=redis://:pass@host:6379/0
      RATE_LIMIT_REDIS_SSL=true|false
    """
    if Redis is None:
        return None
    url = os.getenv("RATE_LIMIT_REDIS_URL", "")
    if not url:
        return None
    ssl = os.getenv("RATE_LIMIT_REDIS_SSL", "false").lower() == "true"
    return Redis.from_url(url, ssl=ssl, decode_responses=False)  # type: ignore


def register_ratelimit_middleware(
    app: ASGIApp,
    rules: Optional[List[RateLimitRule]] = None,
    config: Optional[RateLimitConfig] = None,
    redis: Optional[Redis] = None,  # type: ignore
) -> RateLimitMiddleware:
    """
    Удобный регистратор: создаёт и навешивает middleware.
    Пример:
        app = FastAPI()
        rl = register_ratelimit_middleware(app)
    """
    rl = RateLimitMiddleware(
        app=app,
        rules=rules or make_default_rules(),
        config=config or RateLimitConfig(),
        redis=redis or build_redis_from_env(),
    )
    # Starlette/FastAPI ожидают экземпляр middleware через .add_middleware,
    # но мы совместимы и с ручной инициализацией (как класс).
    if hasattr(app, "add_middleware"):
        # type: ignore[attr-defined]
        app.add_middleware(  # type: ignore
            RateLimitMiddleware,
            rules=rl.rules,
            config=rl.cfg,
            redis=rl.redis,
        )
    return rl
