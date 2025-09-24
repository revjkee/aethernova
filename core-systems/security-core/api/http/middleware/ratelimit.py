# security-core/api/http/middleware/ratelimit.py
"""
Промышленный ASGI middleware для rate limiting:
- Токен‑бакет (token bucket) поверх Redis с атомарным Lua (без гонок).
- Гибкая маршрутизация правил по методу/пути/тенанту/заголовкам.
- Идентификатор клиента: API-ключ/Authorization/Bearer, заголовок, IP (X-Forwarded-For), кастомный колбэк.
- Белые/чёрные списки сетей (CIDR).
- Мягкий/жёсткий режим: только заголовки или запрет с 429.
- Идемпотентность: повтор с тем же Idempotency-Key не списывает токены.
- Заголовки совместимы с практикой RateLimit-* и Retry-After.
- Хуки для метрик (например, Prometheus/StatsD).
- Полностью async, без блокировок. Совместим со Starlette/FastAPI/Any ASGI.

Зависимости: redis>=5 (redis.asyncio), starlette.types (или совместимые типы ASGI).
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Pattern, Sequence, Tuple

try:
    # Redis 5.x async client
    from redis.asyncio import Redis
except Exception as e:  # pragma: no cover
    raise ImportError("ratelimit middleware requires redis>=5 with redis.asyncio") from e

try:
    # Типы ASGI
    from starlette.types import ASGIApp, Message, Receive, Scope, Send
except Exception as e:  # pragma: no cover
    # Минимальные определения, если Starlette не установлена (ASGI протокол совместим)
    ASGIApp = Any  # type: ignore
    Scope = MutableMapping[str, Any]  # type: ignore
    Receive = Callable[[], Awaitable[Mapping[str, Any]]]  # type: ignore
    Send = Callable[[Mapping[str, Any]], Awaitable[None]]  # type: ignore
    Message = Mapping[str, Any]  # type: ignore

logger = logging.getLogger("security_core.ratelimit")


class RateLimitExceeded(Exception):
    """Исключение для превышения лимита."""


# ---------- Lua-скрипт токен‑бакета (микро‑токены: все целое, без float) ----------

_LUA_TOKEN_BUCKET = """
-- KEYS[1]: bucket key
-- ARGV[1]: capacity_micro (int)
-- ARGV[2]: rate_micro_per_ms (int)
-- ARGV[3]: now_ms (int)
-- ARGV[4]: request_micro (int)
-- ARGV[5]: ttl_ms (int)
-- ARGV[6]: idem_key (string) or "" if none
-- ARGV[7]: idem_ttl_ms (int)

local bucket = KEYS[1]
local capacity = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local now_ms = tonumber(ARGV[3])
local req = tonumber(ARGV[4])
local ttl_ms = tonumber(ARGV[5])
local idem_key = ARGV[6]
local idem_ttl_ms = tonumber(ARGV[7])

-- идемпотентность: если ключ уже видели, позволяем без списания токенов
if idem_key ~= nil and idem_key ~= "" then
  local idem_full_key = bucket .. ":idem:" .. idem_key
  local seen = redis.call("GET", idem_full_key)
  if seen then
    -- вернуть allowed=1, remaining (не вычисляя бакет), retry_ms=0, reset_ms=0, idem=1
    return {1, -1, 0, 0, 1}
  end
end

local data = redis.call("HMGET", bucket, "tokens", "ts")
local tokens = tonumber(data[1])
local ts = tonumber(data[2])

if not tokens or not ts then
  tokens = capacity
  ts = now_ms
else
  if now_ms > ts then
    local delta = now_ms - ts
    local refill = delta * rate
    tokens = tokens + refill
    if tokens > capacity then
      tokens = capacity
    end
  end
end

local allowed = 0
local retry_ms = 0
if tokens >= req then
  tokens = tokens - req
  allowed = 1
else
  local deficit = req - tokens
  -- ceil(deficit / rate)
  retry_ms = math.floor((deficit + rate - 1) / rate)
end

-- reset_ms = время до полного восстановления ёмкости (информативно)
local reset_ms = 0
if tokens < capacity and rate > 0 then
  reset_ms = math.floor((capacity - tokens + rate - 1) / rate)
end

-- Пишем состояние и TTL
redis.call("HMSET", bucket, "tokens", tokens, "ts", now_ms)
local ttl_sec = math.floor((ttl_ms + 999) / 1000)
if ttl_sec < 1 then ttl_sec = 1 end
redis.call("PEXPIRE", bucket, ttl_ms)

-- Отметка идемпотентности только если запрос успешен
if allowed == 1 and idem_key ~= nil and idem_key ~= "" then
  local idem_full_key = bucket .. ":idem:" .. idem_key
  redis.call("PSETEX", idem_full_key, idem_ttl_ms, "1")
end

-- Возврат:
-- 1: allowed (0/1)
-- 2: remaining_micro
-- 3: retry_ms
-- 4: reset_ms
-- 5: idem_hit (0/1)
return {allowed, math.floor(tokens), retry_ms, reset_ms, 0}
"""


def _now_ms() -> int:
    return int(time.time() * 1000)


def _b64sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RateLimitRule:
    name: str
    limit: int                    # разрешённых запросов за окно
    window_seconds: int           # длина окна в секундах (для темпа пополнения)
    burst: Optional[int] = None   # ёмкость бакета; по умолчанию = limit
    methods: Optional[Sequence[str]] = None     # e.g. ["GET","POST"]
    path_pattern: Optional[str] = None          # regex для пути
    identifier: Optional[str] = None            # "ip", "header:X-API-Key", "header:Authorization", "query:api_key"
    tenant_header: Optional[str] = None         # доп. сегментация "X-Tenant-ID"
    soft_enforce: bool = False                  # только выставлять заголовки, не блокировать
    idem_ttl_seconds: int = 600                 # TTL для Idempotency-Key

    def tokens_per_ms(self) -> Tuple[int, int]:
        """
        Возвращает (capacity_micro, rate_micro_per_ms)
        """
        cap = (self.burst or self.limit)
        # дискретизация: 1000 микротокенов на 1 токен
        capacity_micro = cap * 1000
        # rate = limit токенов за window_seconds -> micro/ms
        rate_micro_per_ms = max(1, int((self.limit * 1000) / max(1, self.window_seconds) / 1000))
        # Выше rate_micro_per_ms = floor(limit/window_seconds) в микротокенах/мс.
        # Для высокой точности можно повысить дискретизацию (10000).
        return capacity_micro, max(1, rate_micro_per_ms)

    def ttl_ms(self) -> int:
        # TTL бакета = время полного восстановления + запас 10%
        cap_micro, rate = self.tokens_per_ms()
        full_ms = int(cap_micro / rate)
        return int(full_ms * 1.1) + 1000

    def compiled_pattern(self) -> Optional[Pattern[str]]:
        return re.compile(self.path_pattern) if self.path_pattern else None


@dataclass
class RateLimiterConfig:
    redis: Redis
    prefix: str = "rl:"
    trust_forwarded: bool = True
    allow_cidrs: Sequence[str] = field(default_factory=tuple)   # белый список
    deny_cidrs: Sequence[str] = field(default_factory=tuple)    # чёрный список
    default_rules: Sequence[RateLimitRule] = field(default_factory=tuple)
    metrics_hook: Optional[Callable[[str, Mapping[str, Any]], None]] = None  # e.g. lambda name,tags: ...
    hash_identity: bool = True  # хэшировать идентификатор в ключе
    include_ratelimit_headers: bool = True


class RedisTokenBucket:
    def __init__(self, redis: Redis, prefix: str = "rl:") -> None:
        self._r = redis
        self._prefix = prefix
        self._sha: Optional[str] = None
        self._lock = asyncio.Lock()

    async def _ensure_script(self) -> str:
        if self._sha:
            return self._sha
        async with self._lock:
            if self._sha:
                return self._sha
            self._sha = await self._r.script_load(_LUA_TOKEN_BUCKET)
            return self._sha

    async def consume(
        self,
        key: str,
        capacity_micro: int,
        rate_micro_per_ms: int,
        now_ms: int,
        request_micro: int = 1000,
        ttl_ms: Optional[int] = None,
        idem_key: str = "",
        idem_ttl_ms: int = 600_000,
    ) -> Tuple[bool, int, int, int, bool]:
        """
        Возвращает (allowed, remaining_micro, retry_ms, reset_ms, idem_hit)
        """
        sha = await self._ensure_script()
        ttl_ms = ttl_ms or int(capacity_micro / max(1, rate_micro_per_ms)) + 1000
        try:
            res = await self._r.evalsha(
                sha,
                1,
                key,
                capacity_micro,
                rate_micro_per_ms,
                now_ms,
                request_micro,
                ttl_ms,
                idem_key,
                idem_ttl_ms,
            )
        except Exception:
            # Фоллбек на прямой eval (на случай перезагрузки Redis)
            res = await self._r.eval(
                _LUA_TOKEN_BUCKET,
                1,
                key,
                capacity_micro,
                rate_micro_per_ms,
                now_ms,
                request_micro,
                ttl_ms,
                idem_key,
                idem_ttl_ms,
            )
        allowed = bool(int(res[0]))
        remaining = int(res[1])
        retry_ms = int(res[2])
        reset_ms = int(res[3])
        idem_hit = bool(int(res[4]))
        return allowed, remaining, retry_ms, reset_ms, idem_hit

    def key(self, *parts: str) -> str:
        return self._prefix + ":".join(parts)


def _parse_cidrs(cidrs: Sequence[str]) -> List[ipaddress._BaseNetwork]:
    nets: List[ipaddress._BaseNetwork] = []
    for c in cidrs:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except Exception:
            logger.warning("Invalid CIDR ignored: %s", c)
    return nets


def _remote_addr(scope: Scope, trust_forwarded: bool) -> str:
    headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
    if trust_forwarded:
        h = headers.get("x-forwarded-for")
        if h:
            # берем первый адрес из списка
            return h.split(",")[0].strip()
        h = headers.get("x-real-ip")
        if h:
            return h.strip()
    client = scope.get("client")
    if client and isinstance(client, tuple):
        return str(client[0])
    return "0.0.0.0"


def _ip_in(nets: Sequence[ipaddress._BaseNetwork], ip: str) -> bool:
    try:
        ipaddr = ipaddress.ip_address(ip)
    except Exception:
        return False
    return any(ipaddr in n for n in nets)


def _get_header(scope: Scope, name: str) -> Optional[str]:
    lname = name.lower().encode()
    for k, v in scope.get("headers", []):
        if k.lower() == lname:
            return v.decode()
    return None


def _path(scope: Scope) -> str:
    return scope.get("path", "/")


def _method(scope: Scope) -> str:
    return scope.get("method", "GET").upper()


class RateLimitMiddleware:
    def __init__(self, app: ASGIApp, config: RateLimiterConfig):
        self.app = app
        self.cfg = config
        self._limiter = RedisTokenBucket(config.redis, prefix=config.prefix)
        self._allow_nets = _parse_cidrs(config.allow_cidrs)
        self._deny_nets = _parse_cidrs(config.deny_cidrs)
        self._compiled_rules: List[Tuple[RateLimitRule, Optional[Pattern[str]]]] = [
            (r, r.compiled_pattern()) for r in config.default_rules
        ]

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = _path(scope)
        method = _method(scope)
        ip = _remote_addr(scope, self.cfg.trust_forwarded)

        # Сетевые списки
        if self._deny_nets and _ip_in(self._deny_nets, ip):
            await self._reject(
                send,
                status=429,
                msg="Rate limited (denylist).",
                headers={"Retry-After": "60"},
            )
            self._metric("denylist_block", {"ip": ip, "path": path})
            return
        if self._allow_nets and _ip_in(self._allow_nets, ip):
            await self._pass(scope, receive, send, headers=self._headers_passthrough())
            self._metric("allowlist_pass", {"ip": ip, "path": path})
            return

        # Найти подходящее правило
        rule = self._match_rule(path, method)
        if not rule:
            await self._pass(scope, receive, send, headers=self._headers_passthrough())
            return

        # Сформировать идентификатор
        ident = self._make_identity(scope, rule, ip)
        if self.cfg.hash_identity:
            ident_key = _b64sha256(ident)
        else:
            ident_key = ident

        bucket_key = self._limiter.key(rule.name, ident_key)

        # Идемпотентность
        idem = _get_header(scope, "Idempotency-Key") or ""

        # Расход 1 токен на запрос
        capacity_micro, rate_micro_ms = rule.tokens_per_ms()
        now_ms = _now_ms()
        allowed, remaining_micro, retry_ms, reset_ms, idem_hit = await self._limiter.consume(
            key=bucket_key,
            capacity_micro=capacity_micro,
            rate_micro_per_ms=rate_micro_ms,
            now_ms=now_ms,
            request_micro=1000,  # 1 токен = 1000 микротокенов
            ttl_ms=rule.ttl_ms(),
            idem_key=idem,
            idem_ttl_ms=rule.idem_ttl_seconds * 1000,
        )

        # Заголовки
        limit_tokens = rule.burst or rule.limit
        remaining_tokens = max(0, remaining_micro // 1000 if remaining_micro >= 0 else -1)
        headers = self._rate_headers(
            limit=limit_tokens,
            remaining=remaining_tokens if remaining_tokens >= 0 else None,
            retry_after_s=(retry_ms + 999) // 1000 if not allowed else 0,
            reset_s=(reset_ms + 999) // 1000,
            rule=rule,
        )

        if allowed or rule.soft_enforce or idem_hit:
            await self._pass(scope, receive, send, headers=headers)
            self._metric(
                "request_allowed",
                {"ip": ip, "path": path, "method": method, "rule": rule.name, "idem": int(idem_hit)},
            )
            return

        # Жёсткий отказ
        await self._reject(
            send,
            status=429,
            msg="Rate limit exceeded.",
            headers=headers,
        )
        self._metric(
            "request_blocked",
            {"ip": ip, "path": path, "method": method, "rule": rule.name, "retry_after_ms": retry_ms},
        )

    def _match_rule(self, path: str, method: str) -> Optional[RateLimitRule]:
        for rule, pat in self._compiled_rules:
            if rule.methods and method not in {m.upper() for m in rule.methods}:
                continue
            if pat and not pat.search(path):
                continue
            return rule
        return None

    def _make_identity(self, scope: Scope, rule: RateLimitRule, ip: str) -> str:
        tenant = ""
        if rule.tenant_header:
            tenant = _get_header(scope, rule.tenant_header) or ""
        base = ""
        if rule.identifier:
            kind = rule.identifier
            if kind == "ip":
                base = ip
            elif kind.startswith("header:"):
                name = kind.split(":", 1)[1]
                base = _get_header(scope, name) or ""
            elif kind.startswith("query:"):
                base = self._query_param(scope, kind.split(":", 1)[1]) or ""
            elif kind == "authorization.bearer":
                auth = _get_header(scope, "Authorization") or ""
                if auth.lower().startswith("bearer "):
                    base = auth[7:].strip()
            else:
                base = ip  # дефолт — IP
        else:
            base = ip
        if tenant:
            return f"{tenant}|{base}"
        return base

    def _query_param(self, scope: Scope, name: str) -> Optional[str]:
        raw = scope.get("query_string", b"")
        if not raw:
            return None
        # простейший парсинг, без зависимостей
        for pair in raw.split(b"&"):
            if not pair:
                continue
            if b"=" in pair:
                k, v = pair.split(b"=", 1)
            else:
                k, v = pair, b""
            if k.decode() == name:
                try:
                    return v.decode()
                except Exception:
                    return None
        return None

    def _rate_headers(
        self,
        limit: int,
        remaining: Optional[int],
        retry_after_s: int,
        reset_s: int,
        rule: RateLimitRule,
    ) -> Dict[str, str]:
        if not self.cfg.include_ratelimit_headers:
            return {}
        hdrs: Dict[str, str] = {}
        hdrs["RateLimit-Limit"] = str(limit)
        if remaining is not None and remaining >= 0:
            hdrs["RateLimit-Remaining"] = str(remaining)
        hdrs["RateLimit-Reset"] = str(max(0, reset_s))
        if retry_after_s > 0:
            hdrs["Retry-After"] = str(retry_after_s)
        # Информативная политика
        hdrs["RateLimit-Policy"] = f"requests;w={rule.window_seconds};burst={rule.burst or rule.limit}"
        return hdrs

    async def _pass(self, scope: Scope, receive: Receive, send: Send, headers: Mapping[str, str]) -> None:
        # Оборачиваем send для инъекции заголовков на ответ
        async def send_wrapped(message: Message) -> None:
            if message.get("type") == "http.response.start" and headers:
                original = list(message.get("headers", []))
                for k, v in headers.items():
                    original.append((k.encode(), v.encode()))
                message = {**message, "headers": original}
            await send(message)

        await self.app(scope, receive, send_wrapped)

    async def _reject(self, send: Send, status: int, msg: str, headers: Mapping[str, str]) -> None:
        body = json.dumps({"error": "rate_limited", "message": msg}).encode("utf-8")
        hdrs = [(b"content-type", b"application/json; charset=utf-8")]
        for k, v in headers.items():
            hdrs.append((k.encode(), v.encode()))
        await send({"type": "http.response.start", "status": status, "headers": hdrs})
        await send({"type": "http.response.body", "body": body, "more_body": False})

    def _metric(self, name: str, tags: Mapping[str, Any]) -> None:
        try:
            if self.cfg.metrics_hook:
                self.cfg.metrics_hook(name, tags)
        except Exception as e:
            logger.debug("metrics hook error: %s", e)

    def _headers_passthrough(self) -> Mapping[str, str]:
        return {}  # можно расширить для глобальных заголовков
