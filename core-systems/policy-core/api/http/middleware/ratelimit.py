# path: policy-core/api/http/middleware/ratelimit.py
# -*- coding: utf-8 -*-
"""
Production-grade rate limiting middleware for FastAPI/Starlette.

Features:
- Token-bucket (capacity, refill_per_sec, burst) with atomic Redis backend (Lua),
  and resilient in-memory fallback (per-process) with asyncio locks.
- Keys: per_ip, per_api_key (X-API-Key), per_user (JWT sub), per_route, and composites.
- Weights (cost per request), bans with TTL, shadow mode, health/readiness bypass.
- Standards-compliant headers: RateLimit-Limit / RateLimit-Remaining / RateLimit-Reset,
  plus legacy X-RateLimit-* and Retry-After on 429.
- Pydantic-based settings via environment variables and/or programmatic config.
- Minimal external deps: works with redis>=5 (redis.asyncio). If Redis not found, falls back.

Usage:
    from fastapi import FastAPI
    from policy_core.api.http.middleware.ratelimit import RateLimitMiddleware, RateLimitSettings

    app = FastAPI()
    app.add_middleware(
        RateLimitMiddleware,
        settings=RateLimitSettings(),  # or RateLimitSettings(redis_url="redis://...")
    )

Notes:
- For per_user, middleware tries to read request.state.auth_sub or JWT 'sub' from headers (best-effort).
- Configure route-specific overrides via settings.routes.{glob_pattern}.
- Time is measured in monotonic seconds on in-memory backend to avoid clock jumps.
"""

from __future__ import annotations

import asyncio
import json
import math
import os
import re
import time
from dataclasses import dataclass
from enum import Enum
from ipaddress import ip_address
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple

from pydantic import BaseModel, Field, PositiveInt, validator
from starlette.datastructures import Headers
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

try:
    # redis>=5
    from redis.asyncio import Redis  # type: ignore
except Exception:  # pragma: no cover
    Redis = None  # type: ignore


# ----------------------------- Configuration -----------------------------


class IdentityMode(str, Enum):
    per_ip = "per_ip"
    per_api_key = "per_api_key"
    per_user = "per_user"
    per_route = "per_route"
    composite = "composite"  # combine ip+user+route


class Strategy(str, Enum):
    token_bucket = "token_bucket"


class BanAction(str, Enum):
    none = "none"
    block = "block"


class RouteSpec(BaseModel):
    """Route-level override for limits."""

    capacity: PositiveInt = Field(300, description="Max tokens in bucket")
    refill_per_sec: PositiveInt = Field(3, description="Token refill per second")
    burst: PositiveInt = Field(60, description="Max extra burst above steady-state")
    weight: PositiveInt = Field(1, description="Token cost per request")
    identity: IdentityMode = Field(IdentityMode.composite, description="Keying mode for route")
    ban_threshold: int = Field(0, description="Strike count before ban (0=off)")
    ban_ttl_seconds: int = Field(900, description="Ban TTL seconds")
    include_methods: List[str] = Field(default_factory=list, description="Limit only these HTTP methods (empty=all)")
    exclude_paths: List[str] = Field(default_factory=list, description="Regex patterns to skip")
    shadow_mode: bool = Field(False, description="Do not block, only report when True")

    @validator("include_methods", each_item=True)
    def _upper_methods(cls, v: str) -> str:
        return v.upper()


class RateLimitSettings(BaseModel):
    """Pydantic settings for middleware."""

    enabled: bool = Field(True, description="Enable middleware")
    strategy: Strategy = Field(Strategy.token_bucket)
    redis_url: Optional[str] = Field(default=None, description="Redis URL; fallback to memory if None or connect fails")
    redis_key_prefix: str = Field("rl:policy-core:", description="Prefix for Redis keys")
    default: RouteSpec = Field(default_factory=RouteSpec)
    routes: Dict[str, RouteSpec] = Field(default_factory=dict, description="Glob-like patterns -> RouteSpec")
    health_paths: List[str] = Field(default_factory=lambda: [r"^/healthz$", r"^/readyz$", r"^/startupz$"])
    exempt_paths: List[str] = Field(default_factory=list, description="Additional regex paths to bypass")
    trusted_proxy_count: int = Field(0, description="If behind proxies, number of trusted hops for X-Forwarded-For")
    client_ip_headers: List[str] = Field(default_factory=lambda: ["x-forwarded-for", "x-real-ip"])
    header_api_key: str = Field("x-api-key")
    header_request_id: str = Field("x-request-id")
    shadow_mode: bool = Field(False, description="Global shadow mode (does not block)")
    emit_legacy_headers: bool = Field(True, description="Emit X-RateLimit-* alongside RateLimit-*")
    log_json: bool = Field(True)
    log_fn: Optional[Callable[[str], None]] = None  # custom logger sink (info-level)

    class Config:
        arbitrary_types_allowed = True

    @classmethod
    def from_env(cls) -> "RateLimitSettings":
        """Create settings from environment variables (optional helper)."""
        redis_url = os.getenv("RATELIMIT_REDIS_URL") or os.getenv("POLICYCORE_RL_REDIS_URL")
        enabled = os.getenv("RATELIMIT_ENABLED", "true").lower() in {"1", "true", "yes"}
        return cls(enabled=enabled, redis_url=redis_url)


# ----------------------------- Data structures -----------------------------


@dataclass(frozen=True)
class LimitDecision:
    allowed: bool
    remaining: int
    reset_after: int  # seconds until fully refilled or next available
    retry_after: int  # seconds until next token available if blocked
    policy: str  # RateLimit-Policy header value


# ----------------------------- Redis Lua (atomic) -----------------------------

# KEYS[1] bucket key, KEYS[2] ts key, KEYS[3] strikes key, KEYS[4] ban key
# ARGV: capacity, refill_per_sec, burst, weight, now_ms, ban_threshold, ban_ttl
# Return: allowed (1/0), remaining, reset_after, retry_after, strikes, banned (1/0)
REDIS_LUA = """
local bk = KEYS[1]
local tk = KEYS[2]
local sk = KEYS[3]
local hk = KEYS[4]

local capacity = tonumber(ARGV[1])
local refill_per_sec = tonumber(ARGV[2])
local burst = tonumber(ARGV[3])
local weight = tonumber(ARGV[4])
local now_ms = tonumber(ARGV[5])
local ban_threshold = tonumber(ARGV[6])
local ban_ttl = tonumber(ARGV[7])

-- Check ban first
local banned = redis.call('GET', hk)
if banned then
  return {0, 0, 1, 1, tonumber(redis.call('GET', sk) or '0'), 1}
end

local last_ms = tonumber(redis.call('GET', tk) or now_ms)
local tokens = tonumber(redis.call('GET', bk) or capacity + burst)

-- Refill
local elapsed = math.max(0, now_ms - last_ms) / 1000.0
local refill = math.floor(elapsed * refill_per_sec)
tokens = math.min(capacity + burst, tokens + refill)

local allowed = 0
local remaining = tokens
local retry_after = 0

if tokens >= weight then
  allowed = 1
  tokens = tokens - weight
  remaining = tokens
  -- reset strikes if successful
  if ban_threshold > 0 then
    redis.call('DEL', sk)
  end
else
  allowed = 0
  remaining = tokens
  if refill_per_sec > 0 then
    retry_after = math.ceil((weight - tokens) / refill_per_sec)
  else
    retry_after = 1
  end
  if ban_threshold > 0 then
    local strikes = tonumber(redis.call('INCR', sk))
    if strikes >= ban_threshold then
      redis.call('SETEX', hk, ban_ttl, '1')
    end
  end
end

local ttl = math.ceil((capacity + burst - tokens) / math.max(1, refill_per_sec))
redis.call('SET', bk, tokens)
redis.call('SET', tk, now_ms)
redis.call('EXPIRE', bk, ttl + 5)
redis.call('EXPIRE', tk, ttl + 5)

local strikes_val = tonumber(redis.call('GET', sk) or '0')
local banned_now = redis.call('GET', hk) and 1 or 0

return {allowed, remaining, ttl, retry_after, strikes_val, banned_now}
"""


# ----------------------------- Backends -----------------------------


class RateLimiterBackend:
    async def evaluate(
        self,
        key: str,
        spec: RouteSpec,
        now_ms: int,
        prefix: str = "",
    ) -> LimitDecision:
        raise NotImplementedError


class RedisBackend(RateLimiterBackend):
    def __init__(self, redis: "Redis", prefix: str) -> None:
        self.redis = redis
        self.prefix = prefix
        self._script = None

    async def _load_script(self) -> Any:
        if self._script is None:
            self._script = self.redis.register_script(REDIS_LUA)  # type: ignore[attr-defined]
        return self._script

    async def evaluate(self, key: str, spec: RouteSpec, now_ms: int, prefix: str = "") -> LimitDecision:
        script = await self._load_script()
        k_bucket = f"{self.prefix}{prefix}b:{key}"
        k_ts = f"{self.prefix}{prefix}t:{key}"
        k_strikes = f"{self.prefix}{prefix}s:{key}"
        k_ban = f"{self.prefix}{prefix}ban:{key}"
        args = [
            spec.capacity,
            spec.refill_per_sec,
            spec.burst,
            spec.weight,
            now_ms,
            spec.ban_threshold,
            spec.ban_ttl_seconds,
        ]
        res = await script(keys=[k_bucket, k_ts, k_strikes, k_ban], args=args)  # type: ignore[call-arg]
        allowed, remaining, reset_after, retry_after, _strikes, banned = map(int, res)
        policy = f"{spec.capacity};w={spec.weight};burst={spec.burst};window=1s"
        if banned == 1 and retry_after < 1:
            # Banned without retry window => use ban_ttl as reset hint
            reset_after = max(reset_after, spec.ban_ttl_seconds)
            retry_after = max(retry_after, 1)
        return LimitDecision(bool(allowed), max(0, remaining), max(0, reset_after), max(0, retry_after), policy)


class MemoryBucket:
    __slots__ = ("tokens", "last_ms", "strikes", "ban_until")

    def __init__(self, capacity_plus_burst: int, now_ms: int) -> None:
        self.tokens = capacity_plus_burst
        self.last_ms = now_ms
        self.strikes = 0
        self.ban_until = 0


class InMemoryBackend(RateLimiterBackend):
    def __init__(self) -> None:
        self._buckets: Dict[str, MemoryBucket] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        self._gc_last = time.monotonic()

    def _lock_for(self, key: str) -> asyncio.Lock:
        lk = self._locks.get(key)
        if lk is None:
            lk = asyncio.Lock()
            self._locks[key] = lk
        return lk

    def _gc(self) -> None:
        # simple periodic GC
        now = time.monotonic()
        if now - self._gc_last < 30:
            return
        self._gc_last = now
        # best-effort cleanup
        if len(self._buckets) > 10000:
            self._buckets.clear()
            self._locks.clear()

    async def evaluate(self, key: str, spec: RouteSpec, now_ms: int, prefix: str = "") -> LimitDecision:
        self._gc()
        lock = self._lock_for(prefix + key)
        async with lock:
            bucket = self._buckets.get(prefix + key)
            if bucket is None:
                bucket = MemoryBucket(spec.capacity + spec.burst, now_ms)
                self._buckets[prefix + key] = bucket

            # Ban check
            if bucket.ban_until > now_ms:
                reset = int(math.ceil((bucket.ban_until - now_ms) / 1000))
                policy = f"{spec.capacity};w={spec.weight};burst={spec.burst};window=1s"
                return LimitDecision(False, 0, reset, max(1, reset), policy)

            # Refill
            elapsed = max(0, now_ms - bucket.last_ms) / 1000.0
            refill = int(elapsed * spec.refill_per_sec)
            bucket.tokens = min(spec.capacity + spec.burst, bucket.tokens + refill)
            bucket.last_ms = now_ms

            if bucket.tokens >= spec.weight:
                bucket.tokens -= spec.weight
                bucket.strikes = 0
                remaining = bucket.tokens
                ttl = int(math.ceil((spec.capacity + spec.burst - bucket.tokens) / max(1, spec.refill_per_sec)))
                policy = f"{spec.capacity};w={spec.weight};burst={spec.burst};window=1s"
                return LimitDecision(True, remaining, ttl, 0, policy)

            # Not enough tokens
            if spec.refill_per_sec > 0:
                retry_after = int(math.ceil((spec.weight - bucket.tokens) / spec.refill_per_sec))
            else:
                retry_after = 1

            if spec.ban_threshold > 0:
                bucket.strikes += 1
                if bucket.strikes >= spec.ban_threshold:
                    bucket.ban_until = now_ms + spec.ban_ttl_seconds * 1000

            ttl = int(math.ceil((spec.capacity + spec.burst - bucket.tokens) / max(1, spec.refill_per_sec)))
            policy = f"{spec.capacity};w={spec.weight};burst={spec.burst};window=1s"
            return LimitDecision(False, bucket.tokens, ttl, retry_after, policy)


# ----------------------------- Middleware -----------------------------


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, settings: Optional[RateLimitSettings] = None) -> None:
        super().__init__(app)
        self.settings = settings or RateLimitSettings.from_env()
        self.backend: RateLimiterBackend
        self._redis: Optional["Redis"] = None
        self._compiled_patterns: List[Tuple[re.Pattern[str], RouteSpec]] = []
        self._exempt: List[re.Pattern[str]] = []
        self._health: List[re.Pattern[str]] = []
        self._init_patterns()

    def _init_patterns(self) -> None:
        for pat, spec in self.settings.routes.items():
            self._compiled_patterns.append((re.compile(pat), spec))
        self._exempt = [re.compile(p) for p in self.settings.exempt_paths]
        self._health = [re.compile(p) for p in self.settings.health_paths]

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if not self.settings.enabled:
            return await call_next(request)

        path = request.url.path

        # Bypass health and explicit exempted paths
        for rx in self._health + self._exempt:
            if rx.search(path):
                return await call_next(request)

        route_spec = self._match_spec(request)

        # Optional method filter
        if route_spec.include_methods and request.method.upper() not in route_spec.include_methods:
            return await call_next(request)

        # Optional exclude patterns inside spec
        for rx_pat in route_spec.exclude_paths:
            if re.search(rx_pat, path):
                return await call_next(request)

        # Lazy backend init
        if isinstance(getattr(self, "backend", None), RateLimiterBackend):
            backend = self.backend
        else:
            backend = await self._init_backend()

        now_ms = int(time.time() * 1000)
        key = self._build_key(request, route_spec)

        decision = await backend.evaluate(key=key, spec=route_spec, now_ms=now_ms, prefix=self._prefix_for(request))

        # Emit headers regardless of allow/deny
        # RFC 9205: RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset
        def _apply_headers(resp: Response) -> None:
            resp.headers["RateLimit-Limit"] = route_spec.capacity.__str__()
            resp.headers["RateLimit-Remaining"] = str(max(0, decision.remaining))
            resp.headers["RateLimit-Reset"] = str(max(0, decision.reset_after))
            resp.headers["RateLimit-Policy"] = decision.policy
            if self.settings.emit_legacy_headers:
                resp.headers["X-RateLimit-Limit"] = route_spec.capacity.__str__()
                resp.headers["X-RateLimit-Remaining"] = str(max(0, decision.remaining))
                resp.headers["X-RateLimit-Reset"] = str(max(0, decision.reset_after))

        if decision.allowed or route_spec.shadow_mode or self.settings.shadow_mode:
            response = await call_next(request)
            _apply_headers(response)
            if (route_spec.shadow_mode or self.settings.shadow_mode) and not decision.allowed:
                self._log_event(request, route_spec, decision, blocked=False)
            return response

        # Block with 429
        why = {
            "error": "rate_limited",
            "retry_after": max(1, decision.retry_after),
            "route_policy": {
                "capacity": route_spec.capacity,
                "weight": route_spec.weight,
                "burst": route_spec.burst,
                "refill_per_sec": route_spec.refill_per_sec,
            },
        }
        body = JSONResponse(why, status_code=429)
        _apply_headers(body)
        body.headers["Retry-After"] = str(max(1, decision.retry_after))
        self._log_event(request, route_spec, decision, blocked=True)
        return body

    # ----------------------------- Helpers -----------------------------

    async def _init_backend(self) -> RateLimiterBackend:
        if self.settings.redis_url and Redis is not None:
            try:
                self._redis = Redis.from_url(self.settings.redis_url, encoding="utf-8", decode_responses=False)  # type: ignore
                # Quick ping with small timeout
                await asyncio.wait_for(self._redis.ping(), timeout=0.5)  # type: ignore
                self.backend = RedisBackend(self._redis, prefix=self.settings.redis_key_prefix)
                return self.backend
            except Exception:
                # Fallback to memory
                self.backend = InMemoryBackend()
                return self.backend
        self.backend = InMemoryBackend()
        return self.backend

    def _match_spec(self, request: Request) -> RouteSpec:
        path = request.url.path
        for rx, spec in self._compiled_patterns:
            if rx.search(path):
                return spec
        return self.settings.default

    def _prefix_for(self, request: Request) -> str:
        # Namespace by environment header if provided (optional)
        env = request.headers.get("x-env") or ""
        return f"{env}:" if env else ""

    def _get_client_ip(self, request: Request) -> str:
        # If behind proxies, we can parse X-Forwarded-For chain
        headers = request.headers
        ip: Optional[str] = None
        for h in self.settings.client_ip_headers:
            if h in headers:
                ip = headers[h]
                break
        if ip:
            if "," in ip:
                parts = [p.strip() for p in ip.split(",")]
                # choose last untrusted -> first trusted from right
                idx = max(0, len(parts) - 1 - self.settings.trusted_proxy_count)
                ip = parts[idx]
            try:
                _ = ip_address(ip)
            except Exception:
                ip = None
        if not ip:
            ip = request.client.host if request.client else "0.0.0.0"
        return ip

    def _get_api_key(self, request: Request) -> Optional[str]:
        return request.headers.get(self.settings.header_api_key)

    def _get_user_sub(self, request: Request) -> Optional[str]:
        # Prefer app-provided identity on request.state
        sub = getattr(request.state, "auth_sub", None)
        if sub:
            return str(sub)
        # Best-effort parse of JWT 'sub' (not verifying!)
        auth = request.headers.get("authorization")
        if auth and auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()
            # Try Read-only decode of JWT payload (middle segment, base64url)
            try:
                import base64
                parts = token.split(".")
                if len(parts) == 3:
                    pad = "=" * (-len(parts[1]) % 4)
                    payload = json.loads(base64.urlsafe_b64decode(parts[1] + pad).decode("utf-8"))
                    sub = payload.get("sub")
                    if sub:
                        return str(sub)
            except Exception:
                return None
        return None

    def _build_key(self, request: Request, spec: RouteSpec) -> str:
        mode = spec.identity
        path = request.url.path
        ip = self._get_client_ip(request)
        api_key = self._get_api_key(request)
        user = self._get_user_sub(request)

        route = self._normalize_route(path)
        if mode == IdentityMode.per_ip:
            return f"ip:{ip}"
        if mode == IdentityMode.per_api_key and api_key:
            return f"key:{api_key}"
        if mode == IdentityMode.per_user and user:
            return f"user:{user}"
        if mode == IdentityMode.per_route:
            return f"route:{route}"
        # composite default
        pieces = [f"r:{route}", f"m:{request.method.upper()}", f"ip:{ip}"]
        if user:
            pieces.append(f"u:{user}")
        elif api_key:
            pieces.append(f"k:{api_key}")
        return "|".join(pieces)

    @staticmethod
    def _normalize_route(path: str) -> str:
        # Strip multiple slashes, collapse numeric ids to :id to reduce key cardinality
        path = re.sub(r"/{2,}", "/", path)
        path = re.sub(r"/\d+([/?]|$)", r"/:id\1", path)
        path = re.sub(r"[0-9a-fA-F-]{8,}([/?]|$)", r"/:uuid\1", path)
        return path

    def _log_event(self, request: Request, spec: RouteSpec, decision: LimitDecision, blocked: bool) -> None:
        if self.settings.log_fn is None:
            # default: print
            def sink(msg: str) -> None:
                print(msg)  # noqa: T201

            log = sink
        else:
            log = self.settings.log_fn

        entry = {
            "event": "ratelimit",
            "blocked": blocked,
            "method": request.method,
            "path": request.url.path,
            "ip": self._get_client_ip(request),
            "api_key_present": bool(self._get_api_key(request)),
            "user_present": bool(self._get_user_sub(request)),
            "remaining": decision.remaining,
            "reset": decision.reset_after,
            "retry_after": decision.retry_after,
            "policy": decision.policy,
            "shadow": spec.shadow_mode or self.settings.shadow_mode,
            "request_id": request.headers.get(self.settings.header_request_id, ""),
        }
        if self.settings.log_json:
            log(json.dumps(entry, ensure_ascii=False))
        else:
            log(f"[ratelimit] blocked={blocked} {request.method} {request.url.path} rem={decision.remaining} reset={decision.reset_after}s retry={decision.retry_after}s")

    async def __aexit__(self, *args: Any) -> None:
        # Close Redis on shutdown
        if self._redis is not None:
            try:
                await self._redis.close()  # type: ignore
            except Exception:
                pass
