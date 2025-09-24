# -*- coding: utf-8 -*-
"""
Industrial RateLimit middleware for FastAPI/Starlette.

Features
- Distributed token bucket on Redis (atomic via Lua), optional sliding window.
- Per-subject (API key/JWT sub) + per-IP composite keys. Method/Path scoping.
- Shadow mode (observe only), allow/deny lists, emergency kill-switch.
- Proper RateLimit headers (RFC-ish): RateLimit-Limit/Remaining/Reset, Retry-After.
- Local in-memory fallback when Redis is down (best-effort).
- Prometheus-style counters/gauges export hooks.
- Pluggable policy registry (per endpoint/tag).
- Minimal deps: redis>=4.5 (redis.asyncio), starlette.

Environment (defaults in brackets)
  RL_ENABLED=[true] RL_SHADOW=[false]
  RL_REDIS_URL=[redis://localhost:6379/0] RL_REDIS_PREFIX=[rl:]
  RL_DEFAULT_LIMIT=[100]    # tokens per interval
  RL_DEFAULT_INTERVAL=[60]  # seconds
  RL_DEFAULT_BURST=[50]     # extra bucket capacity
  RL_NETWORK_WEIGHT=[1.0]   # weight for IP portion in composite key
  RL_HEADERS=[true] RL_ENFORCE_429=[true]
  RL_ALLOWLIST=[cidr or subject list, comma-separated]
  RL_DENYLIST=[cidr or subject list, comma-separated]
"""

from __future__ import annotations

import ipaddress
import json
import os
import time
import typing as t
from dataclasses import dataclass

from starlette.datastructures import Headers
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

try:
    from redis import asyncio as aioredis
except Exception as _e:  # pragma: no cover
    aioredis = None

# ------------------------- Configuration --------------------------------------

def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.lower() in ("1", "true", "yes", "y", "on")

RL_ENABLED = _env_bool("RL_ENABLED", True)
RL_SHADOW = _env_bool("RL_SHADOW", False)
RL_REDIS_URL = os.getenv("RL_REDIS_URL", "redis://localhost:6379/0")
RL_REDIS_PREFIX = os.getenv("RL_REDIS_PREFIX", "rl:")
RL_DEFAULT_LIMIT = int(os.getenv("RL_DEFAULT_LIMIT", "100"))
RL_DEFAULT_INTERVAL = int(os.getenv("RL_DEFAULT_INTERVAL", "60"))
RL_DEFAULT_BURST = int(os.getenv("RL_DEFAULT_BURST", "50"))
RL_NETWORK_WEIGHT = float(os.getenv("RL_NETWORK_WEIGHT", "1.0"))
RL_HEADERS = _env_bool("RL_HEADERS", True)
RL_ENFORCE_429 = _env_bool("RL_ENFORCE_429", True)

ALLOWLIST = [s.strip() for s in os.getenv("RL_ALLOWLIST", "").split(",") if s.strip()]
DENYLIST = [s.strip() for s in os.getenv("RL_DENYLIST", "").split(",") if s.strip()]

# ------------------------- Policy Model ---------------------------------------

@dataclass(frozen=True)
class RatePolicy:
    limit: int = RL_DEFAULT_LIMIT            # tokens per interval
    interval_s: int = RL_DEFAULT_INTERVAL    # refill interval
    burst: int = RL_DEFAULT_BURST            # extra capacity (bucket size = limit + burst)
    shadow: bool = RL_SHADOW                 # do-not-enforce
    key: str | None = None                   # explicit key pattern override
    sliding: bool = False                    # also track sliding window (experimental)

    @property
    def bucket(self) -> int:
        return max(1, self.limit + max(0, self.burst))

# Registry for route/tag specific policies
POLICIES: dict[str, RatePolicy] = {}

def set_policy(name: str, policy: RatePolicy) -> None:
    POLICIES[name] = policy

def get_policy(name: str | None) -> RatePolicy:
    if name and name in POLICIES:
        return POLICIES[name]
    return RatePolicy()

# ------------------------- Utilities ------------------------------------------

def _client_ip(headers: Headers, client_host: str | None) -> str:
    # Prefer X-Forwarded-For, then X-Real-IP, then client host
    xff = headers.get("x-forwarded-for")
    if xff:
        ip = xff.split(",")[0].strip()
        return ip
    xr = headers.get("x-real-ip")
    if xr:
        return xr.strip()
    return client_host or "0.0.0.0"

def _normalize_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip))
    except Exception:
        return "0.0.0.0"

def _subject_from_request(request: Request) -> str:
    # Prefer API Key, then Bearer sub, then anonymous
    api_key = request.headers.get("x-api-key")
    if api_key:
        return f"api:{api_key[:16]}"
    # Very light JWT parse (without verifying signature) to extract sub/aud safely
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1]
        # Avoid full JWT lib; parse middle part if looks like JWT; best-effort only
        try:
            parts = token.split(".")
            if len(parts) == 3:
                import base64, json as _json
                payload = _json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode("utf-8"))
                sub = payload.get("sub")
                if sub:
                    return f"sub:{str(sub)[:64]}"
        except Exception:
            pass
        return "bearer"
    return "anon"

def _composite_key(subject: str, ip: str, method: str, path: str, policy_name: str | None) -> str:
    # Normalize path to a template-ish form: collapse digits/ids to "*"
    norm_path = []
    for seg in path.split("/"):
        if not seg:
            continue
        if len(seg) > 36 and "-" in seg:
            norm_path.append("*")
        elif seg.isdigit():
            norm_path.append("*")
        else:
            norm_path.append(seg)
    pfx = policy_name or "default"
    return f"{pfx}:{method}:{'/'.join(norm_path)}:{subject}:{ip}"

def _parse_list(items: list[str]) -> tuple[list[ipaddress._BaseNetwork], set[str]]:
    nets: list[ipaddress._BaseNetwork] = []
    subs: set[str] = set()
    for it in items:
        if not it:
            continue
        try:
            nets.append(ipaddress.ip_network(it, strict=False))
        except Exception:
            subs.add(it)
    return nets, subs

ALLOW_NETS, ALLOW_SUBS = _parse_list(ALLOWLIST)
DENY_NETS, DENY_SUBS = _parse_list(DENYLIST)

def _in_list(ip: str, subject: str, nets: list[ipaddress._BaseNetwork], subs: set[str]) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        if any(ip_obj in n for n in nets):
            return True
    except Exception:
        pass
    return subject in subs

# ------------------------- Redis Lua (atomic token bucket) ---------------------

LUA_TOKEN_BUCKET = """
-- KEYS[1] = bucket key
-- ARGV[1] = now_ms
-- ARGV[2] = interval_ms
-- ARGV[3] = limit
-- ARGV[4] = capacity (bucket)
-- Returns: {allowed(0/1), remaining, reset_ms}
local key     = KEYS[1]
local now     = tonumber(ARGV[1])
local int_ms  = tonumber(ARGV[2])
local limit   = tonumber(ARGV[3])
local cap     = tonumber(ARGV[4])

local data = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(data[1])
local ts     = tonumber(data[2])

if tokens == nil then
  tokens = cap
  ts = now
else
  -- Refill
  local elapsed = math.max(0, now - ts)
  if elapsed > 0 then
    local refill = (elapsed / int_ms) * limit
    tokens = math.min(cap, tokens + refill)
    ts = now
  end
end

local allowed = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
end

redis.call('HMSET', key, 'tokens', tokens, 'ts', ts)
-- Keep key while there is capacity to refill; TTL ~ 2 intervals
redis.call('PEXPIRE', key, math.floor(int_ms * 2))

-- Remaining rounded down
local remaining = math.floor(tokens)
-- Reset time until full (approx to next full interval boundary)
local reset_ms = int_ms - ((now - ts) % int_ms)
return { allowed, remaining, reset_ms }
"""

# ------------------------- In-memory fallback ----------------------------------

class _LocalBucket:
    def __init__(self, limit: int, interval_s: int, capacity: int) -> None:
        self.limit = float(limit)
        self.interval = float(interval_s)
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.ts = time.monotonic()

    def take(self) -> tuple[bool, int, int]:
        now = time.monotonic()
        elapsed = max(0.0, now - self.ts)
        if elapsed > 0:
            refill = (elapsed / self.interval) * self.limit
            self.tokens = min(self.capacity, self.tokens + refill)
            self.ts = now
        allowed = self.tokens >= 1.0
        if allowed:
            self.tokens -= 1.0
        remaining = int(self.tokens)
        reset_ms = int((self.interval - (elapsed % self.interval)) * 1000)
        return allowed, remaining, reset_ms

_LOCAL_BUCKETS: dict[str, _LocalBucket] = {}

# ------------------------- Metrics hooks (no-op by default) --------------------

class Metrics:
    def inc(self, name: str, labels: dict[str, str] | None = None, value: float = 1.0) -> None:  # pragma: no cover
        pass
    def observe(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:   # pragma: no cover
        pass

metrics = Metrics()

def attach_metrics(m: Metrics) -> None:
    global metrics
    metrics = m

# ------------------------- Middleware ------------------------------------------

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Starlette/FastAPI middleware.

    Use:
        app.add_middleware(RateLimitMiddleware, policy_name="default")
        # Per-route override:
        set_policy("ingest", RatePolicy(limit=50, interval_s=1, burst=25))
        @app.post("/v1/data/ingest/publish")
        async def handler(...): ...

    Or tag routes and pass policy_name="tag:<name>" (see resolve_policy_name).
    """

    def __init__(self, app, policy_name: str | None = None) -> None:
        super().__init__(app)
        self.policy_name = policy_name
        self._enabled = RL_ENABLED
        self._headers = RL_HEADERS
        self._enforce = RL_ENFORCE_429
        self._shadow_global = RL_SHADOW

        self._redis = None
        if aioredis is not None and self._enabled:
            try:
                self._redis = aioredis.from_url(RL_REDIS_URL, encoding="utf-8", decode_responses=False)
                # Preload script
                self._sha = None
            except Exception:
                self._redis = None
        else:
            self._sha = None

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if not self._enabled:
            return await call_next(request)

        # Allow/deny lists first
        ip = _normalize_ip(_client_ip(request.headers, request.client.host if request.client else None))
        subject = _subject_from_request(request)
        if _in_list(ip, subject, DENY_NETS, DENY_SUBS):
            return JSONResponse({"code": "forbidden", "message": "Access denied by policy"}, status_code=403)
        if _in_list(ip, subject, ALLOW_NETS, ALLOW_SUBS):
            return await call_next(request)

        # Resolve policy
        pname = self.resolve_policy_name(request)
        policy = get_policy(pname)

        # Composite key
        key = policy.key or _composite_key(subject, ip, request.method, request.url.path, pname)
        allowed, remaining, reset_ms, backend = await self._consume(key, policy)

        # Headers
        headers_extra = {}
        if self._headers:
            headers_extra.update({
                "RateLimit-Limit": str(policy.limit),
                "RateLimit-Remaining": str(max(0, remaining)),
                "RateLimit-Reset": str(max(0, int(reset_ms / 1000))),
                "RateLimit-Policy": f"{policy.limit};w={policy.interval_s};burst={policy.burst}",
                "RateLimit-Key": key[-64:],  # tail for observability
                "RateLimit-Backend": backend,
            })

        # Enforcement/shadow
        shadow = policy.shadow or self._shadow_global
        if not allowed and not shadow and self._enforce:
            retry_after = max(1, int(reset_ms / 1000))
            if self._headers:
                headers_extra["Retry-After"] = str(retry_after)
            metrics.inc("ratelimit_block_total", {"policy": pname or "default", "backend": backend})
            return JSONResponse(
                {"code": "rate_limited", "message": "Too Many Requests", "retry_after": retry_after},
                status_code=429,
                headers=headers_extra
            )

        # Pass-through
        response = await call_next(request)
        if headers_extra:
            for k, v in headers_extra.items():
                response.headers[k] = v
        return response

    def resolve_policy_name(self, request: Request) -> str | None:
        # Prefer explicit per-route attribute set by decorator, else middleware default.
        return getattr(request.scope, "rate_policy_name", None) or self.policy_name

    async def _consume(self, key: str, policy: RatePolicy) -> tuple[bool, int, int, str]:
        # Try Redis first
        now_ms = int(time.time() * 1000)
        if self._redis is not None:
            try:
                if not getattr(self, "_sha", None):
                    self._sha = await self._redis.script_load(LUA_TOKEN_BUCKET)
                res = await self._redis.evalsha(
                    self._sha, 1, (RL_REDIS_PREFIX + key).encode("utf-8"),
                    str(now_ms), str(policy.interval_s * 1000), str(policy.limit), str(policy.bucket)
                )
                # Redis returns bulk strings/integers; decode to ints
                allowed = int(res[0]) == 1
                remaining = int(res[1])
                reset_ms = int(res[2])
                return allowed, remaining, reset_ms, "redis"
            except Exception:
                # fall back
                pass

        # Local fallback
        b = _LOCAL_BUCKETS.get(key)
        if b is None:
            b = _LocalBucket(policy.limit, policy.interval_s, policy.bucket)
            _LOCAL_BUCKETS[key] = b
        allowed, remaining, reset_ms = b.take()
        return allowed, remaining, reset_ms, "local"

# ------------------------- Route decorator -------------------------------------

def ratelimit(name: str | None = None) -> t.Callable:
    """
    Decorator to attach policy name to a route function.

        set_policy("ingest", RatePolicy(limit=50, interval_s=1, burst=25))
        @ratelimit("ingest")
        async def publish(...):
            ...
    """
    def wrapper(func: t.Callable) -> t.Callable:
        setattr(func, "_rate_policy_name", name)

        async def asgi_wrapper(request: Request, *args, **kwargs):
            request.scope.rate_policy_name = name
            return await func(request, *args, **kwargs)

        # Keep original attributes when used with FastAPI path functions
        asgi_wrapper.__name__ = getattr(func, "__name__", "wrapped")
        asgi_wrapper.__doc__ = getattr(func, "__doc__", "")
        return asgi_wrapper
    return wrapper

# ------------------------- Example default policies ----------------------------

# Default global policy (can be overridden in app startup)
set_policy("default", RatePolicy(limit=RL_DEFAULT_LIMIT, interval_s=RL_DEFAULT_INTERVAL, burst=RL_DEFAULT_BURST))

# Endpoint-specific examples (uncomment/adapt in your app startup):
# set_policy("ingest", RatePolicy(limit=50, interval_s=1, burst=25))
# set_policy("catalog", RatePolicy(limit=500, interval_s=60, burst=100))
