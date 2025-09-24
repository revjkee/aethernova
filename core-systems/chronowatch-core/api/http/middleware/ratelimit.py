# chronowatch-core/api/http/middleware/ratelimit.py
# -*- coding: utf-8 -*-
"""
ASGI Rate Limiting middleware (industrial-grade) for ChronoWatch.

Features:
- Strategies: TOKEN_BUCKET (refill) and SLIDING_WINDOW (precise window).
- Backends:
    * RedisBackend (redis.asyncio): atomic via Lua; cluster-safe keys; TTL hygiene.
    * MemoryBackend: local fallback, lock-free with asyncio.Lock sharding.
- Flexible rules: by path regex, HTTP methods, identity kinds (ip, user, api_key, tenant), custom cost.
- Standards-compliant headers: RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset (seconds),
  Retry-After (429) per draft-ietf-httpapi-ratelimit-headers.
- Trust-aware client IP derivation: X-Forwarded-For / X-Real-IP with proxy hop limit.
- Monotonic time (time.monotonic_ns) for robustness against wall-clock jumps.
- OTel hooks (optional): counters for allowed/denied; no hard dependency.

Usage (FastAPI / Starlette):
    app.add_middleware(
        RateLimitMiddleware,
        backend=RedisBackend(redis_client, prefix="rl:chrono"),
        rules=[
            RateLimitRule(
                name="public_get",
                limit=100, window=60.0, strategy=Strategy.SLIDING_WINDOW, burst=None,
                match=RuleMatch(path=r"^/api/v1/.*", methods={"GET"}),
                identity=IdentityPolicy(by_ip=True),
            ),
            RateLimitRule(
                name="auth_post",
                limit=30, window=60.0, strategy=Strategy.TOKEN_BUCKET, burst=60,
                match=RuleMatch(path=r"^/api/v1/(submit|write)/.*", methods={"POST"}),
                identity=IdentityPolicy(by_user=True, by_api_key=True),
            ),
        ],
        include_headers=True,
    )

Security note:
- Do NOT trust X-Forwarded-For without a trusted proxy chain. Configure proxy_hops accordingly.
- Keep secrets (API keys) out of logs; hashing is applied for identity parts.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Set, Tuple

try:
    # Optional dependency; redis-py >= 4 provides redis.asyncio
    import redis.asyncio as redis_async  # type: ignore
except Exception:  # pragma: no cover
    redis_async = None  # type: ignore

try:  # Optional OpenTelemetry hooks
    from opentelemetry import metrics as _otel_metrics  # type: ignore
except Exception:  # pragma: no cover
    _otel_metrics = None  # type: ignore

logger = logging.getLogger(__name__)
DEFAULT_LIMIT_HDRS = True


class Strategy(str, Enum):
    TOKEN_BUCKET = "token_bucket"
    SLIDING_WINDOW = "sliding_window"


@dataclass(frozen=True)
class RuleMatch:
    """Route match criteria."""
    path: str = r".*"                             # regex, anchors recommended
    methods: Set[str] = field(default_factory=set)  # e.g., {"GET","POST"}
    exclude_paths: List[str] = field(default_factory=list)  # regexes to skip

    def compile(self) -> "CompiledRuleMatch":
        return CompiledRuleMatch(
            path=re.compile(self.path),
            methods=set(m.upper() for m in self.methods),
            exclude=[re.compile(p) for p in self.exclude_paths],
        )


@dataclass(frozen=True)
class CompiledRuleMatch:
    path: re.Pattern
    methods: Set[str]
    exclude: List[re.Pattern]


@dataclass(frozen=True)
class IdentityPolicy:
    """
    Identity extraction: combine desired dimensions (ip/user/api_key/tenant) into a stable key.
    """
    by_ip: bool = False
    by_user: bool = False
    by_api_key: bool = False
    by_tenant: bool = False
    extra_headers: Tuple[str, ...] = ()  # e.g., ("X-Custom-Scope",)

    # trust chain for X-Forwarded-For
    proxy_hops: int = 1  # how many proxies are trusted; 0 => ignore XFF entirely
    remote_addr_header: Optional[str] = None  # prefer this header for client IP if set

    def identity_key(self, scope: Mapping[str, Any]) -> str:
        parts: List[str] = []
        headers = _headers(scope)

        if self.by_ip:
            ip = _client_ip(headers=headers, scope=scope, proxy_hops=self.proxy_hops, remote_addr_header=self.remote_addr_header)
            parts.append(f"ip:{ip}")

        if self.by_user:
            # Requires authentication middleware populating scope["user"].id or name
            user = None
            try:
                user_obj = scope.get("user")
                if user_obj is not None:
                    user = getattr(user_obj, "id", None) or getattr(user_obj, "username", None) or str(user_obj)
            except Exception:
                user = None
            parts.append(f"user:{user or 'anonymous'}")

        if self.by_api_key:
            api_key = headers.get(b"x-api-key")
            if not api_key:
                # Fallback: Authorization: Bearer/ApiKey <token>
                auth = headers.get(b"authorization")
                if auth:
                    api_key = auth.split()[-1]
            parts.append("api:" + _sha256hex(api_key.decode("utf-8")) if api_key else "api:none")

        if self.by_tenant:
            tenant = headers.get(b"x-tenant-id")
            parts.append("tenant:" + (tenant.decode("utf-8") if tenant else "default"))

        for h in self.extra_headers:
            v = headers.get(h.lower().encode("utf-8"))
            parts.append(h.lower() + ":" + (v.decode("utf-8") if v else "none"))

        if not parts:
            # Fallback to IP to avoid global bucket by mistake
            ip = _client_ip(headers=headers, scope=scope, proxy_hops=self.proxy_hops, remote_addr_header=self.remote_addr_header)
            parts.append(f"ip:{ip}")
        return "|".join(parts)


@dataclass(frozen=True)
class RateLimitRule:
    name: str
    limit: int
    window: float  # seconds
    strategy: Strategy = Strategy.SLIDING_WINDOW
    burst: Optional[int] = None  # token bucket capacity override (>= limit)
    cost: int = 1  # tokens per request
    block_ttl: Optional[float] = None  # optional hard block time after breach
    include_headers: Optional[bool] = None
    match: RuleMatch = field(default_factory=RuleMatch)
    identity: IdentityPolicy = field(default_factory=IdentityPolicy)

    def validate(self) -> None:
        assert self.limit > 0, "limit must be > 0"
        assert self.window > 0.0, "window must be > 0"
        assert self.cost > 0, "cost must be > 0"
        if self.strategy == Strategy.TOKEN_BUCKET:
            if self.burst is not None:
                assert self.burst >= self.limit, "burst must be >= limit"
        _ = self.match.compile()  # compile check


@dataclass
class Decision:
    allowed: bool
    remaining: int
    reset_after: float  # seconds from now until reset
    retry_after: float  # seconds client should wait (for 429); 0 if allowed


class Backend:
    """Abstract rate limit backend."""

    async def check_and_consume(self, key: str, rule: RateLimitRule, now_ns: int) -> Decision:
        raise NotImplementedError

    async def close(self) -> None:  # pragma: no cover
        return None


class MemoryBackend(Backend):
    """
    In-process backend for single-node or fallback. Uses asyncio locks sharded by key hash.
    Sliding window: per-key list of timestamps (ns) pruned by window.
    Token bucket: per-key {tokens, updated_ns}.
    """

    __slots__ = ("_buckets", "_windows", "_locks", "_shards")

    def __init__(self, shards: int = 256) -> None:
        self._buckets: Dict[str, Tuple[float, int]] = {}  # key -> (tokens, updated_ns)
        self._windows: Dict[str, List[int]] = {}          # key -> list[t_ns]
        self._shards = shards
        self._locks = [asyncio.Lock() for _ in range(shards)]

    def _lock(self, key: str) -> asyncio.Lock:
        return self._locks[hash(key) % self._shards]

    async def check_and_consume(self, key: str, rule: RateLimitRule, now_ns: int) -> Decision:
        lock = self._lock(key)
        async with lock:
            if rule.strategy == Strategy.SLIDING_WINDOW:
                return self._check_sliding(key, rule, now_ns)
            else:
                return self._check_bucket(key, rule, now_ns)

    def _check_sliding(self, key: str, rule: RateLimitRule, now_ns: int) -> Decision:
        window_ns = int(rule.window * 1e9)
        arr = self._windows.setdefault(key, [])
        # prune
        cutoff = now_ns - window_ns
        i = 0
        for i in range(len(arr)):
            if arr[i] >= cutoff:
                break
        else:
            i = len(arr)
        if i:
            del arr[:i]
        # check
        used = len(arr)
        remaining = max(0, rule.limit - used)
        if used + rule.cost > rule.limit:
            if arr:
                reset_after = (arr[0] - cutoff) / 1e9  # time until oldest leaves window
            else:
                reset_after = rule.window
            return Decision(False, remaining=0, reset_after=reset_after, retry_after=max(0.001, reset_after))
        # allow
        for _ in range(rule.cost):
            arr.append(now_ns)
        remaining = max(0, rule.limit - len(arr))
        # approximate reset: until first event expires
        reset_after = ((arr[0] - cutoff) / 1e9) if arr else rule.window
        return Decision(True, remaining=remaining, reset_after=reset_after, retry_after=0.0)

    def _check_bucket(self, key: str, rule: RateLimitRule, now_ns: int) -> Decision:
        rate = rule.limit / rule.window  # tokens per second
        cap = rule.burst or rule.limit
        tokens, updated_ns = self._buckets.get(key, (float(cap), now_ns))
        elapsed = max(0.0, (now_ns - updated_ns) / 1e9)
        tokens = min(cap, tokens + elapsed * rate)
        if tokens >= rule.cost:
            tokens -= rule.cost
            self._buckets[key] = (tokens, now_ns)
            remaining = int(tokens)
            # reset after ~ time to refill consumed cost
            reset_after = (cap - tokens) / rate if tokens < cap else 0.0
            return Decision(True, remaining=remaining, reset_after=reset_after, retry_after=0.0)
        # deny
        need = rule.cost - tokens
        retry_after = need / rate
        self._buckets[key] = (tokens, now_ns)
        remaining = 0
        reset_after = retry_after
        return Decision(False, remaining=remaining, reset_after=reset_after, retry_after=max(0.001, retry_after))


class RedisBackend(Backend):
    """
    Redis backend. Requires redis.asyncio client.
    Keys:
      - TOKEN_BUCKET: HSET prefix:tb:{rule}:{id} -> { tokens, updated_ns }, EXPIRE set to ceil(window*burst_factor)
      - SLIDING_WINDOW: ZSET prefix:sw:{rule}:{id} -> timestamps (ns); EXPIRE set to ceil(window*1.5)
    All operations are atomic via Lua.
    """

    LUA_BUCKET = """
    -- KEYS[1]: hash key, ARGV: now_ns, rate, cap, cost, ttl_sec
    local key = KEYS[1]
    local now = tonumber(ARGV[1])
    local rate = tonumber(ARGV[2])
    local cap  = tonumber(ARGV[3])
    local cost = tonumber(ARGV[4])
    local ttl  = tonumber(ARGV[5])

    local h = redis.call('HGETALL', key)
    local tokens = cap
    local updated = now
    if next(h) ~= nil then
      local t = {}
      for i=1,#h,2 do t[h[i]] = h[i+1] end
      tokens = tonumber(t.tokens) or cap
      updated = tonumber(t.updated_ns) or now
    end

    local elapsed = (now - updated) / 1e9
    if elapsed < 0 then elapsed = 0 end
    tokens = math.min(cap, tokens + elapsed * rate)

    if tokens >= cost then
      tokens = tokens - cost
      redis.call('HSET', key, 'tokens', tokens, 'updated_ns', now)
      redis.call('EXPIRE', key, ttl)
      -- allowed, remaining, reset_after, retry_after
      local reset_after = 0
      if tokens < cap then
        reset_after = (cap - tokens) / rate
      end
      return {1, math.floor(tokens), reset_after, 0}
    else
      redis.call('HSET', key, 'tokens', tokens, 'updated_ns', now)
      redis.call('EXPIRE', key, ttl)
      local need = cost - tokens
      local retry_after = need / rate
      return {0, 0, retry_after, retry_after}
    end
    """

    LUA_WINDOW = """
    -- KEYS[1]: zset key, ARGV: now_ns, window_ns, cost, ttl_sec
    local key = KEYS[1]
    local now = tonumber(ARGV[1])
    local win = tonumber(ARGV[2])
    local cost = tonumber(ARGV[3])
    local ttl  = tonumber(ARGV[4])

    local cutoff = now - win
    redis.call('ZREMRANGEBYSCORE', key, 0, cutoff)
    local used = redis.call('ZCARD', key)

    if used + cost > 0x7ffffff0 then
      -- guard against overflow, prune aggressively
      redis.call('ZREMRANGEBYRANK', key, 0, used)
      used = 0
    end

    if used + cost > tonumber(redis.call('GET', key..":limit") or "0") then
      -- When limit not stored, deny path is corrected by caller (we return -1)
      local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
      local reset_after = 1
      if oldest and #oldest >= 2 then
        reset_after = (cutoff - tonumber(oldest[2])) / -1e9
        if reset_after < 0 then reset_after = 0 end
      end
      redis.call('EXPIRE', key, ttl)
      return {0, used, reset_after, reset_after}
    else
      for i = 1, cost do
        redis.call('ZADD', key, now, tostring(now + i))
      end
      redis.call('EXPIRE', key, ttl)
      local new_used = used + cost
      return {1, new_used, win/1e9, 0}
    end
    """

    def __init__(self, client: "redis_async.Redis", prefix: str = "rl:chrono") -> None:
        if redis_async is None:
            raise RuntimeError("redis.asyncio is required for RedisBackend")
        self.client = client
        self.prefix = prefix.rstrip(":")
        self._bucket_sha: Optional[str] = None
        self._window_sha: Optional[str] = None

    async def _load_scripts(self) -> None:
        if self._bucket_sha is None:
            self._bucket_sha = await self.client.script_load(self.LUA_BUCKET)
        if self._window_sha is None:
            self._window_sha = await self.client.script_load(self.LUA_WINDOW)

    async def check_and_consume(self, key: str, rule: RateLimitRule, now_ns: int) -> Decision:
        await self._load_scripts()
        if rule.strategy == Strategy.TOKEN_BUCKET:
            cap = rule.burst or rule.limit
            rate = rule.limit / rule.window
            ttl = int((rule.window * max(1.5, cap / max(1.0, rule.limit))) + 1.0)
            redis_key = f"{self.prefix}:tb:{rule.name}:{key}"
            try:
                res = await self.client.evalsha(
                    self._bucket_sha,  # type: ignore[arg-type]
                    1,
                    redis_key,
                    now_ns,
                    rate,
                    cap,
                    rule.cost,
                    ttl,
                )
            except redis_async.ResponseError:  # type: ignore[attr-defined]
                # fallback eval to handle cache flush
                res = await self.client.eval(self.LUA_BUCKET, 1, redis_key, now_ns, rate, cap, rule.cost, ttl)
            allowed, remaining, reset_after, retry_after = self._decode_res(res)
            return Decision(bool(allowed), int(remaining), float(reset_after), float(retry_after))

        # sliding window
        window_ns = int(rule.window * 1e9)
        ttl = int(rule.window * 1.5 + 1.0)
        redis_key = f"{self.prefix}:sw:{rule.name}:{key}"
        try:
            # store limit alongside (for Lua check); benign if overwritten
            await self.client.setex(redis_key + ":limit", ttl, rule.limit)
            res = await self.client.evalsha(
                self._window_sha,  # type: ignore[arg-type]
                1,
                redis_key,
                now_ns,
                window_ns,
                rule.cost,
                ttl,
            )
        except redis_async.ResponseError:  # type: ignore[attr-defined]
            res = await self.client.eval(self.LUA_WINDOW, 1, redis_key, now_ns, window_ns, rule.cost, ttl)
        allowed, used, reset_after, retry_after = self._decode_res(res)
        remaining = max(0, rule.limit - int(used))
        return Decision(bool(allowed), int(remaining), float(reset_after), float(retry_after))

    @staticmethod
    def _decode_res(res: Any) -> Tuple[int, int, float, float]:
        if isinstance(res, (list, tuple)) and len(res) >= 4:
            a, b, c, d = res[:4]
            return int(a), int(float(b)), float(c), float(d)
        # Defensive default: deny
        return 0, 0, 1.0, 1.0


def _headers(scope: Mapping[str, Any]) -> Dict[bytes, bytes]:
    raw = dict(scope.get("headers") or [])
    # Normalize to last occurrence; ASGI headers are list of (name, value)
    return {k.lower(): v for k, v in raw.items()}


def _client_ip(headers: Mapping[bytes, bytes], scope: Mapping[str, Any], proxy_hops: int, remote_addr_header: Optional[str]) -> str:
    if remote_addr_header:
        v = headers.get(remote_addr_header.lower().encode("utf-8"))
        if v:
            return v.decode("utf-8")
    if proxy_hops > 0:
        xff = headers.get(b"x-forwarded-for")
        if xff:
            # XFF may contain a comma-separated list; take the client IP before trusted proxies
            parts = [p.strip() for p in xff.decode("utf-8").split(",") if p.strip()]
            if len(parts) >= 1:
                # client is the first untrusted hop (list: client, proxy1, proxy2, ...)
                client_index = max(0, len(parts) - 1 - (proxy_hops - 1))
                return parts[client_index]
    # Fallback: peername from ASGI
    client = scope.get("client")
    if isinstance(client, (list, tuple)) and client:
        return str(client[0])
    return "unknown"


def _sha256hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


RateLimitKeyFunc = Callable[[Mapping[str, Any], str, RateLimitRule], str]


def default_key_func(scope: Mapping[str, Any], route_id: str, rule: RateLimitRule) -> str:
    """Build stable key: route_id + identity."""
    ident = rule.identity.identity_key(scope)
    return f"{route_id}|{ident}"


class RateLimitMiddleware:
    """
    ASGI middleware applying ordered rules. First-match wins by default; if multiple rules match and combine=True,
    all must allow (AND).
    """

    def __init__(
        self,
        app: Callable[..., Awaitable[Any]],
        backend: Backend,
        rules: Sequence[RateLimitRule],
        *,
        include_headers: bool = DEFAULT_LIMIT_HDRS,
        key_func: RateLimitKeyFunc = default_key_func,
        combine_matches: bool = False,
        deny_message: Optional[str] = None,
        expose_headers: bool = True,
    ) -> None:
        self.app = app
        self.backend = backend
        self.key_func = key_func
        self.rules = list(rules)
        for r in self.rules:
            r.validate()
        # Precompile matches
        self._compiled: List[Tuple[RateLimitRule, CompiledRuleMatch]] = [(r, r.match.compile()) for r in self.rules]
        self.include_headers = include_headers
        self.combine_matches = combine_matches
        self.deny_message = deny_message or "Too Many Requests"
        self.expose_headers = expose_headers
        self._otel = _RateLimitMetrics() if _otel_metrics else None

    async def __call__(self, scope: Mapping[str, Any], receive: Callable, send: Callable) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "/")
        method: str = (scope.get("method") or "GET").upper()

        matched: List[Tuple[RateLimitRule, CompiledRuleMatch]] = []
        for rule, comp in self._compiled:
            if comp.methods and method not in comp.methods:
                continue
            if not comp.path.search(path):
                continue
            if any(p.search(path) for p in comp.exclude):
                continue
            matched.append((rule, comp))
            if not self.combine_matches:
                break

        if not matched:
            await self.app(scope, receive, send)
            return

        # Apply rules
        now_ns = time.monotonic_ns()
        decisions: List[Tuple[RateLimitRule, Decision]] = []
        deny: Optional[Tuple[RateLimitRule, Decision]] = None
        for rule, _ in matched:
            key = self.key_func(scope, route_id=_route_id(path, method, rule), rule=rule)
            dec = await self.backend.check_and_consume(key, rule, now_ns)
            decisions.append((rule, dec))
            if not dec.allowed:
                deny = (rule, dec)
                if not self.combine_matches:
                    break

        if deny:
            rule, dec = deny
            if self._otel:
                self._otel.record(rule.name, allowed=False)
            await self._send_429(send, rule, dec)
            return

        # allowed
        if self._otel:
            for rule, _ in decisions:
                self._otel.record(rule.name, allowed=True)

        # Wrap send to inject headers once (on response start)
        async def send_wrapper(event: Mapping[str, Any]) -> None:
            if event.get("type") == "http.response.start":
                headers = list(event.get("headers") or [])
                # Only first matched rule headers (or aggregate min remaining) — choose conservative
                rule, dec = decisions[0]
                if (rule.include_headers if rule.include_headers is not None else self.include_headers):
                    headers = _merge_headers_with_ratelimit(headers, rule, dec, expose=self.expose_headers)
                event = dict(event)
                event["headers"] = headers
            await send(event)

        await self.app(scope, receive, send_wrapper)

    async def _send_429(self, send: Callable, rule: RateLimitRule, dec: Decision) -> None:
        body = json.dumps(
            {
                "error": "rate_limited",
                "message": self.deny_message,
                "rule": rule.name,
                "retry_after": round(dec.retry_after, 3),
            }
        ).encode("utf-8")

        headers: List[Tuple[bytes, bytes]] = [
            (b"content-type", b"application/json; charset=utf-8"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"retry-after", str(max(1, int(dec.retry_after)) ).encode("ascii")),
        ]
        if (rule.include_headers if rule.include_headers is not None else self.include_headers):
            headers = _merge_headers_with_ratelimit(headers, rule, dec, expose=self.expose_headers)

        await send(
            {
                "type": "http.response.start",
                "status": 429,
                "headers": headers,
            }
        )
        await send({"type": "http.response.body", "body": body, "more_body": False})


def _merge_headers_with_ratelimit(
    headers: List[Tuple[bytes, bytes]],
    rule: RateLimitRule,
    dec: Decision,
    *,
    expose: bool,
) -> List[Tuple[bytes, bytes]]:
    # RateLimit headers (draft-ietf-httpapi-ratelimit-headers)
    # RateLimit-Limit: <limit>;w=<window>
    # RateLimit-Remaining: <remaining>
    # RateLimit-Reset: <delta-seconds>
    hdrs = list(headers)
    hdrs.append((b"ratelimit-limit", f"{rule.limit};w={int(rule.window)}".encode("ascii")))
    hdrs.append((b"ratelimit-remaining", str(max(0, dec.remaining)).encode("ascii")))
    hdrs.append((b"ratelimit-reset", str(max(0, int(round(dec.reset_after)))).encode("ascii")))
    if expose:
        # Allow clients to see the headers in browsers (CORS)
        # Merge with existing Access-Control-Expose-Headers if present
        existing = None
        for i, (k, v) in enumerate(hdrs):
            if k.lower() == b"access-control-expose-headers":
                existing = (i, v)
                break
        expose_list = b"RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset, Retry-After"
        if existing is None:
            hdrs.append((b"access-control-expose-headers", expose_list))
        else:
            i, v = existing
            merged = b", ".join([v, expose_list]) if v else expose_list
            hdrs[i] = (b"access-control-expose-headers", merged)
    return hdrs


def _route_id(path: str, method: str, rule: RateLimitRule) -> str:
    # Stable per-rule route id: coarse by path regex + method
    base = f"{method}:{rule.match.path}"
    return _sha256hex(base)[:16]


class _RateLimitMetrics:
    """Minimal OTel metrics hooks."""

    def __init__(self) -> None:
        meter = _otel_metrics.get_meter(__name__)  # type: ignore
        self._allowed = meter.create_counter("chronowatch_ratelimit_allowed", unit="1", description="Allowed requests by rule")  # type: ignore
        self._denied = meter.create_counter("chronowatch_ratelimit_denied", unit="1", description="Denied requests by rule")  # type: ignore

    def record(self, rule_name: str, allowed: bool) -> None:
        attrs = {"rule": rule_name}
        if allowed:
            self._allowed.add(1, attributes=attrs)  # type: ignore
        else:
            self._denied.add(1, attributes=attrs)  # type: ignore
