# cybersecurity-core/api/http/middleware/ratelimit.py
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections import deque, defaultdict
from dataclasses import dataclass, field
from ipaddress import ip_network, ip_address
from typing import Callable, Deque, Dict, Iterable, List, Optional, Pattern, Tuple, Union, Any

try:
    # Optional dependency; used if redis_url is provided.
    import redis.asyncio as aioredis  # type: ignore
except Exception:  # pragma: no cover
    aioredis = None  # Lazy-checked at runtime

logger = logging.getLogger(__name__)


# --------------------------- Rate limit primitives ---------------------------

@dataclass(frozen=True)
class RateLimit:
    """Single rate-limit policy."""
    capacity: int                  # e.g., 100
    window_seconds: int            # e.g., 60
    name: str = "default"          # policy name for keys/headers
    methods: Optional[Iterable[str]] = None  # set like {"GET","POST"} or None for any
    path_pattern: Optional[Pattern[str]] = None  # compiled regex to match scope["path"]

    def applies(self, method: str, path: str) -> bool:
        if self.methods:
            if method.upper() not in {m.upper() for m in self.methods} and "*" not in {m.upper() for m in self.methods}:
                return False
        if self.path_pattern and not self.path_pattern.search(path):
            return False
        return True

    @property
    def policy_header(self) -> str:
        # RFC-like RateLimit-Policy item: "<limit>;w=<window>"
        return f"{self.capacity};w={self.window_seconds}"


_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhd])\s*$", re.IGNORECASE)


def _parse_window(s: str) -> int:
    m = _DURATION_RE.match(s)
    if not m:
        raise ValueError(f"Invalid window spec: {s!r}")
    value = int(m.group(1))
    unit = m.group(2).lower()
    if unit == "s":
        return value
    if unit == "m":
        return value * 60
    if unit == "h":
        return value * 3600
    if unit == "d":
        return value * 86400
    raise ValueError(f"Invalid duration unit: {unit}")


def parse_limit(spec: str, *, name: str = "default", methods: Optional[Iterable[str]] = None,
                path_pattern: Optional[Union[str, Pattern[str]]] = None) -> RateLimit:
    """
    Parse "100/1m" into RateLimit(capacity=100, window_seconds=60).
    """
    try:
        count_s, window_s = spec.split("/", 1)
        capacity = int(count_s.strip())
        window_seconds = _parse_window(window_s.strip())
    except Exception as e:
        raise ValueError(f"Invalid rate spec {spec!r}: {e}") from e

    compiled = re.compile(path_pattern) if isinstance(path_pattern, str) else path_pattern
    return RateLimit(capacity=capacity, window_seconds=window_seconds, name=name, methods=methods, path_pattern=compiled)


@dataclass
class RateDecision:
    allowed: bool
    remaining: int
    reset_seconds: int
    limit: RateLimit


# ------------------------------ Backends -------------------------------------

class BaseLimiterBackend:
    async def hit(self, key: str, limit: RateLimit, *, cost: int = 1, now: Optional[float] = None) -> RateDecision:
        raise NotImplementedError


class InMemoryLimiter(BaseLimiterBackend):
    """
    Sliding window in memory using per-key deques of event timestamps (seconds).
    Suitable for single-process dev/tests, not for multi-instance deployments.
    """
    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._buckets: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)
        self._locks: Dict[Tuple[str, str], asyncio.Lock] = defaultdict(asyncio.Lock)
        self._clock = clock

    async def hit(self, key: str, limit: RateLimit, *, cost: int = 1, now: Optional[float] = None) -> RateDecision:
        now = self._clock() if now is None else now
        bucket_key = (key, limit.name)
        lock = self._locks[bucket_key]
        async with lock:
            dq = self._buckets[bucket_key]
            window_start = now - limit.window_seconds
            # Evict old entries
            while dq and dq[0] <= window_start:
                dq.popleft()
            current = len(dq)
            if current + cost > limit.capacity:
                remaining = max(0, limit.capacity - current)
                # Compute reset: when earliest event exits the window
                reset = int(max(1, (dq[0] + limit.window_seconds) - now)) if dq else limit.window_seconds
                return RateDecision(False, remaining, reset, limit)
            # Allow: append cost entries
            for _ in range(cost):
                dq.append(now)
            remaining = limit.capacity - (current + cost)
            reset = int(max(1, limit.window_seconds - (now - (dq[0] if dq else now))))
            return RateDecision(True, remaining, reset, limit)


class RedisLimiter(BaseLimiterBackend):
    """
    Sliding window using Redis ZSET with atomic Lua script.
    Keys expire after window; accurate remaining and reset.
    """
    LUA_SCRIPT = """
    -- KEYS[1] = zset key
    -- ARGV[1] = now (ms)
    -- ARGV[2] = window (ms)
    -- ARGV[3] = capacity
    -- ARGV[4] = cost
    local key = KEYS[1]
    local now_ms = tonumber(ARGV[1])
    local window_ms = tonumber(ARGV[2])
    local capacity = tonumber(ARGV[3])
    local cost = tonumber(ARGV[4])

    -- remove events before window
    redis.call('ZREMRANGEBYSCORE', key, 0, now_ms - window_ms)
    local current = redis.call('ZCARD', key)
    local allowed = 0
    local remaining = capacity - current
    if current + cost <= capacity then
        allowed = 1
        -- add cost entries with the same timestamp but unique members
        for i=1,cost do
            redis.call('ZADD', key, now_ms, string.format("%d:%d", now_ms, i))
        end
        remaining = capacity - (current + cost)
    end
    -- ensure TTL roughly equals the window
    redis.call('PEXPIRE', key, window_ms)
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local reset_ms = window_ms
    if oldest and #oldest >= 2 then
        local oldest_score = tonumber(oldest[2])
        reset_ms = math.max(1, (oldest_score + window_ms) - now_ms)
    end
    return {allowed, remaining, reset_ms}
    """

    def __init__(self, client: Any) -> None:
        self._redis = client
        self._sha: Optional[str] = None

    async def _ensure_script(self) -> None:
        if self._sha is None:
            try:
                self._sha = await self._redis.script_load(self.LUA_SCRIPT)
            except Exception:
                # eval fallback if script_load not allowed
                self._sha = ""

    async def hit(self, key: str, limit: RateLimit, *, cost: int = 1, now: Optional[float] = None) -> RateDecision:
        await self._ensure_script()
        now_ms = int((time.time() if now is None else now) * 1000.0)
        window_ms = int(limit.window_seconds * 1000)
        args = [now_ms, window_ms, limit.capacity, cost]
        try:
            if self._sha:
                allowed, remaining, reset_ms = await self._redis.evalsha(self._sha, 1, key, *args)
            else:
                allowed, remaining, reset_ms = await self._redis.eval(self.LUA_SCRIPT, 1, key, *args)
        except Exception as e:
            logger.exception("Redis rate-limit eval failed, failing open: %s", e)
            # Fail-open to not DOS legitimate traffic on infra issues
            return RateDecision(True, limit.capacity, limit.window_seconds, limit)
        return RateDecision(bool(allowed), int(remaining), max(1, int(reset_ms / 1000)), limit)


# ------------------------------ Configuration --------------------------------

IdentifierFn = Callable[[Dict[str, Any], Dict[str, str]], str]
LimitsFn = Callable[[Dict[str, Any], Dict[str, str]], Iterable[RateLimit]]


@dataclass
class RateLimiterConfig:
    enabled: bool = True
    key_prefix: str = "rl"
    default_limits: List[RateLimit] = field(default_factory=lambda: [parse_limit("100/1m")])
    identifier: Optional[IdentifierFn] = None
    limits_for_request: Optional[LimitsFn] = None
    redis_url: Optional[str] = None
    include_headers: bool = True
    whitelist_cidrs: List[str] = field(default_factory=list)  # e.g., ["10.0.0.0/8", "192.168.0.0/16"]
    exclude_path_patterns: List[Pattern[str]] = field(default_factory=lambda: [re.compile(r"^/healthz$")])

    def compile(self) -> "RateLimiterConfig":
        # Normalize CIDRs to ip_network objects stored as strings for speed
        return self


# ------------------------------ Utilities ------------------------------------

def _get_client_ip(scope: Dict[str, Any], headers: Dict[str, str]) -> Optional[str]:
    # X-Forwarded-For: client, proxy1, proxy2
    xff = headers.get("x-forwarded-for")
    if xff:
        first = xff.split(",")[0].strip()
        if first:
            return first
    xri = headers.get("x-real-ip")
    if xri:
        return xri.strip()
    client = scope.get("client")
    if isinstance(client, (list, tuple)) and client:
        return client[0]
    return None


def _identifier_default(scope: Dict[str, Any], headers: Dict[str, str]) -> str:
    # Prefer explicit identity headers if present
    for hdr in ("x-api-key", "x-client-id"):
        v = headers.get(hdr)
        if v:
            return v
    # Framework user object (if any)
    user = scope.get("user")
    if user is not None:
        # Common patterns across auth middlewares
        for attr in ("id", "sub", "user_id", "uuid"):
            if hasattr(user, attr):
                return str(getattr(user, attr))
        if hasattr(user, "is_authenticated") and getattr(user, "is_authenticated"):  # type: ignore[attr-defined]
            return "user"
    ip = _get_client_ip(scope, headers) or "unknown"
    return ip


def _headers_to_dict(scope: Dict[str, Any]) -> Dict[str, str]:
    raw = scope.get("headers") or []
    out: Dict[str, str] = {}
    for k, v in raw:
        try:
            out[k.decode("latin1").lower()] = v.decode("latin1")
        except Exception:
            # Best-effort
            out[str(k).lower()] = str(v)
    return out


def _path(scope: Dict[str, Any]) -> str:
    return scope.get("path", "/")


def _method(scope: Dict[str, Any]) -> str:
    return scope.get("method", "GET").upper()


def _cidr_list_to_networks(cidrs: Iterable[str]) -> List[Any]:
    nets = []
    for c in cidrs:
        try:
            nets.append(ip_network(c, strict=False))
        except Exception as e:
            logger.warning("Invalid CIDR in whitelist ignored: %r (%s)", c, e)
    return nets


# ------------------------------ Middleware -----------------------------------

class RateLimitMiddleware:
    """
    ASGI middleware implementing request rate limiting with Redis or in-memory backend.
    Compatible with FastAPI/Starlette/Any ASGI app.

    Usage (FastAPI):
        app.add_middleware(RateLimitMiddleware, config=RateLimiterConfig(
            redis_url="redis://localhost:6379/0",
            default_limits=[parse_limit("300/1m"), parse_limit("10/1s", name="burst", methods={"POST"})],
            whitelist_cidrs=["10.0.0.0/8", "127.0.0.0/8"],
        ))
    """
    def __init__(self, app, config: RateLimiterConfig) -> None:
        self.app = app
        self.cfg = config.compile()
        self._identifier = self.cfg.identifier or _identifier_default
        self._limits_for_request = self.cfg.limits_for_request
        self._whitelist_networks = _cidr_list_to_networks(self.cfg.whitelist_cidrs)
        self._backend: BaseLimiterBackend = self._init_backend(self.cfg.redis_url)

    def _init_backend(self, redis_url: Optional[str]) -> BaseLimiterBackend:
        if redis_url:
            if aioredis is None:
                raise RuntimeError("redis.asyncio is required for Redis limiter but is not installed")
            client = aioredis.from_url(redis_url, encoding="utf-8", decode_responses=True)
            logger.info("RateLimitMiddleware using Redis backend at %s", redis_url)
            return RedisLimiter(client)
        logger.info("RateLimitMiddleware using InMemory backend")
        return InMemoryLimiter()

    def _is_whitelisted(self, ip: Optional[str]) -> bool:
        if not ip or not self._whitelist_networks:
            return False
        try:
            addr = ip_address(ip)
        except Exception:
            return False
        return any(addr in net for net in self._whitelist_networks)

    def _excluded(self, path: str) -> bool:
        return any(p.search(path) for p in self.cfg.exclude_path_patterns)

    async def __call__(self, scope: Dict[str, Any], receive, send):
        if scope.get("type") != "http" or not self.cfg.enabled:
            return await self.app(scope, receive, send)

        headers = _headers_to_dict(scope)
        path = _path(scope)
        method = _method(scope)
        client_ip = _get_client_ip(scope, headers)

        if self._excluded(path) or self._is_whitelisted(client_ip):
            return await self.app(scope, receive, send)

        limits: Iterable[RateLimit] = (
            self._limits_for_request(scope, headers) if self._limits_for_request else self.cfg.default_limits
        )

        # Filter applicable limits by method/path
        applicable = [lim for lim in limits if lim.applies(method, path)]
        if not applicable:
            return await self.app(scope, receive, send)

        subject = self._identifier(scope, headers)
        base_key = f"{self.cfg.key_prefix}:{subject}"

        # Evaluate all limits; block if any is exceeded
        decisions: List[RateDecision] = []
        for lim in applicable:
            key = f"{base_key}:{lim.name}"
            try:
                decision = await self._backend.hit(key, lim, cost=1)
            except Exception as e:  # Defensive: fail-open to avoid accidental DOS
                logger.exception("Rate-limit backend error on %s: %s (failing open)", key, e)
                decision = RateDecision(True, lim.capacity, lim.window_seconds, lim)
            decisions.append(decision)

        # Choose the tightest decision for headers (smallest remaining; shortest reset on deny)
        tightest = min(decisions, key=lambda d: (d.remaining, d.reset_seconds))

        if any(not d.allowed for d in decisions):
            # Block: craft 429 response with informative headers
            await self._send_429_with_headers(send, tightest, subject, client_ip)
            return

        # Allowed: add rate headers to response
        add_headers = self.cfg.include_headers

        async def send_with_headers(message):
            if add_headers and message.get("type") == "http.response.start":
                headers_list = message.setdefault("headers", [])
                self._inject_headers(headers_list, tightest)
            await send(message)

        return await self.app(scope, receive, send_with_headers)

    @staticmethod
    def _inject_headers(headers_list: List[Tuple[bytes, bytes]], decision: RateDecision) -> None:
        # Standards-friendly RateLimit headers and common X-RateLimit-* for compatibility
        policy = decision.limit.policy_header
        limit_str = str(decision.limit.capacity)
        remaining_str = str(max(0, decision.remaining))
        reset_str = str(max(1, decision.reset_seconds))

        def add(h: str, v: str):
            headers_list.append((h.encode("latin1"), v.encode("latin1")))

        add("ratelimit-policy", policy)
        add("ratelimit-limit", limit_str)
        add("ratelimit-remaining", remaining_str)
        add("ratelimit-reset", reset_str)

        add("x-ratelimit-limit", limit_str)
        add("x-ratelimit-remaining", remaining_str)
        add("x-ratelimit-reset", reset_str)

    async def _send_429_with_headers(self, send, decision: RateDecision, subject: str, client_ip: Optional[str]) -> None:
        headers: List[Tuple[bytes, bytes]] = []
        self._inject_headers(headers, decision)
        # Retry-After in seconds as conservative estimate equals reset
        headers.append((b"retry-after", str(max(1, decision.reset_seconds)).encode("latin1")))
        payload = {
            "detail": "Rate limit exceeded",
            "policy": decision.limit.policy_header,
            "limit": decision.limit.capacity,
            "remaining": max(0, decision.remaining),
            "reset_seconds": max(1, decision.reset_seconds),
        }
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")

        await send({
            "type": "http.response.start",
            "status": 429,
            "headers": headers + [
                (b"content-type", b"application/json; charset=utf-8"),
                (b"content-length", str(len(body)).encode("latin1")),
            ],
        })
        await send({
            "type": "http.response.body",
            "body": body,
            "more_body": False,
        })


# --------------------------- Convenience factory -----------------------------

def make_limits(specs: Iterable[Union[str, RateLimit]]) -> List[RateLimit]:
    out: List[RateLimit] = []
    for i, s in enumerate(specs):
        if isinstance(s, RateLimit):
            out.append(s)
        else:
            out.append(parse_limit(str(s), name=f"limit{i+1}"))
    return out


__all__ = [
    "RateLimitMiddleware",
    "RateLimiterConfig",
    "RateLimit",
    "parse_limit",
    "make_limits",
]
