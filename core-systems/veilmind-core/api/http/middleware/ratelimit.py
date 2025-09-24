# SPDX-License-Identifier: MIT
"""
Industrial Rate Limiting middleware for ASGI (FastAPI/Starlette).
Features:
- Sliding Window limiting (distributed via Redis, accurate to ms)
- In-memory fallback (per-process) with pruning
- Route/method/tenant/user/ip-aware policies with regex selectors
- Cost-based hits (each request may consume >1 unit)
- Standard headers: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, Retry-After
- Optional Prometheus metrics (if 'prometheus_client' present)
- Optional OpenTelemetry spans (if 'opentelemetry' present)
- Privacy: descriptor key is hashed before exposure

Deploy:
    from ratelimit import RateLimitMiddleware, RateLimitPolicy, RedisSlidingWindowLimiter

    app.add_middleware(
        RateLimitMiddleware,
        policies=[
            RateLimitPolicy(
                id="default-1m",
                method=".*",
                path_regex=r"^/api/.*",
                limit=1000,
                window_seconds=60.0,
                cost=1,
                key_template="{tenant}:{user}:{ip}:{route}"
            ),
            RateLimitPolicy(
                id="auth-tight",
                method="POST",
                path_regex=r"^/api/auth/.*",
                limit=200,
                window_seconds=60.0,
                cost=1,
                key_template="{tenant}:{ip}:{route}"
            ),
        ],
        backend=RedisSlidingWindowLimiter(redis_url="redis://localhost:6379/0"),
        trust_proxy=True,
        exempt_roles={"admin"},  # optional
    )
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Deque, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple

try:
    # Optional Redis backend
    import redis.asyncio as redis  # type: ignore
except Exception:  # pragma: no cover
    redis = None  # type: ignore

try:
    # Optional Prometheus metrics
    from prometheus_client import Counter, Histogram  # type: ignore

    _PROMETHEUS = True
except Exception:  # pragma: no cover
    _PROMETHEUS = False

try:
    # Optional OpenTelemetry tracing
    from opentelemetry import trace  # type: ignore

    _OTEL = True
    _tracer = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _OTEL = False
    _tracer = None  # type: ignore


logger = logging.getLogger("veilmind.ratelimit")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


# =============================== Data Models ==================================


@dataclass(frozen=True)
class RateLimitPolicy:
    """Policy selection rule and parameters."""
    id: str
    path_regex: str
    method: str = ".*"  # regex
    limit: int = 1000
    window_seconds: float = 60.0
    cost: int = 1
    key_template: str = "{tenant}:{user}:{ip}:{route}"
    include_query: bool = False

    _path_pattern: re.Pattern = field(init=False, repr=False)
    _method_pattern: re.Pattern = field(init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_path_pattern", re.compile(self.path_regex))
        object.__setattr__(self, "_method_pattern", re.compile(self.method, flags=re.IGNORECASE))

    def matches(self, method: str, path: str) -> bool:
        return bool(self._method_pattern.match(method)) and bool(self._path_pattern.match(path))


@dataclass
class RateLimitResult:
    allowed: bool
    code: str  # "OK" | "OVER_LIMIT" | "NEAR_LIMIT"
    policy_id: str
    limit: int
    remaining: int
    reset_epoch_s: float
    descriptor_hash: str


# ============================== Helper functions ==============================


def _now_ms() -> int:
    return int(time.time() * 1000)


def _hash_descriptor(descriptor: str) -> str:
    return hashlib.sha256(descriptor.encode("utf-8")).hexdigest()


def _client_ip_from_headers(headers: Mapping[bytes, bytes], trust_proxy: bool) -> str:
    if trust_proxy:
        xff = headers.get(b"x-forwarded-for")
        if xff:
            # first IP
            return xff.decode().split(",")[0].strip()
        real = headers.get(b"x-real-ip")
        if real:
            return real.decode().strip()
    return ""


def default_descriptor_extractor(
    scope: Mapping[str, Any],
    headers: Mapping[bytes, bytes],
    policy: RateLimitPolicy,
    *,
    trust_proxy: bool = True,
) -> Tuple[str, Dict[str, str]]:
    """
    Build the key from method/path/user/tenant/ip.
    Returns (key, attrs_dict_for_hash)
    """
    method: str = scope.get("method", "GET")
    raw_path: str = scope.get("raw_path") or scope.get("path", "/")  # raw_path may be bytes
    if isinstance(raw_path, (bytes, bytearray)):
        path = raw_path.decode("latin-1")
    else:
        path = raw_path

    route = path if policy.include_query else path.split("?", 1)[0]

    # Tenant and user are read from headers if present (non-sensitive examples)
    tenant = headers.get(b"x-tenant-id", b"public").decode()
    user = headers.get(b"x-user-id", b"anonymous").decode()

    ip = _client_ip_from_headers(headers, trust_proxy) or (
        ".".join(map(str, scope.get("client", ("", ""))[0:1])) if scope.get("client") else ""
    )

    key = policy.key_template.format(
        tenant=tenant or "public",
        user=user or "anonymous",
        ip=ip or "0.0.0.0",
        route=route,
        method=method.upper(),
    )
    return key, {"tenant": tenant, "user": user, "ip": ip, "route": route, "method": method}


# ================================ Backends ====================================


class AbstractSlidingWindowLimiter:
    async def should_rate_limit(self, key: str, limit: int, window_s: float, hits: int = 1) -> Tuple[bool, int, float]:
        """
        Returns (allowed, remaining, reset_epoch_s)
        """
        raise NotImplementedError()


class RedisSlidingWindowLimiter(AbstractSlidingWindowLimiter):
    """
    Redis-based sliding window using ZSET:
      - ZREM old entries older than window
      - ZADD 'hits' unique members at current ms
      - EXPIRE at window
      - ZCARD to count
      - ZRANGE to find earliest for reset
    Complexity ~ O(hits + log N). Accurate and horizontally scalable.
    """

    def __init__(self, redis_url: str, *, namespace: str = "veilmind:rl", client: Optional["redis.Redis"] = None):
        if redis is None:
            raise RuntimeError("redis.asyncio is not available; install 'redis>=4.2' or use InMemorySlidingWindowLimiter")
        self._ns = namespace.rstrip(":")
        self._own_client = client is None
        self._r = client or redis.from_url(redis_url, encoding="utf-8", decode_responses=False)

    def _k(self, key: str) -> str:
        return f"{self._ns}:{key}"

    async def close(self) -> None:
        if self._own_client:
            await self._r.close()

    async def should_rate_limit(self, key: str, limit: int, window_s: float, hits: int = 1) -> Tuple[bool, int, float]:
        now = _now_ms()
        zkey = self._k(key)
        min_score = now - int(window_s * 1000)

        pipe = self._r.pipeline(transaction=True)
        pipe.zremrangebyscore(zkey, 0, min_score)
        # add 'hits' with unique members
        for i in range(max(1, hits)):
            member = f"{now}-{i}-{os.getpid()}"
            pipe.zadd(zkey, {member: now})
        pipe.expire(zkey, int(window_s))
        pipe.zcard(zkey)
        results = await pipe.execute()

        count = int(results[-1])
        allowed = count <= int(limit)
        remaining = max(0, int(limit) - count)

        # Fetch earliest for reset
        try:
            earliest = await self._r.zrange(zkey, 0, 0, withscores=True)
            if earliest:
                earliest_ts_ms = int(earliest[0][1])
                reset_epoch_s = (earliest_ts_ms / 1000.0) + float(window_s)
            else:
                reset_epoch_s = time.time() + float(window_s)
        except Exception:
            # fallback if race
            reset_epoch_s = time.time() + float(window_s)
        return allowed, remaining, reset_epoch_s


class InMemorySlidingWindowLimiter(AbstractSlidingWindowLimiter):
    """
    Per-process sliding window (for tests or single-instance deployments).
    Not suitable for multi-instance without sticky sessions.
    """
    def __init__(self) -> None:
        self._buckets: Dict[str, Deque[int]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def should_rate_limit(self, key: str, limit: int, window_s: float, hits: int = 1) -> Tuple[bool, int, float]:
        now = _now_ms()
        cutoff = now - int(window_s * 1000)
        async with self._lock:
            dq = self._buckets[key]
            # prune outdated
            while dq and dq[0] <= cutoff:
                dq.popleft()
            # add hits
            for _ in range(max(1, hits)):
                dq.append(now)
            count = len(dq)
            allowed = count <= limit
            remaining = max(0, limit - count)
            # earliest for reset
            if dq:
                earliest = dq[0]
                reset_epoch_s = (earliest / 1000.0) + float(window_s)
            else:
                reset_epoch_s = time.time() + float(window_s)
        return allowed, remaining, reset_epoch_s


# ================================ Middleware ==================================


@dataclass
class RateLimitMiddlewareConfig:
    policies: List[RateLimitPolicy]
    backend: AbstractSlidingWindowLimiter
    trust_proxy: bool = True
    exempt_roles: Iterable[str] = field(default_factory=set)
    add_headers: bool = True
    reject_status: int = 429
    reject_body: bytes = b"Too Many Requests"
    near_limit_threshold: float = 0.9  # 90% => code=NEAR_LIMIT


class RateLimitMiddleware:
    """
    ASGI middleware implementing sliding-window rate limiting with policy selection.

    Identity and descriptor extraction:
      - tenant: X-Tenant-Id header (default 'public')
      - user:   X-User-Id header   (default 'anonymous')
      - ip:     X-Forwarded-For / X-Real-Ip (if trust_proxy) else client addr
      - route:  path (query stripped by default)
    """

    def __init__(
        self,
        app: Any,
        *,
        policies: List[RateLimitPolicy],
        backend: AbstractSlidingWindowLimiter,
        trust_proxy: bool = True,
        exempt_roles: Iterable[str] = (),
        add_headers: bool = True,
        reject_status: int = 429,
        reject_body: bytes = b"Too Many Requests",
        near_limit_threshold: float = 0.9,
        descriptor_extractor: Callable[
            [Mapping[str, Any], Mapping[bytes, bytes], RateLimitPolicy],
            Tuple[str, Dict[str, str]]
        ] = None,
    ) -> None:
        self.app = app
        self.cfg = RateLimitMiddlewareConfig(
            policies=policies,
            backend=backend,
            trust_proxy=trust_proxy,
            exempt_roles=set(exempt_roles),
            add_headers=add_headers,
            reject_status=reject_status,
            reject_body=reject_body,
            near_limit_threshold=near_limit_threshold,
        )
        self.extractor = descriptor_extractor or (lambda scope, headers, policy: default_descriptor_extractor(
            scope, headers, policy, trust_proxy=trust_proxy
        ))

        # Metrics
        if _PROMETHEUS:
            self.m_req = Counter(
                "veilmind_ratelimit_requests_total",
                "Requests processed by rate limiter",
                ["policy", "code"],
            )
            self.h_decision = Histogram(
                "veilmind_ratelimit_decision_seconds",
                "Decision latency of rate limiter",
                buckets=(0.001, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0),
            )
        else:
            self.m_req = None
            self.h_decision = None

    # ------------------------------ ASGI entry --------------------------------

    async def __call__(self, scope: Mapping[str, Any], receive: Callable, send: Callable) -> Any:
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        headers = self._get_headers(scope)
        method: str = scope.get("method", "GET").upper()
        path = self._get_path(scope)

        # Exempt by role if provided
        if self._is_exempt(headers):
            return await self.app(scope, receive, send)

        policy = self._select_policy(method, path)
        if not policy:
            return await self.app(scope, receive, send)

        key, attrs = self.extractor(scope, headers, policy)
        descriptor_hash = _hash_descriptor(json.dumps(attrs, sort_keys=True))

        # Decision
        t0 = time.perf_counter()
        allowed, remaining, reset_epoch_s = await self.cfg.backend.should_rate_limit(
            key=key, limit=policy.limit, window_s=policy.window_seconds, hits=max(1, policy.cost)
        )
        dt = time.perf_counter() - t0

        # code for observability
        usage = (policy.limit - remaining) / max(1.0, float(policy.limit))
        code = "OK"
        if not allowed:
            code = "OVER_LIMIT"
        elif usage >= self.cfg.near_limit_threshold:
            code = "NEAR_LIMIT"

        result = RateLimitResult(
            allowed=allowed,
            code=code,
            policy_id=policy.id,
            limit=policy.limit,
            remaining=max(0, remaining),
            reset_epoch_s=float(reset_epoch_s),
            descriptor_hash=descriptor_hash,
        )

        if _PROMETHEUS:
            self.m_req.labels(policy=policy.id, code=code).inc()
            self.h_decision.observe(dt)

        if _OTEL and _tracer:
            with _tracer.start_as_current_span("RateLimit.Check") as span:
                span.set_attribute("veilmind.ratelimit.policy", policy.id)
                span.set_attribute("veilmind.ratelimit.code", code)
                span.set_attribute("veilmind.ratelimit.limit", policy.limit)
                span.set_attribute("veilmind.ratelimit.remaining", result.remaining)
                span.set_attribute("veilmind.ratelimit.reset_epoch_s", result.reset_epoch_s)

        # Reject if over limit
        if not result.allowed:
            if self.cfg.add_headers:
                await self._send_429_with_headers(send, result)
                return
            else:
                await self._send_429(send)
                return

        # Otherwise, continue and inject headers on response start
        async def send_wrapper(message: Mapping[str, Any]) -> Any:
            if self.cfg.add_headers and message.get("type") == "http.response.start":
                hdrs: List[Tuple[bytes, bytes]] = list(message.get("headers", []))
                self._inject_headers(hdrs, result)
                message = dict(message)
                message["headers"] = hdrs
            return await send(message)

        return await self.app(scope, receive, send_wrapper)

    # ------------------------------ Internals ---------------------------------

    def _select_policy(self, method: str, path: str) -> Optional[RateLimitPolicy]:
        for p in self.cfg.policies:
            if p.matches(method, path):
                return p
        return None

    def _is_exempt(self, headers: Mapping[bytes, bytes]) -> bool:
        if not self.cfg.exempt_roles:
            return False
        roles_raw = headers.get(b"x-roles")
        if not roles_raw:
            return False
        roles = {r.strip().lower() for r in roles_raw.decode().split(",")}
        return bool(self.cfg.exempt_roles.intersection(roles))

    def _inject_headers(self, headers: List[Tuple[bytes, bytes]], result: RateLimitResult) -> None:
        # RFC-ish headers, widely used by API gateways
        headers.append((b"x-ratelimit-limit", str(result.limit).encode()))
        headers.append((b"x-ratelimit-remaining", str(result.remaining).encode()))
        headers.append((b"x-ratelimit-reset", str(int(result.reset_epoch_s)).encode()))
        headers.append((b"x-ratelimit-policy", result.policy_id.encode()))
        headers.append((b"x-ratelimit-descriptor", result.descriptor_hash.encode()))
        if result.code == "NEAR_LIMIT":
            headers.append((b"x-ratelimit-near-limit", b"1"))

    async def _send_429_with_headers(self, send: Callable, result: RateLimitResult) -> None:
        retry_after = max(1, int(result.reset_epoch_s - time.time()))
        headers = [
            (b"content-type", b"text/plain; charset=utf-8"),
            (b"retry-after", str(retry_after).encode()),
        ]
        self._inject_headers(headers, result)
        await send(
            {
                "type": "http.response.start",
                "status": self.cfg.reject_status,
                "headers": headers,
            }
        )
        await send({"type": "http.response.body", "body": self.cfg.reject_body})

    async def _send_429(self, send: Callable) -> None:
        await send({"type": "http.response.start", "status": self.cfg.reject_status, "headers": []})
        await send({"type": "http.response.body", "body": self.cfg.reject_body})

    def _get_headers(self, scope: Mapping[str, Any]) -> Mapping[bytes, bytes]:
        raw = scope.get("headers") or []
        return {k.lower(): v for (k, v) in raw}

    def _get_path(self, scope: Mapping[str, Any]) -> str:
        raw_path = scope.get("raw_path") or scope.get("path", "/")
        if isinstance(raw_path, (bytes, bytearray)):
            return raw_path.decode("latin-1")
        return raw_path


# ============================== Factory helpers ===============================


def build_default_middleware(
    app: Any,
    *,
    redis_url: Optional[str] = None,
    trust_proxy: bool = True,
) -> RateLimitMiddleware:
    """
    Convenience factory: uses sane defaults based on env vars.
    """
    limit = int(os.getenv("RL_LIMIT", "1000"))
    window = float(os.getenv("RL_WINDOW_SECONDS", "60"))
    auth_limit = int(os.getenv("RL_AUTH_LIMIT", "200"))
    exempt_roles = set(filter(None, os.getenv("RL_EXEMPT_ROLES", "").lower().split(",")))

    policies = [
        RateLimitPolicy(
            id="default-1m",
            method=".*",
            path_regex=r"^/api/.*",
            limit=limit,
            window_seconds=window,
            cost=1,
            key_template="{tenant}:{user}:{ip}:{route}",
        ),
        RateLimitPolicy(
            id="auth-tight",
            method="POST",
            path_regex=r"^/api/auth/.*",
            limit=auth_limit,
            window_seconds=60.0,
            cost=1,
            key_template="{tenant}:{ip}:{route}",
        ),
    ]

    if redis_url and redis is not None:
        backend = RedisSlidingWindowLimiter(redis_url)
    else:
        backend = InMemorySlidingWindowLimiter()

    return RateLimitMiddleware(
        app,
        policies=policies,
        backend=backend,
        trust_proxy=trust_proxy,
        exempt_roles=exempt_roles,
    )


__all__ = [
    "RateLimitMiddleware",
    "RateLimitPolicy",
    "RateLimitMiddlewareConfig",
    "AbstractSlidingWindowLimiter",
    "RedisSlidingWindowLimiter",
    "InMemorySlidingWindowLimiter",
    "build_default_middleware",
]
