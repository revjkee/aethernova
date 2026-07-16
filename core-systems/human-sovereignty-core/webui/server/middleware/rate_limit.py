# human-sovereignty-core/webui/server/middleware/rate_limit.py
from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import ipaddress
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Pattern, Tuple

try:
    # Starlette/FastAPI runtime
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
except Exception as e:  # pragma: no cover
    raise RuntimeError("rate_limit.py requires Starlette (or FastAPI which depends on Starlette)") from e


# =========================
# Models
# =========================

@dataclass(frozen=True)
class RateLimitRule:
    """
    Token bucket configuration.

    rate_per_sec: refill rate (tokens per second)
    burst: maximum tokens capacity
    """

    rate_per_sec: float
    burst: int

    def __post_init__(self) -> None:
        if self.rate_per_sec <= 0:
            raise ValueError("rate_per_sec must be > 0")
        if self.burst <= 0:
            raise ValueError("burst must be > 0")


@dataclass(frozen=True)
class RateLimitPolicy:
    """
    rate limiting policy:
    - per_ip_rule: enforced for each client ip
    - per_session_rule: enforced for each session id (if present)
    - route_rules: optional per-path override rules, first match wins
    - exempt_path_prefixes: allowlist prefixes to bypass limits (e.g. /health)
    - trust_proxy_headers: if True, use X-Forwarded-For and X-Real-IP only when request comes from a trusted proxy ip
    - trusted_proxy_cidrs: list of CIDR strings allowed as proxy sources
    - session_cookie_name/session_header_name: where to extract session id
    - session_required: if True, missing session id is treated as anonymous session "none"
    - key_hash_salt: salt for hashing keys to avoid raw IP/session in memory
    - max_keys: upper bound for in-memory store size (best-effort pruning)
    - stale_ttl_seconds: if a key is inactive for this long, it can be purged
    - cleanup_interval_seconds: background cleanup interval (best-effort)
    """

    per_ip_rule: RateLimitRule = dataclasses.field(default_factory=lambda: RateLimitRule(rate_per_sec=5.0, burst=20))
    per_session_rule: RateLimitRule = dataclasses.field(default_factory=lambda: RateLimitRule(rate_per_sec=8.0, burst=30))

    route_rules: Tuple[Tuple[Pattern[str], Optional[RateLimitRule], Optional[RateLimitRule]], ...] = ()
    exempt_path_prefixes: Tuple[str, ...] = ("/health", "/metrics", "/docs", "/openapi.json")

    trust_proxy_headers: bool = True
    trusted_proxy_cidrs: Tuple[str, ...] = ("127.0.0.1/32", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")

    session_cookie_name: str = "session"
    session_header_name: str = "x-session-id"
    session_required: bool = False

    key_hash_salt: str = "human-sovereignty-core"
    max_keys: int = 200_000
    stale_ttl_seconds: int = 60 * 60
    cleanup_interval_seconds: int = 30

    include_headers: bool = True
    deny_status_code: int = 429
    deny_body: Dict[str, Any] = dataclasses.field(
        default_factory=lambda: {
            "error": "rate_limited",
            "message": "Too many requests",
        }
    )

    def __post_init__(self) -> None:
        if self.max_keys <= 0:
            raise ValueError("max_keys must be > 0")
        if self.stale_ttl_seconds <= 0:
            raise ValueError("stale_ttl_seconds must be > 0")
        if self.cleanup_interval_seconds <= 0:
            raise ValueError("cleanup_interval_seconds must be > 0")
        if not self.session_cookie_name:
            raise ValueError("session_cookie_name must be non-empty")
        if not self.session_header_name:
            raise ValueError("session_header_name must be non-empty")


@dataclass
class _Bucket:
    tokens: float
    updated_at: float
    last_seen: float


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    reason: str
    rule_name: str
    limit: int
    remaining: int
    reset_after_seconds: int
    retry_after_seconds: int


# =========================
# Internal helpers
# =========================

def _now() -> float:
    return time.time()


def _clamp_int(x: float) -> int:
    if x < 0:
        return 0
    return int(x)


def _hash_key(salt: str, raw: str) -> str:
    h = hashlib.sha256()
    h.update(salt.encode("utf-8", errors="strict"))
    h.update(b"\x00")
    h.update(raw.encode("utf-8", errors="replace"))
    return h.hexdigest()


def _compile_cidrs(cidrs: Iterable[str]) -> Tuple[ipaddress._BaseNetwork, ...]:
    out: List[ipaddress._BaseNetwork] = []
    for c in cidrs:
        c = (c or "").strip()
        if not c:
            continue
        out.append(ipaddress.ip_network(c, strict=False))
    return tuple(out)


def _ip_in_trusted(ip: str, nets: Tuple[ipaddress._BaseNetwork, ...]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return False
    for n in nets:
        if addr in n:
            return True
    return False


def _parse_forwarded_for(xff: str) -> Optional[str]:
    # X-Forwarded-For: client, proxy1, proxy2 ...
    # take the first non-empty token
    parts = [p.strip() for p in (xff or "").split(",")]
    for p in parts:
        if p:
            return p
    return None


def _get_client_ip(request: Request, trust_proxy_headers: bool, trusted_proxy_nets: Tuple[ipaddress._BaseNetwork, ...]) -> str:
    # direct peer ip
    peer = request.client.host if request.client else ""
    if not trust_proxy_headers:
        return peer or "0.0.0.0"

    # trust proxy headers only if peer is a trusted proxy
    if not peer or not _ip_in_trusted(peer, trusted_proxy_nets):
        return peer or "0.0.0.0"

    xri = request.headers.get("x-real-ip")
    if xri and xri.strip():
        return xri.strip()

    xff = request.headers.get("x-forwarded-for")
    cand = _parse_forwarded_for(xff or "")
    if cand:
        return cand
    return peer or "0.0.0.0"


def _get_session_id(request: Request, cookie_name: str, header_name: str, session_required: bool) -> Optional[str]:
    sid = request.headers.get(header_name)
    if sid and sid.strip():
        return sid.strip()

    sid = request.cookies.get(cookie_name)
    if sid and sid.strip():
        return sid.strip()

    if session_required:
        return "none"
    return None


def _match_route_rules(
    path: str,
    route_rules: Tuple[Tuple[Pattern[str], Optional[RateLimitRule], Optional[RateLimitRule]], ...],
    default_ip: RateLimitRule,
    default_session: RateLimitRule,
) -> Tuple[RateLimitRule, RateLimitRule, str]:
    for (pat, ip_rule, session_rule) in route_rules:
        if pat.search(path):
            return (ip_rule or default_ip, session_rule or default_session, pat.pattern)
    return (default_ip, default_session, "default")


# =========================
# Store
# =========================

class _InMemoryBucketStore:
    """
    In-memory store with per-key asyncio lock (striped), best-effort bounded size and cleanup.

    Not a distributed limiter. For multi-worker deployments you should place a single
    gateway rate limiter in front, or implement a distributed store.
    """

    def __init__(self, max_keys: int, stale_ttl_seconds: int):
        self._buckets: Dict[str, _Bucket] = {}
        self._max_keys = max_keys
        self._stale_ttl = stale_ttl_seconds

        self._striped_locks: List[asyncio.Lock] = [asyncio.Lock() for _ in range(256)]

    def _lock_for(self, key: str) -> asyncio.Lock:
        idx = int(key[:2], 16) if len(key) >= 2 and re.fullmatch(r"[0-9a-f]{2}", key[:2]) else (hash(key) & 0xFF)
        return self._striped_locks[idx]

    async def get_or_create(self, key: str, initial_tokens: float, now: float) -> _Bucket:
        # Single-key critical section guarded by stripe lock
        lock = self._lock_for(key)
        async with lock:
            b = self._buckets.get(key)
            if b is None:
                b = _Bucket(tokens=initial_tokens, updated_at=now, last_seen=now)
                self._buckets[key] = b
            else:
                b.last_seen = now
            return b

    async def update(self, key: str, bucket: _Bucket) -> None:
        lock = self._lock_for(key)
        async with lock:
            self._buckets[key] = bucket

    async def size(self) -> int:
        return len(self._buckets)

    async def prune(self, now: float) -> int:
        # Best-effort global prune, not fully locked; small race is acceptable for cache eviction
        stale_before = now - float(self._stale_ttl)
        keys = list(self._buckets.keys())
        removed = 0
        for k in keys:
            b = self._buckets.get(k)
            if b is None:
                continue
            if b.last_seen < stale_before:
                # lock stripe for removal
                lock = self._lock_for(k)
                async with lock:
                    b2 = self._buckets.get(k)
                    if b2 is not None and b2.last_seen < stale_before:
                        self._buckets.pop(k, None)
                        removed += 1
        # Best-effort hard cap: if still too large, evict oldest
        if len(self._buckets) > self._max_keys:
            # Evict by last_seen ascending (approximate)
            items = sorted(self._buckets.items(), key=lambda kv: kv[1].last_seen)
            overflow = len(items) - self._max_keys
            for i in range(max(0, overflow)):
                k, _ = items[i]
                lock = self._lock_for(k)
                async with lock:
                    self._buckets.pop(k, None)
                    removed += 1
        return removed


# =========================
# Token bucket algorithm
# =========================

def _consume_token_bucket(bucket: _Bucket, rule: RateLimitRule, now: float) -> Tuple[bool, int, int, int]:
    """
    Returns:
    - allowed
    - remaining (int tokens after consume if allowed; else current tokens int)
    - reset_after_seconds (approx seconds until full burst)
    - retry_after_seconds (seconds until 1 token available)
    """
    elapsed = max(0.0, now - bucket.updated_at)
    refill = elapsed * float(rule.rate_per_sec)
    bucket.tokens = min(float(rule.burst), bucket.tokens + refill)
    bucket.updated_at = now
    bucket.last_seen = now

    if bucket.tokens >= 1.0:
        bucket.tokens -= 1.0
        remaining = int(bucket.tokens)
        # approximate reset: time to fill to burst
        deficit = max(0.0, float(rule.burst) - bucket.tokens)
        reset_after = int(deficit / float(rule.rate_per_sec)) if rule.rate_per_sec > 0 else 0
        return True, remaining, max(0, reset_after), 0

    # not allowed: time until 1 token
    need = 1.0 - bucket.tokens
    retry_after = int((need / float(rule.rate_per_sec)) + 0.999999) if rule.rate_per_sec > 0 else 1
    deficit = float(rule.burst)  # treat as full reset horizon
    reset_after = int(deficit / float(rule.rate_per_sec)) if rule.rate_per_sec > 0 else retry_after
    return False, int(bucket.tokens), max(0, reset_after), max(1, retry_after)


# =========================
# Middleware
# =========================

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    ASGI middleware for per-IP and per-session rate limiting (in-memory).

    Notes:
    - For multi-process deployments this does not provide global correctness.
      Put a gateway limiter in front or replace store with a distributed backend.
    - This middleware is designed to be deterministic and auditable.
    """

    def __init__(self, app: Any, policy: Optional[RateLimitPolicy] = None):
        super().__init__(app)
        self._policy = policy or RateLimitPolicy()
        self._trusted_proxy_nets = _compile_cidrs(self._policy.trusted_proxy_cidrs)
        self._store = _InMemoryBucketStore(
            max_keys=self._policy.max_keys,
            stale_ttl_seconds=self._policy.stale_ttl_seconds,
        )
        self._cleanup_task: Optional[asyncio.Task[Any]] = None
        self._cleanup_started = False
        self._cleanup_lock = asyncio.Lock()

    @property
    def policy(self) -> RateLimitPolicy:
        return self._policy

    async def dispatch(self, request: Request, call_next) -> Response:
        await self._ensure_cleanup_loop()

        path = request.url.path or "/"
        for pref in self._policy.exempt_path_prefixes:
            if pref and path.startswith(pref):
                return await call_next(request)

        ip_rule, session_rule, matched_rule = _match_route_rules(
            path=path,
            route_rules=self._policy.route_rules,
            default_ip=self._policy.per_ip_rule,
            default_session=self._policy.per_session_rule,
        )

        client_ip = _get_client_ip(
            request=request,
            trust_proxy_headers=self._policy.trust_proxy_headers,
            trusted_proxy_nets=self._trusted_proxy_nets,
        )
        session_id = _get_session_id(
            request=request,
            cookie_name=self._policy.session_cookie_name,
            header_name=self._policy.session_header_name,
            session_required=self._policy.session_required,
        )

        now = _now()

        ip_key_raw = f"ip:{client_ip}"
        ip_key = _hash_key(self._policy.key_hash_salt, ip_key_raw)

        # Consume IP bucket
        ip_bucket = await self._store.get_or_create(ip_key, float(ip_rule.burst), now)
        allowed_ip, ip_remaining, ip_reset, ip_retry = _consume_token_bucket(ip_bucket, ip_rule, now)
        await self._store.update(ip_key, ip_bucket)

        # Consume session bucket if present
        allowed_session = True
        s_remaining = session_rule.burst
        s_reset = 0
        s_retry = 0
        s_key = None

        if session_id is not None:
            s_key_raw = f"session:{session_id}"
            s_key = _hash_key(self._policy.key_hash_salt, s_key_raw)
            s_bucket = await self._store.get_or_create(s_key, float(session_rule.burst), now)
            allowed_session, s_remaining, s_reset, s_retry = _consume_token_bucket(s_bucket, session_rule, now)
            await self._store.update(s_key, s_bucket)

        # Decision: deny if either violated
        if not allowed_ip or not allowed_session:
            # choose stricter retry/reset
            retry_after = max(ip_retry, s_retry)
            reset_after = max(ip_reset, s_reset)

            # Build response
            body = dict(self._policy.deny_body)
            body.update(
                {
                    "path": path,
                    "rule": matched_rule,
                    "limited_by": "ip" if not allowed_ip else "session",
                    "retry_after_seconds": retry_after,
                }
            )
            resp = JSONResponse(body, status_code=self._policy.deny_status_code)

            if self._policy.include_headers:
                self._apply_headers(
                    resp,
                    ip_rule=ip_rule,
                    ip_remaining=ip_remaining,
                    ip_reset=ip_reset,
                    session_rule=session_rule if session_id is not None else None,
                    session_remaining=s_remaining if session_id is not None else None,
                    session_reset=s_reset if session_id is not None else None,
                    retry_after=retry_after,
                )
            return resp

        # Allowed path
        resp = await call_next(request)

        if self._policy.include_headers:
            self._apply_headers(
                resp,
                ip_rule=ip_rule,
                ip_remaining=ip_remaining,
                ip_reset=ip_reset,
                session_rule=session_rule if session_id is not None else None,
                session_remaining=s_remaining if session_id is not None else None,
                session_reset=s_reset if session_id is not None else None,
                retry_after=0,
            )
        return resp

    def _apply_headers(
        self,
        resp: Response,
        *,
        ip_rule: RateLimitRule,
        ip_remaining: int,
        ip_reset: int,
        session_rule: Optional[RateLimitRule],
        session_remaining: Optional[int],
        session_reset: Optional[int],
        retry_after: int,
    ) -> None:
        # Standard-ish headers (not claiming RFC compliance)
        # Provide separate namespaces for ip and session to prevent ambiguity.
        resp.headers["RateLimit-IP-Limit"] = str(int(ip_rule.burst))
        resp.headers["RateLimit-IP-Remaining"] = str(max(0, int(ip_remaining)))
        resp.headers["RateLimit-IP-Reset"] = str(max(0, int(ip_reset)))

        if session_rule is not None and session_remaining is not None and session_reset is not None:
            resp.headers["RateLimit-Session-Limit"] = str(int(session_rule.burst))
            resp.headers["RateLimit-Session-Remaining"] = str(max(0, int(session_remaining)))
            resp.headers["RateLimit-Session-Reset"] = str(max(0, int(session_reset)))

        if retry_after and retry_after > 0:
            resp.headers["Retry-After"] = str(int(retry_after))

    async def _ensure_cleanup_loop(self) -> None:
        # Start exactly once, lazily, per process.
        if self._cleanup_started:
            return
        async with self._cleanup_lock:
            if self._cleanup_started:
                return
            self._cleanup_started = True
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def _cleanup_loop(self) -> None:
        # Best-effort loop; exceptions are swallowed to avoid taking down the server.
        interval = float(self._policy.cleanup_interval_seconds)
        while True:
            try:
                await asyncio.sleep(interval)
                await self._store.prune(_now())
            except asyncio.CancelledError:
                return
            except Exception:
                # no logging dependency here by design
                continue


# =========================
# Convenience builder
# =========================

def build_rate_limit_policy(
    *,
    per_ip_rate_per_sec: float = 5.0,
    per_ip_burst: int = 20,
    per_session_rate_per_sec: float = 8.0,
    per_session_burst: int = 30,
    exempt_path_prefixes: Optional[Iterable[str]] = None,
    trusted_proxy_cidrs: Optional[Iterable[str]] = None,
    trust_proxy_headers: bool = True,
    session_cookie_name: str = "session",
    session_header_name: str = "x-session-id",
    session_required: bool = False,
    route_rules: Optional[Iterable[Tuple[str, Optional[RateLimitRule], Optional[RateLimitRule]]]] = None,
) -> RateLimitPolicy:
    rr: List[Tuple[Pattern[str], Optional[RateLimitRule], Optional[RateLimitRule]]] = []
    if route_rules:
        for (pattern, ip_rule, session_rule) in route_rules:
            rr.append((re.compile(pattern), ip_rule, session_rule))

    return RateLimitPolicy(
        per_ip_rule=RateLimitRule(rate_per_sec=per_ip_rate_per_sec, burst=per_ip_burst),
        per_session_rule=RateLimitRule(rate_per_sec=per_session_rate_per_sec, burst=per_session_burst),
        exempt_path_prefixes=tuple(exempt_path_prefixes) if exempt_path_prefixes else RateLimitPolicy().exempt_path_prefixes,
        trusted_proxy_cidrs=tuple(trusted_proxy_cidrs) if trusted_proxy_cidrs else RateLimitPolicy().trusted_proxy_cidrs,
        trust_proxy_headers=bool(trust_proxy_headers),
        session_cookie_name=session_cookie_name,
        session_header_name=session_header_name,
        session_required=bool(session_required),
        route_rules=tuple(rr),
    )
