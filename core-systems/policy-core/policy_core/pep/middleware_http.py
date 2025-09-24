# -*- coding: utf-8 -*-
"""
Policy Enforcement Point (PEP) ASGI middleware for HTTP.

Industrial features:
- Zero-Trust friendly: deny-by-default fallback, strict attribute extraction.
- ABAC context: subject/action/resource/environment attributes.
- PDP client interface with pluggable implementations (HTTP PDP optional).
- Decision TTL cache with size bound + lazy pruning.
- Obligations support:
  * add_response_headers
  * inject_request_headers (downstream)
  * set_status
  * redact_response_fields (JSON, deep, size-capped)
- Correlation / Request-ID management.
- Structured audit logging (JSON) with reason & rule metadata.
- Path excludes (health/metrics/internal).
- Optional rate limiting (token-bucket) per subject/tenant.
- Optional Prometheus metrics (graceful fallback if not installed).
- No hard external deps. Optional: httpx, prometheus_client.

Integrate with FastAPI/Starlette:
    app.add_middleware(PolicyEnforcementMiddleware, pdp_client=YourPDPClient(), config=PepConfig(...))

Author: Aethernova / NeuroCity policy-core
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import types
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Protocol, Tuple

# Optional imports (graceful fallback)
try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

try:
    from prometheus_client import Counter, Histogram  # type: ignore
except Exception:  # pragma: no cover
    Counter = Histogram = None  # type: ignore

LOGGER = logging.getLogger("policy_core.pep.middleware_http")
LOGGER.setLevel(logging.INFO)

# --------------------------- Config & Models ---------------------------

class Effect(str, Enum):
    PERMIT = "permit"
    DENY = "deny"


@dataclass(frozen=True)
class Decision:
    effect: Effect
    obligations: List[Dict[str, Any]] = field(default_factory=list)
    ttl_seconds: int = 5
    reason: Optional[str] = None
    rule_id: Optional[str] = None


@dataclass(frozen=True)
class RequestContext:
    tenant: str
    subject: Dict[str, Any]
    action: Dict[str, Any]
    resource: Dict[str, Any]
    environment: Dict[str, Any]
    # Raw headers snapshot for audit debugging
    raw_headers: Mapping[str, str]


@dataclass
class PepConfig:
    request_id_header: str = "X-Request-ID"
    correlation_header: str = "X-Correlation-ID"
    subject_header: str = "X-User-Id"
    roles_header: str = "X-Roles"
    tenant_header: str = "X-Tenant"
    forwarded_for_header: str = "X-Forwarded-For"
    auth_header: str = "Authorization"

    cache_ttl_seconds_default: int = 5
    cache_max_entries: int = 5000

    # If PDP is unavailable or throws: "deny" or "permit"
    fallback_on_error: Effect = Effect.DENY

    # Regex patterns to bypass PEP (e.g. health, metrics)
    excluded_path_patterns: List[str] = field(default_factory=lambda: [
        r"^/healthz$",
        r"^/livez$",
        r"^/readyz$",
        r"^/metrics$",
        r"^/docs($|/)",
        r"^/openapi\.json$",
    ])

    # Limit JSON response redaction to avoid large buffering
    redact_max_response_bytes: int = 2 * 1024 * 1024  # 2 MiB

    # Optional built-in subject rate limiting (token bucket) per (tenant, subject_id)
    rate_limit_enabled: bool = False
    rate_limit_capacity: int = 100         # tokens
    rate_limit_refill_per_sec: float = 50  # tokens per second
    rate_limit_on_deny_status: int = 429   # HTTP status code when limited

    # Log configuration
    audit_logs_enabled: bool = True
    log_denies_at_warning: bool = True

    # Metrics (prometheus_client)
    metrics_namespace: str = "policy_core"
    metrics_enabled: bool = True


# --------------------------- PDP Client Protocol ---------------------------

class PDPClient(Protocol):
    async def evaluate(self, ctx: RequestContext) -> Decision:
        ...


class AllowAllPDP:
    """Safe default PDP (permits everything). Do NOT use in production."""
    async def evaluate(self, ctx: RequestContext) -> Decision:  # pragma: no cover
        return Decision(effect=Effect.PERMIT, obligations=[], ttl_seconds=5, reason="allow_all_stub")


class HttpPDPClient:
    """
    Optional HTTP PDP client. Requires httpx.
    Expects PDP API accepting JSON {context} and returning:
    {"effect": "permit"|"deny", "obligations": [...], "ttl_seconds": 5, "reason": "...", "rule_id": "..."}
    """
    def __init__(self, endpoint: str, timeout: float = 0.8, api_key: Optional[str] = None):
        if httpx is None:
            raise RuntimeError("httpx is required for HttpPDPClient but is not installed.")
        self._endpoint = endpoint.rstrip("/")
        self._timeout = timeout
        self._api_key = api_key
        self._client = httpx.AsyncClient(timeout=self._timeout)

    async def evaluate(self, ctx: RequestContext) -> Decision:
        payload = {
            "tenant": ctx.tenant,
            "subject": ctx.subject,
            "action": ctx.action,
            "resource": ctx.resource,
            "environment": ctx.environment,
        }
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        resp = await self._client.post(f"{self._endpoint}/v1/decision", headers=headers, json=payload)
        resp.raise_for_status()
        data = resp.json()
        effect = Effect(data.get("effect", "deny"))
        return Decision(
            effect=effect,
            obligations=list(data.get("obligations", [])),
            ttl_seconds=int(data.get("ttl_seconds", 5)),
            reason=data.get("reason"),
            rule_id=data.get("rule_id"),
        )


# --------------------------- TTL Cache ---------------------------

class _TTLCache:
    """Simple TTL cache with size bound and lazy pruning. Not thread-safe; guarded by asyncio.Lock."""
    def __init__(self, max_entries: int, default_ttl: int):
        self._max = max_entries
        self._default_ttl = default_ttl
        self._store: Dict[Any, Tuple[float, Decision]] = {}
        self._lock = asyncio.Lock()

    def _now(self) -> float:
        return time.monotonic()

    async def get(self, key: Any) -> Optional[Decision]:
        async with self._lock:
            rec = self._store.get(key)
            if not rec:
                return None
            expires_at, decision = rec
            if expires_at <= self._now():
                self._store.pop(key, None)
                return None
            return decision

    async def set(self, key: Any, decision: Decision):
        async with self._lock:
            if len(self._store) >= self._max:
                # Lazy prune: remove expired first, otherwise oldest-ish entries by iteration
                now = self._now()
                expired = [k for k, (exp, _) in self._store.items() if exp <= now]
                for k in expired:
                    self._store.pop(k, None)
                if len(self._store) >= self._max:
                    # Drop arbitrary entries to free space
                    for k in list(self._store.keys())[: max(1, self._max // 50)]:
                        self._store.pop(k, None)
            ttl = decision.ttl_seconds or self._default_ttl
            self._store[key] = (self._now() + ttl, decision)

    async def clear(self):  # pragma: no cover
        async with self._lock:
            self._store.clear()


# --------------------------- Token Bucket Rate Limiter ---------------------------

class _TokenBucket:
    __slots__ = ("capacity", "refill_per_sec", "tokens", "last")

    def __init__(self, capacity: int, refill_per_sec: float):
        self.capacity = capacity
        self.refill_per_sec = refill_per_sec
        self.tokens = float(capacity)
        self.last = time.monotonic()

    def allow(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        delta = now - self.last
        self.last = now
        self.tokens = min(self.capacity, self.tokens + delta * self.refill_per_sec)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


class _RateLimiter:
    def __init__(self, capacity: int, refill_per_sec: float):
        self._capacity = capacity
        self._refill = refill_per_sec
        self._buckets: Dict[Tuple[str, str], _TokenBucket] = {}
        self._lock = asyncio.Lock()

    async def allow(self, tenant: str, subject_id: str) -> bool:
        key = (tenant, subject_id)
        async with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = self._buckets[key] = _TokenBucket(self._capacity, self._refill)
            return bucket.allow()


# --------------------------- Metrics (optional) ---------------------------

class _Metrics:
    def __init__(self, ns: str, enabled: bool):
        self.enabled = enabled and (Counter is not None and Histogram is not None)
        if self.enabled:
            self.decisions = Counter(f"{ns}_decisions_total", "PEP decisions", ["effect"])
            self.denies = Counter(f"{ns}_denies_total", "PEP denies", ["reason"])
            self.requests = Counter(f"{ns}_requests_total", "HTTP requests seen")
            self.latency = Histogram(f"{ns}_decision_latency_seconds", "PDP decision latency (sec)")
        else:
            self.decisions = self.denies = self.requests = self.latency = None

    def inc_requests(self):
        if self.enabled:
            self.requests.inc()

    def obs_latency(self, seconds: float):
        if self.enabled:
            self.latency.observe(seconds)

    def inc_decision(self, effect: Effect):
        if self.enabled:
            self.decisions.labels(effect=effect.value).inc()

    def inc_deny(self, reason: str):
        if self.enabled:
            self.denies.labels(reason=reason or "unspecified").inc()


# --------------------------- Utilities ---------------------------

def _headers_to_map(scope_headers: Iterable[Tuple[bytes, bytes]]) -> Dict[str, str]:
    m: Dict[str, str] = {}
    for k, v in scope_headers:
        m[k.decode("latin1").title()] = v.decode("latin1")
    return m


def _gen_request_id() -> str:
    return str(uuid.uuid4())


def _normalize_path(path: str) -> str:
    # Basic normalization, can be replaced with a router-aware normalizer
    return re.sub(r"//+", "/", path.rstrip("/") or "/")


def _match_any(patterns: List[re.Pattern], path: str) -> bool:
    for p in patterns:
        if p.search(path):
            return True
    return False


def _redact_json_fields(obj: Any, fields: Iterable[str], mask: str = "***") -> Any:
    """Recursively redact values for keys in 'fields'."""
    field_set = set(fields)
    if isinstance(obj, dict):
        return {k: (mask if k in field_set else _redact_json_fields(v, field_set, mask)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_json_fields(v, field_set, mask) for v in obj]
    return obj


# --------------------------- Middleware ---------------------------

class PolicyEnforcementMiddleware:
    def __init__(self, app: Callable, pdp_client: PDPClient, config: Optional[PepConfig] = None):
        self.app = app
        self.pdp = pdp_client
        self.cfg = config or PepConfig()
        self.cache = _TTLCache(self.cfg.cache_max_entries, self.cfg.cache_ttl_seconds_default)
        self.excluded_patterns = [re.compile(p) for p in self.cfg.excluded_path_patterns]
        self.metrics = _Metrics(self.cfg.metrics_namespace, self.cfg.metrics_enabled)
        self.rate_limiter = _RateLimiter(self.cfg.rate_limit_capacity, self.cfg.rate_limit_refill_per_sec) \
            if self.cfg.rate_limit_enabled else None

    async def __call__(self, scope: Dict[str, Any], receive: Callable, send: Callable):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        start_ts = time.monotonic()
        self.metrics.inc_requests()

        path = _normalize_path(scope.get("path", "/"))
        method = scope.get("method", "GET").upper()
        raw_headers = _headers_to_map(scope.get("headers") or [])
        client = scope.get("client") or ("", 0)
        client_ip = str(client[0]) if isinstance(client, (list, tuple)) and client else ""

        if _match_any(self.excluded_patterns, path):
            return await self._pass_through_with_request_id(raw_headers, send, receive, scope)

        # Correlation / Request-ID
        req_id = raw_headers.get(self.cfg.request_id_header, _gen_request_id())
        corr_id = raw_headers.get(self.cfg.correlation_header, req_id)

        # Extract attributes
        tenant = raw_headers.get(self.cfg.tenant_header) or raw_headers.get("Host") or "default"
        subject_id = raw_headers.get(self.cfg.subject_header) or "anonymous"
        roles = [r.strip() for r in (raw_headers.get(self.cfg.roles_header) or "").split(",") if r.strip()]
        authz = raw_headers.get(self.cfg.auth_header, "")

        xff = raw_headers.get(self.cfg.forwarded_for_header, "")
        ip = (xff.split(",")[0].strip() if xff else client_ip) or client_ip

        # Action / Resource / Environment
        ctx = RequestContext(
            tenant=tenant,
            subject={"id": subject_id, "roles": roles, "authz": bool(authz)},
            action={"method": method},
            resource={"path": path},
            environment={
                "ip": ip,
                "scheme": scope.get("scheme", "http"),
                "ua": raw_headers.get("User-Agent", ""),
                "proto": scope.get("http_version", ""),
                "request_id": req_id,
                "correlation_id": corr_id,
            },
            raw_headers=raw_headers,
        )

        # Built-in subject rate limiting (optional)
        if self.rate_limiter is not None:
            allowed = await self.rate_limiter.allow(tenant=tenant, subject_id=subject_id)
            if not allowed:
                await self._respond_limited(send, req_id, corr_id)
                self.metrics.inc_deny("rate_limited")
                return

        cache_key = (tenant, subject_id, tuple(sorted(roles)), method, path)
        decision = await self.cache.get(cache_key)
        from_cache = decision is not None
        if decision is None:
            try:
                decision = await self.pdp.evaluate(ctx)
            except Exception as e:
                decision = Decision(effect=self.cfg.fallback_on_error, obligations=[], ttl_seconds=1,
                                    reason=f"pdp_error:{type(e).__name__}")
        await self.cache.set(cache_key, decision)

        self.metrics.inc_decision(decision.effect)
        self.metrics.obs_latency(time.monotonic() - start_ts)

        # Audit log
        if self.cfg.audit_logs_enabled:
            log_data = {
                "type": "pep_decision",
                "effect": decision.effect.value,
                "from_cache": from_cache,
                "tenant": tenant,
                "subject_id": subject_id,
                "roles": roles,
                "method": method,
                "path": path,
                "reason": decision.reason,
                "rule_id": decision.rule_id,
                "request_id": req_id,
                "correlation_id": corr_id,
                "client_ip": ip,
            }
            if decision.effect is Effect.DENY and self.cfg.log_denies_at_warning:
                LOGGER.warning(json.dumps(log_data, ensure_ascii=False))
            else:
                LOGGER.info(json.dumps(log_data, ensure_ascii=False))

        if decision.effect is Effect.DENY:
            self.metrics.inc_deny(decision.reason or "denied")
            await self._respond_denied(send, req_id, corr_id, reason=decision.reason, rule_id=decision.rule_id)
            return

        # Apply obligations and pass downstream
        inject_req_headers = self._collect_inject_request_headers(decision.obligations)
        add_resp_headers = self._collect_add_response_headers(decision.obligations)
        set_status = self._collect_set_status(decision.obligations)
        redact_fields = self._collect_redact_fields(decision.obligations)

        # Wrap send to inject response headers and optionally redact JSON body
        async def send_wrapper(message: Dict[str, Any]):
            if message["type"] == "http.response.start":
                headers: List[Tuple[bytes, bytes]] = message.get("headers", [])
                headers = self._ensure_header(headers, self.cfg.request_id_header, req_id)
                headers = self._ensure_header(headers, self.cfg.correlation_header, corr_id)
                for k, v in add_resp_headers.items():
                    headers = self._ensure_header(headers, k, v, replace=True)
                if set_status is not None:
                    message["status"] = int(set_status)
                message["headers"] = headers
                return await send(message)

            if message["type"] == "http.response.body" and redact_fields:
                # Only attempt to redact if content-type is json and body is reasonable size
                # We need to have seen response.start to read headers; we cannot from here, so we rely on explicit obligation
                body = message.get("body", b"") or b""
                more = message.get("more_body", False)

                # Buffer only if single-chunk and within cap
                if (not more) and len(body) <= self.cfg.redact_max_response_bytes:
                    try:
                        text = body.decode("utf-8")
                        data = json.loads(text)
                        redacted = _redact_json_fields(data, redact_fields)
                        out = json.dumps(redacted, ensure_ascii=False).encode("utf-8")
                        message["body"] = out
                    except Exception:
                        # If not JSON or failed, pass through unchanged
                        pass

                return await send(message)

            return await send(message)

        # Inject request headers downstream (via scope modifications)
        if inject_req_headers:
            scope = self._inject_headers_into_scope(scope, inject_req_headers)

        return await self.app(scope, receive, send_wrapper)

    # --------------------- Obligation helpers ---------------------

    @staticmethod
    def _collect_inject_request_headers(obligations: List[Dict[str, Any]]) -> Dict[str, str]:
        """
        Obligation format example:
          {"type":"inject_request_headers","headers":{"X-Policy":"enforced","X-User-Role":"admin"}}
        """
        out: Dict[str, str] = {}
        for o in obligations:
            if o.get("type") == "inject_request_headers":
                hdrs = o.get("headers") or {}
                for k, v in hdrs.items():
                    out[str(k)] = str(v)
        return out

    @staticmethod
    def _collect_add_response_headers(obligations: List[Dict[str, Any]]) -> Dict[str, str]:
        """
        Obligation format example:
          {"type":"add_response_headers","headers":{"Cache-Control":"no-store"}}
        """
        out: Dict[str, str] = {}
        for o in obligations:
            if o.get("type") == "add_response_headers":
                hdrs = o.get("headers") or {}
                for k, v in hdrs.items():
                    out[str(k)] = str(v)
        return out

    @staticmethod
    def _collect_set_status(obligations: List[Dict[str, Any]]) -> Optional[int]:
        """
        Obligation format example:
          {"type":"set_status","status":202}
        """
        for o in obligations:
            if o.get("type") == "set_status":
                st = o.get("status")
                try:
                    return int(st)
                except Exception:
                    return None
        return None

    @staticmethod
    def _collect_redact_fields(obligations: List[Dict[str, Any]]) -> List[str]:
        """
        Obligation format example:
          {"type":"redact_response_fields","fields":["password","ssn","token"]}
        """
        fields: List[str] = []
        for o in obligations:
            if o.get("type") == "redact_response_fields":
                fs = o.get("fields") or []
                for f in fs:
                    f = str(f).strip()
                    if f:
                        fields.append(f)
        return fields

    # --------------------- ASGI / HTTP helpers ---------------------

    async def _pass_through_with_request_id(self, raw_headers: Mapping[str, str], send: Callable, receive: Callable, scope: Dict[str, Any]):
        req_id = raw_headers.get(self.cfg.request_id_header, _gen_request_id())
        corr_id = raw_headers.get(self.cfg.correlation_header, req_id)

        async def send_wrapper(message: Dict[str, Any]):
            if message["type"] == "http.response.start":
                headers: List[Tuple[bytes, bytes]] = message.get("headers", [])
                headers = self._ensure_header(headers, self.cfg.request_id_header, req_id)
                headers = self._ensure_header(headers, self.cfg.correlation_header, corr_id)
                message["headers"] = headers
            await send(message)

        return await self.app(scope, receive, send_wrapper)

    async def _respond_limited(self, send: Callable, req_id: str, corr_id: str):
        body = json.dumps({
            "error": "rate_limited",
            "message": "Too Many Requests",
            "request_id": req_id,
            "correlation_id": corr_id,
        }).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": self.cfg.rate_limit_on_deny_status,
            "headers": [
                (b"content-type", b"application/json; charset=utf-8"),
                (self.cfg.request_id_header.encode("latin1"), req_id.encode("latin1")),
                (self.cfg.correlation_header.encode("latin1"), corr_id.encode("latin1")),
                (b"cache-control", b"no-store"),
            ],
        })
        await send({"type": "http.response.body", "body": body})

    async def _respond_denied(self, send: Callable, req_id: str, corr_id: str, reason: Optional[str], rule_id: Optional[str]):
        body = json.dumps({
            "effect": "deny",
            "reason": reason or "access_denied",
            "rule_id": rule_id,
            "request_id": req_id,
            "correlation_id": corr_id,
        }, ensure_ascii=False).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": 403,
            "headers": [
                (b"content-type", b"application/json; charset=utf-8"),
                (self.cfg.request_id_header.encode("latin1"), req_id.encode("latin1")),
                (self.cfg.correlation_header.encode("latin1"), corr_id.encode("latin1")),
                (b"cache-control", b"no-store"),
            ],
        })
        await send({"type": "http.response.body", "body": body})

    @staticmethod
    def _ensure_header(headers: List[Tuple[bytes, bytes]], key: str, value: str, replace: bool = False) -> List[Tuple[bytes, bytes]]:
        key_b = key.encode("latin1")
        value_b = value.encode("latin1")
        if replace:
            headers = [(k, v) for (k, v) in headers if k.lower() != key_b.lower()]
        # Prevent duplicates
        for k, _ in headers:
            if k.lower() == key_b.lower():
                return headers
        headers.append((key_b, value_b))
        return headers

    @staticmethod
    def _inject_headers_into_scope(scope: Dict[str, Any], hdrs: Mapping[str, str]) -> Dict[str, Any]:
        headers: List[Tuple[bytes, bytes]] = list(scope.get("headers") or [])
        existing = {k.decode("latin1"): i for i, (k, _) in enumerate(headers)}
        for k, v in hdrs.items():
            kb = k.encode("latin1")
            vb = v.encode("latin1")
            # replace if exists
            idx = next((i for i, (kk, _) in enumerate(headers) if kk.lower() == kb.lower()), None)
            if idx is not None:
                headers[idx] = (kb, vb)
            else:
                headers.append((kb, vb))
        scope = dict(scope)
        scope["headers"] = headers
        return scope
