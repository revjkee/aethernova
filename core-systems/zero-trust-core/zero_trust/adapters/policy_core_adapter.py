# path: zero-trust-core/zero_trust/adapters/policy_core_adapter.py
# -*- coding: utf-8 -*-
"""
Policy Core Adapter for Zero-Trust architectures.

Features:
- Asynchronous, default-deny enforcement
- ABAC/RBAC-ready decision schema (Subject/Action/Resource/Environment)
- TTL cache with bounded size
- Token-bucket rate limiter
- Circuit breaker for backend protection
- Structured audit logging with secret redaction
- Optional OpenTelemetry spans (if installed)
- Optional HMAC-SHA256 signature verification for policy bundles/payloads
- Multi-tenant support (tenant_id-aware)
- Two backends:
    * LocalRulesBackend: in-process, deterministic rule evaluation
    * OPAHttpBackend: REST integration with OPA /v1/data/<package>/allow

No hard external deps (uses stdlib). OpenTelemetry is optional.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import hmac
import hashlib
from dataclasses import dataclass, field
from typing import (
    Any,
    Dict,
    Mapping,
    MutableMapping,
    Optional,
    Tuple,
    Callable,
    List,
    Literal,
)

# Optional OpenTelemetry
try:
    from opentelemetry import trace  # type: ignore
    _OTEL_AVAILABLE = True
    _TRACER = trace.get_tracer(__name__)
except Exception:  # pragma: no cover - best effort
    _OTEL_AVAILABLE = False
    _TRACER = None  # type: ignore


# -----------------------------------------------------------------------------
# Logging setup (caller can reconfigure root logger as needed)
# -----------------------------------------------------------------------------
LOG = logging.getLogger("zero_trust.policy_core_adapter")
if not LOG.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    handler.setFormatter(formatter)
    LOG.addHandler(handler)
LOG.setLevel(logging.INFO)


# -----------------------------------------------------------------------------
# Domain models
# -----------------------------------------------------------------------------
Effect = Literal["Permit", "Deny", "Indeterminate"]


@dataclass(frozen=True)
class Subject:
    id: str
    attributes: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Action:
    name: str
    attributes: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Resource:
    id: str
    type: str
    attributes: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Environment:
    ip: Optional[str] = None
    timestamp: Optional[int] = None
    attributes: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyDecisionRequest:
    subject: Subject
    action: Action
    resource: Resource
    environment: Environment = field(default_factory=Environment)
    tenant_id: Optional[str] = None
    correlation_id: Optional[str] = None

    def to_cache_key_material(self) -> Dict[str, Any]:
        """
        Deterministic subset for cache key; excludes volatile fields.
        """
        return {
            "tenant_id": self.tenant_id,
            "subject": {"id": self.subject.id, "attributes": self.subject.attributes},
            "action": {"name": self.action.name, "attributes": self.action.attributes},
            "resource": {
                "id": self.resource.id,
                "type": self.resource.type,
                "attributes": self.resource.attributes,
            },
            "environment": {
                "ip": self.environment.ip,
                # omit timestamp by default (too volatile) to improve cache hit rate
                "attributes": self.environment.attributes,
            },
        }


@dataclass(frozen=True)
class PolicyDecision:
    effect: Effect
    obligations: Mapping[str, Any] = field(default_factory=dict)
    policy_version: Optional[str] = None
    reason: Optional[str] = None

    @staticmethod
    def deny(reason: str = "default-deny", policy_version: Optional[str] = None) -> "PolicyDecision":
        return PolicyDecision(effect="Deny", obligations={}, policy_version=policy_version, reason=reason)

    @staticmethod
    def permit(obligations: Optional[Mapping[str, Any]] = None, policy_version: Optional[str] = None,
               reason: Optional[str] = None) -> "PolicyDecision":
        return PolicyDecision(effect="Permit", obligations=obligations or {}, policy_version=policy_version, reason=reason)

    @staticmethod
    def indeterminate(reason: str = "indeterminate", policy_version: Optional[str] = None) -> "PolicyDecision":
        return PolicyDecision(effect="Indeterminate", obligations={}, policy_version=policy_version, reason=reason)


# -----------------------------------------------------------------------------
# Resilience primitives: TTL Cache, Token Bucket, Circuit Breaker
# -----------------------------------------------------------------------------
class AsyncTTLCache:
    """
    Simple async TTL cache with max size. Not LRU—evicts oldest expired; if full, evicts one arbitrary item.
    """
    def __init__(self, ttl_seconds: float, max_size: int = 2048):
        self._ttl = ttl_seconds
        self._max = max_size
        self._store: Dict[str, Tuple[float, PolicyDecision]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[PolicyDecision]:
        now = time.monotonic()
        async with self._lock:
            item = self._store.get(key)
            if not item:
                return None
            expires_at, value = item
            if expires_at <= now:
                # expired
                self._store.pop(key, None)
                return None
            return value

    async def set(self, key: str, value: PolicyDecision) -> None:
        now = time.monotonic()
        async with self._lock:
            if len(self._store) >= self._max:
                # best-effort eviction of one expired or arbitrary
                expired_keys = [k for k, (t, _) in self._store.items() if t <= now]
                if expired_keys:
                    self._store.pop(expired_keys[0], None)
                else:
                    self._store.pop(next(iter(self._store)), None)
            self._store[key] = (now + self._ttl, value)

    async def clear(self) -> None:
        async with self._lock:
            self._store.clear()


class AsyncTokenBucket:
    """
    Token-bucket rate limiter for asyncio tasks.
    """
    def __init__(self, rate_per_sec: float, burst: Optional[int] = None):
        self._rate = max(rate_per_sec, 0.0)
        self._capacity = burst if burst is not None else max(1, int(rate_per_sec))
        self._tokens = float(self._capacity)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
            if self._tokens < 1.0:
                # need to wait until a token becomes available
                wait_time = (1.0 - self._tokens) / self._rate if self._rate > 0 else 0.1
                await asyncio.sleep(wait_time)
                # refill after sleep
                now2 = time.monotonic()
                elapsed2 = now2 - self._last
                self._last = now2
                self._tokens = min(self._capacity, self._tokens + elapsed2 * self._rate)
            # consume
            if self._tokens >= 1.0:
                self._tokens -= 1.0


class AsyncCircuitBreaker:
    """
    Half-open circuit breaker with failure threshold and reset timeout.
    """
    def __init__(self, failure_threshold: int = 5, reset_timeout_sec: float = 30.0, half_open_max_calls: int = 1):
        self._failure_threshold = failure_threshold
        self._reset_timeout = reset_timeout_sec
        self._half_open_max_calls = half_open_max_calls

        self._state: Literal["CLOSED", "OPEN", "HALF_OPEN"] = "CLOSED"
        self._failures = 0
        self._opened_at: Optional[float] = None
        self._half_open_inflight = 0
        self._lock = asyncio.Lock()

    async def call(self, func: Callable[[], Any]) -> Any:
        async with self._lock:
            state = self._state
            if state == "OPEN":
                if self._opened_at is not None and (time.monotonic() - self._opened_at) >= self._reset_timeout:
                    self._state = "HALF_OPEN"
                    self._half_open_inflight = 0
                else:
                    raise RuntimeError("circuit-open")

            if self._state == "HALF_OPEN":
                if self._half_open_inflight >= self._half_open_max_calls:
                    raise RuntimeError("circuit-half-open-saturated")
                self._half_open_inflight += 1

        try:
            result = await func()
        except Exception as e:
            await self._on_failure()
            raise e
        else:
            await self._on_success()
            return result
        finally:
            if self._state == "HALF_OPEN":
                async with self._lock:
                    self._half_open_inflight = max(0, self._half_open_inflight - 1)

    async def _on_failure(self) -> None:
        async with self._lock:
            self._failures += 1
            if self._failures >= self._failure_threshold and self._state != "OPEN":
                self._state = "OPEN"
                self._opened_at = time.monotonic()

    async def _on_success(self) -> None:
        async with self._lock:
            self._failures = 0
            self._state = "CLOSED"
            self._opened_at = None


# -----------------------------------------------------------------------------
# Backends
# -----------------------------------------------------------------------------
class PolicyBackend:
    async def evaluate(self, request: PolicyDecisionRequest) -> PolicyDecision:
        raise NotImplementedError

    async def get_policy_version(self) -> Optional[str]:
        return None

    async def warmup(self) -> None:
        return None


class LocalRulesBackend(PolicyBackend):
    """
    Simple deterministic rule engine: first match wins.
    Each rule: Callable[[PolicyDecisionRequest], Tuple[bool, PolicyDecision]]
    Return (True, decision) when rule applies; otherwise (False, _).
    """
    def __init__(self, rules: Optional[List[Callable[[PolicyDecisionRequest], Tuple[bool, PolicyDecision]]]] = None,
                 version: str = "local-1"):
        self._rules = rules or []
        self._version = version

    async def evaluate(self, request: PolicyDecisionRequest) -> PolicyDecision:
        for rule in self._rules:
            try:
                matched, decision = rule(request)
            except Exception as e:
                LOG.exception("Local rule raised exception; continuing default-deny", extra=_audit_extra(request))
                continue
            if matched:
                # ensure policy_version is set
                if decision.policy_version is None:
                    return PolicyDecision(
                        effect=decision.effect,
                        obligations=decision.obligations,
                        policy_version=self._version,
                        reason=decision.reason,
                    )
                return decision
        return PolicyDecision.deny(reason="no-rule-matched", policy_version=self._version)

    async def get_policy_version(self) -> Optional[str]:
        return self._version

    async def warmup(self) -> None:
        return None


class OPAHttpBackend(PolicyBackend):
    """
    Minimal dependency async HTTP client to OPA using urllib in a thread.
    POST {opa_url}/v1/data/{package}/allow with input: {...}

    Expected OPA response shape:
      {"result": {"allow": true/false, "obligations": {...}, "version": "..." } }
    or
      {"result": true/false}

    Note: For production, consider aiohttp/httpx; here we avoid hard deps.
    """
    def __init__(self, opa_url: str, package: str, timeout_sec: float = 1.5,
                 headers: Optional[Mapping[str, str]] = None):
        self._base = opa_url.rstrip("/")
        self._pkg = package.strip(".")
        self._timeout = timeout_sec
        self._headers = {"Content-Type": "application/json"}
        if headers:
            self._headers.update(dict(headers))

    async def evaluate(self, request: PolicyDecisionRequest) -> PolicyDecision:
        url = f"{self._base}/v1/data/{self._pkg}/allow"
        payload = {"input": _request_to_opa_input(request)}
        try:
            data = await _async_http_post_json(url, payload, self._headers, timeout=self._timeout)
        except Exception as e:
            LOG.exception("OPA HTTP error", extra=_audit_extra(request))
            return PolicyDecision.deny(reason="opa-http-error")

        result = data.get("result", None)
        if isinstance(result, dict):
            allow = bool(result.get("allow", False))
            obligations = result.get("obligations", {}) or {}
            version = result.get("version") or result.get("policy_version")
            if allow:
                return PolicyDecision.permit(obligations=obligations, policy_version=version, reason="opa-allow")
            return PolicyDecision.deny(policy_version=version, reason="opa-deny")
        elif isinstance(result, bool):
            return PolicyDecision.permit(reason="opa-allow") if result else PolicyDecision.deny(reason="opa-deny")
        else:
            return PolicyDecision.indeterminate(reason="opa-invalid-response")

    async def get_policy_version(self) -> Optional[str]:
        # Optional: call separate endpoint; here we return None to keep latency low
        return None

    async def warmup(self) -> None:
        # Optional: a lightweight self-check; we skip network warmups to avoid startup stalls
        return None


async def _async_http_post_json(url: str, payload: Dict[str, Any], headers: Mapping[str, str], timeout: float) -> Dict[str, Any]:
    """
    Minimal async POST using stdlib urllib executed in a thread.
    """
    import urllib.request
    import urllib.error

    def _do() -> Dict[str, Any]:
        req = urllib.request.Request(url, method="POST")
        for k, v in headers.items():
            req.add_header(k, v)
        body = json.dumps(payload).encode("utf-8")
        try:
            with urllib.request.urlopen(req, data=body, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"http-error {e.code}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"url-error {e}") from e

    return await asyncio.to_thread(_do)


def _request_to_opa_input(req: PolicyDecisionRequest) -> Dict[str, Any]:
    return {
        "tenant_id": req.tenant_id,
        "subject": {"id": req.subject.id, "attributes": req.subject.attributes},
        "action": {"name": req.action.name, "attributes": req.action.attributes},
        "resource": {
            "id": req.resource.id,
            "type": req.resource.type,
            "attributes": req.resource.attributes,
        },
        "environment": {
            "ip": req.environment.ip,
            "timestamp": req.environment.timestamp,
            "attributes": req.environment.attributes,
        },
        "correlation_id": req.correlation_id,
    }


# -----------------------------------------------------------------------------
# Adapter configuration
# -----------------------------------------------------------------------------
@dataclass(frozen=True)
class AdapterConfig:
    backend: Literal["local", "opa_http"] = "local"
    # Local
    local_rules_version: str = "local-1"
    # OPA
    opa_url: str = "http://127.0.0.1:8181"
    opa_package: str = "authz"
    opa_timeout_sec: float = 1.5
    opa_headers: Mapping[str, str] = field(default_factory=dict)
    # Cache
    cache_ttl_sec: float = 2.0
    cache_max_size: int = 4096
    # Rate limiter
    rate_limit_per_sec: float = 200.0
    rate_burst: Optional[int] = None
    # Circuit breaker
    cb_failure_threshold: int = 10
    cb_reset_timeout_sec: float = 10.0
    cb_half_open_max_calls: int = 2
    # Security
    hmac_key: Optional[bytes] = None  # for payload/bundle verification
    # Audit
    redact_keys: Tuple[str, ...] = ("password", "secret", "token", "authorization", "api_key")
    # Default deny reason
    default_deny_reason: str = "zero-trust-default-deny"


# -----------------------------------------------------------------------------
# Policy Core Adapter
# -----------------------------------------------------------------------------
class PolicyCoreAdapter:
    """
    Facade/Adapter for Zero-Trust Policy Core with resilience, caching and auditing.
    """
    def __init__(self, config: AdapterConfig,
                 rules: Optional[List[Callable[[PolicyDecisionRequest], Tuple[bool, PolicyDecision]]]] = None):
        self._cfg = config
        self._cache = AsyncTTLCache(ttl_seconds=config.cache_ttl_sec, max_size=config.cache_max_size)
        self._limiter = AsyncTokenBucket(rate_per_sec=config.rate_limit_per_sec, burst=config.rate_burst)
        self._breaker = AsyncCircuitBreaker(
            failure_threshold=config.cb_failure_threshold,
            reset_timeout_sec=config.cb_reset_timeout_sec,
            half_open_max_calls=config.cb_half_open_max_calls,
        )
        if config.backend == "local":
            self._backend: PolicyBackend = LocalRulesBackend(rules=rules, version=config.local_rules_version)
        elif config.backend == "opa_http":
            self._backend = OPAHttpBackend(
                opa_url=config.opa_url,
                package=config.opa_package,
                timeout_sec=config.opa_timeout_sec,
                headers=config.opa_headers,
            )
        else:
            raise ValueError(f"unknown backend: {config.backend}")

    # ------------------------------ Public API --------------------------------

    async def evaluate(self, request: PolicyDecisionRequest) -> PolicyDecision:
        """
        Evaluate a decision in a resilient, observable, default-deny manner.
        """
        span_ctx = _otel_start_span("PolicyCoreAdapter.evaluate", attributes={
            "tenant_id": request.tenant_id or "",
            "action": request.action.name,
            "resource_type": request.resource.type,
        })
        try:
            cache_key = self._make_cache_key(request)
            cached = await self._cache.get(cache_key)
            if cached is not None:
                _otel_set_span_attr(span_ctx, "cache.hit", True)
                self._audit("decision-cache-hit", request, cached)
                return cached

            await self._limiter.acquire()

            async def _eval() -> PolicyDecision:
                decision = await self._backend.evaluate(request)
                return decision

            try:
                decision = await self._breaker.call(_eval)
            except Exception as e:
                # Secure fallback: default deny
                self._audit("decision-error-default-deny", request, None, error=str(e))
                return PolicyDecision.deny(reason=self._cfg.default_deny_reason)

            # Cache only determinate decisions (Permit/Deny)
            if decision.effect in ("Permit", "Deny"):
                await self._cache.set(cache_key, decision)

            self._audit("decision", request, decision)
            _otel_set_span_attr(span_ctx, "decision.effect", decision.effect)
            return decision
        finally:
            _otel_end_span(span_ctx)

    async def verify_signature(self, payload: bytes, signature_hex: str) -> bool:
        """
        Optional integrity check for policy bundles or snapshots using HMAC-SHA256.
        Returns True only if signature is valid with configured hmac_key.
        """
        key = self._cfg.hmac_key
        if not key:
            return False
        try:
            expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, signature_hex)
        except Exception:
            return False

    async def warmup(self) -> None:
        await self._backend.warmup()

    async def health(self) -> Dict[str, Any]:
        ver = await self._backend.get_policy_version()
        return {
            "backend": type(self._backend).__name__,
            "policy_version": ver,
            "cache_ttl_sec": self._cfg.cache_ttl_sec,
            "rate_limit_per_sec": self._cfg.rate_limit_per_sec,
            "circuit_breaker": {
                "failure_threshold": self._cfg.cb_failure_threshold,
                "reset_timeout_sec": self._cfg.cb_reset_timeout_sec,
                "half_open_max_calls": self._cfg.cb_half_open_max_calls,
            },
        }

    # ----------------------------- Internal utils -----------------------------

    def _make_cache_key(self, request: PolicyDecisionRequest) -> str:
        material = request.to_cache_key_material()
        # Canonical JSON
        canonical = json.dumps(material, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        # Tenant isolation baked into digest via material. Keep a prefix for inspection.
        prefix = request.tenant_id or "no-tenant"
        return f"{prefix}:{digest}"

    def _audit(self, event: str, request: PolicyDecisionRequest,
               decision: Optional[PolicyDecision], error: Optional[str] = None) -> None:
        extra = _audit_extra(request, redact_keys=self._cfg.redact_keys)
        extra.update({
            "event": event,
            "decision_effect": getattr(decision, "effect", None),
            "decision_reason": getattr(decision, "reason", None),
            "decision_policy_version": getattr(decision, "policy_version", None),
        })
        if error:
            extra["error"] = error
            LOG.warning("policy-event", extra=extra)
        else:
            LOG.info("policy-event", extra=extra)


# -----------------------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------------------
def _redact(obj: Any, redact_keys: Tuple[str, ...]) -> Any:
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            if k.lower() in redact_keys:
                out[k] = "***"
            else:
                out[k] = _redact(v, redact_keys)
        return out
    elif isinstance(obj, list):
        return [_redact(i, redact_keys) for i in obj]
    return obj


def _audit_extra(req: PolicyDecisionRequest, redact_keys: Tuple[str, ...] = ("password", "secret", "token", "authorization", "api_key")) -> Dict[str, Any]:
    return {
        "tenant_id": req.tenant_id,
        "correlation_id": req.correlation_id,
        "subject_id": req.subject.id,
        "action": req.action.name,
        "resource_id": req.resource.id,
        "resource_type": req.resource.type,
        "env_ip": req.environment.ip,
        "subject_attrs": _redact(dict(req.subject.attributes), redact_keys),
        "action_attrs": _redact(dict(req.action.attributes), redact_keys),
        "resource_attrs": _redact(dict(req.resource.attributes), redact_keys),
        "env_attrs": _redact(dict(req.environment.attributes), redact_keys),
    }


def _otel_start_span(name: str, attributes: Optional[Mapping[str, Any]] = None):
    if not _OTEL_AVAILABLE or _TRACER is None:
        return None
    span = _TRACER.start_as_current_span(name)
    cm = span.__enter__()
    if attributes:
        for k, v in attributes.items():
            try:
                cm.set_attribute(k, v)
            except Exception:
                pass
    return span

def _otel_set_span_attr(span_ctx, key: str, value: Any) -> None:
    if span_ctx is None:
        return
    try:
        span_ctx.set_attribute(key, value)
    except Exception:
        pass

def _otel_end_span(span_ctx) -> None:
    if span_ctx is None:
        return
    try:
        span_ctx.__exit__(None, None, None)
    except Exception:
        pass


# -----------------------------------------------------------------------------
# Example local rule helpers (optional for integrators)
# -----------------------------------------------------------------------------
def allow_if_role_in(roles: List[str], reason: str = "role-allowed") -> Callable[[PolicyDecisionRequest], Tuple[bool, PolicyDecision]]:
    roles_lc = {r.lower() for r in roles}
    def _rule(req: PolicyDecisionRequest) -> Tuple[bool, PolicyDecision]:
        role = str(req.subject.attributes.get("role", "")).lower()
        if role in roles_lc:
            return True, PolicyDecision.permit(reason=reason)
        return False, PolicyDecision.deny()
    return _rule


def deny_if_resource_type(types: List[str], reason: str = "resource-type-deny") -> Callable[[PolicyDecisionRequest], Tuple[bool, PolicyDecision]]:
    deny_types = {t.lower() for t in types}
    def _rule(req: PolicyDecisionRequest) -> Tuple[bool, PolicyDecision]:
        if req.resource.type.lower() in deny_types:
            return True, PolicyDecision.deny(reason=reason)
        return False, PolicyDecision.deny()
    return _rule
