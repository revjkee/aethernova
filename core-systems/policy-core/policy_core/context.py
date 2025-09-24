# policy_core/context.py
# Industrial-grade Policy Context for Zero-Trust, RBAC/ABAC, and Guardrails
# Copyright (c) 2025
# License: Apache-2.0 (adjust per project policy)
from __future__ import annotations

import asyncio
import contextvars
import dataclasses
import datetime as dt
import functools
import ipaddress
import json
import logging
import os
import secrets
import sys
import time
import types
import uuid
from abc import ABC, abstractmethod
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

# -----------------------------
# Public API (export control)
# -----------------------------
__all__ = [
    "SecurityLabel",
    "EnforcementMode",
    "PolicyDecision",
    "Identity",
    "Resource",
    "Environment",
    "RequestContext",
    "PolicyRef",
    "PolicyMetadata",
    "Policy",
    "EvaluationResult",
    "PolicyStore",
    "PolicyContext",
    "Auditor",
    "AuditEvent",
    "current_policy_context",
]

# -----------------------------
# Enums & constants
# -----------------------------
class SecurityLabel(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    SECRET = "secret"


class EnforcementMode(str, Enum):
    ENFORCE = "enforce"       # Block on DENY
    PERMISSIVE = "permissive" # Log DENY as WARN, allow
    DRY_RUN = "dry_run"       # Evaluate + log, never block
    DISABLED = "disabled"     # Skip evaluation entirely


class PolicyDecision(str, Enum):
    PERMIT = "permit"
    DENY = "deny"
    CHALLENGE = "challenge"         # Require additional auth/step-up
    INDETERMINATE = "indeterminate" # Error / no applicable policy


# -----------------------------
# Core typed models (dataclasses; no external deps)
# -----------------------------
@dataclass(frozen=True)
class Identity:
    subject_id: str
    tenant_id: Optional[str] = None
    roles: Tuple[str, ...] = field(default_factory=tuple)
    scopes: Tuple[str, ...] = field(default_factory=tuple)
    attributes: Mapping[str, Any] = field(default_factory=dict)
    auth_context: Mapping[str, Any] = field(default_factory=dict)  # e.g., { "amr": ["pwd","mfa"], "ip": "1.2.3.4" }


@dataclass(frozen=True)
class Resource:
    type: str
    id: Optional[str] = None
    owner: Optional[str] = None
    labels: frozenset[str] = field(default_factory=frozenset)
    security_label: SecurityLabel = SecurityLabel.INTERNAL
    attributes: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Environment:
    ip: Optional[str] = None
    location: Optional[str] = None          # ISO 3166-1 alpha-2 country code or city string
    device: Optional[str] = None            # Device ID/fingerprint category
    timezone: Optional[str] = None          # IANA tz
    user_agent: Optional[str] = None
    network: Optional[str] = None           # e.g. "corp", "untrusted", "vpn"
    attributes: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RequestContext:
    correlation_id: str
    request_id: str
    source: str                           # e.g., service name
    actor: Identity
    action: str                           # e.g., "read", "write", "delete", "approve"
    resource: Resource
    environment: Environment = field(default_factory=Environment)
    timestamp: dt.datetime = field(default_factory=lambda: dt.datetime.now(dt.timezone.utc))
    deadline_ms: Optional[int] = None     # Absolute deadline in ms since epoch
    tags: frozenset[str] = field(default_factory=frozenset)
    extra: Mapping[str, Any] = field(default_factory=dict)

    def with_tag(self, *tags: str) -> "RequestContext":
        return dataclasses.replace(self, tags=self.tags.union(tags))


@dataclass(frozen=True)
class PolicyRef:
    policy_id: str
    version: str


@dataclass(frozen=True)
class PolicyMetadata:
    policy_id: str
    version: str
    kind: str
    etag: Optional[str]
    updated_at: dt.datetime
    tenant_id: Optional[str] = None
    tags: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class Policy:
    metadata: PolicyMetadata
    spec: Mapping[str, Any]                # OPA/Rego-like, CEL-like, or custom DSL JSON/YAML parsed
    compiled: Optional[Any] = None         # Optional compiled representation (engine specific)


@dataclass(frozen=True)
class EvaluationResult:
    decision: PolicyDecision
    obligations: Mapping[str, Any] = field(default_factory=dict)  # e.g., {"mask_fields": ["email"], "max_rows": 100}
    reasons: Tuple[str, ...] = field(default_factory=tuple)
    used_policies: Tuple[PolicyRef, ...] = field(default_factory=tuple)
    latency_ms: Optional[float] = None
    debug: Mapping[str, Any] = field(default_factory=dict)


# -----------------------------
# Utilities
# -----------------------------
def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _redact(value: Any) -> Any:
    """
    Redact sensitive tokens/credentials in dict-like structures for safe logging/auditing.
    """
    SENSITIVE_KEYS = {"authorization", "password", "secret", "api_key", "token", "refresh_token", "client_secret"}
    try:
        if isinstance(value, Mapping):
            return {k: ("***" if k.lower() in SENSITIVE_KEYS else _redact(v)) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return type(value)(_redact(v) for v in value)
        if isinstance(value, str) and len(value) > 64:
            # Heuristic: long opaque strings are likely tokens
            return value[:6] + "..." + value[-4:]
        return value
    except Exception:
        return "***"


def _validate_ip(ip: Optional[str]) -> Optional[str]:
    if not ip:
        return ip
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        return "0.0.0.0"


def _deadline_millis(timeout_s: float) -> int:
    return int(time.time() * 1000 + timeout_s * 1000)


# -----------------------------
# Async TTL LRU Cache (in-memory)
# -----------------------------
class _CacheEntry:
    __slots__ = ("value", "expires_at", "etag")

    def __init__(self, value: Any, ttl_s: float, etag: Optional[str] = None):
        self.value = value
        self.expires_at = time.monotonic() + ttl_s
        self.etag = etag

    @property
    def expired(self) -> bool:
        return time.monotonic() >= self.expires_at


class AsyncTTLCache:
    """
    Small-footprint async-safe TTL-LRU cache for policy objects.
    """
    def __init__(self, maxsize: int = 512, default_ttl_s: float = 60.0):
        self._maxsize = maxsize
        self._default_ttl_s = default_ttl_s
        self._lock = asyncio.Lock()
        self._data: OrderedDict[str, _CacheEntry] = OrderedDict()
        self._key_locks: Dict[str, asyncio.Lock] = {}

    def _prune_unlocked(self) -> None:
        # Remove expired entries
        remove_keys = [k for k, v in self._data.items() if v.expired]
        for k in remove_keys:
            self._data.pop(k, None)
        # Enforce LRU size
        while len(self._data) > self._maxsize:
            self._data.popitem(last=False)

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            entry = self._data.get(key)
            if not entry:
                return None
            if entry.expired:
                self._data.pop(key, None)
                return None
            # Move to MRU
            self._data.move_to_end(key, last=True)
            return entry.value

    async def get_with_meta(self, key: str) -> Tuple[Optional[Any], Optional[str]]:
        async with self._lock:
            entry = self._data.get(key)
            if not entry or entry.expired:
                self._data.pop(key, None)
                return None, None
            self._data.move_to_end(key, last=True)
            return entry.value, entry.etag

    async def set(self, key: str, value: Any, ttl_s: Optional[float] = None, etag: Optional[str] = None) -> None:
        ttl = ttl_s if ttl_s is not None else self._default_ttl_s
        async with self._lock:
            self._data[key] = _CacheEntry(value, ttl, etag=etag)
            self._data.move_to_end(key, last=True)
            self._prune_unlocked()

    def key_lock(self, key: str) -> asyncio.Lock:
        # Fine-grained lock per key to avoid thundering herd
        if key not in self._key_locks:
            self._key_locks[key] = asyncio.Lock()
        return self._key_locks[key]


# -----------------------------
# Policy store abstraction
# -----------------------------
class PolicyStore(ABC):
    """
    Abstract store for retrieving policy definitions. Implementations may pull from DB, S3, Git, or OPA bundles.
    """

    @abstractmethod
    async def get_policy(self, policy_id: str) -> Optional[Policy]:
        ...

    @abstractmethod
    async def list_policies(
        self,
        *,
        tenant_id: Optional[str] = None,
        tags: Optional[Iterable[str]] = None,
        kinds: Optional[Iterable[str]] = None,
    ) -> Sequence[PolicyMetadata]:
        ...

    @abstractmethod
    async def get_etag(self, policy_id: str) -> Optional[str]:
        """
        Return a fast freshness token for a policy (e.g., version hash or updated_at digest).
        """
        ...


# -----------------------------
# Auditing
# -----------------------------
@dataclass(frozen=True)
class AuditEvent:
    at: dt.datetime
    correlation_id: str
    policy_id: Optional[str]
    decision: PolicyDecision
    enforcement_mode: EnforcementMode
    reasons: Tuple[str, ...]
    obligations: Mapping[str, Any]
    actor: Mapping[str, Any]
    resource: Mapping[str, Any]
    source: str
    latency_ms: Optional[float] = None
    extra: Mapping[str, Any] = field(default_factory=dict)


class Auditor:
    """
    Structured auditor. Default sink logs as JSON to logger 'policy_core.audit'.
    A custom sink can be provided (async callable).
    """
    def __init__(self, sink: Optional[Callable[[AuditEvent], Awaitable[None]]] = None, logger: Optional[logging.Logger] = None):
        self._sink = sink
        self._logger = logger or logging.getLogger("policy_core.audit")

    async def emit(self, event: AuditEvent) -> None:
        if self._sink is not None:
            try:
                await self._sink(event)
                return
            except Exception as e:
                # Fallback to logging on sink error
                self._logger.exception("Audit sink failed: %s", e)

        payload = dataclasses.asdict(event)
        # Redact nested sensitive data just in case
        payload["actor"] = _redact(payload.get("actor"))
        payload["resource"] = _redact(payload.get("resource"))
        try:
            self._logger.info(json.dumps(payload, default=str))
        except Exception:
            self._logger.info("AUDIT %s", payload)


# -----------------------------
# Evaluator registry
# -----------------------------
PolicyEvaluator = Callable[[Policy, RequestContext, "PolicyContext"], Awaitable[EvaluationResult]]


class _EvaluatorRegistry:
    def __init__(self):
        self._by_kind: Dict[str, PolicyEvaluator] = {}

    def register(self, kind: str, evaluator: PolicyEvaluator) -> None:
        if not kind or not isinstance(kind, str):
            raise ValueError("Policy kind must be a non-empty string")
        if not callable(evaluator):
            raise ValueError("Evaluator must be callable")
        self._by_kind[kind] = evaluator

    def get(self, kind: str) -> PolicyEvaluator:
        try:
            return self._by_kind[kind]
        except KeyError:
            raise KeyError(f"No evaluator registered for policy kind='{kind}'") from None

    def available_kinds(self) -> Tuple[str, ...]:
        return tuple(sorted(self._by_kind.keys()))


# -----------------------------
# Optional OpenTelemetry
# -----------------------------
try:
    from opentelemetry import trace  # type: ignore
    _otel_tracer = trace.get_tracer("policy_core")
except Exception:
    _otel_tracer = None


# -----------------------------
# Current context (ContextVar)
# -----------------------------
current_policy_context: contextvars.ContextVar[Optional["PolicyContext"]] = contextvars.ContextVar(
    "policy_core_current_ctx", default=None
)


# -----------------------------
# PolicyContext (main orchestrator)
# -----------------------------
class PolicyContext:
    """
    Orchestrates policy evaluation with caching, auditing, and enforcement mode.

    Key features:
    - In-memory TTL+LRU cache for policies
    - Pluggable PolicyStore (DB/S3/Git)
    - Evaluator registry (kind -> async evaluator)
    - Enforcement modes (enforce/permissive/dry_run/disabled)
    - Structured auditing with redaction
    - Optional OpenTelemetry spans
    - Timeouts and per-call deadlines
    - Fine-grained per-policy fetch locks (thundering-herd mitigation)
    """

    def __init__(
        self,
        store: PolicyStore,
        *,
        cache_ttl_s: float = 60.0,
        cache_maxsize: int = 1024,
        decision_timeout_s: float = 2.0,
        enforcement_mode: EnforcementMode = EnforcementMode.ENFORCE,
        auditor: Optional[Auditor] = None,
        logger: Optional[logging.Logger] = None,
        feature_flags: Optional[Mapping[str, bool]] = None,
    ):
        self._store = store
        self._cache = AsyncTTLCache(maxsize=cache_maxsize, default_ttl_s=cache_ttl_s)
        self._decision_timeout_s = decision_timeout_s
        self._enforcement = enforcement_mode
        self._auditor = auditor or Auditor()
        self._logger = logger or logging.getLogger("policy_core")
        self._evaluators = _EvaluatorRegistry()
        self._feature_flags = dict(feature_flags or {})
        self._closed = False

    # ---------- lifecycle ----------
    async def aclose(self) -> None:
        self._closed = True

    def __repr__(self) -> str:
        return (
            f"PolicyContext(enforcement={self._enforcement}, ttl={self._cache._default_ttl_s}s, "
            f"timeout={self._decision_timeout_s}s, kinds={self._evaluators.available_kinds()})"
        )

    # ---------- feature flags ----------
    def is_feature_enabled(self, key: str, default: bool = False) -> bool:
        return bool(self._feature_flags.get(key, default))

    # ---------- evaluator registration ----------
    def register_evaluator(self, kind: str, evaluator: PolicyEvaluator) -> None:
        self._evaluators.register(kind, evaluator)

    # ---------- policy retrieval with freshness ----------
    async def _get_policy_fresh(self, policy_id: str) -> Optional[Policy]:
        # Attempt cache with ETag revalidation
        cached, cached_etag = await self._cache.get_with_meta(policy_id)
        try:
            current_etag = await self._store.get_etag(policy_id)
        except Exception as e:
            self._logger.warning("get_etag failed for %s: %s", policy_id, e)
            current_etag = None

        if cached and (current_etag is None or cached_etag == current_etag):
            return cached

        lock = self._cache.key_lock(policy_id)
        async with lock:
            # Re-check inside lock
            cached, cached_etag = await self._cache.get_with_meta(policy_id)
            if cached and (current_etag is None or cached_etag == current_etag):
                return cached

            policy = await self._store.get_policy(policy_id)
            if policy is None:
                return None
            await self._cache.set(policy_id, policy, etag=(policy.metadata.etag or current_etag))
            return policy

    # ---------- evaluation ----------
    async def evaluate(self, policy_id: str, request: RequestContext) -> EvaluationResult:
        """
        Evaluate a single policy by id.
        Honors enforcement mode and decision timeout.
        Emits audit event with structured details.
        """
        if self._closed:
            raise RuntimeError("PolicyContext is closed")

        start = time.perf_counter()
        # Normalize/validate some fields
        env = dataclasses.replace(request.environment, ip=_validate_ip(request.environment.ip))
        request = dataclasses.replace(request, environment=env)

        if _otel_tracer is not None:
            with _otel_tracer.start_as_current_span("policy.evaluate") as span:
                span.set_attribute("policy.id", policy_id)
                span.set_attribute("request.source", request.source)
                span.set_attribute("request.action", request.action)
                span.set_attribute("actor.subject_id", request.actor.subject_id)
                return await self._evaluate_inner(policy_id, request, start)
        else:
            return await self._evaluate_inner(policy_id, request, start)

    async def _evaluate_inner(self, policy_id: str, request: RequestContext, start_perf: float) -> EvaluationResult:
        deadline_ms = request.deadline_ms
        if deadline_ms is None:
            deadline_ms = _deadline_millis(self._decision_timeout_s)
        remaining_s = max(0.0, (deadline_ms - int(time.time() * 1000)) / 1000.0)
        timeout_s = min(self._decision_timeout_s, remaining_s) if remaining_s > 0 else 0.0

        # Fast-path: enforcement disabled
        if self._enforcement == EnforcementMode.DISABLED:
            res = EvaluationResult(
                decision=PolicyDecision.PERMIT,
                reasons=("enforcement_disabled",),
                used_policies=(),
                latency_ms=None,
            )
            await self._audit(policy_id, request, res, start_perf)
            return res

        try:
            policy = await self._get_policy_fresh(policy_id)
        except Exception as e:
            self._logger.exception("Policy fetch failed: %s", e)
            result = EvaluationResult(decision=PolicyDecision.INDETERMINATE, reasons=("fetch_error", str(e)))
            await self._audit(policy_id, request, result, start_perf)
            return self._enforce_or_permit(result)

        if policy is None:
            result = EvaluationResult(decision=PolicyDecision.INDETERMINATE, reasons=("policy_not_found",))
            await self._audit(policy_id, request, result, start_perf)
            return self._enforce_or_permit(result)

        try:
            evaluator = self._evaluators.get(policy.metadata.kind)
        except KeyError:
            result = EvaluationResult(decision=PolicyDecision.INDETERMINATE, reasons=("no_evaluator", policy.metadata.kind))
            await self._audit(policy_id, request, result, start_perf)
            return self._enforce_or_permit(result)

        async def _run() -> EvaluationResult:
            return await evaluator(policy, request, self)

        try:
            if timeout_s <= 0:
                raise asyncio.TimeoutError("deadline_exceeded")
            res = await asyncio.wait_for(_run(), timeout=timeout_s)
        except asyncio.TimeoutError:
            result = EvaluationResult(decision=PolicyDecision.INDETERMINATE, reasons=("timeout",))
            await self._audit(policy_id, request, result, start_perf)
            return self._enforce_or_permit(result)
        except Exception as e:
            self._logger.exception("Policy evaluation error: %s", e)
            result = EvaluationResult(decision=PolicyDecision.INDETERMINATE, reasons=("evaluation_error", str(e)))
            await self._audit(policy_id, request, result, start_perf)
            return self._enforce_or_permit(result)

        # Attach latency and used policy
        latency_ms = (time.perf_counter() - start_perf) * 1000.0
        res = dataclasses.replace(
            res,
            latency_ms=latency_ms,
            used_policies=tuple(res.used_policies) + (PolicyRef(policy_id=policy.metadata.policy_id, version=policy.metadata.version),),
        )

        await self._audit(policy_id, request, res, start_perf)
        return self._enforce_or_permit(res)

    def _enforce_or_permit(self, result: EvaluationResult) -> EvaluationResult:
        if self._enforcement in (EnforcementMode.DRY_RUN, EnforcementMode.PERMISSIVE):
            # Log-only modes: never block
            if result.decision == PolicyDecision.DENY:
                # Re-write decision to PERMIT but keep reasons/obligations for observability
                return dataclasses.replace(result, decision=PolicyDecision.PERMIT)
            return result
        # ENFORCE mode: return as-is
        return result

    async def _audit(self, policy_id: Optional[str], request: RequestContext, result: EvaluationResult, start_perf: float) -> None:
        try:
            latency_ms = (time.perf_counter() - start_perf) * 1000.0
            actor = {
                "subject_id": request.actor.subject_id,
                "tenant_id": request.actor.tenant_id,
                "roles": request.actor.roles,
                "scopes": request.actor.scopes,
                "attributes": _redact(request.actor.attributes),
            }
            resource = {
                "type": request.resource.type,
                "id": request.resource.id,
                "owner": request.resource.owner,
                "labels": tuple(request.resource.labels),
                "security_label": request.resource.security_label.value,
            }
            event = AuditEvent(
                at=_utc_now(),
                correlation_id=request.correlation_id,
                policy_id=policy_id,
                decision=result.decision,
                enforcement_mode=self._enforcement,
                reasons=result.reasons,
                obligations=_redact(result.obligations),
                actor=actor,
                resource=resource,
                source=request.source,
                latency_ms=latency_ms,
                extra={"action": request.action, "env": _redact(dataclasses.asdict(request.environment))},
            )
            await self._auditor.emit(event)
        except Exception as e:
            self._logger.exception("Failed to emit audit: %s", e)

    # ---------- helper factories ----------
    @staticmethod
    def new_request(
        *,
        source: str,
        actor: Identity,
        action: str,
        resource: Resource,
        environment: Optional[Environment] = None,
        correlation_id: Optional[str] = None,
        request_id: Optional[str] = None,
        tags: Optional[Iterable[str]] = None,
        timeout_s: Optional[float] = None,
        extra: Optional[Mapping[str, Any]] = None,
    ) -> RequestContext:
        now = _utc_now()
        corr = correlation_id or str(uuid.uuid4())
        rid = request_id or secrets.token_hex(8)
        deadline_ms = _deadline_millis(timeout_s) if timeout_s else None
        return RequestContext(
            correlation_id=corr,
            request_id=rid,
            source=source,
            actor=actor,
            action=action,
            resource=resource,
            environment=environment or Environment(),
            timestamp=now,
            deadline_ms=deadline_ms,
            tags=frozenset(tags or []),
            extra=extra or {},
        )


# -----------------------------
# Minimal default evaluator (deny-all for unknown)
# Projects should register real evaluators for their policy kinds.
# -----------------------------
async def _deny_all_evaluator(policy: Policy, request: RequestContext, ctx: PolicyContext) -> EvaluationResult:
    return EvaluationResult(
        decision=PolicyDecision.DENY,
        reasons=("no_rules_configured", policy.metadata.kind),
        obligations={},
        used_policies=(PolicyRef(policy_id=policy.metadata.policy_id, version=policy.metadata.version),),
    )


# Register a conservative default for kind="deny_all"
# Consumers should override/register their own evaluators (e.g., "cel", "rego", "rbac", "abac")
def install_default_evaluators(policy_context: PolicyContext) -> None:
    try:
        policy_context.register_evaluator("deny_all", _deny_all_evaluator)
    except Exception:
        pass


# -----------------------------
# Context manager for current PolicyContext
# -----------------------------
class set_current_policy_context:
    """
    Async context manager to set the current policy context into a ContextVar.
    Useful when downstream modules need to fetch it implicitly.
    """
    def __init__(self, ctx: PolicyContext):
        self._ctx = ctx
        self._token: Optional[contextvars.Token] = None

    async def __aenter__(self):
        self._token = current_policy_context.set(self._ctx)
        return self._ctx

    async def __aexit__(self, exc_type, exc, tb):
        if self._token is not None:
            current_policy_context.reset(self._token)
        self._token = None


# -----------------------------
# Example in-code documentation (not executed)
# -----------------------------
"""
USAGE NOTES (to be included in project docs):

1) Provide a PolicyStore implementation, e.g. DbPolicyStore or S3PolicyStore:

    class DbPolicyStore(PolicyStore):
        async def get_policy(self, policy_id: str) -> Optional[Policy]: ...
        async def list_policies(... ) -> Sequence[PolicyMetadata]: ...
        async def get_etag(self, policy_id: str) -> Optional[str]: ...

2) Instantiate PolicyContext and register evaluators:

    ctx = PolicyContext(store, enforcement_mode=EnforcementMode.ENFORCE)
    install_default_evaluators(ctx)
    ctx.register_evaluator("rbac", rbac_evaluator)
    ctx.register_evaluator("abac", abac_evaluator)
    ctx.register_evaluator("cel", cel_evaluator)  # if using CEL engine

3) Create RequestContext and evaluate:

    req = PolicyContext.new_request(
        source="orders-api",
        actor=Identity(subject_id="user:123", roles=("customer",)),
        action="read",
        resource=Resource(type="order", id="ord_001", security_label=SecurityLabel.CONFIDENTIAL),
        environment=Environment(ip="203.0.113.5", user_agent="curl/8.0"),
        timeout_s=1.5,
    )
    result = await ctx.evaluate("order_read_policy", req)

4) Enforcement modes:
   - ENFORCE: result.decision is authoritative (DENY blocks)
   - PERMISSIVE / DRY_RUN: DENY is rewritten to PERMIT, reasons are logged via audit
   - DISABLED: returns PERMIT immediately and audits the bypass

5) Security:
   - Audit redacts sensitive fields automatically.
   - IP normalization prevents log pollution.
   - Timeouts & deadlines prevent stuck evaluations.

This module is dependency-light and production-hardened for high-throughput microservices.
"""
