# chronowatch-core/chronowatch/adapters/policy_core_adapter.py
from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
import hashlib
import ipaddress
import json
import os
import random
import typing as t
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache

from pydantic import BaseModel, Field, ValidationError

# --- Soft deps: Observability (no hard fail) ---
try:
    from opentelemetry import trace  # type: ignore
    _tracer = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    class _NoSpan:
        def __enter__(self): return self
        def __exit__(self, *a): return False
    class _NoTracer:
        def start_as_current_span(self, *a, **k): return _NoSpan()
    _tracer = _NoTracer()

try:
    from prometheus_client import Counter, Histogram  # type: ignore
    _policy_decisions = Counter(
        "chronowatch_policy_decisions_total", "Policy decisions", ["backend", "effect"]
    )
    _policy_eval_latency = Histogram(
        "chronowatch_policy_eval_latency_seconds", "Policy eval latency seconds", ["backend"]
    )
except Exception:  # pragma: no cover
    class _NoMetric:
        def labels(self, *a, **k): return self
        def inc(self, *a, **k): pass
        def observe(self, *a, **k): pass
    _policy_decisions = _NoMetric()
    _policy_eval_latency = _NoMetric()

# --- Optional maintenance integration ---
try:
    # from chronowatch.windows.maintenance import MaintenanceManager
    from chronowatch.windows.maintenance import MaintenanceManager  # type: ignore
except Exception:  # pragma: no cover
    class MaintenanceManager:  # minimal stub
        async def is_in_effect(self, when: dt.datetime | None = None):
            return False, None, None, None


# =========================
# Models
# =========================

class Effect(str, Enum):
    allow = "allow"
    deny = "deny"
    abstain = "abstain"  # no decision

class PolicyRequest(BaseModel):
    subject: dict = Field(default_factory=dict)     # { "id": "...", "roles": ["..."], ... }
    action: str = Field(..., min_length=1)
    resource: dict = Field(default_factory=dict)    # { "type": "...", "tags": ["..."], ... }
    context: dict = Field(default_factory=dict)     # { "ip": "...", "time": "...", ... }
    timestamp: dt.datetime = Field(default_factory=lambda: dt.datetime.now(dt.timezone.utc))

class PolicyDecision(BaseModel):
    effect: Effect
    reason: str = ""
    rule_id: str | None = None
    backend: str = "local"
    obligations: dict = Field(default_factory=dict)
    evidence: dict = Field(default_factory=dict)    # normalized PDP output
    latency_ms: float = 0.0

    @property
    def allowed(self) -> bool:
        return self.effect == Effect.allow


# =========================
# Config & helpers
# =========================

@dataclass(frozen=True, slots=True)
class OPAConfig:
    url: str | None = None          # e.g. http://opa:8181
    query: str | None = None        # e.g. data.authz.allow
    token: str | None = None
    verify_ssl: bool = True

@dataclass(frozen=True, slots=True)
class GeniusConfig:
    url: str | None = None          # internal policy service URL
    token: str | None = None
    verify_ssl: bool = True

@dataclass(frozen=True, slots=True)
class AdapterConfig:
    backend: str = "local"                      # local | opa | genius
    default_effect: Effect = Effect.deny
    cache_ttl_seconds: int = 2
    timeout_seconds: float = 2.0
    retries: int = 1
    jitter_ms: int = 50
    opa: OPAConfig = OPAConfig()
    genius: GeniusConfig = GeniusConfig()
    allow_actions_during_maintenance: tuple[str, ...] = ("read", "health", "metrics")
    maintenance_deny_non_read: bool = True
    local_rules: list[dict] = dataclasses.field(default_factory=list)

    @staticmethod
    def from_env() -> "AdapterConfig":
        def _bool(name: str, default: bool) -> bool:
            v = os.getenv(name)
            if v is None:
                return default
            return v.lower() in ("1", "true", "yes", "on")
        def _json(name: str, default):
            raw = os.getenv(name)
            if not raw:
                return default
            try:
                return json.loads(raw)
            except Exception:
                return default

        return AdapterConfig(
            backend=os.getenv("CHRONO_POLICY_BACKEND", "local"),
            default_effect=Effect(os.getenv("CHRONO_POLICY_DEFAULT", "deny")),
            cache_ttl_seconds=int(os.getenv("CHRONO_POLICY_CACHE_TTL", "2")),
            timeout_seconds=float(os.getenv("CHRONO_POLICY_TIMEOUT", "2.0")),
            retries=int(os.getenv("CHRONO_POLICY_RETRIES", "1")),
            jitter_ms=int(os.getenv("CHRONO_POLICY_JITTER_MS", "50")),
            opa=OPAConfig(
                url=os.getenv("CHRONO_POLICY_OPA_URL"),
                query=os.getenv("CHRONO_POLICY_OPA_QUERY"),
                token=os.getenv("CHRONO_POLICY_OPA_TOKEN"),
                verify_ssl=_bool("CHRONO_POLICY_OPA_VERIFY_SSL", True),
            ),
            genius=GeniusConfig(
                url=os.getenv("CHRONO_POLICY_GENIUS_URL"),
                token=os.getenv("CHRONO_POLICY_GENIUS_TOKEN"),
                verify_ssl=_bool("CHRONO_POLICY_GENIUS_VERIFY_SSL", True),
            ),
            allow_actions_during_maintenance=tuple(
                os.getenv("CHRONO_POLICY_ALLOWED_DURING_MAINT", "read,health,metrics").split(",")
            ),
            maintenance_deny_non_read=_bool("CHRONO_POLICY_MAINT_DENY_NON_READ", True),
            local_rules=_json("CHRONO_POLICY_LOCAL_RULES", []),
        )


# =========================
# TTL Cache (in-memory)
# =========================

class _TTLCache:
    __slots__ = ("_store", "_lock")
    def __init__(self):
        self._store: dict[str, tuple[float, PolicyDecision]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> PolicyDecision | None:
        async with self._lock:
            item = self._store.get(key)
            if not item:
                return None
            exp, value = item
            if exp < dt.datetime.now(dt.timezone.utc).timestamp():
                self._store.pop(key, None)
                return None
            return value

    async def set(self, key: str, value: PolicyDecision, ttl_sec: int) -> None:
        async with self._lock:
            self._store[key] = (dt.datetime.now(dt.timezone.utc).timestamp() + ttl_sec, value)


# =========================
# Circuit Breaker (simple)
# =========================

class _CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, reset_after_sec: float = 30.0):
        self.failure_threshold = failure_threshold
        self.reset_after_sec = reset_after_sec
        self._failures = 0
        self._opened_at: dt.datetime | None = None

    def record_success(self):
        self._failures = 0
        self._opened_at = None

    def record_failure(self):
        self._failures += 1
        if self._failures >= self.failure_threshold and self._opened_at is None:
            self._opened_at = dt.datetime.now(dt.timezone.utc)

    def is_open(self) -> bool:
        if self._opened_at is None:
            return False
        if (dt.datetime.now(dt.timezone.utc) - self._opened_at).total_seconds() > self.reset_after_sec:
            # half-open
            self._failures = 0
            self._opened_at = None
            return False
        return True


# =========================
# Local rule engine (ABAC-lite)
# =========================

@lru_cache(maxsize=256)
def _compile_path(path: str) -> list[str]:
    return path.split(".")

def _dig(obj: t.Any, path: str) -> t.Any:
    cur = obj
    for key in _compile_path(path):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return None
    return cur

def _op_match(lhs: t.Any, op: str, rhs: t.Any) -> bool:
    try:
        if op == "eq":
            return lhs == rhs
        if op == "neq":
            return lhs != rhs
        if op == "in":
            return lhs in rhs if isinstance(rhs, (list, tuple, set)) else lhs == rhs
        if op == "contains":
            return rhs in lhs if isinstance(lhs, (list, tuple, set, str)) else False
        if op == "gte":
            return lhs >= rhs
        if op == "lte":
            return lhs <= rhs
        if op == "gt":
            return lhs > rhs
        if op == "lt":
            return lhs < rhs
        if op == "any_in":
            return bool(set(lhs).intersection(set(rhs))) if isinstance(lhs, (list, set, tuple)) else False
        if op == "all_in":
            return set(rhs).issubset(set(lhs)) if isinstance(lhs, (list, set, tuple)) else False
        if op == "in_cidr":
            ip = ipaddress.ip_address(lhs)
            return any(ip in ipaddress.ip_network(net) for net in (rhs if isinstance(rhs, (list, tuple)) else [rhs]))
        if op == "between":
            lo, hi = rhs
            return lo <= lhs <= hi
        return False
    except Exception:
        return False

def _match_rule(rule: dict, req: PolicyRequest) -> bool:
    # Schema (example):
    # {
    #   "id": "r1", "effect": "allow",
    #   "actions": ["read","write"],
    #   "conditions": [
    #       {"path":"subject.roles", "op":"any_in", "value":["admin","ops"]},
    #       {"path":"context.ip", "op":"in_cidr", "value":["10.0.0.0/8"]},
    #       {"path":"resource.type", "op":"in", "value":["dashboard","metrics"]},
    #       {"path":"context.time.hour", "op":"between", "value":[8,20]}
    #   ]
    # }
    actions: list[str] = rule.get("actions") or []
    if actions and req.action not in actions:
        return False

    # derived fields
    if "context" not in req.context:
        req_ctx = dict(req.context)
    else:
        req_ctx = dict(req.context["context"])
    # inject derived time breakdown
    ts = req.timestamp.astimezone(dt.timezone.utc)
    time_box = {"hour": ts.hour, "weekday": ts.isoweekday()}
    derived = {
        "subject": req.subject,
        "action": req.action,
        "resource": req.resource,
        "context": {**req.context, "time": time_box}
    }

    for cond in (rule.get("conditions") or []):
        path = cond.get("path")
        op = cond.get("op")
        val = cond.get("value")
        lhs = _dig(derived, path) if path else None
        if not _op_match(lhs, op, val):
            return False

    return True


# =========================
# Adapter
# =========================

class PolicyCoreAdapter:
    """
    Industrial Policy adapter (PDP facade) for ChronoWatch:
    - backends: local | opa | genius
    - deny-by-default
    - TTL cache
    - Circuit breaker for HTTP backends
    - Optional maintenance integration
    """
    def __init__(
        self,
        config: AdapterConfig | None = None,
        maintenance: MaintenanceManager | None = None,
        http_client: t.Any | None = None,  # httpx.AsyncClient, but kept soft-typed
    ):
        self.cfg = config or AdapterConfig.from_env()
        self.cache = _TTLCache()
        self.maintenance = maintenance or MaintenanceManager()
        self._cb = _CircuitBreaker()
        self._client = http_client  # if None, will create on demand

    # --------- Public API ---------

    async def is_allowed(self, req: PolicyRequest) -> bool:
        return (await self.evaluate(req)).allowed

    async def evaluate(self, req: PolicyRequest) -> PolicyDecision:
        start = dt.datetime.now(dt.timezone.utc)

        # Maintenance guard (safe degradation)
        if self.cfg.maintenance_deny_non_read:
            in_effect, _, _, _ = await self.maintenance.is_in_effect()
            if in_effect and req.action not in self.cfg.allow_actions_during_maintenance:
                dec = PolicyDecision(
                    effect=Effect.deny, reason="maintenance_window", backend="maintenance",
                    evidence={"action": req.action, "allowed_during_maintenance": list(self.cfg.allow_actions_during_maintenance)}
                )
                self._track(dec, start, backend="maintenance")
                return dec

        # Cache
        key = self._cache_key(req)
        cached = await self.cache.get(key)
        if cached:
            # Cache hit: update latency field for visibility (not re-cached)
            cached.latency_ms = (dt.datetime.now(dt.timezone.utc) - start).total_seconds() * 1000.0
            return cached

        # Dispatch
        backend = (self.cfg.backend or "local").lower()
        with _tracer.start_as_current_span(f"policy.evaluate.{backend}"):
            try:
                if backend == "local":
                    decision = await self._eval_local(req)
                elif backend == "opa":
                    decision = await self._eval_opa(req)
                elif backend == "genius":
                    decision = await self._eval_genius(req)
                else:
                    decision = PolicyDecision(effect=self.cfg.default_effect, reason="unknown_backend", backend=backend)
            except Exception as exc:
                # Fail-safe: deny by default
                decision = PolicyDecision(effect=self.cfg.default_effect, reason=f"backend_error:{type(exc).__name__}", backend=backend, evidence={"error": str(exc)})

        # Cache set
        await self.cache.set(key, decision, self.cfg.cache_ttl_seconds)
        self._track(decision, start, backend=decision.backend)
        return decision

    # --------- Backends ---------

    async def _eval_local(self, req: PolicyRequest) -> PolicyDecision:
        best_rule_id: str | None = None
        best_effect: Effect | None = None
        for rule in (self.cfg.local_rules or []):
            try:
                rid = rule.get("id")
                if _match_rule(rule, req):
                    effect = Effect(rule.get("effect", "allow"))
                    best_rule_id, best_effect = rid, effect
                    # First-match wins (typical)
                    break
            except Exception:
                continue
        if best_effect:
            return PolicyDecision(effect=best_effect, reason="local_rule_match", rule_id=best_rule_id, backend="local", evidence={"rule_id": best_rule_id})
        return PolicyDecision(effect=self.cfg.default_effect, reason="local_no_match", backend="local")

    async def _eval_opa(self, req: PolicyRequest) -> PolicyDecision:
        if self._cb.is_open():
            return PolicyDecision(effect=self.cfg.default_effect, reason="circuit_open", backend="opa")

        if not self.cfg.opa.url or not self.cfg.opa.query:
            return PolicyDecision(effect=self.cfg.default_effect, reason="opa_not_configured", backend="opa")

        try:
            import httpx  # type: ignore
        except Exception as e:  # pragma: no cover
            return PolicyDecision(effect=self.cfg.default_effect, reason="httpx_missing", backend="opa", evidence={"error": str(e)})

        client = self._client or httpx.AsyncClient(verify=self.cfg.opa.verify_ssl, timeout=self.cfg.timeout_seconds)
        headers = {"Content-Type": "application/json"}
        if self.cfg.opa.token:
            headers["Authorization"] = f"Bearer {self.cfg.opa.token}"

        # OPA data API expects {"input": ...}
        payload = {"input": req.dict()}
        url = f"{self.cfg.opa.url.rstrip('/')}/v1/data/{self.cfg.opa.query}"

        last_exc: Exception | None = None
        for attempt in range(1, self.cfg.retries + 2):
            try:
                # jitter to avoid herd
                await asyncio.sleep(random.uniform(0, self.cfg.jitter_ms / 1000.0))
                resp = await client.post(url, headers=headers, content=json.dumps(payload))
                if resp.status_code >= 500:
                    raise RuntimeError(f"OPA {resp.status_code}")
                if resp.status_code == 404:
                    return PolicyDecision(effect=self.cfg.default_effect, reason="opa_query_not_found", backend="opa")
                data = resp.json()
                # Flexible parsing: result can be bool, or object with fields
                result = data.get("result")
                if isinstance(result, bool):
                    eff = Effect.allow if result else Effect.deny
                    self._cb.record_success()
                    return PolicyDecision(effect=eff, reason="opa_bool", backend="opa", evidence={"raw": data})
                if isinstance(result, dict):
                    allow = bool(result.get("allow"))
                    reason = result.get("reason") or "opa_object"
                    obligations = result.get("obligations") or {}
                    rule_id = result.get("rule_id")
                    eff = Effect.allow if allow else Effect.deny
                    self._cb.record_success()
                    return PolicyDecision(effect=eff, reason=reason, rule_id=rule_id, backend="opa", obligations=obligations, evidence={"raw": data})
                # Fallback: unknown shape
                self._cb.record_success()
                return PolicyDecision(effect=self.cfg.default_effect, reason="opa_unknown_result", backend="opa", evidence={"raw": data})
            except Exception as exc:
                last_exc = exc
                self._cb.record_failure()
                if attempt > self.cfg.retries:
                    break
        return PolicyDecision(effect=self.cfg.default_effect, reason=f"opa_error:{type(last_exc).__name__}", backend="opa", evidence={"error": str(last_exc)})

    async def _eval_genius(self, req: PolicyRequest) -> PolicyDecision:
        if self._cb.is_open():
            return PolicyDecision(effect=self.cfg.default_effect, reason="circuit_open", backend="genius")
        if not self.cfg.genius.url:
            return PolicyDecision(effect=self.cfg.default_effect, reason="genius_not_configured", backend="genius")

        try:
            import httpx  # type: ignore
        except Exception as e:  # pragma: no cover
            return PolicyDecision(effect=self.cfg.default_effect, reason="httpx_missing", backend="genius", evidence={"error": str(e)})

        client = self._client or httpx.AsyncClient(verify=self.cfg.genius.verify_ssl, timeout=self.cfg.timeout_seconds)
        headers = {"Content-Type": "application/json"}
        if self.cfg.genius.token:
            headers["Authorization"] = f"Bearer {self.cfg.genius.token}"

        payload = req.dict()
        url = f"{self.cfg.genius.url.rstrip('/')}/v1/policy/evaluate"

        last_exc: Exception | None = None
        for attempt in range(1, self.cfg.retries + 2):
            try:
                await asyncio.sleep(random.uniform(0, self.cfg.jitter_ms / 1000.0))
                resp = await client.post(url, headers=headers, content=json.dumps(payload))
                if resp.status_code >= 500:
                    raise RuntimeError(f"GENIUS {resp.status_code}")
                if resp.status_code == 404:
                    return PolicyDecision(effect=self.cfg.default_effect, reason="genius_endpoint_not_found", backend="genius")
                data = resp.json()
                # Expected: {"effect":"allow|deny","reason":"...", "rule_id":"...", "obligations":{...}, "evidence":{...}}
                eff = data.get("effect", "deny")
                decision = PolicyDecision(
                    effect=Effect(eff) if eff in ("allow", "deny") else self.cfg.default_effect,
                    reason=data.get("reason", "genius_response"),
                    rule_id=data.get("rule_id"),
                    backend="genius",
                    obligations=data.get("obligations") or {},
                    evidence=data.get("evidence") or {"raw": data},
                )
                self._cb.record_success()
                return decision
            except Exception as exc:
                last_exc = exc
                self._cb.record_failure()
                if attempt > self.cfg.retries:
                    break
        return PolicyDecision(effect=self.cfg.default_effect, reason=f"genius_error:{type(last_exc).__name__}", backend="genius", evidence={"error": str(last_exc)})

    # --------- Internals ---------

    def _cache_key(self, req: PolicyRequest) -> str:
        # Normalize request for cache key (exclude timestamp seconds granularity to improve hit rate)
        base = req.dict()
        base["timestamp"] = req.timestamp.replace(microsecond=0).isoformat()
        raw = json.dumps(base, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _track(self, decision: PolicyDecision, start: dt.datetime, backend: str):
        decision.latency_ms = (dt.datetime.now(dt.timezone.utc) - start).total_seconds() * 1000.0
        _policy_decisions.labels(backend=backend, effect=decision.effect.value).inc()
        _policy_eval_latency.labels(backend=backend).observe(decision.latency_ms / 1000.0)


# =========================
# Factory helpers
# =========================

def build_default_adapter(
    config: AdapterConfig | None = None,
    maintenance: MaintenanceManager | None = None,
) -> PolicyCoreAdapter:
    """
    Convenience factory to be used by the service container.
    """
    return PolicyCoreAdapter(config=config or AdapterConfig.from_env(), maintenance=maintenance)
