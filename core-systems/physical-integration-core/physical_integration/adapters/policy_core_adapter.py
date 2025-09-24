# physical-integration-core/physical_integration/adapters/policy_core_adapter.py
"""
Industrial Policy Core adapter for NeuroCity / physical-integration-core.

Features:
- Async PDP client (HTTP) with JWT(HMAC-SHA256) request signing (optional).
- Circuit breaker, exponential backoff retries, and TTL decision cache (LRU).
- Local fallback policy engine (rule-based) if PDP unavailable.
- Structured auditing to file/stdout and Prometheus metrics (optional).
- Strongly-typed Pydantic DTOs with strict validation and safe logging.

Environment (examples):
    POLICY_PDP_BASE_URL=https://policy-core.local
    POLICY_PDP_DECIDE_PATH=/v1/decision
    POLICY_JWT_HS256_SECRET=supersecret
    POLICY_JWT_ISS=physical-integration
    POLICY_JWT_AUD=policy-core
    POLICY_TIMEOUT_SEC=2.5
    POLICY_RETRIES=2
    POLICY_CIRCUIT_FAIL_THRESHOLD=5
    POLICY_CIRCUIT_RESET_SEC=15
    POLICY_CACHE_TTL_SEC=5
    POLICY_CACHE_MAX_ITEMS=5000
    POLICY_AUDIT_PATH=/var/log/neurocity/policy_audit.log
    POLICY_LOG_LEVEL=INFO
    METRICS_PORT=9309   # optional, if using prometheus_client

Dependencies:
    pydantic>=1.10
    httpx (optional but recommended for HTTP)
    prometheus_client (optional for metrics)

Run quick self-check:
    python -m physical_integration.adapters.policy_core_adapter
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import dataclasses
import datetime as dt
import hashlib
import hmac
import json
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    import httpx  # type: ignore
    _HTTPX = True
except Exception:
    _HTTPX = False

try:
    from pydantic import BaseModel, BaseSettings, Field, validator
except Exception as e:
    raise RuntimeError("pydantic>=1.10 is required for policy_core_adapter") from e

# Optional Prometheus metrics
try:
    from prometheus_client import Counter, Histogram, start_http_server  # type: ignore
    _PROM = True
except Exception:
    _PROM = False

    class _Noop:
        def __init__(self, *a, **k): ...
        def labels(self, *a, **k): return self
        def inc(self, *_): ...
        def observe(self, *_): ...
        def set(self, *_): ...
    Counter = Histogram = _Noop  # type: ignore
    def start_http_server(*a, **k): ...


# ------------------------ Logging ---------------------------------------------

def _configure_logger() -> logging.Logger:
    lvl = os.environ.get("POLICY_LOG_LEVEL", "INFO").upper()
    logger = logging.getLogger("adapters.policy_core")
    if not logger.handlers:
        h = logging.StreamHandler(sys.stdout)
        fmt = logging.Formatter("%(asctime)sZ %(levelname)s %(name)s %(message)s", "%Y-%m-%dT%H:%M:%S")
        h.setFormatter(fmt)
        logger.addHandler(h)
        logger.propagate = False
    logger.setLevel(getattr(logging, lvl, logging.INFO))
    return logger

log = _configure_logger()

def _truncate(s: str, limit: int = 600) -> str:
    return s if len(s) <= limit else (s[:limit] + "...[truncated]")


# ------------------------ Metrics --------------------------------------------

_policy_req = Counter("policy_requests_total", "Policy requests by outcome",)
_policy_cache_hits = Counter("policy_cache_hits_total", "Policy cache hits")
_policy_errors = Counter("policy_errors_total", "Policy errors")
_policy_latency = Histogram(
    "policy_latency_seconds", "Policy decision latency seconds",
    buckets=(0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0)
)


# ------------------------ Settings -------------------------------------------

class PolicyAdapterSettings(BaseSettings):
    pdp_base_url: str = Field(..., env="POLICY_PDP_BASE_URL")
    pdp_decide_path: str = Field(default="/v1/decision", env="POLICY_PDP_DECIDE_PATH")
    timeout_sec: float = Field(default=2.5, env="POLICY_TIMEOUT_SEC")
    retries: int = Field(default=2, env="POLICY_RETRIES")
    backoff_base_sec: float = Field(default=0.2, env="POLICY_BACKOFF_BASE")
    circuit_fail_threshold: int = Field(default=5, env="POLICY_CIRCUIT_FAIL_THRESHOLD")
    circuit_reset_sec: float = Field(default=15.0, env="POLICY_CIRCUIT_RESET_SEC")

    cache_ttl_sec: float = Field(default=5.0, env="POLICY_CACHE_TTL_SEC")
    cache_max_items: int = Field(default=5000, env="POLICY_CACHE_MAX_ITEMS")

    jwt_hs256_secret: Optional[str] = Field(default=None, env="POLICY_JWT_HS256_SECRET")
    jwt_iss: Optional[str] = Field(default="physical-integration", env="POLICY_JWT_ISS")
    jwt_aud: Optional[str] = Field(default="policy-core", env="POLICY_JWT_AUD")
    jwt_kid: Optional[str] = Field(default=None, env="POLICY_JWT_KID")
    jwt_exp_sec: int = Field(default=60, env="POLICY_JWT_EXP_SEC")

    audit_path: Optional[str] = Field(default=None, env="POLICY_AUDIT_PATH")
    audit_stdout: bool = Field(default=False, env="POLICY_AUDIT_STDOUT")

    metrics_port: Optional[int] = Field(default=None, env="METRICS_PORT")

    class Config:
        env_file = os.environ.get("POLICY_ENV", ".env")
        env_file_encoding = "utf-8"
        case_sensitive = False


# ------------------------ DTOs ------------------------------------------------

class Subject(BaseModel):
    id: str
    roles: List[str] = Field(default_factory=list)
    attrs: Dict[str, Union[str, int, float, bool]] = Field(default_factory=dict)


class Resource(BaseModel):
    id: str
    type: str
    attrs: Dict[str, Union[str, int, float, bool]] = Field(default_factory=dict)


class Action(BaseModel):
    name: str
    method: Optional[str] = None
    attrs: Dict[str, Union[str, int, float, bool]] = Field(default_factory=dict)


class Context(BaseModel):
    ip: Optional[str] = None
    device_id: Optional[str] = None
    location: Optional[str] = None
    time_utc: Optional[str] = None  # ISO8601
    attrs: Dict[str, Union[str, int, float, bool]] = Field(default_factory=dict)

    @validator("time_utc", pre=True, always=True)
    def _default_time(cls, v):
        if v:
            return v
        return dt.datetime.now(dt.timezone.utc).isoformat()


class Obligation(BaseModel):
    key: str
    value: Union[str, int, float, bool, Dict[str, Any], List[Any]]


class Decision(BaseModel):
    effect: str  # Permit | Deny | Indeterminate | NotApplicable
    reason: Optional[str] = None
    obligations: List[Obligation] = Field(default_factory=list)
    policy_id: Optional[str] = None


class PDPResponse(BaseModel):
    decision: Decision
    # option to return any opaque fields
    extras: Dict[str, Any] = Field(default_factory=dict)


class AuditRecord(BaseModel):
    ts_utc: str
    subject: Subject
    resource: Resource
    action: Action
    context: Context
    decision: Decision
    from_cache: bool = False
    source: str = "pdp"  # pdp|fallback|cache
    latency_ms: float = 0.0


# ------------------------ Utils ----------------------------------------------

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def _jwt_hs256(secret: str, claims: Dict[str, Any], kid: Optional[str] = None) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    if kid:
        header["kid"] = kid
    now = int(time.time())
    if "iat" not in claims:
        claims["iat"] = now
    if "exp" not in claims and "exp_sec" in claims:
        claims["exp"] = now + int(claims.pop("exp_sec"))
    header_b64 = _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    payload_b64 = _b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    signing = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = hmac.new(secret.encode("utf-8"), signing, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url(sig)}"

def _norm_json(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)

def _hash_key(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


# ------------------------ TTL LRU Cache --------------------------------------

class _TTLCache:
    def __init__(self, ttl_sec: float, max_items: int):
        self.ttl = float(ttl_sec)
        self.max = int(max_items)
        self._store: Dict[str, Tuple[float, Any]] = {}
        self._order: List[str] = []

    def get(self, key: str) -> Optional[Any]:
        rec = self._store.get(key)
        if not rec:
            return None
        exp, val = rec
        if time.time() > exp:
            self.delete(key)
            return None
        # move to end (LRU)
        if key in self._order:
            self._order.remove(key)
        self._order.append(key)
        return val

    def set(self, key: str, val: Any) -> None:
        exp = time.time() + self.ttl
        self._store[key] = (exp, val)
        if key in self._order:
            self._order.remove(key)
        self._order.append(key)
        # evict
        while len(self._order) > self.max:
            old = self._order.pop(0)
            self._store.pop(old, None)

    def delete(self, key: str) -> None:
        self._store.pop(key, None)
        with contextlib.suppress(ValueError):
            self._order.remove(key)

    def clear(self) -> None:
        self._store.clear()
        self._order.clear()


# ------------------------ Circuit Breaker -------------------------------------

class _CircuitBreaker:
    def __init__(self, fail_threshold: int, reset_sec: float):
        self.fail_threshold = int(fail_threshold)
        self.reset_sec = float(reset_sec)
        self.state = "CLOSED"
        self.fail_count = 0
        self.opened_at = 0.0

    def allow(self) -> bool:
        if self.state == "OPEN":
            if (time.time() - self.opened_at) >= self.reset_sec:
                self.state = "HALF_OPEN"
                return True
            return False
        return True

    def record_success(self) -> None:
        self.state = "CLOSED"
        self.fail_count = 0
        self.opened_at = 0.0

    def record_failure(self) -> None:
        self.fail_count += 1
        if self.fail_count >= self.fail_threshold:
            self.state = "OPEN"
            self.opened_at = time.time()


# ------------------------ Local Policy (fallback) -----------------------------

class LocalPolicyRule(BaseModel):
    effect: str  # Permit|Deny
    match: Dict[str, Any]  # simple eq/one-of comparisons over subject/role/resource.type/action.name/context.device_id etc.
    obligations: List[Obligation] = Field(default_factory=list)

class LocalPolicy(BaseModel):
    rules: List[LocalPolicyRule] = Field(default_factory=list)

    def evaluate(self, subj: Subject, res: Resource, act: Action, ctx: Context) -> Decision:
        # very simple matcher: dotted paths, value or list-of-values means one-of
        env = {
            "subject": subj.dict(),
            "resource": res.dict(),
            "action": act.dict(),
            "context": ctx.dict(),
        }
        for rule in self.rules:
            ok = True
            for path, expected in rule.match.items():
                cur: Any = env
                for part in path.split("."):
                    if not isinstance(cur, dict) or part not in cur:
                        ok = False
                        break
                    cur = cur[part]
                if not ok:
                    break
                if isinstance(expected, list):
                    ok = cur in expected
                else:
                    ok = cur == expected
                if not ok:
                    break
            if ok:
                return Decision(effect=rule.effect, obligations=rule.obligations, reason="local-policy")
        return Decision(effect="NotApplicable", reason="no-local-rule")


# ------------------------ Audit Logger ----------------------------------------

class _AsyncAuditLogger:
    def __init__(self, path: Optional[str], to_stdout: bool):
        self.path = path
        self.to_stdout = to_stdout
        self._q: asyncio.Queue[AuditRecord] = asyncio.Queue(maxsize=10000)
        self._task: Optional[asyncio.Task] = None
        self._shutdown = False

    async def start(self) -> None:
        if self._task:
            return
        self._task = asyncio.create_task(self._run(), name="policy_audit_writer")

    async def log(self, rec: AuditRecord) -> None:
        try:
            await self._q.put(rec)
        except asyncio.QueueFull:
            # drop silently to avoid blocking policy path
            pass

    async def _run(self) -> None:
        fp = None
        if self.path:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            fp = open(self.path, "a", encoding="utf-8")
        try:
            while not self._shutdown:
                rec = await self._q.get()
                line = _norm_json(rec.dict()) + "\n"
                if fp:
                    fp.write(line)
                    fp.flush()
                if self.to_stdout:
                    sys.stdout.write(line)
        except asyncio.CancelledError:
            pass
        finally:
            if fp:
                fp.close()

    async def stop(self) -> None:
        self._shutdown = True
        if self._task and not self._task.done():
            self._task.cancel()
            with contextlib.suppress(Exception):
                await self._task


# ------------------------ Adapter ---------------------------------------------

class PolicyCoreAdapter:
    """
    High-reliability adapter to Policy Core (PDP) with caching, breaker and fallback.

    Usage:
        settings = PolicyAdapterSettings(pdp_base_url="https://pdp", ...)
        adapter = PolicyCoreAdapter(settings)
        await adapter.start()
        decision = await adapter.check_access(subject, resource, action, context)
        await adapter.close()
    """
    def __init__(self, settings: PolicyAdapterSettings, local_policy: Optional[LocalPolicy] = None, logger: Optional[logging.Logger] = None):
        self.settings = settings
        self.log = logger or log
        self.cache = _TTLCache(ttl_sec=settings.cache_ttl_sec, max_items=settings.cache_max_items)
        self.breaker = _CircuitBreaker(settings.circuit_fail_threshold, settings.circuit_reset_sec)
        self.local_policy = local_policy or LocalPolicy(rules=[])
        self.audit = _AsyncAuditLogger(settings.audit_path, settings.audit_stdout)
        self._client: Optional[httpx.AsyncClient] = None if _HTTPX else None
        self._metrics_started = False

    async def start(self) -> None:
        if _PROM and self.settings.metrics_port and not self._metrics_started:
            start_http_server(self.settings.metrics_port)
            self._metrics_started = True
            self.log.info("Prometheus metrics server started", extra={"port": self.settings.metrics_port})
        await self.audit.start()
        if _HTTPX and self._client is None:
            self._client = httpx.AsyncClient(base_url=self.settings.pdp_base_url, timeout=self.settings.timeout_sec, http2=True)

    async def close(self) -> None:
        await self.audit.stop()
        if self._client:
            await self._client.aclose()
            self._client = None

    def _build_input(self, subject: Subject, resource: Resource, action: Action, context: Context) -> Dict[str, Any]:
        return {
            "subject": subject.dict(),
            "resource": resource.dict(),
            "action": action.dict(),
            "context": context.dict(),
            "timestamp": _now_iso(),
        }

    def _cache_key(self, payload: Dict[str, Any]) -> str:
        return _hash_key(_norm_json(payload))

    def _auth_header(self) -> Dict[str, str]:
        if not self.settings.jwt_hs256_secret:
            return {}
        claims = {
            "iss": self.settings.jwt_iss,
            "aud": self.settings.jwt_aud,
            "exp_sec": self.settings.jwt_exp_sec,
        }
        token = _jwt_hs256(self.settings.jwt_hs256_secret, claims, kid=self.settings.jwt_kid)
        return {"Authorization": f"Bearer {token}"}

    async def _request_pdp(self, payload: Dict[str, Any]) -> PDPResponse:
        if not _HTTPX:
            raise RuntimeError("httpx is not installed; PDP calls are unavailable")
        assert self._client is not None, "Adapter not started"
        url = self.settings.pdp_decide_path
        headers = {"Content-Type": "application/json"}
        headers.update(self._auth_header())

        backoff = self.settings.backoff_base_sec
        last_exc: Optional[Exception] = None
        for attempt in range(self.settings.retries + 1):
            if not self.breaker.allow():
                raise RuntimeError("Circuit breaker OPEN: PDP temporarily blocked")
            try:
                t0 = time.time()
                resp = await self._client.post(url, content=_norm_json(payload).encode("utf-8"), headers=headers)
                dt_ms = (time.time() - t0) * 1000.0
                if 200 <= resp.status_code < 300:
                    data = resp.json()
                    # Validate & normalize
                    decision = Decision(**data.get("decision", {}))
                    extras = data.get("extras", {})
                    return PDPResponse(decision=decision, extras=extras)
                else:
                    last_exc = RuntimeError(f"PDP HTTP {resp.status_code}: {_truncate(resp.text)}")
                    self.breaker.record_failure()
            except Exception as e:
                last_exc = e
                self.breaker.record_failure()

            # backoff
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2.0, 5.0)

        raise last_exc if last_exc else RuntimeError("Unknown PDP error")

    async def evaluate_policy(self, input_payload: Dict[str, Any]) -> PDPResponse:
        """
        Generic evaluate call when caller формирует payload самостоятельно.
        Кеширование не используется по умолчанию (слишком вариативные входы).
        """
        t0 = time.time()
        try:
            resp = await self._request_pdp(input_payload)
            _policy_latency.observe(time.time() - t0)
            _policy_req.inc()
            return resp
        except Exception as e:
            _policy_errors.inc()
            self.log.error("evaluate_policy failed", extra={"error": repr(e)})
            # Fallback not defined for generic evaluate — пробрасываем
            raise

    async def check_access(self, subject: Subject, resource: Resource, action: Action, context: Context) -> Decision:
        """
        Main entrypoint: PDP decision with cache and fallback.
        """
        payload = self._build_input(subject, resource, action, context)
        key = self._cache_key(payload)

        # Cache first
        cached = self.cache.get(key)
        if cached:
            _policy_cache_hits.inc()
            dec = Decision(**cached["decision"])
            # audit
            await self.audit.log(AuditRecord(
                ts_utc=_now_iso(),
                subject=subject, resource=resource, action=action, context=context,
                decision=dec, from_cache=True, source="cache", latency_ms=0.0
            ))
            return dec

        # Try PDP
        t0 = time.time()
        try:
            resp = await self._request_pdp(payload)
            elapsed = (time.time() - t0)
            _policy_latency.observe(elapsed)
            _policy_req.inc()
            # Cache only deterministic outcomes
            self.cache.set(key, {"decision": resp.decision.dict()})
            # audit
            await self.audit.log(AuditRecord(
                ts_utc=_now_iso(),
                subject=subject, resource=resource, action=action, context=context,
                decision=resp.decision, from_cache=False, source="pdp", latency_ms=elapsed * 1000.0
            ))
            # reset breaker on success
            self.breaker.record_success()
            return resp.decision
        except Exception as e:
            _policy_errors.inc()
            self.log.warning("PDP request failed; fallback engaged", extra={"error": repr(e)})

        # Fallback to local policy
        t1 = time.time()
        dec = self.local_policy.evaluate(subject, resource, action, context)
        elapsed = (time.time() - t1)
        # audit
        await self.audit.log(AuditRecord(
            ts_utc=_now_iso(),
            subject=subject, resource=resource, action=action, context=context,
            decision=dec, from_cache=False, source="fallback", latency_ms=elapsed * 1000.0
        ))
        # No cache for NotApplicable to avoid masking future PDP truth
        if dec.effect in ("Permit", "Deny"):
            self.cache.set(key, {"decision": dec.dict()})
        return dec

    def preload_policies(self, policy: LocalPolicy) -> None:
        """
        Replace or extend local policy at runtime (hot load).
        """
        self.local_policy = policy


# ------------------------ __main__ (smoke test) -------------------------------

if __name__ == "__main__":
    async def _demo():
        settings = PolicyAdapterSettings(
            pdp_base_url=os.environ.get("POLICY_PDP_BASE_URL", "http://127.0.0.1:8080"),
            pdp_decide_path=os.environ.get("POLICY_PDP_DECIDE_PATH", "/v1/decision"),
            jwt_hs256_secret=os.environ.get("POLICY_JWT_HS256_SECRET"),
            metrics_port=int(os.environ.get("METRICS_PORT", "0") or 0) or None,
        )
        adapter = PolicyCoreAdapter(
            settings=settings,
            local_policy=LocalPolicy(rules=[
                LocalPolicyRule(effect="Permit", match={"subject.roles": ["operator", "admin"], "action.name": "read"}),
                LocalPolicyRule(effect="Deny", match={"resource.type": "camera", "action.name": "delete"}),
            ])
        )
        await adapter.start()

        subj = Subject(id="u-123", roles=["operator"], attrs={"dept": "plantA"})
        res = Resource(id="cam-07", type="camera", attrs={"site": "A"})
        act = Action(name="read")
        ctx = Context(ip="10.0.0.5", device_id="gw-01")

        try:
            dec = await adapter.check_access(subj, res, act, ctx)
            print("[decision]", dec.dict())
        finally:
            await adapter.close()

    asyncio.run(_demo())
