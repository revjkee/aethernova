# path: oblivionvault-core/oblivionvault/policy/evaluator_rego.py
from __future__ import annotations

import asyncio
import json
import logging
import time
import hashlib
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set, Tuple, Callable, Sequence, Union

# -----------------------------
# Optional deps
# -----------------------------
try:
    # Pydantic v2 preferred
    from pydantic import BaseModel, Field, ConfigDict, ValidationError
except Exception:  # pragma: no cover
    class BaseModel:  # minimal fallback
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

        def model_dump(self) -> Dict[str, Any]:
            return dict(self.__dict__)

    def Field(default=None, **kwargs):  # type: ignore
        return default

    class ValidationError(Exception):  # type: ignore
        pass

    ConfigDict = dict  # type: ignore

try:
    import aiohttp  # type: ignore
    _AIOHTTP = True
except Exception:  # pragma: no cover
    _AIOHTTP = False

try:
    from opentelemetry import trace as ot_trace  # type: ignore
    _OT_TRACER = ot_trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _OT_TRACER = None  # type: ignore

# -----------------------------
# Logging
# -----------------------------
LOG = logging.getLogger("oblivionvault.policy.rego")
if not LOG.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
    LOG.addHandler(h)
LOG.setLevel(logging.INFO)

# -----------------------------
# Exceptions
# -----------------------------
class PolicyError(Exception):
    """Base policy error."""

class PolicyTimeout(PolicyError):
    """Operation exceeded allowed time."""

class PolicyUnavailable(PolicyError):
    """OPA backend unavailable or transient error."""

class PolicyAuthError(PolicyError):
    """Access not permitted by scopes/tenant."""

class PolicyCompileError(PolicyError):
    """Partial evaluation/compile error."""

class PolicyManagementError(PolicyError):
    """Policy upsert/delete error."""

class CircuitOpen(PolicyError):
    """Circuit breaker is open."""

# -----------------------------
# Models
# -----------------------------
class AccessContext(BaseModel):
    """Zero-Trust access context."""
    model_config = ConfigDict(extra="allow") if isinstance(ConfigDict, dict) else ConfigDict(extra="allow")  # type: ignore
    tenant_id: str = Field(..., description="Tenant identifier")
    principal_id: str = Field(..., description="Actor identifier")
    scopes: Set[str] = Field(default_factory=set, description="Granted scopes")
    trace_id: Optional[str] = Field(default=None, description="Correlation/trace id")

class DecisionResult(BaseModel):
    """OPA decision result."""
    model_config = ConfigDict(extra="forbid") if isinstance(ConfigDict, dict) else ConfigDict(extra="forbid")  # type: ignore
    ok: bool
    allow: Optional[bool] = None
    result: Any = None
    metrics: Optional[Dict[str, Any]] = None
    elapsed_ms: int = 0
    trace_id: Optional[str] = None
    source: str = "opa.http"

class CompileResult(BaseModel):
    """OPA /v1/compile result."""
    model_config = ConfigDict(extra="forbid") if isinstance(ConfigDict, dict) else ConfigDict(extra="forbid")  # type: ignore
    ok: bool
    result: Dict[str, Any]
    elapsed_ms: int
    trace_id: Optional[str] = None

# -----------------------------
# Retry policy & Circuit Breaker
# -----------------------------
class RetryPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid") if isinstance(ConfigDict, dict) else ConfigDict(extra="forbid")  # type: ignore
    max_attempts: int = 5
    initial_backoff_s: float = 0.1
    max_backoff_s: float = 2.0
    jitter_s: float = 0.05
    retry_on: Tuple[type, ...] = (PolicyUnavailable, PolicyTimeout)

    def next_backoff(self, attempt: int) -> float:
        base = min(self.max_backoff_s, self.initial_backoff_s * (2 ** (attempt - 1)))
        # bounded jitter by attempt hash
        return max(0.0, base + (self.jitter_s * ((hash(attempt) % 100) / 100.0 - 0.5)))

class CircuitBreaker:
    __slots__ = ("_lock", "_state", "_fail_cnt", "_opened_at",
                 "_failure_threshold", "_recovery_time_s",
                 "_half_open_need", "_half_open_ok")

    def __init__(self, failure_threshold: int = 5,
                 recovery_time_s: float = 5.0,
                 half_open_successes_needed: int = 2):
        self._lock = asyncio.Lock()
        self._state = "CLOSED"
        self._fail_cnt = 0
        self._opened_at = 0.0
        self._failure_threshold = failure_threshold
        self._recovery_time_s = recovery_time_s
        self._half_open_need = half_open_successes_needed
        self._half_open_ok = 0

    async def allow(self) -> None:
        async with self._lock:
            if self._state == "OPEN":
                if time.time() - self._opened_at >= self._recovery_time_s:
                    self._state = "HALF_OPEN"
                    self._half_open_ok = 0
                else:
                    raise CircuitOpen("circuit open")

    async def on_success(self) -> None:
        async with self._lock:
            if self._state == "HALF_OPEN":
                self._half_open_ok += 1
                if self._half_open_ok >= self._half_open_need:
                    self._state = "CLOSED"
                    self._fail_cnt = 0
                    self._opened_at = 0.0
            else:
                self._fail_cnt = 0

    async def on_failure(self) -> None:
        async with self._lock:
            self._fail_cnt += 1
            if self._fail_cnt >= self._failure_threshold:
                self._state = "OPEN"
                self._opened_at = time.time()

# -----------------------------
# TTL cache for decisions
# -----------------------------
class _TTLCache:
    def __init__(self, ttl_s: float = 60.0, max_entries: int = 10000):
        self._ttl_s = ttl_s
        self._max = max_entries
        self._store: Dict[str, Tuple[float, DecisionResult]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[DecisionResult]:
        async with self._lock:
            item = self._store.get(key)
            if not item:
                return None
            ts, val = item
            if (time.time() - ts) > self._ttl_s:
                self._store.pop(key, None)
                return None
            return val

    async def put(self, key: str, value: DecisionResult) -> None:
        async with self._lock:
            if len(self._store) >= self._max:
                oldest_key = min(self._store.items(), key=lambda kv: kv[1][0])[0]
                self._store.pop(oldest_key, None)
            self._store[key] = (time.time(), value)

# -----------------------------
# Utils
# -----------------------------
def _stable_json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

def _require_scopes(ctx: AccessContext, needed: Set[str]) -> None:
    missing = needed - set(ctx.scopes or set())
    if missing:
        raise PolicyAuthError(f"missing scopes: {sorted(missing)}")

class _TracerCtx:
    def __init__(self, name: str, attrs: Optional[Dict[str, Any]] = None):
        self._name = name
        self._attrs = attrs or {}
        self._span = None
    def __enter__(self):
        if _OT_TRACER:
            self._span = _OT_TRACER.start_span(self._name)
            for k, v in self._attrs.items():
                try:
                    self._span.set_attribute(k, v)
                except Exception:
                    pass
        return self
    def __exit__(self, exc_type, exc, tb):
        if self._span:
            if exc:
                try:
                    self._span.record_exception(exc)
                    self._span.set_attribute("error", True)
                except Exception:
                    pass
            try:
                self._span.end()
            except Exception:
                pass

async def _async_retry(
    func: Callable[[], Any],
    policy: RetryPolicy,
    timeout_s: Optional[float],
    breaker: Optional[CircuitBreaker],
    op_name: str,
    trace_attrs: Optional[Dict[str, Any]] = None,
) -> Any:
    attempt = 0
    with _TracerCtx(f"rego.{op_name}", trace_attrs):
        while True:
            attempt += 1
            if breaker:
                await breaker.allow()
            try:
                if timeout_s is not None:
                    return await asyncio.wait_for(func(), timeout=timeout_s)
                else:
                    return await func()
            except policy.retry_on as e:
                if attempt >= policy.max_attempts:
                    if breaker:
                        await breaker.on_failure()
                    LOG.warning("retry_exhausted op=%s attempts=%s err=%s", op_name, attempt, type(e).__name__)
                    raise
                backoff = policy.next_backoff(attempt)
                LOG.info("retry op=%s attempt=%s backoff=%.3f err=%s", op_name, attempt, backoff, type(e).__name__)
                await asyncio.sleep(backoff)
                continue
            except asyncio.TimeoutError as e:
                if attempt >= policy.max_attempts:
                    if breaker:
                        await breaker.on_failure()
                    raise PolicyTimeout(f"timeout for {op_name}") from e
                backoff = policy.next_backoff(attempt)
                LOG.info("retry_timeout op=%s attempt=%s backoff=%.3f", op_name, attempt, backoff)
                await asyncio.sleep(backoff)
                continue
            except CircuitOpen:
                raise
            except Exception as e:
                if breaker:
                    await breaker.on_failure()
                LOG.exception("non_retriable op=%s err=%s", op_name, type(e).__name__)
                raise

# -----------------------------
# Backend interface
# -----------------------------
class RegoBackend(ABC):
    @abstractmethod
    async def health(self) -> Dict[str, Any]:
        ...

    @abstractmethod
    async def evaluate(self, package_path: str, input_doc: Dict[str, Any], data_doc: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """POST /v1/data/<package_path> returns plain OPA JSON."""
        ...

    @abstractmethod
    async def compile(self, query: str, input_doc: Optional[Dict[str, Any]] = None, unknowns: Optional[List[str]] = None, data_doc: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """POST /v1/compile returns partial evaluation JSON."""
        ...

    @abstractmethod
    async def upsert_policy(self, policy_id: str, rego_source: str) -> None:
        """PUT /v1/policies/<id> with text/plain."""
        ...

    @abstractmethod
    async def delete_policy(self, policy_id: str) -> None:
        """DELETE /v1/policies/<id>."""
        ...

# -----------------------------
# HTTP client wrapper (aiohttp or stdlib fallback)
# -----------------------------
class _AsyncHttp:
    def __init__(self, base_url: str, headers: Optional[Dict[str, str]] = None, timeout_s: float = 10.0):
        self._base = base_url.rstrip("/")
        self._headers = headers or {}
        self._timeout = timeout_s
        self._session: Optional[aiohttp.ClientSession] = None if _AIOHTTP else None

    async def _ensure_session(self):
        if _AIOHTTP and self._session is None:
            self._session = aiohttp.ClientSession()

    async def close(self):
        if _AIOHTTP and self._session:
            await self._session.close()
            self._session = None

    async def request(self, method: str, path: str, *, params: Optional[Dict[str, Any]] = None,
                      json_body: Optional[Dict[str, Any]] = None,
                      headers: Optional[Dict[str, str]] = None,
                      expected: Tuple[int, ...] = (200,)) -> Dict[str, Any]:
        url = f"{self._base}{path}"
        hdrs = dict(self._headers)
        if headers:
            hdrs.update(headers)

        if _AIOHTTP:
            await self._ensure_session()
            assert self._session
            try:
                async with self._session.request(
                    method=method,
                    url=url,
                    params=params,
                    json=json_body,
                    headers=hdrs,
                    timeout=self._timeout
                ) as resp:
                    status = resp.status
                    text = await resp.text()
                    try:
                        data = json.loads(text) if text else {}
                    except Exception:
                        data = {"raw": text}
                    if status not in expected:
                        self._raise_http(status, data)
                    return data
            except asyncio.TimeoutError as e:
                raise PolicyTimeout(str(e)) from e
            except PolicyError:
                raise
            except Exception as e:
                raise PolicyUnavailable(str(e)) from e
        else:
            # Fallback: run blocking HTTP in a thread using urllib
            import urllib.request
            import urllib.error
            import urllib.parse

            def _do_blocking():
                try:
                    req_data = None
                    req_headers = hdrs.copy()
                    if json_body is not None:
                        req_data = json.dumps(json_body).encode("utf-8")
                        req_headers["Content-Type"] = "application/json"
                    if params:
                        q = urllib.parse.urlencode(params, doseq=True)
                        full = url + ("?" + q if q else "")
                    else:
                        full = url
                    req = urllib.request.Request(full, method=method, headers=req_headers, data=req_data)
                    with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                        status = resp.getcode()
                        text = resp.read().decode("utf-8") if resp.length != 0 else ""
                    try:
                        data = json.loads(text) if text else {}
                    except Exception:
                        data = {"raw": text}
                    if status not in expected:
                        self._raise_http(status, data)
                    return data
                except urllib.error.HTTPError as e:
                    try:
                        body = e.read().decode("utf-8")
                        data = json.loads(body)
                    except Exception:
                        data = {"raw": body}
                    self._raise_http(e.code, data)
                except urllib.error.URLError as e:
                    raise PolicyUnavailable(str(e)) from e

            try:
                return await asyncio.wait_for(asyncio.to_thread(_do_blocking), timeout=self._timeout + 1.0)
            except asyncio.TimeoutError as e:
                raise PolicyTimeout(str(e)) from e

    def _raise_http(self, status: int, data: Dict[str, Any]) -> None:
        msg = data.get("message") or data.get("error") or str(data)
        if status in (408,):
            raise PolicyTimeout(msg)
        if status in (429, 502, 503, 504):
            raise PolicyUnavailable(f"{status}: {msg}")
        if status in (400, 422):
            raise PolicyCompileError(f"{status}: {msg}")
        if status in (401, 403):
            raise PolicyAuthError(f"{status}: {msg}")
        if status in (404,):
            raise PolicyManagementError(f"{status}: {msg}")
        raise PolicyError(f"{status}: {msg}")

# -----------------------------
# OPA HTTP backend
# -----------------------------
class OPAHttpBackend(RegoBackend):
    def __init__(self, base_url: str = "http://127.0.0.1:8181", *, timeout_s: float = 10.0, headers: Optional[Dict[str, str]] = None):
        self._http = _AsyncHttp(base_url, headers=headers, timeout_s=timeout_s)

    async def close(self):
        await self._http.close()

    async def health(self) -> Dict[str, Any]:
        return await self._http.request("GET", "/health", expected=(200,))

    async def evaluate(self, package_path: str, input_doc: Dict[str, Any], data_doc: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        body: Dict[str, Any] = {"input": input_doc}
        if data_doc is not None:
            body["data"] = data_doc
        path = f"/v1/data/{package_path.strip('/')}"
        return await self._http.request("POST", path, json_body=body, expected=(200,))

    async def compile(self, query: str, input_doc: Optional[Dict[str, Any]] = None, unknowns: Optional[List[str]] = None, data_doc: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        body: Dict[str, Any] = {"query": query}
        if input_doc is not None:
            body["input"] = input_doc
        if unknowns is not None:
            body["unknowns"] = unknowns
        if data_doc is not None:
            body["data"] = data_doc
        return await self._http.request("POST", "/v1/compile", json_body=body, expected=(200,))

    async def upsert_policy(self, policy_id: str, rego_source: str) -> None:
        # OPA expects text/plain body for /v1/policies/<id>
        path = f"/v1/policies/{policy_id}"
        await self._http.request("PUT", path, headers={"Content-Type": "text/plain"}, json_body=None, expected=(204,))
        # We cannot send text via json_body; use a separate request
        # Fallback for text PUT:
        # Implement real text PUT since _AsyncHttp currently supports JSON only
        # Use internal method directly:
        if _AIOHTTP and isinstance(self._http._session, aiohttp.ClientSession):  # type: ignore
            async with self._http._session.put(self._http._base + path, data=rego_source.encode("utf-8"), headers={"Content-Type": "text/plain"}, timeout=self._http._timeout) as resp:
                if resp.status not in (200, 204):
                    text = await resp.text()
                    self._http._raise_http(resp.status, {"raw": text})
        else:
            import urllib.request
            import urllib.error
            import urllib.parse
            def _do_put_text():
                req = urllib.request.Request(
                    self._http._base + path,
                    method="PUT",
                    headers={"Content-Type": "text/plain"},
                    data=rego_source.encode("utf-8"),
                )
                with urllib.request.urlopen(req, timeout=self._http._timeout) as resp:
                    status = resp.getcode()
                    if status not in (200, 204):
                        raise PolicyManagementError(f"unexpected status {status}")
            await asyncio.to_thread(_do_put_text)

    async def delete_policy(self, policy_id: str) -> None:
        path = f"/v1/policies/{policy_id}"
        await self._http.request("DELETE", path, expected=(200, 204))

# -----------------------------
# Evaluator
# -----------------------------
class RegoPolicyEvaluator:
    """
    High-reliability OPA/Rego evaluator:
    - async, retries+breaker, timeouts, concurrency limit
    - TTL cache for evaluate()
    - partial evaluation via /v1/compile
    - policy management (upsert/delete)
    - Zero-Trust scopes
    - optional OpenTelemetry spans
    """
    def __init__(
        self,
        backend: Optional[RegoBackend] = None,
        *,
        retry_policy: Optional[RetryPolicy] = None,
        breaker: Optional[CircuitBreaker] = None,
        default_timeout_s: float = 5.0,
        max_concurrency: int = 128,
        decision_cache_ttl_s: float = 30.0,
    ):
        self._backend = backend or OPAHttpBackend()
        self._retry = retry_policy or RetryPolicy()
        self._breaker = breaker or CircuitBreaker()
        self._timeout = default_timeout_s
        self._sem = asyncio.Semaphore(max_concurrency)
        self._cache = _TTLCache(ttl_s=decision_cache_ttl_s)

    # ---------- Health ----------
    async def health_check(self, ctx: Optional[AccessContext] = None) -> Dict[str, Any]:
        async def _call():
            async with self._sem:
                return await self._backend.health()
        res = await _async_retry(_call, self._retry, self._timeout, self._breaker, "health", {"tenant": getattr(ctx, "tenant_id", None)})
        await self._breaker.on_success()
        return res

    # ---------- Evaluate ----------
    async def evaluate(
        self,
        ctx: AccessContext,
        *,
        package: str,
        rule: Optional[str] = None,
        input_doc: Optional[Dict[str, Any]] = None,
        data_doc: Optional[Dict[str, Any]] = None,
        timeout_s: Optional[float] = None,
        cache: bool = True,
    ) -> DecisionResult:
        _require_scopes(ctx, {"policy:evaluate"})

        input_doc = input_doc or {}
        package_path = _normalize_package_path(package, rule)
        cache_key = None
        if cache:
            cache_key = self._decision_cache_key(package_path, input_doc, data_doc, ctx)
            cached = await self._cache.get(cache_key)
            if cached:
                return cached

        started = time.perf_counter()
        async def _call():
            async with self._sem:
                return await self._backend.evaluate(package_path, input_doc, data_doc)

        raw = await _async_retry(
            _call,
            self._retry,
            timeout_s or self._timeout,
            self._breaker,
            "evaluate",
            {"tenant": ctx.tenant_id, "package": package_path}
        )

        await self._breaker.on_success()
        elapsed_ms = int((time.perf_counter() - started) * 1000)

        # OPA returns {"result": <any>} possibly with boolean allow at data.pkg.rule
        result_field = raw.get("result")
        allow: Optional[bool] = None
        if isinstance(result_field, dict) and "allow" in result_field:
            try:
                allow = bool(result_field["allow"])
            except Exception:
                allow = None
        elif isinstance(result_field, bool):
            allow = result_field

        decision = DecisionResult(
            ok=True,
            allow=allow,
            result=result_field,
            metrics=raw.get("metrics"),
            elapsed_ms=elapsed_ms,
            trace_id=ctx.trace_id,
            source=self._backend.__class__.__name__.lower(),
        )
        if cache and cache_key is not None:
            await self._cache.put(cache_key, decision)
        return decision

    # ---------- Partial compile ----------
    async def compile_partial(
        self,
        ctx: AccessContext,
        *,
        query: Optional[str] = None,
        package: Optional[str] = None,
        rule: Optional[str] = None,
        input_doc: Optional[Dict[str, Any]] = None,
        unknowns: Optional[List[str]] = None,
        data_doc: Optional[Dict[str, Any]] = None,
        timeout_s: Optional[float] = None,
    ) -> CompileResult:
        _require_scopes(ctx, {"policy:evaluate"})
        if not query:
            if not package or not rule:
                raise PolicyCompileError("Either query or (package+rule) must be provided")
            query = f"data.{package}.{rule} == true"

        started = time.perf_counter()
        async def _call():
            async with self._sem:
                return await self._backend.compile(query=query, input_doc=input_doc, unknowns=unknowns, data_doc=data_doc)

        raw = await _async_retry(
            _call,
            self._retry,
            timeout_s or self._timeout,
            self._breaker,
            "compile",
            {"tenant": ctx.tenant_id}
        )
        await self._breaker.on_success()
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return CompileResult(ok=True, result=raw.get("result", {}), elapsed_ms=elapsed_ms, trace_id=ctx.trace_id)

    # ---------- Policy management ----------
    async def upsert_policy(self, ctx: AccessContext, *, policy_id: str, rego_source: str, timeout_s: Optional[float] = None) -> None:
        _require_scopes(ctx, {"policy:manage"})
        async def _call():
            async with self._sem:
                return await self._backend.upsert_policy(policy_id, rego_source)
        await _async_retry(_call, self._retry, timeout_s or self._timeout, self._breaker, "policy.upsert", {"tenant": ctx.tenant_id, "policy_id": policy_id})
        await self._breaker.on_success()

    async def delete_policy(self, ctx: AccessContext, *, policy_id: str, timeout_s: Optional[float] = None) -> None:
        _require_scopes(ctx, {"policy:manage"})
        async def _call():
            async with self._sem:
                return await self._backend.delete_policy(policy_id)
        await _async_retry(_call, self._retry, timeout_s or self._timeout, self._breaker, "policy.delete", {"tenant": ctx.tenant_id, "policy_id": policy_id})
        await self._breaker.on_success()

    # ---------- Helpers ----------
    def _decision_cache_key(self, package_path: str, input_doc: Dict[str, Any], data_doc: Optional[Dict[str, Any]], ctx: AccessContext) -> str:
        h = hashlib.sha256()
        h.update(package_path.encode("utf-8"))
        h.update(b"|")
        h.update(_stable_json(input_doc).encode("utf-8"))
        h.update(b"|")
        h.update(_stable_json(data_doc or {}).encode("utf-8"))
        h.update(b"|")
        h.update(ctx.tenant_id.encode("utf-8"))
        return h.hexdigest()

def _normalize_package_path(package: str, rule: Optional[str]) -> str:
    # package like "authz.rbac", rule like "allow" -> "data/authz/rbac/allow"
    pkg = "data/" + package.strip(".").replace(".", "/")
    if rule:
        return f"{pkg}/{rule}"
    return pkg
