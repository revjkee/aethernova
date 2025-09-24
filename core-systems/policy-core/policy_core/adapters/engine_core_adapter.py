# policy_core/adapters/engine_core_adapter.py
"""
Industrial-grade Engine Core Adapter for policy-core PDP.

Responsibilities:
- Fetch policies from PolicyRepository by a flexible selector.
- Compile policy documents into executable PolicyLike via pluggable PolicyCompiler.
- Cache compiled policies in memory (TTL + LRU) to avoid recompilation overhead.
- Enrich request context via AsyncAttributeProvider (PIP).
- Evaluate policies with PDP combiner (async/sync) under concurrency/timeout controls.
- Optionally publish obligations/advice through ObligationSink after decision.
- Structured logging with per-request trace id (contextvar).
- Limits (max policies per request) to mitigate abuse.

No third-party dependencies beyond policy_core.* and Python 3.11 stdlib.
"""

from __future__ import annotations

import abc
import asyncio
import contextvars
import dataclasses
import logging
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    Union,
    runtime_checkable,
)

# ---- PDP imports -------------------------------------------------------------
from policy_core.pdp.combiner import (
    acombine,
    combine,
    Context,
    Decision,
    PolicyLike,
)
from policy_core.store.repository import (
    Page,
    Policy,
    PolicyRepository,
    SearchQuery,
    NotFound,
    AlreadyExists,
    VersionConflict,
    StoreError,
)

# ---- Logging / tracing -------------------------------------------------------

_LOG = logging.getLogger("policy_core.adapters.engine_core_adapter")
if not _LOG.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] trace=%(trace_id)s %(message)s"))
    _LOG.addHandler(_h)
    _LOG.setLevel(logging.INFO)

_trace_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("trace_id", default="")

def _trace_id() -> str:
    tid = _trace_id_ctx.get()
    if not tid:
        tid = uuid.uuid4().hex
        _trace_id_ctx.set(tid)
    return tid

class _LogExtra(dict):
    def __init__(self, **kw: Any) -> None:
        super().__init__(**kw)
        self.setdefault("trace_id", _trace_id())

def _now_ms() -> int:
    return int(time.time() * 1000)


# ---- Public errors -----------------------------------------------------------

class AdapterError(RuntimeError): ...
class CompilationError(AdapterError): ...
class EvaluationError(AdapterError): ...
class LimitsExceeded(AdapterError): ...


# ---- Contracts: Compiler / PIP / Obligations --------------------------------

@runtime_checkable
class PolicyCompiler(Protocol):
    """
    Compiles policy document into executable PolicyLike.
    Implementations may parse JSON/YAML/XACML/Rego/DSL and produce a callable or Evaluable.
    """
    def can_compile(self, policy: Policy) -> bool: ...
    async def compile(self, policy: Policy) -> PolicyLike: ...


@runtime_checkable
class AsyncAttributeProvider(Protocol):
    """
    Enriches evaluation context with external attributes (PIP).
    Called once per request prior to evaluation.
    """
    async def enrich(self, context: Context, *, tenant_id: str) -> Context: ...


class NullAttributeProvider:
    async def enrich(self, context: Context, *, tenant_id: str) -> Context:
        return dict(context)  # copy-for-safety


@runtime_checkable
class ObligationSink(Protocol):
    """
    Receives obligations/advice after a decision is made.
    Useful for logging, notifications, or side-effects (out of band).
    """
    async def publish(self, decision: Decision, *, tenant_id: str) -> None: ...


class NullObligationSink:
    async def publish(self, decision: Decision, *, tenant_id: str) -> None:
        return None


# ---- Compilation cache (in-memory TTL + LRU) ---------------------------------

class _CacheItem:
    __slots__ = ("value", "expires_at_ms")
    def __init__(self, value: PolicyLike, ttl_seconds: int) -> None:
        self.value = value
        self.expires_at_ms = _now_ms() + max(0, ttl_seconds) * 1000

    def valid(self) -> bool:
        return _now_ms() <= self.expires_at_ms


class CompileCache(Protocol):
    async def get(self, key: str) -> Optional[PolicyLike]: ...
    async def set(self, key: str, value: PolicyLike, ttl_seconds: int) -> None: ...
    async def delete(self, key: str) -> None: ...
    async def size(self) -> int: ...


class InMemoryTTLCache(CompileCache):
    """
    Thread-safe (async) in-memory TTL cache with LRU eviction.
    Stores callables/objects (not serializable).
    """
    def __init__(self, *, capacity: int = 10_000) -> None:
        self._cap = int(max(1, capacity))
        self._lock = asyncio.Lock()
        self._data: OrderedDict[str, _CacheItem] = OrderedDict()

    async def _evict_if_needed(self) -> None:
        # remove expired
        dead: List[str] = [k for k, v in self._data.items() if not v.valid()]
        for k in dead:
            self._data.pop(k, None)
        # LRU eviction
        while len(self._data) > self._cap:
            self._data.popitem(last=False)

    async def get(self, key: str) -> Optional[PolicyLike]:
        async with self._lock:
            itm = self._data.get(key)
            if not itm:
                return None
            if not itm.valid():
                self._data.pop(key, None)
                return None
            # mark as recently used
            self._data.move_to_end(key, last=True)
            return itm.value

    async def set(self, key: str, value: PolicyLike, ttl_seconds: int) -> None:
        async with self._lock:
            self._data[key] = _CacheItem(value, ttl_seconds)
            self._data.move_to_end(key, last=True)
            await self._evict_if_needed()

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._data.pop(key, None)

    async def size(self) -> int:
        async with self._lock:
            return len(self._data)


# ---- Selection and options ---------------------------------------------------

@dataclass(slots=True, frozen=True)
class PolicySelector:
    """
    Flexible policy selection for evaluation.
    - If `ids` provided, repository.batch_get is used.
    - Otherwise a search query is built from other fields.
    """
    tenant_id: str
    ids: Optional[Sequence[str]] = None
    types: Optional[Sequence[str]] = None
    is_active: Optional[bool] = True
    text: Optional[str] = None
    tag_any: Optional[Sequence[str]] = None
    tag_all: Optional[Sequence[str]] = None


@dataclass(slots=True)
class EngineOptions:
    algorithm: str = "permit-overrides"
    merge_obligations: bool = True
    max_policies: int = 1000
    concurrency: int = 16
    timeout_per_policy: Optional[float] = None  # seconds
    compile_cache_ttl_seconds: int = 900
    compile_cache_capacity: int = 10000
    # When search is used (ids is None)
    search_page_size: int = 500
    search_order_by: str = "id"
    search_desc: bool = False


# ---- Default sample compiler (for tests/dev only) ----------------------------

class MinimalDefaultCompiler(PolicyCompiler):
    """
    Minimalistic compiler for testing:
    Expects policy.document to contain {"effect": "permit" | "deny" | "not_applicable"}.
    """
    def can_compile(self, policy: Policy) -> bool:
        doc = policy.document or {}
        return isinstance(doc, dict) and "effect" in doc

    async def compile(self, policy: Policy) -> PolicyLike:
        effect_raw = str(policy.document.get("effect", "")).strip().lower()

        from policy_core.pdp.combiner import Decision, Effect  # local import to avoid cycles

        def _call(ctx: Context) -> Decision:
            if effect_raw == "permit":
                return Decision(effect=Effect.PERMIT)
            if effect_raw == "deny":
                return Decision(effect=Effect.DENY)
            if effect_raw == "not_applicable":
                return Decision(effect=Effect.NOT_APPLICABLE)
            return Decision(effect=Effect.INDETERMINATE, errors=[f"unknown effect {effect_raw}"])
        return _call


# ---- Adapter ----------------------------------------------------------------

@dataclass(slots=True)
class EngineCoreAdapter:
    """
    High-level facade over PolicyRepository + Compiler + PDP Combiner.
    """
    repository: PolicyRepository
    compiler_chain: Sequence[PolicyCompiler] = field(default_factory=lambda: (MinimalDefaultCompiler(),))
    attribute_provider: AsyncAttributeProvider = field(default_factory=NullAttributeProvider)
    obligation_sink: ObligationSink = field(default_factory=NullObligationSink)
    options: EngineOptions = field(default_factory=EngineOptions)
    compile_cache: CompileCache = field(default_factory=lambda: InMemoryTTLCache(capacity=10_000))

    # ------------- Public API -------------

    async def evaluate_async(self, selector: PolicySelector, context: Context) -> Decision:
        """
        Full async path: fetch → compile (cached) → PIP enrich → acombine → publish obligations.
        """
        trace = _trace_id()
        t0 = _now_ms()
        _LOG.info("evaluate_async start tenant=%s algorithm=%s", selector.tenant_id, self.options.algorithm, extra=_LogExtra())

        # 1) select policies
        policies = await self._select_policies(selector)
        if not policies:
            from policy_core.pdp.combiner import Decision, Effect
            d = Decision(effect=Effect.NOT_APPLICABLE, attributes={"reason": "no_policies"})
            await self._obligations_safe(d, selector.tenant_id)
            return d

        # 2) compile with cache
        compiled = await self._compile_many(policies)

        # 3) PIP enrich
        enriched = await self._enrich_safe(context, selector.tenant_id)

        # 4) evaluate with PDP
        mapping: Dict[str, PolicyLike] = {p.id: c for p, c in compiled}
        decision = await acombine(
            self.options.algorithm,
            mapping,
            enriched,
            concurrency=self.options.concurrency,
            timeout_per_policy=self.options.timeout_per_policy,
            merge_obligations=self.options.merge_obligations,
        )

        # 5) publish obligations (best-effort)
        await self._obligations_safe(decision, selector.tenant_id)

        # 6) telemetry
        decision.attributes.setdefault("trace_id", trace)
        decision.attributes["engine_latency_ms"] = _now_ms() - t0
        decision.attributes["policies_evaluated"] = len(mapping)
        _LOG.info(
            "evaluate_async end effect=%s policies=%s latency_ms=%s",
            getattr(decision.effect, "name", str(decision.effect)),
            len(mapping),
            decision.attributes["engine_latency_ms"],
            extra=_LogExtra(),
        )
        return decision

    def evaluate_sync(self, selector: PolicySelector, context: Context) -> Decision:
        """
        Sync path wrapper. Uses synchronous PDP combine.
        """
        trace = _trace_id()
        t0 = _now_ms()
        _LOG.info("evaluate_sync start tenant=%s algorithm=%s", selector.tenant_id, self.options.algorithm, extra=_LogExtra())

        policies = asyncio.run(self._select_policies(selector))
        if not policies:
            from policy_core.pdp.combiner import Decision, Effect
            d = Decision(effect=Effect.NOT_APPLICABLE, attributes={"reason": "no_policies"})
            asyncio.run(self._obligations_safe(d, selector.tenant_id))
            return d

        compiled = asyncio.run(self._compile_many(policies))
        enriched = asyncio.run(self._enrich_safe(context, selector.tenant_id))
        mapping: Dict[str, PolicyLike] = {p.id: c for p, c in compiled}

        decision = combine(
            self.options.algorithm,
            mapping,
            enriched,
            merge_obligations=self.options.merge_obligations,
        )
        asyncio.run(self._obligations_safe(decision, selector.tenant_id))

        decision.attributes.setdefault("trace_id", trace)
        decision.attributes["engine_latency_ms"] = _now_ms() - t0
        decision.attributes["policies_evaluated"] = len(mapping)
        _LOG.info(
            "evaluate_sync end effect=%s policies=%s latency_ms=%s",
            getattr(decision.effect, "name", str(decision.effect)),
            len(mapping),
            decision.attributes["engine_latency_ms"],
            extra=_LogExtra(),
        )
        return decision

    async def warmup_async(self, tenant_id: str, ids: Sequence[str]) -> int:
        """
        Pre-compile and cache policies by ids. Returns number cached.
        """
        if not ids:
            return 0
        fetched = await self.repository.batch_get(tenant_id, ids)
        return await self._compile_many(list(fetched.values()), store_only=True)

    # ------------- Internals --------------

    async def _select_policies(self, selector: PolicySelector) -> List[Policy]:
        """
        Select policies by ids or by search. Enforce limits.
        """
        pols: List[Policy] = []
        # by ids
        if selector.ids:
            if len(selector.ids) > self.options.max_policies:
                raise LimitsExceeded("ids exceed max_policies")
            items = await self.repository.batch_get(selector.tenant_id, selector.ids)
            pols = list(items.values())
        else:
            # paginated search
            page = Page(
                limit=min(self.options.search_page_size, self.options.max_policies),
                offset=0,
                order_by=self.options.search_order_by,
                desc=self.options.search_desc,
            )
            q = SearchQuery(
                tenant_id=selector.tenant_id,
                ids=None,
                types=selector.types,
                is_active=selector.is_active,
                text=selector.text,
                tag_any=selector.tag_any,
                tag_all=selector.tag_all,
            )
            total_collected = 0
            while True:
                items, total = await self.repository.search(q, page)
                pols.extend(items)
                total_collected += len(items)
                if total_collected >= self.options.max_policies:
                    _LOG.warning("search truncated at max_policies=%s", self.options.max_policies, extra=_LogExtra())
                    pols = pols[: self.options.max_policies]
                    break
                if len(items) < page.limit:
                    break
                page.offset += page.limit

        # final guard
        if len(pols) > self.options.max_policies:
            pols = pols[: self.options.max_policies]
        return pols

    async def _compile_many(self, policies: List[Policy], *, store_only: bool = False) -> Union[List[Tuple[Policy, PolicyLike]], int]:
        """
        Compile list of policies using cache. If store_only=True, prefill cache and return count.
        """
        out: List[Tuple[Policy, PolicyLike]] = []
        hits = 0
        for p in policies:
            key = self._compile_key(p)
            cached = await self.compile_cache.get(key)
            if cached:
                hits += 1
                if not store_only:
                    out.append((p, cached))
                continue
            compiled = await self._compile_one(p)
            await self.compile_cache.set(key, compiled, self.options.compile_cache_ttl_seconds)
            if not store_only:
                out.append((p, compiled))
        if store_only:
            return len(policies) - (len(policies) - hits)  # count cached after fill ≈ total
        return out

    async def _compile_one(self, policy: Policy) -> PolicyLike:
        for comp in self.compiler_chain:
            try:
                if comp.can_compile(policy):
                    return await comp.compile(policy)
            except Exception as e:
                _LOG.exception("compiler error policy=%s", policy.id, extra=_LogExtra())
                raise CompilationError(f"compiler failed for policy {policy.id}") from e
        raise CompilationError(f"no compiler available for policy {policy.id} type={policy.type}")

    async def _enrich_safe(self, context: Context, tenant_id: str) -> Context:
        try:
            enriched = await self.attribute_provider.enrich(context, tenant_id=tenant_id)
            # defensive copy to plain dict
            return dict(enriched)
        except Exception as e:
            _LOG.exception("attribute provider error", extra=_LogExtra())
            # Fail-closed: do not drop request, but attach error to context metadata
            c = dict(context)
            c.setdefault("__pip_errors__", []).append(repr(e))
            return c

    async def _obligations_safe(self, decision: Decision, tenant_id: str) -> None:
        try:
            await self.obligation_sink.publish(decision, tenant_id=tenant_id)
        except Exception:
            _LOG.exception("obligation sink error", extra=_LogExtra())

    @staticmethod
    def _compile_key(p: Policy) -> str:
        # Stable key combining id, version, and content hash for safety.
        return f"{p.tenant_id}:{p.id}:{p.version}:{p.content_hash}"
