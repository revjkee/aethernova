# agent_mash/tests/performance/test_load_agents.py
from __future__ import annotations

import asyncio
import importlib
import inspect
import os
import time
import tracemalloc
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional, Sequence, Tuple

import pytest


# -----------------------------
# Configuration (ENV overridable)
# -----------------------------

def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None or v == "":
        return default
    try:
        return int(v)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    v = os.getenv(name)
    if v is None or v == "":
        return default
    try:
        return float(v)
    except ValueError:
        return default


AGENT_LOAD_COUNT: int = _env_int("AGENT_LOAD_COUNT", 200)
AGENT_LOAD_CONCURRENCY: int = _env_int("AGENT_LOAD_CONCURRENCY", 50)

# Soft defaults. Adjust in CI via env.
MAX_LOAD_SECONDS: float = _env_float("AGENT_LOAD_MAX_SECONDS", 8.0)
MAX_RSS_MB: int = _env_int("AGENT_LOAD_MAX_RSS_MB", 800)

# If true, failing to discover loader is a hard failure.
STRICT_DISCOVERY: bool = os.getenv("AGENT_LOAD_STRICT_DISCOVERY", "0") in ("1", "true", "TRUE", "yes", "YES")

# Tracemalloc snapshot diff limit (approx allocations growth). Soft guard.
MAX_TRACEMALLOC_MB: int = _env_int("AGENT_LOAD_MAX_TRACEMALLOC_MB", 600)


# -----------------------------
# Pytest markers
# -----------------------------

pytestmark = [
    pytest.mark.performance,
    pytest.mark.slow,
]


# -----------------------------
# Optional dependencies
# -----------------------------

def _try_import_psutil():
    try:
        import psutil  # type: ignore
        return psutil
    except Exception:
        return None


PSUTIL = _try_import_psutil()


# -----------------------------
# Discovery layer
# -----------------------------

Candidate = Tuple[str, str]  # (module_path, attr_name)


CANDIDATE_LOADERS: Sequence[Candidate] = (
    ("agent_mash", "load_agents"),
    ("agent_mash", "bootstrap_agents"),
    ("agent_mash", "init_agents"),
    ("agent_mash.agents", "load_agents"),
    ("agent_mash.agents", "bootstrap_agents"),
    ("agent_mash.agents", "init_agents"),
    ("agent_mash.agents.registry", "load_agents"),
    ("agent_mash.agents.registry", "bootstrap_agents"),
    ("agent_mash.agents.registry", "init_agents"),
    ("agent_mash.registry", "load_agents"),
    ("agent_mash.registry", "bootstrap_agents"),
    ("agent_mash.registry", "init_agents"),
    ("agent_mash.core", "load_agents"),
    ("agent_mash.core", "bootstrap_agents"),
    ("agent_mash.core", "init_agents"),
)

CANDIDATE_FACTORIES: Sequence[Candidate] = (
    ("agent_mash", "get_registry"),
    ("agent_mash", "registry"),
    ("agent_mash.agents", "get_registry"),
    ("agent_mash.agents", "registry"),
    ("agent_mash.agents.registry", "get_registry"),
    ("agent_mash.agents.registry", "registry"),
    ("agent_mash.registry", "get_registry"),
    ("agent_mash.registry", "registry"),
)


@dataclass(frozen=True)
class LoaderHandle:
    """
    Unified handle for either:
    - a direct loader function/coroutine, or
    - a registry/factory that yields a loader method.
    """
    kind: str
    obj: Any
    call: Callable[..., Any]
    is_async: bool
    origin: str


def _safe_import_module(module_path: str):
    try:
        return importlib.import_module(module_path)
    except Exception:
        return None


def _get_attr(mod: Any, name: str) -> Any:
    try:
        return getattr(mod, name)
    except Exception:
        return None


def _is_coroutine_callable(fn: Any) -> bool:
    try:
        return asyncio.iscoroutinefunction(fn) or inspect.iscoroutinefunction(fn)
    except Exception:
        return False


def _discover_direct_loader() -> Optional[LoaderHandle]:
    for module_path, attr_name in CANDIDATE_LOADERS:
        mod = _safe_import_module(module_path)
        if mod is None:
            continue
        candidate = _get_attr(mod, attr_name)
        if candidate is None:
            continue
        if not callable(candidate):
            continue

        is_async = _is_coroutine_callable(candidate)
        return LoaderHandle(
            kind="direct",
            obj=mod,
            call=candidate,
            is_async=is_async,
            origin=f"{module_path}.{attr_name}",
        )
    return None


def _discover_registry_loader() -> Optional[LoaderHandle]:
    for module_path, attr_name in CANDIDATE_FACTORIES:
        mod = _safe_import_module(module_path)
        if mod is None:
            continue
        factory = _get_attr(mod, attr_name)
        if factory is None:
            continue

        registry_obj = None
        if callable(factory):
            try:
                registry_obj = factory()
            except Exception:
                registry_obj = None
        else:
            registry_obj = factory

        if registry_obj is None:
            continue

        # Try common method names on registry
        for method_name in ("load_agents", "bootstrap_agents", "init_agents", "load", "bootstrap", "init"):
            method = getattr(registry_obj, method_name, None)
            if method is None or not callable(method):
                continue

            is_async = _is_coroutine_callable(method)
            return LoaderHandle(
                kind="registry",
                obj=registry_obj,
                call=method,
                is_async=is_async,
                origin=f"{module_path}.{attr_name}->{method_name}()",
            )

    return None


def discover_loader() -> Optional[LoaderHandle]:
    handle = _discover_direct_loader()
    if handle is not None:
        return handle
    handle = _discover_registry_loader()
    if handle is not None:
        return handle
    return None


# -----------------------------
# Metrics
# -----------------------------

@dataclass
class PerfMetrics:
    elapsed_s: float
    rss_mb_before: Optional[float]
    rss_mb_after: Optional[float]
    tracemalloc_mb_delta: Optional[float]
    loader_origin: str
    count: int
    concurrency: int


def _get_rss_mb() -> Optional[float]:
    if PSUTIL is None:
        return None
    try:
        proc = PSUTIL.Process(os.getpid())
        rss = proc.memory_info().rss
        return float(rss) / (1024.0 * 1024.0)
    except Exception:
        return None


def _tracemalloc_to_mb(size_bytes: int) -> float:
    return float(size_bytes) / (1024.0 * 1024.0)


# -----------------------------
# Invocation strategy
# -----------------------------

async def _maybe_await(result: Any) -> Any:
    if inspect.isawaitable(result):
        return await result
    return result


def _build_loader_call_args(fn: Callable[..., Any], *, count: int, concurrency: int) -> dict:
    """
    Build kwargs based on function signature, without guessing meaning beyond matching names.
    If signature doesn't support these, we call without them.
    """
    try:
        sig = inspect.signature(fn)
    except Exception:
        return {}

    params = sig.parameters
    kwargs: dict = {}

    # Prefer explicit names
    for k in ("count", "n", "num_agents", "agents_count", "size"):
        if k in params:
            kwargs[k] = count
            break

    for k in ("concurrency", "workers", "parallelism", "max_concurrency"):
        if k in params:
            kwargs[k] = concurrency
            break

    # Some loaders may accept config dict
    for k in ("options", "settings", "cfg", "config"):
        if k in params and k not in kwargs:
            # Minimal config only; no behavioral speculation.
            kwargs[k] = {"count": count, "concurrency": concurrency}
            break

    return kwargs


async def run_loader(handle: LoaderHandle, *, count: int, concurrency: int) -> Any:
    kwargs = _build_loader_call_args(handle.call, count=count, concurrency=concurrency)

    if handle.is_async:
        return await _maybe_await(handle.call(**kwargs))  # type: ignore[arg-type]

    # Sync function: execute in default loop executor to avoid blocking.
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: handle.call(**kwargs))  # type: ignore[misc]


async def run_loader_many(handle: LoaderHandle, *, count: int, concurrency: int) -> None:
    """
    If loader supports count, we call once.
    If not, we attempt repeated calls to simulate per-agent initialization, but only if loader has no args
    and is safe to call repeatedly. Otherwise we call once and treat it as batch.
    """
    kwargs = _build_loader_call_args(handle.call, count=count, concurrency=concurrency)

    # If it can accept count, do single batch call.
    if any(k in kwargs for k in ("count", "n", "num_agents", "agents_count", "size")):
        await run_loader(handle, count=count, concurrency=concurrency)
        return

    # If it accepts config/options with our dict, still single call.
    if any(k in kwargs for k in ("options", "settings", "cfg", "config")):
        await run_loader(handle, count=count, concurrency=concurrency)
        return

    # Otherwise: call it many times concurrently but bounded, only if it takes no required params.
    try:
        sig = inspect.signature(handle.call)
        required = [
            p for p in sig.parameters.values()
            if p.default is inspect._empty and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY)
        ]
        if len(required) != 0:
            # Can't safely call without required args.
            await run_loader(handle, count=count, concurrency=concurrency)
            return
    except Exception:
        await run_loader(handle, count=count, concurrency=concurrency)
        return

    sem = asyncio.Semaphore(max(1, concurrency))

    async def _one():
        async with sem:
            if handle.is_async:
                return await _maybe_await(handle.call())  # type: ignore[call-arg]
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, handle.call)  # type: ignore[misc]

    tasks = [asyncio.create_task(_one()) for _ in range(max(1, count))]
    await asyncio.gather(*tasks)


# -----------------------------
# Tests
# -----------------------------

@pytest.fixture(scope="module")
def loader_handle() -> LoaderHandle:
    handle = discover_loader()
    if handle is None:
        msg = (
            "Agent loader not discovered. "
            "Expected one of known callables like agent_mash.load_agents or registry.load_agents. "
            "Set AGENT_LOAD_STRICT_DISCOVERY=1 to fail instead of skipping."
        )
        if STRICT_DISCOVERY:
            raise AssertionError(msg)
        pytest.skip(msg)
    return handle


@pytest.mark.asyncio
async def test_load_agents_time_and_memory(loader_handle: LoaderHandle) -> None:
    """
    Industrial performance guard:
    - Measures elapsed time
    - Measures RSS (if psutil available)
    - Measures tracemalloc delta
    - Uses env thresholds to be CI-friendly
    """
    count = max(1, AGENT_LOAD_COUNT)
    concurrency = max(1, AGENT_LOAD_CONCURRENCY)

    rss_before = _get_rss_mb()

    tracemalloc.start()
    snap_before = tracemalloc.take_snapshot()

    t0 = time.perf_counter()
    await run_loader_many(loader_handle, count=count, concurrency=concurrency)
    elapsed = time.perf_counter() - t0

    snap_after = tracemalloc.take_snapshot()
    tracemalloc.stop()

    rss_after = _get_rss_mb()

    # Compute tracemalloc delta in bytes (approx, by comparing total size stats).
    stats_before = snap_before.statistics("filename")
    stats_after = snap_after.statistics("filename")
    total_before = sum(s.size for s in stats_before)
    total_after = sum(s.size for s in stats_after)
    tracemalloc_delta_mb = _tracemalloc_to_mb(max(0, total_after - total_before))

    metrics = PerfMetrics(
        elapsed_s=elapsed,
        rss_mb_before=rss_before,
        rss_mb_after=rss_after,
        tracemalloc_mb_delta=tracemalloc_delta_mb,
        loader_origin=loader_handle.origin,
        count=count,
        concurrency=concurrency,
    )

    # Assertions with clear diagnostics
    assert metrics.elapsed_s <= MAX_LOAD_SECONDS, (
        f"Agent load too slow: elapsed={metrics.elapsed_s:.3f}s "
        f"(max={MAX_LOAD_SECONDS:.3f}s), count={metrics.count}, concurrency={metrics.concurrency}, "
        f"loader={metrics.loader_origin}"
    )

    if metrics.rss_mb_before is not None and metrics.rss_mb_after is not None:
        assert metrics.rss_mb_after <= float(MAX_RSS_MB), (
            f"RSS too high after load: rss_after={metrics.rss_mb_after:.1f}MB "
            f"(max={float(MAX_RSS_MB):.1f}MB), rss_before={metrics.rss_mb_before:.1f}MB, "
            f"count={metrics.count}, concurrency={metrics.concurrency}, loader={metrics.loader_origin}"
        )

    # Tracemalloc is allocator-level and may differ from RSS; keep as a guardrail.
    assert metrics.tracemalloc_mb_delta <= float(MAX_TRACEMALLOC_MB), (
        f"Tracemalloc growth too high: delta={metrics.tracemalloc_mb_delta:.1f}MB "
        f"(max={float(MAX_TRACEMALLOC_MB):.1f}MB), "
        f"count={metrics.count}, concurrency={metrics.concurrency}, loader={metrics.loader_origin}"
    )


@pytest.mark.asyncio
async def test_load_agents_stability_repeat(loader_handle: LoaderHandle) -> None:
    """
    Repeatability guard:
    - Two consecutive loads should not degrade catastrophically.
    - This does not assume idempotency; it only checks time ratio.
    """
    count = max(1, min(AGENT_LOAD_COUNT, 150))
    concurrency = max(1, AGENT_LOAD_CONCURRENCY)

    t0 = time.perf_counter()
    await run_loader_many(loader_handle, count=count, concurrency=concurrency)
    t1 = time.perf_counter()

    await run_loader_many(loader_handle, count=count, concurrency=concurrency)
    t2 = time.perf_counter()

    first = max(1e-9, (t1 - t0))
    second = max(1e-9, (t2 - t1))

    # Allow some warmup benefit or minor regression; block major regressions.
    max_ratio = _env_float("AGENT_LOAD_REPEAT_MAX_RATIO", 2.0)
    assert (second / first) <= max_ratio, (
        f"Second load degraded too much: first={first:.3f}s, second={second:.3f}s, ratio={second/first:.2f} "
        f"(max_ratio={max_ratio:.2f}), count={count}, concurrency={concurrency}, loader={loader_handle.origin}"
    )
