# agent_mash/tests/performance/test_latency.py
from __future__ import annotations

import asyncio
import json
import math
import os
import platform
import statistics
import sys
import time
from dataclasses import dataclass, asdict
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import pytest


# -----------------------------
# Pytest integration
# -----------------------------

def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "performance: performance-sensitive tests (opt-in)")
    config.addinivalue_line("markers", "latency: latency-focused performance tests (opt-in)")


# -----------------------------
# Configuration (env-driven)
# -----------------------------
#
# Important: These are not "facts" about your environment; they are defaults.
# They can be overridden via environment variables.
#
# Enable test execution:
#   PERF_TESTS=1
#
# Control sampling:
#   PERF_WARMUP=30
#   PERF_ITER=200
#   PERF_MIN_SECONDS=0.35
#
# Control thresholds (milliseconds):
#   PERF_P50_MS=5
#   PERF_P95_MS=20
#   PERF_P99_MS=40
#
# Output JSON report (optional):
#   PERF_REPORT_JSON=/absolute/path/to/report.json
#
# Optional: avoid failing on threshold exceed, only record:
#   PERF_SOFT_FAIL=1
#
# Optional: print details always:
#   PERF_VERBOSE=1


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    raw = raw.strip().lower()
    return raw in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int, min_value: int = 1, max_value: int = 10_000_000) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        val = int(raw)
    except ValueError as e:
        raise ValueError(f"Invalid integer in env var {name}={raw!r}") from e
    if val < min_value or val > max_value:
        raise ValueError(f"Env var {name} out of range: {val} not in [{min_value}, {max_value}]")
    return val


def _env_float(name: str, default: float, min_value: float = 0.0, max_value: float = 10_000_000.0) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        val = float(raw)
    except ValueError as e:
        raise ValueError(f"Invalid float in env var {name}={raw!r}") from e
    if val < min_value or val > max_value:
        raise ValueError(f"Env var {name} out of range: {val} not in [{min_value}, {max_value}]")
    return val


def _env_path(name: str) -> Optional[str]:
    raw = os.getenv(name)
    if not raw:
        return None
    return raw


PERF_ENABLED = _env_flag("PERF_TESTS", default=False)
PERF_SOFT_FAIL = _env_flag("PERF_SOFT_FAIL", default=False)
PERF_VERBOSE = _env_flag("PERF_VERBOSE", default=False)

WARMUP = _env_int("PERF_WARMUP", default=30, min_value=0, max_value=1_000_000)
ITER = _env_int("PERF_ITER", default=200, min_value=1, max_value=5_000_000)
MIN_SECONDS = _env_float("PERF_MIN_SECONDS", default=0.35, min_value=0.0, max_value=60.0)

THRESH_P50_MS = _env_float("PERF_P50_MS", default=5.0, min_value=0.0, max_value=1_000_000.0)
THRESH_P95_MS = _env_float("PERF_P95_MS", default=20.0, min_value=0.0, max_value=1_000_000.0)
THRESH_P99_MS = _env_float("PERF_P99_MS", default=40.0, min_value=0.0, max_value=1_000_000.0)

REPORT_JSON_PATH = _env_path("PERF_REPORT_JSON")


# -----------------------------
# Core measurement utilities
# -----------------------------

def _now_ns() -> int:
    return time.perf_counter_ns()


def _ns_to_ms(ns: float) -> float:
    return ns / 1_000_000.0


def _percentile_sorted(sorted_values: Sequence[float], p: float) -> float:
    """
    Calculate percentile using linear interpolation between closest ranks.
    Expects sorted_values sorted ascending.
    p in [0, 100].
    """
    if not sorted_values:
        raise ValueError("percentile on empty data")
    if p <= 0.0:
        return float(sorted_values[0])
    if p >= 100.0:
        return float(sorted_values[-1])

    n = len(sorted_values)
    # index in [0, n-1]
    pos = (p / 100.0) * (n - 1)
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return float(sorted_values[lo])
    frac = pos - lo
    return float(sorted_values[lo] * (1.0 - frac) + sorted_values[hi] * frac)


@dataclass(frozen=True)
class LatencyStats:
    unit: str
    samples: int
    mean: float
    median_p50: float
    p95: float
    p99: float
    stdev: float
    min: float
    max: float


@dataclass(frozen=True)
class LatencyReport:
    test_name: str
    target_kind: str
    thresholds_ms: Dict[str, float]
    stats_ms: LatencyStats
    warmup: int
    iterations: int
    min_seconds: float
    soft_fail: bool
    python: str
    platform: str
    timestamp_unix: int


def _compute_stats_ms(samples_ns: List[int]) -> LatencyStats:
    if not samples_ns:
        raise ValueError("No samples to compute stats")
    values_ms = [_ns_to_ms(float(x)) for x in samples_ns]
    values_ms.sort()
    mean = statistics.fmean(values_ms)
    stdev = statistics.pstdev(values_ms) if len(values_ms) > 1 else 0.0
    p50 = _percentile_sorted(values_ms, 50.0)
    p95 = _percentile_sorted(values_ms, 95.0)
    p99 = _percentile_sorted(values_ms, 99.0)
    return LatencyStats(
        unit="ms",
        samples=len(values_ms),
        mean=mean,
        median_p50=p50,
        p95=p95,
        p99=p99,
        stdev=stdev,
        min=float(values_ms[0]),
        max=float(values_ms[-1]),
    )


def _should_run_perf() -> None:
    if not PERF_ENABLED:
        pytest.skip("Performance tests are opt-in. Set PERF_TESTS=1 to enable.")


def _maybe_dump_report(report: LatencyReport) -> None:
    if not REPORT_JSON_PATH:
        return
    # Single file path: write/overwrite atomically best-effort.
    payload = asdict(report)
    payload["stats_ms"] = asdict(report.stats_ms)
    try:
        os.makedirs(os.path.dirname(REPORT_JSON_PATH), exist_ok=True)
        tmp_path = REPORT_JSON_PATH + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, REPORT_JSON_PATH)
    except Exception as e:
        # In performance tests, report writing should not crash the suite.
        if PERF_VERBOSE:
            print(f"[perf] Failed to write report {REPORT_JSON_PATH!r}: {e}", file=sys.stderr)


def _format_stats(stats: LatencyStats) -> str:
    return (
        f"samples={stats.samples} "
        f"mean={stats.mean:.3f}{stats.unit} "
        f"p50={stats.median_p50:.3f}{stats.unit} "
        f"p95={stats.p95:.3f}{stats.unit} "
        f"p99={stats.p99:.3f}{stats.unit} "
        f"min={stats.min:.3f}{stats.unit} "
        f"max={stats.max:.3f}{stats.unit} "
        f"stdev={stats.stdev:.3f}{stats.unit}"
    )


def _assert_thresholds(stats: LatencyStats, *, p50_ms: float, p95_ms: float, p99_ms: float) -> Tuple[bool, str]:
    failures: List[str] = []
    if stats.median_p50 > p50_ms:
        failures.append(f"p50 {stats.median_p50:.3f}ms > {p50_ms:.3f}ms")
    if stats.p95 > p95_ms:
        failures.append(f"p95 {stats.p95:.3f}ms > {p95_ms:.3f}ms")
    if stats.p99 > p99_ms:
        failures.append(f"p99 {stats.p99:.3f}ms > {p99_ms:.3f}ms")

    if not failures:
        return True, "ok"
    return False, "; ".join(failures)


# -----------------------------
# Targets to measure (replace with real code)
# -----------------------------

def target_sync() -> None:
    """
    Replace this function body with your real synchronous target.
    Keep it small and pure for stable latency measurement.
    """
    # Minimal deterministic work to avoid measuring "nothing".
    x = 0
    for i in range(50):
        x ^= (i * 2654435761) & 0xFFFFFFFF
    if x == -1:  # unreachable guard to prevent optimization assumptions
        raise RuntimeError("unreachable")


async def target_async() -> None:
    """
    Replace this function body with your real async target.
    """
    # Yield once to exercise event loop overhead deterministically.
    await asyncio.sleep(0)
    target_sync()


# -----------------------------
# Measurement runners
# -----------------------------

def _run_sync_measurement(fn: Callable[[], None], *, warmup: int, iterations: int, min_seconds: float) -> List[int]:
    # Warmup
    for _ in range(warmup):
        fn()

    samples: List[int] = []
    start_ns = _now_ns()
    for _ in range(iterations):
        t0 = _now_ns()
        fn()
        t1 = _now_ns()
        samples.append(t1 - t0)
        # Ensure we collect at least min_seconds worth of wall-clock time (best-effort stabilization).
        if min_seconds > 0.0 and (_now_ns() - start_ns) >= int(min_seconds * 1_000_000_000):
            # stop early only if we already have a meaningful number of samples
            if len(samples) >= max(20, iterations // 5):
                break
    return samples


async def _run_async_measurement(fn: Callable[[], Any], *, warmup: int, iterations: int, min_seconds: float) -> List[int]:
    # Warmup
    for _ in range(warmup):
        await fn()

    samples: List[int] = []
    start_ns = _now_ns()
    for _ in range(iterations):
        t0 = _now_ns()
        await fn()
        t1 = _now_ns()
        samples.append(t1 - t0)
        if min_seconds > 0.0 and (_now_ns() - start_ns) >= int(min_seconds * 1_000_000_000):
            if len(samples) >= max(20, iterations // 5):
                break
    return samples


# -----------------------------
# Tests
# -----------------------------

@pytest.mark.performance
@pytest.mark.latency
def test_latency_sync() -> None:
    _should_run_perf()

    samples_ns = _run_sync_measurement(
        target_sync,
        warmup=WARMUP,
        iterations=ITER,
        min_seconds=MIN_SECONDS,
    )
    stats = _compute_stats_ms(samples_ns)

    thresholds = {"p50_ms": THRESH_P50_MS, "p95_ms": THRESH_P95_MS, "p99_ms": THRESH_P99_MS}
    ok, reason = _assert_thresholds(stats, p50_ms=THRESH_P50_MS, p95_ms=THRESH_P95_MS, p99_ms=THRESH_P99_MS)

    report = LatencyReport(
        test_name="test_latency_sync",
        target_kind="sync",
        thresholds_ms=thresholds,
        stats_ms=stats,
        warmup=WARMUP,
        iterations=ITER,
        min_seconds=MIN_SECONDS,
        soft_fail=PERF_SOFT_FAIL,
        python=sys.version.replace("\n", " "),
        platform=f"{platform.system()} {platform.release()} ({platform.machine()})",
        timestamp_unix=int(time.time()),
    )
    _maybe_dump_report(report)

    if PERF_VERBOSE or (not ok):
        print(f"[perf] sync: {_format_stats(stats)}")
        print(f"[perf] thresholds: {thresholds}")
        print(f"[perf] verdict: {reason}")

    if not ok and not PERF_SOFT_FAIL:
        pytest.fail(f"Latency thresholds exceeded: {reason}. {_format_stats(stats)}")


@pytest.mark.performance
@pytest.mark.latency
@pytest.mark.asyncio
async def test_latency_async() -> None:
    _should_run_perf()

    samples_ns = await _run_async_measurement(
        target_async,
        warmup=WARMUP,
        iterations=ITER,
        min_seconds=MIN_SECONDS,
    )
    stats = _compute_stats_ms(samples_ns)

    thresholds = {"p50_ms": THRESH_P50_MS, "p95_ms": THRESH_P95_MS, "p99_ms": THRESH_P99_MS}
    ok, reason = _assert_thresholds(stats, p50_ms=THRESH_P50_MS, p95_ms=THRESH_P95_MS, p99_ms=THRESH_P99_MS)

    report = LatencyReport(
        test_name="test_latency_async",
        target_kind="async",
        thresholds_ms=thresholds,
        stats_ms=stats,
        warmup=WARMUP,
        iterations=ITER,
        min_seconds=MIN_SECONDS,
        soft_fail=PERF_SOFT_FAIL,
        python=sys.version.replace("\n", " "),
        platform=f"{platform.system()} {platform.release()} ({platform.machine()})",
        timestamp_unix=int(time.time()),
    )
    _maybe_dump_report(report)

    if PERF_VERBOSE or (not ok):
        print(f"[perf] async: {_format_stats(stats)}")
        print(f"[perf] thresholds: {thresholds}")
        print(f"[perf] verdict: {reason}")

    if not ok and not PERF_SOFT_FAIL:
        pytest.fail(f"Latency thresholds exceeded: {reason}. {_format_stats(stats)}")
