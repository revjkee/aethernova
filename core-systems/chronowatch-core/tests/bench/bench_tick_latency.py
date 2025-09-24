# chronowatch-core/tests/bench/bench_tick_latency.py
# Industrial-grade tick-latency benchmark for ChronoWatch
# - Standalone CLI + pytest integration
# - JSON/CSV artifacts
# - Warmup, spin-sleep scheduling, percentiles, histogram
# - Optional Windows timeBeginPeriod(1)
# - Optional CPU affinity pinning on Linux
# - Threshold-based assertion via env for CI

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import math
import os
import platform
import statistics
import sys
import time
from dataclasses import dataclass, asdict
from typing import Callable, Dict, List, Optional, Tuple, Iterable, Any
from contextlib import contextmanager

# ---------------------------
# Platform helpers
# ---------------------------

@contextmanager
def windows_timer_resolution(enabled: bool):
    """
    On Windows, increase system timer resolution to 1ms via winmm.timeBeginPeriod(1).
    Safe no-op on non-Windows or when disabled/fails.
    """
    if not enabled or platform.system().lower() != "windows":
        yield
        return
    try:
        import ctypes
        winmm = ctypes.WinDLL("winmm")
        timeBeginPeriod = winmm.timeBeginPeriod
        timeBeginPeriod.argtypes = [ctypes.c_uint]
        timeBeginPeriod.restype = ctypes.c_uint
        timeEndPeriod = winmm.timeEndPeriod
        timeEndPeriod.argtypes = [ctypes.c_uint]
        timeEndPeriod.restype = ctypes.c_uint
        r = timeBeginPeriod(1)
        try:
            yield
        finally:
            timeEndPeriod(1)
    except Exception:
        # Graceful fallback
        yield


@contextmanager
def cpu_affinity_pin(cpu_index: int | None):
    """
    Pin the process to a specific CPU core on Linux to reduce jitter.
    No-op elsewhere or on failure.
    """
    if cpu_index is None:
        yield
        return
    if hasattr(os, "sched_getaffinity") and hasattr(os, "sched_setaffinity"):
        try:
            pid = 0  # current
            old = os.sched_getaffinity(pid)
            try:
                os.sched_setaffinity(pid, {cpu_index})
                yield
            finally:
                os.sched_setaffinity(pid, old)
            return
        except Exception:
            pass
    # Fallback
    yield


# ---------------------------
# Config & Results
# ---------------------------

@dataclass
class BenchConfig:
    interval_ns: int                # target period per tick (ns)
    duration_s: float               # measurement duration (seconds)
    warmup_s: float                 # warmup duration (seconds)
    spin_threshold_ns: int          # when remaining < this, switch to spin
    clock: str                      # 'perf_counter'|'monotonic'
    runs: int                       # number of repeated runs
    windows_timer_1ms: bool         # enable 1ms resolution on Windows
    cpu_pin: Optional[int]          # CPU index to pin (Linux)
    artifacts_dir: str              # folder to store JSON/CSV
    histogram_buckets: int          # number of buckets for histogram
    histogram_max_ns: Optional[int] # clamp histogram at this latency (ns) if set
    seed: Optional[int]             # reserved for future (no randomness now)


@dataclass
class RunStats:
    count: int
    min_ns: int
    max_ns: int
    mean_ns: float
    median_ns: float
    stdev_ns: float
    p90_ns: float
    p95_ns: float
    p99_ns: float
    rms_ns: float
    missed_ticks: int               # ticks where latency >= interval_ns
    drift_ns: float                 # mean absolute drift from schedule


@dataclass
class BenchRunResult:
    run_index: int
    latencies_ns: List[int]
    tick_targets_ns: List[int]
    tick_actual_ns: List[int]
    stats: RunStats


@dataclass
class BenchMeta:
    python_version: str
    platform: str
    machine: str
    processor: str
    cpu_count: int
    clock: str
    start_time_utc: str


@dataclass
class BenchSuiteResult:
    config: BenchConfig
    meta: BenchMeta
    runs: List[BenchRunResult]
    aggregate: RunStats


# ---------------------------
# Timing helpers
# ---------------------------

def _get_clock(clock_name: str) -> Tuple[Callable[[], int], str]:
    """
    Return (clock_fn_ns, clock_label)
    """
    name = clock_name.strip().lower()
    if name in ("perf_counter", "perf", "pc"):
        return time.perf_counter_ns, "perf_counter_ns"
    if name in ("monotonic", "mono", "monotonic_ns"):
        # time.monotonic_ns exists in 3.7+
        if hasattr(time, "monotonic_ns"):
            return time.monotonic_ns, "monotonic_ns"
        # Fallback with scale (rare)
        return lambda: int(time.monotonic() * 1e9), "monotonic*1e9"
    raise ValueError(f"Unknown clock: {clock_name}")


def _percentile(sorted_values: List[int], q: float) -> float:
    """
    Compute percentile q in [0, 100] from a sorted list using linear interpolation.
    """
    if not sorted_values:
        return float("nan")
    if q <= 0:
        return float(sorted_values[0])
    if q >= 100:
        return float(sorted_values[-1])
    k = (len(sorted_values) - 1) * (q / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(sorted_values[int(k)])
    d0 = sorted_values[f] * (c - k)
    d1 = sorted_values[c] * (k - f)
    return float(d0 + d1)


def _rms(values: Iterable[int]) -> float:
    acc = 0.0
    n = 0
    for v in values:
        acc += (v * 1.0) ** 2
        n += 1
    return math.sqrt(acc / n) if n else float("nan")


def _build_histogram(values_ns: List[int], buckets: int, max_ns: Optional[int]) -> List[Tuple[int, int, int]]:
    """
    Build histogram as list of tuples: (bucket_start_ns, bucket_end_ns, count)
    If max_ns is set, clamp values above it into the last bucket.
    """
    if not values_ns or buckets <= 0:
        return []
    vmin = min(values_ns)
    vmax = max(values_ns)
    if max_ns is not None:
        vmax = min(vmax, max_ns)
    if vmax == vmin:
        return [(vmin, vmax, len(values_ns))]
    width = max(1, (vmax - vmin) // buckets)
    edges = [vmin + i * width for i in range(buckets)]
    edges.append(vmax + 1)  # last edge
    counts = [0] * buckets
    for v in values_ns:
        vv = min(v, vmax) if max_ns is not None else v
        # bucket index
        idx = min(buckets - 1, max(0, (vv - vmin) // width))
        counts[idx] += 1
    hist = []
    for i in range(buckets):
        start = edges[i]
        end = edges[i + 1] - 1
        hist.append((start, end, counts[i]))
    return hist


# ---------------------------
# Core benchmark
# ---------------------------

def _spin_until(target_ns: int, now_fn: Callable[[], int], spin_threshold_ns: int):
    """
    Hybrid sleep-spin wait until target_ns.
    Sleep while far; spin for the last spin_threshold_ns.
    """
    while True:
        now = now_fn()
        delta = target_ns - now
        if delta <= 0:
            return
        if delta > spin_threshold_ns + 1_000_000:  # > (spin + 1ms)
            # leave some margin before spin zone
            time.sleep((delta - spin_threshold_ns) / 1e9)
        else:
            # transition to spin
            break
    # Spin phase
    while now_fn() < target_ns:
        pass


def _summarize(latencies_ns: List[int], interval_ns: int, targets: List[int], actuals: List[int]) -> RunStats:
    values_sorted = sorted(latencies_ns)
    count = len(values_sorted)
    min_ns = values_sorted[0] if count else 0
    max_ns = values_sorted[-1] if count else 0
    mean_ns = statistics.fmean(values_sorted) if count else float("nan")
    median_ns = _percentile(values_sorted, 50.0)
    stdev_ns = statistics.pstdev(values_sorted) if count else float("nan")
    p90_ns = _percentile(values_sorted, 90.0)
    p95_ns = _percentile(values_sorted, 95.0)
    p99_ns = _percentile(values_sorted, 99.0)
    rms_ns = _rms(values_sorted)
    missed_ticks = sum(1 for v in latencies_ns if v >= interval_ns)
    # drift: mean absolute difference between (actual-target)
    abs_drifts = [abs(a - t) for a, t in zip(actuals, targets)]
    drift_ns = statistics.fmean(abs_drifts) if abs_drifts else float("nan")
    return RunStats(
        count=count,
        min_ns=min_ns,
        max_ns=max_ns,
        mean_ns=mean_ns,
        median_ns=median_ns,
        stdev_ns=stdev_ns,
        p90_ns=p90_ns,
        p95_ns=p95_ns,
        p99_ns=p99_ns,
        rms_ns=rms_ns,
        missed_ticks=missed_ticks,
        drift_ns=drift_ns,
    )


def _single_run(cfg: BenchConfig, now_fn: Callable[[], int]) -> Tuple[List[int], List[int], List[int]]:
    """
    Perform a single timed run:
    - Warmup (no recording)
    - Measure tick latency over duration
    """
    interval = cfg.interval_ns
    spin = cfg.spin_threshold_ns

    start_ns = now_fn()
    # Warmup schedule
    if cfg.warmup_s > 0:
        warmup_end = start_ns + int(cfg.warmup_s * 1e9)
        i = 1
        while True:
            target = start_ns + i * interval
            if target >= warmup_end:
                break
            _spin_until(target, now_fn, spin)
            i += 1

    # Measurement schedule
    measure_start = now_fn()
    measure_end = measure_start + int(cfg.duration_s * 1e9)
    latencies: List[int] = []
    targets: List[int] = []
    actuals: List[int] = []

    i = 1
    while True:
        target = measure_start + i * interval
        if target > measure_end:
            break
        _spin_until(target, now_fn, spin)
        now = now_fn()
        latency = max(0, now - target)
        latencies.append(latency)
        targets.append(target)
        actuals.append(now)
        i += 1

    return latencies, targets, actuals


def run_benchmark(cfg: BenchConfig) -> BenchSuiteResult:
    now_fn, clock_label = _get_clock(cfg.clock)

    meta = BenchMeta(
        python_version=sys.version.split()[0],
        platform=platform.platform(),
        machine=platform.machine(),
        processor=platform.processor(),
        cpu_count=os.cpu_count() or 1,
        clock=clock_label,
        start_time_utc=dt.datetime.utcnow().isoformat() + "Z",
    )

    results: List[BenchRunResult] = []

    with windows_timer_resolution(cfg.windows_timer_1ms), cpu_affinity_pin(cfg.cpu_pin):
        for run_idx in range(cfg.runs):
            latencies, targets, actuals = _single_run(cfg, now_fn)
            stats = _summarize(latencies, cfg.interval_ns, targets, actuals)
            results.append(BenchRunResult(
                run_index=run_idx,
                latencies_ns=latencies,
                tick_targets_ns=targets,
                tick_actual_ns=actuals,
                stats=stats
            ))

    # Aggregate across runs
    all_lat = [v for r in results for v in r.latencies_ns]
    all_targets = [v for r in results for v in r.tick_targets_ns]
    all_actuals = [v for r in results for v in r.tick_actual_ns]
    aggregate = _summarize(all_lat, cfg.interval_ns, all_targets, all_actuals)

    suite = BenchSuiteResult(config=cfg, meta=meta, runs=results, aggregate=aggregate)
    _persist_artifacts(suite)
    _print_summary(suite)
    return suite


# ---------------------------
# Artifacts & Reporting
# ---------------------------

def _ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def _persist_artifacts(suite: BenchSuiteResult):
    artifacts_dir = suite.config.artifacts_dir
    _ensure_dir(artifacts_dir)
    ts = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    base = f"tick_latency_{ts}"

    # JSON (full suite)
    json_path = os.path.join(artifacts_dir, f"{base}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(_suite_to_dict(suite), f, indent=2)

    # CSV (aggregate + per-run stats)
    csv_path = os.path.join(artifacts_dir, f"{base}_stats.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "scope", "run_index", "count", "min_ns", "max_ns", "mean_ns", "median_ns",
            "stdev_ns", "p90_ns", "p95_ns", "p99_ns", "rms_ns", "missed_ticks", "drift_ns"
        ])
        agg = suite.aggregate
        w.writerow(["aggregate", -1, agg.count, agg.min_ns, agg.max_ns, agg.mean_ns, agg.median_ns,
                    agg.stdev_ns, agg.p90_ns, agg.p95_ns, agg.p99_ns, agg.rms_ns, agg.missed_ticks, agg.drift_ns])
        for r in suite.runs:
            s = r.stats
            w.writerow(["run", r.run_index, s.count, s.min_ns, s.max_ns, s.mean_ns, s.median_ns,
                        s.stdev_ns, s.p90_ns, s.p95_ns, s.p99_ns, s.rms_ns, s.missed_ticks, s.drift_ns])

    # CSV histogram (aggregate)
    hist = _build_histogram(
        [v for r in suite.runs for v in r.latencies_ns],
        suite.config.histogram_buckets,
        suite.config.histogram_max_ns
    )
    hist_path = os.path.join(artifacts_dir, f"{base}_histogram.csv")
    with open(hist_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["bucket_start_ns", "bucket_end_ns", "count"])
        for start, end, cnt in hist:
            w.writerow([start, end, cnt])


def _suite_to_dict(suite: BenchSuiteResult) -> Dict[str, Any]:
    d = {
        "config": asdict(suite.config),
        "meta": asdict(suite.meta),
        "aggregate": asdict(suite.aggregate),
        "runs": []
    }
    for r in suite.runs:
        d["runs"].append({
            "run_index": r.run_index,
            "stats": asdict(r.stats),
            "latencies_ns": r.latencies_ns,
            "tick_targets_ns": r.tick_targets_ns,
            "tick_actual_ns": r.tick_actual_ns,
        })
    return d


def _ns(v: float) -> str:
    return f"{int(v):>10d} ns"


def _print_summary(suite: BenchSuiteResult):
    cfg = suite.config
    agg = suite.aggregate
    print("\n=== ChronoWatch Tick Latency Benchmark ===")
    print(f"Clock           : {suite.meta.clock}")
    print(f"Interval        : {cfg.interval_ns} ns ({cfg.interval_ns/1e6:.3f} ms)")
    print(f"Duration        : {cfg.duration_s:.3f} s (x{cfg.runs} runs), warmup={cfg.warmup_s:.3f} s")
    print(f"Spin threshold  : {cfg.spin_threshold_ns} ns")
    print(f"Windows 1ms     : {cfg.windows_timer_1ms}")
    print(f"CPU pin         : {cfg.cpu_pin}")
    print(f"Artifacts dir   : {cfg.artifacts_dir}")
    print(f"Platform        : {suite.meta.platform} | CPU: {suite.meta.processor} | Cores: {suite.meta.cpu_count}")
    print("\n-- Aggregate stats --")
    print(f"count   : {agg.count}")
    print(f"min     : {_ns(agg.min_ns)}")
    print(f"median  : {_ns(agg.median_ns)}")
    print(f"mean    : {agg.mean_ns:>10.1f} ns")
    print(f"stdev   : {agg.stdev_ns:>10.1f} ns")
    print(f"p90     : {_ns(agg.p90_ns)}")
    print(f"p95     : {_ns(agg.p95_ns)}")
    print(f"p99     : {_ns(agg.p99_ns)}")
    print(f"max     : {_ns(agg.max_ns)}")
    print(f"rms     : {agg.rms_ns:>10.1f} ns")
    print(f"missed  : {agg.missed_ticks}")
    print(f"drift   : {agg.drift_ns:>10.1f} ns")
    print("=========================================\n")


# ---------------------------
# CLI
# ---------------------------

def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="ChronoWatch tick latency benchmark")
    p.add_argument("--interval-ms", type=float, default=1.0, help="Tick interval in milliseconds (default: 1.0)")
    p.add_argument("--duration", type=float, default=5.0, help="Measurement duration in seconds (default: 5.0)")
    p.add_argument("--warmup", type=float, default=0.5, help="Warmup duration in seconds (default: 0.5)")
    p.add_argument("--spin-threshold-us", type=int, default=200, help="Spin threshold in microseconds (default: 200)")
    p.add_argument("--clock", type=str, default="perf_counter", choices=["perf_counter", "monotonic"], help="Clock source")
    p.add_argument("--runs", type=int, default=3, help="Number of runs (default: 3)")
    p.add_argument("--windows-1ms", action="store_true", help="Enable 1ms timer resolution on Windows")
    p.add_argument("--cpu-pin", type=int, default=None, help="Pin to CPU index (Linux only)")
    p.add_argument("--artifacts-dir", type=str, default=os.getenv("CHRONOWATCH_ARTIFACTS_DIR", ".artifacts"),
                   help="Directory to write JSON/CSV artifacts")
    p.add_argument("--hist-buckets", type=int, default=40, help="Histogram buckets (default: 40)")
    p.add_argument("--hist-max-ns", type=int, default=None, help="Clamp histogram upper bound (ns)")
    return p.parse_args(argv)


def _cfg_from_args(ns: argparse.Namespace) -> BenchConfig:
    return BenchConfig(
        interval_ns=int(ns.interval_ms * 1_000_000),
        duration_s=ns.duration,
        warmup_s=ns.warmup,
        spin_threshold_ns=int(ns.spin_threshold_us * 1_000),
        clock=ns.clock,
        runs=ns.runs,
        windows_timer_1ms=bool(ns.windows_1ms),
        cpu_pin=ns.cpu_pin,
        artifacts_dir=ns.artifacts_dir,
        histogram_buckets=ns.hist_buckets,
        histogram_max_ns=ns.hist_max_ns,
        seed=None,
    )


def main(argv: Optional[List[str]] = None) -> int:
    ns = _parse_args(argv)
    cfg = _cfg_from_args(ns)
    run_benchmark(cfg)
    return 0


# ---------------------------
# Pytest integration
# ---------------------------

def _threshold_from_env(default_ns: Optional[int] = None) -> Optional[int]:
    """
    If CHRONOWATCH_BENCH_P95_NS is set, use it as threshold for aggregate p95.
    """
    v = os.getenv("CHRONOWATCH_BENCH_P95_NS", "")
    try:
        return int(v) if v else default_ns
    except ValueError:
        return default_ns


def _should_run_in_pytest() -> bool:
    """
    Controlled by RUN_BENCH env var to avoid long runs in CI unless explicit.
    """
    return os.getenv("RUN_BENCH", "0") in ("1", "true", "TRUE", "yes", "YES")


def test_tick_latency_smoke():
    """
    Smoke test to ensure the benchmark runs and produces sane counts.
    Skips unless RUN_BENCH=1 to keep CI fast by default.
    """
    if not _should_run_in_pytest():
        import pytest  # type: ignore
        pytest.skip("RUN_BENCH != 1")

    cfg = BenchConfig(
        interval_ns=int(1.0 * 1_000_000),  # 1ms
        duration_s=1.0,
        warmup_s=0.2,
        spin_threshold_ns=200_000,  # 200us
        clock="perf_counter",
        runs=1,
        windows_timer_1ms=(platform.system().lower() == "windows"),
        cpu_pin=0 if platform.system().lower() == "linux" else None,
        artifacts_dir=os.getenv("CHRONOWATCH_ARTIFACTS_DIR", ".artifacts"),
        histogram_buckets=20,
        histogram_max_ns=None,
        seed=None,
    )
    suite = run_benchmark(cfg)
    assert suite.aggregate.count >= 500, "Expect at least 500 ticks at 1ms over 1s"


def test_tick_latency_threshold():
    """
    Optional CI guard: fail if aggregate p95 exceeds CHRONOWATCH_BENCH_P95_NS.
    Skips unless RUN_BENCH=1 and the env threshold is set.
    """
    if not _should_run_in_pytest():
        import pytest  # type: ignore
        pytest.skip("RUN_BENCH != 1")

    threshold_ns = _threshold_from_env()
    if threshold_ns is None:
        import pytest  # type: ignore
        pytest.skip("CHRONOWATCH_BENCH_P95_NS not set")

    cfg = BenchConfig(
        interval_ns=int(1.0 * 1_000_000),  # 1ms
        duration_s=2.0,
        warmup_s=0.3,
        spin_threshold_ns=200_000,  # 200us
        clock="perf_counter",
        runs=2,
        windows_timer_1ms=(platform.system().lower() == "windows"),
        cpu_pin=0 if platform.system().lower() == "linux" else None,
        artifacts_dir=os.getenv("CHRONOWATCH_ARTIFACTS_DIR", ".artifacts"),
        histogram_buckets=30,
        histogram_max_ns=None,
        seed=None,
    )
    suite = run_benchmark(cfg)
    p95 = suite.aggregate.p95_ns
    assert p95 <= threshold_ns, f"p95={p95} ns exceeds threshold={threshold_ns} ns"


if __name__ == "__main__":
    sys.exit(main())
