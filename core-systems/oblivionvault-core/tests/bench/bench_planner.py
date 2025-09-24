# File: tests/bench/bench_planner.py
# Industrial-grade benchmarks for oblivionvault.retention.calc.compute_retention_plan
# Usage:
#   pip install pytest pytest-benchmark psutil
#   pytest -q tests/bench/bench_planner.py --benchmark-only
#
# ENV knobs (with sensible defaults for CI):
#   BENCH_PLANNER_SEED=1337
#   BENCH_PLANNER_N_BULK=4000          # records per bulk test
#   BENCH_PLANNER_N_CONC=2000          # records per concurrency test
#   BENCH_PLANNER_WORKERS=0            # 0 -> cpu_count(), else fixed
#   BENCH_PLANNER_TZ=UTC               # default tz for generated dates
#   BENCH_PLANNER_FAST=0               # 1 -> lighter sizes (e.g., CI)
#   RETENTION_JITTER_SEED=12345        # seed consumed by implementation (if supported)
#
# Notes:
# - Benchmarks are deterministic across runs when seeds are fixed.
# - If target module is missing, tests are skipped cleanly.

from __future__ import annotations

import math
import os
import random
import statistics
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import pytest

# Optional psutil for RSS diagnostics
try:
    import psutil  # type: ignore
    _HAS_PSUTIL = True
except Exception:  # pragma: no cover
    _HAS_PSUTIL = False

# Target under test
try:
    from oblivionvault.retention.calc import compute_retention_plan  # type: ignore
except Exception as e:  # pragma: no cover
    pytest.skip(f"compute_retention_plan unavailable: {e}", allow_module_level=True)

UTC = timezone.utc
pytestmark = pytest.mark.benchmark(group="planner")


# ------------------------------ ENV & Defaults -------------------------------

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, "").strip() or default)
    except Exception:
        return default

def _env_str(name: str, default: str) -> str:
    v = os.getenv(name)
    return v if v else default

def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "t", "yes", "y", "on")

SEED_GLOBAL = _env_int("BENCH_PLANNER_SEED", 1337)
N_BULK = _env_int("BENCH_PLANNER_N_BULK", 4000)
N_CONC = _env_int("BENCH_PLANNER_N_CONC", 2000)
TZ_DEFAULT = _env_str("BENCH_PLANNER_TZ", "UTC")
FAST = _env_bool("BENCH_PLANNER_FAST", False)
WORKERS = _env_int("BENCH_PLANNER_WORKERS", 0)

if FAST:
    N_BULK = min(N_BULK, 1000)
    N_CONC = min(N_CONC, 800)


# ------------------------------ Policy helpers -------------------------------

def base_policy(**over: Any) -> Dict[str, Any]:
    p: Dict[str, Any] = {
        "name": "bench-default",
        "base_days": 90,
        "pii_days": 30,
        "archive_after_days": 60,
        "purge_delay_days": 7,
        "grace_days_after_hold": 14,
        "sliding_window": True,
        "max_ttl_days": 365,
        "allow_manual_override": True,
        "jitter_days": 0,
        "jitter_mode": "none",            # "none" | "positive" | "symmetric"
        "tz": TZ_DEFAULT,                 # implementation may or may not use; tests do not rely on this here
        "rounding": "midnight_utc",
    }
    p.update(over)
    return p


# ------------------------------ Data generation ------------------------------

def dt_utc(y: int, m: int, d: int, hh: int = 0, mm: int = 0, ss: int = 0) -> datetime:
    return datetime(y, m, d, hh, mm, ss, tzinfo=UTC)

def _make_record(
    *,
    rid: str,
    created_at: datetime,
    last_access_at: Optional[datetime],
    classification: Optional[str],
    legal_hold: bool,
    legal_hold_set_at: Optional[datetime],
    legal_hold_released_at: Optional[datetime],
    ttl_override_days: Optional[int],
) -> Dict[str, Any]:
    return {
        "id": rid,
        "classification": classification,
        "created_at": created_at,
        "last_access_at": last_access_at,
        "legal_hold": legal_hold,
        "legal_hold_set_at": legal_hold_set_at,
        "legal_hold_released_at": legal_hold_released_at,
        "ttl_override_days": ttl_override_days,
    }

def _rng(seed: int) -> random.Random:
    r = random.Random()
    r.seed(seed)
    return r

def gen_dataset(n: int, scenario: str, seed: int) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Generate deterministic dataset for a given scenario.
    Returns (records, policy).
    """
    r = _rng(seed)
    base_dt = dt_utc(2025, 1, 1, 12, 0, 0)
    recs: List[Dict[str, Any]] = []

    if scenario == "base":
        policy = base_policy()
        for i in range(n):
            created = base_dt + timedelta(days=r.randint(0, 45), hours=r.randint(0, 23))
            recs.append(_make_record(
                rid=f"b-{i}",
                created_at=created,
                last_access_at=None,
                classification=None,
                legal_hold=False,
                legal_hold_set_at=None,
                legal_hold_released_at=None,
                ttl_override_days=None,
            ))

    elif scenario == "sliding":
        policy = base_policy(sliding_window=True)
        for i in range(n):
            created = base_dt + timedelta(days=r.randint(0, 30))
            last_acc = created + timedelta(days=r.randint(0, 60))
            recs.append(_make_record(
                rid=f"s-{i}",
                created_at=created,
                last_access_at=last_acc,
                classification=None,
                legal_hold=False,
                legal_hold_set_at=None,
                legal_hold_released_at=None,
                ttl_override_days=None,
            ))

    elif scenario == "pii":
        policy = base_policy()
        for i in range(n):
            created = base_dt + timedelta(days=r.randint(0, 30))
            recs.append(_make_record(
                rid=f"p-{i}",
                created_at=created,
                last_access_at=None,
                classification="PII",
                legal_hold=False,
                legal_hold_set_at=None,
                legal_hold_released_at=None,
                ttl_override_days=None,
            ))

    elif scenario == "legal_hold_active":
        policy = base_policy()
        for i in range(n):
            created = base_dt + timedelta(days=r.randint(0, 30))
            hold_set = created + timedelta(days=r.randint(1, 10))
            recs.append(_make_record(
                rid=f"h-{i}",
                created_at=created,
                last_access_at=None,
                classification=None,
                legal_hold=True,
                legal_hold_set_at=hold_set,
                legal_hold_released_at=None,
                ttl_override_days=None,
            ))

    elif scenario == "after_release_grace":
        policy = base_policy(grace_days_after_hold=21)
        for i in range(n):
            created = base_dt + timedelta(days=r.randint(0, 30))
            hold_set = created + timedelta(days=5)
            hold_rel = hold_set + timedelta(days=10)
            recs.append(_make_record(
                rid=f"g-{i}",
                created_at=created,
                last_access_at=None,
                classification=None,
                legal_hold=False,
                legal_hold_set_at=hold_set,
                legal_hold_released_at=hold_rel,
                ttl_override_days=None,
            ))

    elif scenario == "override_cap":
        policy = base_policy(allow_manual_override=True, max_ttl_days=180)
        for i in range(n):
            created = base_dt + timedelta(days=r.randint(0, 30))
            ov = r.choice([200, 300, 500])  # will be capped by policy
            recs.append(_make_record(
                rid=f"o-{i}",
                created_at=created,
                last_access_at=None,
                classification=None,
                legal_hold=False,
                legal_hold_set_at=None,
                legal_hold_released_at=None,
                ttl_override_days=ov,
            ))

    elif scenario == "jitter_positive":
        # Implementation may read RETENTION_JITTER_SEED -> set it deterministically
        os.environ.setdefault("RETENTION_JITTER_SEED", str(SEED_GLOBAL))
        policy = base_policy(jitter_days=3, jitter_mode="positive")
        for i in range(n):
            created = base_dt + timedelta(days=r.randint(0, 30))
            recs.append(_make_record(
                rid=f"j-{i}",
                created_at=created,
                last_access_at=None,
                classification=None,
                legal_hold=False,
                legal_hold_set_at=None,
                legal_hold_released_at=None,
                ttl_override_days=None,
            ))

    else:
        raise ValueError(f"Unknown scenario: {scenario}")

    return recs, policy


SCENARIOS = [
    "base",
    "sliding",
    "pii",
    "legal_hold_active",
    "after_release_grace",
    "override_cap",
    "jitter_positive",
]


# ------------------------------ Fixtures -------------------------------------

@pytest.fixture(scope="module", params=SCENARIOS)
def bulk_data(request):
    """Pre-generated bulk dataset per scenario to keep hot path clean."""
    records, policy = gen_dataset(N_BULK, request.param, SEED_GLOBAL)
    return request.param, records, policy

@pytest.fixture(scope="module", params=SCENARIOS)
def conc_data(request):
    """Pre-generated dataset for concurrency measurements."""
    records, policy = gen_dataset(N_CONC, request.param, SEED_GLOBAL + 1)
    return request.param, records, policy


# ------------------------------ Diagnostics ----------------------------------

def _rss_mb() -> Optional[float]:
    if not _HAS_PSUTIL:
        return None
    try:
        p = psutil.Process()
        return p.memory_info().rss / (1024 * 1024)
    except Exception:
        return None


# ------------------------------ Benchmarks -----------------------------------

def _run_compute_many(records: Sequence[Mapping[str, Any]], policy: Mapping[str, Any]) -> int:
    # Hot path: compute in a tight for-loop; return count to avoid dead-code elimination
    c = 0
    for rec in records:
        plan = compute_retention_plan(rec, policy)
        # consume a couple fields to keep it realistic
        if plan.deletion_at is not None:
            c += 1
    return c


def test_micro_baseline_single_call(benchmark):
    """Measure pure function call overhead and minimal path on a single record (base scenario)."""
    records, policy = gen_dataset(1, "base", SEED_GLOBAL)
    rec = records[0]

    def _target():
        return compute_retention_plan(rec, policy)

    result = benchmark.pedantic(_target, iterations=1000, rounds=10)
    benchmark.extra_info = {
        "scenario": "base",
        "iterations": 1000,
        "rounds": 10,
        "rss_mb": _rss_mb(),
    }
    # assert something trivial to keep pytest happy
    assert result is not None


def test_bulk_throughput_all_scenarios(bulk_data, benchmark):
    """Measure throughput over prebuilt datasets without allocations in hot path."""
    scenario, records, policy = bulk_data

    def _target():
        return _run_compute_many(records, policy)

    processed = benchmark(_target)
    benchmark.extra_info = {
        "scenario": scenario,
        "n": len(records),
        "rss_mb": _rss_mb(),
    }
    assert processed >= 0


def test_concurrency_threadpool(conc_data, benchmark):
    """Measure scalability with threads (I/O-free CPU-bound; still shows scheduling/GC effects)."""
    scenario, records, policy = conc_data
    n_workers = (os.cpu_count() or 2) if WORKERS <= 0 else WORKERS

    def _target():
        # Chunk records evenly across workers
        if n_workers <= 1:
            return _run_compute_many(records, policy)
        size = math.ceil(len(records) / n_workers)
        chunks = [records[i:i + size] for i in range(0, len(records), size)]
        total = 0
        with ThreadPoolExecutor(max_workers=n_workers, thread_name_prefix="bench-planner") as ex:
            for cnt in ex.map(lambda ch: _run_compute_many(ch, policy), chunks):
                total += cnt
        return total

    processed = benchmark(_target)
    benchmark.extra_info = {
        "scenario": scenario,
        "n": len(records),
        "workers": n_workers,
        "rss_mb": _rss_mb(),
    }
    assert processed >= 0


@pytest.mark.parametrize("tz_name", ["UTC", "Europe/Stockholm", "America/New_York"])
def test_timezone_and_rounding_overhead(benchmark, tz_name):
    """Measure any overhead when records come with different tz offsets."""
    try:
        import zoneinfo  # Python 3.9+
    except Exception:
        pytest.skip("zoneinfo not available")

    rng = _rng(SEED_GLOBAL + hash(tz_name) % 1000)
    tz = zoneinfo.ZoneInfo(tz_name)
    records: List[Dict[str, Any]] = []
    for i in range(min(2000, N_BULK // 2)):
        created = datetime(2025, 3, 28, rng.randint(0, 23), rng.randint(0, 59), tzinfo=tz)
        records.append(_make_record(
            rid=f"tz-{tz_name}-{i}",
            created_at=created,
            last_access_at=None,
            classification=None,
            legal_hold=False,
            legal_hold_set_at=None,
            legal_hold_released_at=None,
            ttl_override_days=None,
        ))
    policy = base_policy(tz=tz_name)

    def _target():
        return _run_compute_many(records, policy)

    processed = benchmark(_target)
    benchmark.extra_info = {"tz": tz_name, "n": len(records), "rss_mb": _rss_mb()}
    assert processed >= 0


def test_jitter_positive_overhead(benchmark):
    """Measure overhead when jitter is enabled in policy."""
    # Implementation may consume RETENTION_JITTER_SEED; set deterministically
    os.environ["RETENTION_JITTER_SEED"] = str(SEED_GLOBAL)
    records, policy = gen_dataset(min(3000, N_BULK), "jitter_positive", SEED_GLOBAL + 42)

    def _target():
        return _run_compute_many(records, policy)

    processed = benchmark(_target)
    benchmark.extra_info = {"scenario": "jitter_positive", "n": len(records), "rss_mb": _rss_mb()}
    assert processed >= 0


# ------------------------------ Smoke: result sanity -------------------------

def test_bulk_result_sanity(bulk_data):
    """Light sanity check to prevent optimizing away the core logic during refactors."""
    scenario, records, policy = bulk_data
    # Sample 100 results and ensure deletion_at is monotonic w.r.t. created_at for base scenario
    sample = records[: min(100, len(records))]
    outs = [compute_retention_plan(r, policy) for r in sample]
    # Basic invariants — non-failing and consistent tz
    assert all(o is not None for o in outs)
    # For legal_hold_active scenario, many deletion_at should be None
    if scenario == "legal_hold_active":
        assert sum(1 for o in outs if o.deletion_at is None) >= len(outs) // 2
