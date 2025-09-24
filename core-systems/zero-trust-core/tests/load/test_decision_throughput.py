# File: zero-trust-core/tests/load/test_decision_throughput.py
# Industrial-grade load test for Zero Trust decision engine throughput and latency.
# Mode A (in-process):   zero_trust.decision.engine.DecisionEngine().evaluate(payload) -> DecisionResult
# Mode B (HTTP):         set ZTC_LOAD_URL=https://host/api/v1/decision  (POST JSON)
#
# Configuration via env:
#   ZTC_LOAD_MODE=http|inproc           # default: auto-detect
#   ZTC_LOAD_URL=<url>                  # required for http mode
#   ZTC_RPS=200                         # steady-state requests per second
#   ZTC_CONCURRENCY=64                  # max concurrent workers
#   ZTC_DURATION_SEC=30                 # measurement duration (excluding warmup)
#   ZTC_WARMUP_SEC=5                    # warmup duration
#   ZTC_TIMEOUT_MS=800                  # per-request timeout
#   ZTC_BACKOFF_BASE_MS=25              # initial backoff on 5xx/timeout
#   ZTC_BACKOFF_MAX_MS=250
#   ZTC_SLA_P50_MS=40                   # SLA thresholds (optional)
#   ZTC_SLA_P95_MS=120
#   ZTC_SLA_P99_MS=250
#   ZTC_SLA_ERR_RATE=0.01               # max fraction of errors
#   ZTC_OUT_CSV=./out/decision_bench.csv
#
# Requires: pytest (stdlib otherwise)

from __future__ import annotations

import json
import math
import os
import queue
import random
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
import urllib.request
import urllib.error

import pytest


# ---------- Optional in-process engine ----------
_ENGINE = None
_ENGINE_ERR = None
try:
    from zero_trust.decision.engine import DecisionEngine  # type: ignore
    _ENGINE = DecisionEngine()
except Exception as e:  # engine may be absent in this repo snapshot
    _ENGINE_ERR = e


# ---------- Config helpers ----------

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default

def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except Exception:
        return default

def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).lower() not in ("0", "false", "no")

CFG = {
    "mode": os.getenv("ZTC_LOAD_MODE", "").strip().lower(),           # "http"|"inproc"|auto
    "url": os.getenv("ZTC_LOAD_URL", "").strip(),
    "rps": _env_int("ZTC_RPS", 200),
    "conc": _env_int("ZTC_CONCURRENCY", 64),
    "dur": _env_int("ZTC_DURATION_SEC", 30),
    "warm": _env_int("ZTC_WARMUP_SEC", 5),
    "timeout_ms": _env_int("ZTC_TIMEOUT_MS", 800),
    "backoff_base_ms": _env_int("ZTC_BACKOFF_BASE_MS", 25),
    "backoff_max_ms": _env_int("ZTC_BACKOFF_MAX_MS", 250),
    "sla_p50": _env_int("ZTC_SLA_P50_MS", 0),
    "sla_p95": _env_int("ZTC_SLA_P95_MS", 0),
    "sla_p99": _env_int("ZTC_SLA_P99_MS", 0),
    "sla_err_rate": _env_float("ZTC_SLA_ERR_RATE", -1.0),
    "csv": os.getenv("ZTC_OUT_CSV", "./out/decision_bench.csv"),
}

def _detect_mode() -> str:
    m = CFG["mode"]
    if m in ("http", "inproc"):
        return m
    if CFG["url"]:
        return "http"
    if _ENGINE is not None:
        return "inproc"
    return "skip"


# ---------- Payload generator (realistic signals) ----------

def _rand_ip(rnd: random.Random) -> str:
    return ".".join(str(rnd.randint(1, 254)) for _ in range(4))

def _device_fingerprint(rnd: random.Random) -> str:
    alpha = "abcdef0123456789"
    return "".join(rnd.choice(alpha) for _ in range(32))

def _gen_payload(rnd: random.Random, user_id: Optional[str] = None) -> Dict[str, Any]:
    # Signals roughly in [0,1] where 1 => высокий риск
    geo_anomaly = rnd.random()
    device_rep = rnd.random()
    ip_risk = rnd.random()
    mfa_present = rnd.choice([True, False])
    hour = rnd.randint(0, 23)
    return {
        "subject": {
            "user_id": user_id or f"user-{rnd.randint(1, 50000)}",
            "tenant_id": f"t-{rnd.randint(1, 128)}",
            "roles": rnd.sample(["user", "staff", "admin", "contractor"], k=rnd.randint(1, 2)),
        },
        "context": {
            "ip": _rand_ip(rnd),
            "ua": rnd.choice(["Chrome", "Safari", "Firefox", "Edge"]),
            "device_fp": _device_fingerprint(rnd),
            "hour": hour,
            "mfa": mfa_present,
        },
        "signals": {
            "geo_anomaly": geo_anomaly,
            "device_reputation": device_rep,
            "ip_risk": ip_risk,
        },
        "resource": {
            "type": rnd.choice(["vault", "api", "admin_ui"]),
            "name": f"res-{rnd.randint(1, 2000)}",
            "action": rnd.choice(["read", "write", "delete", "approve"]),
        },
        "trace_id": f"{rnd.randint(1, 10**12):x}",
    }


# ---------- HTTP client with timeout and backoff ----------

class _HttpClient:
    def __init__(self, base_url: str, timeout_ms: int):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout_ms / 1000.0

    def evaluate(self, payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            url=self.base_url,
            data=data,
            headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "ZTC-Load/1.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            code = resp.getcode()
            raw = resp.read()
            if raw:
                return code, json.loads(raw.decode("utf-8"))
            return code, {}

# ---------- Token bucket for RPS ----------

class _TokenBucket:
    def __init__(self, rate_per_sec: float, capacity: float):
        self.rate = float(rate_per_sec)
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.last = time.monotonic()
        self.lock = threading.Lock()

    def take(self, n: float = 1.0) -> None:
        while True:
            with self.lock:
                now = time.monotonic()
                delta = now - self.last
                self.last = now
                self.tokens = min(self.capacity, self.tokens + delta * self.rate)
                if self.tokens >= n:
                    self.tokens -= n
                    return
            time.sleep(0.0005)

# ---------- Metrics ----------

@dataclass
class Metrics:
    latencies_ms: list
    errors: int
    oks: int

    @property
    def total(self) -> int:
        return self.errors + self.oks

def _percentile(sorted_vals, p: float) -> float:
    if not sorted_vals:
        return float("nan")
    k = (len(sorted_vals) - 1) * p
    f = math.floor(k); c = math.ceil(k)
    if f == c:
        return float(sorted_vals[int(k)])
    d0 = sorted_vals[int(f)] * (c - k)
    d1 = sorted_vals[int(c)] * (k - f)
    return float(d0 + d1)

def _aggregate(lat_ms: list, errors: int, oks: int) -> Dict[str, Any]:
    lat_ms.sort()
    res = {
        "count": oks,
        "errors": errors,
        "p50_ms": round(_percentile(lat_ms, 0.50), 3) if lat_ms else float("nan"),
        "p90_ms": round(_percentile(lat_ms, 0.90), 3) if lat_ms else float("nan"),
        "p95_ms": round(_percentile(lat_ms, 0.95), 3) if lat_ms else float("nan"),
        "p99_ms": round(_percentile(lat_ms, 0.99), 3) if lat_ms else float("nan"),
        "mean_ms": round(statistics.fmean(lat_ms), 3) if lat_ms else float("nan"),
        "throughput_rps": 0.0,  # set later
    }
    return res

def _write_csv(path: str, head: Dict[str, Any]) -> None:
    Path(os.path.dirname(path) or ".").mkdir(parents=True, exist_ok=True)
    hdrs = list(head.keys())
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            f.write(",".join(hdrs) + "\n")
    with open(path, "a", encoding="utf-8") as f:
        vals = [str(head[k]) for k in hdrs]
        f.write(",".join(vals) + "\n")


# ---------- Worker ----------

def _evaluate_inproc(payload: Dict[str, Any], timeout_ms: int) -> Tuple[bool, Optional[float]]:
    if _ENGINE is None:
        raise RuntimeError(f"In-process engine unavailable: {_ENGINE_ERR}")
    t0 = time.perf_counter()
    # If engine supports timeout in evaluate, pass it, else rely on wall clock.
    res = _ENGINE.evaluate(payload)  # type: ignore
    t1 = time.perf_counter()
    # Expect res like {"decision":"allow","score":...} or object with .decision
    if res is None:
        return False, None
    return True, (t1 - t0) * 1000.0

def _evaluate_http(client: _HttpClient, payload: Dict[str, Any], timeout_ms: int, backoff_base: float, backoff_max: float) -> Tuple[bool, Optional[float]]:
    attempt = 0
    t0 = time.perf_counter()
    while True:
        attempt += 1
        try:
            c0 = time.perf_counter()
            code, body = client.evaluate(payload)
            c1 = time.perf_counter()
            if 200 <= code < 300:
                return True, (c1 - c0) * 1000.0
            # 5xx -> retry with backoff
            if code >= 500 and (c1 - t0) * 1000.0 < timeout_ms:
                back = min(backoff_max, backoff_base * (2 ** (attempt - 1)) * (0.5 + random.random()))
                time.sleep(back / 1000.0)
                continue
            return False, None
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            c_now = (time.perf_counter() - t0) * 1000.0
            if c_now < timeout_ms:
                back = min(backoff_max, backoff_base * (2 ** (attempt - 1)) * (0.5 + random.random()))
                time.sleep(back / 1000.0)
                continue
            return False, None

# ---------- The load test itself ----------

@pytest.mark.load
def test_decision_throughput():
    mode = _detect_mode()
    if mode == "skip":
        pytest.skip("No DecisionEngine and no ZTC_LOAD_URL; skipping load test.")
    if mode == "http" and not CFG["url"]:
        pytest.skip("ZTC_LOAD_URL not set; skipping HTTP mode.")

    rps = max(1, CFG["rps"])
    conc = max(1, CFG["conc"])
    dur = max(1, CFG["dur"])
    warm = max(0, CFG["warm"])
    timeout_ms = max(1, CFG["timeout_ms"])
    backoff_base = CFG["backoff_base_ms"]
    backoff_max = CFG["backoff_max_ms"]

    client = _HttpClient(CFG["url"], timeout_ms) if mode == "http" else None
    bucket = _TokenBucket(rate_per_sec=float(rps), capacity=float(rps))
    rnd = random.Random(173_17)

    lat_ms: list[float] = []
    errors = 0
    oks = 0
    err_lock = threading.Lock()
    lat_lock = threading.Lock()

    stop_flag = threading.Event()
    start_time = time.monotonic()

    def worker_loop():
        nonlocal errors, oks
        while not stop_flag.is_set():
            # RPS throttle
            bucket.take(1.0)
            payload = _gen_payload(rnd)
            t0 = time.perf_counter()
            ok = False
            latency = None
            if mode == "http":
                ok, latency = _evaluate_http(client, payload, timeout_ms, backoff_base, backoff_max)  # type: ignore
            else:
                ok, latency = _evaluate_inproc(payload, timeout_ms)
            if ok and latency is not None:
                with lat_lock:
                    lat_ms.append(latency)
                with err_lock:
                    oks += 1
            else:
                with err_lock:
                    errors += 1

    # Warmup
    if warm > 0:
        stop_warm = time.monotonic() + warm
        with ThreadPoolExecutor(max_workers=min(conc, 8)) as ex:
            futs = [ex.submit(worker_loop) for _ in range(min(conc, 8))]
            while time.monotonic() < stop_warm:
                time.sleep(0.05)
            stop_flag.set()
            for _ in futs:
                pass
        # reset accumulators
        stop_flag.clear()
        lat_ms.clear()
        errors = 0
        oks = 0
        start_time = time.monotonic()

    # Measurement
    end_time = start_time + dur
    with ThreadPoolExecutor(max_workers=conc) as ex:
        futs = [ex.submit(worker_loop) for _ in range(conc)]
        while time.monotonic() < end_time:
            time.sleep(0.02)
        stop_flag.set()
        for _ in futs:
            pass

    elapsed = max(0.0001, time.monotonic() - start_time)
    agg = _aggregate(lat_ms, errors, oks)
    agg["throughput_rps"] = round(oks / elapsed, 3)
    agg["target_rps"] = rps
    agg["concurrency"] = conc
    agg["duration_sec"] = dur
    agg["mode"] = mode
    agg["errors"] = errors
    agg["oks"] = oks
    agg["total"] = errors + oks

    # Export
    try:
        _write_csv(CFG["csv"], agg)
    except Exception:
        pass

    # SLA assertions if provided
    sla_msgs = []
    if CFG["sla_p50"] > 0 and not math.isnan(agg["p50_ms"]) and agg["p50_ms"] > CFG["sla_p50"]:
        sla_msgs.append(f"p50 {agg['p50_ms']}ms > SLA {CFG['sla_p50']}ms")
    if CFG["sla_p95"] > 0 and not math.isnan(agg["p95_ms"]) and agg["p95_ms"] > CFG["sla_p95"]:
        sla_msgs.append(f"p95 {agg['p95_ms']}ms > SLA {CFG['sla_p95']}ms")
    if CFG["sla_p99"] > 0 and not math.isnan(agg["p99_ms"]) and agg["p99_ms"] > CFG["sla_p99"]:
        sla_msgs.append(f"p99 {agg['p99_ms']}ms > SLA {CFG['sla_p99']}ms")
    if CFG["sla_err_rate"] >= 0.0 and agg["total"] > 0:
        err_rate = errors / agg["total"]
        agg["err_rate"] = round(err_rate, 6)
        if err_rate > CFG["sla_err_rate"]:
            sla_msgs.append(f"error_rate {err_rate:.4f} > SLA {CFG['sla_err_rate']:.4f}")

    # Основные инварианты
    assert agg["total"] > 0, "No requests executed"
    assert agg["throughput_rps"] > 0, "Zero throughput measured"
    if sla_msgs:
        pytest.fail("SLA violation: " + "; ".join(sla_msgs))

    # Для наглядности вывести краткую сводку в лог pytest
    print(json.dumps(agg, ensure_ascii=False, sort_keys=True))


"""
Примеры запуска:

# HTTP режим (цель p95<=120ms, ошибок <1%)
export ZTC_LOAD_URL=https://ztc.example.com/api/v1/decision
export ZTC_RPS=300 ZTC_CONCURRENCY=128 ZTC_DURATION_SEC=60 ZTC_WARMUP_SEC=10
export ZTC_SLA_P95_MS=120 ZTC_SLA_ERR_RATE=0.01
pytest -q tests/load/test_decision_throughput.py -m load

# In‑process режим (если доступен zero_trust.decision.engine)
export ZTC_RPS=500 ZTC_CONCURRENCY=256 ZTC_DURATION_SEC=30
pytest -q tests/load/test_decision_throughput.py -m load
"""
