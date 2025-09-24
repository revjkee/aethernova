# -*- coding: utf-8 -*-
"""
Zero Trust PEP Latency Benchmark
Промышленный бенчмарк латентности PEP и смежных путей.

Запуск примеры:
  python -m zero_trust_core.tests.bench.bench_pep_latency --scenario session_validate --concurrency 8 --duration-s 10 --pretty
  python tests/bench/bench_pep_latency.py --scenario pep_stub --iterations 200000 --concurrency 4 --slo-ms 1.0 --csv-out bench.csv
"""

from __future__ import annotations

import argparse
import csv
import gc
import json
import math
import os
import platform
import random
import statistics
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ---------------------- Опциональные импорты проекта ----------------------

_HAS_IDGEN = False
_HAS_SESSION = False

try:
    # Официальные утилиты ID, если доступны
    from zero_trust.utils.idgen import IdGenerator, SnowflakeGenerator, IdGenConfig
    _HAS_IDGEN = True
except Exception:
    _HAS_IDGEN = False

try:
    # Менеджер сессий для сценария session_validate
    from zero_trust.session.session_manager import SessionManager
    _HAS_SESSION = True
except Exception:
    _HAS_SESSION = False

# ---------------------- Утилиты времени/метрик ----------------------

def _now_ns() -> int:
    return time.perf_counter_ns()

def _percentiles(xs: Sequence[float], ps: Sequence[float]) -> Dict[str, float]:
    if not xs:
        return {f"p{int(p*1000)/10:.1f}": float("nan") for p in ps}
    s = sorted(xs)
    n = len(s)
    out: Dict[str, float] = {}
    for p in ps:
        # p в [0,1]; позиция по nearest-rank
        idx = min(max(int(math.ceil(p * n)) - 1, 0), n - 1)
        out[f"p{int(p*1000)/10:.1f}"] = s[idx]
    return out

def _exp_histogram(xs: Sequence[float], start_us: float = 0.5, factor: float = 2.0, buckets: int = 16) -> List[Tuple[str, int]]:
    """
    Экспоненциальная гистограмма по микросекундам.
    """
    if buckets < 1:
        buckets = 1
    bounds: List[float] = [start_us * (factor ** i) for i in range(buckets)]
    counts = [0] * (buckets + 1)  # последний — overflow
    for v in xs:
        placed = False
        for i, b in enumerate(bounds):
            if v <= b:
                counts[i] += 1
                placed = True
                break
        if not placed:
            counts[-1] += 1
    labels = [f"<= {b:.3f}us" for b in bounds] + ["> last"]
    return list(zip(labels, counts))

def _qps(samples: int, wall_s: float) -> float:
    if wall_s <= 0:
        return float("nan")
    return samples / wall_s

# ---------------------- Сценарии ----------------------

class ScenarioBase:
    name: str = "base"
    def setup(self) -> None:
        pass
    def op(self) -> bool:
        raise NotImplementedError
    def teardown(self) -> None:
        pass

class ScenarioIdgenUlid(ScenarioBase):
    name = "idgen_ulid"
    def __init__(self) -> None:
        if _HAS_IDGEN:
            self._idgen = IdGenerator()
        else:
            self._idgen = None
    def setup(self) -> None:
        pass
    def op(self) -> bool:
        if self._idgen:
            _ = self._idgen.ulid()
        else:
            # Фолбэк без зависимостей
            _ = os.urandom(16).hex()
        return True

class ScenarioIdgenSnowflake(ScenarioBase):
    name = "idgen_snowflake"
    def __init__(self) -> None:
        if _HAS_IDGEN:
            self._gen = SnowflakeGenerator(IdGenConfig())
        else:
            self._gen = None
    def setup(self) -> None:
        pass
    def op(self) -> bool:
        if self._gen:
            _ = self._gen.next_id()
        else:
            # Фолбэк — счётчик в памяти
            _ = int(time.time() * 1000) << 12
        return True

class ScenarioSessionValidate(ScenarioBase):
    name = "session_validate"
    def __init__(self, valid_ratio: float = 0.9, tamper_ratio: float = 0.05, revoked_ratio: float = 0.05) -> None:
        self.valid_ratio = valid_ratio
        self.tamper_ratio = tamper_ratio
        self.revoked_ratio = revoked_ratio
        self._mgr: Optional[Any] = None
        self._valid_tokens: List[str] = []
        self._tampered_tokens: List[str] = []
        self._revoked_tokens: List[str] = []
        self._rnd = random.Random(1337)

    def setup(self) -> None:
        if not _HAS_SESSION:
            raise RuntimeError("SessionManager module not found for scenario 'session_validate'")
        self._mgr = SessionManager(hmac_key=b"bench-hmac-key-32-xxxxxxxxxxxxxxx", ttl_seconds=60, sliding=True, max_sessions=100000, bind_fingerprint=False, bind_ip=False)
        # Подготовим корпуса токенов
        total = 5000
        for _ in range(total):
            tok = self._mgr.create_session()
            self._valid_tokens.append(tok)
            # Тампер версия
            tampered = tok[:-1] + ("A" if tok[-1] != "A" else "B")
            self._tampered_tokens.append(tampered)
        # Отозванные
        for t in self._valid_tokens[: int(len(self._valid_tokens) * self.revoked_ratio) or 1]:
            self._mgr.revoke(t)
            self._revoked_tokens.append(t)

    def op(self) -> bool:
        assert self._mgr is not None
        r = self._rnd.random()
        if r < self.valid_ratio:
            t = self._rnd.choice(self._valid_tokens)
        elif r < self.valid_ratio + self.tamper_ratio:
            t = self._rnd.choice(self._tampered_tokens)
        else:
            t = self._rnd.choice(self._revoked_tokens) if self._revoked_tokens else self._rnd.choice(self._tampered_tokens)
        ok, _, _ = self._mgr.validate(t)
        return ok

class ScenarioPepStub(ScenarioBase):
    """
    Эталонный PEP-стаб: проверка атрибутов запроса против компактной политики.
    Имитация реального PEP (ABAC): subject, action, resource, context.
    """
    name = "pep_stub"

    def __init__(self) -> None:
        self._policy: Dict[str, Any] = {}
        self._rnd = random.Random(424242)

    def setup(self) -> None:
        # Политика: разрешаем чтение low/medium ресурсов, запись только admin, время — рабочие часы.
        self._policy = {
            "allow_actions": {"read", "list"},
            "write_roles": {"admin", "ops"},
            "work_hours": (7, 20),  # 07:00-20:00
            "blocked_ips": {"203.0.113.13"},
            "sensitivity_levels": {"low", "medium", "high"},
        }

    def _decision(self, subject_role: str, action: str, resource_level: str, ip: str, ts: float) -> bool:
        h_start, h_end = self._policy["work_hours"]
        hour = (int(ts) // 3600) % 24
        if ip in self._policy["blocked_ips"]:
            return False
        if action in self._policy["allow_actions"]:
            return resource_level in {"low", "medium"}
        if action == "write":
            if subject_role in self._policy["write_roles"] and h_start <= hour <= h_end:
                return resource_level in {"low", "medium"}
            return False
        if action == "delete":
            return subject_role == "admin" and resource_level == "low"
        return False

    def op(self) -> bool:
        role = self._rnd.choice(["user", "ops", "admin"])
        action = self._rnd.choice(["read", "list", "write", "delete"])
        level = self._rnd.choice(["low", "medium", "high"])
        ip = self._rnd.choice(["198.51.100.5", "203.0.113.13", "192.0.2.77"])
        ts = time.time()
        return self._decision(role, action, level, ip, ts)

# ---------------------- Раннер бенчмарка ----------------------

@dataclass
class BenchResult:
    scenario: str
    concurrency: int
    samples: int
    errors: int
    wall_seconds: float
    mean_us: float
    min_us: float
    max_us: float
    stdev_us: float
    percentiles_us: Dict[str, float]
    histogram_us: List[Tuple[str, int]]
    qps: float
    slo_under_ms: Optional[float]
    slo_ok_ratio: Optional[float]
    env: Dict[str, str]

def _lower_priority() -> None:
    try:
        if hasattr(os, "nice"):
            os.nice(5)
    except Exception:
        pass
    try:
        if sys.platform.startswith("win"):
            import ctypes, ctypes.wintypes as wt
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            handle = kernel32.GetCurrentProcess()
            BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
            kernel32.SetPriorityClass(handle, BELOW_NORMAL_PRIORITY_CLASS)
    except Exception:
        pass

def _set_affinity(cpu: Optional[int]) -> None:
    if cpu is None:
        return
    try:
        if hasattr(os, "sched_setaffinity"):
            os.sched_setaffinity(0, {int(cpu)})
    except Exception:
        pass

def run_benchmark(
    scenario: ScenarioBase,
    duration_s: Optional[float],
    iterations: Optional[int],
    concurrency: int,
    warmup_s: float,
    disable_gc: bool,
    pin_cpu: Optional[int],
    slo_ms: Optional[float],
) -> BenchResult:
    if disable_gc:
        gc.disable()
    _lower_priority()
    _set_affinity(pin_cpu)

    scenario.setup()

    # Прогрев
    t_end_warm = time.time() + warmup_s
    while time.time() < t_end_warm:
        scenario.op()

    barrier = threading.Barrier(concurrency)
    stop_flag = False
    samples_counts = [0] * concurrency
    errors_counts = [0] * concurrency
    lat_lists: List[List[float]] = [[] for _ in range(concurrency)]

    def worker(idx: int) -> None:
        nonlocal stop_flag
        rnd = random.Random(1000 + idx)
        barrier.wait()
        local_samples = 0
        local_errors = 0
        local_lat = lat_lists[idx]
        if iterations is None:
            # По времени
            t_end = time.time() + float(duration_s or 10.0)
            while not stop_flag and time.time() < t_end:
                t0 = _now_ns()
                ok = scenario.op()
                t1 = _now_ns()
                local_lat.append((t1 - t0) / 1000.0)  # микросекунды
                local_samples += 1
                if not ok:
                    local_errors += 1
        else:
            # По числу итераций
            to_do = iterations // concurrency + (1 if idx < (iterations % concurrency) else 0)
            for _ in range(to_do):
                t0 = _now_ns()
                ok = scenario.op()
                t1 = _now_ns()
                local_lat.append((t1 - t0) / 1000.0)
                local_samples += 1
                if not ok:
                    local_errors += 1
        samples_counts[idx] = local_samples
        errors_counts[idx] = local_errors

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(concurrency)]

    wall_t0 = time.time()
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    wall_t1 = time.time()
    stop_flag = True

    scenario.teardown()

    all_lat = [v for sub in lat_lists for v in sub]
    total_samples = sum(samples_counts)
    total_errors = sum(errors_counts)
    wall = max(wall_t1 - wall_t0 - warmup_s, 0.000001) if iterations is None else (wall_t1 - wall_t0 - warmup_s if warmup_s > 0 else wall_t1 - wall_t0)

    if not all_lat:
        all_lat = [float("nan")]

    mean_us = statistics.fmean(all_lat)
    min_us = min(all_lat)
    max_us = max(all_lat)
    stdev_us = statistics.pstdev(all_lat) if len(all_lat) > 1 else 0.0
    pmap = _percentiles(all_lat, [0.50, 0.90, 0.95, 0.99, 0.999])
    hist = _exp_histogram(all_lat, start_us=0.5, factor=2.0, buckets=16)
    qps = _qps(total_samples, wall)

    slo_ok_ratio: Optional[float] = None
    if slo_ms is not None:
        thr_us = slo_ms * 1000.0
        okc = sum(1 for v in all_lat if v <= thr_us)
        slo_ok_ratio = okc / len(all_lat) if all_lat else float("nan")

    env = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_count": str(os.cpu_count() or 0),
    }

    return BenchResult(
        scenario=scenario.name,
        concurrency=concurrency,
        samples=total_samples,
        errors=total_errors,
        wall_seconds=wall,
        mean_us=mean_us,
        min_us=min_us,
        max_us=max_us,
        stdev_us=stdev_us,
        percentiles_us=pmap,
        histogram_us=hist,
        qps=qps,
        slo_under_ms=slo_ms,
        slo_ok_ratio=slo_ok_ratio,
        env=env,
    )

# ---------------------- CLI ----------------------

def _scenario_from_args(name: str) -> ScenarioBase:
    if name == "idgen_ulid":
        return ScenarioIdgenUlid()
    if name == "idgen_snowflake":
        return ScenarioIdgenSnowflake()
    if name == "session_validate":
        return ScenarioSessionValidate()
    if name == "pep_stub":
        return ScenarioPepStub()
    raise SystemExit(f"Unknown scenario: {name}")

def _to_json(result: BenchResult) -> str:
    d = {
        "scenario": result.scenario,
        "concurrency": result.concurrency,
        "samples": result.samples,
        "errors": result.errors,
        "wall_seconds": round(result.wall_seconds, 6),
        "mean_us": round(result.mean_us, 3),
        "min_us": round(result.min_us, 3),
        "max_us": round(result.max_us, 3),
        "stdev_us": round(result.stdev_us, 3),
        "percentiles_us": {k: round(v, 3) for k, v in result.percentiles_us.items()},
        "histogram_us": result.histogram_us,
        "qps": round(result.qps, 3),
        "slo_under_ms": result.slo_under_ms,
        "slo_ok_ratio": None if result.slo_ok_ratio is None else round(result.slo_ok_ratio, 6),
        "env": result.env,
    }
    return json.dumps(d, ensure_ascii=False)

def _print_pretty(result: BenchResult) -> None:
    print(f"Scenario: {result.scenario}")
    print(f"Concurrency: {result.concurrency} | Samples: {result.samples} | Errors: {result.errors} | Wall: {result.wall_seconds:.3f}s | QPS: {result.qps:.1f}")
    print(f"Latency [us] mean={result.mean_us:.2f} min={result.min_us:.2f} p50={result.percentiles_us['p50.0']:.2f} "
          f"p90={result.percentiles_us['p90.0']:.2f} p95={result.percentiles_us['p95.0']:.2f} "
          f"p99={result.percentiles_us['p99.0']:.2f} p99.9={result.percentiles_us['p99.9']:.2f} max={result.max_us:.2f}")
    if result.slo_under_ms is not None and result.slo_ok_ratio is not None:
        print(f"SLO: <= {result.slo_under_ms} ms -> {result.slo_ok_ratio*100:.3f}% within SLO")
    print("Histogram (exp, microseconds):")
    for label, cnt in result.histogram_us:
        print(f"  {label:<12} : {cnt}")

def _append_csv(path: str, result: BenchResult) -> None:
    header = ["ts_iso","scenario","concurrency","samples","errors","wall_seconds","qps","mean_us","p50_us","p95_us","p99_us","max_us","slo_ms","slo_ok_ratio"]
    row = [
        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        result.scenario,
        result.concurrency,
        result.samples,
        result.errors,
        f"{result.wall_seconds:.6f}",
        f"{result.qps:.3f}",
        f"{result.mean_us:.3f}",
        f"{result.percentiles_us['p50.0']:.3f}",
        f"{result.percentiles_us['p95.0']:.3f}",
        f"{result.percentiles_us['p99.0']:.3f}",
        f"{result.max_us:.3f}",
        "" if result.slo_under_ms is None else f"{result.slo_under_ms:.3f}",
        "" if result.slo_ok_ratio is None else f"{result.slo_ok_ratio:.6f}",
    ]
    exists = os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if not exists:
            w.writerow(header)
        w.writerow(row)

def main() -> int:
    parser = argparse.ArgumentParser(description="Zero Trust PEP Latency Benchmark")
    parser.add_argument("--scenario", type=str, default="pep_stub",
                        choices=["pep_stub","session_validate","idgen_ulid","idgen_snowflake"],
                        help="Сценарий бенчмарка")
    parser.add_argument("--concurrency", type=int, default=4, help="Количество потоков")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--duration-s", type=float, default=10.0, help="Длительность теста в секундах")
    group.add_argument("--iterations", type=int, help="Общее число операций (делится между потоками)")
    parser.add_argument("--warmup-s", type=float, default=2.0, help="Время прогрева")
    parser.add_argument("--slo-ms", type=float, default=None, help="Порог SLO в миллисекундах для расчета процента укладываний")
    parser.add_argument("--disable-gc", action="store_true", help="Отключить GC на время бенчмарка")
    parser.add_argument("--pin-cpu", type=int, default=None, help="Закрепить процесс за указанным CPU (Linux)")
    parser.add_argument("--json-out", type=str, default=None, help="Путь для JSON результата")
    parser.add_argument("--csv-out", type=str, default=None, help="Путь для CSV строки результатов")
    parser.add_argument("--pretty", action="store_true", help="Человекочитаемый вывод")
    args = parser.parse_args()

    scenario = _scenario_from_args(args.scenario)
    res = run_benchmark(
        scenario=scenario,
        duration_s=args.duration_s if args.iterations is None else None,
        iterations=args.iterations,
        concurrency=max(1, int(args.concurrency)),
        warmup_s=max(0.0, float(args.warmup_s)),
        disable_gc=bool(args.disable_gc),
        pin_cpu=args.pin_cpu,
        slo_ms=args.slo_ms,
    )

    payload = _to_json(res)
    if args.pretty:
        _print_pretty(res)
    else:
        print(payload)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            f.write(payload)
    if args.csv_out:
        _append_csv(args.csv_out, res)

    return 0

if __name__ == "__main__":
    sys.exit(main())
