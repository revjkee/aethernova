# engine/tests/bench/bench_ecs_iter.py
from __future__ import annotations

import argparse
import contextlib
import csv
import gc
import json
import logging
import os
import platform
import random
import statistics
import sys
import time
import tracemalloc
from dataclasses import dataclass, asdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

LOG = logging.getLogger("bench.ecs")
if not LOG.handlers:
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s"))
    LOG.addHandler(h)
    LOG.setLevel(logging.INFO)

# -----------------------------
# Опциональные зависимости
# -----------------------------
_HAS_NUMPY = False
_HAS_ESPER = False
_HAS_PSUTIL = False
_HAS_MPL = False

try:
    import numpy as np  # type: ignore
    _HAS_NUMPY = True
except Exception:
    pass

try:
    import esper  # type: ignore
    _HAS_ESPER = True
except Exception:
    pass

try:
    import psutil  # type: ignore
    _HAS_PSUTIL = True
except Exception:
    pass

try:
    import matplotlib.pyplot as plt  # type: ignore
    _HAS_MPL = True
except Exception:
    pass


# -----------------------------
# Конфигурация бенчмарка
# -----------------------------

@dataclass
class BenchConfig:
    entities: int = 200_000
    with_velocity_ratio: float = 0.7
    with_accel_ratio: float = 0.5
    seed: int = 1337

    # итерации систем
    iters: int = 200
    warmup_iters: int = 50

    # реплики (повторения) для усреднения
    repeats: int = 5

    # системные параметры
    cpu_affinity: Optional[int] = None  # id CPU для пиннинга
    disable_gc: bool = True
    tracemalloc: bool = True

    # вывод
    out_json: Optional[str] = None
    out_csv: Optional[str] = None
    out_png: Optional[str] = None

    # выбор бекендов
    backends: Tuple[str, ...] = ("naive", "packed", "esper", "numpy")

    # нагрузка/варианты систем
    sys_variant: str = "full"  # full|pos_only|mask_query


# -----------------------------
# Утилиты системные
# -----------------------------

def try_pin_cpu(cpu_id: Optional[int]) -> None:
    if cpu_id is None:
        return
    with contextlib.suppress(Exception):
        if platform.system() == "Linux":
            os.sched_setaffinity(0, {cpu_id})
            LOG.info("Pinned process to CPU %s via sched_setaffinity", cpu_id)
            return
    if _HAS_PSUTIL and cpu_id is not None:
        with contextlib.suppress(Exception):
            psutil.Process().cpu_affinity([cpu_id])
            LOG.info("Pinned process to CPU %s via psutil", cpu_id)

def now_ns() -> int:
    return time.perf_counter_ns()

def rss_bytes() -> int:
    if _HAS_PSUTIL:
        try:
            return int(psutil.Process().memory_info().rss)
        except Exception:
            pass
    # best-effort, неизвестно — возвращаем 0
    return 0


# -----------------------------
# Модель данных для ECS
# -----------------------------

@dataclass
class Pos:
    x: float
    y: float

@dataclass
class Vel:
    vx: float
    vy: float

@dataclass
class Acc:
    ax: float
    ay: float


# -----------------------------
# Интерфейс backend'а ECS
# -----------------------------

class ECSBackend:
    name: str = "base"

    def setup(self, n: int, cfg: BenchConfig) -> None:
        raise NotImplementedError

    def sys_pos_integrate(self, dt: float, iters: int) -> None:
        """pos += vel * dt (только для тех, у кого есть pos и vel)."""
        raise NotImplementedError

    def sys_vel_integrate(self, dt: float, iters: int) -> None:
        """vel += acc * dt (только у кого есть vel и acc)."""
        raise NotImplementedError

    def sys_mask_query(self, iters: int) -> int:
        """Тест выборки: подсчёт сущностей с pos и без vel (или произвольное условие). Возвращает счётчик."""
        raise NotImplementedError

    def teardown(self) -> None:
        pass


# -----------------------------
# Backend 1: NaiveDict (dict-of-sets)
# -----------------------------

class NaiveDictECS(ECSBackend):
    name = "naive"

    def __init__(self) -> None:
        self.pos: Dict[int, Pos] = {}
        self.vel: Dict[int, Vel] = {}
        self.acc: Dict[int, Acc] = {}
        self.entities: List[int] = []

    def setup(self, n: int, cfg: BenchConfig) -> None:
        rnd = random.Random(cfg.seed)
        self.entities = list(range(n))
        for e in self.entities:
            self.pos[e] = Pos(rnd.random(), rnd.random())
            if rnd.random() < cfg.with_velocity_ratio:
                self.vel[e] = Vel(rnd.random(), rnd.random())
            if rnd.random() < cfg.with_accel_ratio:
                self.acc[e] = Acc(rnd.random(), rnd.random())

    def sys_pos_integrate(self, dt: float, iters: int) -> None:
        pos, vel = self.pos, self.vel
        for _ in range(iters):
            for e, v in vel.items():
                p = pos.get(e)
                if p:
                    p.x += v.vx * dt
                    p.y += v.vy * dt

    def sys_vel_integrate(self, dt: float, iters: int) -> None:
        vel, acc = self.vel, self.acc
        for _ in range(iters):
            for e, a in acc.items():
                v = vel.get(e)
                if v:
                    v.vx += a.ax * dt
                    v.vy += a.ay * dt

    def sys_mask_query(self, iters: int) -> int:
        pos, vel = self.pos, self.vel
        cnt = 0
        for _ in range(iters):
            for e in pos.keys():
                if e not in vel:
                    cnt += 1
        return cnt


# -----------------------------
# Backend 2: PackedList (compact arrays)
# -----------------------------

class PackedListECS(ECSBackend):
    name = "packed"

    def __init__(self) -> None:
        self.pos_e: List[int] = []
        self.pos_x: List[float] = []
        self.pos_y: List[float] = []

        self.vel_e: Dict[int, int] = {}   # entity -> index в массивах vel
        self.vel_vx: List[float] = []
        self.vel_vy: List[float] = []

        self.acc_e: Dict[int, int] = {}
        self.acc_ax: List[float] = []
        self.acc_ay: List[float] = []

    def setup(self, n: int, cfg: BenchConfig) -> None:
        rnd = random.Random(cfg.seed)
        self.pos_e = list(range(n))
        self.pos_x = [rnd.random() for _ in range(n)]
        self.pos_y = [rnd.random() for _ in range(n)]

        # подмножества vel/acc
        for e in range(n):
            if rnd.random() < cfg.with_velocity_ratio:
                self.vel_e[e] = len(self.vel_vx)
                self.vel_vx.append(rnd.random())
                self.vel_vy.append(rnd.random())
            if rnd.random() < cfg.with_accel_ratio:
                self.acc_e[e] = len(self.acc_ax)
                self.acc_ax.append(rnd.random())
                self.acc_ay.append(rnd.random())

    def sys_pos_integrate(self, dt: float, iters: int) -> None:
        pos_e, pos_x, pos_y = self.pos_e, self.pos_x, self.pos_y
        vel_e, vel_vx, vel_vy = self.vel_e, self.vel_vx, self.vel_vy
        for _ in range(iters):
            # итерация по всем позициям, проверка наличия vel через индекс‑мап
            for i, e in enumerate(pos_e):
                j = vel_e.get(e, -1)
                if j >= 0:
                    pos_x[i] += vel_vx[j] * dt
                    pos_y[i] += vel_vy[j] * dt

    def sys_vel_integrate(self, dt: float, iters: int) -> None:
        vel_e, vel_vx, vel_vy = self.vel_e, self.vel_vx, self.vel_vy
        acc_e, acc_ax, acc_ay = self.acc_e, self.acc_ax, self.acc_ay
        for _ in range(iters):
            # итерация по acc, обновление vel
            for e, j in acc_e.items():
                k = vel_e.get(e, -1)
                if k >= 0:
                    vel_vx[k] += acc_ax[j] * dt
                    vel_vy[k] += acc_ay[j] * dt

    def sys_mask_query(self, iters: int) -> int:
        pos_e, vel_e = self.pos_e, self.vel_e
        cnt = 0
        for _ in range(iters):
            for e in pos_e:
                if e not in vel_e:
                    cnt += 1
        return cnt


# -----------------------------
# Backend 3: Esper (опционально)
# -----------------------------

class EsperECS(ECSBackend):
    name = "esper"

    def __init__(self) -> None:
        self.world = None

    def setup(self, n: int, cfg: BenchConfig) -> None:
        if not _HAS_ESPER:
            raise RuntimeError("Esper not installed")
        rnd = random.Random(cfg.seed)
        w = esper.World()
        for _ in range(n):
            e = w.create_entity()
            w.add_component(e, Pos(rnd.random(), rnd.random()))
            if rnd.random() < cfg.with_velocity_ratio:
                w.add_component(e, Vel(rnd.random(), rnd.random()))
            if rnd.random() < cfg.with_accel_ratio:
                w.add_component(e, Acc(rnd.random(), rnd.random()))
        self.world = w

    def sys_pos_integrate(self, dt: float, iters: int) -> None:
        w = self.world
        assert w is not None
        for _ in range(iters):
            for _, (p, v) in w.get_components(Pos, Vel):
                p.x += v.vx * dt
                p.y += v.vy * dt

    def sys_vel_integrate(self, dt: float, iters: int) -> None:
        w = self.world
        assert w is not None
        for _ in range(iters):
            for _, (v, a) in w.get_components(Vel, Acc):
                v.vx += a.ax * dt
                v.vy += a.ay * dt

    def sys_mask_query(self, iters: int) -> int:
        w = self.world
        assert w is not None
        cnt = 0
        for _ in range(iters):
            # pos без vel
            pos_only = set(e for e, _ in w.get_component(Pos)) - set(e for e, _ in w.get_component(Vel))
            cnt += len(pos_only)
        return cnt


# -----------------------------
# Backend 4: Numpy (опционально)
# -----------------------------

class NumpyECS(ECSBackend):
    name = "numpy"

    def __init__(self) -> None:
        if not _HAS_NUMPY:
            raise RuntimeError("numpy not installed")
        self.pos_x = None
        self.pos_y = None
        self.has_vel = None
        self.vel_vx = None
        self.vel_vy = None
        self.has_acc = None
        self.acc_ax = None
        self.acc_ay = None

    def setup(self, n: int, cfg: BenchConfig) -> None:
        rnd = np.random.default_rng(cfg.seed)
        self.pos_x = rnd.random(n, dtype=np.float64)
        self.pos_y = rnd.random(n, dtype=np.float64)

        self.has_vel = rnd.random(n) < cfg.with_velocity_ratio
        self.has_acc = rnd.random(n) < cfg.with_accel_ratio

        # заполняем только для истинных масок
        self.vel_vx = np.zeros(n, dtype=np.float64)
        self.vel_vy = np.zeros(n, dtype=np.float64)
        idx_v = np.where(self.has_vel)[0]
        self.vel_vx[idx_v] = rnd.random(idx_v.shape[0])
        self.vel_vy[idx_v] = rnd.random(idx_v.shape[0])

        self.acc_ax = np.zeros(n, dtype=np.float64)
        self.acc_ay = np.zeros(n, dtype=np.float64)
        idx_a = np.where(self.has_acc)[0]
        self.acc_ax[idx_a] = rnd.random(idx_a.shape[0])
        self.acc_ay[idx_a] = rnd.random(idx_a.shape[0])

    def sys_pos_integrate(self, dt: float, iters: int) -> None:
        px, py, hv, vx, vy = self.pos_x, self.pos_y, self.has_vel, self.vel_vx, self.vel_vy
        assert px is not None and py is not None and hv is not None
        for _ in range(iters):
            px[hv] += vx[hv] * dt
            py[hv] += vy[hv] * dt

    def sys_vel_integrate(self, dt: float, iters: int) -> None:
        hv, ha, vx, vy, ax, ay = self.has_vel, self.has_acc, self.vel_vx, self.vel_vy, self.acc_ax, self.acc_ay
        assert hv is not None and ha is not None
        # там, где есть и vel, и acc
        mask = hv & ha
        for _ in range(iters):
            vx[mask] += ax[mask] * dt
            vy[mask] += ay[mask] * dt

    def sys_mask_query(self, iters: int) -> int:
        hv = self.has_vel
        assert hv is not None
        cnt = 0
        for _ in range(iters):
            cnt += int((~hv).sum())
        return cnt


# -----------------------------
# Раннер одного прогона
# -----------------------------

@dataclass
class RunResult:
    backend: str
    entities: int
    iters: int
    sys_variant: str
    time_s: float
    ns_per_iter: float
    iters_per_s: float
    rss_bytes: int
    tracemalloc_peak_kb: int
    notes: str = ""

def run_one(backend: ECSBackend, cfg: BenchConfig) -> RunResult:
    random.seed(cfg.seed)
    LOG.debug("Setting up backend %s ...", backend.name)
    backend.setup(cfg.entities, cfg)

    # прогрев
    warm = max(0, cfg.warmup_iters)
    if warm:
        _dispatch_systems(backend, cfg.sys_variant, dt=1/120.0, iters=warm)

    # измерение
    tm0_ns = now_ns()
    tm0_rss = rss_bytes()

    if cfg.tracemalloc:
        tracemalloc.start()

    _dispatch_systems(backend, cfg.sys_variant, dt=1/120.0, iters=cfg.iters)

    tm1_ns = now_ns()
    peak_kb = 0
    if cfg.tracemalloc:
        _, peak = tracemalloc.get_traced_memory()
        peak_kb = int(peak / 1024)
        tracemalloc.stop()

    rss = rss_bytes() or tm0_rss
    dt_ns = tm1_ns - tm0_ns
    ns_per_iter = dt_ns / max(1, cfg.iters)
    iters_per_s = 1e9 / ns_per_iter

    backend.teardown()

    return RunResult(
        backend=backend.name,
        entities=cfg.entities,
        iters=cfg.iters,
        sys_variant=cfg.sys_variant,
        time_s=dt_ns / 1e9,
        ns_per_iter=ns_per_iter,
        iters_per_s=iters_per_s,
        rss_bytes=rss,
        tracemalloc_peak_kb=peak_kb,
        notes=""
    )

def _dispatch_systems(backend: ECSBackend, variant: str, dt: float, iters: int) -> None:
    if variant == "pos_only":
        backend.sys_pos_integrate(dt, iters)
        return
    if variant == "mask_query":
        _ = backend.sys_mask_query(iters)
        return
    # full по умолчанию: pos + vel
    backend.sys_pos_integrate(dt, iters)
    backend.sys_vel_integrate(dt, iters)


# -----------------------------
# Запуск набора бенчей (реплики и усреднение)
# -----------------------------

@dataclass
class AggregateResult:
    backend: str
    entities: int
    iters: int
    sys_variant: str
    repeats: int
    time_s_p50: float
    time_s_p90: float
    iters_per_s_avg: float
    iters_per_s_p50: float
    ns_per_iter_p50: float
    rss_bytes_last: int
    tracemalloc_peak_kb_max: int

def aggregate_runs(runs: List[RunResult], cfg: BenchConfig) -> AggregateResult:
    times = [r.time_s for r in runs]
    itps = [r.iters_per_s for r in runs]
    nsit = [r.ns_per_iter for r in runs]
    p50 = statistics.median(times)
    p90 = percentile(times, 90)
    return AggregateResult(
        backend=runs[0].backend,
        entities=cfg.entities,
        iters=cfg.iters,
        sys_variant=cfg.sys_variant,
        repeats=len(runs),
        time_s_p50=p50,
        time_s_p90=p90,
        iters_per_s_avg=sum(itps)/len(itps),
        iters_per_s_p50=statistics.median(itps),
        ns_per_iter_p50=statistics.median(nsit),
        rss_bytes_last=runs[-1].rss_bytes,
        tracemalloc_peak_kb_max=max(r.tracemalloc_peak_kb for r in runs)
    )

def percentile(xs: List[float], p: int) -> float:
    if not xs:
        return 0.0
    xs_sorted = sorted(xs)
    k = (len(xs_sorted) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(xs_sorted) - 1)
    if f == c:
        return xs_sorted[f]
    d0 = xs_sorted[f] * (c - k)
    d1 = xs_sorted[c] * (k - f)
    return d0 + d1

def build_backend(name: str) -> ECSBackend:
    name = name.lower()
    if name == "naive":
        return NaiveDictECS()
    if name == "packed":
        return PackedListECS()
    if name == "esper":
        if not _HAS_ESPER:
            raise RuntimeError("Backend 'esper' requested but 'esper' package not installed")
        return EsperECS()
    if name == "numpy":
        if not _HAS_NUMPY:
            raise RuntimeError("Backend 'numpy' requested but 'numpy' package not installed")
        return NumpyECS()
    raise ValueError(f"Unknown backend: {name}")


# -----------------------------
# CLI и main
# -----------------------------

def parse_args(argv: Optional[List[str]] = None) -> BenchConfig:
    p = argparse.ArgumentParser(prog="bench_ecs_iter", description="ECS iteration microbenchmark")
    p.add_argument("--entities", type=int, default=BenchConfig.entities)
    p.add_argument("--iters", type=int, default=BenchConfig.iters)
    p.add_argument("--warmup", type=int, default=BenchConfig.warmup_iters)
    p.add_argument("--repeats", type=int, default=BenchConfig.repeats)
    p.add_argument("--seed", type=int, default=BenchConfig.seed)
    p.add_argument("--cpu", type=int, default=None, help="Pin to CPU core id")
    p.add_argument("--keep-gc", action="store_true", help="Do not disable GC during runs")
    p.add_argument("--no-tracemalloc", action="store_true")
    p.add_argument("--backends", default="naive,packed,esper,numpy", help="Comma-separated list")
    p.add_argument("--variant", choices=["full","pos_only","mask_query"], default="full")
    p.add_argument("--vel-ratio", type=float, default=BenchConfig.with_velocity_ratio)
    p.add_argument("--acc-ratio", type=float, default=BenchConfig.with_accel_ratio)
    p.add_argument("--out-json", default=None)
    p.add_argument("--out-csv", default=None)
    p.add_argument("--out-png", default=None, help="If matplotlib available, save a bar chart")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG","INFO","WARNING","ERROR"])
    args = p.parse_args(argv)

    LOG.setLevel(getattr(logging, args.log_level))

    cfg = BenchConfig(
        entities=args.entities,
        iters=args.iters,
        warmup_iters=args.warmup,
        repeats=args.repeats,
        seed=args.seed,
        cpu_affinity=args.cpu,
        disable_gc=not args.keep_gc,
        tracemalloc=not args.no_tracemalloc,
        backends=tuple(x.strip() for x in args.backends.split(",") if x.strip()),
        sys_variant=args.variant,
        with_velocity_ratio=args.vel_ratio,
        with_accel_ratio=args.acc_ratio,
        out_json=args.out_json,
        out_csv=args.out_csv,
        out_png=args.out_png,
    )
    return cfg

def write_csv(path: str, agg_results: List[AggregateResult]) -> None:
    fields = list(asdict(agg_results[0]).keys()) if agg_results else []
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in agg_results:
            w.writerow(asdict(r))

def write_json(path: str, agg_results: List[AggregateResult]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in agg_results], f, ensure_ascii=False, indent=2)

def plot_png(path: str, agg: List[AggregateResult]) -> None:
    if not _HAS_MPL:
        LOG.warning("matplotlib not installed; skip plot")
        return
    labels = [f"{r.backend}\n{r.sys_variant}" for r in agg]
    values = [r.iters_per_s_p50 for r in agg]
    plt.figure(figsize=(max(6, len(labels) * 1.4), 4))
    plt.bar(labels, values)
    plt.ylabel("iters/sec (p50)")
    plt.title(f"ECS iteration benchmark — entities={agg[0].entities if agg else 0}, repeats={agg[0].repeats if agg else 0}")
    plt.tight_layout()
    plt.savefig(path, dpi=160)
    plt.close()

def maybe_disable_gc(disable: bool):
    if disable:
        gc.disable()
        LOG.debug("GC disabled for run")
    else:
        gc.enable()

def main(argv: Optional[List[str]] = None) -> int:
    cfg = parse_args(argv)

    try_pin_cpu(cfg.cpu_affinity)
    maybe_disable_gc(cfg.disable_gc)

    results: List[AggregateResult] = []
    for bname in cfg.backends:
        # пропускаем недоступные бекенды, не срывая бенч
        try:
            backend = build_backend(bname)
        except Exception as e:
            LOG.warning("Skip backend %s: %s", bname, e)
            continue

        runs: List[RunResult] = []
        for i in range(cfg.repeats):
            # межповторный GC/стабилизация
            gc.collect()
            time.sleep(0.02)
            r = run_one(backend, cfg)
            LOG.info("Backend=%s repeat=%d time=%.4fs it/s=%.0f ns/iter=%.0f rss=%.1fMB peak=%.1fMB",
                     r.backend, i+1, r.time_s, r.iters_per_s, r.ns_per_iter, r.rss_bytes/1e6, r.tracemalloc_peak_kb/1024)
            runs.append(r)

        agg = aggregate_runs(runs, cfg)
        LOG.info("== %s p50=%.4fs p90=%.4fs it/s(avg)=%.0f it/s(p50)=%.0f ns/iter(p50)=%.0f",
                 agg.backend, agg.time_s_p50, agg.time_s_p90, agg.iters_per_s_avg, agg.iters_per_s_p50, agg.ns_per_iter_p50)
        results.append(agg)

    # вывод
    if cfg.out_csv:
        write_csv(cfg.out_csv, results)
        LOG.info("CSV written to %s", cfg.out_csv)
    if cfg.out_json:
        write_json(cfg.out_json, results)
        LOG.info("JSON written to %s", cfg.out_json)
    if cfg.out_png:
        with contextlib.suppress(Exception):
            plot_png(cfg.out_png, results)
            LOG.info("PNG written to %s", cfg.out_png)

    # печать краткого отчёта в stdout в JSON для машинного парсинга (best effort)
    print(json.dumps([asdict(r) for r in results], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
