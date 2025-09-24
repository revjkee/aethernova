# -*- coding: utf-8 -*-
# neuroforge-core/tests/load/test_infer_throughput.py
"""
Нагрузочный тест инференса NeuroForge: throughput и latency percentiles.

Возможности:
- Автодетект инференс-движка в модулях neuroforge.* (infer/predict/run)
- Фоллбек на DummyEngine (безопасная симуляция нагрузки)
- Разогрев (warmup), закрытая петля (closed-loop), фиксированная длительность
- Параллелизм потоками (threading) без GIL-узких мест для I/O-bound/CPU-lite путей
- Параметризация по batch_size и concurrency
- SLA через ENV/CLI: NF_THROUGHPUT_MIN_RPS, NF_P95_MAX_MS, NF_FAIL_ON_DUMMY
- Экспорт артефакта JSON с метриками (tmp_path / throughput_report.json)
- Без внешних зависимостей; numpy используется опционально для генерации входов

CLI (через pytest -o addopts или conftest):
  --nf-duration-s=3                длительность замера (сек)
  --nf-warmup-s=1                  длительность разогрева (сек)
  --nf-batches=0                   ограничение на кол-во батчей (0 = по времени)
  --nf-input-shape=1,3,224,224     форма входа (по запятой)
  --nf-dtype=float32               тип данных для генерации
  --nf-skip-dummy                  пропустить тест, если используется DummyEngine
  --nf-engine-path=module:attr     явное указание движка (например, neuroforge.infer:engine)
  --nf-concurrency=1               число потоков инференса
  --nf-batch-size=1                размер батча
  --nf-save-report                 принудительно сохранить отчет в JSON

ENV (альтернативы/дополнения):
  NF_THROUGHPUT_MIN_RPS, NF_P95_MAX_MS, NF_FAIL_ON_DUMMY=1

Примечание:
- Тест построен как нагрузочный unit-lite: короткий, воспроизводимый, без долгих прогонов.
- Для реального сервиса gRPC/HTTP следует адаптировать EngineWrapper на сетевой клиент.
"""

from __future__ import annotations

import importlib
import json
import math
import os
import statistics
import threading
import time
from dataclasses import dataclass, asdict
from types import SimpleNamespace
from typing import Any, Callable, List, Optional, Tuple

import pytest

# -----------------------------
# Опциональный NumPy
# -----------------------------
try:
    import numpy as np  # type: ignore
    HAS_NUMPY = True
except Exception:
    HAS_NUMPY = False


# -----------------------------
# Конфигурация теста (CLI/ENV)
# -----------------------------
def pytest_addoption(parser):
    g = parser.getgroup("neuroforge-load")
    g.addoption("--nf-duration-s", type=float, default=float(os.getenv("NF_DURATION_S", 3)), help="Duration of measurement phase (seconds)")
    g.addoption("--nf-warmup-s", type=float, default=float(os.getenv("NF_WARMUP_S", 1)), help="Warmup duration (seconds)")
    g.addoption("--nf-batches", type=int, default=int(os.getenv("NF_BATCHES", 0)), help="Max batches during measurement (0 = time-bound)")
    g.addoption("--nf-input-shape", type=str, default=os.getenv("NF_INPUT_SHAPE", "1,3,224,224"), help="Comma-separated input shape")
    g.addoption("--nf-dtype", type=str, default=os.getenv("NF_DTYPE", "float32"), help="Input dtype")
    g.addoption("--nf-skip-dummy", action="store_true", default=bool(int(os.getenv("NF_SKIP_DUMMY", "0"))), help="Skip when DummyEngine is used")
    g.addoption("--nf-engine-path", type=str, default=os.getenv("NF_ENGINE_PATH", ""), help="Explicit engine path module:attr")
    g.addoption("--nf-concurrency", type=int, default=int(os.getenv("NF_CONCURRENCY", 1)), help="Number of worker threads")
    g.addoption("--nf-batch-size", type=int, default=int(os.getenv("NF_BATCH_SIZE", 1)), help="Batch size")
    g.addoption("--nf-save-report", action="store_true", default=bool(int(os.getenv("NF_SAVE_REPORT", "0"))), help="Always save JSON report")

# SLA через переменные окружения
def _env_float(name: str) -> Optional[float]:
    v = os.getenv(name)
    if not v:
        return None
    try:
        return float(v)
    except ValueError:
        return None

NF_THROUGHPUT_MIN_RPS = _env_float("NF_THROUGHPUT_MIN_RPS")
NF_P95_MAX_MS = _env_float("NF_P95_MAX_MS")
NF_FAIL_ON_DUMMY = bool(int(os.getenv("NF_FAIL_ON_DUMMY", "0")))


# -----------------------------
# Утилиты
# -----------------------------
def parse_shape(s: str) -> Tuple[int, ...]:
    parts = [p.strip() for p in s.split(",") if p.strip()]
    return tuple(int(x) for x in parts)

def now() -> float:
    return time.perf_counter()

def percentiles(values: List[float], ps=(50, 90, 95, 99)) -> dict:
    if not values:
        return {f"p{p}": math.nan for p in ps}
    vs = sorted(values)
    res = {}
    for p in ps:
        k = (len(vs) - 1) * (p / 100.0)
        f = math.floor(k); c = math.ceil(k)
        if f == c:
            val = vs[int(k)]
        else:
            d0 = vs[f] * (c - k)
            d1 = vs[c] * (k - f)
            val = d0 + d1
        res[f"p{p}"] = float(val)
    return res

def to_millis(sec: float) -> float:
    return sec * 1000.0


# -----------------------------
# Движок инференса (дискавери)
# -----------------------------
class EngineProtocol:
    """
    Протокол движка инференса: функция infer(inputs) -> outputs.
    inputs: любой объект или список/батч; вывод не важен для метрик, важна длительность.
    """
    def infer(self, inputs: Any) -> Any:  # pragma: no cover (interface)
        raise NotImplementedError

def _load_attr(module_attr: str):
    """
    Загрузка символа 'module:attr' либо 'module.attr'.
    """
    if ":" in module_attr:
        mod, attr = module_attr.split(":", 1)
    elif "." in module_attr:
        parts = module_attr.split(".")
        mod, attr = ".".join(parts[:-1]), parts[-1]
    else:
        mod, attr = module_attr, None
    m = importlib.import_module(mod)
    return getattr(m, attr) if attr else m

def try_discover_engine(explicit: str = "") -> Tuple[EngineProtocol, bool]:
    """
    Возвращает (engine, is_dummy).
    Порядок:
      1) Явный путь через --nf-engine-path
      2) Поиск в известных местах neuroforge: (infer|runtime|serving).(engine|infer|predict|run)
      3) DummyEngine
    """
    # 1) явный
    if explicit:
        obj = _load_attr(explicit)
        eng = adapt_to_engine(obj)
        if eng:
            return eng, False

    # 2) эвристики
    candidates = [
        "neuroforge.infer:engine",
        "neuroforge.infer:infer",
        "neuroforge.runtime:engine",
        "neuroforge.runtime:infer",
        "neuroforge.serving:engine",
        "neuroforge.serving:infer",
        "neuroforge.infer:predict",
        "neuroforge.runtime:predict",
        "neuroforge.serving:predict",
    ]
    for path in candidates:
        try:
            obj = _load_attr(path)
        except Exception:
            continue
        eng = adapt_to_engine(obj)
        if eng:
            return eng, False

    # 3) Dummy
    return DummyEngine(sleep_per_item_ms=0.6), True  # мягкая симуляция ~0.6мс/элемент

def adapt_to_engine(obj: Any) -> Optional[EngineProtocol]:
    """
    Адаптация разных форм API к EngineProtocol.
    Поддерживает:
      - объект с методом infer(inputs)
      - функция infer(inputs) / predict(inputs) / run(inputs)
    """
    # объект с infer
    if hasattr(obj, "infer") and callable(getattr(obj, "infer")):
        return _ObjectEngine(obj)
    # функция
    for name in ("infer", "predict", "run"):
        if callable(obj) and obj.__name__ == name:
            return _CallableEngine(obj)
        if hasattr(obj, name) and callable(getattr(obj, name)):
            return _CallableEngine(getattr(obj, name))
    return None


class _ObjectEngine(EngineProtocol):
    def __init__(self, obj: Any):
        self._obj = obj
    def infer(self, inputs: Any) -> Any:
        return self._obj.infer(inputs)

class _CallableEngine(EngineProtocol):
    def __init__(self, fn: Callable[[Any], Any]):
        self._fn = fn
    def infer(self, inputs: Any) -> Any:
        return self._fn(inputs)

class DummyEngine(EngineProtocol):
    """
    Лёгкий симулятор инференса: имитирует вычисление с паузой,
    пропорциональной количеству элементов во входе.
    """
    def __init__(self, sleep_per_item_ms: float = 0.5):
        self.sleep_per_item_ms = float(sleep_per_item_ms)
    def infer(self, inputs: Any) -> Any:
        # Оценим количество элементов
        n = 1
        try:
            if HAS_NUMPY and isinstance(inputs, np.ndarray):
                n = int(inputs.shape[0]) if inputs.ndim >= 1 else 1
            elif isinstance(inputs, (list, tuple)):
                n = len(inputs)
        except Exception:
            n = 1
        time.sleep((self.sleep_per_item_ms * n) / 1000.0)
        return inputs  # не важно, что вернуть


# -----------------------------
# Генерация входных данных
# -----------------------------
def make_inputs(batch_size: int, shape: Tuple[int, ...], dtype: str) -> Any:
    if HAS_NUMPY:
        # Преобразуем shape: если первая размерность — это already batch, уважаем её
        if len(shape) >= 1 and shape[0] != batch_size:
            shape = (batch_size, *shape[1:])
        dt_map = {
            "float32": np.float32,
            "float16": np.float16,
            "float64": np.float64,
            "int64": np.int64,
            "int32": np.int32,
            "uint8": np.uint8,
        }
        dt = dt_map.get(dtype, np.float32)
        return np.random.rand(*shape).astype(dt, copy=False)
    # Без numpy — список списков нулей
    total = 1
    dims = list(shape)
    if dims and dims[0] != batch_size:
        dims[0] = batch_size
    for d in dims:
        total *= max(int(d), 1)
    # Создаём только batch плоских элементов, чтобы не тратить память
    return [0.0 for _ in range(batch_size)]


# -----------------------------
# Измерение
# -----------------------------
@dataclass
class RunConfig:
    duration_s: float
    warmup_s: float
    max_batches: int
    input_shape: Tuple[int, ...]
    dtype: str
    batch_size: int
    concurrency: int

@dataclass
class RunMetrics:
    batches: int
    items: int
    rps_batches: float
    rps_items: float
    p50_ms: float
    p90_ms: float
    p95_ms: float
    p99_ms: float
    mean_ms: float
    stdev_ms: float
    engine: str
    dummy: bool

def closed_loop_run(engine: EngineProtocol, cfg: RunConfig) -> RunMetrics:
    latencies: List[float] = []
    batches_done = 0
    items_done = 0

    # Разогрев
    warm_deadline = now() + max(0.0, cfg.warmup_s)
    warm_inputs = make_inputs(cfg.batch_size, cfg.input_shape, cfg.dtype)
    while now() < warm_deadline:
        engine.infer(warm_inputs)

    # Основной замер
    deadline = now() + max(0.0, cfg.duration_s)
    lock = threading.Lock()

    def worker():
        nonlocal batches_done, items_done
        inputs = make_inputs(cfg.batch_size, cfg.input_shape, cfg.dtype)
        local_lat: List[float] = []
        local_batches = 0
        local_items = 0
        while True:
            t0 = now()
            if cfg.max_batches > 0 and (batches_done + local_batches) >= cfg.max_batches:
                break
            if now() >= deadline:
                break
            engine.infer(inputs)
            t1 = now()
            local_lat.append(t1 - t0)
            local_batches += 1
            local_items += cfg.batch_size
        with lock:
            latencies.extend(local_lat)
            batches_done += local_batches
            items_done += local_items

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(max(1, cfg.concurrency))]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    # Расчёт метрик
    wall = max(cfg.duration_s, 1e-9)
    rps_b = batches_done / wall
    rps_i = items_done / wall
    l_ms = [to_millis(x) for x in latencies]
    pr = percentiles(l_ms, ps=(50, 90, 95, 99))
    mean = float(statistics.fmean(l_ms)) if l_ms else float("nan")
    stdev = float(statistics.pstdev(l_ms)) if len(l_ms) >= 2 else 0.0

    eng_name = type(engine).__name__
    is_dummy = isinstance(engine, DummyEngine)

    return RunMetrics(
        batches=batches_done,
        items=items_done,
        rps_batches=rps_b,
        rps_items=rps_i,
        p50_ms=pr["p50"],
        p90_ms=pr["p90"],
        p95_ms=pr["p95"],
        p99_ms=pr["p99"],
        mean_ms=mean,
        stdev_ms=stdev,
        engine=eng_name,
        dummy=is_dummy,
    )


# -----------------------------
# Параметризация теста
# -----------------------------
BATCH_SIZES = [1, 4]         # можно расширять через --nf-batch-size
CONCURRENCIES = [1, 2]       # можно расширять через --nf-concurrency

def _single_or_list(opt_val: int, default_list: List[int]) -> List[int]:
    return [opt_val] if opt_val not in (None, 0) else default_list


# -----------------------------
# Сам тест
# -----------------------------
@pytest.mark.slow
@pytest.mark.parametrize("dummy_allowed", [True], ids=["throughput"])
def test_infer_throughput(request, tmp_path, dummy_allowed):
    """
    Нагрузочный тест инференса. По умолчанию использует короткие интервалы для CI.

    SLA (необязательно):
      NF_THROUGHPUT_MIN_RPS   - минимальный rps_items
      NF_P95_MAX_MS           - максимальный p95 латентности в мс
    Поведение с DummyEngine управляется:
      --nf-skip-dummy или NF_FAIL_ON_DUMMY=1
    """
    # Конфиг из CLI/ENV
    duration_s: float = request.config.getoption("--nf-duration-s")
    warmup_s: float = request.config.getoption("--nf-warmup-s")
    max_batches: int = request.config.getoption("--nf-batches")
    input_shape = parse_shape(request.config.getoption("--nf-input-shape"))
    dtype: str = request.config.getoption("--nf-dtype")
    skip_dummy: bool = request.config.getoption("--nf-skip-dummy")
    engine_path: str = request.config.getoption("--nf-engine-path")
    cli_conc: int = request.config.getoption("--nf-concurrency")
    cli_bs: int = request.config.getoption("--nf-batch-size")
    save_report: bool = request.config.getoption("--nf-save-report")

    bs_list = _single_or_list(cli_bs, BATCH_SIZES)
    cc_list = _single_or_list(cli_conc, CONCURRENCIES)

    engine, is_dummy = try_discover_engine(engine_path)
    if is_dummy and (skip_dummy or NF_FAIL_ON_DUMMY):
        pytest.skip("DummyEngine активен и запрещён конфигурацией (--nf-skip-dummy или NF_FAIL_ON_DUMMY=1)")

    all_runs: List[dict] = []
    violations: List[str] = []

    for bs in bs_list:
        for cc in cc_list:
            cfg = RunConfig(
                duration_s=duration_s,
                warmup_s=warmup_s,
                max_batches=max_batches,
                input_shape=input_shape,
                dtype=dtype,
                batch_size=bs,
                concurrency=cc,
            )
            metrics = closed_loop_run(engine, cfg)
            rec = {
                "config": asdict(cfg),
                "metrics": asdict(metrics),
            }
            all_runs.append(rec)

            # SLA проверки
            if NF_THROUGHPUT_MIN_RPS is not None and metrics.rps_items < NF_THROUGHPUT_MIN_RPS:
                violations.append(f"rps_items({metrics.rps_items:.2f}) < NF_THROUGHPUT_MIN_RPS({NF_THROUGHPUT_MIN_RPS:.2f}) [bs={bs}, cc={cc}]")
            if NF_P95_MAX_MS is not None and metrics.p95_ms > NF_P95_MAX_MS:
                violations.append(f"p95_ms({metrics.p95_ms:.2f}) > NF_P95_MAX_MS({NF_P95_MAX_MS:.2f}) [bs={bs}, cc={cc}]")

    # Сохраняем отчёт
    report = {
        "engine": type(engine).__name__,
        "is_dummy": is_dummy,
        "runs": all_runs,
        "env": {
            "NF_THROUGHPUT_MIN_RPS": NF_THROUGHPUT_MIN_RPS,
            "NF_P95_MAX_MS": NF_P95_MAX_MS,
        },
        "timestamp": time.time(),
    }
    report_path = tmp_path / "throughput_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    # В CI удобно всегда иметь артефакт; локально можно отключить
    if save_report:
        print(f"[neuroforge] throughput report saved: {report_path}")

    # Если есть нарушения SLA — проваливаем тест
    if violations:
        msg = " | ".join(violations)
        pytest.fail(f"SLA violations: {msg}")


# -----------------------------
# Дополнительный sanity-тест
# -----------------------------
def test_percentiles_sanity():
    vals = [1, 2, 3, 4, 5]
    pr = percentiles(vals, ps=(50, 90))
    assert abs(pr["p50"] - 3.0) < 1e-9
    assert pr["p90"] >= 4.0

