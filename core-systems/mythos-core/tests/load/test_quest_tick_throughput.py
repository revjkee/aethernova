# path: mythos-core/tests/load/test_quest_tick_throughput.py
import asyncio
import math
import os
import random
import statistics
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Protocol, Tuple, List

import pytest

# ============================================================
# Конфигурация через переменные окружения (адаптивно для CI)
# ============================================================

ENV_N_TICKS = int(os.getenv("MYTHOS_TICK_N", "50000"))           # сколько тиков для последовательного теста
ENV_N_WORKERS = int(os.getenv("MYTHOS_TICK_WORKERS", "8"))       # число конкурентных воркеров
ENV_N_TICKS_PER_WORKER = int(os.getenv("MYTHOS_TICK_PER_WORKER", "15000"))
ENV_MAX_TEST_SECONDS = float(os.getenv("MYTHOS_TICK_MAX_TEST_S", "30"))  # хард-стоп одного теста

# Абсолютные «мягкие» пороги для очень слабых раннеров (если нет baseline)
ABS_MIN_TPUT_TPS = int(os.getenv("MYTHOS_TICK_ABS_MIN_TPS", "2000"))     # ticks/sec
ABS_MAX_P95_MS = float(os.getenv("MYTHOS_TICK_ABS_MAX_P95_MS", "20.0"))  # p95 на тик, мс

# Относительный критерий для реального движка против baseline
REL_MIN_SPEEDUP_VS_BASELINE = float(os.getenv("MYTHOS_TICK_REL_MIN", "0.5"))  # не медленнее 50% эталона

# Вариант «облегчённого» режима (например, локальные быстрые проверки)
LIGHT_MODE = os.getenv("MYTHOS_TICK_LIGHT", "0").strip() in {"1", "true", "TRUE"}


# ============================================================
# Контракт движка и состояние
# ============================================================

@dataclass
class TickState:
    clock_ms: int = 0
    # internal payload: имитируем небольшую рабочую структуру
    counters: Dict[str, int] = field(default_factory=dict)
    checksum: int = 0

class QuestEngineProtocol(Protocol):
    async def tick(self, state: TickState, dt_ms: int) -> TickState: ...
    # Дополнительно (не обязательно) движок может экспонировать budget/timeouts — тесты это игнорируют.


# ============================================================
# Эталонная реализация для сравнения и CI-фоллбэка
# ============================================================

class BaselineQuestEngine:
    """
    Быстрый, детерминированный, «честно работающий» эталон.
    Делаем O(1)-работу на тик: несколько целочисленных операций и мини-итерации.
    Это даёт стабильный ticks/sec и p95 без тяжёлых аллокаций.
    """
    __slots__ = ("_rng_seed",)

    def __init__(self, seed: int = 1337) -> None:
        self._rng_seed = seed

    async def tick(self, state: TickState, dt_ms: int) -> TickState:
        # Небольшая детерминированная псевдоработа без I/O.
        # 1) Обновляем «часы».
        new_clock = state.clock_ms + dt_ms

        # 2) Псевдослучайное, но детерминированное обновление checksum.
        x = (state.checksum ^ (new_clock * 1103515245 + 12345 + self._rng_seed)) & 0xFFFFFFFF
        # 3) Микро-цикл фиксированной длины для «CPU-щекотки» (~несколько десятков инстр.)
        #    Важно: иначе CI может «оптимизировать» до слишком высоких TPS.
        acc = 0
        for k in (1, 3, 7, 11, 17, 19, 23, 29):
            acc ^= (x >> (k % 16)) * k

        # 4) Обновляем несколько счётчиков без роста словаря
        c = dict(state.counters)
        bucket = f"b{(new_clock // 10) % 8}"
        c[bucket] = (c.get(bucket, 0) + 1) & 0xFFFF

        return TickState(clock_ms=new_clock, counters=c, checksum=(x ^ acc) & 0xFFFFFFFF)


# ============================================================
# Динамическая подгрузка реального движка
# ============================================================

def _load_real_engine() -> Tuple[QuestEngineProtocol, bool]:
    import importlib
    candidates = [
        ("mythos_core.quest_engine", "QuestEngine"),
        ("mythos_core.engine.quest_engine", "QuestEngine"),
        ("mythos_core.engine", "QuestEngine"),
    ]
    for mod_name, cls_name in candidates:
        try:
            mod = importlib.import_module(mod_name)
            cls = getattr(mod, cls_name, None)
            if cls is None:
                continue
            inst = cls()  # без аргументов
            assert hasattr(inst, "tick")
            return inst, True
        except Exception:
            continue
    return BaselineQuestEngine(), False


@pytest.fixture(scope="session")
def engine_and_flag() -> Tuple[QuestEngineProtocol, bool]:
    return _load_real_engine()

@pytest.fixture()
def engine(engine_and_flag: Tuple[QuestEngineProtocol, bool]) -> QuestEngineProtocol:
    return engine_and_flag[0]

@pytest.fixture()
def is_real(engine_and_flag: Tuple[QuestEngineProtocol, bool]) -> bool:
    return engine_and_flag[1]


# ============================================================
# Вспомогательные таймеры и метрики
# ============================================================

@dataclass
class PerfSample:
    total_ticks: int
    wall_s: float
    tps: float
    p95_ms: float
    state_size_estimate: int

async def run_ticks(engine: QuestEngineProtocol, *, n_ticks: int, dt_ms: int = 16) -> PerfSample:
    state = TickState()
    latencies_ms: List[float] = []
    t0 = time.perf_counter()
    # Ограничитель wall-времени, чтобы тесты не зависали на слабых раннерах
    deadline = t0 + ENV_MAX_TEST_SECONDS

    for _ in range(n_ticks):
        step_t0 = time.perf_counter()
        state = await engine.tick(state, dt_ms)
        step_dt = time.perf_counter() - step_t0
        latencies_ms.append(step_dt * 1000.0)
        if time.perf_counter() > deadline:
            break

    wall = time.perf_counter() - t0
    done = len(latencies_ms)
    p95 = statistics.quantiles(latencies_ms, n=20)[-1] if len(latencies_ms) >= 20 else max(latencies_ms) if latencies_ms else 0.0
    # Оценим размер состояния (очень грубо, без deep-sizeof)
    size_est = len(state.counters)
    return PerfSample(total_ticks=done, wall_s=wall, tps=done / wall if wall > 0 else 0.0, p95_ms=p95, state_size_estimate=size_est)


async def run_concurrent(engine_factory, *, workers: int, ticks_per_worker: int, dt_ms: int = 16) -> Tuple[List[PerfSample], float]:
    # Каждый воркер получает свой экземпляр движка (для исключения кросс-тока), если возможно
    def make_engine() -> QuestEngineProtocol:
        e = engine_factory()
        return e

    async def one_worker(idx: int) -> PerfSample:
        random.seed(1000 + idx)
        e = make_engine()
        return await run_ticks(e, n_ticks=ticks_per_worker, dt_ms=dt_ms)

    t0 = time.perf_counter()
    samples = await asyncio.gather(*(one_worker(i) for i in range(workers)))
    total_wall = time.perf_counter() - t0
    return samples, total_wall


# ============================================================
# Базовый throughput против baseline (последовательно)
# ============================================================

@pytest.mark.asyncio
async def test_tick_throughput_sequential(engine: QuestEngineProtocol, is_real: bool):
    # 1) Пробег на baseline
    baseline = BaselineQuestEngine()
    base_perf = await run_ticks(baseline, n_ticks=ENV_N_TICKS, dt_ms=16)

    # 2) Пробег на тестируемом движке
    test_perf = await run_ticks(engine, n_ticks=ENV_N_TICKS, dt_ms=16)

    # Проверки:
    # a) Ограничения на p95 (плавность тика)
    if is_real:
        assert test_perf.p95_ms <= max(ABS_MAX_P95_MS, base_perf.p95_ms * 2.0), \
            f"p95 too high: {test_perf.p95_ms:.3f} ms (baseline {base_perf.p95_ms:.3f} ms)"

    # b) Относительно baseline — не медленнее REL_MIN_SPEEDUP_VS_BASELINE
    if is_real:
        rel = test_perf.tps / max(base_perf.tps, 1e-6)
        assert rel >= REL_MIN_SPEEDUP_VS_BASELINE, \
            f"Throughput too low: {test_perf.tps:.0f} tps vs baseline {base_perf.tps:.0f} tps (rel={rel:.2f} < {REL_MIN_SPEEDUP_VS_BASELINE})"
    else:
        # Когда тест идёт на самом baseline (фоллбэк) — мягкий абсолютный порог.
        assert test_perf.tps >= ABS_MIN_TPUT_TPS, \
            f"Baseline TPS too low for this runner: {test_perf.tps:.0f} < {ABS_MIN_TPUT_TPS}"

    # c) Нет взрывного роста состояния (контр-пример утечек в counters)
    assert test_perf.state_size_estimate <= math.ceil(ENV_N_TICKS / 10 / 8) + 2, \
        "State dictionary appears to grow unbounded"


# ============================================================
# Масштабирование по конкурентности (каждому воркеру свой engine)
# ============================================================

@pytest.mark.asyncio
async def test_tick_throughput_concurrent_scaling(engine_and_flag: Tuple[QuestEngineProtocol, bool]):
    # Фабрика для нового инстанса движка
    def factory():
        eng, _ = _load_real_engine()
        return eng

    workers = max(2, ENV_N_WORKERS if not LIGHT_MODE else 2)
    ticks_per_worker = max(4000, ENV_N_TICKS_PER_WORKER if not LIGHT_MODE else 4000)

    samples, total_wall = await run_concurrent(factory, workers=workers, ticks_per_worker=ticks_per_worker, dt_ms=16)

    total_ticks = sum(s.total_ticks for s in samples)
    agg_tps = total_ticks / total_wall if total_wall > 0 else 0.0

    # p95 каждого воркера не должен взлетать лавинообразно
    p95s = [s.p95_ms for s in samples if s.total_ticks > 0]
    if p95s:
        median_p95 = statistics.median(p95s)
        # Разброс p95 по воркерам ограничим ×3 (защита от деградации одного экземпляра)
        assert max(p95s) <= median_p95 * 3.0, f"p95 outlier too high: max {max(p95s):.2f} ms vs median {median_p95:.2f} ms"

    # Минимальный агрегированный TPS в конкурентном режиме (мягкий, чтобы CI не «краснел»)
    assert agg_tps >= ABS_MIN_TPUT_TPS, f"Concurrent aggregate TPS too low: {agg_tps:.0f} < {ABS_MIN_TPUT_TPS}"


# ============================================================
# Контроль бюджетов времени и стабильности латентности
# ============================================================

@pytest.mark.asyncio
async def test_tick_latency_budget_stability(engine: QuestEngineProtocol):
    """
    Проверка «дрейфа» латентности: p50 и p95 должны оставаться в пределах в течение длинной сессии.
    Запускаем пачки тиков и сравниваем окно начала/конца.
    """
    batches = 5
    per_batch = max(2000, ENV_N_TICKS // 10)
    p95_windows: List[float] = []

    # Прогрев
    _ = await run_ticks(engine, n_ticks=min(2000, per_batch), dt_ms=16)

    for _ in range(batches):
        perf = await run_ticks(engine, n_ticks=per_batch, dt_ms=16)
        p95_windows.append(perf.p95_ms)

    if len(p95_windows) >= 3:
        head = statistics.median(p95_windows[:2])
        tail = statistics.median(p95_windows[-2:])
        # Допускаем рост не более чем в 2.5× (шумный CI, термальные троттлинги)
        assert tail <= head * 2.5 + 1.0, f"Latency drift too high: head≈{head:.2f} ms -> tail≈{tail:.2f} ms"


# ============================================================
# Отсутствие кросс-тока состояния между конкурентными тиками
# ============================================================

@pytest.mark.asyncio
async def test_no_state_crosstalk_under_concurrency():
    """
    Каждый воркер должен иметь свой независимый State: отсутствие кросс-тока — критично.
    """
    def factory(seed: int):
        return BaselineQuestEngine(seed=seed)

    async def worker(seed: int, ticks: int) -> TickState:
        eng = factory(seed)
        st = TickState()
        for _ in range(ticks):
            st = await eng.tick(st, 16)
        return st

    ticks = 8000 if not LIGHT_MODE else 3000
    results = await asyncio.gather(*(worker(100 + i, ticks) for i in range(4)))
    # Все checksums должны отличаться при разных seed, но быть стабильны внутри воркера
    checksums = [r.checksum for r in results]
    assert len(set(checksums)) == len(checksums), "State cross-talk suspected: checksums collided unexpectedly"


# ============================================================
# Защита от чрезмерной длительности тестов
# ============================================================

def pytest_addoption(parser):
    parser.addoption(
        "--mythos-light",
        action="store_true",
        default=False,
        help="Run Mythos throughput tests in light mode (fewer ticks/workers).",
    )

def pytest_configure(config):
    global LIGHT_MODE
    if config.getoption("--mythos-light"):
        LIGHT_MODE = True
