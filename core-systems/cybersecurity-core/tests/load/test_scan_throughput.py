# -*- coding: utf-8 -*-
# I'll answer as the world-famous performance & reliability testing expert in asynchronous network scanners
# with a Black Hat USA Arsenal recognition.
#
# TL;DR:
# Промышленный load/throughput-тест для подсистемы обнаружения активов (asset discovery).
# Тесты не выполняют реальный сетевой скан: все I/O-зависимости замоканы. Мы замеряем время выполнения,
# устойчивость к нагрузке, отсутствие блокировок event loop, стабильность памяти при повторных запусках
# и безопасную параллелизацию. Тяжёлые сценарии запускаются только при CYBER_LOAD_TEST=1.
#
# Контекст и шаги:
# 1) Унифицируем точку входа в API: поддерживаем класс AssetDiscovery.discover(...) или глобальные discover(...)
#    / discover_assets(...). Если не найдено — пропускаем тесты.
# 2) Полностью изолируем внешний мир: мок DNS, порт-сканер и fingerprint. Параметризуем задержки через ENV.
# 3) Метрики: считаем "проб" как сумму просканированных портов (через перехват функции сканирования).
# 4) Тесты:
#    - smoke throughput: быстрая проверка скорости и корректности;
#    - repeated stability: многократные прогоны + tracemalloc для контроля утечек;
#    - parallel invocations: конкурентные вызовы discover для проверки реентерабельности;
#    - loop fairness: пока discover работает, фоновый тикер должен регулярно исполняться (нет блокировок).
#
# Примечания:
# - Тесты адаптивны к CI: по умолчанию запускается лёгкий профиль. Для полноценных нагрузок:
#       CYBER_LOAD_TEST=1 CYBER_LOAD_HEAVY=1 pytest -m load
# - Тесты не предъявляют жёстких SLA, а проверяют верхнюю границу времени относительно синтетических задержек.
# - Нет внешних ссылок: это чистый код тестов без утверждений о сторонних источниках.

from __future__ import annotations

import asyncio
import gc
import os
import random
import time
import tracemalloc
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import pytest

# ------------------------- Глобальные флаги и маркеры ---------------------------

RUN_LOAD = os.getenv("CYBER_LOAD_TEST", "0") == "1"
RUN_HEAVY = os.getenv("CYBER_LOAD_HEAVY", "0") == "1"

pytestmark = [
    pytest.mark.load,
    pytest.mark.asyncio,
    pytest.mark.skipif(not RUN_LOAD, reason="Пропуск: включите CYBER_LOAD_TEST=1 для запуска нагрузочных тестов"),
]

# ------------------- Импорт тестируемого модуля и поиск discover ----------------

asset_mod = pytest.importorskip(
    "cybersecurity_core.asset_discovery",
    reason="Не найден cybersecurity_core.asset_discovery",
)

DiscoverCallable = Callable[..., Awaitable[Any]]


def _get_discover_callable() -> Tuple[Optional[object], Optional[DiscoverCallable], str]:
    """
    Поддерживаем следующие API:
      1) class AssetDiscovery(...).discover(targets, **kwargs) -> list[Asset]
      2) async def discover(targets, **kwargs) -> list[Asset]
      3) async def discover_assets(targets, **kwargs) -> list[Asset]
    """
    svc_cls = getattr(asset_mod, "AssetDiscovery", None)
    if svc_cls is not None:
        try:
            instance = svc_cls()
            discover = getattr(instance, "discover", None)
            if discover is not None and asyncio.iscoroutinefunction(discover):
                return instance, discover, "class.AssetDiscovery.discover"
        except Exception:
            pass

    discover_fn = getattr(asset_mod, "discover", None)
    if discover_fn is not None and asyncio.iscoroutinefunction(discover_fn):
        return None, discover_fn, "function.discover"

    discover_assets_fn = getattr(asset_mod, "discover_assets", None)
    if discover_assets_fn is not None and asyncio.iscoroutinefunction(discover_assets_fn):
        return None, discover_assets_fn, "function.discover_assets"

    return None, None, "unavailable"


@pytest.fixture(scope="module")
def discover_api() -> Tuple[Optional[object], DiscoverCallable, str]:
    instance, callable_, tag = _get_discover_callable()
    if callable_ is None:
        pytest.skip("Не найден совместимый API discover: реализуйте AssetDiscovery.discover(...) или discover(...).")
    return instance, callable_, tag


async def _run_discover(
    discover_api: Tuple[Optional[object], DiscoverCallable, str],
    targets: Sequence[str],
    **kwargs: Any,
) -> Any:
    _instance, discover, _tag = discover_api
    return await discover(targets, **kwargs)


# ------------------------------ Профили нагрузки --------------------------------

@dataclass(frozen=True)
class LoadProfile:
    name: str
    targets: int
    ports_per_target: int
    repeats: int
    io_delay_ms_scan: int
    io_delay_ms_fp: int

    @property
    def total_ports(self) -> int:
        return self.targets * self.ports_per_target


def _select_profile() -> LoadProfile:
    # Управление профилями через ENV переменные с безопасными дефолтами.
    # Для детерминизма избегаем больших значений по умолчанию в CI.
    if RUN_HEAVY:
        return LoadProfile(
            name="heavy",
            targets=int(os.getenv("CYBER_LOAD_TARGETS", "1500")),
            ports_per_target=int(os.getenv("CYBER_LOAD_PORTS_PER_TARGET", "20")),
            repeats=int(os.getenv("CYBER_LOAD_REPEATS", "3")),
            io_delay_ms_scan=int(os.getenv("CYBER_DELAY_SCAN_MS", "0")),
            io_delay_ms_fp=int(os.getenv("CYBER_DELAY_FP_MS", "0")),
        )
    return LoadProfile(
        name="smoke",
        targets=int(os.getenv("CYBER_LOAD_TARGETS", "200")),
        ports_per_target=int(os.getenv("CYBER_LOAD_PORTS_PER_TARGET", "10")),
        repeats=int(os.getenv("CYBER_LOAD_REPEATS", "2")),
        io_delay_ms_scan=int(os.getenv("CYBER_DELAY_SCAN_MS", "0")),
        io_delay_ms_fp=int(os.getenv("CYBER_DELAY_FP_MS", "0")),
    )


@pytest.fixture(scope="module")
def load_profile() -> LoadProfile:
    return _select_profile()


# ----------------------------- Генерация целей ----------------------------------

def _gen_targets(n: int) -> List[str]:
    # Детерминированный список IPv4 внутри RFC1918 для теста.
    # 172.20.0.0/16
    base_a, base_b = 172, 20
    out: List[str] = []
    x, y = 0, 1
    for _ in range(n):
        # простой, но детерминированный перебор
        oct3 = (x % 254) + 1
        oct4 = (y % 254) + 1
        out.append(f"{base_a}.{base_b}.{oct3}.{oct4}")
        x += 1
        y += 3
    return out


def _gen_port_list(k: int) -> List[int]:
    # Детерминированный порт-лист в окне 10000..20000
    rnd = random.Random(1337)
    ports = set()
    while len(ports) < k:
        ports.add(10000 + rnd.randint(0, 9999))
    return sorted(ports)


# -------------------------- Моки: DNS / сканер / fp -----------------------------

class ProbeCounter:
    """
    Счётчик "проб" (портов) и вызовов примитивов.
    """
    def __init__(self) -> None:
        self.scan_calls: int = 0
        self.fp_calls: int = 0
        self.probes_counted: int = 0

    def add_scan(self, ports_passed: Iterable[int]) -> None:
        self.scan_calls += 1
        # Считаем количество просканированных портов
        self.probes_counted += sum(1 for _ in ports_passed)

    def add_fp(self) -> None:
        self.fp_calls += 1


@pytest.fixture
def probe_counter() -> ProbeCounter:
    return ProbeCounter()


@pytest.fixture
def patch_discovery_primitives(
    monkeypatch: pytest.MonkeyPatch,
    load_profile: LoadProfile,
    probe_counter: ProbeCounter,
):
    """
    Подменяем возможные примитивы модуля:
      - resolve_many / resolve_hostnames / dns_resolve_many
      - scan_host_ports / scan_ports / port_scan
      - fingerprint_service / fingerprint / identify_service
    Все функции — async и не выполняют реальных I/O.
    """
    dns_names = ("resolve_hostnames", "resolve_many", "dns_resolve_many")
    scan_names = ("scan_host_ports", "scan_ports", "port_scan")
    fp_names = ("fingerprint_service", "fingerprint", "identify_service")

    delay_scan = load_profile.io_delay_ms_scan / 1000.0
    delay_fp = load_profile.io_delay_ms_fp / 1000.0

    async def fake_dns(addresses: Sequence[str]) -> Dict[str, Optional[str]]:
        if delay_scan:
            await asyncio.sleep(delay_scan * 0.1)  # крошечная задержка для честности
        # Имитация: хостнеймы отсутствуют — не критично для throughput
        return {addr: None for addr in addresses}

    async def fake_scan(address: str, ports: Optional[Iterable[int]] = None) -> List[int]:
        # Сканер возвращает back тот же список портов, будто все "открыты".
        ports_list = list(ports or [])
        probe_counter.add_scan(ports_list)
        if delay_scan:
            await asyncio.sleep(delay_scan)
        return ports_list

    async def fake_fp(address: str, port: int) -> str:
        probe_counter.add_fp()
        if delay_fp:
            await asyncio.sleep(delay_fp)
        # детерминированный fingerprint
        return "service"

    def try_patch(names: Iterable[str], func: Callable[..., Any]) -> None:
        for nm in names:
            if hasattr(asset_mod, nm):
                monkeypatch.setattr(asset_mod, nm, func, raising=True)
                break

    try_patch(dns_names, fake_dns)
    try_patch(scan_names, fake_scan)
    try_patch(fp_names, fake_fp)


# ------------------------------- Вспомогательные --------------------------------

def _throughput(probes: int, elapsed_s: float) -> float:
    if elapsed_s <= 0:
        return float("inf")
    return probes / elapsed_s


def _soft_time_budget_seconds(profile: LoadProfile) -> float:
    """
    Мягкая верхняя граница времени на выполнение одного discover с учётом синтетических задержек.
    Мы не знаем внутреннюю степень параллелизма, поэтому используем консервативную оценку:
      T_budget ≈ (io_delay_scan_ms + io_delay_fp_ms) * ports_per_target / 1000 + const
    """
    base = (profile.io_delay_ms_scan + profile.io_delay_ms_fp) * max(profile.ports_per_target, 1) / 1000.0
    # Константная надбавка на планирование и агрегацию результатов
    return max(0.01, base + 0.25)


# --------------------------------- Тест-кейсы ----------------------------------

@pytest.mark.timeout(60)
async def test_throughput_smoke(discover_api, patch_discovery_primitives, load_profile: LoadProfile, probe_counter: ProbeCounter):
    """
    Быстрый замер: один прогон discover, подсчёт "проб" (портов) и времени.
    Проверяем, что функция отрабатывает в разумный срок относительно синтетической задержки.
    """
    targets = _gen_targets(load_profile.targets)
    ports = _gen_port_list(load_profile.ports_per_target)

    started = time.perf_counter()
    result = await _run_discover(discover_api, targets, include_ports=ports)
    elapsed = time.perf_counter() - started

    # Метрики
    seq = list(result)
    assert len(seq) == load_profile.targets, "Ожидаем актив на каждую цель (детерминированный мок)"
    # Время не должно превышать мягкий бюджет в многократном размере (на случай низкой параллельности)
    budget = _soft_time_budget_seconds(load_profile)
    assert elapsed <= budget * 10.0, f"Выполнение слишком долго: {elapsed:.3f}s > {budget*10:.3f}s"

    # Через перехват сканирования считаем "пробы":
    # Если модуль не вызывал наш сканер — счётчик будет 0; тогда пропустим проверку throughput.
    if probe_counter.probes_counted > 0:
        qps = _throughput(probe_counter.probes_counted, elapsed)
        # Невалидировать порогом, лишь проверим, что QPS конечен и положителен
        assert qps > 0.0
        # Выводим краткую сводку в лог pytest (stdout)
        print(
            f"[throughput] profile={load_profile.name} targets={load_profile.targets} "
            f"ports/target={load_profile.ports_per_target} probes={probe_counter.probes_counted} "
            f"time={elapsed:.3f}s qps={qps:.1f}"
        )


@pytest.mark.timeout(90)
async def test_repeated_runs_memory_stability(discover_api, patch_discovery_primitives, load_profile: LoadProfile):
    """
    Повторные запуски discover не должны приводить к заметным утечкам памяти.
    Используем tracemalloc для сравнения пиков между началом и завершением серии повторов.
    """
    targets = _gen_targets(load_profile.targets // 2 or 1)
    ports = _gen_port_list(load_profile.ports_per_target)

    gc.collect()
    tracemalloc.start()
    snapshot_before = tracemalloc.take_snapshot()

    for _ in range(load_profile.repeats):
        await _run_discover(discover_api, targets, include_ports=ports)

    # Дадим планировщику время собрать мусор
    await asyncio.sleep(0)
    gc.collect()
    snapshot_after = tracemalloc.take_snapshot()
    tracemalloc.stop()

    # Оценим изменение памяти (сумма по топ-статам)
    stats = snapshot_after.compare_to(snapshot_before, "filename")
    added = sum([s.size for s in stats if s.size > 0])
    # Разрешим небольшой дрейф (например, кэш интерпретатора) до 2 МБ
    assert added < 2 * 1024 * 1024, f"Подозрительный рост памяти: {added} bytes"


@pytest.mark.timeout(120)
async def test_parallel_invocations(discover_api, patch_discovery_primitives, load_profile: LoadProfile):
    """
    Параллельные вызовы discover должны выполняться корректно и независимо.
    """
    # Берём меньшие поднаборы, чтобы не перегружать CI
    targets_a = _gen_targets(max(1, load_profile.targets // 3))
    targets_b = _gen_targets(max(1, load_profile.targets // 4))
    ports = _gen_port_list(max(3, load_profile.ports_per_target // 2))

    async def run_one(tgts: Sequence[str]) -> float:
        tic = time.perf_counter()
        res = await _run_discover(discover_api, tgts, include_ports=ports)
        toc = time.perf_counter()
        assert len(res) == len(tgts)
        return toc - tic

    t0 = time.perf_counter()
    durations = await asyncio.gather(run_one(targets_a), run_one(targets_b), return_exceptions=False)
    total = time.perf_counter() - t0

    # Обе задачи должны завершиться без исключений
    assert all(d > 0 for d in durations)
    # Совместное время не должно в разы превышать сумму индивидуальных времён
    # (позволяем 3x из-за конкуренции в CI/локальной машине)
    assert total <= sum(durations) * 3.0, "Параллелизм не должен деградировать многократно"


@pytest.mark.timeout(60)
async def test_event_loop_fairness(discover_api, patch_discovery_primitives, load_profile: LoadProfile):
    """
    Пока discover работает, фоновый тикер должен исполняться регулярно.
    Это индикатор отсутствия долгих синхронных блокировок event loop.
    """
    targets = _gen_targets(max(1, load_profile.targets // 2))
    ports = _gen_port_list(load_profile.ports_per_target)

    tick_ms = 50
    expected_ticks_min = 5

    running = True
    ticks = 0

    async def ticker():
        nonlocal ticks
        while running:
            ticks += 1
            await asyncio.sleep(tick_ms / 1000.0)

    async def run_discovery():
        await _run_discover(discover_api, targets, include_ports=ports)

    started = time.perf_counter()
    t_task = asyncio.create_task(ticker())
    try:
        await run_discovery()
    finally:
        running = False
        await asyncio.sleep(0)  # дать тикеру завершиться
        t_task.cancel()
        with contextlib.suppress(Exception):
            await t_task
    elapsed = time.perf_counter() - started

    # Если очередь событий не блокировалась "надолго", тиков должно быть не меньше порога
    # (при минимальном времени выполнения теста)
    if elapsed >= (tick_ms * expected_ticks_min) / 1000.0:
        assert ticks >= expected_ticks_min, f"Мало тиков ({ticks}) за {elapsed:.3f}s — вероятна блокировка event loop"


# ---------------------------- Вспомогательный импорт ----------------------------

import contextlib  # в конце файла, чтобы не мешать чтению кода
