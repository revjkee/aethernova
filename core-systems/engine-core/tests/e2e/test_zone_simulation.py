# -*- coding: utf-8 -*-
"""
E2E: дискретно‑событийная симуляция зон/каналов с проверкой SLO.
Сценарии:
  1) steady_state: устойчивый поток, стабильная задержка, отсутствие потерь.
  2) failure_and_reroute: отказ центральной зоны, перемаршрутизация, затем восстановление,
     отсутствие потерь и исчерпывание очередей после heal.

Дизайн симулятора (упрощённо, но детерминированно):
- Тики времени: целые шаги (tick = 1 единица времени).
- Источники генерируют заявки с детерминированной псевдослучайностью (LCRNG).
- Зона имеет очередь (FIFO), N инстансов мощности (capacity_units), пропускную способность per_unit_rps.
- Ссылки (links) в виде каналов с фиксированной задержкой (latency_ticks) и буфером в полёте.
- Таблица маршрутизации per‑zone: последовательность узлов от entry до sink, с fallback на соседей.
- Сбои: zone.down = True в интервале; при down обработка 0, заявки копятся; маршрутизатор пытается обойти отказ,
         если обходной путь доступен.
- Метрики: сквозная задержка (start_tick -> completion_tick), p50/p90/p99, потери, остатки в очередях.

Ограничения:
- Только stdlib + pytest.
- Все случайности детерминированы seed‑ом LCRNG.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import pytest


# -----------------------------
# Детерминированный LCRNG
# -----------------------------
class LCRNG:
    __slots__ = ("state",)
    def __init__(self, seed: int) -> None:
        self.state = (seed & 0xFFFFFFFF) or 1

    def next(self) -> int:
        # Параметры MINSTD (Lehmer)
        self.state = (48271 * self.state) % 2147483647
        return self.state

    def uniform(self) -> float:
        return (self.next() / 2147483647.0)

    def poisson_bernoulli(self, rate_per_tick: float) -> int:
        """
        Генерация целочисленного потока ~Poisson(rate) через бернуллизацию дробной части и floor-инт.
        Дет‑детерминированно: floor(rate) + Бернулли(frac(rate)).
        """
        k = int(math.floor(rate_per_tick))
        frac = rate_per_tick - k
        if self.uniform() < frac:
            k += 1
        return k


# -----------------------------
# Модель событий
# -----------------------------
@dataclass
class Job:
    id: int
    start_tick: int
    last_tick: int
    route_idx: int = 0  # позиция в маршруте


@dataclass
class Link:
    name: str
    latency_ticks: int
    inflight: List[Tuple[int, Job]] = field(default_factory=list)  # (deliver_at_tick, job)

    def send(self, now: int, job: Job) -> None:
        self.inflight.append((now + self.latency_ticks, job))

    def deliver_ready(self, now: int) -> List[Job]:
        ready, pending = [], []
        for deliver_at, job in self.inflight:
            if deliver_at <= now:
                ready.append(job)
            else:
                pending.append((deliver_at, job))
        self.inflight = pending
        return ready


@dataclass
class Zone:
    name: str
    per_unit_rps: int
    capacity_units: int = 1
    down: bool = False
    queue: List[Job] = field(default_factory=list)
    max_queue: int = 100000

    def enqueue(self, job: Job) -> None:
        if len(self.queue) >= self.max_queue:
            # В данной модели мы не допускаем потерь в тест‑сценариях; если произойдёт — это ошибка.
            raise AssertionError(f"Queue overflow in {self.name}")
        self.queue.append(job)

    def process(self, now: int) -> List[Job]:
        if self.down or self.capacity_units <= 0 or self.per_unit_rps <= 0:
            return []
        budget = self.per_unit_rps * self.capacity_units
        out: List[Job] = []
        # Обработка FIFO
        take = min(budget, len(self.queue))
        for _ in range(take):
            job = self.queue.pop(0)
            job.last_tick = now
            out.append(job)
        return out


# -----------------------------
# Топология/маршрутизация
# -----------------------------
@dataclass
class Topology:
    zones: Dict[str, Zone]
    links: Dict[Tuple[str, str], Link]  # (src, dst) -> Link
    routes: Dict[str, List[str]]        # имя маршрута -> список зон от entry до sink
    # Альтернативы для отказов: узел -> список соседей (в порядке приоритета) для обхода
    fallbacks: Dict[str, List[str]] = field(default_factory=dict)

    def route_next(self, current: str, route: List[str]) -> Optional[str]:
        # Обычный следующий хоп
        idx = route.index(current)
        if idx + 1 < len(route):
            nxt = route[idx + 1]
            # Если следующий узел down — попробовать fallback
            if self.zones[nxt].down:
                # Ищем живого соседа по fallbacks
                for alt in self.fallbacks.get(current, []):
                    if not self.zones[alt].down:
                        return alt
                return None
            return nxt
        return None  # sink


# -----------------------------
# Симулятор
# -----------------------------
@dataclass
class Simulator:
    topo: Topology
    seed: int = 42
    now: int = 0
    completed: List[Job] = field(default_factory=list)
    rng: LCRNG = field(init=False)
    job_id_seq: int = 0

    def __post_init__(self) -> None:
        self.rng = LCRNG(self.seed)

    def _new_job(self) -> Job:
        jid = self.job_id_seq
        self.job_id_seq += 1
        return Job(id=jid, start_tick=self.now, last_tick=self.now, route_idx=0)

    def generate_into(self, route_name: str, rate_per_tick: float) -> None:
        n = self.rng.poisson_bernoulli(rate_per_tick)
        if n <= 0:
            return
        route = self.topo.routes[route_name]
        entry = self.topo.zones[route[0]]
        for _ in range(n):
            entry.enqueue(self._new_job())

    def step(self, route_name: str) -> None:
        # 1) Доставки по всем линкам
        for (src, dst), link in list(self.topo.links.items()):
            ready = link.deliver_ready(self.now)
            for job in ready:
                self.topo.zones[dst].enqueue(job)

        route = self.topo.routes[route_name]

        # 2) Обработка в узлах (в порядке маршрута для предсказуемости)
        out_edges: List[Tuple[str, Job]] = []
        for zname in route:
            zone = self.topo.zones[zname]
            processed = zone.process(self.now)
            for job in processed:
                # Определяем следующий хоп
                next_hop = self.topo.route_next(zname, route)
                if next_hop is None:
                    # Достигли sink
                    self.completed.append(job)
                else:
                    link = self.topo.links[(zname, next_hop)]
                    link.send(self.now, job)
                    out_edges.append((next_hop, job))

        self.now += 1

    def run(self, route_name: str, ticks: int, gen_rate: float) -> None:
        for _ in range(ticks):
            self.generate_into(route_name, gen_rate)
            self.step(route_name)

    # Метрики
    def latencies(self) -> List[int]:
        return [j.last_tick - j.start_tick for j in self.completed]

    def percentile(self, values: List[int], p: float) -> float:
        if not values:
            return float("nan")
        s = sorted(values)
        k = (len(s) - 1) * p
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return float(s[int(k)])
        d0 = s[f] * (c - k)
        d1 = s[c] * (k - f)
        return float(d0 + d1)

    def all_queues_empty(self) -> bool:
        return all(len(z.queue) == 0 for z in self.topo.zones.values()) and all(
            len(l.inflight) == 0 for l in self.topo.links.values()
        )


# -----------------------------
# Конструирование эталонной топологии
# -----------------------------
def build_baseline_topology(
    per_unit_rps: int = 5,
    capacity_units: Tuple[int, int, int] = (1, 1, 1),
    link_latency: Tuple[int, int] = (1, 2)
) -> Topology:
    """
    Маршрут: entry -> core -> sink, с обходом: entry -> sink (минуя core).
    """
    z_entry = Zone("entry", per_unit_rps=per_unit_rps, capacity_units=capacity_units[0])
    z_core  = Zone("core",  per_unit_rps=per_unit_rps, capacity_units=capacity_units[1])
    z_sink  = Zone("sink",  per_unit_rps=per_unit_rps, capacity_units=capacity_units[2])

    l_e_c = Link("e->c", latency_ticks=link_latency[0])
    l_c_s = Link("c->s", latency_ticks=link_latency[0])
    l_e_s = Link("e->s", latency_ticks=link_latency[1])  # обход дольше

    topo = Topology(
        zones={"entry": z_entry, "core": z_core, "sink": z_sink},
        links={
            ("entry", "core"): l_e_c,
            ("core", "sink"): l_c_s,
            ("entry", "sink"): l_e_s,  # fallback
        },
        routes={"main": ["entry", "core", "sink"]},
        fallbacks={"entry": ["sink"], "core": ["sink"]},
    )
    return topo


# -----------------------------
# Тесты
# -----------------------------
@pytest.mark.parametrize("seed", [7, 42, 31337])
def test_steady_state_no_loss_and_low_p99(seed: int):
    """
    Устойчивый режим: входной поток меньше совокупной мощности конвейера.
    Ожидания:
      - отсутствие потерь (очереди не переполняются),
      - p99 задержки < 12 тиков,
      - очереди сходятся к стабильному уровню.
    """
    topo = build_baseline_topology(per_unit_rps=8, capacity_units=(1, 1, 1), link_latency=(1, 1))
    sim = Simulator(topo, seed=seed)

    warmup = 100
    sim.run("main", ticks=warmup, gen_rate=6.5)  # < 8 rps узла; запас
    # Стабилизация очередей
    for _ in range(50):
        sim.step("main")

    lat = sim.latencies()
    assert len(lat) > 0, "Должны быть завершённые заявки"
    p99 = sim.percentile(lat, 0.99)
    assert p99 < 12.0, f"p99 задержки слишком высок: {p99}"

    # Проверяем, что очереди не раздуваются неограниченно (верхняя граница эвристическая)
    total_q = sum(len(z.queue) for z in sim.topo.zones.values())
    assert total_q < 200, f"Очередь слишком велика в устойчивом режиме: {total_q}"

    # Нет «зависших» пакетов в каналах после стабилизации шага
    for _ in range(5):
        sim.step("main")
    assert all(len(l.inflight) < 50 for l in sim.topo.links.values())


@pytest.mark.parametrize("down_interval", [(120, 220)])
def test_failure_and_reroute_no_loss_then_heal_and_drain(down_interval):
    """
    Сбой центральной зоны (core) -> трафик должен перемаршрутизироваться entry->sink.
    Ожидания:
      - отсутствие потерь (очереди выдерживают),
      - p99 во время отказа хуже, но ограниченно,
      - после heal очереди исчерпываются и каналы пустеют.
    """
    seed = 2025
    topo = build_baseline_topology(per_unit_rps=6, capacity_units=(1, 1, 1), link_latency=(1, 3))
    sim = Simulator(topo, seed=seed)

    # Фаза 1: прогрев (core жив)
    sim.run("main", ticks=100, gen_rate=5.0)

    # Фаза 2: отказ core
    start_down, end_down = down_interval
    assert start_down > sim.now
    # Догоним до начала интервала отказа
    sim.run("main", ticks=start_down - sim.now, gen_rate=5.5)
    topo.zones["core"].down = True

    # Пока отказ: поток идёт через обходной линк entry->sink (дольше)
    sim.run("main", ticks=end_down - sim.now, gen_rate=5.5)
    topo.zones["core"].down = False

    # Фаза 3: восстановление и дренаж
    sim.run("main", ticks=150, gen_rate=4.0)

    # Метрики по всему горизонту
    lat = sim.latencies()
    assert len(lat) > 0, "Ожидаем завершённые заявки"
    p99_total = sim.percentile(lat, 0.99)
    assert p99_total < 40.0, f"p99 общая слишком велика: {p99_total}"

    # Проверка, что очереди исчерпаны и каналов без «хвостов»
    # Сделаем несколько дополнительных шагов для полного слива
    for _ in range(20):
        sim.step("main")
    assert sim.all_queues_empty(), "Очереди/каналы должны быть пусты после слива"


def test_capacity_bump_reduces_latency_under_spike():
    """
    Имитация автоскейла: при обнаружении роста очереди в core увеличиваем capacity_units.
    Ожидание: после «бампа» p95 заметно снижается.
    """
    topo = build_baseline_topology(per_unit_rps=5, capacity_units=(1, 1, 1), link_latency=(1, 1))
    sim = Simulator(topo, seed=11)

    # Фаза 1: до всплеска
    sim.run("main", ticks=60, gen_rate=4.2)
    lat_before = list(sim.latencies())  # снимок «до»
    p95_before = sim.percentile(lat_before, 0.95) if lat_before else float("nan")

    # Фаза 2: всплеск
    spike_ticks = 120
    for _ in range(spike_ticks):
        sim.generate_into("main", rate_per_tick=7.0)
        # простая «автошкала»: если очередь core > 50, удвоить capacity (единоразово)
        core = sim.topo.zones["core"]
        if core.capacity_units == 1 and len(core.queue) > 50:
            core.capacity_units = 2
        sim.step("main")

    # Дренаж после всплеска
    sim.run("main", ticks=100, gen_rate=3.0)

    lat_after = sim.latencies()
    assert len(lat_after) > 0
    p95_after = sim.percentile(lat_after, 0.95)

    # Проверка улучшения после масштабирования
    # (Если p95_before nan из‑за малого горизонта, требуем просто разумного порога)
    if math.isnan(p95_before):
        assert p95_after < 20.0, f"p95 после масштабирования слишком велик: {p95_after}"
    else:
        assert p95_after <= max(1.0, p95_before * 0.8), f"p95 не улучшился достаточно: before={p95_before}, after={p95_after}"


def test_no_starvation_and_fifo_ordering():
    """
    Гарантия отсутствия голодания и сохранение порядка FIFO на маршруте.
    """
    topo = build_baseline_topology(per_unit_rps=9, capacity_units=(1, 1, 1), link_latency=(1, 1))
    sim = Simulator(topo, seed=99)

    # Сгенерируем «пачку» и пропустим её без новых инъекций
    for _ in range(20):
        sim.generate_into("main", rate_per_tick=10.0)
    for _ in range(200):
        sim.step("main")

    # Все, кто вошёл, должны выйти
    completed_ids = [j.id for j in sim.completed]
    assert completed_ids == list(range(len(completed_ids))), "FIFO порядок должен сохраняться сквозь маршрут"

    # Очереди и каналы пусты
    assert sim.all_queues_empty()
