# path: chronowatch-core/tests/load/test_timer_throughput.py
# -*- coding: utf-8 -*-
"""
Промышленный тест пропускной способности и точности планирования таймера.

Назначение:
- Проверить, что реализация таймера/планировщика выдерживает целевой QPS при N потоках.
- Измерить позднение (lateness = actual_start_ns - scheduled_deadline_ns) и рассчитать p50/p95/p99.
- Зафиксировать прогрев, сбор метрик и детерминированность границ SLA для CI.

Параметры через окружение (все значения по умолчанию CI-safe):
  CHRONO_QPS                целевой QPS на поток (int, default 500)
  CHRONO_THREADS            число потоков (int, default 4)
  CHRONO_DURATION_S         основная длительность измерения в сек (int, default 5)
  CHRONO_WARMUP_S           прогрев в сек (int, default 1)
  CHRONO_SLA_THROUGHPUT     мин. доля достижимого QPS (float, default 0.95)
  CHRONO_SLA_P95_LATE_MS    макс. допустимый p95 позднения, мс (float, default 10.0)
  CHRONO_SLA_DROP_PCT       макс. доля "пропусков" дедлайнов (float, default 0.02)
  CHRONO_SPIN_NS            граница активного ожидания перед дедлайном, нс (int, default 200_000) ~0.2ms
  CHRONO_CI_FAST            если "1", сокращает нагрузку (QPS=200, THREADS=2, DURATION=3)

Примечания:
- Тест специально не зависит от конкретной реализации таймера проекта. Мы валидируем базовые
  гарантии планирования на уровне ОС/интерпретатора для целевой частоты. При интеграции со
  специфическим таймером замените функцию _tick() на вызов вашего callback/таймера.
"""

from __future__ import annotations

import json
import math
import os
import csv
import statistics
import threading
from dataclasses import dataclass, asdict
from time import perf_counter_ns, sleep

import pytest


def _env_int(name: str, default: int) -> int:
    try:
        val = int(os.getenv(name, "").strip() or default)
        return val
    except Exception:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        val = float(os.getenv(name, "").strip() or default)
        return val
    except Exception:
        return default


def _ns_to_ms(ns: int | float) -> float:
    return float(ns) / 1_000_000.0


def _percentile(values: list[float], p: float) -> float:
    """
    Простой перцентиль без внешних зависимостей.
    p в [0, 100]. Пустой список -> NaN.
    """
    if not values:
        return float("nan")
    if p <= 0:
        return min(values)
    if p >= 100:
        return max(values)
    idx = (len(values) - 1) * (p / 100.0)
    lo = int(math.floor(idx))
    hi = int(math.ceil(idx))
    if lo == hi:
        return values[lo]
    frac = idx - lo
    return values[lo] * (1 - frac) + values[hi] * frac


@dataclass
class ThreadStats:
    events: int
    drops: int
    lateness_ns: list[int]
    started_ns: int
    ended_ns: int

    def duration_s(self) -> float:
        return (self.ended_ns - self.started_ns) / 1_000_000_000.0


@dataclass
class AggregatedMetrics:
    total_events: int
    total_drops: int
    total_expected: int
    throughput_eps: float
    achieved_ratio: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    late_mean_ms: float
    late_stdev_ms: float


def _tick() -> None:
    """
    Место для логики вашего таймера/обратного вызова.
    По умолчанию — no-op с минимальной работой.
    """
    # Минимальная операция, чтобы не оптимизировалось в ничто.
    pass


def _worker(rate_hz: int, run_s: int, warmup_s: int, spin_ns: int, start_barrier: threading.Barrier) -> ThreadStats:
    """
    Выполняет цикл fixed-rate: на каждую квоту времени планирует _tick и
    измеряет позднение относительно дедлайна.
    """
    # Предварительный прогрев: даем интерпретатору "раскачаться"
    warmup_deadline = perf_counter_ns() + warmup_s * 1_000_000_000
    quantum_ns = int(1_000_000_000 // rate_hz)
    lateness_ns: list[int] = []
    drops = 0
    events = 0

    # Прогрев с пониженным QPS (в 5 раз ниже)
    warm_quantum_ns = quantum_ns * 5
    while True:
        now = perf_counter_ns()
        if now >= warmup_deadline:
            break
        deadline = now + warm_quantum_ns
        # Сон до допустимой границы, затем короткий spin
        while True:
            remaining = deadline - perf_counter_ns()
            if remaining <= spin_ns:
                break
            # сон не менее 50 мкс, максимум 0.5 мс
            sleep(min(remaining / 1_000_000_000.0 / 10.0, 0.0005))
        # короткий активный spin
        while perf_counter_ns() < deadline:
            pass
        # Фиксируем позднение
        real = perf_counter_ns()
        lateness_ns.append(max(0, real - deadline))
        _tick()

    # Ожидаем общий старт всех потоков
    start_barrier.wait()

    started_ns = perf_counter_ns()
    end_ns = started_ns + run_s * 1_000_000_000
    next_deadline = started_ns

    while True:
        now = perf_counter_ns()
        if now >= end_ns:
            break
        # Планируем следующий дедлайн по fixed-rate, без дрейфа по задержкам
        next_deadline += quantum_ns

        # Сон и докрутка
        while True:
            remaining = next_deadline - perf_counter_ns()
            if remaining <= spin_ns:
                break
            sleep(min(remaining / 1_000_000_000.0 / 10.0, 0.0005))
        while perf_counter_ns() < next_deadline:
            pass

        real = perf_counter_ns()
        late = max(0, real - next_deadline)
        lateness_ns.append(late)
        events += 1

        # Считаем "drop", если опоздали критично: пропустили следующий квант
        if late > quantum_ns:
            drops += 1

        _tick()

    ended_ns = perf_counter_ns()
    return ThreadStats(events=events, drops=drops, lateness_ns=lateness_ns, started_ns=started_ns, ended_ns=ended_ns)


def _aggregate(stats: list[ThreadStats], rate_hz: int, threads: int, run_s: int) -> AggregatedMetrics:
    total_events = sum(s.events for s in stats)
    total_drops = sum(s.drops for s in stats)
    total_expected = rate_hz * threads * run_s

    # Склеиваем позднения в миллисекундах и сортируем для перцентилей
    all_late_ms = sorted([_ns_to_ms(x) for s in stats for x in s.lateness_ns])

    duration_s = max(1e-9, sum(s.duration_s() for s in stats) / max(1, len(stats)))
    throughput = total_events / duration_s
    achieved_ratio = (total_events / total_expected) if total_expected > 0 else float("nan")

    p50 = _percentile(all_late_ms, 50.0)
    p95 = _percentile(all_late_ms, 95.0)
    p99 = _percentile(all_late_ms, 99.0)
    late_mean = statistics.fmean(all_late_ms) if all_late_ms else float("nan")
    late_stdev = statistics.pstdev(all_late_ms) if len(all_late_ms) > 1 else 0.0

    return AggregatedMetrics(
        total_events=total_events,
        total_drops=total_drops,
        total_expected=total_expected,
        throughput_eps=throughput,
        achieved_ratio=achieved_ratio,
        p50_ms=p50,
        p95_ms=p95,
        p99_ms=p99,
        late_mean_ms=late_mean,
        late_stdev_ms=late_stdev,
    )


@pytest.mark.load
@pytest.mark.timeout(60)
def test_timer_throughput(tmp_path):
    """
    SLA-проверка пропускной способности и позднения для таймера/планировщика.

    Артефакты:
      - report.json: агрегированные метрики и параметры прогона
      - lateness_ms.csv: p50/p95/p99 рассчитываются из данных; CSV для внешнего анализа

    Пороговые значения можно переопределить переменными окружения (см. шапку файла).
    """
    # Параметры окружения с режимом CI_FAST
    ci_fast = os.getenv("CHRONO_CI_FAST", "0") == "1"

    rate_hz = _env_int("CHRONO_QPS", 200 if ci_fast else 500)
    threads = _env_int("CHRONO_THREADS", 2 if ci_fast else 4)
    duration_s = _env_int("CHRONO_DURATION_S", 3 if ci_fast else 5)
    warmup_s = _env_int("CHRONO_WARMUP_S", 1)

    sla_ratio = _env_float("CHRONO_SLA_THROUGHPUT", 0.95)
    sla_p95_ms = _env_float("CHRONO_SLA_P95_LATE_MS", 10.0)
    sla_drop_pct = _env_float("CHRONO_SLA_DROP_PCT", 0.02)

    spin_ns = _env_int("CHRONO_SPIN_NS", 200_000)  # ~0.2ms

    # Стартовый барьер
    barrier = threading.Barrier(threads)

    # Запускаем потоки
    workers = []
    results: list[ThreadStats] = []
    for _ in range(threads):
        t = threading.Thread(
            target=lambda acc: acc.append(_worker(rate_hz, duration_s, warmup_s, spin_ns, barrier)),
            args=(results,),
            daemon=True,
        )
        workers.append(t)

    for t in workers:
        t.start()
    for t in workers:
        t.join()

    # Агрегация
    metrics = _aggregate(results, rate_hz, threads, duration_s)

    # Сохраняем артефакты
    report = {
        "params": {
            "rate_hz_per_thread": rate_hz,
            "threads": threads,
            "duration_s": duration_s,
            "warmup_s": warmup_s,
            "spin_ns": spin_ns,
            "ci_fast": ci_fast,
            "sla": {
                "throughput_ratio_min": sla_ratio,
                "p95_late_ms_max": sla_p95_ms,
                "drop_pct_max": sla_drop_pct,
            },
        },
        "metrics": asdict(metrics),
    }
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))

    # Также выгружаем выборку позднения (для наглядности и внешней проверки)
    lateness_csv = tmp_path / "lateness_ms.csv"
    with open(lateness_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["thread_idx", "lateness_ms"])
        for idx, s in enumerate(results):
            for ln in s.lateness_ns:
                writer.writerow([idx, _ns_to_ms(ln)])

    # Проверки SLA
    # 1) Доля достигнутого QPS суммарно
    assert metrics.achieved_ratio >= sla_ratio, (
        f"Throughput ratio below SLA: got {metrics.achieved_ratio:.3f}, need >= {sla_ratio:.3f}. "
        f"(events={metrics.total_events} expected={metrics.total_expected}, "
        f"eps={metrics.throughput_eps:.1f})"
    )

    # 2) P95 позднения (мс)
    assert metrics.p95_ms <= sla_p95_ms, (
        f"P95 lateness exceeded SLA: got {metrics.p95_ms:.3f} ms, max {sla_p95_ms:.3f} ms. "
        f"(p50={metrics.p50_ms:.3f} p99={metrics.p99_ms:.3f})"
    )

    # 3) Доля пропусков дедлайнов
    drop_pct = (metrics.total_drops / max(1, metrics.total_events)) if metrics.total_events else 1.0
    assert drop_pct <= sla_drop_pct, (
        f"Drop percentage exceeded SLA: got {drop_pct:.3%}, max {sla_drop_pct:.3%}. "
        f"(drops={metrics.total_drops} events={metrics.total_events})"
    )

    # Информативный вывод в лог pytest
    print(
        "Timer throughput OK | "
        f"eps={metrics.throughput_eps:.1f} ratio={metrics.achieved_ratio:.3f} | "
        f"p50={metrics.p50_ms:.3f}ms p95={metrics.p95_ms:.3f}ms p99={metrics.p99_ms:.3f}ms | "
        f"drops={metrics.total_drops}/{metrics.total_events}"
    )
