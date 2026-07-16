# agent_mash/tests/performance/test_memory_pressure.py
from __future__ import annotations

import gc
import os
import time
import platform
import tracemalloc
from dataclasses import dataclass
from typing import Callable, Optional, Tuple, List

import pytest


try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None  # type: ignore


MiB = 1024 * 1024


@dataclass(frozen=True)
class MemorySnapshot:
    """
    Унифицированный снимок памяти процесса.

    rss_bytes: Resident Set Size (физическая память процесса), если доступно.
    tracemalloc_current_bytes / tracemalloc_peak_bytes: метрики Python-аллокатора.
    timestamp: для диагностики и корреляции.
    """
    rss_bytes: Optional[int]
    tracemalloc_current_bytes: int
    tracemalloc_peak_bytes: int
    timestamp: float


def _now() -> float:
    return time.time()


def _force_gc(repeat: int = 3) -> None:
    # Принудительно собираем мусор несколько раз, чтобы стабилизировать RSS/аллокатор.
    for _ in range(max(1, repeat)):
        gc.collect()
        time.sleep(0.01)


def _ensure_tracemalloc_started(n_frames: int = 25) -> None:
    if not tracemalloc.is_tracing():
        tracemalloc.start(n_frames)


def _get_rss_bytes() -> Optional[int]:
    """
    Возвращает RSS процесса в байтах через psutil, если возможно.

    Если psutil недоступен или платформа ограничивает сбор метрик, вернёт None.
    """
    if psutil is None:
        return None
    try:
        proc = psutil.Process(os.getpid())
        return int(proc.memory_info().rss)
    except Exception:
        return None


def _snapshot() -> MemorySnapshot:
    _ensure_tracemalloc_started()
    current, peak = tracemalloc.get_traced_memory()
    return MemorySnapshot(
        rss_bytes=_get_rss_bytes(),
        tracemalloc_current_bytes=int(current),
        tracemalloc_peak_bytes=int(peak),
        timestamp=_now(),
    )


def _format_bytes(n: Optional[int]) -> str:
    if n is None:
        return "n/a"
    return f"{n / MiB:.2f} MiB"


def _allocate_bytes(total_bytes: int, chunk_bytes: int = 1 * MiB) -> List[bytearray]:
    """
    Аллоцирует total_bytes байт, возвращает список чанков, удерживающих память.

    Важно: bytearray используется намеренно, чтобы нагрузка была предсказуемой.
    """
    if total_bytes <= 0:
        return []
    chunk = max(1, int(chunk_bytes))
    remaining = int(total_bytes)
    blocks: List[bytearray] = []
    while remaining > 0:
        size = chunk if remaining >= chunk else remaining
        blocks.append(bytearray(size))
        remaining -= size
    return blocks


def _touch_blocks(blocks: List[bytearray], step: int = 4096) -> None:
    """
    Пробегает по блокам и "трогает" страницы, чтобы уменьшить ленивую аллокацию/CoW эффекты.
    """
    s = max(1, int(step))
    for b in blocks:
        for i in range(0, len(b), s):
            b[i] = (b[i] + 1) % 256


def _stable_sleep(seconds: float = 0.05) -> None:
    time.sleep(max(0.0, float(seconds)))


def _delta_bytes(after: Optional[int], before: Optional[int]) -> Optional[int]:
    if after is None or before is None:
        return None
    return int(after) - int(before)


@pytest.mark.performance
class TestMemoryPressure:
    """
    Набор стресс-тестов памяти.

    Цель: при нагрузке и последующем освобождении не должно быть неконтролируемого роста
    (подозрение на утечки/фрагментацию/удержание ссылок).
    """

    @pytest.mark.parametrize(
        "peak_mib,hold_mib,allowed_residual_growth_mib",
        [
            # Пик, удержание, допустимый остаточный рост после освобождения.
            (256, 64, 32),
            (384, 96, 48),
        ],
    )
    def test_memory_pressure_release_stability(
        self,
        peak_mib: int,
        hold_mib: int,
        allowed_residual_growth_mib: int,
    ) -> None:
        """
        Сценарий:
        1) Прогрев и базовый снимок.
        2) Аллокация до пика, касание страниц, снимок.
        3) Освобождение до уровня удержания (имитация реального кеша), GC, снимок.
        4) Полное освобождение, GC, снимок.
        5) Проверка: остаточный рост относительно базы в пределах порога.

        Метрика:
        - Приоритет: RSS (psutil).
        - Fallback: tracemalloc current (Python heap), если RSS недоступен.
        """
        # Если rss невозможно измерить, тест всё равно полезен через tracemalloc,
        # но пороги должны применяться к tracemalloc (он обычно ниже RSS).
        use_rss = _get_rss_bytes() is not None

        _force_gc()
        base = _snapshot()
        _stable_sleep()

        # Прогрев: маленькая аллокация и освобождение, чтобы стабилизировать аллокатор.
        warm = _allocate_bytes(8 * MiB, 1 * MiB)
        _touch_blocks(warm)
        del warm
        _force_gc()
        _stable_sleep()

        base2 = _snapshot()
        # Используем более стабильную базу после прогрева.
        base = base2

        peak_bytes = int(peak_mib) * MiB
        hold_bytes = int(hold_mib) * MiB

        blocks = _allocate_bytes(peak_bytes, 2 * MiB)
        _touch_blocks(blocks)
        _stable_sleep()
        peak_snap = _snapshot()

        # Освобождаем часть, оставляя hold_bytes.
        if hold_bytes <= 0:
            blocks_to_keep: List[bytearray] = []
        else:
            keep: List[bytearray] = []
            kept = 0
            for b in blocks:
                if kept >= hold_bytes:
                    break
                keep.append(b)
                kept += len(b)
            blocks_to_keep = keep

        del blocks
        blocks = blocks_to_keep
        _force_gc()
        _stable_sleep()
        hold_snap = _snapshot()

        # Полное освобождение.
        del blocks
        _force_gc(repeat=5)
        _stable_sleep(0.15)
        final_snap = _snapshot()

        if use_rss:
            before = base.rss_bytes
            after = final_snap.rss_bytes
            delta = _delta_bytes(after, before)
            allowed = int(allowed_residual_growth_mib) * MiB

            assert delta is not None and before is not None and after is not None, (
                "RSS метрика стала недоступна во время теста; "
                "окружение не позволяет корректно измерять потребление процесса."
            )

            assert delta <= allowed, (
                "Подозрение на утечку/удержание памяти: RSS вырос выше порога.\n"
                f"Platform: {platform.platform()}\n"
                f"Base RSS: {_format_bytes(before)}\n"
                f"Peak RSS: {_format_bytes(peak_snap.rss_bytes)}\n"
                f"Hold RSS: {_format_bytes(hold_snap.rss_bytes)}\n"
                f"Final RSS: {_format_bytes(after)}\n"
                f"Residual delta: {_format_bytes(delta)} (allowed {_format_bytes(allowed)})\n"
                f"Tracemalloc base/peak/final (current): "
                f"{_format_bytes(base.tracemalloc_current_bytes)} / "
                f"{_format_bytes(peak_snap.tracemalloc_current_bytes)} / "
                f"{_format_bytes(final_snap.tracemalloc_current_bytes)}\n"
            )
        else:
            # Fallback: tracemalloc current.
            before = base.tracemalloc_current_bytes
            after = final_snap.tracemalloc_current_bytes
            delta = after - before

            # Для tracemalloc порог делаем более строгим: он учитывает Python heap,
            # но не учитывает allocator arenas полностью как RSS.
            allowed = int(max(8, allowed_residual_growth_mib // 2)) * MiB

            assert delta <= allowed, (
                "Подозрение на утечку/удержание памяти (tracemalloc fallback): "
                "текущие аллокации Python выросли выше порога.\n"
                f"Platform: {platform.platform()}\n"
                f"Base tracemalloc current: {_format_bytes(before)}\n"
                f"Peak tracemalloc current: {_format_bytes(peak_snap.tracemalloc_current_bytes)}\n"
                f"Final tracemalloc current: {_format_bytes(after)}\n"
                f"Residual delta: {_format_bytes(delta)} (allowed {_format_bytes(allowed)})\n"
            )

    @pytest.mark.parametrize(
        "cycles,cycle_mib,allowed_growth_mib",
        [
            (8, 64, 24),
            (10, 48, 24),
        ],
    )
    def test_memory_pressure_repeated_cycles_no_unbounded_growth(
        self,
        cycles: int,
        cycle_mib: int,
        allowed_growth_mib: int,
    ) -> None:
        """
        Повторяющиеся циклы аллокации/освобождения.
        Цель: отсутствие неограниченного роста между первым и последним циклом.
        """
        _force_gc()
        base = _snapshot()
        use_rss = base.rss_bytes is not None

        per_cycle_bytes = int(cycle_mib) * MiB
        for _ in range(int(cycles)):
            blocks = _allocate_bytes(per_cycle_bytes, 2 * MiB)
            _touch_blocks(blocks)
            _stable_sleep(0.02)
            del blocks
            _force_gc(repeat=2)
            _stable_sleep(0.03)

        final_snap = _snapshot()

        if use_rss:
            delta = _delta_bytes(final_snap.rss_bytes, base.rss_bytes)
            allowed = int(allowed_growth_mib) * MiB
            assert delta is not None, "RSS метрика недоступна для сравнения."
            assert delta <= allowed, (
                "Неограниченный рост RSS на повторяющихся циклах.\n"
                f"Base RSS: {_format_bytes(base.rss_bytes)}\n"
                f"Final RSS: {_format_bytes(final_snap.rss_bytes)}\n"
                f"Delta: {_format_bytes(delta)} (allowed {_format_bytes(allowed)})\n"
            )
        else:
            delta = final_snap.tracemalloc_current_bytes - base.tracemalloc_current_bytes
            allowed = int(max(8, allowed_growth_mib // 2)) * MiB
            assert delta <= allowed, (
                "Неограниченный рост tracemalloc current на повторяющихся циклах.\n"
                f"Base: {_format_bytes(base.tracemalloc_current_bytes)}\n"
                f"Final: {_format_bytes(final_snap.tracemalloc_current_bytes)}\n"
                f"Delta: {_format_bytes(delta)} (allowed {_format_bytes(allowed)})\n"
            )
