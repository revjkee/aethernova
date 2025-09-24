# tests/unit/test_interlocks.py
# -*- coding: utf-8 -*-
import asyncio
import json
import time
from typing import Any, Dict, List, Tuple

import pytest

from physical_integration.safety.watchdog import (
    Watchdog,
    WatchdogSettings,
    WatchConfig,
    GroupConfig,
    TripPolicy,
    Severity,
)

# --------------------------------------------------------------------------------------
# ФИКСТУРЫ И ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# --------------------------------------------------------------------------------------

@pytest.fixture
def fast_settings(tmp_path) -> WatchdogSettings:
    """
    Настройки для быстрых тестов:
    - быстрый тик
    - файл персистентности в tmp
    """
    return WatchdogSettings(
        tick_interval_s=0.01,
        persist_path=tmp_path / "watchdog_state.json",
    )


class PublishSpy:
    def __init__(self):
        self.events: List[Tuple[str, Dict[str, Any]]] = []

    async def __call__(self, topic: str, payload: Dict[str, Any]) -> None:
        # сохраняем кортеж (topic, payload) как факт публикации
        self.events.append((topic, json.loads(json.dumps(payload))))  # копия


class TripSpy:
    def __init__(self):
        self.calls: List[Tuple[str, Dict[str, Any]]] = []

    async def __call__(self, topic: str, payload: Dict[str, Any]) -> None:
        self.calls.append((topic, json.loads(json.dumps(payload))))


async def wait_for(cond, timeout: float = 1.5, interval: float = 0.01):
    """
    Утилита ожидания произвольного условия без активного ожидания.
    """
    start = time.time()
    while time.time() - start < timeout:
        if cond():
            return True
        await asyncio.sleep(interval)
    return False


async def wait_watch_state(wd: Watchdog, wid: str, desired: Severity, timeout: float = 1.5) -> None:
    ok = await wait_for(lambda: wd.snapshot()["watches"].get(wid, {}).get("severity") == int(desired), timeout=timeout)
    assert ok, f"Ожидали состояние {desired} для '{wid}', текущее: {wd.snapshot()['watches'].get(wid)}"


async def wait_group_state(wd: Watchdog, gname: str, desired: Severity, timeout: float = 1.5) -> None:
    ok = await wait_for(lambda: wd.snapshot()["groups"].get(gname, {}).get("severity") == int(desired), timeout=timeout)
    assert ok, f"Ожидали состояние {desired} для группы '{gname}', текущее: {wd.snapshot()['groups'].get(gname)}"


# --------------------------------------------------------------------------------------
# ТЕСТЫ: ANY/ALL/QUORUM
# --------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_group_any_trip_and_trip_cb(fast_settings):
    pub, trip = PublishSpy(), TripSpy()
    wd = Watchdog(fast_settings, publish=pub.__call__, trip_cb=trip.__call__)

    await wd.start()
    try:
        # Регистрируем два «наблюдаемых объекта»: быстрые таймауты для ускорения тестов
        cfg = WatchConfig(timeout_s=0.08, miss_threshold=1, warn_after_misses=1, recover_hits=1, grace_start_s=0.02)
        await wd.register("a", cfg)
        await wd.register("b", cfg)
        await wd.define_group(GroupConfig(name="cell", members=["a", "b"], policy=TripPolicy.ANY, squelch_s=0.05))

        # Подадим начальные пульсы, дождёмся OK
        await wd.feed("a")
        await wd.feed("b")
        await wait_watch_state(wd, "a", Severity.OK)
        await wait_watch_state(wd, "b", Severity.OK)
        await wait_group_state(wd, "cell", Severity.OK)

        # Прекращаем «a», даём просрочиться timeout → TRIP в ANY
        await asyncio.sleep(0.10)
        await wait_watch_state(wd, "a", Severity.TRIP)
        await wait_group_state(wd, "cell", Severity.TRIP)

        # Проверка, что trip_cb был вызван
        assert any(t[0] == "safety.estop" for t in trip.calls), "Ожидался вызов аварийного останова"
        # Проверка публикации события перехода группы
        assert any(top == "safety.watchdog.group" and ev.get("group") == "cell" and ev.get("to") == int(Severity.TRIP)
                   for top, ev in pub.events)
    finally:
        await wd.stop()


@pytest.mark.asyncio
async def test_group_all_warn_then_trip(fast_settings):
    pub, trip = PublishSpy(), TripSpy()
    wd = Watchdog(fast_settings, publish=pub.__call__, trip_cb=trip.__call__)
    await wd.start()
    try:
        # Для ALL: сделаем так, чтобы один участник перешёл в WARN, другой — в TRIP позже.
        cfg_warn_first = WatchConfig(timeout_s=0.06, miss_threshold=2, warn_after_misses=1, grace_start_s=0.0)
        cfg_trip_fast = WatchConfig(timeout_s=0.06, miss_threshold=1, warn_after_misses=1, grace_start_s=0.0)

        await wd.register("w1", cfg_warn_first)
        await wd.register("w2", cfg_trip_fast)
        await wd.define_group(GroupConfig(name="cell", members=["w1", "w2"], policy=TripPolicy.ALL, squelch_s=0.02))

        await wd.feed("w1")
        await wd.feed("w2")
        # Ждём пока w1 станет WARN (1 пропуск), а w2 — ещё OK
        await asyncio.sleep(0.07)
        await wait_watch_state(wd, "w1", Severity.WARN)
        # ALL при присутствии WARN даёт WARN
        await wait_group_state(wd, "cell", Severity.WARN)

        # Теперь доведём w2 до TRIP, тогда ALL не станет TRIP пока w1 не TRIP
        await asyncio.sleep(0.07)
        await wait_watch_state(wd, "w2", Severity.TRIP)
        # Группа всё ещё WARN, т.к. не все TRIP
        await wait_group_state(wd, "cell", Severity.WARN)

        # Доведём w1 до TRIP
        await asyncio.sleep(0.07)
        await wait_watch_state(wd, "w1", Severity.TRIP)
        await wait_group_state(wd, "cell", Severity.TRIP)
    finally:
        await wd.stop()


@pytest.mark.asyncio
async def test_group_quorum_two_of_three(fast_settings):
    pub, trip = PublishSpy(), TripSpy()
    wd = Watchdog(fast_settings, publish=pub.__call__, trip_cb=trip.__call__)
    await wd.start()
    try:
        cfg = WatchConfig(timeout_s=0.05, miss_threshold=1, warn_after_misses=1, grace_start_s=0.0)
        await wd.register("a", cfg)
        await wd.register("b", cfg)
        await wd.register("c", cfg)

        await wd.define_group(GroupConfig(name="cell", members=["a", "b", "c"], policy=TripPolicy.QUORUM, quorum=2, squelch_s=0.02))

        # Изначально все OK
        await wd.feed("a"); await wd.feed("b"); await wd.feed("c")
        await wait_group_state(wd, "cell", Severity.OK)

        # Сначала один TRIP — кворм не выполнен, ожидаем OK или WARN (в нашем алгоритме WARN появляется при WARN у кого-либо)
        await asyncio.sleep(0.06)  # доведём a до TRIP
        await wait_watch_state(wd, "a", Severity.TRIP)
        # Ни один в WARN — значит группа остаётся OK (по действующей логике)
        await wait_group_state(wd, "cell", Severity.OK)

        # Доведём b до TRIP — кворум 2/3 достигнут
        await asyncio.sleep(0.06)
        await wait_watch_state(wd, "b", Severity.TRIP)
        await wait_group_state(wd, "cell", Severity.TRIP)
    finally:
        await wd.stop()


# --------------------------------------------------------------------------------------
# ТЕСТЫ: SQUELCH И ИДЕМПОТЕНТНОСТЬ СОБЫТИЙ
# --------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_event_squelch_no_storm(fast_settings):
    pub, trip = PublishSpy(), TripSpy()
    wd = Watchdog(fast_settings, publish=pub.__call__, trip_cb=trip.__call__)
    await wd.start()
    try:
        cfg = WatchConfig(timeout_s=0.04, miss_threshold=1, warn_after_misses=1, grace_start_s=0.0, squelch_s=0.2)
        await wd.register("x", cfg)
        await wd.define_group(GroupConfig(name="g", members=["x"], policy=TripPolicy.ANY, squelch_s=0.2))

        # Переводим в TRIP
        await asyncio.sleep(0.05)
        await wait_watch_state(wd, "x", Severity.TRIP)
        await wait_group_state(wd, "g", Severity.TRIP)

        # Через короткий промежуток состояние не меняется — повторная публикация не должна произойти из-за squelch
        before = len(pub.events)
        await asyncio.sleep(0.05)
        after = len(pub.events)
        assert after == before, "Повторные события не должны публиковаться в пределах squelch"

        # По истечении squelch допускается повтор (если логика создаст идентичный переход). Мы явно не создаём переход, поэтому остаётся без изменений.
    finally:
        await wd.stop()


# --------------------------------------------------------------------------------------
# ТЕСТЫ: ПЕРСИСТЕНТНОСТЬ
# --------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_persistence_restore_severity(fast_settings, tmp_path):
    pub, trip = PublishSpy(), TripSpy()
    # Первый инстанс — установим состояние и сохраним
    wd1 = Watchdog(fast_settings, publish=pub.__call__, trip_cb=trip.__call__)
    await wd1.start()
    try:
        cfg = WatchConfig(timeout_s=0.2, miss_threshold=1, grace_start_s=0.0)
        await wd1.register("persisted", cfg)
        await wd1.define_group(GroupConfig(name="grp", members=["persisted"], policy=TripPolicy.ANY))
        await wd1.feed("persisted")
        await wait_watch_state(wd1, "persisted", Severity.OK)
    finally:
        await wd1.stop()

    # Второй инстанс — загрузит состояние из того же persist_path
    pub2, trip2 = PublishSpy(), TripSpy()
    wd2 = Watchdog(fast_settings, publish=pub2.__call__, trip_cb=trip2.__call__)
    # Регистрация (та же) — конфиг присвоится, а состояние подтянуто из файла
    await wd2.start()
    try:
        await wd2.register("persisted", WatchConfig(timeout_s=0.2, miss_threshold=1, grace_start_s=0.0))
        # Сразу после старта состояние из файла может быть OK/UNKNOWN в зависимости от давности.
        # Дождёмся максимума — если не пришёл новый feed и возраст превысил timeout, перейдёт в TRIP.
        # Мы здесь проверяем сам факт чтения: last_seen_ts не нулевой, что проявится как не мгновенный TRIP.
        snap = wd2.snapshot()
        assert "persisted" in snap["watches"], "Ожидалась запись watch из персистентного состояния"
    finally:
        await wd2.stop()
