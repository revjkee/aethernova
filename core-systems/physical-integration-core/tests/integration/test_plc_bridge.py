# tests/integration/test_plc_bridge.py
"""
Интеграционные тесты PLC Bridge.

Режимы работы:
  1) По умолчанию (без окружения) используется встроенный симулятор (in-memory),
     тестируя контракт и конкурентность.
  2) Для реальной системы установите:
       PLC_BRIDGE_FACTORY="pkg.module:factory_callable"
     где factory_callable -> async context manager, возвращающий объект Bridge.

Контракт интерфейса Bridge (минимальный):
  - async __aenter__() / __aexit__()         : контекст жизни соединения/ресурсов
  - async ping() -> float                     : средняя задержка (сек)
  - async read(tag: str) -> Any               : чтение значения тега
  - async write(tag: str, value: Any) -> None : запись значения тега
  - async batch_read(tags: list[str]) -> dict[str, Any]    : пакетное чтение
  - async subscribe(tags: list[str], cb: Callable[[str, Any, float], Awaitable[None]]) -> AsyncCallable[[], None]
        Подписка на изменения; возвращает async-функцию отписки.
  - capabilities: dict[str, Any] (необязательно), например {"subscriptions": True}

Окружение (опционально):
  - PLC_TEST_TIMEOUT=30          # таймаут отдельной операции (сек)
  - PLC_TEST_LATENCY_WARN_MS=50  # порог предупреждения по latency в ping
  - PLC_TEST_TAG_BOOL=DI0, PLC_TEST_TAG_INT=HR1, PLC_TEST_TAG_FLOAT=AI1  # имена тегов для реального моста
"""

from __future__ import annotations

import asyncio
import importlib
import os
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Optional

import pytest

# ---------- Конфигурация тестов ----------

TEST_TIMEOUT = int(os.getenv("PLC_TEST_TIMEOUT", "30"))
LAT_WARN_MS = int(os.getenv("PLC_TEST_LATENCY_WARN_MS", "50"))

REAL_TAG_BOOL = os.getenv("PLC_TEST_TAG_BOOL", "DI0")
REAL_TAG_INT = os.getenv("PLC_TEST_TAG_INT", "HR1")
REAL_TAG_FLOAT = os.getenv("PLC_TEST_TAG_FLOAT", "AI1")


# ---------- Контракт Bridge (только подсказки типов) ----------

class Bridge:
    async def __aenter__(self) -> "Bridge": ...
    async def __aexit__(self, exc_type, exc, tb) -> None: ...
    async def ping(self) -> float: ...
    async def read(self, tag: str) -> Any: ...
    async def write(self, tag: str, value: Any) -> None: ...
    async def batch_read(self, tags: list[str]) -> dict[str, Any]: ...
    async def subscribe(
        self,
        tags: list[str],
        cb: Callable[[str, Any, float], Awaitable[None]],
    ) -> Callable[[], Awaitable[None]]: ...
    @property
    def capabilities(self) -> dict[str, Any]:  # например: {"subscriptions": True}
        return {}


# ---------- Симулятор по умолчанию ----------

@dataclass
class _SimState:
    data: Dict[str, Any]
    subs: Dict[str, list[Callable[[str, Any, float], Awaitable[None]]]]


class SimBridge(Bridge):
    """
    Легковесный in-memory симулятор:
      - Поддерживает bool/int/float теги
      - Подписки: рассылает изменения подписчикам
      - Пакетное чтение
      - Псевдо-latency через asyncio.sleep(минимальный)
    """
    def __init__(self) -> None:
        self._st = _SimState(
            data={REAL_TAG_BOOL: False, REAL_TAG_INT: 0, REAL_TAG_FLOAT: 0.0},
            subs={},
        )
        self._closed = False

    async def __aenter__(self) -> "SimBridge":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        self._closed = True
        self._st.subs.clear()

    @property
    def capabilities(self) -> dict[str, Any]:
        return {"subscriptions": True}

    async def ping(self) -> float:
        t0 = time.perf_counter()
        await asyncio.sleep(0)  # реалисты — даем шанс планировщику
        return max(0.0001, time.perf_counter() - t0)

    async def read(self, tag: str) -> Any:
        await asyncio.sleep(0)
        if tag not in self._st.data:
            raise KeyError(f"unknown tag: {tag}")
        return self._st.data[tag]

    async def write(self, tag: str, value: Any) -> None:
        await asyncio.sleep(0)
        if tag not in self._st.data:
            raise KeyError(f"unknown tag: {tag}")
        cur = self._st.data[tag]
        # типобезопасность
        if isinstance(cur, bool):
            self._st.data[tag] = bool(value)
        elif isinstance(cur, int) and not isinstance(cur, bool):
            self._st.data[tag] = int(value)
        elif isinstance(cur, float):
            self._st.data[tag] = float(value)
        else:
            self._st.data[tag] = value
        # уведомления
        ts = time.time()
        for cb in self._st.subs.get(tag, []):
            # fire-and-forget, но без подавления ошибок в тестовом окружении
            asyncio.create_task(cb(tag, self._st.data[tag], ts))

    async def batch_read(self, tags: list[str]) -> dict[str, Any]:
        await asyncio.sleep(0)
        return {t: await self.read(t) for t in tags}

    async def subscribe(
        self,
        tags: list[str],
        cb: Callable[[str, Any, float], Awaitable[None]],
    ) -> Callable[[], Awaitable[None]]:
        for t in tags:
            self._st.subs.setdefault(t, []).append(cb)

        async def _unsub() -> None:
            for t in tags:
                if t in self._st.subs:
                    self._st.subs[t] = [c for c in self._st.subs[t] if c is not cb]
        return _unsub


# ---------- Загрузка реальной фабрики (если задано окружение) ----------

def _load_bridge_factory() -> Optional[Callable[[], Any]]:
    val = os.getenv("PLC_BRIDGE_FACTORY")
    if not val:
        return None
    mod_name, _, attr = val.partition(":")
    if not attr:
        raise RuntimeError("PLC_BRIDGE_FACTORY должен быть в формате 'pkg.module:callable'")
    mod = importlib.import_module(mod_name)
    factory = getattr(mod, attr)
    return factory


@asynccontextmanager
async def _bridge_ctx() -> Bridge:
    factory = _load_bridge_factory()
    if factory is None:
        # симулятор
        async with SimBridge() as b:
            yield b
        return
    # ожидаем async context manager от фабрики
    cm = factory()
    if hasattr(cm, "__aenter__"):
        async with cm as b:  # type: ignore[call-arg]
            yield b  # type: ignore[misc]
    else:
        # допускаем, что фабрика возвращает уже готовый Bridge
        b = cm  # type: ignore[assignment]
        try:
            yield b
        finally:
            if hasattr(b, "__aexit__"):
                await b.__aexit__(None, None, None)  # type: ignore[misc]


# ---------- Фикстуры ----------

@pytest.fixture(scope="module")
async def bridge() -> Any:
    async with _bridge_ctx() as b:
        yield b


# ---------- Тесты ----------

@pytest.mark.integration
@pytest.mark.asyncio
async def test_connect_and_ping(bridge: Bridge) -> None:
    # Пингуем несколько раз, проверим, что latency разумная
    latencies = []
    for _ in range(5):
        lat = await asyncio.wait_for(bridge.ping(), timeout=TEST_TIMEOUT)
        latencies.append(lat)
    avg_ms = sum(latencies) / len(latencies) * 1000.0
    # В симуляторе почти всегда < 1мс; в реале порог мягкий и настраиваемый
    assert avg_ms < max(LAT_WARN_MS * 4, 2000), f"Средняя задержка слишком велика: {avg_ms:.1f} ms"


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tag,values",
    [
        (REAL_TAG_BOOL, [False, True, False]),
        (REAL_TAG_INT, [0, 1, 123, -5, 65535]),
        (REAL_TAG_FLOAT, [0.0, 1.5, -3.25, 42.001]),
    ],
)
async def test_scalar_read_write_roundtrip(bridge: Bridge, tag: str, values: list[Any]) -> None:
    for v in values:
        await asyncio.wait_for(bridge.write(tag, v), timeout=TEST_TIMEOUT)
        got = await asyncio.wait_for(bridge.read(tag), timeout=TEST_TIMEOUT)
        if isinstance(v, float):
            assert abs(float(got) - float(v)) <= 1e-6
        else:
            assert got == (bool(v) if isinstance(got, bool) else type(got)(v))


@pytest.mark.integration
@pytest.mark.asyncio
async def test_batch_read_consistency(bridge: Bridge) -> None:
    tags = [REAL_TAG_BOOL, REAL_TAG_INT, REAL_TAG_FLOAT]
    # подготовим значения
    await bridge.write(REAL_TAG_BOOL, True)
    await bridge.write(REAL_TAG_INT, 321)
    await bridge.write(REAL_TAG_FLOAT, 12.75)
    # проверка batch_read = сумма одиночных чтений
    single = {t: await bridge.read(t) for t in tags}
    batch = await asyncio.wait_for(bridge.batch_read(tags), timeout=TEST_TIMEOUT)
    assert batch == single


@pytest.mark.integration
@pytest.mark.asyncio
async def test_subscriptions_deliver_updates(bridge: Bridge) -> None:
    if not getattr(bridge, "capabilities", {}).get("subscriptions", False):
        pytest.skip("Подписки не поддерживаются реализацией bridge")
    q: asyncio.Queue[tuple[str, Any, float]] = asyncio.Queue()

    async def cb(tag: str, value: Any, ts: float) -> None:
        await q.put((tag, value, ts))

    unsub = await asyncio.wait_for(bridge.subscribe([REAL_TAG_INT, REAL_TAG_FLOAT], cb), timeout=TEST_TIMEOUT)

    try:
        # изменяем несколько значений
        await bridge.write(REAL_TAG_INT, 777)
        await bridge.write(REAL_TAG_FLOAT, 3.14)
        # ждём два события
        got = []
        for _ in range(2):
            item = await asyncio.wait_for(q.get(), timeout=TEST_TIMEOUT)
            got.append(item[0])
        assert set(got) == {REAL_TAG_INT, REAL_TAG_FLOAT}
    finally:
        await unsub()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_concurrency_and_fairness(bridge: Bridge) -> None:
    # Одновременно много чтений/записей — не должно быть дедлоков, порядок может отличаться.
    N = 50
    async def writer():
        for i in range(N):
            await bridge.write(REAL_TAG_INT, i)
    async def reader():
        seen = 0
        last = -1
        t_end = time.time() + 5.0
        while time.time() < t_end and seen < N:
            val = await bridge.read(REAL_TAG_INT)
            if isinstance(val, int) and val != last:
                last = val
                seen += 1
        return seen
    # запускаем конкурентно
    seen = await asyncio.wait_for(asyncio.gather(writer(), reader()), timeout=TEST_TIMEOUT)
    # Второй результат — количество уникальных прочтений
    assert seen[1] > 0


@pytest.mark.integration
@pytest.mark.asyncio
async def test_idempotent_write(bridge: Bridge) -> None:
    v = 123
    await bridge.write(REAL_TAG_INT, v)
    before = await bridge.read(REAL_TAG_INT)
    await bridge.write(REAL_TAG_INT, v)  # повтор
    after = await bridge.read(REAL_TAG_INT)
    assert before == v and after == v


@pytest.mark.integration
@pytest.mark.asyncio
async def test_timeout_behavior(bridge: Bridge, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Эмуляция задержки в реализациях без явной поддержки таймаутов:
    - для симулятора временно переопределяем read, чтобы спровоцировать TimeoutError
    - для реального моста — пропускаем тест, если нет способа инъектировать задержку
    """
    if isinstance(bridge, SimBridge):
        async def slow_read(tag: str) -> Any:
            await asyncio.sleep(TEST_TIMEOUT + 2)
            return await SimBridge.read(bridge, tag)  # type: ignore[misc]
        monkeypatch.setattr(bridge, "read", slow_read)  # type: ignore[arg-type]
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(bridge.read(REAL_TAG_INT), timeout=TEST_TIMEOUT)
    else:
        pytest.skip("Инъекция задержки для реального моста не поддерживается этим тестом")


# ---------- Завершение файла ----------
