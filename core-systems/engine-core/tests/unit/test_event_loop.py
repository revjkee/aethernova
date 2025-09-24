# engine-core/engine/tests/unit/test_event_loop.py
import asyncio
import gc
import sys
import time
import types
import weakref

import pytest

PY311_PLUS = sys.version_info >= (3, 11)

# -------------------------------------------------------------
# Утилиты и хелперы
# -------------------------------------------------------------

async def _sleep_and_return(val, delay=0.01):
    await asyncio.sleep(delay)
    return val

async def _hang_forever(evt: asyncio.Event):
    # Ждет внешнего события бесконечно.
    await evt.wait()
    return "unreachable"

class _Finalizable:
    """Объект для детектора утечек (через weakref)."""
    def __init__(self):
        self.alive = True
    def __del__(self):
        self.alive = False

# -------------------------------------------------------------
# Базовые тесты event loop
# -------------------------------------------------------------

@pytest.mark.asyncio
async def test_event_loop_runs_simple_coroutine():
    res = await _sleep_and_return(42, delay=0.001)
    assert res == 42

@pytest.mark.asyncio
async def test_wait_for_timeout_raises():
    evt = asyncio.Event()
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(_hang_forever(evt), timeout=0.02)

@pytest.mark.asyncio
async def test_task_cancellation_propagates():
    evt = asyncio.Event()
    task = asyncio.create_task(_hang_forever(evt))
    await asyncio.sleep(0)  # дайте задаче стартовать
    assert not task.done()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

@pytest.mark.asyncio
async def test_background_task_cleanup_no_leak():
    # Создаем фоновую задачу и слабую ссылку; убеждаемся, что после отмены и gc сборки нет утечек Task.
    async def bg():
        await asyncio.sleep(0.05)

    t = asyncio.create_task(bg())
    w = weakref.ref(t)
    await asyncio.sleep(0)  # старт
    t.cancel()
    with pytest.raises(asyncio.CancelledError):
        await t
    del t
    # Даем шанс циклу обработать финализацию
    for _ in range(5):
        await asyncio.sleep(0)
        gc.collect()
        if w() is None:
            break
    assert w() is None, "Task leaked (weakref still alive)"

@pytest.mark.asyncio
async def test_shield_prevents_cancellation_until_complete():
    # shield защищает внутреннюю корутину от CancelledError снаружи
    async def work():
        await asyncio.sleep(0.02)
        return "ok"

    task = asyncio.create_task(asyncio.shield(work()))
    await asyncio.sleep(0)  # старт
    task.cancel()
    # shield превращает внешнюю отмену в ожидание результата
    res = await task
    assert res == "ok"

# -------------------------------------------------------------
# Интеграция с ObservabilityAdapter (опционально)
# -------------------------------------------------------------

@pytest.mark.asyncio
async def test_observability_adapter_import_safe():
    # Должно либо корректно импортироваться, либо не падать и быть пропущено.
    try:
        from engine.adapters.observability_adapter import get_observability
    except Exception:
        pytest.skip("observability adapter not installed/available")
    obs = get_observability()
    # Логи не должны падать
    obs.log_info("test-log", unit="event_loop")
    assert hasattr(obs, "metrics_asgi_app")

# -------------------------------------------------------------
# Интеграция с DataFabricMock (опционально)
# -------------------------------------------------------------

@pytest.mark.asyncio
async def test_datafabric_mock_stream_cancellation_is_clean():
    try:
        from engine.mocks.datafabric_mock import DataFabricMock, TableSchema, Column, Query
    except Exception:
        pytest.skip("DataFabricMock not available")

    async with DataFabricMock.session() as df:
        schema = TableSchema(
            name="users",
            primary_key="id",
            columns=(Column("id", int, True), Column("name", str, True)),
            ttl_seconds=None,
            soft_delete=True,
        )
        await df.create_table(schema)
        await df.insert("users", [{"id": i, "name": f"user{i}"} for i in range(100)])

        q = Query(filters=[], projection=("id", "name"), order_by=("id", "asc"), limit=100, offset=0)

        agen = df.stream("users", q, batch_size=10)
        # Прочитаем один батч и отменим
        first = await agen.__anext__()
        assert len(first) == 10
        # Отменим поток: правильное завершение — StopAsyncIteration без висящих задач
        await agen.aclose()

        # Проверим, что get/Query все также работают после закрытия стрима
        one = await df.get("users", 1)
        assert one and one["name"] == "user1"

# -------------------------------------------------------------
# Интеграция с AIMock (опционально)
# -------------------------------------------------------------

@pytest.mark.asyncio
async def test_aimock_chat_and_stream_basic():
    try:
        from engine.mocks.ai_mock import AIMock, AIMockConfig
    except Exception:
        pytest.skip("AIMock not available")

    mock = AIMock(AIMockConfig())
    # Обычный completion
    resp = await mock.chat_complete([{"role": "user", "content": "Hello"}], temperature=0.0, max_tokens=32)
    assert "choices" in resp and resp["choices"][0]["message"]["content"]
    assert resp["usage"]["total_tokens"] >= resp["usage"]["prompt_tokens"]

    # Стриминговый ответ должен отдать хотя бы 2 чанка (header + часть текста) и финальный стоп
    chunks = []
    async for ch in mock.chat_stream([{"role": "user", "content": "Stream, please"}], temperature=0.1, max_tokens=32):
        chunks.append(ch)
    assert chunks[0].get("delta", "") == ""
    assert any(c.get("delta") for c in chunks[1:-1]), "No streaming chunks with content"
    assert chunks[-1].get("finish_reason") == "stop"

# -------------------------------------------------------------
# Параллелизм и семафоры
# -------------------------------------------------------------

@pytest.mark.asyncio
async def test_concurrent_gather_with_return_exceptions():
    # Один таск падает, другой завершается — с return_exceptions=True собираем оба результата.
    async def ok():
        await asyncio.sleep(0.01)
        return 1

    async def boom():
        await asyncio.sleep(0.01)
        raise RuntimeError("boom")

    res = await asyncio.gather(ok(), boom(), return_exceptions=True)
    assert len(res) == 2
    assert res[0] == 1
    assert isinstance(res[1], RuntimeError)

@pytest.mark.asyncio
async def test_semaphore_limits_concurrency():
    sem = asyncio.Semaphore(3)
    running = 0
    max_running = 0

    async def worker():
        nonlocal running, max_running
        async with sem:
            running += 1
            max_running = max(max_running, running)
            await asyncio.sleep(0.01)
            running -= 1

    await asyncio.gather(*(worker() for _ in range(10)))
    assert max_running <= 3

# -------------------------------------------------------------
# Таймауты «мягкого» завершения
# -------------------------------------------------------------

@pytest.mark.asyncio
async def test_graceful_timeout_pattern():
    # Типовой паттерн «мягкого» завершения: ждём задачи, затем отменяем, затем ограниченный wait.
    async def slow(n):
        try:
            await asyncio.sleep(0.2)
            return n
        except asyncio.CancelledError:
            # имитация корректной уборки ресурсов
            await asyncio.sleep(0.01)
            raise

    task = asyncio.create_task(slow(5))
    # Ждем немного и инициируем graceful shutdown
    await asyncio.sleep(0.02)
    task.cancel()
    t0 = time.perf_counter()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=0.1)
    assert (time.perf_counter() - t0) < 0.2  # не зависли дольше, чем положено

# -------------------------------------------------------------
# Политика событийного цикла (проверка без падений)
# -------------------------------------------------------------

def test_event_loop_policy_no_crash(monkeypatch):
    # Проверяем, что установка политики и создание нового лупа не приводит к ошибкам.
    policy = asyncio.get_event_loop_policy()
    asyncio.set_event_loop_policy(policy)  # идемпотентно
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(_sleep_and_return("ok", 0))
    finally:
        loop.close()

# -------------------------------------------------------------
# XFail/Skip для платформенных особенностей
# -------------------------------------------------------------

@pytest.mark.xfail(sys.platform.startswith("win"), reason="Signal handling differs on Windows")
def test_signal_handling_placeholder():
    # Здесь только placeholder: полноценные сигналы сложно тестировать кроссплатформенно.
    # Важна лишь проверка, что доступ к модулю signal не приводит к ошибкам импорта.
    import signal  # noqa: F401
