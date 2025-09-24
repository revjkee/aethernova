# engine-core/engine/tests/integration/test_datafabric_bus.py
import asyncio
import time

import pytest

pytestmark = pytest.mark.asyncio

# ----------------------------------------------------------------------
# Skip, если мок недоступен
# ----------------------------------------------------------------------

try:
    from engine.mocks.datafabric_mock import DataFabricMock, TableSchema, Column, Query
except Exception:
    DataFabricMock = None  # type: ignore
    TableSchema = None     # type: ignore
    Column = None          # type: ignore
    Query = None           # type: ignore


def _skip_if_unavailable():
    if not DataFabricMock or not TableSchema or not Column:
        pytest.skip("DataFabricMock is not available")


# ----------------------------------------------------------------------
# Вспомогательные «рекордеры» событий
# ----------------------------------------------------------------------

class Recorder:
    def __init__(self):
        self.events = []

    def handler_sync(self, table: str, payload):
        self.events.append(("sync", table, dict(payload)))

    async def handler_async(self, table: str, payload):
        await asyncio.sleep(0)  # контекст‑свитч
        self.events.append(("async", table, dict(payload)))


# ----------------------------------------------------------------------
# Базовый happy‑path: insert/upsert/delete → события, порядок, данные
# ----------------------------------------------------------------------

async def test_bus_emits_on_insert_upsert_delete_and_order():
    _skip_if_unavailable()

    rec = Recorder()

    async with DataFabricMock.session() as df:  # type: ignore
        schema = TableSchema(
            name="users",
            primary_key="id",
            columns=(Column("id", int, True), Column("name", str, True)),
            ttl_seconds=None,
            soft_delete=True,
        )
        await df.create_table(schema)

        # Подписание на события: порядок в списке определяет последовательность вызовов
        df.bus.on_insert.append(rec.handler_sync)
        df.bus.on_insert.append(rec.handler_async)
        df.bus.on_update.append(rec.handler_async)
        df.bus.on_delete.append(rec.handler_sync)

        # insert
        n_ins = await df.insert("users", [{"id": 1, "name": "Ann"}, {"id": 2, "name": "Bob"}])
        assert n_ins == 2

        # upsert
        n_up = await df.upsert("users", [{"id": 2, "name": "Bob Jr"}])
        assert n_up == 1

        # delete (soft)
        n_del = await df.delete("users", [1])
        assert n_del == 1

        # Проверка порядка и содержимого записанных событий
        # insert → два обработчика; upsert → один; delete → один = всего 4 записи
        kinds = [k for (k, _, _) in rec.events]
        assert kinds == ["sync", "async", "async", "sync"]

        # Суммарная проверка таблицы: id=2 существует, имя обновлено; id=1 помечен удаленным
        row2 = await df.get("users", 2)
        assert row2 and row2["name"] == "Bob Jr"

        row1_visible = await df.get("users", 1)
        assert row1_visible is None  # soft‑delete скрывает

        row1_deleted = await df.get("users", 1, include_deleted=True)
        assert row1_deleted and row1_deleted.get("_deleted") is True


# ----------------------------------------------------------------------
# Бекпрешер: медленный обработчик должен «тормозить» emit (ожидание завершения)
# ----------------------------------------------------------------------

async def test_bus_backpressure_waits_for_slow_handlers():
    _skip_if_unavailable()

    called = []

    async def slow_handler(table: str, payload):
        called.append(("slow.start", table))
        await asyncio.sleep(0.05)  # 50 мс
        called.append(("slow.end", table))

    async with DataFabricMock.session() as df:  # type: ignore
        schema = TableSchema(
            name="items",
            primary_key="sku",
            columns=(Column("sku", str, True), Column("price", float, True)),
        )
        await df.create_table(schema)
        df.bus.on_update.append(slow_handler)

        t0 = time.perf_counter()
        await df.upsert("items", [{"sku": "A1", "price": 10.0}])
        dt = time.perf_counter() - t0

        # Emit должен ждать slow_handler ≈50мс
        assert dt >= 0.045, f"emit finished too early: {dt:.3f}s"
        assert called == [("slow.start", "items"), ("slow.end", "items")]


# ----------------------------------------------------------------------
# Исключения обработчика: исключение всплывает, но состояние уже изменено
# (at-least-once delivery, отсутствие транзакционности шины событий)
# ----------------------------------------------------------------------

async def test_handler_exception_bubbles_but_state_is_committed():
    _skip_if_unavailable()

    marker = {"raised": False, "second_called": False}

    def bad_handler(table: str, payload):
        marker["raised"] = True
        raise RuntimeError("handler failed")

    def good_handler(table: str, payload):
        marker["second_called"] = True

    async with DataFabricMock.session() as df:  # type: ignore
        schema = TableSchema(
            name="orders",
            primary_key="id",
            columns=(Column("id", int, True), Column("amount", float, True)),
        )
        await df.create_table(schema)

        # ВАЖНО: bad_handler первым — последующие не будут вызваны из-за исключения
        df.bus.on_insert.append(bad_handler)
        df.bus.on_insert.append(good_handler)

        # Операция должна выбросить исключение...
        with pytest.raises(RuntimeError, match="handler failed"):
            await df.insert("orders", [{"id": 10, "amount": 99.0}])

        # ...но данные уже в состоянии (emit вызывается ПОСЛЕ записи в память)
        row = await df.get("orders", 10)
        assert row and row["amount"] == 99.0

        # Проверяем маркеры
        assert marker["raised"] is True
        assert marker["second_called"] is False  # второй не был вызван из-за исключения


# ----------------------------------------------------------------------
# Порядок подписчиков: последовательное выполнение в порядке регистрации
# ----------------------------------------------------------------------

async def test_handlers_called_in_registration_order():
    _skip_if_unavailable()

    order = []

    def h1(table: str, payload): order.append("h1")
    async def h2(table: str, payload): order.append("h2")
    def h3(table: str, payload): order.append("h3")

    async with DataFabricMock.session() as df:  # type: ignore
        schema = TableSchema(
            name="logs",
            primary_key="id",
            columns=(Column("id", int, True), Column("msg", str, True)),
        )
        await df.create_table(schema)

        df.bus.on_update.extend([h1, h2, h3])
        await df.upsert("logs", [{"id": 1, "msg": "x"}])

    assert order == ["h1", "h2", "h3"]


# ----------------------------------------------------------------------
# Stream + события: закрытие стрима не мешает эмиту и последующим операциям
# ----------------------------------------------------------------------

async def test_stream_then_emit_then_stream_close_is_safe():
    _skip_if_unavailable()

    async with DataFabricMock.session() as df:  # type: ignore
        schema = TableSchema(
            name="u",
            primary_key="id",
            columns=(Column("id", int, True), Column("name", str, True)),
        )
        await df.create_table(schema)
        await df.insert("u", [{"id": i, "name": f"n{i}"} for i in range(30)])

        q = Query(filters=[], projection=("id",), order_by=("id", "asc"), limit=30, offset=0)
        agen = df.stream("u", q, batch_size=10)
        first = await agen.__anext__()
        assert len(first) == 10

        # Параллельно апдейт, который вызовет on_update (без подписчиков — no-op)
        await df.upsert("u", [{"id": 1, "name": "nx"}])

        # Корректно закрываем стрим и продолжаем работу
        await agen.aclose()
        got = await df.get("u", 1)
        assert got and got["name"] == "nx"
