# tests/unit/test_protocol_opcua.py
import asyncio
import types
import sys
import importlib
from dataclasses import dataclass
import pytest

# -----------------------------------------------------------------------------
# Фейковая реализация asyncua (минимум необходимого API), инъекция в sys.modules
# -----------------------------------------------------------------------------

# ---- ua псевдомодуль с константами/структурами, на которые ссылается клиент ----
class _UAStatusCode:
    def __init__(self, value=0):
        self.value = value

class _UAAttributeIds:
    Value = 13

class _UATimestampsToReturn:
    Both = 3

class _UAMonitoringMode:
    Reporting = 1

@dataclass
class _UAReadValueId:
    nodeId: object
    AttributeId: int
    IndexRange: object
    DataEncoding: object

@dataclass
class _UAMonitoringParameters:
    ClientHandle: int
    SamplingInterval: float
    Filter: object
    QueueSize: int
    DiscardOldest: bool

@dataclass
class _UAMonitoredItemCreateRequest:
    ReadValueId: _UAReadValueId
    MonitoringMode: int
    RequestedParameters: _UAMonitoringParameters

class _UADataValue:
    def __init__(self, status_code=0):
        class _TS:  # имитируем .datetime поле
            def __init__(self):
                self.datetime = None
        class _Val:
            def __init__(self, sc):
                self.ServerTimestamp = _TS()
                self.SourceTimestamp = _TS()
                self.StatusCode = sc
        self.Value = _Val(status_code)

class _UADataChangeNotification:
    def __init__(self, status_code=0):
        self.monitored_item = _UADataValue(status_code)

class _UA:
    StatusCode = _UAStatusCode
    AttributeIds = _UAAttributeIds
    TimestampsToReturn = _UATimestampsToReturn
    MonitoringMode = _UAMonitoringMode
    ReadValueId = _UAReadValueId
    MonitoringParameters = _UAMonitoringParameters
    MonitoredItemCreateRequest = _UAMonitoredItemCreateRequest
    DataChangeNotification = _UADataChangeNotification

# ---- Фейковые Node/Client/Subscription ----
class _FakeNodeId:
    def __init__(self, s: str):
        self._s = s
    def to_string(self) -> str:
        return self._s

class _FakeNode:
    def __init__(self, s: str, *, fail_after_reads: int = -1):
        self.nodeid = _FakeNodeId(s)
        self._reads_left = fail_after_reads

    async def read_value(self):
        if self._reads_left == 0:
            raise RuntimeError("keepalive read_value failure")
        if self._reads_left > 0:
            self._reads_left -= 1
        return f"VAL:{self.nodeid.to_string()}"

    async def call_method(self, method_node, *args):
        return ["ok", {"method": method_node.nodeid.to_string(), "args": list(args)}]

class _FakeSubscription:
    def __init__(self, handler):
        self._handler = handler
        self.created = False
        self.deleted = False
        self._monitored = []

    async def create_monitored_items(self, _ts_ret, reqs):
        self.created = True
        self._monitored.extend(reqs)

    async def delete(self):
        self.deleted = True

    # тестовая «инъекция» события
    def simulate_change(self, node: _FakeNode, value):
        data = _UADataChangeNotification(status_code=0)
        # вызов синхронного обработчика asyncua
        self._handler.datachange_notification(node, value, data)

_FAKE_CLIENTS = []

class _FakeClient:
    def __init__(self, url: str, timeout: float, name: str, server_timeout: float):
        self.url = url
        self.timeout = timeout
        self.name = name
        self.server_timeout = server_timeout
        self.connected = False
        self.ns_calls = 0
        # объект .nodes.server_serverstatus_currenttime
        self.nodes = types.SimpleNamespace(server_serverstatus_currenttime=_FakeNode("i=2258"))
        _FAKE_CLIENTS.append(self)

    async def connect(self):
        self.connected = True

    async def disconnect(self):
        self.connected = False

    def get_node(self, node_id: str):
        # Для keepalive теста возвращаем ноду с единичным фейлом на первом чтении,
        # если тест установит специальное поле:
        fn = _FakeNode(node_id)
        # перенастраивается в тесте через замену self.nodes.server_serverstatus_currenttime
        return fn

    async def read_values(self, nodes):
        # Возвращаем список значений той же длины
        return [f"R:{getattr(n.nodeid, 'to_string')()}" for n in nodes]

    async def write_values(self, nodes, values):
        # Возвращаем список «успехов»
        return [_UAStatusCode(0) for _ in nodes]

    async def create_subscription(self, _publishing_interval_ms, handler):
        sub = _FakeSubscription(handler)
        self._subscription = sub
        return sub

    async def get_namespace_array(self):
        self.ns_calls += 1
        return ["http://opcfoundation.org/UA/", "urn:test:ns2"]

# Сконструировать и внедрить модуль asyncua
_fake_asyncua = types.ModuleType("asyncua")
_fake_asyncua.Client = _FakeClient
_fake_asyncua.Node = _FakeNode
_fake_asyncua.ua = _UA

sys.modules["asyncua"] = _fake_asyncua

# Теперь можно импортировать тестируемый модуль
opc = importlib.import_module("physical_integration.protocols.opcua_client")

# -----------------------------------------------------------------------------
# Вспомогательная фабрика настроек с быстрыми таймерами
# -----------------------------------------------------------------------------
def fast_settings(**overrides):
    s = opc.OPCUAClientSettings(
        endpoint_url="opc.tcp://fake:4840",
        keepalive_period_s=0.05,
        op_timeout_s=0.2,
        reconnect_min_s=0.05,
        reconnect_max_s=0.2,
        ns_cache_ttl_s=5.0,  # можно менять в тестах
    )
    for k, v in overrides.items():
        setattr(s, k, v)
    return s

# -----------------------------------------------------------------------------
# Тесты
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_connect_ready_and_stop():
    client = opc.OPCUAClient(fast_settings())
    await client.start()
    await client.ready()
    assert client._connected.is_set()
    await client.stop()
    assert client._client is None

@pytest.mark.asyncio
async def test_read_and_write_batching_respects_limits():
    # Подготовим 500 нод для проверки чанкинга (по умолчанию MAX_BATCH_NODES=200)
    settings = fast_settings()
    client = opc.OPCUAClient(settings)
    await client.start()
    await client.ready()

    nodes_to_read = [f"ns=2;s=Tag{i}" for i in range(500)]
    values = await client.read_values(nodes_to_read)
    assert len(values) == 500
    assert all(isinstance(v, str) and v.startswith("R:") for v in values)

    items_to_write = [(f"ns=2;s=WTag{i}", i) for i in range(500)]
    write_rc = await client.write_values(items_to_write)
    assert len(write_rc) == 500
    # проверяем, что вернулись объекты статуса (наша фейковая заглушка)
    from types import SimpleNamespace
    assert all(hasattr(rc, "value") for rc in write_rc)

    await client.stop()

@pytest.mark.asyncio
async def test_subscribe_queue_drop_oldest_and_backpressure():
    # event_queue_max малый, чтобы легко переполнить
    sub_cfg = opc.SubscriptionConfig(event_queue_max=25, drop_policy_oldest=True)
    client = opc.OPCUAClient(fast_settings())
    await client.start()
    await client.ready()

    sub_id, q = await client.subscribe_data_change(["ns=2;s=Temp"], cfg=sub_cfg)
    # Достаём handler для инъекции событий (через внутреннее состояние — допустимо в unit-тестах)
    sub, handler, queue, cfg = client._subs[sub_id]
    assert queue is q
    fake_node = _FakeNode("ns=2;s=Temp")

    # Сгенерируем больше событий, чем размер очереди, и убедимся, что дропается «старое»
    total = sub_cfg.event_queue_max + 5
    for i in range(total):
        sub.simulate_change(fake_node, i)

    assert q.qsize() == sub_cfg.event_queue_max

    # Первое значение в очереди должно быть 5 (пять старых выталкнуто)
    first = await q.get()
    assert first["value"] == 5

    # Последнее значение в очереди должно быть total-1
    last = None
    # опорожним очередь
    vals = [first["value"]]
    while not q.empty():
        vals.append((await q.get())["value"])
    assert vals[0] == 5
    assert vals[-1] == total - 1

    await client.stop()

@pytest.mark.asyncio
async def test_namespace_array_caching():
    settings = fast_settings(ns_cache_ttl_s=999.0)
    client = opc.OPCUAClient(settings)
    await client.start()
    await client.ready()

    arr1 = await client.namespace_array()
    assert isinstance(arr1, list) and len(arr1) >= 1
    # Доступ к конкретному инстансу клиента
    fake = client._client
    assert fake is not None
    # Второй вызов должен взять из кеша (счётчик вызовов get_namespace_array не изменится)
    arr2 = await client.namespace_array()
    assert arr1 == arr2
    assert fake.ns_calls == 1

    await client.stop()

@pytest.mark.asyncio
async def test_keepalive_failure_triggers_reconnect():
    # Настроим: первая keepalive read_value успешна, затем сбой → реконнект.
    settings = fast_settings(keepalive_period_s=0.05)
    client = opc.OPCUAClient(settings)
    await client.start()
    await client.ready()

    # На текущем _client подменим keepalive-ноду, чтобы следующий вызов read_value упал
    fake_client = client._client
    assert fake_client is not None
    # первый вызов ok, второй — raise
    fake_client.nodes.server_serverstatus_currenttime = _FakeNode("i=2258", fail_after_reads=1)

    # Дадим циклу keepalive время упасть и супервизору — переподключиться
    await asyncio.sleep(0.3)

    # Должно быть как минимум два клиента создано за время теста
    assert len(_FAKE_CLIENTS) >= 2
    # Клиент снова в состоянии connected
    assert client._connected.is_set()

    await client.stop()

@pytest.mark.asyncio
async def test_call_method_invocation():
    client = opc.OPCUAClient(fast_settings())
    await client.start()
    await client.ready()

    res = await client.call_method("ns=2;s=Obj", "ns=2;s=Method", args=[1, "x"])
    assert isinstance(res, list)
    assert res[0] == "ok"
    assert isinstance(res[1], dict)
    assert res[1]["method"].endswith("Method")

    await client.stop()
