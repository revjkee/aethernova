import pytest
from llmops.storage.db_client import DBClient
from llmops.cache.redis_client import RedisCache
from llmops.queue.task_queue import TaskQueueClient
from llmops.utils.healthcheck import ping_service
from llmops.security.connection_guard import secure_connection_check
from llmops.audit.logger import audit_event
from llmops.meta.trace_id import generate_trace_id

@pytest.fixture(scope="module")
def db():
    client = DBClient()
    client.connect()
    yield client
    client.disconnect()

@pytest.fixture(scope="module")
def cache():
    cache = RedisCache()
    cache.connect()
    yield cache
    cache.disconnect()

@pytest.fixture(scope="module")
def queue():
    q = TaskQueueClient()
    q.connect()
    yield q
    q.disconnect()

def test_db_connection_health(db):
    assert db.is_connected()
    assert ping_service(db) is True
    assert secure_connection_check(db.dsn) is True
    trace_id = generate_trace_id()
    audit_event("db_connection_success", {"trace_id": trace_id, "dsn": db.dsn})

def test_cache_connection_health(cache):
    assert cache.is_connected()
    assert ping_service(cache) is True
    key = "test_key"
    value = "test_value"

    cache.set(key, value, ttl=30)
    result = cache.get(key)
    assert result == value

    audit_event("cache_test_passed", {"key": key, "result": result})

def test_queue_connection_health(queue):
    assert queue.is_connected()
    assert ping_service(queue) is True

    task = {"type": "test", "payload": {"msg": "Hello"}}
    queue.publish(task)
    received = queue.consume()

    assert received["type"] == "test"
    assert received["payload"]["msg"] == "Hello"

    audit_event("queue_message_verified", {"task": task})

def test_storage_reconnect_on_failure():
    client = DBClient()
    client.connect()
    client.simulate_disconnect()
    assert client.reconnect() is True
    assert client.is_connected()
    audit_event("db_auto_reconnect_passed", {"dsn": client.dsn})
