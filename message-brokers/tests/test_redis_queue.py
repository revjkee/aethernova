# message-brokers/tests/test_redis_queue.py

import pytest
import threading
import time
from unittest.mock import MagicMock, patch

import redis

from message_brokers.adapters.connection_pool import ConnectionPool, BrokerType


class MockRedisPubSub:
    def __init__(self):
        self._subscribed = {}
        self._messages = []

    def subscribe(self, *channels):
        for ch in channels:
            self._subscribed[ch] = True

    def get_message(self, timeout=0):
        if self._messages:
            return self._messages.pop(0)
        return None

    def publish(self, channel, message):
        if channel in self._subscribed:
            self._messages.append({'type': 'message', 'channel': channel, 'data': message})
            return 1
        return 0

    def close(self):
        self._subscribed.clear()
        self._messages.clear()


class MockRedisClient:
    def __init__(self):
        self._pubsub = MockRedisPubSub()

    def pubsub(self):
        return self._pubsub

    def publish(self, channel, message):
        return self._pubsub.publish(channel, message)

    def close(self):
        pass


@pytest.fixture(scope="function")
def redis_pool_mock():
    pool = ConnectionPool()
    pool.configure("test_redis", BrokerType.REDIS, {"host": "localhost"}, ttl=60)
    with patch("redis.Redis", return_value=MockRedisClient()):
        yield pool


def test_pub_sub_message_delivery(redis_pool_mock):
    conn = redis_pool_mock.get("test_redis")
    pubsub = conn.pubsub()
    pubsub.subscribe("genesis:test")

    # Publish message
    conn.publish("genesis:test", "message_payload")

    # Simulate read
    msg = pubsub.get_message(timeout=1)
    assert msg is not None
    assert msg['type'] == 'message'
    assert msg['channel'] == "genesis:test"
    assert msg['data'] == "message_payload"


def test_pub_sub_timeout_behavior(redis_pool_mock):
    conn = redis_pool_mock.get("test_redis")
    pubsub = conn.pubsub()
    pubsub.subscribe("genesis:timeout")

    msg = pubsub.get_message(timeout=0.1)
    assert msg is None  # no messages should exist


def test_pub_sub_multiple_channels(redis_pool_mock):
    conn = redis_pool_mock.get("test_redis")
    pubsub = conn.pubsub()
    pubsub.subscribe("genesis:one", "genesis:two")

    conn.publish("genesis:two", "two-data")

    msg = pubsub.get_message(timeout=1)
    assert msg['channel'] == "genesis:two"
    assert msg['data'] == "two-data"


def test_redis_failover_trigger(redis_pool_mock):
    # Искусственно провоцируем повторную инициализацию
    conn1 = redis_pool_mock.get("test_redis")
    time.sleep(1.1)  # TTL истекает быстрее для теста
    redis_pool_mock._ttl["test_redis"] = time.time() - 1  # ручной override

    conn2 = redis_pool_mock.get("test_redis")

    # Проверка: соединение обновлено
    assert conn1 is not conn2
