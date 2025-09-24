# message-brokers/tests/test_kafka_flow.py

import pytest
import time
from unittest.mock import MagicMock, patch

from message_brokers.internal_events.event_schema import BaseInternalEvent, EventType, EventContext
from message_brokers.adapters.connection_pool import ConnectionPool, BrokerType
from message_brokers.adapters.secure_middleware import SecureMiddleware, MiddlewareSettings, SecureMessage
from message_brokers.internal_events.audit_logger import AuditLogger, AuditEvent, SeverityLevel
from message_brokers.tests.utils.kafka_mock import FakeKafkaProducer, FakeKafkaConsumer

TEST_HMAC_SECRET = "test_secret_key"

@pytest.fixture(scope="function")
def mock_kafka_environment():
    with patch("kafka.KafkaProducer", new=FakeKafkaProducer), \
         patch("kafka.KafkaConsumer", new=FakeKafkaConsumer):
        yield


@pytest.fixture(scope="function")
def secure_middleware():
    settings = MiddlewareSettings(
        hmac_secret=TEST_HMAC_SECRET,
        allowed_roles=["admin", "ai-core"],
        gpg_required=False,  # отключено для тестов
        trace_enabled=True
    )
    return SecureMiddleware(settings)


@pytest.fixture(scope="function")
def test_event():
    return BaseInternalEvent(
        type=EventType.SCAN,
        context=EventContext(
            actor_id="test-agent",
            actor_role="ai-core",
            ip_address="127.0.0.1"
        ),
        payload={"targets": ["10.0.0.1"], "profile": "fast_scan"},
        criticality="high"
    )


def test_kafka_event_flow_end_to_end(mock_kafka_environment, secure_middleware, test_event):
    # Подготовка события
    test_event.sign(TEST_HMAC_SECRET)
    secure_message = SecureMessage(
        message_id=test_event.event_id,
        timestamp=test_event.timestamp,
        sender_id=test_event.context.actor_id,
        role=test_event.context.actor_role,
        payload=test_event.payload,
        hmac_signature=test_event.signature,
        gpg_signature=None
    )

    # Mock Alert handler
    alert_handler = MagicMock()

    # Пропуск через middleware
    secure_middleware.process(secure_message, callback=alert_handler)

    # Проверка: alert вызван
    alert_handler.assert_called_once()
    assert "targets" in alert_handler.call_args[0][0]
    assert alert_handler.call_args[0][0]["targets"] == ["10.0.0.1"]


def test_event_rejected_if_untrusted_role(secure_middleware, test_event):
    test_event.context.actor_role = "guest"
    test_event.sign(TEST_HMAC_SECRET)
    msg = SecureMessage(
        message_id=test_event.event_id,
        timestamp=test_event.timestamp,
        sender_id=test_event.context.actor_id,
        role="guest",
        payload=test_event.payload,
        hmac_signature=test_event.signature,
        gpg_signature=None
    )

    callback = MagicMock()
    secure_middleware.process(msg, callback)
    callback.assert_not_called()


def test_event_dropped_on_expired_timestamp(secure_middleware, test_event):
    test_event.timestamp = time.time() - 1000  # явно просрочено
    test_event.sign(TEST_HMAC_SECRET)
    msg = SecureMessage(
        message_id=test_event.event_id,
        timestamp=test_event.timestamp,
        sender_id=test_event.context.actor_id,
        role=test_event.context.actor_role,
        payload=test_event.payload,
        hmac_signature=test_event.signature,
        gpg_signature=None
    )

    callback = MagicMock()
    secure_middleware.process(msg, callback)
    callback.assert_not_called()


def test_signature_verification_failure(secure_middleware, test_event):
    msg = SecureMessage(
        message_id="wrong-id",
        timestamp=test_event.timestamp,
        sender_id=test_event.context.actor_id,
        role=test_event.context.actor_role,
        payload=test_event.payload,
        hmac_signature="invalid_signature",
        gpg_signature=None
    )

    callback = MagicMock()
    secure_middleware.process(msg, callback)
    callback.assert_not_called()
