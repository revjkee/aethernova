# message-brokers/tests/test_secure_publish.py

import time
import pytest
from unittest.mock import MagicMock

from message_brokers.adapters.secure_middleware import SecureMiddleware, MiddlewareSettings, SecureMessage
from message_brokers.internal_events.event_schema import EventContext, BaseInternalEvent, EventType
from message_brokers.internal_events.audit_logger import AuditLogger, AuditEvent, SeverityLevel


TEST_HMAC_SECRET = "secure_test_key"

@pytest.fixture(scope="function")
def secure_middleware():
    settings = MiddlewareSettings(
        hmac_secret=TEST_HMAC_SECRET,
        allowed_roles=["admin", "ai-core"],
        gpg_required=False,
        trace_enabled=True,
        replay_protection=True,
        max_delay_sec=60
    )
    return SecureMiddleware(settings)


@pytest.fixture(scope="function")
def valid_event():
    event = BaseInternalEvent(
        type=EventType.LOGIN,
        context=EventContext(
            actor_id="ai-unit-7",
            actor_role="ai-core",
            ip_address="10.0.0.77"
        ),
        payload={"method": "key", "success": True, "target_user": "system-admin"},
        criticality="high"
    )
    event.sign(TEST_HMAC_SECRET)
    return event


def test_valid_signature_allows_processing(secure_middleware, valid_event):
    msg = SecureMessage(
        message_id=valid_event.event_id,
        timestamp=valid_event.timestamp,
        sender_id=valid_event.context.actor_id,
        role=valid_event.context.actor_role,
        payload=valid_event.payload,
        hmac_signature=valid_event.signature,
        gpg_signature=None
    )

    callback = MagicMock()
    secure_middleware.process(msg, callback)
    callback.assert_called_once()
    assert callback.call_args[0][0]["target_user"] == "system-admin"


def test_invalid_hmac_blocks_message(secure_middleware, valid_event):
    msg = SecureMessage(
        message_id=valid_event.event_id,
        timestamp=valid_event.timestamp,
        sender_id=valid_event.context.actor_id,
        role=valid_event.context.actor_role,
        payload=valid_event.payload,
        hmac_signature="wrong_signature",
        gpg_signature=None
    )

    callback = MagicMock()
    secure_middleware.process(msg, callback)
    callback.assert_not_called()


def test_untrusted_role_rejected(secure_middleware, valid_event):
    msg = SecureMessage(
        message_id=valid_event.event_id,
        timestamp=valid_event.timestamp,
        sender_id=valid_event.context.actor_id,
        role="guest",  # неразрешённая роль
        payload=valid_event.payload,
        hmac_signature=valid_event.signature,
        gpg_signature=None
    )

    callback = MagicMock()
    secure_middleware.process(msg, callback)
    callback.assert_not_called()


def test_replay_protection_blocks_duplicate(secure_middleware, valid_event):
    msg = SecureMessage(
        message_id=valid_event.event_id,
        timestamp=valid_event.timestamp,
        sender_id=valid_event.context.actor_id,
        role=valid_event.context.actor_role,
        payload=valid_event.payload,
        hmac_signature=valid_event.signature,
        gpg_signature=None
    )

    callback = MagicMock()
    secure_middleware.process(msg, callback)
    secure_middleware.process(msg, callback)  # Повтор — должен быть заблокирован

    assert callback.call_count == 1


def test_expired_message_is_ignored(secure_middleware, valid_event):
    valid_event.timestamp = time.time() - 999  # просрочено
    valid_event.sign(TEST_HMAC_SECRET)

    msg = SecureMessage(
        message_id=valid_event.event_id,
        timestamp=valid_event.timestamp,
        sender_id=valid_event.context.actor_id,
        role=valid_event.context.actor_role,
        payload=valid_event.payload,
        hmac_signature=valid_event.signature,
        gpg_signature=None
    )

    callback = MagicMock()
    secure_middleware.process(msg, callback)
    callback.assert_not_called()
