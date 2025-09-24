# observability/dashboards/tests/test_sentry_integration.py

import pytest
import sentry_sdk
from sentry_sdk.transport import Transport
from sentry_sdk.integrations.logging import LoggingIntegration
import logging

class DummyTransport(Transport):
    def __init__(self, options):
        self.events = []

    def capture_event(self, event):
        self.events.append(event)

@pytest.fixture
def dummy_sentry_transport(monkeypatch):
    transport = DummyTransport({})
    monkeypatch.setattr("sentry_sdk.transport.HttpTransport", lambda options: transport)
    return transport

@pytest.fixture(autouse=True)
def setup_sentry(dummy_sentry_transport):
    sentry_sdk.init(
        dsn="http://public@sentry.local/1",
        transport=dummy_sentry_transport,
        integrations=[LoggingIntegration(level=logging.INFO, event_level=logging.ERROR)]
    )
    yield
    sentry_sdk.flush()

def test_exception_captured_by_sentry(dummy_sentry_transport):
    try:
        raise ValueError("test error")
    except Exception as e:
        sentry_sdk.capture_exception(e)

    assert len(dummy_sentry_transport.events) == 1
    assert dummy_sentry_transport.events[0]["exception"]["values"][0]["type"] == "ValueError"
    assert "test error" in dummy_sentry_transport.events[0]["exception"]["values"][0]["value"]

def test_message_captured_by_sentry(dummy_sentry_transport):
    sentry_sdk.capture_message("Sentry integration message test")

    assert len(dummy_sentry_transport.events) == 1
    assert dummy_sentry_transport.events[0]["message"] == "Sentry integration message test"

def test_logging_event_redirected_to_sentry(dummy_sentry_transport):
    logger = logging.getLogger("sentry_test_logger")
    logger.setLevel(logging.INFO)
    logger.addHandler(logging.StreamHandler())

    logger.error("Test logging error")

    assert len(dummy_sentry_transport.events) == 1
    event = dummy_sentry_transport.events[0]
    assert "logentry" in event
    assert event["logentry"]["message"] == "Test logging error"
