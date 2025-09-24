# observability/dashboards/tests/test_siem_router.py

import pytest
from unittest.mock import MagicMock, patch
from dashboards.handlers import siem_router


@pytest.fixture
def mock_handlers():
    handler_a = MagicMock(name="handler_a")
    handler_b = MagicMock(name="handler_b")
    return {
        "threat_intel": handler_a,
        "compliance": handler_b
    }


def test_siem_routing_dispatch(mock_handlers):
    event = {"type": "threat_intel", "message": "Suspicious activity"}
    with patch.object(siem_router, "SIEM_HANDLERS", mock_handlers):
        siem_router.route_event(event)
        mock_handlers["threat_intel"].handle.assert_called_once_with(event)
        mock_handlers["compliance"].handle.assert_not_called()


def test_siem_routing_dispatch_to_fallback_if_unknown(mock_handlers):
    event = {"type": "unknown_event", "message": "Something weird"}

    fallback_handler = MagicMock(name="fallback")
    with patch.object(siem_router, "SIEM_HANDLERS", mock_handlers), \
         patch.object(siem_router, "fallback_handler", fallback_handler):
        siem_router.route_event(event)
        fallback_handler.handle.assert_called_once_with(event)


def test_event_type_key_absent_fallback(mock_handlers):
    event = {"message": "No type key in event"}

    fallback_handler = MagicMock(name="fallback")
    with patch.object(siem_router, "SIEM_HANDLERS", mock_handlers), \
         patch.object(siem_router, "fallback_handler", fallback_handler):
        siem_router.route_event(event)
        fallback_handler.handle.assert_called_once_with(event)


def test_handler_exception_logged(monkeypatch):
    # simulate handler raising an exception
    class FailingHandler:
        def handle(self, event):
            raise ValueError("Failure during event handling")

    event = {"type": "threat_intel", "message": "Something bad"}
    logger = MagicMock()
    monkeypatch.setattr(siem_router, "SIEM_HANDLERS", {"threat_intel": FailingHandler()})
    monkeypatch.setattr(siem_router, "logger", logger)

    siem_router.route_event(event)

    assert logger.exception.called
    assert "Failed to route event" in logger.exception.call_args[0][0]
