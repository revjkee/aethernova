import json
import logging

from observability_core.ecs import ECSFormatter
from observability_core.formatters import JSONFormatter
from observability_core.middlewares import ContextInjector, clear_context, set_context


def make_record(message: str = "event") -> logging.LogRecord:
    return logging.LogRecord(
        name="observability.tests",
        level=logging.INFO,
        pathname=__file__,
        lineno=12,
        msg=message,
        args=(),
        exc_info=None,
    )


def test_context_injector_adds_and_clears_context() -> None:
    record = make_record()
    set_context(trace_id="trace-1", user_id="user-1", environment="test")
    try:
        assert ContextInjector().filter(record) is True
        assert record.trace_id == "trace-1"
        assert record.user_id == "user-1"
        assert record.environment == "test"
    finally:
        clear_context()


def test_json_and_ecs_formatters_emit_valid_structured_logs() -> None:
    record = make_record("structured event")
    record.user_id = "user-1"
    record.trace_id = "trace-1"

    generic = json.loads(JSONFormatter().format(record))
    ecs = json.loads(ECSFormatter("observability-core", "test").format(record))

    assert generic["message"] == "structured event"
    assert generic["trace_id"] == "trace-1"
    assert ecs["log.level"] == "info"
    assert ecs["service"]["name"] == "observability-core"
    assert ecs["service"]["environment"] == "test"
    assert ecs["user"]["id"] == "user-1"
