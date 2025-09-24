# observability/dashboards/tests/test_stdout_handler.py

import pytest
import sys
from io import StringIO
from unittest.mock import patch
from dashboards.handlers.stdout_handler import StdoutHandler


@pytest.fixture
def stdout_handler():
    return StdoutHandler()


def test_stdout_handler_initialization(stdout_handler):
    assert stdout_handler.stream == sys.stdout
    assert callable(getattr(stdout_handler, "emit", None))


def test_stdout_handler_emit_writes_to_stdout(stdout_handler):
    test_record = type("LogRecord", (object,), {"message": "Test Message"})()
    fake_stdout = StringIO()

    with patch("sys.stdout", fake_stdout):
        stdout_handler.stream = sys.stdout
        stdout_handler.emit(test_record)

    assert "Test Message" in fake_stdout.getvalue()


def test_stdout_handler_emit_handles_missing_message_gracefully(stdout_handler):
    test_record = type("LogRecord", (object,), {})()  # no message attr
    fake_stdout = StringIO()

    with patch("sys.stdout", fake_stdout):
        stdout_handler.stream = sys.stdout
        stdout_handler.emit(test_record)

    output = fake_stdout.getvalue()
    assert "object" in output or "LogRecord" in output  # fallback to repr()


def test_stdout_handler_fallback_on_exception(stdout_handler):
    broken_record = None  # emit will raise
    fake_stdout = StringIO()

    with patch("sys.stdout", fake_stdout):
        stdout_handler.stream = sys.stdout
        stdout_handler.emit(broken_record)

    assert "Exception during emit" in fake_stdout.getvalue()
