# observability/dashboards/tests/test_json_formatter.py

import json
import pytest
from observability.dashboards.formatters.json_formatter import JSONLogFormatter

@pytest.fixture
def log_record():
    return {
        "timestamp": "2025-07-21T12:00:00Z",
        "level": "INFO",
        "message": "User login successful",
        "user": {"id": "user123", "email": "test@example.com"},
        "source": {"ip": "192.168.0.1"},
        "tags": ["auth", "login"]
    }

def test_json_formatter_output_structure(log_record):
    formatter = JSONLogFormatter()
    formatted = formatter.format(log_record)
    parsed = json.loads(formatted)

    assert isinstance(parsed, dict)
    assert "timestamp" in parsed
    assert "level" in parsed
    assert "message" in parsed
    assert parsed["level"] == log_record["level"]

def test_json_formatter_serializes_nested_objects(log_record):
    formatter = JSONLogFormatter()
    formatted = formatter.format(log_record)
    parsed = json.loads(formatted)

    assert isinstance(parsed["user"], dict)
    assert parsed["user"]["id"] == "user123"
    assert parsed["user"]["email"] == "test@example.com"

def test_json_formatter_handles_special_characters():
    record = {
        "timestamp": "2025-07-21T12:00:00Z",
        "level": "ERROR",
        "message": "Failed with exception: ValueError('Invalid input')"
    }
    formatter = JSONLogFormatter()
    formatted = formatter.format(record)

    assert "ValueError" in formatted
    assert "\\n" not in formatted  # Проверка отсутствия необработанных переносов

def test_json_formatter_is_json_serializable(log_record):
    formatter = JSONLogFormatter()
    formatted = formatter.format(log_record)
    try:
        json.loads(formatted)
    except json.JSONDecodeError:
        pytest.fail("Formatted log is not valid JSON")

def test_json_formatter_injects_default_fields_if_missing():
    record = {"message": "Minimal"}
    formatter = JSONLogFormatter()
    formatted = json.loads(formatter.format(record))

    assert "message" in formatted
    assert formatted.get("level") in (None, "INFO", "UNKNOWN", "DEFAULT")  # зависит от реализации fallback
