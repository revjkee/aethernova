# observability/dashboards/tests/test_ecs_formatter.py

import logging
import json
from io import StringIO
from observability.dashboards.formatters.json_formatter import ECSJsonFormatter

def test_ecs_formatter_outputs_valid_json():
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    formatter = ECSJsonFormatter(service_name="test-service", environment="test-env")
    handler.setFormatter(formatter)

    logger = logging.getLogger("ecs-test-logger")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)

    logger.info("Test ECS message", extra={"user_id": "123", "request_id": "abc-xyz"})

    stream.seek(0)
    output = stream.read()

    try:
        parsed = json.loads(output)
    except json.JSONDecodeError:
        assert False, "Output is not valid JSON"

    assert parsed.get("message") == "Test ECS message"
    assert parsed.get("log", {}).get("level") == "INFO"
    assert parsed.get("service", {}).get("name") == "test-service"
    assert parsed.get("user", {}).get("id") == "123"
    assert parsed.get("labels", {}).get("request_id") == "abc-xyz"
    assert parsed.get("environment") == "test-env"
