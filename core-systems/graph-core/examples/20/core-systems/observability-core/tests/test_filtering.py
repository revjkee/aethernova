# observability/dashboards/tests/test_filtering.py

import pytest
from observability.dashboards.filters.noise_filter import NoiseFilter
from observability.dashboards.filters.pii_filter import PIIFilter
from observability.dashboards.filters.honeypot_filter import HoneypotFilter
from observability.dashboards.filters.severity_filter import SeverityFilter
from observability.dashboards.filters.security_event_filter import SecurityEventFilter

@pytest.fixture
def base_event():
    return {
        "message": "User admin logged in",
        "severity": "INFO",
        "user": {
            "id": "admin",
            "email": "admin@example.com"
        },
        "source": {
            "ip": "192.168.1.1"
        },
        "tags": []
    }

def test_noise_filter_removes_known_noise(base_event):
    noisy_event = base_event.copy()
    noisy_event["message"] = "Keep-alive ping from agent"
    assert NoiseFilter().filter(noisy_event) is None

def test_pii_filter_removes_email(base_event):
    filtered = PIIFilter().filter(base_event)
    assert "email" not in filtered.get("user", {})

def test_honeypot_filter_blocks_honeypot_ip(base_event):
    event = base_event.copy()
    event["source"]["ip"] = "10.10.10.10"  # Предположим, это honeypot
    assert HoneypotFilter().filter(event) is None

def test_severity_filter_drops_low_severity(base_event):
    event = base_event.copy()
    event["severity"] = "DEBUG"
    assert SeverityFilter(min_severity="INFO").filter(event) is None

def test_security_event_filter_passes_only_security_events(base_event):
    event = base_event.copy()
    event["tags"].append("security")
    assert SecurityEventFilter().filter(event) is not None

    event["tags"].remove("security")
    assert SecurityEventFilter().filter(event) is None
