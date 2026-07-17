from observability_core.filters import (
    HoneypotFilter,
    NoiseFilter,
    PIIFilter,
    SecurityEventFilter,
    SeverityFilter,
)


def test_noise_honeypot_severity_and_security_filters() -> None:
    assert NoiseFilter().filter({"message": "Prometheus scrape completed"}) is None
    assert HoneypotFilter().filter({"url": "/.env", "headers": {}}) is None
    assert SeverityFilter("warning").filter({"severity": "INFO"}) is None

    security = SecurityEventFilter().filter(
        {"security_tag": "privilege_escalation", "source": "auth_service"}
    )
    assert security is not None
    assert security["threat_level"] == "critical"
    assert security["critical_source"] is True


def test_pii_filter_redacts_nested_values_without_retaining_secrets() -> None:
    pii_filter = PIIFilter()
    result = pii_filter.filter(
        {
            "message": "Contact admin@example.com",
            "nested": {"token": "eyJabc.def.ghi"},
        }
    )

    assert "admin@example.com" not in str(result)
    assert "eyJabc.def.ghi" not in str(result)
    assert result["pii_masked"] is True
    assert pii_filter.get_redacted() == ["message", "nested.token"]

    clean = pii_filter.filter({"message": "no personal data"})
    assert clean["pii_masked"] is False
    assert pii_filter.get_redacted() == []
