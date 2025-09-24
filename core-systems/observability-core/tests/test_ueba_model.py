# observability/dashboards/tests/test_ueba_model.py

import pytest
from dashboards.siem.ueba_model import UEBAEngine, AnomalyScore


@pytest.fixture
def ueba_engine():
    return UEBAEngine(threshold=0.7)


def test_engine_detects_anomaly(ueba_engine):
    event = {
        "user": "alice",
        "action": "ssh_login",
        "location": "RU",
        "time": "03:12",
        "device": "new_laptop"
    }

    score = ueba_engine.score_event(event)
    assert isinstance(score, AnomalyScore)
    assert 0.0 <= score.value <= 1.0


def test_engine_triggers_alert_on_high_anomaly(ueba_engine):
    event = {
        "user": "admin",
        "action": "disable_logs",
        "location": "unknown",
        "device": "unrecognized_device",
        "time": "02:00"
    }

    score = ueba_engine.score_event(event)
    decision = ueba_engine.is_anomalous(score)
    assert decision is True


def test_engine_does_not_trigger_on_normal_event(ueba_engine):
    event = {
        "user": "bob",
        "action": "view_logs",
        "location": "US",
        "device": "known_pc",
        "time": "09:30"
    }

    score = ueba_engine.score_event(event)
    assert not ueba_engine.is_anomalous(score)


def test_engine_handles_missing_fields(ueba_engine):
    event = {
        "user": "charlie",
        "action": "download_report"
        # Missing location, time, device
    }

    score = ueba_engine.score_event(event)
    assert isinstance(score, AnomalyScore)
    assert score.value < 0.5
