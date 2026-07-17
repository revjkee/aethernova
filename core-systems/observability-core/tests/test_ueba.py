import pytest

from observability_core.ueba import AnomalyDetector, ThreatScorer, UserBehaviorModel


def test_user_behavior_profile_and_threat_score() -> None:
    model = UserBehaviorModel(window_size=3, decay=0.5)
    for value in (10.0, 20.0, 30.0):
        model.update_behavior("user-1", value)

    profile = model.get_profile("user-1")
    assert profile["mean"] == 20.0
    assert profile["std"] > 0

    score = ThreatScorer().score_event(
        "user-1",
        {"weight": 10, "context": {"privileged_account": True}},
    )
    assert score == 25.0


def test_anomaly_detector_calls_alert_callback() -> None:
    alerts: list[tuple[dict, float]] = []
    detector = AnomalyDetector(
        threshold=1.0,
        window_size=5,
        alert_callback=lambda event, z_score: alerts.append((event, z_score)),
    )

    for value in (10, 10, 10, 10):
        assert detector.update({"value": value}) is False

    event = {"value": 100}
    assert detector.update(event) is True
    assert alerts[0][0] == event
    assert alerts[0][1] > 1.0


def test_ueba_configuration_rejects_invalid_ranges() -> None:
    with pytest.raises(ValueError):
        AnomalyDetector(window_size=1)
    with pytest.raises(ValueError):
        ThreatScorer(decay_factor=0)
    with pytest.raises(ValueError):
        UserBehaviorModel(decay=1.1)
