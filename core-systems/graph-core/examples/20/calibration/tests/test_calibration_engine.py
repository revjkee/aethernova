import pytest
from calibration.metrics.calibration_stats import CalibrationStats, TrendDirection

@pytest.fixture
def stats():
    return CalibrationStats()

def test_initial_update_with_target(stats):
    result = stats.update(new_value=1.0, target_value=1.0)
    assert result.accuracy == 1.0
    assert result.delta == 0.0
    assert result.trend == TrendDirection.STABLE

def test_multiple_updates_generate_trend(stats):
    values = [1.0, 0.8, 0.6, 0.5, 0.3]
    for val in values:
        result = stats.update(new_value=val, target_value=0.0)
    
    assert result.trend == TrendDirection.IMPROVING
    assert result.accuracy > 0.0
    assert result.deviation > 0.0
    assert 0.0 <= result.stability_score <= 1.0

def test_trend_deteriorating(stats):
    values = [0.3, 0.5, 0.7, 0.9]
    for val in values:
        result = stats.update(new_value=val, target_value=0.0)

    assert result.trend == TrendDirection.DETERIORATING
    assert result.delta > 0

def test_trend_stable(stats):
    values = [1.0, 1.0, 1.0, 1.0]
    for val in values:
        result = stats.update(new_value=val, target_value=1.0)

    assert result.trend == TrendDirection.STABLE
    assert result.deviation == 0.0
    assert result.signal_entropy == 0.0

def test_entropy_nonzero_on_variation(stats):
    values = [0.1, 0.2, 0.3, 0.4]
    for val in values:
        result = stats.update(new_value=val, target_value=0.0)

    assert result.signal_entropy > 0.0

def test_large_history_limit(stats):
    for i in range(150):
        stats.update(new_value=i * 0.1, target_value=0.0)

    assert len(stats.history) == stats.max_history_size
    assert stats.history[-1] > stats.history[0]

def test_reset_function(stats):
    stats.update(1.0)
    stats.update(2.0)
    stats.reset()

    assert stats.history == []

def test_accuracy_edge_case_div_by_zero(stats):
    stats.update(new_value=0.0, target_value=0.0)
    result = stats.update(new_value=0.0, target_value=0.0)

    assert result.accuracy == 1.0

def test_improvement_rate_logic(stats):
    values = [1.0, 0.9, 0.8, 0.7, 0.6]
    for val in values:
        result = stats.update(new_value=val)

    assert result.improvement_rate > 0.0
