import pytest
from agent_mash.trading_agent.analytics.signal_quality_analyzer import SignalQualityAnalyzer, Signal

@pytest.fixture
def mock_signals():
    return [
        Signal(action="buy", confidence=0.91, meta={"source": "EMA"}),
        Signal(action="sell", confidence=0.82, meta={"source": "MACD"}),
        Signal(action="hold", confidence=0.45, meta={"source": "RSI"}),
        Signal(action="buy", confidence=0.12, meta={"source": "noise"})
    ]

@pytest.fixture
def analyzer():
    return SignalQualityAnalyzer(thresholds={"low": 0.2, "high": 0.8}, weights={"buy": 1.5, "sell": 1.2, "hold": 1.0})

def test_calculate_quality_score_structure(analyzer, mock_signals):
    result = analyzer.calculate_quality_score(mock_signals)
    assert isinstance(result, dict)
    assert "average_confidence" in result
    assert "weighted_score" in result
    assert "distribution" in result

def test_confidence_distribution_sum_to_one(analyzer, mock_signals):
    result = analyzer.calculate_quality_score(mock_signals)
    total_dist = sum(result["distribution"].values())
    assert pytest.approx(total_dist, 0.01) == 1.0

def test_empty_signals_returns_zero(analyzer):
    result = analyzer.calculate_quality_score([])
    assert result["average_confidence"] == 0.0
    assert result["weighted_score"] == 0.0
    assert result["distribution"] == {"buy": 0.0, "sell": 0.0, "hold": 0.0}

@pytest.mark.parametrize("conf,expected", [
    (0.91, "high"),
    (0.81, "high"),
    (0.51, "medium"),
    (0.21, "medium"),
    (0.19, "low"),
    (0.01, "low"),
])
def test_confidence_bucket_mapping(conf, expected):
    analyzer = SignalQualityAnalyzer()
    category = analyzer.map_confidence_to_bucket(conf)
    assert category == expected

def test_extreme_signal_handling():
    analyzer = SignalQualityAnalyzer()
    signals = [Signal("buy", confidence=1e6, meta={})]  # абсурдное значение
    result = analyzer.calculate_quality_score(signals)
    assert result["average_confidence"] <= 1.0  # должны быть ограничены

def test_negative_confidence_signal_handling():
    analyzer = SignalQualityAnalyzer()
    signals = [Signal("sell", confidence=-0.5, meta={})]
    result = analyzer.calculate_quality_score(signals)
    assert result["average_confidence"] >= 0.0  # отсечение снизу
