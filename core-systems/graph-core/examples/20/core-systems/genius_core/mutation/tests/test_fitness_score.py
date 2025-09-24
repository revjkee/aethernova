# test_fitness_score.py

import pytest
from genius_core.mutation.fitness_score import FitnessScorer


@pytest.fixture
def base_config():
    return {
        "learning_rate": 0.001,
        "dropout": 0.2,
        "num_layers": 4,
        "batch_size": 128,
        "activation": "relu",
        "optimizer": "adam",
        "hidden_dim": 512
    }


def test_fitness_with_valid_config(base_config):
    scorer = FitnessScorer()
    score = scorer.evaluate(base_config)
    assert 0.0 <= score <= 1.0, f"Fitness вне допустимого диапазона: {score}"


def test_accuracy_impact_on_layers():
    scorer = FitnessScorer()
    low_layer = {"num_layers": 2, "optimizer": "adamw", "dropout": 0.2}
    high_layer = {"num_layers": 8, "optimizer": "adamw", "dropout": 0.2}
    acc_low = scorer._default_accuracy(low_layer)
    acc_high = scorer._default_accuracy(high_layer)
    assert acc_high > acc_low, "Точность не увеличивается с увеличением num_layers"


def test_dropout_penalty_behavior():
    scorer = FitnessScorer()
    ideal = {"dropout": 0.2}
    off = {"dropout": 0.5}
    acc_ideal = scorer._default_accuracy(ideal)
    acc_penalized = scorer._default_accuracy(off)
    assert acc_ideal > acc_penalized, "Penalty за dropout не работает корректно"


def test_latency_penalty_scaling():
    scorer = FitnessScorer()
    fast = {"batch_size": 32, "hidden_dim": 128}
    slow = {"batch_size": 512, "hidden_dim": 1024}
    fast_penalty = scorer._default_latency_penalty(fast)
    slow_penalty = scorer._default_latency_penalty(slow)
    assert fast_penalty > slow_penalty, "Неверное масштабирование latency penalty"


def test_memory_penalty_limits():
    scorer = FitnessScorer()
    small = {"num_layers": 2, "hidden_dim": 64}
    large = {"num_layers": 10, "hidden_dim": 2048}
    mem_small = scorer._default_memory_penalty(small)
    mem_large = scorer._default_memory_penalty(large)
    assert mem_small > mem_large, "Пенальти за память работает неверно"


def test_stability_curve():
    scorer = FitnessScorer()
    ideal = {"learning_rate": 0.001}
    bad = {"learning_rate": 0.02}
    stab_ideal = scorer._default_stability(ideal)
    stab_bad = scorer._default_stability(bad)
    assert stab_ideal > stab_bad, "Stability penalty не распознаёт отклонения"


def test_override_metric_behavior(base_config):
    scorer = FitnessScorer()
    scorer.override_metric("accuracy", lambda x: 0.777)
    result = scorer.evaluate(base_config)
    assert abs(result - scorer.weights["accuracy"] * 0.777) < 0.1, "Override не применяется корректно"


def test_fitness_score_edge_cases():
    scorer = FitnessScorer()
    broken_config = {}
    score = scorer.evaluate(broken_config)
    assert score >= 0.0, "Пустой конфиг вызвал сбой в fitness"
