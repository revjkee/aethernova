# test_mutation_engine.py

import pytest
import copy

from genius_core.mutation.mutation_engine import MUTATION_RULES


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


def test_mutation_rule_keys_exist(base_config):
    for param in base_config.keys():
        assert param in MUTATION_RULES, f"Мутационное правило не определено для: {param}"


def test_mutation_output_types(base_config):
    for key, mutate_fn in MUTATION_RULES.items():
        original = base_config.get(key)
        mutated = mutate_fn(copy.deepcopy(original))
        assert isinstance(mutated, type(original)), f"Тип изменился: {key} | {type(original)} → {type(mutated)}"


def test_learning_rate_range():
    mutate_fn = MUTATION_RULES["learning_rate"]
    for _ in range(100):
        mutated = mutate_fn(0.001)
        assert 1e-6 <= mutated <= 1.0, f"learning_rate вне допустимого диапазона: {mutated}"


def test_dropout_bounds():
    mutate_fn = MUTATION_RULES["dropout"]
    for _ in range(100):
        mutated = mutate_fn(0.3)
        assert 0.0 <= mutated <= 0.9, f"dropout вне границ: {mutated}"


def test_num_layers_limits():
    mutate_fn = MUTATION_RULES["num_layers"]
    for _ in range(100):
        mutated = mutate_fn(4)
        assert mutated >= 1, f"num_layers должен быть >= 1, получено: {mutated}"


def test_stability_of_mutations(base_config):
    mutated_values = {}
    for key, fn in MUTATION_RULES.items():
        mutated_values[key] = fn(base_config[key])
    # Повторная мутация тех же значений не должна давать экстремальных скачков
    for key, original_mutated in mutated_values.items():
        repeated = MUTATION_RULES[key](original_mutated)
        if isinstance(original_mutated, float):
            diff = abs(repeated - original_mutated)
            assert diff < 10 * abs(original_mutated), f"Мутация нестабильна: {key} → Δ={diff:.4f}"


def test_no_exception_thrown(base_config):
    for key, fn in MUTATION_RULES.items():
        try:
            fn(copy.deepcopy(base_config[key]))
        except Exception as e:
            pytest.fail(f"Мутация вызвала исключение: {key} — {str(e)}")
