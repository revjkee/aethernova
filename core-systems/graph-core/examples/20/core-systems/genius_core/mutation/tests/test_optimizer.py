# test_optimizer.py

import pytest
from copy import deepcopy

from genius_core.mutation.optimizer import CodeOptimizer
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

def test_population_initialization(base_config):
    opt = CodeOptimizer(population_size=10)
    opt.initialize_population(base_config)
    assert len(opt.get_population()) == 10, "Популяция не была правильно инициализирована"
    for cfg, score in opt.get_population():
        assert isinstance(cfg, dict)
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0

def test_elite_selection(base_config):
    opt = CodeOptimizer(population_size=10, elite_fraction=0.3)
    opt.initialize_population(base_config)
    elite = opt.select_elite()
    assert len(elite) == 3, "Неверное число элитных стратегий"
    for cfg in elite:
        assert isinstance(cfg, dict)

def test_evolution_progress(base_config):
    opt = CodeOptimizer(population_size=10, elite_fraction=0.2)
    opt.initialize_population(base_config)
    before = max(score for _, score in opt.get_population())
    result = opt.evolve(generations=5)
    after = max(score for _, score in opt.get_population())
    assert after >= before, f"Fitness не улучшился: {before:.4f} → {after:.4f}"

def test_stable_crossover_and_mutation(base_config):
    opt = CodeOptimizer(population_size=6)
    opt.initialize_population(base_config)
    elite = opt.select_elite()
    parent1, parent2 = elite[0], elite[1]
    child = opt.crossover(parent1, parent2)
    mutated = opt.mutate(deepcopy(child))
    assert isinstance(mutated, dict)
    assert mutated != parent1 or mutated != parent2

def test_population_consistency(base_config):
    opt = CodeOptimizer(population_size=12)
    opt.initialize_population(base_config)
    opt.evolve(generations=3)
    population = opt.get_population()
    assert all(isinstance(cfg, dict) and isinstance(score, float) for cfg, score in population)
    assert len(population) == 12, "Размер популяции изменился после эволюции"

def test_no_exceptions_in_evolution(base_config):
    try:
        opt = CodeOptimizer(population_size=10)
        opt.initialize_population(base_config)
        opt.evolve(generations=2)
    except Exception as e:
        pytest.fail(f"Эволюция вызвала исключение: {str(e)}")
