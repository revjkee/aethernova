# mutation_core.py
import logging
import traceback
from typing import Dict, Any

from genius_core.mutation.mutation_engine import MutationEngine
from genius_core.mutation.optimizer import CodeOptimizer
from genius_core.mutation.lineage_tracker import LineageTracker
from genius_core.mutation.fitness_score import FitnessScorer
from genius_core.mutation.mutation_observer import MutationObserver
from genius_core.mutation.mutation_strategies import (
    greedy_mutation,
    guided_mutation,
    random_mutation
)

logger = logging.getLogger("mutation_core")
logger.setLevel(logging.INFO)

class MutationCore:
    def __init__(self, config: Dict[str, Any] = None):
        self.engine = MutationEngine()
        self.optimizer = CodeOptimizer()
        self.tracker = LineageTracker()
        self.fitness = FitnessScorer()
        self.observer = MutationObserver()

        # Конфигурация стратегий
        self.strategies = {
            "greedy": greedy_mutation.mutate,
            "guided": guided_mutation.mutate,
            "random": random_mutation.mutate
        }

        self.config = config or {
            "strategy": "guided",
            "max_iterations": 100,
            "fitness_threshold": 0.85
        }

    def execute_mutation_cycle(self):
        logger.info("[MutationCore] Запуск цикла мутаций.")
        try:
            # Выбор стратегии
            strategy_fn = self.strategies.get(self.config["strategy"], random_mutation.mutate)
            mutation_input = self.engine.prepare_input()

            # Применение мутации
            mutated = strategy_fn(mutation_input)
            score = self.fitness.evaluate(mutated)

            # Отслеживание и оптимизация
            self.tracker.record(mutated, score)
            self.observer.log_mutation(mutated, score)

            if score >= self.config["fitness_threshold"]:
                optimized = self.optimizer.refine(mutated)
                logger.info(f"[MutationCore] Успешная мутация с оценкой {score:.3f}")
                return optimized

            logger.warning(f"[MutationCore] Низкая пригодность мутации: {score:.3f}")
            return None

        except Exception as e:
            logger.error(f"[MutationCore] Ошибка цикла мутаций: {e}")
            logger.debug(traceback.format_exc())
            return None

    def run_batch(self, cycles: int = None):
        max_iter = cycles or self.config["max_iterations"]
        logger.info(f"[MutationCore] Запуск {max_iter} мутационных итераций.")
        for i in range(max_iter):
            logger.info(f"[MutationCore] Итерация {i + 1}/{max_iter}")
            result = self.execute_mutation_cycle()
            if result:
                logger.info("[MutationCore] Ранний выход: успешная мутация.")
                break

    def get_statistics(self) -> Dict[str, Any]:
        return {
            "total_mutations": self.tracker.total(),
            "successful": self.tracker.successful(),
            "average_fitness": self.tracker.average_fitness(),
            "last_score": self.tracker.last_score()
        }

# Для автономного запуска
if __name__ == "__main__":
    core = MutationCore()
    core.run_batch()
    stats = core.get_statistics()
    logger.info(f"[MutationCore] Статистика: {stats}")
