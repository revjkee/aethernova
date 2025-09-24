# mutation_engine.py

import random
import logging
import copy
from typing import Dict, Any, Callable, List

logger = logging.getLogger("mutation_engine")
logger.setLevel(logging.INFO)

# === Регистрация допустимых правил мутаций ===
MUTATION_RULES: Dict[str, Callable[[Any], Any]] = {
    "learning_rate": lambda x: round(max(min(x * random.uniform(0.5, 1.5), 1.0), 1e-6), 6),
    "dropout": lambda x: round(min(max(x + random.uniform(-0.1, 0.1), 0.0), 0.9), 3),
    "num_layers": lambda x: max(1, int(x + random.choice([-1, 1]))),
    "batch_size": lambda x: int(max(8, min(x * random.choice([0.5, 2]), 1024))),
    "activation": lambda x: random.choice(["relu", "tanh", "gelu", "swish"]),
    "optimizer": lambda x: random.choice(["adam", "sgd", "rmsprop", "adamw"]),
    "hidden_dim": lambda x: int(max(32, min(x + random.randint(-64, 64), 4096)))
}

# === Модельный шаблон ===
DEFAULT_MODEL_CONFIG = {
    "learning_rate": 0.001,
    "dropout": 0.3,
    "num_layers": 3,
    "batch_size": 64,
    "activation": "relu",
    "optimizer": "adam",
    "hidden_dim": 256
}

class MutationEngine:
    def __init__(self, rules: Dict[str, Callable[[Any], Any]] = None):
        self.rules = rules or MUTATION_RULES
        self.history: List[Dict[str, Any]] = []

    def prepare_input(self) -> Dict[str, Any]:
        logger.debug("[MutationEngine] Подготовка исходной конфигурации.")
        return copy.deepcopy(DEFAULT_MODEL_CONFIG)

    def mutate(self, config: Dict[str, Any]) -> Dict[str, Any]:
        mutated_config = copy.deepcopy(config)
        logger.info("[MutationEngine] Применение мутаций к конфигурации.")

        for param, mutator in self.rules.items():
            if param in mutated_config:
                original = mutated_config[param]
                try:
                    mutated_config[param] = mutator(mutated_config[param])
                    logger.debug(f"[Mutation] {param}: {original} -> {mutated_config[param]}")
                except Exception as e:
                    logger.warning(f"[MutationEngine] Ошибка мутации параметра {param}: {e}")
                    mutated_config[param] = original

        self.history.append(mutated_config)
        return mutated_config

    def get_last_mutation(self) -> Dict[str, Any]:
        return self.history[-1] if self.history else {}

    def get_last_stats(self) -> Dict[str, Any]:
        last = self.get_last_mutation()
        return {
            "params": list(last.keys()),
            "hash": hash(str(last)),
            "total_mutations": len(self.history)
        }

    def mutate_batch(self, base_config: Dict[str, Any], n: int = 10) -> List[Dict[str, Any]]:
        logger.info(f"[MutationEngine] Запуск пакетной мутации на {n} копий.")
        return [self.mutate(copy.deepcopy(base_config)) for _ in range(n)]
