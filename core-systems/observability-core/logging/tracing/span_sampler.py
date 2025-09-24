import re
import random
import os
from typing import Dict

# Таблица регулярных выражений с приоритетами сэмплирования
SAMPLING_RULES: Dict[str, float] = {
    r"^ai_core_.*": 1.0,
    r"^critical_.*": 1.0,
    r"^heartbeat$": 0.05,
    r"^db_query_.*": 0.1,
    r"^cache_lookup_.*": 0.2,
    r"^agent_\w+_.*": 0.3,
    r"^metrics_export_.*": 0.05,
    r"^trace_.*": 0.5,
    r"^.*_background.*": 0.01,
}

# Возможность динамической настройки уровня через переменные окружения
GLOBAL_SAMPLING_RATE = float(os.environ.get("GENESIS_TRACE_SAMPLING", "0.15"))


def should_sample_span(span_name: str) -> bool:
    """
    Определяет, нужно ли сэмплировать спан, основываясь на имени и политике.
    """
    for pattern, probability in SAMPLING_RULES.items():
        if re.match(pattern, span_name):
            return random.random() < probability

    # fallback если ни один паттерн не подошел
    return random.random() < GLOBAL_SAMPLING_RATE


def reload_sampling_rules(new_rules: Dict[str, float]):
    """
    Позволяет динамически обновить правила сэмплирования в рантайме
    """
    global SAMPLING_RULES
    SAMPLING_RULES.clear()
    SAMPLING_RULES.update(new_rules)


def get_current_sampling_config() -> Dict[str, float]:
    """
    Возвращает текущие правила и глобальный порог
    """
    return {
        "rules": SAMPLING_RULES.copy(),
        "global_rate": GLOBAL_SAMPLING_RATE
    }
