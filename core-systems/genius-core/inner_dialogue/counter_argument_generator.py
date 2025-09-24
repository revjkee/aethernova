# AI-platform-core/genius-core/inner-dialogue/counter_argument_generator.py

import logging
from typing import Dict, List, Optional

logger = logging.getLogger("CounterArgumentGenerator")

class CounterArgumentGenerator:
    """
    Генератор контраргументов для размышлений, дебатов и критического анализа.
    Используется в цепочках саморефлексии, взаимодействии агентов и при анализе моральных дилемм.
    """

    def __init__(self):
        self.heuristic_patterns = {
            "appeal_to_emotion": "Факт может игнорировать чувства, но реальность требует жёстких решений.",
            "slippery_slope": "Последствия должны быть доказаны, а не предположены.",
            "status_quo": "То, что используется давно — не обязательно лучше.",
            "authority_bias": "Авторитет — не всегда гарантия истины.",
            "fear_based": "Страх — плохой советчик при принятии решений.",
            "efficiency_over_ethics": "Не всё, что эффективно — морально допустимо."
        }

    def generate(self, statement: str, context: Optional[Dict] = None) -> Dict[str, str]:
        """
        Возвращает один или несколько контраргументов на входное утверждение.
        """
        logger.debug(f"[CounterArgumentGenerator] Получен тезис: '{statement}'")
        counters = []

        # 1. Логическая инверсия
        counters.append(f"Допустим, обратное утверждение: что если '{statement}' — ложное предположение?")

        # 2. Моральный вызов
        if "должны" in statement or "обязаны" in statement:
            counters.append("Моральное обязательство должно быть обосновано универсальной ценностью, а не обстоятельством.")

        # 3. Рациональное сомнение
        counters.append("Какие доказательства реально подтверждают это утверждение?")

        # 4. Прагматический скепсис
        counters.append("Если следовать этому, не возникнет ли непредвиденный вред в другой области?")

        # 5. Эвристическое применение
        for pattern, rebuttal in self.heuristic_patterns.items():
            if pattern in statement.lower():
                counters.append(rebuttal)

        return {
            "original": statement,
            "counters": counters
        }

    def generate_batch(self, statements: List[str]) -> List[Dict[str, str]]:
        """
        Обрабатывает список утверждений, возвращая контраргументы по каждому.
        """
        return [self.generate(s) for s in statements]

    def export_patterns(self) -> Dict[str, str]:
        """
        Экспорт эвристических шаблонов для внешней логики (обучение, симуляции).
        """
        return self.heuristic_patterns.copy()
