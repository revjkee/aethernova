# intel-core/correlation-engine/engines/correlation_manager.py

import logging
from typing import List, Dict, Any
from .rule_evaluator import RuleEvaluator

logger = logging.getLogger(__name__)

class CorrelationManager:
    """
    Управляет процессом корреляции событий:
    - Принимает новые события
    - Применяет правила корреляции
    - Агрегирует и сохраняет результаты
    """

    def __init__(self, rules: List[Dict[str, Any]]):
        """
        Инициализация с набором правил и RuleEvaluator.

        :param rules: список правил
        """
        self.rule_evaluator = RuleEvaluator(rules)
        self.correlated_events = []  # Хранилище коррелированных событий

    def process_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Обрабатывает список событий, применяет корреляцию и возвращает результаты.

        :param events: список входящих событий
        :return: список коррелированных событий с применёнными правилами
        """
        results = []
        for event in events:
            matched_rules = self.rule_evaluator.evaluate(event)
            if matched_rules:
                correlated_event = {
                    "event": event,
                    "matched_rules": matched_rules
                }
                self.correlated_events.append(correlated_event)
                results.append(correlated_event)
                logger.debug(f"Событие {event.get('id', 'unknown')} соответствует правилам: {[r.get('id') for r in matched_rules]}")
            else:
                logger.debug(f"Событие {event.get('id', 'unknown')} не соответствует ни одному правилу")
        return results

    def get_correlated_events(self) -> List[Dict[str, Any]]:
        """
        Возвращает все коррелированные события, сохранённые в менеджере.

        :return: список коррелированных событий
        """
        return self.correlated_events

    def clear(self) -> None:
        """
        Очистка состояния коррелированных событий.
        """
        self.correlated_events.clear()
        logger.info("Состояние коррелированных событий очищено")
