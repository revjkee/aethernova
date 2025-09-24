# intel-core/correlation-engine/engines/rule_evaluator.py

import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class RuleEvaluator:
    """
    Класс для оценки событий на соответствие правилам корреляции.
    """

    def __init__(self, rules: List[Dict[str, Any]]):
        """
        Инициализация с набором правил.

        :param rules: список правил в формате словарей
        """
        self.rules = rules

    def evaluate(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Применяет правила к событию, возвращает список совпадающих правил.

        :param event: событие для проверки
        :return: список правил, которым соответствует событие
        """
        matched_rules = []
        for rule in self.rules:
            if self._match_rule(event, rule):
                matched_rules.append(rule)
        return matched_rules

    def _match_rule(self, event: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        """
        Логика проверки соответствия события правилу.

        :param event: событие
        :param rule: правило
        :return: True если событие соответствует правилу, иначе False
        """
        conditions = rule.get('conditions', [])
        for cond in conditions:
            field = cond.get('field')
            value = cond.get('value')
            op = cond.get('operator', 'equals')

            event_value = event.get(field)
            if event_value is None:
                logger.debug(f"В событии отсутствует поле {field} для правила {rule.get('id')}")
                return False

            if not self._check_condition(event_value, value, op):
                return False

        return True

    def _check_condition(self, event_value: Any, rule_value: Any, operator: str) -> bool:
        """
        Проверка одного условия правила.

        :param event_value: значение из события
        :param rule_value: значение из правила
        :param operator: оператор сравнения
        :return: True/False
        """
        if operator == 'equals':
            return event_value == rule_value
        elif operator == 'not_equals':
            return event_value != rule_value
        elif operator == 'contains':
            return rule_value in event_value if isinstance(event_value, str) else False
        elif operator == 'in':
            return event_value in rule_value if isinstance(rule_value, (list, set)) else False
        else:
            logger.warning(f"Неизвестный оператор {operator} в правиле")
            return False
