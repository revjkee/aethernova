# genius-core/ethics-core/ethical_dilemma_resolver.py

"""
Решатель этических дилемм:
— анализирует конфликтующие моральные нормы
— оценивает последствия
— предлагает наиболее приемлемое решение по шкале ценностей
"""

from typing import List, Dict, Tuple
import math


class MoralAction:
    """
    Представление возможного действия с моральной перспективы
    """
    def __init__(self, name: str, outcomes: Dict[str, float], risk: float = 0.0):
        """
        :param name: название действия
        :param outcomes: влияние на ценности (value_name → эффект [-1.0, +1.0])
        :param risk: вероятность негативного исхода
        """
        self.name = name
        self.outcomes = outcomes
        self.risk = risk


class EthicalDilemmaResolver:
    """
    Основной класс для выбора между морально сложными действиями
    """

    def __init__(self, value_weights: Dict[str, float]):
        """
        :param value_weights: приоритеты ценностей (value → вес)
        Пример: {"честность": 1.0, "безопасность": 2.0, "свобода": 0.8}
        """
        self.value_weights = value_weights

    def evaluate_action(self, action: MoralAction) -> float:
        """
        Вычисляет итоговый моральный балл действия
        """
        score = 0.0
        for value, effect in action.outcomes.items():
            weight = self.value_weights.get(value, 0.0)
            score += weight * effect

        # штраф за риск
        score -= 2.0 * action.risk
        return round(score, 4)

    def resolve(self, actions: List[MoralAction]) -> Tuple[str, float]:
        """
        Выбирает наиболее приемлемое с точки зрения морали действие
        """
        if not actions:
            return ("NO_ACTION", 0.0)

        best_action = None
        best_score = -math.inf

        for action in actions:
            score = self.evaluate_action(action)
            if score > best_score:
                best_score = score
                best_action = action.name

        return (best_action, round(best_score, 3))

    def rank_actions(self, actions: List[MoralAction]) -> List[Dict]:
        """
        Возвращает все действия, отсортированные по моральной оценке
        """
        evaluations = []
        for a in actions:
            evaluations.append({
                "action": a.name,
                "score": self.evaluate_action(a),
                "risk": a.risk,
                "outcomes": a.outcomes
            })

        return sorted(evaluations, key=lambda x: x["score"], reverse=True)
