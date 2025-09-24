import random
from typing import List, Dict, Any, Tuple

class CompetitionArena:
    """
    Арена для состязаний и симуляций между агентами из разных популяций.
    Используется для оценки конкурентоспособности агентов в различных условиях.
    """

    def __init__(self,
                 populations: Dict[str, List[Any]],
                 match_function,
                 rounds_per_match: int = 1):
        """
        Инициализация арены.

        :param populations: Словарь с группами агентов по ключам (названия групп)
        :param match_function: Функция для проведения одного матча между агентами, возвращает результат
        :param rounds_per_match: Количество раундов в одном матче
        """
        self.populations = populations
        self.match_function = match_function
        self.rounds_per_match = rounds_per_match

    def conduct_tournament(self) -> Dict[str, Dict[Any, float]]:
        """
        Проведение турнира между агентами из всех популяций.
        Каждый агент играет с агентами из других популяций.

        :return: Результаты турнира в виде словаря:
                 {group_name: {agent: aggregated_score}}
        """
        results = {group: {agent: 0.0 for agent in agents} for group, agents in self.populations.items()}

        groups = list(self.populations.keys())
        for i, group_a in enumerate(groups):
            for group_b in groups[i+1:]:
                for agent_a in self.populations[group_a]:
                    for agent_b in self.populations[group_b]:
                        score_a, score_b = self._play_match(agent_a, agent_b)
                        results[group_a][agent_a] += score_a
                        results[group_b][agent_b] += score_b
        return results

    def _play_match(self, agent_a: Any, agent_b: Any) -> Tuple[float, float]:
        """
        Проведение одного матча между двумя агентами.

        :param agent_a: Агент из первой популяции
        :param agent_b: Агент из второй популяции
        :return: Кортеж с результатами (очки) для каждого агента
        """
        total_score_a = 0.0
        total_score_b = 0.0
        for _ in range(self.rounds_per_match):
            score_a, score_b = self.match_function(agent_a, agent_b)
            total_score_a += score_a
            total_score_b += score_b
        return total_score_a, total_score_b
