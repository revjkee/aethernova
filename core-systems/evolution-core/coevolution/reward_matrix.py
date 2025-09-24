from typing import Dict, Tuple, Any

class RewardMatrix:
    """
    Матрица наград для сложных взаимодействий между агентами.
    Позволяет задавать и вычислять награды в играх с несколькими участниками,
    учитывая их стратегии и параметры.
    """

    def __init__(self):
        # Хранит награды в формате:
        # {(strategy_a, strategy_b): (reward_for_a, reward_for_b)}
        self.matrix: Dict[Tuple[Any, Any], Tuple[float, float]] = {}

    def set_reward(self, strategy_a: Any, strategy_b: Any, reward_a: float, reward_b: float):
        """
        Установить награды для пары стратегий.

        :param strategy_a: Стратегия агента A
        :param strategy_b: Стратегия агента B
        :param reward_a: Награда для агента A
        :param reward_b: Награда для агента B
        """
        self.matrix[(strategy_a, strategy_b)] = (reward_a, reward_b)

    def get_reward(self, strategy_a: Any, strategy_b: Any) -> Tuple[float, float]:
        """
        Получить награды для пары стратегий.

        :param strategy_a: Стратегия агента A
        :param strategy_b: Стратегия агента B
        :return: Кортеж (reward_for_a, reward_for_b)
        """
        return self.matrix.get((strategy_a, strategy_b), (0.0, 0.0))

    def load_matrix(self, reward_data: Dict[Tuple[Any, Any], Tuple[float, float]]):
        """
        Загрузить матрицу наград из словаря.

        :param reward_data: Словарь с наградами в формате {(strategy_a, strategy_b): (reward_a, reward_b)}
        """
        self.matrix = reward_data.copy()

    def clear(self):
        """Очистить матрицу наград."""
        self.matrix.clear()
