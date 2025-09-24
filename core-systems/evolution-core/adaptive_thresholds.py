from typing import Dict

class AdaptiveThresholds:
    """
    Модуль для управления динамическими порогами адаптивности и реактивности агентов.
    Обеспечивает гибкую настройку поведения агентов в зависимости от внешних и внутренних условий.
    """

    def __init__(self):
        # Базовые пороги адаптивности и реактивности
        self.base_adaptivity_threshold: float = 0.5
        self.base_reactivity_threshold: float = 0.5

        # Коэффициенты влияния различных факторов на динамические пороги
        self.environment_factor_weight: float = 0.3
        self.fitness_factor_weight: float = 0.5
        self.mutation_rate_weight: float = 0.2

        # Текущие значения порогов (будут динамически пересчитываться)
        self.current_adaptivity_threshold: float = self.base_adaptivity_threshold
        self.current_reactivity_threshold: float = self.base_reactivity_threshold

    def update_thresholds(self,
                          environment_score: float,
                          fitness_score: float,
                          mutation_rate: float) -> None:
        """
        Обновляет текущие пороги адаптивности и реактивности в зависимости от переданных параметров.

        :param environment_score: Оценка среды (от 0 до 1)
        :param fitness_score: Оценка fitness агента (от 0 до 1)
        :param mutation_rate: Текущая скорость мутаций (от 0 до 1)
        """
        self.current_adaptivity_threshold = (
            self.base_adaptivity_threshold
            + environment_score * self.environment_factor_weight
            + fitness_score * self.fitness_factor_weight
        )
        self.current_adaptivity_threshold = min(max(self.current_adaptivity_threshold, 0.0), 1.0)

        self.current_reactivity_threshold = (
            self.base_reactivity_threshold
            + mutation_rate * self.mutation_rate_weight
            + environment_score * self.environment_factor_weight
        )
        self.current_reactivity_threshold = min(max(self.current_reactivity_threshold, 0.0), 1.0)

    def get_adaptivity_threshold(self) -> float:
        """
        Возвращает текущий порог адаптивности.

        :return: float [0, 1]
        """
        return self.current_adaptivity_threshold

    def get_reactivity_threshold(self) -> float:
        """
        Возвращает текущий порог реактивности.

        :return: float [0, 1]
        """
        return self.current_reactivity_threshold
