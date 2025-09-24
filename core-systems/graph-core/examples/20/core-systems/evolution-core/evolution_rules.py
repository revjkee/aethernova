from typing import Dict, List, Union

class EvolutionRules:
    """
    Правила эволюции:
    - Определяют допустимые типы мутаций
    - Лимиты на количество мутаций за цикл
    - Параметры для селекции и репликации
    """

    def __init__(self):
        # Разрешённые типы мутаций и их максимальная частота на один цикл
        self.allowed_mutations: Dict[str, int] = {
            "random_mutation": 5,
            "greedy_mutation": 3,
            "guided_mutation": 4,
        }

        # Максимальное количество мутаций на агента за цикл
        self.max_mutations_per_agent: int = 7

        # Параметры селекции: процент лучших агентов, проходящих в следующий этап
        self.selection_ratio: float = 0.2  # 20%

        # Минимальный порог fitness для допуска агента к репликации
        self.min_fitness_threshold: float = 0.5

        # Ограничение общего количества агентов в популяции
        self.population_limit: int = 1000

        # Дополнительные параметры, например, вес различных мутаций в процессе выбора
        self.mutation_weights: Dict[str, float] = {
            "random_mutation": 0.3,
            "greedy_mutation": 0.5,
            "guided_mutation": 0.2,
        }

    def is_mutation_allowed(self, mutation_type: str) -> bool:
        """
        Проверяет, разрешён ли данный тип мутации.

        :param mutation_type: Название мутации.
        :return: True, если разрешён.
        """
        return mutation_type in self.allowed_mutations

    def get_max_mutations_for_type(self, mutation_type: str) -> int:
        """
        Возвращает максимальное число мутаций данного типа за цикл.

        :param mutation_type: Название мутации.
        :return: Максимум мутаций.
        """
        return self.allowed_mutations.get(mutation_type, 0)

    def validate_population_size(self, current_size: int) -> bool:
        """
        Проверяет, не превышает ли текущий размер популяции лимит.

        :param current_size: Текущий размер популяции.
        :return: True, если размер в пределах лимита.
        """
        return current_size <= self.population_limit

    def can_replicate(self, fitness_score: float) -> bool:
        """
        Определяет, можно ли реплицировать агента по fitness.

        :param fitness_score: Значение fitness.
        :return: True, если fitness выше порога.
        """
        return fitness_score >= self.min_fitness_threshold

    def get_selection_ratio(self) -> float:
        """
        Возвращает процент агентов, проходящих селекцию.

        :return: float от 0 до 1.
        """
        return self.selection_ratio

    def get_mutation_weights(self) -> Dict[str, float]:
        """
        Возвращает веса мутаций для выбора.

        :return: Словарь с весами.
        """
        return self.mutation_weights
