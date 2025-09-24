import random
from typing import Dict, Any, Callable, List

class SelfMutator:
    """
    Класс для выполнения мутаций над особью.
    Поддерживает несколько стратегий мутации, которые можно комбинировать.
    """

    def __init__(self, mutation_strategies: List[Callable[[Dict[str, Any]], Dict[str, Any]]], mutation_rate: float = 0.1):
        """
        mutation_strategies — список функций мутации.
        mutation_rate — вероятность применения мутации к каждой характеристике.
        """
        if not mutation_strategies:
            raise ValueError("mutation_strategies list cannot be empty")
        self.mutation_strategies = mutation_strategies
        self.mutation_rate = mutation_rate

    def mutate(self, individual: Dict[str, Any]) -> Dict[str, Any]:
        """
        Применяет мутации к особи.
        Для каждой стратегии мутации вероятность применения определяется mutation_rate.
        Возвращает новую мутированную особь (копию).
        """
        mutated = individual.copy()
        for strategy in self.mutation_strategies:
            if random.random() < self.mutation_rate:
                mutated = strategy(mutated)
        return mutated

# Пример возможных стратегий мутации, их реализацию подключать отдельно
def mutate_numeric_gene(individual: Dict[str, Any], gene_key: str, mutation_amount: float = 0.1) -> Dict[str, Any]:
    """
    Пример мутации числового гена: добавляет или вычитает случайное значение.
    """
    new_individual = individual.copy()
    if gene_key in new_individual and isinstance(new_individual[gene_key], (int, float)):
        delta = (random.random() * 2 - 1) * mutation_amount
        new_individual[gene_key] += delta
    return new_individual
