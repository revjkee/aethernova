# genius-core/code-enhancement/code-evolver/evolver.py

import ast
import copy
import random
from typing import List, Optional

class CodeEvolver:
    """
    Класс для автоматического рефакторинга и эволюции Python кода
    с использованием AST и генетических алгоритмов.
    """

    def __init__(self, population_size: int = 20, mutation_rate: float = 0.1, generations: int = 50):
        self.population_size = population_size
        self.mutation_rate = mutation_rate
        self.generations = generations
        self.population: List[ast.AST] = []

    def initialize_population(self, base_code: str):
        """
        Инициализация популяции из копий базового AST кода.
        """
        base_ast = ast.parse(base_code)
        self.population = [copy.deepcopy(base_ast) for _ in range(self.population_size)]

    def mutate(self, tree: ast.AST) -> ast.AST:
        """
        Выполнение мутации AST: случайное изменение узлов.
        """
        mutated = copy.deepcopy(tree)
        for node in ast.walk(mutated):
            if random.random() < self.mutation_rate:
                self._mutate_node(node)
        return mutated

    def _mutate_node(self, node: ast.AST):
        """
        Простейшая мутация: изменение числовых констант.
        """
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            old_val = node.value
            node.value = old_val + random.choice([-1, 1]) * random.uniform(0.1, 5)
            if isinstance(old_val, int):
                node.value = int(node.value)

    def fitness(self, tree: ast.AST) -> float:
        """
        Функция оценки: базовый пример - длина исходного кода.
        В реальности сюда впишется метрика качества кода.
        """
        code = ast.unparse(tree)
        return -len(code)  # Меньше кода — лучше (пример)

    def evolve(self, base_code: str) -> str:
        """
        Основной цикл эволюции: инициализация, мутация, отбор.
        Возвращает лучший вариант кода.
        """
        self.initialize_population(base_code)

        for gen in range(self.generations):
            scored_population = [(self.fitness(ind), ind) for ind in self.population]
            scored_population.sort(key=lambda x: x[0], reverse=True)
            # Отбор лучших 50%
            survivors = [ind for _, ind in scored_population[:self.population_size // 2]]
            # Восполнение популяции мутациями
            new_population = survivors[:]
            while len(new_population) < self.population_size:
                parent = random.choice(survivors)
                mutated = self.mutate(parent)
                new_population.append(mutated)
            self.population = new_population

        best_tree = max(self.population, key=self.fitness)
        return ast.unparse(best_tree)


# Пример использования
if __name__ == "__main__":
    base_code = """
def add(a, b):
    return a + b
"""
    evolver = CodeEvolver()
    best_code = evolver.evolve(base_code)
    print("Лучший сгенерированный код:")
    print(best_code)
