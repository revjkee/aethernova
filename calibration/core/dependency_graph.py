import logging
from typing import Dict, List, Set, Optional
from collections import defaultdict, deque

logger = logging.getLogger("calibration.dependency")

class DependencyCycleError(Exception):
    """Ошибка цикла в графе зависимостей."""
    pass

class DependencyGraph:
    """
    Управляет зависимостями между параметрами и модулями.
    Используется для вычисления безопасного порядка калибровки,
    предотвращения циклов и определения затронутых компонентов.
    """

    def __init__(self):
        self._forward: Dict[str, Set[str]] = defaultdict(set)
        self._backward: Dict[str, Set[str]] = defaultdict(set)
        self._nodes: Set[str] = set()

    def add_node(self, node: str) -> None:
        self._nodes.add(node)

    def add_dependency(self, source: str, target: str) -> None:
        """
        Задаёт зависимость source -> target (target зависит от source).
        """
        if target == source:
            raise ValueError("Нельзя создать самозависимость.")
        self._forward[source].add(target)
        self._backward[target].add(source)
        self._nodes.update([source, target])
        logger.debug(f"Dependency added: {source} -> {target}")

    def remove_dependency(self, source: str, target: str) -> None:
        self._forward[source].discard(target)
        self._backward[target].discard(source)
        logger.debug(f"Dependency removed: {source} -> {target}")

    def get_dependencies(self, node: str) -> Set[str]:
        return self._forward.get(node, set())

    def get_dependents(self, node: str) -> Set[str]:
        return self._backward.get(node, set())

    def detect_cycles(self) -> bool:
        """
        Проверяет наличие циклов в графе зависимостей.
        """
        visited = set()
        stack = set()

        def dfs(node: str) -> bool:
            visited.add(node)
            stack.add(node)
            for neighbor in self._forward.get(node, []):
                if neighbor not in visited:
                    if dfs(neighbor):
                        return True
                elif neighbor in stack:
                    return True
            stack.remove(node)
            return False

        for node in self._nodes:
            if node not in visited:
                if dfs(node):
                    logger.error(f"Цикл обнаружен, начиная с узла: {node}")
                    return True
        return False

    def topological_sort(self) -> List[str]:
        """
        Возвращает список узлов в порядке разрешённой калибровки.
        Бросает ошибку, если найден цикл.
        """
        in_degree = {node: 0 for node in self._nodes}
        for src in self._forward:
            for dst in self._forward[src]:
                in_degree[dst] += 1

        queue = deque([node for node in self._nodes if in_degree[node] == 0])
        result = []

        while queue:
            node = queue.popleft()
            result.append(node)
            for neighbor in self._forward.get(node, []):
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        if len(result) != len(self._nodes):
            raise DependencyCycleError("Невозможно отсортировать: цикл в графе")

        return result

    def affected_nodes(self, changed: str) -> Set[str]:
        """
        Возвращает все узлы, напрямую или косвенно зависящие от изменённого узла.
        """
        affected = set()
        stack = [changed]

        while stack:
            current = stack.pop()
            for dependent in self._forward.get(current, []):
                if dependent not in affected:
                    affected.add(dependent)
                    stack.append(dependent)

        return affected

    def export_graph(self) -> Dict[str, List[str]]:
        """
        Возвращает граф в формате, пригодном для сериализации или визуализации.
        """
        return {k: list(v) for k, v in self._forward.items()}

    def reset(self) -> None:
        """
        Полностью очищает граф зависимостей.
        """
        self._forward.clear()
        self._backward.clear()
        self._nodes.clear()
        logger.info("Dependency graph reset.")
