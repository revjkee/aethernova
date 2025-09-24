from typing import Dict, List, Set
from collections import deque
from graph_core.storage import GraphStorage

class GraphAnalytics:
    """
    Класс для аналитики графа с базовыми алгоритмами:
    - Поиск в ширину (BFS)
    - Поиск в глубину (DFS)
    - Поиск кратчайшего пути (BFS)
    - Вычисление степени узлов
    """

    def __init__(self, storage: GraphStorage):
        self.storage = storage

    def bfs(self, start_node: str) -> List[str]:
        """
        Обход графа в ширину, возвращает список посещённых узлов в порядке обхода.
        """
        if start_node not in self.storage:
            return []

        visited: Set[str] = set()
        queue: deque = deque([start_node])
        order: List[str] = []

        while queue:
            node = queue.popleft()
            if node not in visited:
                visited.add(node)
                order.append(node)
                neighbors = self.storage.get_neighbors(node) or set()
                for neighbor in neighbors:
                    if neighbor not in visited:
                        queue.append(neighbor)
        return order

    def dfs(self, start_node: str) -> List[str]:
        """
        Обход графа в глубину, возвращает список посещённых узлов в порядке обхода.
        """
        if start_node not in self.storage:
            return []

        visited: Set[str] = set()
        order: List[str] = []
        stack: List[str] = [start_node]

        while stack:
            node = stack.pop()
            if node not in visited:
                visited.add(node)
                order.append(node)
                neighbors = self.storage.get_neighbors(node) or set()
                for neighbor in sorted(neighbors, reverse=True):
                    if neighbor not in visited:
                        stack.append(neighbor)
        return order

    def shortest_path(self, start_node: str, end_node: str) -> List[str]:
        """
        Находит кратчайший путь (BFS) между двумя узлами, возвращает список узлов пути.
        Если путь не найден — возвращает пустой список.
        """
        if start_node not in self.storage or end_node not in self.storage:
            return []

        visited: Set[str] = set()
        queue: deque = deque([(start_node, [start_node])])

        while queue:
            current, path = queue.popleft()
            if current == end_node:
                return path
            if current not in visited:
                visited.add(current)
                neighbors = self.storage.get_neighbors(current) or set()
                for neighbor in neighbors:
                    if neighbor not in visited:
                        queue.append((neighbor, path + [neighbor]))
        return []

    def node_degrees(self) -> Dict[str, int]:
        """
        Возвращает словарь: узел -> степень (число исходящих рёбер).
        """
        degrees: Dict[str, int] = {}
        for node in self.storage.nodes():
            neighbors = self.storage.get_neighbors(node)
            degrees[node] = len(neighbors) if neighbors else 0
        return degrees
