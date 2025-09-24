import networkx as nx
from datetime import datetime, timedelta
from collections import deque
from typing import Dict, Any, Deque, Tuple, Optional


class BehaviorGraph:
    """
    Граф действий пользователя для отслеживания активности, паттернов
    и выявления аномалий поведения на основе контекста и временных меток.
    """

    def __init__(self, retention_minutes: int = 120):
        self.graph = nx.DiGraph()
        self.action_log: Dict[str, Deque[Tuple[datetime, str]]] = {}
        self.retention = timedelta(minutes=retention_minutes)

    def record_action(self, user_id: str, request: Dict[str, Any], timestamp: Optional[datetime] = None):
        """
        Добавляет новое действие в граф поведения пользователя.
        """
        if timestamp is None:
            timestamp = datetime.utcnow()

        action_type = self._extract_action_type(request)
        self._ensure_user(user_id)

        # Добавляем вершину и ребро в граф
        self.graph.add_node(action_type, last_seen=timestamp)
        previous_action = self._get_last_action(user_id)
        if previous_action:
            self.graph.add_edge(previous_action, action_type, timestamp=timestamp)

        # Лог действий
        self.action_log[user_id].append((timestamp, action_type))
        self._prune_old_actions(user_id)

    def get_user_path(self, user_id: str, window_minutes: int = 10) -> Deque[str]:
        """
        Возвращает список действий пользователя за последние N минут.
        """
        cutoff = datetime.utcnow() - timedelta(minutes=window_minutes)
        return deque(
            action for ts, action in self.action_log.get(user_id, [])
            if ts >= cutoff
        )

    def get_transition_matrix(self) -> Dict[str, Dict[str, int]]:
        """
        Возвращает матрицу переходов между действиями.
        """
        matrix = {}
        for u, v in self.graph.edges:
            matrix.setdefault(u, {}).setdefault(v, 0)
            matrix[u][v] += 1
        return matrix

    def get_graph_stats(self) -> Dict[str, Any]:
        """
        Статистика графа: количество узлов, связность, плотность и т.д.
        """
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "density": nx.density(self.graph),
            "avg_degree": sum(dict(self.graph.degree()).values()) / max(1, self.graph.number_of_nodes())
        }

    def _get_last_action(self, user_id: str) -> Optional[str]:
        if user_id not in self.action_log or not self.action_log[user_id]:
            return None
        return self.action_log[user_id][-1][1]

    def _ensure_user(self, user_id: str):
        if user_id not in self.action_log:
            self.action_log[user_id] = deque()

    def _extract_action_type(self, request: Dict[str, Any]) -> str:
        """
        Определяет тип действия по содержимому запроса.
        """
        return request.get("action_type") or request.get("endpoint") or "unknown"

    def _prune_old_actions(self, user_id: str):
        """
        Удаляет устаревшие действия за пределами retention-периода.
        """
        cutoff = datetime.utcnow() - self.retention
        while self.action_log[user_id] and self.action_log[user_id][0][0] < cutoff:
            self.action_log[user_id].popleft()


# Экспорт
__all__ = ["BehaviorGraph"]
