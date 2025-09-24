# red-vs-blue-engine/agents/shared/tactic_graph.py

from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict, deque
import networkx as nx


class TacticGraph:
    """
    Индустриальная реализация тактического графа на базе MITRE ATT&CK.
    Поддерживает:
    - Directed Acyclic Graph (DAG) для тактик и техник
    - Веса риска, стоимости и успеха
    - Навигацию стратегий Red/Blue команд
    - Расширение кастомными техниками
    """

    def __init__(self):
        self.graph = nx.DiGraph()
        self.tactic_order: List[str] = []
        self.default_success_rate = 0.5
        self.default_detection_risk = 0.3

    def add_tactic(self, tactic: str):
        if tactic not in self.graph:
            self.graph.add_node(tactic, type="tactic")

    def add_technique(self, tactic: str, technique_id: str, description: str = "", success_rate: float = None, detection_risk: float = None):
        self.add_tactic(tactic)
        success = success_rate if success_rate is not None else self.default_success_rate
        risk = detection_risk if detection_risk is not None else self.default_detection_risk

        self.graph.add_node(technique_id, type="technique", description=description,
                            success_rate=success, detection_risk=risk)
        self.graph.add_edge(tactic, technique_id)

    def add_transition(self, from_tech: str, to_tech: str, weight: float = 1.0):
        if from_tech in self.graph and to_tech in self.graph:
            self.graph.add_edge(from_tech, to_tech, weight=weight)

    def get_techniques_by_tactic(self, tactic: str) -> List[str]:
        return [n for n in self.graph.successors(tactic) if self.graph.nodes[n]["type"] == "technique"]

    def get_successors(self, node: str) -> List[str]:
        return list(self.graph.successors(node))

    def get_path_score(self, path: List[str]) -> Dict[str, float]:
        score = {"total_risk": 0.0, "total_success": 1.0}
        for node in path:
            data = self.graph.nodes.get(node)
            if data and data["type"] == "technique":
                score["total_risk"] += data.get("detection_risk", self.default_detection_risk)
                score["total_success"] *= data.get("success_rate", self.default_success_rate)
        return score

    def find_attack_path(self, start_tactic: str, depth: int = 3) -> List[str]:
        """
        Строит вероятностный путь атаки от начальной тактики.
        """
        if start_tactic not in self.graph:
            return []

        path = []
        visited = set()

        def dfs(current, current_depth):
            if current_depth == 0 or current in visited:
                return
            visited.add(current)
            path.append(current)
            successors = self.get_successors(current)
            if successors:
                best = sorted(successors, key=lambda n: self.graph.nodes[n].get("success_rate", 0), reverse=True)
                for next_node in best[:1]:  # Выбираем лучший путь
                    dfs(next_node, current_depth - 1)

        dfs(start_tactic, depth)
        return path

    def visualize(self) -> nx.DiGraph:
        """
        Возвращает граф для визуализации (используйте matplotlib или pyvis отдельно).
        """
        return self.graph

    def export_as_json(self) -> Dict:
        """
        Экспортирует граф в формате, пригодном для Web-интерфейса или AI-визуализации.
        """
        data = {
            "nodes": [],
            "edges": []
        }
        for node, attrs in self.graph.nodes(data=True):
            data["nodes"].append({"id": node, **attrs})
        for source, target, attrs in self.graph.edges(data=True):
            data["edges"].append({"from": source, "to": target, **attrs})
        return data

