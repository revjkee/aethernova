import networkx as nx
import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta

from core.models.threat_graph import ThreatGraph, ThreatNode
from core.config.propagation_config import load_propagation_profile
from core.utils.time_utils import now_utc

logger = logging.getLogger("graph.propagation_simulator")
logger.setLevel(logging.INFO)


class PropagationSimulator:
    def __init__(self):
        self.profile = load_propagation_profile()
        self.base_probabilities = self.profile.get("base_ttp_probs", {})
        self.time_window_minutes = self.profile.get("time_window_minutes", 30)
        self.max_depth = self.profile.get("max_propagation_depth", 5)

    def simulate(self, graph: ThreatGraph, origin_node_id: str, timestamp: Optional[datetime] = None) -> Dict[str, float]:
        """
        Симулирует вероятности заражения других узлов из начального узла.
        Возвращает словарь {node_id: infection_probability}.
        """
        if not graph.has_node(origin_node_id):
            logger.warning(f"Node {origin_node_id} not found in graph.")
            return {}

        if timestamp is None:
            timestamp = now_utc()

        visited = set()
        infection_scores = {origin_node_id: 1.0}
        frontier = [(origin_node_id, 0)]

        while frontier:
            current_node, depth = frontier.pop(0)
            if depth >= self.max_depth:
                continue
            visited.add(current_node)

            for neighbor in graph.neighbors(current_node):
                if neighbor in visited:
                    continue
                edge_data = graph.get_edge_data(current_node, neighbor)
                propagation_weight = self._calculate_propagation_weight(graph, current_node, neighbor, edge_data, timestamp)
                cumulative_score = infection_scores[current_node] * propagation_weight

                if cumulative_score > infection_scores.get(neighbor, 0):
                    infection_scores[neighbor] = round(min(cumulative_score, 1.0), 4)
                    frontier.append((neighbor, depth + 1))

        return infection_scores

    def _calculate_propagation_weight(self, graph: ThreatGraph, src_id: str, dst_id: str, edge_data: Dict, ts: datetime) -> float:
        """
        Оценивает вероятность передачи угрозы по ребру, учитывая TTP, чувствительность, эвристику времени и MITRE.
        """
        src_node: ThreatNode = graph.get_node(src_id)
        dst_node: ThreatNode = graph.get_node(dst_id)

        base_ttp = edge_data.get("ttp", "T0000")
        base_prob = self.base_probabilities.get(base_ttp, 0.3)

        dst_sens = dst_node.metadata.get("sensitivity", "low")
        sens_boost = {"low": 0.8, "medium": 1.0, "high": 1.2}.get(dst_sens, 0.8)

        tdelta = (ts - dst_node.last_seen).total_seconds() if dst_node.last_seen else 999999
        time_decay = 1.0 if tdelta < 60 else 0.9 if tdelta < 300 else 0.6 if tdelta < 3600 else 0.3

        node_type_weight = 1.2 if dst_node.metadata.get("is_cloud_asset") else 1.0
        mitre_context_bonus = 1.1 if dst_node.metadata.get("in_mitre_killchain") else 1.0

        final_weight = base_prob * sens_boost * time_decay * node_type_weight * mitre_context_bonus
        return min(final_weight, 1.0)

    def trace_path(self, graph: ThreatGraph, origin_node_id: str, target_node_id: str, limit_depth: int = 6) -> List[str]:
        """
        Возвращает вероятный путь атаки между узлами, если существует.
        """
        try:
            path = nx.shortest_path(graph.nx, source=origin_node_id, target=target_node_id)
            if len(path) > limit_depth:
                return []
            return path
        except Exception as e:
            logger.debug(f"No path from {origin_node_id} to {target_node_id}: {e}")
            return []

    def export_risk_heatmap(self, graph: ThreatGraph, origin_node_id: str) -> Dict[str, float]:
        """
        Возвращает распределение риска в формате {node_id: risk_score}, подходящем для визуализации.
        """
        infection_map = self.simulate(graph, origin_node_id)
        normalized = {nid: min(score, 1.0) for nid, score in infection_map.items()}
        return normalized


# Global instance
simulator = PropagationSimulator()
