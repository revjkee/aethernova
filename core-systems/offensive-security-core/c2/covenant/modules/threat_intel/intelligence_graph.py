# Построение графа угроз
# intelligence_graph.py
# Построение, обновление и анализ графа угроз (threat graph)

import networkx as nx
from datetime import datetime
from typing import Optional
import logging
import hashlib

logger = logging.getLogger("intelligence_graph")
logger.setLevel(logging.INFO)


class ThreatIntelligenceGraph:
    def __init__(self):
        """
        Инициализация пустого графа угроз.
        """
        self.graph = nx.MultiDiGraph()

    def _generate_node_id(self, data: dict) -> str:
        """
        Генерирует уникальный идентификатор узла по содержимому
        """
        content = str(sorted(data.items()))
        return hashlib.sha256(content.encode()).hexdigest()

    def add_threat_event(self, event: dict) -> str:
        """
        Добавляет новое событие угрозы в граф.
        :param event: dict с ключами src_ip, attack_vector, timestamp, severity, metadata
        :return: идентификатор узла
        """
        node_data = {
            "type": "event",
            "src_ip": event.get("src_ip"),
            "vector": event.get("attack_vector"),
            "timestamp": event.get("timestamp", datetime.utcnow().isoformat()),
            "severity": event.get("severity", "unknown"),
            "metadata": event.get("metadata", {}),
        }

        node_id = self._generate_node_id(node_data)
        self.graph.add_node(node_id, **node_data)
        logger.info(f"Добавлен узел угрозы: {node_id}")
        return node_id

    def link_nodes(self, source_id: str, target_id: str, label: str = "related", confidence: float = 0.5):
        """
        Связывает два узла в графе с заданной меткой и уровнем уверенности.
        """
        if not self.graph.has_node(source_id) or not self.graph.has_node(target_id):
            logger.warning("Один из узлов для связи не найден")
            return
        self.graph.add_edge(source_id, target_id, label=label, confidence=confidence)
        logger.debug(f"Связь: {source_id} -> {target_id} ({label})")

    def get_related_events(self, src_ip: str) -> list[dict]:
        """
        Возвращает список связанных событий по IP.
        """
        results = []
        for node_id, data in self.graph.nodes(data=True):
            if data.get("src_ip") == src_ip:
                neighbors = list(self.graph.successors(node_id)) + list(self.graph.predecessors(node_id))
                related = [self.graph.nodes[n] for n in neighbors]
                results.append({
                    "event": data,
                    "related": related
                })
        return results

    def classify_node(self, node_id: str) -> Optional[str]:
        """
        Классифицирует узел на основе атрибутов и связей.
        :return: метка категории
        """
        node = self.graph.nodes.get(node_id)
        if not node:
            return None
        severity = node.get("severity", "unknown")
        degree = self.graph.degree(node_id)
        if severity == "high" and degree > 3:
            return "APT cluster"
        elif severity == "medium" and degree > 2:
            return "suspicious"
        else:
            return "low_risk"

    def export_graphml(self, path: str):
        """
        Сохраняет граф в формате GraphML.
        """
        nx.write_graphml(self.graph, path)
        logger.info(f"Граф сохранён в: {path}")

    def reset(self):
        """
        Полная очистка графа.
        """
        self.graph.clear()
        logger.info("Граф угроз очищен.")
