# File: contextual_threat_map.py
import logging
import networkx as nx
from typing import Dict, List, Tuple, Optional
from datetime import datetime

from core.models.threat_entity import ThreatNode, ThreatEdge
from core.config.graph_config import load_graph_config
from core.analytics.ttp_semantics import analyze_ttp_context
from core.alerts.alert_dispatcher import dispatch_graph_alert
from core.db.neo4j_driver import Neo4jConnector

logger = logging.getLogger("graph.contextual_threat_map")
logger.setLevel(logging.INFO)


class ContextualThreatMap:
    def __init__(self):
        self.graph = nx.MultiDiGraph()
        self.config = load_graph_config()
        self.neo4j = Neo4jConnector(self.config.get("neo4j_uri"),
                                    self.config.get("neo4j_user"),
                                    self.config.get("neo4j_password"))
        self.node_lifetime = self.config.get("node_lifetime_seconds", 3600)
        self.threat_threshold = self.config.get("threat_score_threshold", 0.85)

    def add_threat_node(self, node: ThreatNode):
        if not self.graph.has_node(node.id):
            self.graph.add_node(node.id, **node.dict())
            logger.debug(f"Node added: {node.id}")
        else:
            self.graph.nodes[node.id].update(node.dict())
            logger.debug(f"Node updated: {node.id}")

    def add_edge(self, source_id: str, target_id: str, edge: ThreatEdge):
        self.graph.add_edge(source_id, target_id, key=edge.id, **edge.dict())
        logger.debug(f"Edge added: {source_id} -> {target_id} ({edge.relationship})")

    def process_threat_event(self, ttp_id: str, context: Dict):
        ttp_data = analyze_ttp_context(ttp_id, context)
        nodes, edges = ttp_data.get("nodes", []), ttp_data.get("edges", [])

        for node_data in nodes:
            self.add_threat_node(ThreatNode(**node_data))

        for edge_data in edges:
            self.add_edge(edge_data["source_id"], edge_data["target_id"], ThreatEdge(**edge_data))

        self._evaluate_threat_score(ttp_id)

    def _evaluate_threat_score(self, ttp_id: str):
        subgraph = self._build_subgraph_by_ttp(ttp_id)
        threat_score = self._calculate_score(subgraph)

        if threat_score >= self.threat_threshold:
            logger.warning(f"[CRITICAL] Threat score exceeded for TTP {ttp_id}: {threat_score}")
            alert_payload = {
                "timestamp": datetime.utcnow().isoformat(),
                "ttp_id": ttp_id,
                "score": threat_score,
                "graph_snapshot": self._export_subgraph(subgraph),
                "severity": "critical",
                "source": "contextual_threat_map"
            }
            dispatch_graph_alert(alert_payload)
        else:
            logger.info(f"Threat score below threshold for {ttp_id}: {threat_score}")

    def _build_subgraph_by_ttp(self, ttp_id: str) -> nx.MultiDiGraph:
        return self.graph.subgraph([
            node_id for node_id, data in self.graph.nodes(data=True)
            if data.get("ttp") == ttp_id
        ]).copy()

    def _calculate_score(self, graph: nx.MultiDiGraph) -> float:
        if graph.number_of_nodes() == 0:
            return 0.0

        criticality_weights = {
            "lateral_move": 1.5,
            "persistence": 1.3,
            "exfil": 1.8,
            "execution": 1.1
        }

        score = 0.0
        for _, data in graph.nodes(data=True):
            category = data.get("category", "execution")
            score += criticality_weights.get(category, 1.0)

        centrality = nx.degree_centrality(graph)
        avg_centrality = sum(centrality.values()) / len(centrality) if centrality else 0

        normalized_score = min(score / 10.0 + avg_centrality, 1.0)
        return normalized_score

    def _export_subgraph(self, graph: nx.MultiDiGraph) -> Dict:
        return {
            "nodes": [data for _, data in graph.nodes(data=True)],
            "edges": [
                {
                    "source": u,
                    "target": v,
                    "attributes": data
                }
                for u, v, data in graph.edges(data=True)
            ]
        }

    def sync_to_persistent_store(self):
        logger.info("Persisting graph to Neo4j.")
        self.neo4j.store_graph(self.graph)


# External singleton
threat_map = ContextualThreatMap()


def ingest_threat_event(ttp_id: str, context: Dict):
    threat_map.process_threat_event(ttp_id, context)


if __name__ == "__main__":
    from core.ingestion.demo_input import SAMPLE_TTP
    ingest_threat_event(SAMPLE_TTP["id"], SAMPLE_TTP["context"])
    threat_map.sync_to_persistent_store()
