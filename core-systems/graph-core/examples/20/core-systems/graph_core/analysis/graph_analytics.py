import networkx as nx
import numpy as np
import hashlib
from typing import Dict, Any, Optional, List
from concurrent.futures import ThreadPoolExecutor
from graph_core.validation.schema_validator import validate_graph_schema
from graph_core.security.integrity import compute_checksum, verify_checksum
from graph_core.utils.logger import setup_logger
from graph_core.analytics.cache import AnalyticsCache
from graph_core.analytics.structural_metrics import calculate_entropy, detect_anomaly_nodes
from graph_core.audit.logger import graph_audit_log

logger = setup_logger("graph_analytics", log_level="INFO")

class GraphAnalyticsEngine:
    def __init__(self):
        self.cache = AnalyticsCache()
        self.executor = ThreadPoolExecutor(max_workers=8)

    def _hash_graph(self, graph: Dict[str, Any]) -> str:
        return hashlib.sha512(str(graph).encode()).hexdigest()

    def analyze(self, graph: Dict[str, Any], force: bool = False) -> Dict[str, Any]:
        validate_graph_schema(graph)
        graph_hash = self._hash_graph(graph)

        if not force and self.cache.contains(graph_hash):
            logger.info("Graph analytics loaded from cache.")
            return self.cache.get(graph_hash)

        logger.info("Starting graph analytics computation.")
        G = self._to_networkx(graph)
        results = {
            "node_count": G.number_of_nodes(),
            "edge_count": G.number_of_edges(),
            "density": nx.density(G),
            "degree_centrality": self._safe_map(nx.degree_centrality, G),
            "closeness_centrality": self._safe_map(nx.closeness_centrality, G),
            "betweenness_centrality": self._safe_map(nx.betweenness_centrality, G, normalized=True),
            "pagerank": self._safe_map(nx.pagerank, G),
            "communities": self._detect_communities(G),
            "entropy": calculate_entropy(G),
            "anomaly_nodes": detect_anomaly_nodes(G),
        }

        self.cache.set(graph_hash, results)
        graph_audit_log("graph_analyzed", {
            "hash": graph_hash,
            "nodes": results["node_count"],
            "edges": results["edge_count"]
        })
        return results

    def _to_networkx(self, graph: Dict[str, Any]) -> nx.Graph:
        G = nx.Graph()
        for node in graph.get("nodes", []):
            G.add_node(node["id"], **node.get("attributes", {}))
        for edge in graph.get("edges", []):
            G.add_edge(edge["source"], edge["target"], **edge.get("attributes", {}))
        return G

    def _safe_map(self, func, graph: nx.Graph, **kwargs) -> Dict[str, float]:
        try:
            result = func(graph, **kwargs)
            return {str(k): float(v) for k, v in result.items()}
        except Exception as e:
            logger.error(f"Failed analytics: {func.__name__} - {str(e)}")
            return {}

    def _detect_communities(self, graph: nx.Graph) -> List[List[str]]:
        try:
            from networkx.algorithms.community import greedy_modularity_communities
            communities = greedy_modularity_communities(graph)
            return [[str(node) for node in group] for group in communities]
        except Exception as e:
            logger.error(f"Community detection failed: {str(e)}")
            return []
