# path: sageai-core/reasoning_engine/critical_path_solver.py

import networkx as nx
from typing import List, Dict, Optional, Tuple, Any
from pydantic import BaseModel, Field
from loguru import logger
import uuid
import heapq


class ThoughtNode(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    content: str
    weight: float
    dependencies: List[str] = []

class CriticalPathResult(BaseModel):
    path: List[str]
    total_weight: float
    reasoning_trace: List[str]

class CriticalPathSolver:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.node_map: Dict[str, ThoughtNode] = {}

    def add_thought(self, node: ThoughtNode):
        logger.debug(f"Adding node: {node.id} [{node.content}]")
        self.graph.add_node(node.id, weight=node.weight)
        self.node_map[node.id] = node
        for dep_id in node.dependencies:
            self.graph.add_edge(dep_id, node.id)

    def compute_critical_path(self) -> CriticalPathResult:
        if not nx.is_directed_acyclic_graph(self.graph):
            raise ValueError("Dependency graph must be a DAG (no cycles allowed)")

        longest_paths: Dict[str, Tuple[float, List[str]]] = {}

        for node in nx.topological_sort(self.graph):
            preds = list(self.graph.predecessors(node))
            node_weight = self.graph.nodes[node]['weight']

            if not preds:
                longest_paths[node] = (node_weight, [node])
            else:
                best_pred = max(
                    (longest_paths[p] for p in preds),
                    key=lambda x: x[0],
                    default=(0, [])
                )
                longest_paths[node] = (best_pred[0] + node_weight, best_pred[1] + [node])

        critical_end = max(longest_paths.items(), key=lambda x: x[1][0])
        total_weight, path = critical_end[1]
        trace = [self.node_map[n].content for n in path]

        logger.info(f"Critical path: {path} | Weight: {total_weight}")
        return CriticalPathResult(path=path, total_weight=total_weight, reasoning_trace=trace)

    def reset(self):
        logger.debug("Resetting solver state")
        self.graph.clear()
        self.node_map.clear()

    def visualize(self, path: Optional[List[str]] = None) -> Any:
        try:
            import matplotlib.pyplot as plt

            pos = nx.spring_layout(self.graph)
            weights = nx.get_node_attributes(self.graph, 'weight')

            nx.draw(self.graph, pos, with_labels=True, node_color='lightblue', node_size=2000, font_size=10)
            nx.draw_networkx_labels(self.graph, pos, labels={n: f"{n[:4]} ({weights[n]})" for n in self.graph.nodes})

            if path:
                edges = [(path[i], path[i + 1]) for i in range(len(path) - 1)]
                nx.draw_networkx_edges(self.graph, pos, edgelist=edges, edge_color='r', width=2)

            plt.title("Critical Thought Graph")
            plt.show()

        except ImportError:
            logger.warning("matplotlib not installed. Skipping visualization.")

