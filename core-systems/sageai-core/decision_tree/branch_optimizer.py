# path: sageai-core/decision_tree/branch_optimizer.py

from typing import List, Dict, Any, Optional, Tuple
from pydantic import BaseModel, Field
from loguru import logger
import uuid
import math
import heapq


class DecisionNode(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    description: str
    utility: float
    children: List['DecisionNode'] = []
    probability: Optional[float] = 1.0
    is_terminal: bool = False


class OptimizedBranch(BaseModel):
    path: List[str]
    total_expected_utility: float
    nodes: List[DecisionNode]


class BranchOptimizer:
    def __init__(self):
        self.memo: Dict[str, float] = {}

    def optimize(self, root: DecisionNode) -> OptimizedBranch:
        logger.debug(f"Starting optimization from root node: {root.id}")
        max_utility, best_path, best_nodes = self._dfs_optimize(root)
        return OptimizedBranch(
            path=best_path,
            total_expected_utility=max_utility,
            nodes=best_nodes
        )

    def _dfs_optimize(
        self, node: DecisionNode, path: Optional[List[str]] = None
    ) -> Tuple[float, List[str], List[DecisionNode]]:
        if path is None:
            path = []

        current_path = path + [node.id]

        if node.is_terminal or not node.children:
            expected = node.utility * node.probability
            logger.debug(f"Terminal node reached: {node.id} with utility {expected}")
            return expected, current_path, [node]

        best_value = -math.inf
        best_sequence = []
        best_node_list = []

        for child in node.children:
            child_utility, child_path, child_nodes = self._dfs_optimize(child, current_path)
            total_utility = node.utility * node.probability + child_utility

            logger.debug(f"Evaluating path via {child.id}: expected utility {total_utility}")

            if total_utility > best_value:
                best_value = total_utility
                best_sequence = child_path
                best_node_list = [node] + child_nodes

        return best_value, best_sequence, best_node_list

    def prune_tree(self, node: DecisionNode, threshold: float) -> Optional[DecisionNode]:
        """Удаляет ветви, где utility ниже порога"""
        if node.utility < threshold and not node.children:
            logger.info(f"Pruning node {node.id} with utility {node.utility}")
            return None

        pruned_children = []
        for child in node.children:
            pruned_child = self.prune_tree(child, threshold)
            if pruned_child:
                pruned_children.append(pruned_child)
        node.children = pruned_children

        return node if pruned_children or node.utility >= threshold else None

    def flatten_tree(self, node: DecisionNode) -> List[DecisionNode]:
        """Разворачивает дерево в линейный список для анализа"""
        result = [node]
        for child in node.children:
            result.extend(self.flatten_tree(child))
        return result

    def visualize_tree(self, node: DecisionNode, level: int = 0):
        indent = "  " * level
        logger.info(f"{indent}- [{node.id[:4]}] {node.description} | U={node.utility:.2f} | P={node.probability}")
        for child in node.children:
            self.visualize_tree(child, level + 1)

