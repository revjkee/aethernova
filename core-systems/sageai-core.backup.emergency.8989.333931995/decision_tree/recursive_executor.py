# path: sageai-core/decision_tree/recursive_executor.py

from typing import List, Dict, Any, Optional, Union
from pydantic import BaseModel, Field
import uuid
import logging
import time

logger = logging.getLogger("RecursiveExecutor")
logger.setLevel(logging.INFO)


class StrategyNode(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    params: Dict[str, Any] = Field(default_factory=dict)
    children: List['StrategyNode'] = Field(default_factory=list)
    depth: int = 0
    priority: float = 1.0
    active: bool = True
    terminal: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ExecutionResult(BaseModel):
    node_id: str
    success: bool
    output: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    children_results: List['ExecutionResult'] = Field(default_factory=list)


class RecursiveExecutor:
    def __init__(self, max_depth: int = 12, timeout: float = 10.0):
        self.max_depth = max_depth
        self.timeout = timeout
        self.execution_start_time = time.time()

    def execute_node(self, node: StrategyNode, context: Dict[str, Any]) -> ExecutionResult:
        if not node.active:
            logger.info(f"Skipping inactive node {node.name} ({node.id})")
            return ExecutionResult(node_id=node.id, success=False, error="Node inactive")

        if node.depth > self.max_depth:
            logger.warning(f"Max depth exceeded for node {node.name} ({node.id})")
            return ExecutionResult(node_id=node.id, success=False, error="Max depth exceeded")

        if time.time() - self.execution_start_time > self.timeout:
            logger.warning(f"Timeout reached for node {node.name} ({node.id})")
            return ExecutionResult(node_id=node.id, success=False, error="Execution timeout")

        logger.info(f"Executing node {node.name} ({node.id}) at depth {node.depth}")
        try:
            result = self._execute_strategy(node, context)
            result.node_id = node.id

            for child in sorted(node.children, key=lambda c: -c.priority):
                child.depth = node.depth + 1
                child_result = self.execute_node(child, context)
                result.children_results.append(child_result)

            return result
        except Exception as e:
            logger.error(f"Error in node {node.name} ({node.id}): {str(e)}")
            return ExecutionResult(node_id=node.id, success=False, error=str(e))

    def _execute_strategy(self, node: StrategyNode, context: Dict[str, Any]) -> ExecutionResult:
        # Placeholder for domain-specific strategy execution
        output = {
            "strategy": node.name,
            "executed_at": time.time(),
            "params": node.params,
            "context_snapshot": dict(context),
        }
        logger.debug(f"Executed strategy logic for node {node.name} ({node.id})")
        return ExecutionResult(node_id=node.id, success=True, output=output)

    def walk_tree(self, root: StrategyNode, context: Dict[str, Any]) -> ExecutionResult:
        self.execution_start_time = time.time()
        return self.execute_node(root, context)

    def flatten_strategies(self, root: StrategyNode) -> List[StrategyNode]:
        result = []

        def _traverse(n: StrategyNode):
            result.append(n)
            for c in n.children:
                _traverse(c)

        _traverse(root)
        return result

    def deactivate_by_criteria(self, root: StrategyNode, key: str, value: Any):
        for node in self.flatten_strategies(root):
            if node.params.get(key) == value:
                node.active = False
                logger.info(f"Node {node.name} ({node.id}) deactivated by criteria")

    def analyze_priority_path(self, root: StrategyNode) -> List[str]:
        path = []
        node = root
        while node.children:
            path.append(node.name)
            node = max(node.children, key=lambda c: c.priority)
        path.append(node.name)
        return path
