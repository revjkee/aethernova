import uuid
import logging
from typing import Any, Dict, List, Optional, Callable, Tuple
from datetime import datetime

from core.structures.thought_graph import ThoughtNode, ThoughtGraph
from core.models.context_memory import ContextMemory
from core.strategies.reasoning_policies import ReasoningPolicy
from core.utils.time_control import utc_now

logger = logging.getLogger("sage.thought_simulator")
logger.setLevel(logging.INFO)


class ThoughtSimulator:
    def __init__(self,
                 max_depth: int = 8,
                 max_branches: int = 4,
                 branch_strategy: Optional[Callable] = None,
                 correction_enabled: bool = True,
                 weight_decay: float = 0.85):
        self.max_depth = max_depth
        self.max_branches = max_branches
        self.branch_strategy = branch_strategy or self.default_branch_strategy
        self.correction_enabled = correction_enabled
        self.weight_decay = weight_decay

    def simulate(self,
                 input_prompt: str,
                 memory: ContextMemory,
                 policy: ReasoningPolicy,
                 trace_enabled: bool = True) -> Dict[str, Any]:
        """
        Стартует симуляцию мышления: строит дерево мысли, активирует policy, возвращает результат и трассировку.
        """
        root_id = str(uuid.uuid4())
        graph = ThoughtGraph()
        root_node = ThoughtNode(
            node_id=root_id,
            depth=0,
            parent_id=None,
            content=input_prompt,
            generated_at=utc_now(),
            weight=1.0
        )
        graph.add_node(root_node)

        self._expand(graph, root_node, memory, policy)

        if trace_enabled:
            trace = graph.serialize_trace()
        else:
            trace = {}

        best_leaf = graph.get_highest_weight_leaf()
        return {
            "final_thought": best_leaf.content,
            "trace": trace,
            "graph": graph
        }

    def _expand(self,
                graph: ThoughtGraph,
                current_node: ThoughtNode,
                memory: ContextMemory,
                policy: ReasoningPolicy):
        """
        Рекурсивно расширяет ветви размышлений, применяя стратегию разветвления и контекстную память.
        """
        if current_node.depth >= self.max_depth:
            return

        thoughts = self.branch_strategy(current_node.content, memory, policy, self.max_branches)
        for idx, t in enumerate(thoughts):
            node_id = str(uuid.uuid4())
            weight = current_node.weight * (self.weight_decay ** (idx + 1))
            child_node = ThoughtNode(
                node_id=node_id,
                parent_id=current_node.node_id,
                depth=current_node.depth + 1,
                content=t,
                generated_at=utc_now(),
                weight=weight
            )
            graph.add_node(child_node)
            graph.add_edge(current_node.node_id, node_id)
            if self.correction_enabled:
                t_corr = policy.correction(t, memory)
                if t_corr and t_corr != t:
                    correction_node = ThoughtNode(
                        node_id=str(uuid.uuid4()),
                        parent_id=node_id,
                        depth=child_node.depth + 1,
                        content=t_corr,
                        generated_at=utc_now(),
                        weight=weight * 0.95
                    )
                    graph.add_node(correction_node)
                    graph.add_edge(node_id, correction_node.node_id)
                    continue
            self._expand(graph, child_node, memory, policy)

    def default_branch_strategy(self,
                                prompt: str,
                                memory: ContextMemory,
                                policy: ReasoningPolicy,
                                max_branches: int) -> List[str]:
        """
        Дефолтная стратегия ветвления: policy выдает n логических вариантов ответа/шага.
        """
        return policy.generate_branches(prompt, memory, max_branches)
