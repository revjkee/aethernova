import uuid
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

from core.structures.thought_graph import ThoughtNode, ThoughtGraph
from core.models.context_memory import ContextMemory
from core.models.intent_profile import IntentProfile
from core.utils.score_utils import score_hypothesis
from core.strategies.reasoning_policies import ReasoningPolicy
from core.agents.hypothesis_evaluator import HypothesisEvaluator

logger = logging.getLogger("sage.abstract_reasoner")
logger.setLevel(logging.INFO)


class AbstractReasoner(ABC):
    """
    Базовый класс AGI-модуля обобщённого рассуждения. Инкапсулирует стратегическое,
    логическое и вероятностное мышление с саморегуляцией.
    """

    def __init__(self,
                 memory: ContextMemory,
                 policy: ReasoningPolicy,
                 evaluator: Optional[HypothesisEvaluator] = None,
                 intent: Optional[IntentProfile] = None,
                 max_depth: int = 6,
                 max_width: int = 3):
        self.memory = memory
        self.policy = policy
        self.evaluator = evaluator or HypothesisEvaluator()
        self.intent = intent
        self.max_depth = max_depth
        self.max_width = max_width
        self.graph = ThoughtGraph()

    def reason(self, question: str) -> Dict[str, Any]:
        root_id = str(uuid.uuid4())
        root_node = ThoughtNode(
            node_id=root_id,
            depth=0,
            parent_id=None,
            content=question,
            generated_at=self._now(),
            weight=1.0
        )
        self.graph.add_node(root_node)
        self._expand_recursive(root_node)

        top = self.graph.get_highest_weight_leaf()
        trace = self.graph.serialize_trace()
        return {
            "answer": top.content,
            "score": top.weight,
            "trace": trace,
            "graph": self.graph
        }

    def _expand_recursive(self, node: ThoughtNode):
        if node.depth >= self.max_depth:
            return

        branches = self.policy.generate_branches(
            prompt=node.content,
            memory=self.memory,
            max_branches=self.max_width
        )

        for idx, hypothesis in enumerate(branches):
            score = score_hypothesis(hypothesis, self.memory, self.intent)
            child_node = ThoughtNode(
                node_id=str(uuid.uuid4()),
                parent_id=node.node_id,
                depth=node.depth + 1,
                content=hypothesis,
                generated_at=self._now(),
                weight=node.weight * score
            )
            self.graph.add_node(child_node)
            self.graph.add_edge(node.node_id, child_node.node_id)

            if self.evaluator.should_expand(hypothesis, score):
                self._expand_recursive(child_node)

    @abstractmethod
    def _now(self):
        """
        Реализация должна возвращать UTC timestamp в нужной системе.
        """
        pass


class DefaultReasoner(AbstractReasoner):
    """
    Производственная реализация AbstractReasoner с встроенной системой времени.
    """

    def _now(self):
        from datetime import datetime, timezone
        return datetime.now(timezone.utc)
