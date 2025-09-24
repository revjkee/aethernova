# path: sageai-core/decision_tree/goal_conflict_resolver.py

from typing import List, Dict, Any, Tuple
from pydantic import BaseModel, Field
import uuid
import logging
import numpy as np

logger = logging.getLogger("GoalConflictResolver")
logger.setLevel(logging.INFO)


class Goal(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    importance: float
    urgency: float
    context_score: float = 0.0
    constraints: Dict[str, Any] = Field(default_factory=dict)
    incompatible_with: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ResolutionDecision(BaseModel):
    resolved_goals: List[Goal]
    dropped_goals: List[Goal]
    conflict_matrix: List[Tuple[str, str]] = Field(default_factory=list)


class GoalConflictResolver:
    def __init__(self, threshold: float = 0.6):
        self.conflict_threshold = threshold

    def resolve_conflicts(self, goals: List[Goal], context: Dict[str, Any]) -> ResolutionDecision:
        logger.info(f"Resolving conflicts among {len(goals)} goals...")
        active_goals = self._filter_compatible(goals)
        scored_goals = self._score_goals(active_goals, context)
        selected, dropped = self._select_resolved_goals(scored_goals)
        matrix = self._build_conflict_matrix(goals)
        return ResolutionDecision(
            resolved_goals=selected,
            dropped_goals=dropped,
            conflict_matrix=matrix
        )

    def _score_goals(self, goals: List[Goal], context: Dict[str, Any]) -> List[Tuple[Goal, float]]:
        scored = []
        for g in goals:
            g.context_score = self._evaluate_context(g, context)
            score = (g.importance * 0.5 + g.urgency * 0.3 + g.context_score * 0.2)
            scored.append((g, score))
            logger.debug(f"Scored goal {g.name}: {score}")
        return sorted(scored, key=lambda x: -x[1])

    def _evaluate_context(self, goal: Goal, context: Dict[str, Any]) -> float:
        match_score = 0.0
        for k, v in goal.constraints.items():
            if context.get(k) == v:
                match_score += 1.0
        normalized_score = match_score / max(1, len(goal.constraints))
        logger.debug(f"Context score for goal {goal.name}: {normalized_score}")
        return normalized_score

    def _select_resolved_goals(self, scored_goals: List[Tuple[Goal, float]]) -> Tuple[List[Goal], List[Goal]]:
        resolved = []
        dropped = []
        seen = set()
        for goal, _ in scored_goals:
            if goal.id in seen:
                continue
            if any(incomp in seen for incomp in goal.incompatible_with):
                dropped.append(goal)
                continue
            resolved.append(goal)
            seen.add(goal.id)
        return resolved, dropped
