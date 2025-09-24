"""
agent_goal_evaluator.py

Модуль оценки целей и мотивации AGI-агента.
Оценивает релевантность, полезность, достижимость и риски целей в текущем контексте.

Ключевые функции:
- Расчёт мотивационного веса
- Динамическая переоценка при изменении внешних условий
- Механизм фокусировки и отбрасывания ложных или устаревших целей
"""

import math
import logging
from typing import List, Dict, Tuple, Optional
from genius_core.common.context import AgentContext
from genius_core.common.models import Goal, GoalEvaluationResult

logger = logging.getLogger("AgentGoalEvaluator")
logger.setLevel(logging.INFO)

# Константы весов мотивации
RELEVANCE_WEIGHT = 0.4
UTILITY_WEIGHT = 0.3
ACHIEVABILITY_WEIGHT = 0.2
RISK_PENALTY_WEIGHT = 0.1

# Порог для активации цели
ACTIVATION_THRESHOLD = 0.6


class AgentGoalEvaluator:
    def __init__(self, context: AgentContext):
        self.context = context
        self.evaluation_cache: Dict[str, GoalEvaluationResult] = {}

    def evaluate_goal(self, goal: Goal) -> GoalEvaluationResult:
        if goal.id in self.evaluation_cache:
            return self.evaluation_cache[goal.id]

        relevance = self._calculate_relevance(goal)
        utility = self._estimate_utility(goal)
        achievability = self._estimate_achievability(goal)
        risk_penalty = self._assess_risk(goal)

        motivation_score = (
            RELEVANCE_WEIGHT * relevance +
            UTILITY_WEIGHT * utility +
            ACHIEVABILITY_WEIGHT * achievability -
            RISK_PENALTY_WEIGHT * risk_penalty
        )

        motivation_score = max(0.0, min(1.0, motivation_score))  # нормализация

        result = GoalEvaluationResult(
            goal_id=goal.id,
            motivation_score=motivation_score,
            is_activated=motivation_score >= ACTIVATION_THRESHOLD,
            factors={
                "relevance": relevance,
                "utility": utility,
                "achievability": achievability,
                "risk_penalty": risk_penalty
            }
        )

        self.evaluation_cache[goal.id] = result
        logger.debug(f"Оценка цели {goal.name}: {result}")
        return result

    def _calculate_relevance(self, goal: Goal) -> float:
        context_tags = self.context.get_active_tags()
        match_count = len(set(goal.tags) & set(context_tags))
        relevance = match_count / max(len(goal.tags), 1)
        logger.debug(f"Relevance for goal {goal.id}: {relevance}")
        return relevance

    def _estimate_utility(self, goal: Goal) -> float:
        return min(1.0, max(0.0, goal.estimated_benefit))

    def _estimate_achievability(self, goal: Goal) -> float:
        if goal.estimated_effort <= 0:
            return 0.0
        return min(1.0, 1.0 / math.log1p(goal.estimated_effort))

    def _assess_risk(self, goal: Goal) -> float:
        return min(1.0, goal.risk_factor)

    def reevaluate_all(self, goals: List[Goal]) -> List[GoalEvaluationResult]:
        results = []
        self.evaluation_cache.clear()
        for goal in goals:
            results.append(self.evaluate_goal(goal))
        return results
