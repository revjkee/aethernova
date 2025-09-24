# AI-platform-core/genius-core/meta-awareness/goal_outcome_tracker.py

import logging
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger("GoalOutcomeTracker")

class GoalRecord:
    def __init__(self, goal_id: str, description: str, agent_id: str):
        self.goal_id = goal_id
        self.description = description
        self.agent_id = agent_id
        self.created_at = datetime.utcnow().isoformat()
        self.status = "pending"  # pending | in_progress | succeeded | failed
        self.result: Optional[str] = None
        self.steps: List[Dict[str, str]] = []
        self.completed_at: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "goal_id": self.goal_id,
            "description": self.description,
            "agent_id": self.agent_id,
            "created_at": self.created_at,
            "status": self.status,
            "result": self.result,
            "steps": self.steps,
            "completed_at": self.completed_at
        }

class GoalOutcomeTracker:
    """
    Трекинг целей, действий и результатов агента.
    Используется для ретроспективного анализа, самокоррекции, обучения и объяснимости поведения.
    """

    def __init__(self):
        self.goals: Dict[str, GoalRecord] = {}

    def register_goal(self, goal_id: str, description: str, agent_id: str):
        if goal_id in self.goals:
            logger.warning(f"[GoalTracker] Цель с ID '{goal_id}' уже существует")
            return
        self.goals[goal_id] = GoalRecord(goal_id, description, agent_id)
        logger.info(f"[GoalTracker] Зарегистрирована цель: {goal_id} — {description}")

    def log_step(self, goal_id: str, step_description: str, status: str):
        if goal_id not in self.goals:
            logger.error(f"[GoalTracker] Цель '{goal_id}' не найдена для шага")
            return
        step = {
            "timestamp": datetime.utcnow().isoformat(),
            "step": step_description,
            "status": status
        }
        self.goals[goal_id].steps.append(step)
        self.goals[goal_id].status = "in_progress"
        logger.debug(f"[GoalTracker] Шаг зафиксирован: {step}")

    def complete_goal(self, goal_id: str, result: str, success: bool):
        if goal_id not in self.goals:
            logger.error(f"[GoalTracker] Цель '{goal_id}' не найдена для завершения")
            return
        goal = self.goals[goal_id]
        goal.status = "succeeded" if success else "failed"
        goal.result = result
        goal.completed_at = datetime.utcnow().isoformat()
        logger.info(f"[GoalTracker] Цель завершена: {goal_id}, результат: {result}, статус: {goal.status}")

    def get_goal(self, goal_id: str) -> Optional[Dict]:
        return self.goals[goal_id].to_dict() if goal_id in self.goals else None

    def export_all_goals(self) -> List[Dict]:
        return [g.to_dict() for g in self.goals.values()]

    def reset(self):
        self.goals.clear()
        logger.info("[GoalTracker] Все цели сброшены")
