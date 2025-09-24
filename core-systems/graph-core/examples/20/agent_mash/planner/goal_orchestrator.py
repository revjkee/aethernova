# agent-mesh/planner/goal_orchestrator.py

from typing import Dict, Any, Optional
from agent_mesh.strategy_router import StrategyRouter
from agent_mesh.core.agent_message import AgentMessage
from uuid import uuid4
import time
import logging

logger = logging.getLogger("GoalOrchestrator")


class GoalOrchestrator:
    """
    Постановщик и управляющий целей среди агентов.
    Делегирует задачи в зависимости от типа цели и стратегии исполнения (LLM, RL, Rule).
    """

    def __init__(self, strategy_router: StrategyRouter):
        self.router = strategy_router
        self.active_goals: Dict[str, Dict[str, Any]] = {}  # goal_id -> metadata

    def create_goal(
        self,
        sender: str,
        task_type: str,
        payload: Dict[str, Any],
        priority: Optional[int] = 5,
        meta: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Создаёт новую цель и делегирует её подходящему агенту.
        Возвращает goal_id.
        """
        goal_id = str(uuid4())
        timestamp = time.time()

        message = AgentMessage(
            sender=sender,
            task_type=task_type,
            payload=payload,
            meta={
                "goal_id": goal_id,
                "priority": priority,
                "created_at": timestamp,
                **(meta or {})
            }
        )

        self.active_goals[goal_id] = {
            "status": "pending",
            "task_type": task_type,
            "sender": sender,
            "timestamp": timestamp,
            "payload": payload,
            "meta": message.meta
        }

        self.router.route(message)
        logger.info(f"Goal {goal_id} created and routed (type={task_type})")
        return goal_id

    def update_goal_status(self, goal_id: str, status: str):
        """
        Обновляет статус цели (например, 'in_progress', 'completed', 'failed')
        """
        if goal_id in self.active_goals:
            self.active_goals[goal_id]["status"] = status
            self.active_goals[goal_id]["updated_at"] = time.time()
            logger.debug(f"Goal {goal_id} status updated to {status}")
        else:
            logger.warning(f"Unknown goal_id: {goal_id}")

    def get_goal(self, goal_id: str) -> Optional[Dict[str, Any]]:
        """
        Получение информации о цели
        """
        return self.active_goals.get(goal_id)

    def list_goals(self, status_filter: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
        """
        Возвращает список всех целей, с опциональной фильтрацией по статусу
        """
        if status_filter:
            return {gid: g for gid, g in self.active_goals.items() if g["status"] == status_filter}
        return self.active_goals

    def cancel_goal(self, goal_id: str):
        """
        Отмена цели вручную
        """
        if goal_id in self.active_goals:
            self.active_goals[goal_id]["status"] = "cancelled"
            self.active_goals[goal_id]["cancelled_at"] = time.time()
            logger.info(f"Goal {goal_id} cancelled")
