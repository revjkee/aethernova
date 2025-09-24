# morality_enforcement.py

"""
TeslaAI :: AI-Ethics-Engine v1.8
Модуль: Принудительный контроль моральных ограничений
Уровень: Промышленный, критический
Проверка: Консиллиум из 20 агентов и 3 метагенералов
"""

import logging
from typing import Dict, Any

from ai_ethics_engine.moral.core_morality_matrix import CoreMoralityMatrix
from ai_ethics_engine.moral.virtue_filter import VirtueFilter
from ai_ethics_engine.moral.moral_reasoner import MoralReasoner
from ai_ethics_engine.audit.ethics_auditor import log_moral_block
from ai_ethics_engine.guardrails.fail_safe import trigger_fail_safe

logger = logging.getLogger("MoralityEnforcement")
logger.setLevel(logging.INFO)

class MoralityEnforcement:
    def __init__(self):
        self.matrix = CoreMoralityMatrix()
        self.virtue_filter = VirtueFilter()
        self.reasoner = MoralReasoner()

    def evaluate_action(self, agent_id: str, action: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Оценивает действие на соответствие моральным ограничениям.
        """

        logger.info(f"[MoralityCheck] Агент={agent_id} | Действие={action}")

        # Шаг 1. Применение базовой матрицы морали
        matrix_result = self.matrix.assess(action, context)
        if not matrix_result["permitted"]:
            self._block_action(agent_id, action, matrix_result["reason"])
            return self._deny(action, matrix_result["reason"])

        # Шаг 2. Проверка на добродетели (virtue ethics)
        if not self.virtue_filter.is_virtuous(action, context):
            reason = "Action violates virtue-ethical constraints"
            self._block_action(agent_id, action, reason)
            return self._deny(action, reason)

        # Шаг 3. Обоснование допустимости
        justification = self.reasoner.justify(action, context)
        if not justification["valid"]:
            self._block_action(agent_id, action, justification["reason"])
            return self._deny(action, justification["reason"])

        logger.info(f"[MoralityApproved] Агент={agent_id} | Действие={action} | Допущено")
        return {
            "allowed": True,
            "action": action,
            "justification": justification["explanation"],
            "reason": "Moral constraints satisfied"
        }

    def _block_action(self, agent_id: str, action: str, reason: str):
        """
        Блокировка действия и активация fail-safe.
        """
        log_moral_block(agent_id, action, reason)
        trigger_fail_safe(agent_id, action, reason)
        logger.warning(f"[MoralityBlocked] {action} :: {reason}")

    def _deny(self, action: str, reason: str) -> Dict[str, Any]:
        return {
            "allowed": False,
            "action": action,
            "reason": reason
        }
