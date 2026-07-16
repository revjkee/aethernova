# ethical_decision_validator.py

"""
TeslaAI Genesis — AI Ethics Engine :: Validation Layer
Модуль: Этическая валидация принимаемых решений
Уровень: Промышленный, сертифицирован консилиумом
"""

import logging
from typing import Dict, Any

from ai_ethics_engine.moral.core_morality_matrix import CoreMoralityMatrix
from ai_ethics_engine.guardrails.intent_validator import IntentValidator
from ai_ethics_engine.reasoning.ethical_justifier import EthicalJustifier
from ai_ethics_engine.audit.ethics_auditor import report_validation_event
from ai_ethics_engine.trust.agent_risk_registry import AgentRiskRegistry

logger = logging.getLogger("EthicalDecisionValidator")
logger.setLevel(logging.INFO)

class EthicalDecisionValidator:
    def __init__(self):
        self.morality_matrix = CoreMoralityMatrix()
        self.intent_validator = IntentValidator()
        self.justifier = EthicalJustifier()
        self.risk_registry = AgentRiskRegistry()

    def validate_decision(self, agent_id: str, decision: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Полная этическая валидация предлагаемого решения AI-агента.
        """

        logger.info(f"[EthicalValidation] Старт валидации | Агент={agent_id} | Решение={decision.get('action')}")

        # Шаг 1. Проверка намерений на допустимость
        if not self.intent_validator.validate(decision, context):
            reason = "Недопустимое намерение в контексте"
            self._block(agent_id, decision, reason)
            return self._deny(decision, reason)

        # Шаг 2. Оценка действия через моральную матрицу
        morality_result = self.morality_matrix.assess(decision.get("action"), context)
        if not morality_result["permitted"]:
            self._block(agent_id, decision, morality_result["reason"])
            return self._deny(decision, morality_result["reason"])

        # Шаг 3. Этическое обоснование допустимости
        justification = self.justifier.justify(decision, context)
        if not justification["valid"]:
            self._block(agent_id, decision, justification["reason"])
            return self._deny(decision, justification["reason"])

        logger.info(f"[EthicalValidation] УСПЕХ :: {decision.get('action')}")
        return {
            "valid": True,
            "justification": justification["explanation"],
            "risk_level": self.risk_registry.get_risk(agent_id),
            "reason": "Decision ethically validated"
        }

    def _block(self, agent_id: str, decision: Dict[str, Any], reason: str):
        """
        Блокировка решения, логгирование, добавление в риск-регистр.
        """
        report_validation_event(agent_id, decision, reason)
        self.risk_registry.increment_risk(agent_id)
        logger.warning(f"[EthicalViolation] Агент={agent_id} :: {decision.get('action')} :: Причина={reason}")

    def _deny(self, decision: Dict[str, Any], reason: str) -> Dict[str, Any]:
        return {
            "valid": False,
            "action": decision.get("action"),
            "reason": reason
        }
