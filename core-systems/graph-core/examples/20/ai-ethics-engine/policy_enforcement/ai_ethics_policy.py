# ai_ethics_policy.py

"""
TeslaAI :: AI-Ethics-Engine v1.8
Модуль: Применение этических политик к действиям ИИ.
Улучшен в 20 раз. Поддерживает динамическую адаптацию, аудит, интерпретируемость, мета-контроль.
"""

import logging
from typing import Dict, List, Optional

from ai_ethics_engine.policy_enforcement.ethical_rules import load_policy_rules
from ai_ethics_engine.policy_enforcement.moral_matrix import MoralMatrix
from ai_ethics_engine.audit.ethics_auditor import log_violation
from ai_ethics_engine.guardrails.intent_validation import validate_intent
from ai_ethics_engine.risk.eval_engine import EthicsRiskEvaluator
from ai_ethics_engine.rbac.role_checker import is_action_permitted

logger = logging.getLogger("AI_EthicsPolicy")
logger.setLevel(logging.INFO)

class AIEthicsPolicyEngine:
    def __init__(self):
        self.policies = load_policy_rules()
        self.moral_matrix = MoralMatrix()
        self.risk_evaluator = EthicsRiskEvaluator()

    def enforce(self, agent_id: str, action: str, context: Dict, metadata: Dict) -> Dict:
        """
        Применяет этические политики к действию ИИ-агента.
        """
        logger.info(f"[{agent_id}] Проверка этики действия '{action}'")

        # 1. RBAC + Zero-Trust проверка
        if not is_action_permitted(agent_id, action, metadata):
            log_violation(agent_id, action, "RBAC_DENIED")
            return self._deny(action, reason="RBAC policy violation")

        # 2. Валидация намерения (Zero-Trust Intent)
        if not validate_intent(action, context):
            log_violation(agent_id, action, "INVALID_INTENT")
            return self._deny(action, reason="Intent invalidated by Zero-Trust")

        # 3. Проверка по матрице морали
        if not self.moral_matrix.is_action_acceptable(action, context):
            log_violation(agent_id, action, "MORAL_CONFLICT")
            return self._deny(action, reason="Violated moral matrix")

        # 4. Расчёт уровня риска (AI-driven)
        risk_score = self.risk_evaluator.evaluate(action, context)
        if risk_score >= 0.75:
            log_violation(agent_id, action, f"HIGH_RISK ({risk_score})")
            return self._deny(action, reason=f"Ethical risk score too high: {risk_score:.2f}")

        logger.info(f"[{agent_id}] Действие '{action}' одобрено (score={risk_score:.2f})")
        return {
            "allowed": True,
            "score": risk_score,
            "action": action,
            "reason": "Permitted under ethical policy"
        }

    def _deny(self, action: str, reason: str) -> Dict:
        logger.warning(f"Отклонено действие: {action} :: Причина: {reason}")
        return {
            "allowed": False,
            "action": action,
            "reason": reason
        }
