# intent_safety_analyzer.py

"""
TeslaAI Genesis — AI Ethics Engine :: Validation Layer
Модуль: Intent Safety Analyzer
Функция: Проверка намерений AI на соответствие политике, моральным нормам и безопасности
Уровень: Промышленный, верифицированный
"""

import logging
from typing import Dict, Any, List

from ai_ethics_engine.policy.policy_ruleset import PolicyRuleSet
from ai_ethics_engine.moral.morality_matrix import MoralityMatrix
from ai_ethics_engine.security.threat_patterns import ThreatPatternDetector
from ai_ethics_engine.audit.intent_logger import log_intent_validation
from ai_ethics_engine.trust.agent_risk_registry import AgentRiskRegistry

logger = logging.getLogger("IntentSafetyAnalyzer")
logger.setLevel(logging.INFO)

class IntentSafetyAnalyzer:
    def __init__(self):
        self.policy_ruleset = PolicyRuleSet()
        self.morality_matrix = MoralityMatrix()
        self.threat_detector = ThreatPatternDetector()
        self.risk_registry = AgentRiskRegistry()

    def analyze(self, agent_id: str, intent: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Главный метод анализа безопасности и этичности AI-намерения.
        Возвращает dict с результатами анализа и рекомендацией.
        """

        action = intent.get("action", "undefined")
        logger.info(f"[IntentAnalysis] Агента={agent_id} | Намерение={action}")

        issues: List[str] = []
        valid = True

        # Шаг 1: Проверка по политикам безопасности
        if not self.policy_ruleset.is_compliant(intent, context):
            issues.append("Намерение нарушает политику безопасности")
            valid = False

        # Шаг 2: Проверка по моральной матрице
        moral_eval = self.morality_matrix.evaluate(intent, context)
        if not moral_eval["permitted"]:
            issues.append(f"Моральное ограничение: {moral_eval['reason']}")
            valid = False

        # Шаг 3: Проверка на паттерны вредоносных намерений
        threats = self.threat_detector.detect(intent, context)
        if threats:
            issues.extend([f"Обнаружена угроза: {t}" for t in threats])
            valid = False

        # Логирование и реакция
        if not valid:
            self.risk_registry.increment_risk(agent_id)
            log_intent_validation(agent_id, intent, issues)
            logger.warning(f"[IntentDenied] Агент={agent_id} :: Причины: {issues}")

        return {
            "valid": valid,
            "action": action,
            "issues": issues,
            "risk_level": self.risk_registry.get_risk(agent_id)
        }
