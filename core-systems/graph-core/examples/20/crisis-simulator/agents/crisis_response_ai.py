# crisis_response_ai.py

"""
Crisis Response AI — автономный агент обработки чрезвычайных ситуаций.
Агент работает в условиях неопределённости и мультифакторного риска, принимает оптимальные решения
на основе симуляционных моделей, поведенческих предсказаний и социальных метрик.

Уровень надежности: промышленный
Уровень автономности: оперативный / автономный (configurable)
"""

import logging
from typing import Dict, Any

from crisis_simulator.core.models import CrisisInputData, MitigationAction
from crisis_simulator.core.policies import PolicyDecisionEngine
from crisis_simulator.core.predictors import ThreatImpactPredictor
from crisis_simulator.core.simulator import CrisisEnvironment
from crisis_simulator.core.risk.assessor import DynamicRiskAssessor
from crisis_simulator.core.logger.explain import ExplainableDecisionLogger

logger = logging.getLogger("CrisisResponseAI")

class CrisisResponseAI:
    def __init__(
        self,
        environment: CrisisEnvironment,
        policy_engine: PolicyDecisionEngine,
        risk_model: DynamicRiskAssessor,
        predictor: ThreatImpactPredictor,
        explain_mode: bool = True
    ):
        self.env = environment
        self.policy_engine = policy_engine
        self.risk_model = risk_model
        self.predictor = predictor
        self.explain_mode = explain_mode
        self.explainer = ExplainableDecisionLogger(enabled=explain_mode)

    def process_event(self, input_data: CrisisInputData) -> MitigationAction:
        logger.info(f"[AGENT] Обработка события {input_data.event_type} в регионе {input_data.region}")
        
        risk_score = self.risk_model.assess(input_data)
        impact_prediction = self.predictor.predict(input_data)
        
        logger.debug(f"[AGENT] Расчёт риска: {risk_score}, Прогноз последствий: {impact_prediction}")
        
        action_plan = self.policy_engine.decide(
            risk_level=risk_score,
            impact=impact_prediction,
            context=input_data.context
        )

        if self.explain_mode:
            self.explainer.log_decision(
                input=input_data,
                risk=risk_score,
                impact=impact_prediction,
                decision=action_plan
            )

        return action_plan

    def reevaluate_policy(self, new_data: Dict[str, Any]):
        logger.info("[AGENT] Перестройка стратегии в реальном времени.")
        self.policy_engine.update_policies(new_data)
