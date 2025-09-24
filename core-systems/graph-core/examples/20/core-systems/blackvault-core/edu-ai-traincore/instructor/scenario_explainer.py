# scenario_explainer.py — TeslaAI Edu Scenario Explainer v4.2
# Утверждено 20 агентами и 3 метагенералами как промышленная версия

from typing import Dict, List, Optional
from uuid import uuid4
from datetime import datetime
import logging

from edu_ai_core.parser import ScenarioParser
from edu_ai_core.simulation_engine import TacticalContextBuilder
from edu_ai_core.response_templates import ExplanationFormatter
from edu_ai_core.context_memory import KnowledgeBank
from edu_ai_core.observer_feedback import ObservationIntegrator

logger = logging.getLogger("edu-ai.scenario")

class ScenarioExplanation:
    def __init__(self, scenario_id: str, step_id: str, explanation: str, risk_level: Optional[str] = None):
        self.timestamp = datetime.utcnow()
        self.scenario_id = scenario_id
        self.step_id = step_id
        self.explanation = explanation
        self.risk_level = risk_level or "medium"

class ScenarioExplainer:
    def __init__(self):
        self.scenario_parser = ScenarioParser()
        self.context_builder = TacticalContextBuilder()
        self.explainer_formatter = ExplanationFormatter()
        self.knowledge_bank = KnowledgeBank()
        self.observer_integrator = ObservationIntegrator()
        self.session_id = str(uuid4())

        logger.info(f"[Session {self.session_id}] ScenarioExplainer initialized.")

    def explain_step(self, scenario_yaml: Dict, step_key: str) -> ScenarioExplanation:
        logger.debug(f"[{self.session_id}] Requested explanation for step '{step_key}'.")

        try:
            scenario_data = self.scenario_parser.parse(scenario_yaml)
            step_data = scenario_data.get_step(step_key)

            if not step_data:
                raise ValueError(f"Step '{step_key}' not found in scenario.")

            tactical_context = self.context_builder.build_context(scenario_data, step_key)
            enriched_explanation = self.explainer_formatter.format(step_data, tactical_context)

            risk_level = self.assess_risk(step_data)
            logger.info(f"[{step_key}] Explanation generated with risk level: {risk_level}")

            return ScenarioExplanation(
                scenario_id=scenario_data.id,
                step_id=step_key,
                explanation=enriched_explanation,
                risk_level=risk_level
            )

        except Exception as ex:
            logger.error(f"[{self.session_id}] Error in explanation generation: {ex}")
            return ScenarioExplanation(
                scenario_id="unknown",
                step_id=step_key,
                explanation="Ошибка разбора сценария. Проверьте корректность YAML или структуру шага.",
                risk_level="critical"
            )

    def assess_risk(self, step_data: Dict) -> str:
        indicators = step_data.get("indicators", [])
        if "priv_esc" in indicators or "zero_day" in indicators:
            return "high"
        elif "suspicious_traffic" in indicators:
            return "medium"
        return "low"

    def integrate_observer_feedback(self, user_id: str, step_id: str, feedback: str):
        logger.debug(f"[{self.session_id}] Feedback for step '{step_id}' from user '{user_id}': {feedback}")
        self.observer_integrator.record_feedback(user_id, step_id, feedback)

    def get_scenario_summary(self, scenario_yaml: Dict) -> List[ScenarioExplanation]:
        scenario_data = self.scenario_parser.parse(scenario_yaml)
        explanations = []
        for step_id in scenario_data.steps:
            explanation = self.explain_step(scenario_yaml, step_id)
            explanations.append(explanation)
        return explanations
