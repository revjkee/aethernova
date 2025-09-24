import logging
from typing import Dict, Any, List, Optional
from uuid import uuid4
import json
import datetime

from hr_ai.intake.cv_parser import extract_features
from hr_ai.prediction.performance_model import predict_performance
from hr_ai.intake.skill_matcher import match_skills
from hr_ai.governance.policy_rules_engine import validate_policies

logger = logging.getLogger("decision_explainer")
logger.setLevel(logging.INFO)

class DecisionTrace:
    def __init__(self):
        self.trace_id = str(uuid4())
        self.timestamp = datetime.datetime.utcnow().isoformat()
        self.steps: List[Dict[str, Any]] = []
        self.factors: List[str] = []
        self.violations: List[Dict[str, Any]] = []
        self.final_decision: Optional[str] = None
        self.confidence: float = 0.0

    def log_step(self, step: str, input_data: Any, output_data: Any, reason: Optional[str] = None):
        entry = {
            "step": step,
            "input": input_data,
            "output": output_data,
            "reason": reason or "N/A"
        }
        self.steps.append(entry)

    def record_factor(self, factor: str):
        self.factors.append(factor)

    def record_violation(self, policy_id: str, description: str):
        self.violations.append({
            "policy_id": policy_id,
            "description": description
        })

    def finalize(self, decision: str, confidence: float):
        self.final_decision = decision
        self.confidence = round(confidence, 3)

    def export(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "timestamp": self.timestamp,
            "steps": self.steps,
            "factors": self.factors,
            "violations": self.violations,
            "final_decision": self.final_decision,
            "confidence": self.confidence
        }

class DecisionExplainer:
    def __init__(self):
        self.trace = DecisionTrace()

    def explain(self, cv_data: Dict[str, Any], job_description: Dict[str, Any]) -> Dict[str, Any]:
        features = extract_features(cv_data)
        self.trace.log_step("feature_extraction", cv_data, features, "Извлечены ключевые признаки из резюме")

        skill_match = match_skills(features["skills"], job_description["required_skills"])
        self.trace.log_step("skill_matching", {"skills": features["skills"]}, skill_match, "Сопоставление навыков")
        self.trace.record_factor("skill_match")

        perf_score = predict_performance(features)
        self.trace.log_step("performance_prediction", features, perf_score, "Оценка ожидаемой продуктивности")
        self.trace.record_factor("performance_model")

        policies_result = validate_policies(cv_data, features, skill_match, perf_score)
        for v in policies_result.get("violations", []):
            self.trace.record_violation(v["policy_id"], v["description"])
        self.trace.log_step("policy_validation", {}, policies_result, "Проверка соответствия политике")

        decision = "REJECTED" if policies_result.get("violated") else "ACCEPTED"
        confidence = perf_score["confidence"] * skill_match["score"]
        self.trace.finalize(decision, confidence)

        logger.info(f"Decision trace {self.trace.trace_id} completed with decision: {decision}")
        return self.trace.export()

    def explain_json(self, *args, **kwargs) -> str:
        return json.dumps(self.explain(*args, **kwargs), indent=2)

