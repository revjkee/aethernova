import logging
import json
from typing import Dict, Any, Optional, List
from uuid import UUID, uuid4
from datetime import datetime
from pathlib import Path
from pydantic import BaseModel, Field, validator
from quantumpulse_core.utils.qmath import QuantumNoiseEngine
from quantumpulse_core.utils.guardrails import validate_intent_signature
from quantumpulse_core.security.audit import record_scenario_audit
from quantumpulse_core.interfaces.model_loader import QuantumModelLoader
from quantumpulse_core.core.errors import ScenarioExecutionError, InvalidScenarioInput

logger = logging.getLogger("quantum.scenario_oracle")
logging.basicConfig(level=logging.INFO)

SCENARIO_CACHE = {}

class ScenarioInput(BaseModel):
    scenario_id: UUID = Field(default_factory=uuid4)
    parameters: Dict[str, Any]
    context: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    user_role: Optional[str] = "anonymous"

    @validator("parameters")
    def validate_params(cls, v):
        if not v or not isinstance(v, dict):
            raise ValueError("Parameters must be a non-empty dictionary")
        return v

class ScenarioOutput(BaseModel):
    outcome: str
    confidence: float
    trace: Optional[List[str]]
    anomalies_detected: int
    qentropy: float
    execution_id: UUID = Field(default_factory=uuid4)
    issued_at: datetime = Field(default_factory=datetime.utcnow)

class ScenarioOracle:
    def __init__(self, model_loader: QuantumModelLoader):
        self.model_loader = model_loader
        self.qengine = QuantumNoiseEngine()
        self._initialized = False
        self._model = None

    def initialize(self, model_name: str = "quantum-risk-v2"):
        try:
            self._model = self.model_loader.load(model_name)
            self._initialized = True
            logger.info(f"Quantum model '{model_name}' successfully initialized.")
        except Exception as e:
            logger.error(f"Failed to initialize quantum model '{model_name}': {e}")
            raise ScenarioExecutionError("Model initialization failed") from e

    def run(self, input_data: ScenarioInput) -> ScenarioOutput:
        if not self._initialized:
            raise ScenarioExecutionError("ScenarioOracle is not initialized")

        if not validate_intent_signature(input_data.parameters):
            raise InvalidScenarioInput("Intent signature invalid or unsafe")

        record_scenario_audit(input_data)

        try:
            qstate = self.qengine.inject_noise(input_data.parameters)
            result = self._model.predict(qstate)
            trace = self._model.get_trace()
            qentropy = self.qengine.calculate_entropy(qstate)

            logger.debug(f"Quantum result: {result}, Q-Entropy: {qentropy}")
            return ScenarioOutput(
                outcome=result.get("label", "unknown"),
                confidence=result.get("confidence", 0.0),
                trace=trace,
                anomalies_detected=self._model.count_anomalies(qstate),
                qentropy=qentropy,
            )
        except Exception as e:
            logger.exception("Scenario execution failed")
            raise ScenarioExecutionError("Scenario execution failed") from e

def load_cached_oracle(model_loader: QuantumModelLoader, model_key: str = "default") -> ScenarioOracle:
    if model_key not in SCENARIO_CACHE:
        oracle = ScenarioOracle(model_loader)
        oracle.initialize()
        SCENARIO_CACHE[model_key] = oracle
    return SCENARIO_CACHE[model_key]
