# path: sageai-core/multi_agent_coordinator/timeline_predictor.py

import logging
import uuid
import numpy as np
import datetime
from typing import List, Dict, Optional, Tuple
from pydantic import BaseModel, Field
from scipy.optimize import curve_fit
from sklearn.ensemble import GradientBoostingRegressor

logger = logging.getLogger("TimelinePredictor")
logger.setLevel(logging.INFO)


class ScenarioEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime.datetime
    features: Dict[str, float]
    outcome_score: float


class ScenarioTrajectory(BaseModel):
    scenario_id: str
    events: List[ScenarioEvent]
    label: Optional[str] = None
    confidence: float = 1.0


class PredictionResult(BaseModel):
    scenario_id: str
    next_timestamps: List[datetime.datetime]
    predicted_scores: List[float]
    model_used: str
    confidence: float


class TimelinePredictor:
    def __init__(self):
        self.trajectories: Dict[str, ScenarioTrajectory] = {}
        self.model_registry: Dict[str, GradientBoostingRegressor] = {}

    def register_scenario(self, scenario: ScenarioTrajectory):
        self.trajectories[scenario.scenario_id] = scenario
        logger.info(f"Registered scenario: {scenario.scenario_id} with {len(scenario.events)} events")

    def _extract_features_targets(
        self, events: List[ScenarioEvent]
    ) -> Tuple[np.ndarray, np.ndarray]:
        X, y = [], []
        base_time = events[0].timestamp.timestamp()
        for event in events:
            time_delta = event.timestamp.timestamp() - base_time
            feature_vector = [time_delta] + list(event.features.values())
            X.append(feature_vector)
            y.append(event.outcome_score)
        return np.array(X), np.array(y)

    def _fit_model(self, X: np.ndarray, y: np.ndarray) -> GradientBoostingRegressor:
        model = GradientBoostingRegressor(n_estimators=100, max_depth=4)
        model.fit(X, y)
        return model

    def predict_future(
        self, scenario_id: str, time_steps: int = 5, interval_seconds: int = 3600
    ) -> PredictionResult:
        if scenario_id not in self.trajectories:
            raise ValueError(f"Scenario {scenario_id} not found")

        trajectory = self.trajectories[scenario_id]
        if len(trajectory.events) < 3:
            raise ValueError("Not enough data points for prediction")

        X, y = self._extract_features_targets(trajectory.events)
        model = self._fit_model(X, y)
        self.model_registry[scenario_id] = model

        base_time = trajectory.events[0].timestamp
        latest_time = trajectory.events[-1].timestamp
        feature_names = list(trajectory.events[0].features.keys())
        last_features = list(trajectory.events[-1].features.values())

        future_times = [
            latest_time + datetime.timedelta(seconds=(i + 1) * interval_seconds)
            for i in range(time_steps)
        ]
        X_future = []
        for t in future_times:
            time_delta = t.timestamp() - base_time.timestamp()
            X_future.append([time_delta] + last_features)

        predicted_scores = model.predict(np.array(X_future)).tolist()
        logger.info(f"Predicted {time_steps} steps into the future for {scenario_id}")

        return PredictionResult(
            scenario_id=scenario_id,
            next_timestamps=future_times,
            predicted_scores=predicted_scores,
            model_used="GradientBoostingRegressor",
            confidence=trajectory.confidence
        )

    def reset(self):
        self.trajectories.clear()
        self.model_registry.clear()
        logger.info("Timeline predictor has been reset")

    def export_predictions(self) -> Dict[str, List[float]]:
        return {
            sid: model.predict(self._extract_features_targets(traj.events)[0]).tolist()
            for sid, traj in self.trajectories.items()
            if sid in self.model_registry
        }

    def forecast_peak_risk(
        self, scenario_id: str, horizon: int = 10
    ) -> Tuple[datetime.datetime, float]:
        result = self.predict_future(scenario_id, time_steps=horizon)
        max_score = max(result.predicted_scores)
        max_index = result.predicted_scores.index(max_score)
        return result.next_timestamps[max_index], max_score
