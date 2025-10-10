import logging
from typing import Dict, Optional
from datetime import datetime, timedelta

import numpy as np

from core.models.threat_entity import ThreatNode
from core.config.risk_config import load_risk_profile
from core.ml.inference_model import MLThreatScorer
from core.utils.time_utils import parse_timestamp

logger = logging.getLogger("graph.node_risk_analyzer")
logger.setLevel(logging.INFO)


class NodeRiskAnalyzer:
    def __init__(self):
        self.risk_profile = load_risk_profile()
        self.ml_scorer = MLThreatScorer(model_path=self.risk_profile.get("ml_model_path"))
        self.now = datetime.utcnow()

    def compute_node_risk(self, node_data: Dict) -> float:
        """
        Основной метод оценки риска одного узла по множеству метаданных.
        """
        base_score = self._base_risk_score(node_data)
        activity_score = self._activity_factor(node_data)
        ml_score = self._ml_score(node_data)
        final_score = min(base_score * activity_score + ml_score, 1.0)

        logger.debug(f"Risk for node {node_data.get('id')}: base={base_score:.2f}, activity={activity_score:.2f}, ml={ml_score:.2f}, final={final_score:.2f}")
        return round(final_score, 4)

    def _base_risk_score(self, node_data: Dict) -> float:
        ttp_weight = self.risk_profile.get("ttp_weight", {})
        category = node_data.get("category", "unknown")
        ttp = node_data.get("ttp", "T0000")
        sensitivity = node_data.get("sensitivity", "low")

        category_weight = {
            "execution": 0.3,
            "persistence": 0.5,
            "privilege_escalation": 0.7,
            "exfiltration": 0.9,
            "impact": 1.0
        }.get(category, 0.2)

        ttp_score = ttp_weight.get(ttp, 0.4)
        sens_map = {"low": 0.2, "medium": 0.5, "high": 0.9}

        return float(category_weight + ttp_score + sens_map.get(sensitivity, 0.2)) / 3

    def _activity_factor(self, node_data: Dict) -> float:
        """
        Вычисляет коэффициент активности на основе времени последнего действия.
        """
        last_seen = node_data.get("last_seen")
        if not last_seen:
            return 0.8

        ts = parse_timestamp(last_seen)
        delta_seconds = (self.now - ts).total_seconds()

        if delta_seconds < 60:
            return 1.0
        elif delta_seconds < 300:
            return 0.85
        elif delta_seconds < 3600:
            return 0.6
        else:
            return 0.3

    def _ml_score(self, node_data: Dict) -> float:
        """
        Возвращает предсказание модели машинного обучения (0-1).
        """
        try:
            features = self._extract_features_for_ml(node_data)
            return self.ml_scorer.predict_proba(features)
        except Exception as e:
            logger.warning(f"ML scoring failed for node {node_data.get('id')}: {e}")
            return 0.0

    def _extract_features_for_ml(self, node_data: Dict) -> np.ndarray:
        """
        Преобразование входных данных узла в ML-вектор фиксированной длины.
        """
        vec = np.zeros(10)
        vec[0] = 1 if node_data.get("category") == "exfiltration" else 0
        vec[1] = self._activity_factor(node_data)
        vec[2] = {"low": 0.1, "medium": 0.5, "high": 0.9}.get(node_data.get("sensitivity", "low"), 0.1)
        vec[3] = 1 if "T10" in node_data.get("ttp", "") else 0
        vec[4] = len(node_data.get("related_alerts", [])) / 10
        vec[5] = 1 if node_data.get("is_endpoint") else 0
        vec[6] = 1 if node_data.get("is_cloud_asset") else 0
        vec[7] = 1 if node_data.get("in_mitre_killchain") else 0
        vec[8] = node_data.get("suspicious_connection_count", 0) / 50
        vec[9] = 1 if node_data.get("enriched_geo") == "high_risk_region" else 0
        return vec.reshape(1, -1)


# External instance
risk_analyzer = NodeRiskAnalyzer()


def evaluate_risk_for_node(node: ThreatNode) -> float:
    return risk_analyzer.compute_node_risk(node.dict())
