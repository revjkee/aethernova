import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

from ai_siem.registry import DetectorRegistry
from ai_siem.schemas import DetectionAlert
from ai_siem.utils.anomaly import compute_anomaly_score
from ai_siem.utils.mitre import map_to_mitre_tactic
from ai_siem.middleware.tracer import trace_detection
from ai_siem.middleware.guardrails import validate_input_log
from ai_siem.config import MATRIX_CONF

logger = logging.getLogger("siem.detector_matrix")
logger.setLevel(logging.INFO)


class DetectorMatrix:
    def __init__(self, registry: Optional[DetectorRegistry] = None):
        self.registry = registry or DetectorRegistry()
        self.detectors = {}
        self.matrix_index: Dict[str, List[str]] = {}
        self._init_matrix()

    def _init_matrix(self):
        for detector_cls in self.registry.get_all():
            try:
                instance = detector_cls()
                self.detectors[instance.name] = instance
                for tactic in instance.get_mitre_tactics():
                    self.matrix_index.setdefault(tactic, []).append(instance.name)
                logger.info(f"Loaded detector: {instance.name} ({instance.get_mitre_tactics()})")
            except Exception as e:
                logger.error(f"Error loading detector {detector_cls}: {e}")

    def detect(self, log: Dict[str, Any], source: str = "unknown") -> List[DetectionAlert]:
        results = []
        log = validate_input_log(log)
        timestamp = datetime.utcnow()

        for name, detector in self.detectors.items():
            try:
                if not detector.enabled:
                    continue

                trace_id = trace_detection(detector.name, log)
                detection = detector.detect(log)

                if detection:
                    anomaly_score = compute_anomaly_score(log, detector.weight)
                    mitre_tactics = map_to_mitre_tactic(detection.signature)

                    alert = DetectionAlert(
                        timestamp=timestamp.isoformat(),
                        detector=name,
                        tactics=mitre_tactics,
                        signature=detection.signature,
                        details=detection.details,
                        anomaly_score=anomaly_score,
                        confidence=detection.confidence,
                        trace_id=trace_id,
                        source=source,
                        environment=log.get("env", "default")
                    )
                    results.append(alert)
            except Exception as e:
                logger.warning(f"Detector {name} failed: {e}")
        return results

    def get_matrix(self) -> Dict[str, List[str]]:
        return self.matrix_index

    def reload_detector(self, name: str) -> bool:
        try:
            cls = self.registry.get(name)
            if not cls:
                raise ValueError(f"Detector not registered: {name}")
            self.detectors[name] = cls()
            logger.info(f"Reloaded detector: {name}")
            return True
        except Exception as e:
            logger.error(f"Reload failed for {name}: {e}")
            return False

    def batch_detect(self, logs: List[Dict[str, Any]], source: str = "batch") -> List[DetectionAlert]:
        all_alerts = []
        for log in logs:
            alerts = self.detect(log, source=source)
            all_alerts.extend(alerts)
        return all_alerts

    def stats(self) -> Dict[str, Any]:
        return {
            "total_detectors": len(self.detectors),
            "matrix_coverage": {k: len(v) for k, v in self.matrix_index.items()},
            "detectors": {
                name: {
                    "tactics": detector.get_mitre_tactics(),
                    "enabled": detector.enabled,
                    "weight": detector.weight
                } for name, detector in self.detectors.items()
            }
        }

    def export_config(self) -> str:
        config = {
            "version": MATRIX_CONF["version"],
            "detectors": list(self.detectors.keys()),
            "coverage": list(self.matrix_index.keys())
        }
        return json.dumps(config, indent=2)
