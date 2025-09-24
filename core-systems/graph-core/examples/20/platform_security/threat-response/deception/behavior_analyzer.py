# platform-security/genius-core-security/defense/behavior_analyzer.py

import logging
from typing import List, Dict, Optional
from datetime import datetime
import hashlib
import json

from sklearn.ensemble import IsolationForest
import numpy as np

from genius_core_security.defense.threat_db import ThreatDB
from genius_core_security.defense.alert_manager import Alert
from genius_core_security.defense.alert_manager import DefenseLevel

logger = logging.getLogger("BehaviorAnalyzer")

class BehaviorAnalyzer:
    def __init__(self):
        self.model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        self.samples: List[Dict[str, any]] = []
        self.threat_db = ThreatDB()
        self.trained = False

    def _vectorize(self, session: Dict[str, any]) -> List[float]:
        # Упрощённый векторизатор поведения на основе признаков сеанса
        features = [
            len(session.get("commands", [])),
            session.get("duration", 0),
            session.get("num_failed_logins", 0),
            session.get("num_file_mods", 0),
            session.get("port_scan_detected", 0),
        ]
        return features

    def ingest_session(self, session: Dict[str, any]):
        logger.debug(f"Новый сеанс поведения: {session}")
        self.samples.append(session)
        if len(self.samples) >= 50 and not self.trained:
            self._train_model()

    def _train_model(self):
        X = [self._vectorize(s) for s in self.samples]
        self.model.fit(X)
        self.trained = True
        logger.info("ML-модель поведения обучена на первых 50+ сеансах")

    def analyze_session(self, session: Dict[str, any]) -> Optional[Alert]:
        if not self.trained:
            logger.warning("Модель ещё не обучена — анализ невозможен")
            return None

        vector = np.array(self._vectorize(session)).reshape(1, -1)
        prediction = self.model.predict(vector)[0]  # -1 = аномалия

        if prediction == -1:
            threat_id = self._generate_threat_id(session)
            self.threat_db.add_threat(
                ioc={"ip": session.get("source_ip", "unknown")},
                severity="HIGH",
                source="honeypot"
            )

            alert = Alert(
                source="BehaviorAnalyzer",
                level=DefenseLevel.HIGH,
                message="Выявлено аномальное поведение атакующего в honeypot",
                metadata={
                    "session": session,
                    "threat_id": threat_id,
                    "detected_at": datetime.utcnow().isoformat()
                }
            )
            logger.warning(f"Аномалия поведения зафиксирована: {alert.to_dict()}")
            return alert

        logger.info("Сеанс проанализирован: поведение в пределах нормы")
        return None

    def _generate_threat_id(self, session: Dict[str, any]) -> str:
        serialized = json.dumps(session, sort_keys=True)
        return hashlib.sha256(serialized.encode()).hexdigest()
