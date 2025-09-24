# natural_disasters_sim.py

"""
Модуль симуляции природных катастроф TeslaAI
Поддерживает: землетрясения, наводнения, вулканы, ураганы, пожары
"""

import random
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import numpy as np

from crisis_simulator.core.models import GeoRegion, DisasterEvent
from crisis_simulator.core.ai.predictors import TeslaGeoPredictor
from crisis_simulator.core.sensors import SatelliteSensorNetwork
from crisis_simulator.core.utils.geo import compute_impact_zone, estimate_population_at_risk
from crisis_simulator.core.feedback import ImpactReportEmitter

logger = logging.getLogger("NaturalDisasterSimulator")

class NaturalDisasterSimulator:
    def __init__(self, region: GeoRegion, seed: Optional[int] = None):
        self.region = region
        self.random = random.Random(seed)
        self.predictor = TeslaGeoPredictor()
        self.sensor_network = SatelliteSensorNetwork()
        self.feedback = ImpactReportEmitter()
    
    def simulate_disaster(self, disaster_type: str) -> DisasterEvent:
        if disaster_type not in ["earthquake", "flood", "wildfire", "hurricane", "volcano"]:
            raise ValueError(f"Unsupported disaster type: {disaster_type}")

        logger.info(f"[SIM] Starting simulation of {disaster_type} in region {self.region.name}")
        
        # Генерация параметров события
        intensity = self.random.uniform(4.5, 9.5) if disaster_type == "earthquake" else self.random.uniform(1.0, 5.0)
        timestamp = datetime.utcnow()
        center = self.region.get_random_point()

        affected_area = compute_impact_zone(center, radius_km=self._get_radius(disaster_type, intensity))
        population = estimate_population_at_risk(affected_area)

        event = DisasterEvent(
            type=disaster_type,
            location=center,
            intensity=intensity,
            timestamp=timestamp,
            affected_area=affected_area,
            population_at_risk=population,
        )

        # ИИ прогноз пост-эффектов
        event.predicted_damage_usd = self.predictor.estimate_economic_loss(event)
        event.infrastructure_impact_score = self.predictor.estimate_infrastructure_damage(event)
        event.recovery_time_days = self.predictor.estimate_recovery_duration(event)

        # Обратная связь с сенсоров
        sensor_data = self.sensor_network.collect_feedback(event)
        self.feedback.emit(event, sensor_data)

        logger.info(f"[SIM] Finished simulation of {disaster_type}. Population at risk: {population}")
        return event

    def _get_radius(self, disaster_type: str, intensity: float) -> float:
        if disaster_type == "earthquake":
            return intensity ** 1.3
        elif disaster_type == "hurricane":
            return intensity * 50
        elif disaster_type == "wildfire":
            return intensity * 10
        elif disaster_type == "flood":
            return intensity * 15
        elif disaster_type == "volcano":
            return intensity * 25
        else:
            return 0

