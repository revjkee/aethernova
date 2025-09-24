# cyber_attacks_sim.py

"""
Промышленная симуляция кибератак в рамках модуля TeslaAI Crisis Simulator.
Поддерживает симуляцию APT, ransomware, supply-chain, DDoS, AI-driven атак, zero-day, insider threats.
"""

import logging
from datetime import datetime
from typing import List, Optional, Dict

from crisis_simulator.core.models import CyberAttackEvent, TargetSystem
from crisis_simulator.core.ai.attackers import AdversarialAITasker
from crisis_simulator.core.feedback import CyberTelemetryCollector
from crisis_simulator.core.utils.metrics import compute_exposure_score, estimate_response_time
from crisis_simulator.core.intel.knowledge_base import AttackPatternsDB

logger = logging.getLogger("CyberAttackSimulator")

class CyberAttackSimulator:
    def __init__(self, targets: List[TargetSystem], seed: Optional[int] = None):
        self.targets = targets
        self.attack_generator = AdversarialAITasker(seed=seed)
        self.telemetry_collector = CyberTelemetryCollector()
        self.attack_patterns = AttackPatternsDB()

    def simulate_attack(self, attack_type: str) -> CyberAttackEvent:
        if attack_type not in self.attack_patterns.supported_types():
            raise ValueError(f"Attack type '{attack_type}' not supported.")

        logger.info(f"[SIM] Starting simulation of {attack_type} attack...")

        # Выбор цели и построение вектора атаки
        selected_target = self._select_target()
        tactic_flow = self.attack_patterns.generate_tactics(attack_type)
        timestamp = datetime.utcnow()

        # Запуск атаки через AI Tasker
        exploit_report = self.attack_generator.execute_attack(selected_target, tactic_flow)

        # Вычисление уязвимости и ущерба
        exposure = compute_exposure_score(selected_target, tactic_flow)
        estimated_recovery = estimate_response_time(exploit_report.impact)

        # Телеметрия и отчёт
        telemetry_data = self.telemetry_collector.collect(selected_target, exploit_report)

        event = CyberAttackEvent(
            attack_type=attack_type,
            target=selected_target,
            tactic_flow=tactic_flow,
            timestamp=timestamp,
            exposure_score=exposure,
            estimated_downtime_hr=estimated_recovery,
            exploit_report=exploit_report,
            telemetry=telemetry_data
        )

        logger.info(f"[SIM] Cyberattack simulated: {attack_type} on {selected_target.hostname}")
        return event

    def _select_target(self) -> TargetSystem:
        return max(self.targets, key=lambda t: t.criticality)

