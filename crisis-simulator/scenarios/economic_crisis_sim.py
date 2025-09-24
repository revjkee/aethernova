# economic_crisis_sim.py

"""
Симуляция макроэкономических кризисов на базе AI-моделей.
Поддерживает сценарии:
- краха фондовых рынков
- валютных шоков
- банковской паники
- гиперинфляции
- цепных долговых дефолтов
- торговых санкций и блокад
"""

import logging
import random
from datetime import datetime
from typing import Dict, Optional

from crisis_simulator.core.models import EconomicCrisisEvent, NationEconomyState
from crisis_simulator.core.ai.macroeconomics import CentralBankAI, MarketBehaviorAI
from crisis_simulator.core.feedback import MacroTelemetryCollector
from crisis_simulator.core.utils.metrics import compute_macro_risk_index

logger = logging.getLogger("EconomicCrisisSimulator")

class EconomicCrisisSimulator:
    def __init__(self, country_profile: NationEconomyState, seed: Optional[int] = None):
        self.country = country_profile
        self.central_bank_ai = CentralBankAI()
        self.market_ai = MarketBehaviorAI(seed=seed)
        self.telemetry = MacroTelemetryCollector()

    def simulate_crisis(self, crisis_type: str) -> EconomicCrisisEvent:
        logger.info(f"[SIM] Simulating economic crisis: {crisis_type} for {self.country.name}")

        scenario = self._generate_crisis(crisis_type)
        macro_risk = compute_macro_risk_index(self.country, scenario)

        cb_response = self.central_bank_ai.react_to_crisis(self.country, scenario)
        market_cascade = self.market_ai.simulate_market_response(self.country, scenario)

        telemetry = self.telemetry.collect(self.country, scenario, market_cascade)

        event = EconomicCrisisEvent(
            timestamp=datetime.utcnow(),
            country=self.country.name,
            crisis_type=crisis_type,
            cause_vector=scenario,
            central_bank_response=cb_response,
            market_effects=market_cascade,
            macro_risk_score=macro_risk,
            telemetry=telemetry
        )

        logger.info(f"[SIM] Economic crisis event completed for {self.country.name}")
        return event

    def _generate_crisis(self, crisis_type: str) -> Dict[str, float]:
        base = {
            "interest_rate_shock": 0.0,
            "currency_devaluation": 0.0,
            "stock_market_crash": 0.0,
            "bank_liquidity": 1.0,
            "inflation_rate": self.country.inflation,
            "external_debt_ratio": self.country.debt_to_gdp,
            "supply_chain_disruption": 0.0
        }

        # Инициализация шоков по типу кризиса
        if crisis_type == "currency_crash":
            base["currency_devaluation"] = random.uniform(0.25, 0.65)
            base["external_debt_ratio"] += random.uniform(0.1, 0.3)
        elif crisis_type == "market_crash":
            base["stock_market_crash"] = random.uniform(0.4, 0.9)
            base["interest_rate_shock"] = random.uniform(0.02, 0.08)
        elif crisis_type == "inflation_surge":
            base["inflation_rate"] += random.uniform(10.0, 40.0)
        elif crisis_type == "banking_collapse":
            base["bank_liquidity"] = random.uniform(0.0, 0.3)
        elif crisis_type == "supply_chain_blockade":
            base["supply_chain_disruption"] = random.uniform(0.4, 0.95)
        else:
            raise ValueError(f"Unknown crisis type: {crisis_type}")

        return base
