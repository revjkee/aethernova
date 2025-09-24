# agent_mash/trading_agent/strategies/trading_strategy.py

from abc import ABC, abstractmethod
from typing import Dict, Optional
from agent_mash.trading_agent.schema.trading_message import TradeSignal
from agent_mash.trading_agent.policy.risk_policy import RiskPolicy
from agent_mash.trading_agent.analytics.signal_quality_analyzer import SignalQualityAnalyzer
from agent_mash.trading_agent.utils.trade_logger import TradeLogger
from agent_mash.trading_agent.strategies.base_strategy import BaseStrategy
from agent_rl.copilot_adapter import CopilotAdapter


class TradingStrategyController:
    """
    Central controller that delegates signal generation to registered strategies,
    validates signal quality, applies policies and logs decisions.
    """

    def __init__(
        self,
        strategies: Dict[str, BaseStrategy],
        copilot: Optional[CopilotAdapter] = None,
        policy: Optional[RiskPolicy] = None,
    ):
        self.strategies = strategies
        self.copilot = copilot
        self.policy = policy or RiskPolicy()
        self.quality_analyzer = SignalQualityAnalyzer()
        self.logger = TradeLogger("trading_strategy")

    def decide(self, observation: Dict, strategy_name: str) -> Optional[TradeSignal]:
        try:
            strategy = self.strategies.get(strategy_name)
            if not strategy:
                raise ValueError(f"Strategy '{strategy_name}' not found")

            raw_signal = strategy.generate_signal(observation)

            if not self.quality_analyzer.validate(raw_signal):
                self.logger.warn("Signal rejected by quality analyzer", extra=raw_signal.model_dump())
                return None

            if self.copilot:
                raw_action = raw_signal.action
                adjusted = self.copilot.adjust_action(observation, raw_action)
                raw_signal.action = adjusted

            if not self.policy.allows(raw_signal):
                self.logger.info("Signal blocked by policy", extra=raw_signal.model_dump())
                return None

            self.logger.info("Signal accepted", extra=raw_signal.model_dump())
            return raw_signal

        except Exception as e:
            self.logger.exception("Strategy decision failed", error=str(e))
            return None
