# feedback_loop.py

import logging
from typing import List
from statistics import mean
from agent_mash.trading_agent.memory.trade_history import TradeHistory
from agent_mash.trading_agent.analytics.pnl_tracker import PnLTracker
from agent_mash.trading_agent.analytics.signal_quality_analyzer import SignalQualityAnalyzer
from agent_mash.trading_agent.memory.risk_memory import RiskMemory
from agent_mash.trading_agent.strategies.base_strategy import BaseStrategy

logger = logging.getLogger("FeedbackLoop")
logger.setLevel(logging.INFO)


class FeedbackLoop:
    """
    Система самокоррекции торговых стратегий на основе результата.
    Использует динамическую коррекцию веса стратегий и фильтрацию неэффективных.
    """

    def __init__(
        self,
        strategies: List[BaseStrategy],
        trade_history: TradeHistory,
        pnl_tracker: PnLTracker,
        signal_analyzer: SignalQualityAnalyzer,
        risk_memory: RiskMemory,
        min_confidence_threshold: float = 0.55,
        max_drawdown: float = -0.10
    ):
        self.strategies = strategies
        self.trade_history = trade_history
        self.pnl_tracker = pnl_tracker
        self.signal_analyzer = signal_analyzer
        self.risk_memory = risk_memory
        self.min_confidence_threshold = min_confidence_threshold
        self.max_drawdown = max_drawdown
        self.history_window = 100

    def evaluate_strategies(self):
        """
        Проводит оценку стратегий на основе истории сигналов, доходности и качества.
        """
        for strategy in self.strategies:
            name = strategy.__class__.__name__
            signals = self.signal_analyzer.get_signals_by_strategy(name, window=self.history_window)
            pnl = self.pnl_tracker.get_strategy_return(name)
            confidence_values = [s.confidence for s in signals]
            mean_confidence = mean(confidence_values) if confidence_values else 0.0
            drawdown = self.pnl_tracker.get_strategy_drawdown(name)

            logger.info(f"[FEEDBACK] Стратегия {name}: PnL={pnl:.4f}, "
                        f"Drawdown={drawdown:.4f}, Confidence={mean_confidence:.3f}")

            if pnl < 0 or drawdown < self.max_drawdown:
                logger.warning(f"[DISABLE] Стратегия {name} временно отключена (низкий PnL/высокий DD).")
                strategy.active = False
            elif mean_confidence < self.min_confidence_threshold:
                logger.warning(f"[FILTER] Стратегия {name} помечена как слабая (уверенность < {self.min_confidence_threshold}).")
                strategy.set_aggressiveness(scale=0.5)
            else:
                strategy.active = True
                strategy.set_aggressiveness(scale=1.0)

    def adjust_based_on_loss_patterns(self):
        """
        Корректирует поведение стратегий на основе повторяющихся убыточных паттернов.
        """
        bad_patterns = self.risk_memory.extract_frequent_loss_patterns()
        if not bad_patterns:
            return

        for strategy in self.strategies:
            if hasattr(strategy, "avoid_patterns"):
                strategy.avoid_patterns(bad_patterns)
                logger.info(f"[AVOID] Стратегия {strategy.__class__.__name__} скорректирована под убытки.")

    def run(self):
        """
        Запускает полную обратную связь по всем стратегиям.
        """
        logger.info("[FEEDBACK LOOP] Старт анализа стратегий...")
        self.evaluate_strategies()
        self.adjust_based_on_loss_patterns()
        logger.info("[FEEDBACK LOOP] Обратная связь завершена.")
