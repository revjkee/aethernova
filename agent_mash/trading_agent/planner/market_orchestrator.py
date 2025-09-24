# market_orchestrator.py

import time
import logging
from typing import Dict, Any, List, Optional

from agent_mash.trading_agent.strategies.base_strategy import BaseStrategy, Signal
from agent_mash.trading_agent.agents.execution_agent import ExecutionAgent

logger = logging.getLogger("market_orchestrator")
logger.setLevel(logging.INFO)


class MarketOrchestrator:
    """
    Центральный планировщик, который управляет жизненным циклом торгового агента:
    - собирает данные
    - получает сигналы от стратегий
    - выбирает оптимальное действие
    - делегирует его исполнение
    """

    def __init__(
        self,
        strategies: List[BaseStrategy],
        executor: ExecutionAgent,
        heartbeat_interval: float = 5.0,
        symbol: str = "BTCUSDT"
    ):
        self.strategies = strategies
        self.executor = executor
        self.symbol = symbol
        self.heartbeat_interval = heartbeat_interval

        self.last_market_data: Optional[Dict[str, Any]] = None
        self.last_signal: Optional[Signal] = None
        self.active = False

    def fetch_market_data(self) -> Dict[str, Any]:
        """
        Имитация получения рыночных данных. В боевой системе заменяется на API.
        """
        # TODO: интегрировать с real-time источниками: Binance, Bybit, OKX и др.
        return {
            "symbol": self.symbol,
            "price": 28950.00,
            "rsi": 41.3,
            "macd": -0.13,
            "volume": 745812,
            "volatility": 0.027
        }

    def aggregate_signals(self, data: Dict[str, Any]) -> List[Signal]:
        """
        Получает сигналы от всех стратегий.
        """
        signals = []
        for strategy in self.strategies:
            try:
                signal = strategy.generate_signal(data)
                strategy.report(signal, data)
                signals.append(signal)
                logger.info(f"[{strategy.name}] Сигнал: {signal}")
            except Exception as e:
                logger.error(f"Ошибка в стратегии {strategy.__class__.__name__}: {e}")
        return signals

    def select_final_action(self, signals: List[Signal]) -> Signal:
        """
        Выбирает финальное действие на основе максимальной уверенности.
        """
        if not signals:
            logger.warning("[ORCHESTRATOR] Нет доступных сигналов, HOLD по умолчанию.")
            return Signal("hold", 0.0, {"reason": "no_signals"})

        final = max(signals, key=lambda s: float(getattr(s, "confidence", 0.0)))
        logger.info(f"[ORCHESTRATOR] Выбран финальный сигнал: {final}")
        return final

    def execute(self, signal: Signal):
        """
        Делегирует исполнение выбранного сигнала исполнителю.
        """
        if signal.action in {"buy", "sell"} and signal.confidence > 0.5:
            logger.info(f"[ORCHESTRATOR] Исполнение сигнала: {signal}")
            self.executor.execute_order(signal)
        else:
            logger.info(f"[ORCHESTRATOR] [HOLD] Уверенность слишком низкая: {signal.confidence:.2f}")

    def run(self, cycles: int = 100):
        """
        Запускает основной цикл торгового агента.
        """
        logger.info(f"[ORCHESTRATOR] Запуск торгового планировщика для {self.symbol}")
        self.active = True

        for step in range(cycles):
            logger.info(f"[ORCHESTRATOR] Шаг {step+1}/{cycles}")

            try:
                self.last_market_data = self.fetch_market_data()
                signals = self.aggregate_signals(self.last_market_data)
                final_signal = self.select_final_action(signals)

                self.last_signal = final_signal
                self.execute(final_signal)

            except Exception as e:
                logger.error(f"[ORCHESTRATOR] Ошибка во время цикла: {e}")

            time.sleep(self.heartbeat_interval)

        self.active = False
        logger.info("[ORCHESTRATOR] Завершение цикла")
