# base_strategy.py

import abc
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("trading_agent.strategies.base")
logger.setLevel(logging.INFO)


class Signal:
    """Базовая структура торгового сигнала."""
    def __init__(self, action: str, confidence: float, metadata: Optional[Dict[str, Any]] = None):
        self.action = action  # 'buy', 'sell', 'hold'
        self.confidence = confidence  # float от 0 до 1
        self.metadata = metadata or {}

    def __repr__(self):
        return f"<Signal action={self.action} confidence={self.confidence:.2f}>"


class StrategyState:
    """Хранилище состояния между вызовами стратегии (для управления памятью и условиями входа/выхода)."""
    def __init__(self):
        self.position_open: bool = False
        self.last_signal: Optional[str] = None
        self.memory: Dict[str, Any] = {}


class BaseStrategy(abc.ABC):
    """
    Абстрактный базовый класс торговой стратегии.
    """

    def __init__(self, parameters: Optional[Dict[str, Any]] = None):
        self.params = parameters or self.default_parameters()
        self.state = StrategyState()
        self.name = self.__class__.__name__
        logger.info(f"[{self.name}] Инициализация с параметрами: {self.params}")

    @abc.abstractmethod
    def generate_signal(self, market_data: Dict[str, Any]) -> Signal:
        """
        Основной метод, который возвращает торговый сигнал.
        """
        raise NotImplementedError

    def reset(self):
        """
        Сброс состояния между сессиями.
        """
        self.state = StrategyState()
        logger.info(f"[{self.name}] Состояние сброшено")

    def default_parameters(self) -> Dict[str, Any]:
        """
        Установить параметры по умолчанию.
        """
        return {
            "risk_limit": 0.02,  # 2% риска на сделку
            "confidence_threshold": 0.6
        }

    def evaluate(self, signal: Signal) -> bool:
        """
        Проверяет, достаточно ли уверенности, чтобы исполнить сигнал.
        """
        threshold = self.params.get("confidence_threshold", 0.6)
        decision = signal.confidence >= threshold
        logger.debug(f"[{self.name}] Evaluate signal: {signal} → {decision}")
        return decision

    def report(self, signal: Signal, market_data: Dict[str, Any]):
        """
        Публикация отчёта по стратегии.
        """
        logger.info(f"[{self.name}] Signal={signal} | Market snapshot: {market_data.get('symbol', 'N/A')}")

    def backtest(self, historical_data: list) -> Dict[str, Any]:
        """
        Простейший режим обратного тестирования.
        """
        wins, losses, trades = 0, 0, 0
        self.reset()
        for data_point in historical_data:
            signal = self.generate_signal(data_point)
            if self.evaluate(signal):
                trades += 1
                result = data_point.get("simulated_result", "win")
                if result == "win":
                    wins += 1
                else:
                    losses += 1
        win_rate = round(wins / trades, 4) if trades else 0.0
        logger.info(f"[{self.name}] Backtest results: WinRate={win_rate}, Trades={trades}")
        return {
            "trades": trades,
            "wins": wins,
            "losses": losses,
            "win_rate": win_rate
        }
