# trader_agent.py

import logging
from typing import List, Optional
from agent_mash.trading_agent.strategies.base_strategy import BaseStrategy
from agent_mash.trading_agent.memory.trade_history import TradeHistory
from agent_mash.trading_agent.memory.market_cache import MarketCache
from agent_mash.trading_agent.memory.risk_memory import RiskMemory
from agent_mash.trading_agent.policy.risk_policy import RiskPolicy
from agent_mash.trading_agent.policy.profit_target_policy import ProfitTargetPolicy
from agent_mash.trading_agent.policy.trading_hours_policy import TradingHoursPolicy
from agent_mash.trading_agent.analytics.signal_quality_analyzer import SignalQualityAnalyzer
from agent_mash.trading_agent.analytics.pnl_tracker import PnLTracker
from agent_mash.trading_agent.analytics.drawdown_monitor import DrawdownMonitor
from agent_mash.trading_agent.planner.market_orchestrator import MarketOrchestrator
from agent_mash.trading_agent.planner.execution_scheduler import ExecutionScheduler
from agent_mash.trading_agent.planner.portfolio_balancer import PortfolioBalancer
from agent_mash.trading_agent.agents.execution_agent import ExecutionAgent
from agent_mash.trading_agent.utils.trade_logger import TradeLogger
from agent_mash.trading_agent.utils.market_api_adapter import MarketAPIAdapter
from agent_mash.trading_agent.utils.indicator_builder import IndicatorBuilder

logger = logging.getLogger("TraderAgent")
logger.setLevel(logging.INFO)


class TraderAgent:
    """
    Главный агент, координирующий торговую систему. Управляет стратегиями, исполнением,
    риск-политикой, памятью, аналитикой и адаптацией.
    """

    def __init__(
        self,
        strategies: List[BaseStrategy],
        execution_agent: ExecutionAgent,
        symbol: str = "BTCUSDT",
        heartbeat_interval: float = 5.0,
    ):
        self.symbol = symbol
        self.strategies = strategies
        self.execution_agent = execution_agent
        self.heartbeat_interval = heartbeat_interval

        # Подсистемы
        self.trade_history = TradeHistory()
        self.market_cache = MarketCache(max_size=500)
        self.risk_memory = RiskMemory()
        self.risk_policy = RiskPolicy()
        self.profit_policy = ProfitTargetPolicy()
        self.time_policy = TradingHoursPolicy()
        self.signal_analyzer = SignalQualityAnalyzer()
        self.pnl_tracker = PnLTracker()
        self.drawdown_monitor = DrawdownMonitor()
        self.indicator_builder = IndicatorBuilder()
        self.logger = TradeLogger()
        self.api_adapter = MarketAPIAdapter()

        # Планировщики
        self.portfolio_balancer = PortfolioBalancer()
        self.execution_scheduler = ExecutionScheduler(execution_agent)
        self.orchestrator = MarketOrchestrator(
            strategies=self.strategies,
            executor=self.execution_agent,
            heartbeat_interval=self.heartbeat_interval,
            symbol=self.symbol
        )

        self.active = False

    def initialize(self):
        """
        Инициализация всех подсистем и логирование параметров.
        """
        logger.info("[INIT] TraderAgent инициализируется...")
        self.market_cache.clear()
        self.trade_history.clear()
        self.drawdown_monitor.reset()
        self.pnl_tracker.reset()
        logger.info("[INIT] Готово.")

    def start(self, cycles: int = 100):
        """
        Запуск торгового процесса.
        """
        logger.info(f"[START] Запуск торгового агента на {cycles} циклов.")
        self.initialize()
        self.active = True
        self.orchestrator.run(cycles=cycles)
        self.active = False
        logger.info("[END] Торговый агент завершил работу.")

    def shutdown(self):
        """
        Принудительная остановка.
        """
        self.active = False
        logger.warning("[SHUTDOWN] Остановлен вручную.")

    def status(self) -> dict:
        """
        Актуальное состояние торгового агента.
        """
        return {
            "active": self.active,
            "symbol": self.symbol,
            "strategies": [s.__class__.__name__ for s in self.strategies],
            "drawdown": self.drawdown_monitor.get_current_drawdown(),
            "pnl": self.pnl_tracker.get_total_return(),
        }
