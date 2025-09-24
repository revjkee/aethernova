# execution_scheduler.py

import logging
import threading
import queue
from typing import Dict, Any, Optional
from agent_mash.trading_agent.strategies.base_strategy import Signal
from agent_mash.trading_agent.agents.execution_agent import ExecutionAgent

logger = logging.getLogger("execution_scheduler")
logger.setLevel(logging.INFO)


class ExecutionScheduler:
    """
    Диспетчер исполнения ордеров. Управляет очередью торговых сигналов и делегирует их исполнителю.
    """

    def __init__(self, executor: ExecutionAgent, risk_limit: float = 0.03):
        self.executor = executor
        self.order_queue = queue.Queue()
        self.risk_limit = risk_limit
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        if self._running:
            logger.warning("[SCHEDULER] Уже запущен.")
            return

        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info("[SCHEDULER] Запущен поток диспетчера исполнения.")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join()
            logger.info("[SCHEDULER] Остановлен.")

    def submit(self, signal: Signal):
        """
        Добавляет сигнал в очередь на исполнение.
        """
        if not self._running:
            logger.error("[SCHEDULER] Попытка добавить ордер при остановленном диспетчере.")
            return

        if signal.action not in {"buy", "sell"}:
            logger.info(f"[SCHEDULER] Игнорируется неактивный сигнал: {signal.action}")
            return

        self.order_queue.put(signal)
        logger.info(f"[SCHEDULER] Сигнал поставлен в очередь: {signal}")

    def _run_loop(self):
        while self._running:
            try:
                signal: Signal = self.order_queue.get(timeout=1.0)

                if signal.confidence < 0.5:
                    logger.warning(f"[SCHEDULER] Сигнал с низкой уверенностью отброшен: {signal.confidence:.2f}")
                    continue

                if self._exceeds_risk(signal):
                    logger.warning(f"[SCHEDULER] Превышен лимит риска, отклонено: {signal}")
                    continue

                logger.info(f"[SCHEDULER] Исполнение сигнала: {signal}")
                self.executor.execute_order(signal)

            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"[SCHEDULER] Ошибка в цикле исполнения: {e}")

    def _exceeds_risk(self, signal: Signal) -> bool:
        """
        Проверка на превышение лимита риска (заглушка).
        """
        # В будущем можно внедрить анализ позиции, баланса, стоп-лоссов и PnL.
        return False
