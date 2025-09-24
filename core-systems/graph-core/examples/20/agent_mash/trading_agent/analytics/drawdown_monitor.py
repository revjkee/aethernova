# drawdown_monitor.py

import logging
from datetime import datetime
from typing import List, Optional, Dict
from dataclasses import dataclass, field

logger = logging.getLogger("drawdown_monitor")
logger.setLevel(logging.INFO)

@dataclass
class EquityPoint:
    timestamp: datetime
    equity: float

@dataclass
class DrawdownRecord:
    peak_time: datetime
    trough_time: datetime
    recovery_time: Optional[datetime]
    max_drawdown: float
    duration: float  # в секундах
    recovered: bool = False

class DrawdownMonitor:
    """
    Монитор просадок. Фиксирует максимальную просадку, длительность, восстановление, фазы.
    """

    def __init__(self):
        self.equity_history: List[EquityPoint] = []
        self.peak_equity: float = 0.0
        self.trough_equity: float = 0.0
        self.peak_time: Optional[datetime] = None
        self.trough_time: Optional[datetime] = None
        self.current_drawdown: float = 0.0
        self.max_drawdown: float = 0.0
        self.drawdown_log: List[DrawdownRecord] = []

    def update_equity(self, equity: float, timestamp: Optional[datetime] = None):
        now = timestamp or datetime.utcnow()
        self.equity_history.append(EquityPoint(timestamp=now, equity=equity))

        if equity > self.peak_equity:
            if self.current_drawdown > 0:
                self._recover_drawdown(now)
            self.peak_equity = equity
            self.peak_time = now
            self.trough_equity = equity
            self.trough_time = now
            self.current_drawdown = 0.0

        elif equity < self.trough_equity:
            self.trough_equity = equity
            self.trough_time = now
            self.current_drawdown = (self.peak_equity - self.trough_equity) / self.peak_equity
            if self.current_drawdown > self.max_drawdown:
                self.max_drawdown = self.current_drawdown
                logger.info(f"[DRAWDOWN] Новая максимальная просадка: {self.max_drawdown:.4f}")

    def _recover_drawdown(self, recovery_time: datetime):
        if self.peak_time and self.trough_time:
            duration = (self.trough_time - self.peak_time).total_seconds()
            record = DrawdownRecord(
                peak_time=self.peak_time,
                trough_time=self.trough_time,
                recovery_time=recovery_time,
                max_drawdown=self.current_drawdown,
                duration=duration,
                recovered=True
            )
            self.drawdown_log.append(record)
            logger.info(f"[DRAWDOWN] Восстановление после просадки {self.current_drawdown:.4f} завершено.")
        self.current_drawdown = 0.0

    def get_current_state(self) -> Dict[str, float]:
        return {
            "peak_equity": self.peak_equity,
            "trough_equity": self.trough_equity,
            "current_drawdown": round(self.current_drawdown, 6),
            "max_drawdown": round(self.max_drawdown, 6)
        }

    def get_drawdown_log(self) -> List[DrawdownRecord]:
        return self.drawdown_log

    def reset(self):
        self.__init__()
        logger.info("[DRAWDOWN] Состояние монитора сброшено.")
