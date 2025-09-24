# signal_quality_analyzer.py

import logging
from typing import List, Dict, Any
from dataclasses import dataclass
from statistics import mean, stdev

logger = logging.getLogger("signal_quality_analyzer")
logger.setLevel(logging.INFO)

@dataclass
class Signal:
    action: str  # "buy", "sell", "hold"
    confidence: float
    metadata: Dict[str, Any]

@dataclass
class SignalExecutionResult:
    signal: Signal
    success: bool
    profit: float
    slippage: float
    delay: float
    execution_time: str  # ISO timestamp

class SignalQualityAnalyzer:
    """
    Анализирует качество торговых сигналов, предоставляя метрики уверенности,
    успеха, задержек, проскальзывания и общей прибыльности.
    """

    def __init__(self):
        self.history: List[SignalExecutionResult] = []

    def record_execution(self, result: SignalExecutionResult):
        self.history.append(result)
        logger.info(f"[QUALITY] Запись сигнала: {result}")

    def compute_statistics(self) -> Dict[str, Any]:
        if not self.history:
            logger.warning("[QUALITY] Нет данных для анализа")
            return {}

        confidences = [res.signal.confidence for res in self.history]
        profits = [res.profit for res in self.history]
        slippages = [res.slippage for res in self.history]
        delays = [res.delay for res in self.history]
        success_count = sum(1 for res in self.history if res.success)

        stats = {
            "total_signals": len(self.history),
            "success_rate": success_count / len(self.history),
            "avg_confidence": mean(confidences),
            "avg_profit": mean(profits),
            "avg_slippage": mean(slippages),
            "avg_delay": mean(delays),
            "std_confidence": stdev(confidences) if len(confidences) > 1 else 0.0,
            "std_profit": stdev(profits) if len(profits) > 1 else 0.0,
        }

        logger.info(f"[QUALITY] Метрики качества сигналов: {stats}")
        return stats

    def detect_degradation(self, min_success_rate: float = 0.6, max_slippage: float = 0.3) -> bool:
        stats = self.compute_statistics()
        if not stats:
            return False

        degraded = (
            stats["success_rate"] < min_success_rate or
            stats["avg_slippage"] > max_slippage
        )

        if degraded:
            logger.warning("[QUALITY] Обнаружена деградация качества сигналов")

        return degraded

    def reset(self):
        self.history.clear()
        logger.info("[QUALITY] История сигналов сброшена")
