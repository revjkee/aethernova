import logging
from typing import List, Dict, Optional
import numpy as np
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger("CalibrationStats")


class TrendDirection(str, Enum):
    STABLE = "stable"
    IMPROVING = "improving"
    DETERIORATING = "deteriorating"
    VOLATILE = "volatile"


@dataclass
class CalibrationMetrics:
    delta: float
    accuracy: float
    trend: TrendDirection
    deviation: float
    stability_score: float
    improvement_rate: float
    signal_entropy: float

    def as_dict(self) -> Dict[str, float]:
        return asdict(self)


class CalibrationStats:
    def __init__(self):
        self.history: List[float] = []
        self.target: Optional[float] = None
        self.max_history_size = 100

    def update(self, new_value: float, target_value: Optional[float] = None) -> CalibrationMetrics:
        if target_value is not None:
            self.target = target_value

        self.history.append(new_value)
        if len(self.history) > self.max_history_size:
            self.history.pop(0)

        logger.debug(f"New calibration value: {new_value}, history length: {len(self.history)}")

        if len(self.history) < 3:
            return self._empty_metrics(new_value)

        history_arr = np.array(self.history)
        delta = abs(history_arr[-1] - self.target) if self.target is not None else 0.0
        accuracy = 1.0 - delta / (abs(self.target) + 1e-8) if self.target else 0.0
        deviation = float(np.std(history_arr))
        improvement_rate = float(self._compute_improvement_rate(history_arr))
        trend = self._detect_trend(history_arr)
        stability_score = 1.0 - deviation / (abs(self.target or 1.0) + 1e-8)
        entropy = self._compute_entropy(history_arr)

        return CalibrationMetrics(
            delta=delta,
            accuracy=round(accuracy, 6),
            trend=trend,
            deviation=round(deviation, 6),
            stability_score=round(stability_score, 6),
            improvement_rate=round(improvement_rate, 6),
            signal_entropy=round(entropy, 6)
        )

    def _compute_improvement_rate(self, data: np.ndarray) -> float:
        if len(data) < 2:
            return 0.0
        diffs = np.diff(data)
        improvements = diffs[diffs < 0]
        return float(-np.sum(improvements)) / len(data)

    def _detect_trend(self, data: np.ndarray) -> TrendDirection:
        if len(data) < 3:
            return TrendDirection.STABLE

        slope = np.polyfit(range(len(data)), data, 1)[0]
        if abs(slope) < 1e-4:
            return TrendDirection.STABLE
        elif slope < 0:
            return TrendDirection.IMPROVING
        elif slope > 0:
            return TrendDirection.DETERIORATING
        else:
            return TrendDirection.VOLATILE

    def _compute_entropy(self, data: np.ndarray) -> float:
        hist, _ = np.histogram(data, bins=10, density=True)
        hist = hist[hist > 0]
        return float(-np.sum(hist * np.log2(hist + 1e-8)))

    def _empty_metrics(self, value: float) -> CalibrationMetrics:
        return CalibrationMetrics(
            delta=0.0,
            accuracy=1.0,
            trend=TrendDirection.STABLE,
            deviation=0.0,
            stability_score=1.0,
            improvement_rate=0.0,
            signal_entropy=0.0
        )

    def reset(self):
        self.history.clear()
        logger.info("Calibration history reset.")
