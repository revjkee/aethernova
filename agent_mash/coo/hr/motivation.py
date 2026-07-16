# agent_mash/hr/motivation.py
from __future__ import annotations

import dataclasses
import math
from dataclasses import dataclass
from typing import Any, Dict, Optional


class MotivationError(RuntimeError):
    pass


class MotivationValidationError(MotivationError):
    pass


def _ensure_float(
    v: Any,
    field: str,
    min_value: float = 0.0,
    max_value: float = 1.0,
) -> float:
    if not isinstance(v, (int, float)):
        raise MotivationValidationError(f"{field} must be float")
    f = float(v)
    if f < min_value or f > max_value:
        raise MotivationValidationError(
            f"{field} must be in range [{min_value}, {max_value}]"
        )
    return f


def _ensure_non_negative(v: Any, field: str) -> float:
    if not isinstance(v, (int, float)):
        raise MotivationValidationError(f"{field} must be numeric")
    f = float(v)
    if f < 0:
        raise MotivationValidationError(f"{field} must be >= 0")
    return f


@dataclass(frozen=True)
class MotivationFactors:
    """
    Формализованные факторы мотивации.
    Все значения нормализованы и проверяемы.
    """

    workload: float
    reward: float
    autonomy: float
    trust: float
    growth: float
    fatigue: float

    @staticmethod
    def validate(
        workload: Any,
        reward: Any,
        autonomy: Any,
        trust: Any,
        growth: Any,
        fatigue: Any,
    ) -> "MotivationFactors":
        return MotivationFactors(
            workload=_ensure_float(workload, "workload"),
            reward=_ensure_float(reward, "reward"),
            autonomy=_ensure_float(autonomy, "autonomy"),
            trust=_ensure_float(trust, "trust"),
            growth=_ensure_float(growth, "growth"),
            fatigue=_ensure_float(fatigue, "fatigue"),
        )


@dataclass(frozen=True)
class MotivationResult:
    """
    Итоговая оценка мотивации.
    """

    index: float
    burnout_risk: float
    details: Dict[str, float]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "burnout_risk": self.burnout_risk,
            "details": dict(self.details),
        }


class MotivationModel:
    """
    Промышленная модель мотивации.
    Все расчёты детерминированы и прозрачны.
    """

    def __init__(
        self,
        weight_workload: float = 0.20,
        weight_reward: float = 0.25,
        weight_autonomy: float = 0.20,
        weight_trust: float = 0.20,
        weight_growth: float = 0.15,
    ) -> None:
        total = (
            weight_workload
            + weight_reward
            + weight_autonomy
            + weight_trust
            + weight_growth
        )
        if not math.isclose(total, 1.0, abs_tol=1e-6):
            raise MotivationValidationError("weights must sum to 1.0")

        self.weights = {
            "workload": weight_workload,
            "reward": weight_reward,
            "autonomy": weight_autonomy,
            "trust": weight_trust,
            "growth": weight_growth,
        }

    def evaluate(self, factors: MotivationFactors) -> MotivationResult:
        """
        Рассчитывает индекс мотивации и риск выгорания.
        """

        effective_workload = 1.0 - factors.workload
        burnout_risk = min(
            1.0,
            0.6 * factors.fatigue + 0.4 * factors.workload,
        )

        score = (
            effective_workload * self.weights["workload"]
            + factors.reward * self.weights["reward"]
            + factors.autonomy * self.weights["autonomy"]
            + factors.trust * self.weights["trust"]
            + factors.growth * self.weights["growth"]
        )

        index = max(0.0, min(1.0, score * (1.0 - burnout_risk)))

        details = {
            "effective_workload": effective_workload,
            "reward": factors.reward,
            "autonomy": factors.autonomy,
            "trust": factors.trust,
            "growth": factors.growth,
            "fatigue": factors.fatigue,
        }

        return MotivationResult(
            index=index,
            burnout_risk=burnout_risk,
            details=details,
        )


def assess_motivation(
    workload: Any,
    reward: Any,
    autonomy: Any,
    trust: Any,
    growth: Any,
    fatigue: Any,
    model: Optional[MotivationModel] = None,
) -> MotivationResult:
    """
    Функция верхнего уровня для оценки мотивации.
    Удобна для использования в governance и decision-pipeline.
    """

    factors = MotivationFactors.validate(
        workload=workload,
        reward=reward,
        autonomy=autonomy,
        trust=trust,
        growth=growth,
        fatigue=fatigue,
    )

    m = model or MotivationModel()
    return m.evaluate(factors)
