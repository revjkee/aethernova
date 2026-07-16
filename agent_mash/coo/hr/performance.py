# agent_mash/hr/performance.py
from __future__ import annotations

import dataclasses
import json
import math
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


class PerformanceLevel(str, Enum):
    EXCELLENT = "excellent"
    GOOD = "good"
    SATISFACTORY = "satisfactory"
    NEEDS_IMPROVEMENT = "needs_improvement"
    UNSATISFACTORY = "unsatisfactory"


class ReviewStatus(str, Enum):
    DRAFT = "draft"
    SUBMITTED = "submitted"
    APPROVED = "approved"
    REJECTED = "rejected"
    FINALIZED = "finalized"


# ----------------------------
# Core domain objects
# ----------------------------

@dataclass(frozen=True)
class KPI:
    """
    Key Performance Indicator.

    value and target are numeric and compared via direction.
    weight is relative importance in total score.
    """
    id: str
    name: str
    target: float
    value: float
    weight: float = 1.0
    higher_is_better: bool = True
    notes: str = ""

    def validate(self) -> None:
        _validate_id(self.id, "kpi.id")
        _validate_nonempty(self.name, "kpi.name")
        _validate_number(self.target, "kpi.target")
        _validate_number(self.value, "kpi.value")
        _validate_positive(self.weight, "kpi.weight")

    def score(self) -> float:
        """
        Returns normalized score in range 0..1.
        """
        self.validate()
        if self.target == 0:
            return 0.0

        ratio = self.value / self.target
        if not self.higher_is_better:
            ratio = self.target / self.value if self.value != 0 else 0.0

        return _clamp01(ratio)


@dataclass(frozen=True)
class Goal:
    """
    A performance goal consisting of multiple KPIs.
    """
    id: str
    title: str
    description: str
    kpis: Tuple[KPI, ...]
    weight: float = 1.0

    def validate(self) -> None:
        _validate_id(self.id, "goal.id")
        _validate_nonempty(self.title, "goal.title")
        _validate_nonempty(self.description, "goal.description")
        _validate_positive(self.weight, "goal.weight")
        if not self.kpis:
            raise ValueError("goal.kpis must not be empty")
        for k in self.kpis:
            k.validate()

    def score(self) -> float:
        """
        Weighted KPI score normalized to 0..1.
        """
        self.validate()
        total_weight = sum(k.weight for k in self.kpis)
        if total_weight <= 0:
            return 0.0

        acc = 0.0
        for k in self.kpis:
            acc += k.score() * k.weight

        return _clamp01(acc / total_weight)


@dataclass(frozen=True)
class ReviewPeriod:
    """
    Defines a performance review period.
    """
    id: str
    name: str
    start_unix: float
    end_unix: float

    def validate(self) -> None:
        _validate_id(self.id, "period.id")
        _validate_nonempty(self.name, "period.name")
        if self.end_unix <= self.start_unix:
            raise ValueError("period.end_unix must be greater than start_unix")


@dataclass(frozen=True)
class PerformanceReview:
    """
    A performance review for an individual.
    """
    id: str
    employee_id: str
    reviewer_id: str
    period: ReviewPeriod
    goals: Tuple[Goal, ...]
    status: ReviewStatus = ReviewStatus.DRAFT
    created_at_unix: float = field(default_factory=lambda: time.time())
    comments: str = ""

    def validate(self) -> None:
        _validate_id(self.id, "review.id")
        _validate_id(self.employee_id, "review.employee_id")
        _validate_id(self.reviewer_id, "review.reviewer_id")
        self.period.validate()
        if not self.goals:
            raise ValueError("review.goals must not be empty")
        for g in self.goals:
            g.validate()

    def score(self) -> float:
        """
        Overall performance score normalized to 0..100.
        """
        self.validate()
        total_weight = sum(g.weight for g in self.goals)
        if total_weight <= 0:
            return 0.0

        acc = 0.0
        for g in self.goals:
            acc += g.score() * g.weight

        return round(_clamp01(acc / total_weight) * 100.0, 2)

    def level(self) -> PerformanceLevel:
        """
        Maps numeric score to qualitative level.
        """
        s = self.score()
        if s >= 90:
            return PerformanceLevel.EXCELLENT
        if s >= 75:
            return PerformanceLevel.GOOD
        if s >= 60:
            return PerformanceLevel.SATISFACTORY
        if s >= 40:
            return PerformanceLevel.NEEDS_IMPROVEMENT
        return PerformanceLevel.UNSATISFACTORY


# ----------------------------
# Aggregation and reporting
# ----------------------------

@dataclass(frozen=True)
class PerformanceSummary:
    review: PerformanceReview
    score: float
    level: PerformanceLevel

    def to_dict(self) -> Dict[str, Any]:
        return {
            "review_id": self.review.id,
            "employee_id": self.review.employee_id,
            "period_id": self.review.period.id,
            "score": self.score,
            "level": self.level.value,
            "status": self.review.status.value,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)


def summarize_review(review: PerformanceReview) -> PerformanceSummary:
    review.validate()
    return PerformanceSummary(
        review=review,
        score=review.score(),
        level=review.level(),
    )


# ----------------------------
# Serialization helpers
# ----------------------------

def review_to_dict(review: PerformanceReview) -> Dict[str, Any]:
    review.validate()
    return {
        "id": review.id,
        "employee_id": review.employee_id,
        "reviewer_id": review.reviewer_id,
        "status": review.status.value,
        "created_at_unix": review.created_at_unix,
        "comments": review.comments,
        "period": dataclasses.asdict(review.period),
        "goals": [
            {
                "id": g.id,
                "title": g.title,
                "description": g.description,
                "weight": g.weight,
                "kpis": [dataclasses.asdict(k) for k in g.kpis],
            }
            for g in review.goals
        ],
    }


def review_to_json(review: PerformanceReview) -> str:
    return json.dumps(review_to_dict(review), ensure_ascii=False, sort_keys=True)


# ----------------------------
# Validation utilities
# ----------------------------

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\\-]{2,127}$")


def _validate_id(value: str, field_name: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be str")
    if not _ID_RE.fullmatch(value):
        raise ValueError(f"{field_name} must match {_ID_RE.pattern}")


def _validate_nonempty(value: str, field_name: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be str")
    if not value.strip():
        raise ValueError(f"{field_name} must be non-empty")


def _validate_number(value: float, field_name: str) -> None:
    if not isinstance(value, (int, float)):
        raise TypeError(f"{field_name} must be numeric")
    if math.isnan(value) or math.isinf(value):
        raise ValueError(f"{field_name} must be finite")


def _validate_positive(value: float, field_name: str) -> None:
    _validate_number(value, field_name)
    if value <= 0:
        raise ValueError(f"{field_name} must be > 0")


def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return float(x)
