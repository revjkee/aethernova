# agent_mash/hr/reviews.py
from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple


# ============================================================
# Errors
# ============================================================
class ReviewsError(RuntimeError):
    """Base HR reviews error."""


class ReviewNotFound(ReviewsError):
    """Raised when review entity not found."""


class ReviewValidationError(ReviewsError):
    """Raised on invalid input or illegal state."""


class ReviewConflict(ReviewsError):
    """Raised on duplicate or conflicting operations."""


# ============================================================
# Core enums
# ============================================================
class ReviewStatus(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    ARCHIVED = "archived"


class ReviewOutcome(str, Enum):
    EXCELLENT = "excellent"
    GOOD = "good"
    AVERAGE = "average"
    POOR = "poor"
    UNDECIDED = "undecided"


# ============================================================
# Identity
# ============================================================
@dataclass(frozen=True, slots=True)
class Person:
    subject_id: str
    display_name: str
    roles: Tuple[str, ...] = ()

    def has_role(self, role: str) -> bool:
        return role in self.roles


# ============================================================
# Review models
# ============================================================
@dataclass(frozen=True, slots=True)
class ReviewCriterion:
    """
    One evaluation criterion.
    """
    criterion_id: str
    title: str
    weight: float  # 0..1


@dataclass(frozen=True, slots=True)
class ReviewScore:
    criterion_id: str
    score: float  # 0..10
    comment: str = ""


@dataclass(frozen=True, slots=True)
class ReviewerInput:
    reviewer: Person
    scores: Tuple[ReviewScore, ...]
    overall_comment: str = ""


@dataclass(slots=True)
class Review:
    """
    Immutable-by-append HR review record.
    """
    review_id: str
    employee: Person
    created_at_utc: str
    period: str  # e.g. "2026-Q1"

    criteria: Tuple[ReviewCriterion, ...]

    status: ReviewStatus = ReviewStatus.OPEN
    outcome: ReviewOutcome = ReviewOutcome.UNDECIDED

    reviewers: Dict[str, ReviewerInput] = field(default_factory=dict)
    final_score: float = 0.0
    resolved_at_utc: str = ""

    meta: Dict[str, Any] = field(default_factory=dict)

    def is_open(self) -> bool:
        return self.status == ReviewStatus.OPEN

    def reviewers_count(self) -> int:
        return len(self.reviewers)


# ============================================================
# Storage abstraction
# ============================================================
class ReviewsStore(Protocol):
    async def put(self, review: Review) -> None:
        ...

    async def get(self, review_id: str) -> Review:
        ...

    async def list_all(self) -> Tuple[Review, ...]:
        ...


class InMemoryReviewsStore:
    """
    Deterministic, async-safe HR review store.
    """
    def __init__(self, *, max_items: int = 100_000) -> None:
        self._lock = asyncio.Lock()
        self._items: Dict[str, Review] = {}
        self._max_items = max_items

    async def put(self, review: Review) -> None:
        async with self._lock:
            if review.review_id not in self._items and len(self._items) >= self._max_items:
                raise ReviewsError("reviews store capacity exceeded")
            self._items[review.review_id] = review

    async def get(self, review_id: str) -> Review:
        async with self._lock:
            r = self._items.get(review_id)
            if r is None:
                raise ReviewNotFound(review_id)
            return r

    async def list_all(self) -> Tuple[Review, ...]:
        async with self._lock:
            return tuple(sorted(self._items.values(), key=lambda r: r.created_at_utc))


# ============================================================
# Engine
# ============================================================
class ReviewsEngine:
    """
    Industrial HR performance review engine.

    Guarantees:
    - deterministic review IDs
    - immutable scoring history
    - weighted scoring
    - role-based reviewer validation
    - auditable lifecycle
    """

    def __init__(
        self,
        *,
        store: Optional[ReviewsStore] = None,
        clock: Optional[callable] = None,
    ) -> None:
        self._store = store or InMemoryReviewsStore()
        self._clock = clock or time.time
        self._lock = asyncio.Lock()

    # --------------------------------------------------------
    # Creation
    # --------------------------------------------------------
    async def create_review(
        self,
        *,
        employee: Person,
        period: str,
        criteria: Sequence[ReviewCriterion],
        meta: Optional[Mapping[str, Any]] = None,
    ) -> Review:
        _validate_employee(employee)
        _validate_criteria(criteria)
        if not period:
            raise ReviewValidationError("period must be non-empty")

        created = _now_utc_iso(self._clock)
        review_id = _make_review_id(employee.subject_id, period)

        review = Review(
            review_id=review_id,
            employee=employee,
            created_at_utc=created,
            period=period,
            criteria=tuple(criteria),
            meta=dict(meta or {}),
        )

        async with self._lock:
            try:
                existing = await self._store.get(review_id)
                return existing
            except ReviewNotFound:
                pass
            await self._store.put(review)

        return review

    # --------------------------------------------------------
    # Access
    # --------------------------------------------------------
    async def get(self, review_id: str) -> Review:
        if not review_id:
            raise ReviewValidationError("review_id required")
        return await self._store.get(review_id)

    async def list_all(self) -> Tuple[Review, ...]:
        return await self._store.list_all()

    # --------------------------------------------------------
    # Review process
    # --------------------------------------------------------
    async def submit_review(
        self,
        *,
        review_id: str,
        input: ReviewerInput,
    ) -> Review:
        _validate_reviewer_input(input)

        async with self._lock:
            review = await self._store.get(review_id)

            if not review.is_open():
                raise ReviewConflict("review is not open")

            if input.reviewer.subject_id in review.reviewers:
                raise ReviewConflict("reviewer already submitted")

            # Role check: reviewer must be manager or hr
            if not input.reviewer.has_role("manager") and not input.reviewer.has_role("hr"):
                raise ReviewValidationError("reviewer role not permitted")

            review.reviewers[input.reviewer.subject_id] = input
            await self._store.put(review)

        return review

    # --------------------------------------------------------
    # Finalization
    # --------------------------------------------------------
    async def finalize_review(self, *, review_id: str) -> Review:
        async with self._lock:
            review = await self._store.get(review_id)

            if not review.is_open():
                raise ReviewConflict("review already finalized")

            if not review.reviewers:
                raise ReviewValidationError("no reviewer input")

            score = _calculate_weighted_score(review.criteria, review.reviewers.values())
            review.final_score = score
            review.outcome = _map_score_to_outcome(score)
            review.status = ReviewStatus.CLOSED
            review.resolved_at_utc = _now_utc_iso(self._clock)

            await self._store.put(review)

        return review

    async def archive(self, *, review_id: str) -> Review:
        async with self._lock:
            review = await self._store.get(review_id)
            if review.status != ReviewStatus.CLOSED:
                raise ReviewConflict("only closed reviews can be archived")
            review.status = ReviewStatus.ARCHIVED
            await self._store.put(review)
        return review


# ============================================================
# Helpers
# ============================================================
def _validate_employee(p: Person) -> None:
    if not p.subject_id:
        raise ReviewValidationError("employee.subject_id required")
    if not p.display_name:
        raise ReviewValidationError("employee.display_name required")


def _validate_criteria(criteria: Sequence[ReviewCriterion]) -> None:
    if not criteria:
        raise ReviewValidationError("criteria must be non-empty")
    total_weight = 0.0
    ids = set()
    for c in criteria:
        if not c.criterion_id:
            raise ReviewValidationError("criterion_id required")
        if c.criterion_id in ids:
            raise ReviewValidationError("duplicate criterion_id")
        ids.add(c.criterion_id)
        if c.weight <= 0 or c.weight > 1:
            raise ReviewValidationError("criterion weight must be in (0,1]")
        total_weight += c.weight
    if abs(total_weight - 1.0) > 0.001:
        raise ReviewValidationError("criteria weights must sum to 1.0")


def _validate_reviewer_input(inp: ReviewerInput) -> None:
    if not inp.reviewer or not inp.reviewer.subject_id:
        raise ReviewValidationError("reviewer required")
    if not inp.scores:
        raise ReviewValidationError("scores required")
    for s in inp.scores:
        if s.score < 0 or s.score > 10:
            raise ReviewValidationError("score must be in 0..10")


def _calculate_weighted_score(
    criteria: Sequence[ReviewCriterion],
    reviewers: Iterable[ReviewerInput],
) -> float:
    weight_map = {c.criterion_id: c.weight for c in criteria}
    totals: Dict[str, float] = {cid: 0.0 for cid in weight_map}
    counts: Dict[str, int] = {cid: 0 for cid in weight_map}

    for r in reviewers:
        for s in r.scores:
            if s.criterion_id in totals:
                totals[s.criterion_id] += s.score
                counts[s.criterion_id] += 1

    final = 0.0
    for cid, weight in weight_map.items():
        if counts[cid] == 0:
            continue
        avg = totals[cid] / counts[cid]
        final += avg * weight

    return round(final, 3)


def _map_score_to_outcome(score: float) -> ReviewOutcome:
    if score >= 8.5:
        return ReviewOutcome.EXCELLENT
    if score >= 7.0:
        return ReviewOutcome.GOOD
    if score >= 5.0:
        return ReviewOutcome.AVERAGE
    return ReviewOutcome.POOR


def _now_utc_iso(clock: callable) -> str:
    return datetime.fromtimestamp(clock(), tz=timezone.utc).isoformat()


def _make_review_id(employee_id: str, period: str) -> str:
    raw = f"{employee_id}:{period}".encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    return f"rev_{digest}"
