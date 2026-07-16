# agent_mash/hr/grades.py
from __future__ import annotations

import dataclasses
from enum import Enum
from typing import Dict, FrozenSet, Iterable, List, Optional, Set


class GradeError(RuntimeError):
    pass


class GradeLevel(Enum):
    INTERN = "intern"
    JUNIOR = "junior"
    MIDDLE = "middle"
    SENIOR = "senior"
    LEAD = "lead"
    PRINCIPAL = "principal"
    DIRECTOR = "director"


@dataclasses.dataclass(frozen=True, slots=True)
class CompensationRange:
    currency: str
    min_amount: int
    max_amount: int

    def __post_init__(self) -> None:
        if self.min_amount < 0 or self.max_amount < 0:
            raise GradeError("Compensation amounts must be non-negative")
        if self.min_amount > self.max_amount:
            raise GradeError("min_amount cannot exceed max_amount")


@dataclasses.dataclass(frozen=True, slots=True)
class GradeRequirements:
    experience_years: int
    required_skills: FrozenSet[str]
    responsibility_scope: str

    def __post_init__(self) -> None:
        if self.experience_years < 0:
            raise GradeError("experience_years must be non-negative")
        if not self.responsibility_scope:
            raise GradeError("responsibility_scope must be defined")


@dataclasses.dataclass(frozen=True, slots=True)
class Grade:
    level: GradeLevel
    title: str
    requirements: GradeRequirements
    compensation: CompensationRange
    next_levels: FrozenSet[GradeLevel]

    def can_promote_to(self, target: GradeLevel) -> bool:
        return target in self.next_levels


class GradeRegistry:
    def __init__(self, grades: Iterable[Grade]) -> None:
        self._grades: Dict[GradeLevel, Grade] = {}
        for grade in grades:
            if grade.level in self._grades:
                raise GradeError(f"Duplicate grade level: {grade.level}")
            self._grades[grade.level] = grade

        self._validate_transitions()

    def _validate_transitions(self) -> None:
        for grade in self._grades.values():
            for next_level in grade.next_levels:
                if next_level not in self._grades:
                    raise GradeError(
                        f"Invalid transition from {grade.level} "
                        f"to undefined grade {next_level}"
                    )

    def get(self, level: GradeLevel) -> Grade:
        try:
            return self._grades[level]
        except KeyError as e:
            raise GradeError(f"Grade not found: {level}") from e

    def all_levels(self) -> List[GradeLevel]:
        return list(self._grades.keys())

    def can_promote(
        self,
        current: GradeLevel,
        target: GradeLevel,
        *,
        years_experience: int,
        skills: Set[str],
    ) -> bool:
        grade = self.get(current)
        if not grade.can_promote_to(target):
            return False

        target_grade = self.get(target)
        req = target_grade.requirements

        if years_experience < req.experience_years:
            return False

        if not req.required_skills.issubset(skills):
            return False

        return True


DEFAULT_GRADES: List[Grade] = [
    Grade(
        level=GradeLevel.INTERN,
        title="Intern",
        requirements=GradeRequirements(
            experience_years=0,
            required_skills=frozenset(),
            responsibility_scope="Learning and assisting",
        ),
        compensation=CompensationRange("USD", 0, 2000),
        next_levels=frozenset({GradeLevel.JUNIOR}),
    ),
    Grade(
        level=GradeLevel.JUNIOR,
        title="Junior Specialist",
        requirements=GradeRequirements(
            experience_years=1,
            required_skills=frozenset({"basic_programming"}),
            responsibility_scope="Simple tasks under supervision",
        ),
        compensation=CompensationRange("USD", 2000, 4000),
        next_levels=frozenset({GradeLevel.MIDDLE}),
    ),
    Grade(
        level=GradeLevel.MIDDLE,
        title="Middle Specialist",
        requirements=GradeRequirements(
            experience_years=3,
            required_skills=frozenset({"programming", "system_design"}),
            responsibility_scope="Independent task execution",
        ),
        compensation=CompensationRange("USD", 4000, 7000),
        next_levels=frozenset({GradeLevel.SENIOR}),
    ),
    Grade(
        level=GradeLevel.SENIOR,
        title="Senior Specialist",
        requirements=GradeRequirements(
            experience_years=5,
            required_skills=frozenset({"architecture", "mentoring"}),
            responsibility_scope="Technical leadership",
        ),
        compensation=CompensationRange("USD", 7000, 10000),
        next_levels=frozenset({GradeLevel.LEAD, GradeLevel.PRINCIPAL}),
    ),
    Grade(
        level=GradeLevel.LEAD,
        title="Team Lead",
        requirements=GradeRequirements(
            experience_years=7,
            required_skills=frozenset({"management", "architecture"}),
            responsibility_scope="Team and project ownership",
        ),
        compensation=CompensationRange("USD", 9000, 13000),
        next_levels=frozenset({GradeLevel.DIRECTOR}),
    ),
    Grade(
        level=GradeLevel.PRINCIPAL,
        title="Principal Engineer",
        requirements=GradeRequirements(
            experience_years=8,
            required_skills=frozenset({"deep_architecture", "strategy"}),
            responsibility_scope="Company-wide technical impact",
        ),
        compensation=CompensationRange("USD", 10000, 15000),
        next_levels=frozenset({GradeLevel.DIRECTOR}),
    ),
    Grade(
        level=GradeLevel.DIRECTOR,
        title="Director",
        requirements=GradeRequirements(
            experience_years=10,
            required_skills=frozenset({"leadership", "business_strategy"}),
            responsibility_scope="Organizational leadership",
        ),
        compensation=CompensationRange("USD", 13000, 20000),
        next_levels=frozenset(),
    ),
]


GRADE_REGISTRY = GradeRegistry(DEFAULT_GRADES)

__all__ = [
    "GradeLevel",
    "CompensationRange",
    "GradeRequirements",
    "Grade",
    "GradeRegistry",
    "GRADE_REGISTRY",
    "GradeError",
]
