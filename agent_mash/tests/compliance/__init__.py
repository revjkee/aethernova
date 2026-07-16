# agent_mash/tests/compliance/__init__.py

"""
Compliance test suite package for agent_mash.

Purpose
-------
This package contains compliance tests: checks that the system conforms to
explicitly defined security, privacy, reliability, and quality requirements.

Key properties
--------------
- No hidden external dependencies.
- No network calls by default.
- Deterministic by design.
- Clear separation from unit/integration/e2e.
- Extensible without breaking existing imports.

Non-goals
---------
- This package does not define or claim any particular compliance framework
  (ISO, SOC2, GDPR, etc.) is implemented in the repository. It only provides
  a structured place to implement such checks if/when requirements exist.

Usage
-----
Tests in this package should be marked with:
- pytest.mark.compliance (if such marker is configured)
or with a project-specific marker policy.

Note
----
If your pytest configuration does not define a 'compliance' marker, tests
should still function but you may want to add the marker to pytest config.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Sequence, Tuple

__all__ = [
    "ComplianceRequirement",
    "ComplianceResult",
    "RequirementRegistry",
    "default_registry",
]


@dataclass(frozen=True, slots=True)
class ComplianceRequirement:
    """
    Represents a single compliance requirement.

    Fields
    ------
    id:
        Stable identifier, e.g. "SEC-001" or "PRIV-010".
    title:
        Short human-readable name.
    description:
        Longer text describing the requirement.
    severity:
        One of: "low", "medium", "high", "critical".
        This is informational and does not enforce policy on its own.
    references:
        Optional references to documents, tickets, or internal specs.
        This module does not validate the references.
    """

    id: str
    title: str
    description: str
    severity: str = "medium"
    references: Tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ComplianceResult:
    """
    Result of evaluating a compliance requirement.

    Fields
    ------
    requirement_id:
        ID of the requirement.
    passed:
        Whether it passed.
    details:
        Optional structured details for debugging in CI.
    """

    requirement_id: str
    passed: bool
    details: Dict[str, Any] = None  # type: ignore[assignment]


class RequirementRegistry:
    """
    Registry for compliance requirements and their evaluators.

    This registry is intentionally minimal and side-effect free:
    - No imports of project code at module import time.
    - Evaluators are stored as callables and invoked only in tests.

    Evaluator signature:
        evaluator() -> ComplianceResult
    """

    def __init__(self) -> None:
        self._requirements: Dict[str, ComplianceRequirement] = {}
        self._evaluators: Dict[str, Callable[[], ComplianceResult]] = {}

    def register_requirement(self, requirement: ComplianceRequirement) -> None:
        if requirement.id in self._requirements:
            raise ValueError(f"Duplicate compliance requirement id: {requirement.id}")
        self._requirements[requirement.id] = requirement

    def register_evaluator(self, requirement_id: str, evaluator: Callable[[], ComplianceResult]) -> None:
        if requirement_id not in self._requirements:
            raise KeyError(f"Requirement not registered: {requirement_id}")
        if requirement_id in self._evaluators:
            raise ValueError(f"Duplicate evaluator for requirement id: {requirement_id}")
        self._evaluators[requirement_id] = evaluator

    def get_requirement(self, requirement_id: str) -> Optional[ComplianceRequirement]:
        return self._requirements.get(requirement_id)

    def list_requirements(self) -> Tuple[ComplianceRequirement, ...]:
        return tuple(self._requirements.values())

    def list_evaluators(self) -> Tuple[Tuple[str, Callable[[], ComplianceResult]], ...]:
        return tuple(self._evaluators.items())

    def evaluate_all(self) -> Tuple[ComplianceResult, ...]:
        """
        Evaluates all registered compliance checks.

        Behavior:
        - If a requirement has no evaluator, it is ignored here by design.
          The policy for missing evaluators must be enforced by tests, not by registry.
        """
        results: list[ComplianceResult] = []
        for req_id, evaluator in self._evaluators.items():
            res = evaluator()
            results.append(res)
        return tuple(results)


# Default empty registry.
# This file does not claim that any compliance requirements exist in the repository.
default_registry = RequirementRegistry()
