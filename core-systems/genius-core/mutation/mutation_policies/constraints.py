# genius_core/mutation/mutation_policies/constraints.py

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("MutationConstraints")


class ConstraintViolation(Exception):
    def __init__(self, violations: List[str]):
        self.violations = violations
        super().__init__(f"Constraint violations: {violations}")


class MutationConstraints:
    """
    Промышленный модуль валидации мутаций:
    - проверка структурных и семантических ограничений
    - защита от разрушительных мутаций
    - адаптируемый фильтр для Zero-Trust архитектуры
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {
            "max_lines_changed": 100,
            "block_dangerous_calls": True,
            "required_tags": ["@mutation-safe"],
            "forbidden_imports": ["os.system", "subprocess", "eval", "exec"],
            "enforce_semantic_tags": True,
            "max_model_memory": 2048,
            "required_fields": ["description", "impact_score", "tested"]
        }

    def validate(self, mutation: Dict[str, Any]) -> bool:
        """
        Валидация мутации по множеству критериев.
        """
        violations = []

        if self._exceeds_line_limit(mutation):
            violations.append("Too many lines changed")

        if self._contains_forbidden_calls(mutation):
            violations.append("Forbidden call or import detected")

        if self.config["enforce_semantic_tags"] and not self._has_required_tags(mutation):
            violations.append("Missing required semantic tags")

        if not self._has_required_fields(mutation):
            violations.append("Mutation metadata incomplete")

        if violations:
            logger.error(f"Mutation rejected: {violations}")
            raise ConstraintViolation(violations)

        logger.info("Mutation passed constraint validation.")
        return True

    def _exceeds_line_limit(self, mutation: Dict[str, Any]) -> bool:
        changes = mutation.get("lines_changed", 0)
        return changes > self.config["max_lines_changed"]

    def _contains_forbidden_calls(self, mutation: Dict[str, Any]) -> bool:
        content = mutation.get("code", "")
        return any(kw in content for kw in self.config["forbidden_imports"])

    def _has_required_tags(self, mutation: Dict[str, Any]) -> bool:
        tags = mutation.get("tags", [])
        return all(tag in tags for tag in self.config["required_tags"])

    def _has_required_fields(self, mutation: Dict[str, Any]) -> bool:
        return all(f in mutation for f in self.config["required_fields"])

    def add_constraint(self, key: str, value: Any):
        self.config[key] = value
        logger.info(f"Constraint added/updated: {key} = {value}")

    def remove_constraint(self, key: str):
        if key in self.config:
            del self.config[key]
            logger.info(f"Constraint removed: {key}")
