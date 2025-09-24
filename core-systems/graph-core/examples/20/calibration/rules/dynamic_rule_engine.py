import logging
import operator
from typing import Any, Dict, Callable, List, Union, Optional
from pydantic import BaseModel, ValidationError

from calibration.core.validator import Validator
from calibration.core.dependency_graph import DependencyGraph

logger = logging.getLogger("DynamicRuleEngine")

# Допустимые операции (расширяемый DSL)
OPERATORS: Dict[str, Callable[[Any, Any], bool]] = {
    "eq": operator.eq,
    "ne": operator.ne,
    "gt": operator.gt,
    "lt": operator.lt,
    "ge": operator.ge,
    "le": operator.le,
    "in": lambda a, b: a in b,
    "not_in": lambda a, b: a not in b,
}

class RuleCondition(BaseModel):
    parameter: str
    op: str
    value: Any

class RuleAction(BaseModel):
    set_parameter: str
    set_value: Any
    override: bool = True

class DynamicRule(BaseModel):
    id: str
    name: str
    description: Optional[str]
    priority: int = 0
    conditions: List[RuleCondition]
    actions: List[RuleAction]
    enabled: bool = True
    metadata: Optional[Dict[str, Any]] = {}

class DynamicRuleEngine:
    def __init__(self, dependency_graph: DependencyGraph):
        self.rules: List[DynamicRule] = []
        self.graph = dependency_graph
        self.validator = Validator()

    def load_rules(self, rules_data: List[Dict[str, Any]]) -> None:
        for rule_dict in rules_data:
            try:
                rule = DynamicRule(**rule_dict)
                self.rules.append(rule)
                logger.debug(f"Loaded rule: {rule.id}")
            except ValidationError as e:
                logger.warning(f"Failed to validate rule: {e}")

        self.rules.sort(key=lambda r: r.priority, reverse=True)

    def evaluate(self, context: Dict[str, Any]) -> Dict[str, Any]:
        changes = {}
        for rule in self.rules:
            if not rule.enabled:
                continue

            if self._conditions_met(rule.conditions, context):
                for action in rule.actions:
                    if action.override or action.set_parameter not in context:
                        validated = self.validator.validate_value(
                            name=action.set_parameter,
                            value=action.set_value
                        )
                        if validated:
                            changes[action.set_parameter] = action.set_value
                            logger.debug(f"Rule {rule.id} applied: {action.set_parameter} -> {action.set_value}")
                        else:
                            logger.warning(f"Rule {rule.id} failed validation on action: {action.set_parameter}")
        return changes

    def _conditions_met(self, conditions: List[RuleCondition], context: Dict[str, Any]) -> bool:
        for condition in conditions:
            if condition.parameter not in context:
                logger.warning(f"Missing parameter in context: {condition.parameter}")
                return False
            actual_value = context[condition.parameter]
            op_func = OPERATORS.get(condition.op)
            if not op_func:
                logger.warning(f"Unsupported operator: {condition.op}")
                return False
            try:
                if not op_func(actual_value, condition.value):
                    return False
            except Exception as e:
                logger.warning(f"Error during condition evaluation: {e}")
                return False
        return True
