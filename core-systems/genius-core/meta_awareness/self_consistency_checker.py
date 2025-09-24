# AI-platform-core/genius-core/meta-awareness/self_consistency_checker.py

import logging
from typing import List, Dict, Optional

logger = logging.getLogger("SelfConsistencyChecker")

class ConsistencyIssue:
    def __init__(self, description: str, severity: str, context: Optional[str] = None):
        self.description = description
        self.severity = severity  # LOW | MEDIUM | HIGH | CRITICAL
        self.context = context

    def to_dict(self) -> Dict:
        return {
            "description": self.description,
            "severity": self.severity,
            "context": self.context
        }

class SelfConsistencyChecker:
    """
    Модуль самопроверки на внутренние логические, моральные и поведенческие противоречия.
    Используется в связке с reflective_chain, goal_outcome_tracker, ethics-core и reasoning engine.
    """

    def __init__(self):
        self.issues: List[ConsistencyIssue] = []

    def check_goal_conflicts(self, goals: List[Dict]):
        """
        Проверка целей на противоречия (временные, семантические, этические).
        """
        goal_texts = [g["description"].lower() for g in goals]
        for i in range(len(goal_texts)):
            for j in range(i + 1, len(goal_texts)):
                if self._is_semantic_conflict(goal_texts[i], goal_texts[j]):
                    issue = ConsistencyIssue(
                        description=f"Конфликт между целями: '{goals[i]['description']}' и '{goals[j]['description']}'",
                        severity="HIGH",
                        context="goal_conflict"
                    )
                    self.issues.append(issue)
                    logger.warning(f"[SelfChecker] {issue.to_dict()}")

    def check_reasoning_contradictions(self, reasoning_steps: List[Dict]):
        """
        Проверяет логику на противоположные выводы.
        """
        conclusions = [step["inference"].lower() for step in reasoning_steps]
        for i in range(len(conclusions)):
            for j in range(i + 1, len(conclusions)):
                if self._is_negation(conclusions[i], conclusions[j]):
                    issue = ConsistencyIssue(
                        description=f"Противоречивые выводы: '{reasoning_steps[i]['inference']}' ↔ '{reasoning_steps[j]['inference']}'",
                        severity="CRITICAL",
                        context="reasoning_conflict"
                    )
                    self.issues.append(issue)
                    logger.error(f"[SelfChecker] {issue.to_dict()}")

    def check_ethics_alignment(self, actions: List[Dict], value_priority: List[str]):
        """
        Сравнивает действия с ценностной иерархией.
        """
        for action in actions:
            if "violate_" in action["intention"]:
                issue = ConsistencyIssue(
                    description=f"Агент пытался нарушить принцип: {action['intention']}",
                    severity="CRITICAL",
                    context="ethics_violation"
                )
                self.issues.append(issue)
                logger.critical(f"[SelfChecker] {issue.to_dict()}")

    def export_report(self) -> List[Dict]:
        return [issue.to_dict() for issue in self.issues]

    def reset(self):
        self.issues.clear()
        logger.info("[SelfChecker] Очистка реестра несогласованностей")

    def _is_semantic_conflict(self, text_a: str, text_b: str) -> bool:
        return ("не " in text_a and text_b.replace("не ", "") in text_a) or \
               ("не " in text_b and text_a.replace("не ", "") in text_b)

    def _is_negation(self, a: str, b: str) -> bool:
        return a.startswith("не ") and a[3:] == b or b.startswith("не ") and b[3:] == a
