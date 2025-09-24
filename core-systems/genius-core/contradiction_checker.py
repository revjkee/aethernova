import logging
from typing import List, Dict, Optional, Tuple
from z3 import Solver, Bool, Not, And, Or, sat

logger = logging.getLogger(__name__)


class ContradictionReport:
    def __init__(self):
        self.conflicts: List[Dict] = []

    def add_conflict(self, module_a: str, module_b: str, reason: str, detail: Optional[Dict] = None):
        conflict = {
            "module_a": module_a,
            "module_b": module_b,
            "reason": reason,
            "detail": detail or {}
        }
        self.conflicts.append(conflict)

    def has_conflicts(self) -> bool:
        return len(self.conflicts) > 0

    def as_dict(self) -> List[Dict]:
        return self.conflicts


class LogicalRule:
    def __init__(self, name: str, formula: Bool, source_module: str):
        self.name = name
        self.formula = formula
        self.source = source_module


class ContradictionChecker:
    def __init__(self):
        self.rules: List[LogicalRule] = []
        self.solver = Solver()

    def add_rule(self, name: str, formula: Bool, source_module: str):
        rule = LogicalRule(name=name, formula=formula, source_module=source_module)
        self.rules.append(rule)
        logger.debug(f"Добавлено правило {name} из модуля {source_module}")

    def check_for_conflicts(self) -> ContradictionReport:
        report = ContradictionReport()

        for i in range(len(self.rules)):
            for j in range(i + 1, len(self.rules)):
                a = self.rules[i]
                b = self.rules[j]

                self.solver.push()
                self.solver.add(And(a.formula, b.formula))
                result = self.solver.check()
                self.solver.pop()

                if result != sat:
                    logger.warning(f"Обнаружено противоречие: {a.name} <-> {b.name}")
                    report.add_conflict(
                        module_a=a.source,
                        module_b=b.source,
                        reason=f"Logical contradiction between {a.name} and {b.name}",
                        detail={
                            "formula_a": str(a.formula),
                            "formula_b": str(b.formula)
                        }
                    )
        return report

    def explain_conflicts(self, report: ContradictionReport):
        for conflict in report.as_dict():
            logger.info(
                f"Модуль {conflict['module_a']} противоречит модулю {conflict['module_b']}: {conflict['reason']}"
            )


# Пример использования
if __name__ == "__main__":
    checker = ContradictionChecker()

    # Примерные булевы переменные
    A = Bool("moduleA_enabled")
    B = Bool("moduleB_requires_A_disabled")

    # Модуль A требует A включён
    checker.add_rule(name="A_active", formula=A, source_module="module_A")

    # Модуль B требует A выключен
    checker.add_rule(name="B_depends_on_not_A", formula=Not(A), source_module="module_B")

    # Проверка
    report = checker.check_for_conflicts()
    if report.has_conflicts():
        checker.explain_conflicts(report)
    else:
        print("Конфликтов не обнаружено.")
