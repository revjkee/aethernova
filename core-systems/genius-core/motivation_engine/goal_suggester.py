# genius-core/motivation-engine/goal_suggester.py

"""
Модуль генерации целей на основе текущих мотивационных импульсов (драйвов).
Переход от внутренних состояний → к формализованным целям AGI.
"""

from typing import List, Dict
from .drive_theory import DriveTheory


class Goal:
    """
    Цель, возникающая из активного мотивационного импульса.
    Атрибуты:
    - имя
    - источник (имя потребности)
    - сила (вес важности)
    - критичность (признак срочности)
    """
    def __init__(self, name: str, source: str, strength: float, critical: bool):
        self.name = name
        self.source = source
        self.strength = strength
        self.critical = critical

    def to_dict(self) -> Dict:
        return {
            "goal": self.name,
            "source": self.source,
            "strength": round(self.strength, 3),
            "critical": self.critical
        }


class GoalSuggester:
    """
    Генератор целей на основе мотивационных сигналов.
    Подключается к DriveTheory и формирует приоритезированный список целей.
    """

    def __init__(self, drive_theory: DriveTheory):
        self.drive_theory = drive_theory
        self.goal_templates = self._load_goal_templates()

    def _load_goal_templates(self) -> Dict[str, str]:
        """
        Словарь: потребность → шаблон цели
        Позволяет превратить drive → goal
        """
        return {
            "energy": "recharge_battery",
            "social": "initiate_dialogue",
            "learning": "explore_new_domain",
            "security": "increase_defense_level",
            "self-optimization": "run_self_diagnostics",
            "exploration": "scan_unfamiliar_zone",
            "alignment": "verify_moral_consistency"
        }

    def suggest_goals(self, max_goals: int = 3) -> List[Goal]:
        """
        Возвращает список целей на основе самых активных мотиваций.
        """
        motivation_signals = self.drive_theory.get_motivation_signals()
        goals = []

        for signal in motivation_signals[:max_goals]:
            source = signal["need"]
            template = self.goal_templates.get(source, f"satisfy_{source}")
            goal = Goal(
                name=template,
                source=source,
                strength=signal["intensity"],
                critical=signal["is_critical"]
            )
            goals.append(goal)

        return goals

    def suggest_goals_as_dict(self, max_goals: int = 3) -> List[Dict]:
        return [g.to_dict() for g in self.suggest_goals(max_goals=max_goals)]
