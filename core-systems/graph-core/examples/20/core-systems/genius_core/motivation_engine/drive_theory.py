# genius-core/motivation-engine/drive_theory.py

"""
Drive-модель мотивации: преобразует неудовлетворённые потребности в конкретные мотивационные импульсы.
Основано на теориях Hull, Deci-Ryan и нейроподобных мотивационных схемах.
"""

from typing import Dict, List, Tuple
from .needs_model import Need, NeedsModel


class DriveTheory:
    """
    Управляющий класс, конвертирующий состояние потребностей в активные мотивации.
    Отвечает за:
    - генерацию мотивационных импульсов
    - приоритезацию поведения
    - вычисление направленности поведения
    """

    def __init__(self, needs_model: NeedsModel):
        self.needs_model = needs_model

    def get_motivation_signals(self) -> List[Dict]:
        """
        Вычисляет список мотивационных импульсов (drive-сигналов),
        ранжированный по силе воздействия на поведение.
        """
        drives = self.needs_model.get_active_drives()
        signals = []

        for d in drives:
            signal = {
                "need": d["name"],
                "intensity": round(d["drive"], 3),
                "is_critical": d["critical"],
                "level": d["level"]
            }
            signals.append(signal)

        return sorted(signals, key=lambda s: s["intensity"], reverse=True)

    def select_dominant_drive(self) -> Tuple[str, float]:
        """
        Возвращает имя и силу самого доминирующего драйва.
        """
        signals = self.get_motivation_signals()
        if not signals:
            return ("", 0.0)
        top = signals[0]
        return (top["need"], top["intensity"])

    def compute_action_bias(self, need_name: str) -> float:
        """
        Возвращает вес bias для action selection алгоритмов (RL / planner)
        — используется для модуля поведения
        """
        if need_name not in self.needs_model.needs:
            return 0.0

        need = self.needs_model.needs[need_name]
        # Учитывает не только уровень, но и важность
        return round(need.drive(), 3)

    def get_drive_matrix(self) -> Dict[str, float]:
        """
        Возвращает словарь: потребность → сила drive
        Полезно для goal allocator и planner'ов
        """
        return {
            need.name: round(need.drive(), 3)
            for need in self.needs_model.needs.values()
        }

    def should_interrupt(self, threshold: float = 5.0) -> bool:
        """
        Проверка: стоит ли немедленно прервать текущее поведение из-за сильного драйва.
        Например: голод < 0.1 → interrupt
        """
        signals = self.get_motivation_signals()
        return any(s["is_critical"] or s["intensity"] >= threshold for s in signals)
