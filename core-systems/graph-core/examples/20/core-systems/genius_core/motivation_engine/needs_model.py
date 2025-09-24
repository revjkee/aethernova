# genius-core/motivation-engine/needs_model.py

"""
Модуль моделирует внутренние потребности AGI в рамках мотивационного движка.
Основы: теория Маслоу, гомеостатический контроль и drive theory.
"""

from typing import List, Dict
import math
import time


class Need:
    """
    Базовая единица потребности. Каждая потребность имеет:
    - имя
    - текущий уровень удовлетворённости (0.0 — 1.0)
    - внутренний приоритет (важность)
    - скорость истощения
    """

    def __init__(self, name: str, priority: float, decay_rate: float = 0.001):
        self.name = name
        self.priority = priority  # весовая важность
        self.level = 1.0          # 1.0 = полностью удовлетворена
        self.decay_rate = decay_rate
        self.last_update = time.time()

    def decay(self):
        now = time.time()
        delta = now - self.last_update
        self.level = max(0.0, self.level - self.decay_rate * delta)
        self.last_update = now

    def replenish(self, amount: float):
        self.level = min(1.0, self.level + amount)
        self.last_update = time.time()

    def drive(self) -> float:
        """
        Вычисление силы мотивации этой потребности:
        чем ниже уровень, тем выше внутренний импульс (драйв)
        """
        self.decay()
        # нелинейная реакция: чем сильнее дефицит, тем экспоненциальнее драйв
        return self.priority * math.exp(1.0 - self.level)

    def is_critical(self) -> bool:
        return self.level < 0.2


class NeedsModel:
    """
    Хранилище и логика всех потребностей AGI.
    Позволяет:
    - получать список самых острых потребностей
    - обновлять уровни
    - обучать/добавлять новые потребности
    """

    def __init__(self):
        self.needs: Dict[str, Need] = {}

    def register_need(self, name: str, priority: float, decay_rate: float = 0.001):
        if name not in self.needs:
            self.needs[name] = Need(name, priority, decay_rate)

    def update_need(self, name: str, amount: float):
        if name in self.needs:
            self.needs[name].replenish(amount)

    def get_active_drives(self) -> List[Dict]:
        """
        Возвращает список потребностей по степени мотивационного давления
        """
        return sorted(
            [
                {
                    "name": need.name,
                    "drive": need.drive(),
                    "level": round(need.level, 3),
                    "critical": need.is_critical()
                }
                for need in self.needs.values()
            ],
            key=lambda n: n["drive"],
            reverse=True
        )

    def decay_all(self):
        for need in self.needs.values():
            need.decay()

    def get_critical_needs(self) -> List[str]:
        return [n.name for n in self.needs.values() if n.is_critical()]
