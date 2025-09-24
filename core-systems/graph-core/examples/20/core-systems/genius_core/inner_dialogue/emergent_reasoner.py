# AI-platform-core/genius-core/inner-dialogue/emergent_reasoner.py

import logging
from typing import List, Dict, Optional

logger = logging.getLogger("EmergentReasoner")

class Premise:
    def __init__(self, text: str, source: str):
        self.text = text
        self.source = source

    def to_dict(self) -> Dict:
        return {"text": self.text, "source": self.source}

class ReasoningStep:
    def __init__(self, inference: str, based_on: List[Premise]):
        self.inference = inference
        self.based_on = based_on

    def to_dict(self) -> Dict:
        return {
            "inference": self.inference,
            "based_on": [p.to_dict() for p in self.based_on]
        }

class EmergentReasoner:
    """
    Модуль логических выводов, основанных на предпосылках и цепочках причинно-следственной связи.
    Используется в explainable AI, внутренних рассуждениях, анализе последствий и построении trace-логики.
    """

    def __init__(self):
        self.premises: List[Premise] = []
        self.reasoning_chain: List[ReasoningStep] = []

    def add_premise(self, text: str, source: str):
        premise = Premise(text, source)
        self.premises.append(premise)
        logger.debug(f"[EmergentReasoner] Добавлена предпосылка: {premise.to_dict()}")

    def reason(self, conclusion: str, supporting_indices: List[int]):
        """
        Строит логический шаг на основе заданных предпосылок
        """
        if any(i >= len(self.premises) for i in supporting_indices):
            raise IndexError("Недопустимый индекс предпосылки")

        supports = [self.premises[i] for i in supporting_indices]
        step = ReasoningStep(conclusion, supports)
        self.reasoning_chain.append(step)
        logger.info(f"[EmergentReasoner] Построено логическое заключение: {step.to_dict()}")

    def explain_latest(self) -> str:
        """
        Формирует объяснение последнего логического вывода
        """
        if not self.reasoning_chain:
            return "Логических выводов пока не сделано."

        step = self.reasoning_chain[-1]
        explanation = f"Вывод: {step.inference}\nОснован на:"
        for p in step.based_on:
            explanation += f"\n - {p.text} (источник: {p.source})"
        return explanation

    def export_trace(self) -> List[Dict]:
        return [step.to_dict() for step in self.reasoning_chain]

    def clear(self):
        self.premises.clear()
        self.reasoning_chain.clear()
        logger.debug("[EmergentReasoner] Очищена логическая память")
