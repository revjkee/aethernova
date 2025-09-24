# AI-platform-core/genius-core/inner-dialogue/reflective_chain.py

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger("ReflectiveChain")

class Thought:
    def __init__(self, content: str, origin: str, timestamp: Optional[str] = None, meta: Optional[Dict[str, Any]] = None):
        self.content = content
        self.origin = origin
        self.timestamp = timestamp or datetime.utcnow().isoformat()
        self.meta = meta or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content": self.content,
            "origin": self.origin,
            "timestamp": self.timestamp,
            "meta": self.meta
        }

class ReflectiveChain:
    """
    Саморефлексивный механизм ИИ — отслеживает поток мыслей, обрабатывает сомнения, корректирует цели.
    Используется для мета-анализа, самоконтроля, деконфликтации решений и построения trace логики.
    """

    def __init__(self, max_depth: int = 10):
        self.thoughts: List[Thought] = []
        self.max_depth = max_depth

    def add_thought(self, content: str, origin: str, meta: Optional[Dict[str, Any]] = None):
        if len(self.thoughts) >= self.max_depth:
            self.thoughts.pop(0)
        thought = Thought(content, origin, meta=meta)
        self.thoughts.append(thought)
        logger.debug(f"[ReflectiveChain] Новая мысль: {thought.to_dict()}")

    def summarize_chain(self) -> str:
        """
        Сводка размышлений: хронологический вывод содержания
        """
        return "\n".join(f"[{t.timestamp}] {t.origin}: {t.content}" for t in self.thoughts)

    def find_conflicts(self) -> List[Dict[str, Any]]:
        """
        Ищет противоречия в цепочке мыслей
        """
        conflicts = []
        for i in range(len(self.thoughts)):
            for j in range(i + 1, len(self.thoughts)):
                ti = self.thoughts[i]
                tj = self.thoughts[j]
                if ti.content.strip().lower() == tj.content.strip().lower():
                    continue
                if self._is_potential_conflict(ti, tj):
                    conflicts.append({
                        "thought_a": ti.to_dict(),
                        "thought_b": tj.to_dict(),
                        "reason": "semantic divergence"
                    })
        return conflicts

    def reflect_and_reframe(self) -> str:
        """
        Анализирует текущую цепочку, формирует итоговое размышление / вывод
        """
        summary = self.summarize_chain()
        conflicts = self.find_conflicts()

        if conflicts:
            logger.warning(f"[ReflectiveChain] Обнаружены внутренние конфликты: {len(conflicts)}")
            return f"После анализа размышлений я заметил противоречия. Необходимо скорректировать стратегию."

        return f"Внутренний анализ завершён. Оснований для пересмотра действий не обнаружено.\n{summary}"

    def _is_potential_conflict(self, t1: Thought, t2: Thought) -> bool:
        """
        Эвристическая проверка на логическое расхождение
        """
        # Пример: если одно высказывание содержит 'не', а другое — нет
        return ("не " in t1.content.lower()) != ("не " in t2.content.lower())

    def export_state(self) -> List[Dict[str, Any]]:
        return [t.to_dict() for t in self.thoughts]
