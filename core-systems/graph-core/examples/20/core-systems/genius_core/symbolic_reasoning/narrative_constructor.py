# AI-platform-core/genius-core/symbolic-reasoning/narrative_constructor.py

import logging
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger("NarrativeConstructor")

class NarrativeEvent:
    def __init__(self, event: str, agent_id: str, context: Optional[str] = None):
        self.timestamp = datetime.utcnow().isoformat()
        self.event = event
        self.agent_id = agent_id
        self.context = context

    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "event": self.event,
            "agent_id": self.agent_id,
            "context": self.context
        }

class NarrativeConstructor:
    """
    Построение внутренней нарративной истории агента — последовательной и осмысленной цепи событий, действий и намерений.
    Используется для рефлексии, объяснения, деконфликтации памяти и обоснования решений.
    """

    def __init__(self):
        self.storyline: List[NarrativeEvent] = []

    def record_event(self, event: str, agent_id: str, context: Optional[str] = None):
        """
        Добавляет новое событие в нарратив.
        """
        narrative_event = NarrativeEvent(event=event, agent_id=agent_id, context=context)
        self.storyline.append(narrative_event)
        logger.debug(f"[NarrativeConstructor] Записано событие: {narrative_event.to_dict()}")

    def generate_narrative(self, format: str = "text") -> str:
        """
        Генерирует связную историю на основе записанных событий.
        """
        if not self.storyline:
            return "История пока не сформирована."

        lines = []
        for entry in self.storyline:
            line = f"[{entry.timestamp}] Агент {entry.agent_id} — {entry.event}"
            if entry.context:
                line += f" (Контекст: {entry.context})"
            lines.append(line)

        return "\n".join(lines) if format == "text" else self.export_as_dict()

    def export_as_dict(self) -> List[Dict]:
        return [e.to_dict() for e in self.storyline]

    def summarize_narrative(self) -> Dict[str, int]:
        """
        Подсчитывает статистику нарратива (кол-во событий, уникальных агентов и тем).
        """
        agents = set()
        contexts = set()
        for entry in self.storyline:
            agents.add(entry.agent_id)
            if entry.context:
                contexts.add(entry.context)
        return {
            "total_events": len(self.storyline),
            "unique_agents": len(agents),
            "distinct_contexts": len(contexts)
        }

    def reset(self):
        self.storyline.clear()
        logger.info("[NarrativeConstructor] Нарратив сброшен")
