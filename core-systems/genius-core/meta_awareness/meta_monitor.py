# AI-platform-core/genius-core/meta-awareness/meta_monitor.py

import logging
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger("MetaMonitor")

class ActionLog:
    def __init__(self, action: str, agent_id: str, intention: str, outcome: Optional[str] = None):
        self.timestamp = datetime.utcnow().isoformat()
        self.action = action
        self.agent_id = agent_id
        self.intention = intention
        self.outcome = outcome
        self.verified = False

    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "action": self.action,
            "intention": self.intention,
            "outcome": self.outcome,
            "verified": self.verified
        }

class MetaMonitor:
    """
    Отвечает за мета-контроль агентов: фиксирует действия, проверяет соответствие намерениям и правилам.
    Используется для самонаблюдения, самокоррекции, этического контроля и защиты от отклонений.
    """

    def __init__(self):
        self.history: List[ActionLog] = []

    def register_action(self, action: str, agent_id: str, intention: str):
        log = ActionLog(action=action, agent_id=agent_id, intention=intention)
        self.history.append(log)
        logger.info(f"[MetaMonitor] Зарегистрировано действие агента {agent_id}: '{action}' с намерением '{intention}'")

    def update_outcome(self, agent_id: str, action: str, outcome: str):
        for entry in reversed(self.history):
            if entry.agent_id == agent_id and entry.action == action and entry.outcome is None:
                entry.outcome = outcome
                logger.debug(f"[MetaMonitor] Обновлён результат действия: {entry.to_dict()}")
                break

    def verify_alignment(self, alignment_fn) -> List[Dict]:
        """
        Проверяет соответствие действий заявленным намерениям. alignment_fn(entry) -> bool
        """
        misalignments = []
        for entry in self.history:
            if not entry.verified:
                is_aligned = alignment_fn(entry)
                entry.verified = True
                if not is_aligned:
                    misalignments.append(entry.to_dict())
                    logger.warning(f"[MetaMonitor] Обнаружено отклонение намерения: {entry.to_dict()}")
        return misalignments

    def get_recent_logs(self, limit: int = 20) -> List[Dict]:
        return [entry.to_dict() for entry in self.history[-limit:]]

    def reset(self):
        self.history.clear()
        logger.info("[MetaMonitor] История действий сброшена")
