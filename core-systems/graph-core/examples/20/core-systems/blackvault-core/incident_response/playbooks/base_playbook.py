# base_playbook.py

from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Dict, Any, Optional
import logging
import traceback

from ..utils.telemetry import emit_telemetry_event
from ..utils.policy_guard import validate_intent_zero_trust
from ..utils.audit_log import record_action_audit
from ..utils.rollback_registry import rollback_handler_registry

logger = logging.getLogger("TeslaAI.PlaybookCore")

class PlaybookExecutionError(Exception):
    """Exception for any failure during playbook execution."""


class BasePlaybook(ABC):
    """
    Абстрактный базовый класс для всех playbook-сценариев реагирования.
    Включает безопасный контекст выполнения, аудит, Zero Trust валидацию и поддержку откатов.
    """

    def __init__(self, incident_id: str, context: Dict[str, Any], config: Optional[Dict[str, Any]] = None):
        self.incident_id = incident_id
        self.context = context
        self.config = config or {}
        self.actions: List[Dict[str, Any]] = []
        self.executed_steps: List[str] = []
        self.timestamp = datetime.utcnow().isoformat()

        self._validate_context()

    def _validate_context(self):
        if not self.incident_id or not isinstance(self.context, dict):
            raise ValueError("Недопустимый контекст для playbook")

    def _log_step(self, step: str):
        logger.info(f"[{self.incident_id}] Выполняется шаг: {step}")
        record_action_audit(incident_id=self.incident_id, step=step, timestamp=self.timestamp)

    def _emit_telemetry(self, event: str, metadata: Optional[Dict[str, Any]] = None):
        emit_telemetry_event(source="playbook", event=event, incident_id=self.incident_id, metadata=metadata or {})

    def _zero_trust_check(self, intent: str):
        if not validate_intent_zero_trust(intent, self.context):
            raise PlaybookExecutionError(f"Zero Trust отказал выполнению действия: {intent}")

    def execute(self):
        logger.info(f"[{self.incident_id}] Запуск playbook: {self.__class__.__name__}")
        try:
            self._emit_telemetry("playbook_started", {"playbook": self.__class__.__name__})
            self.run()
            self._emit_telemetry("playbook_completed", {"success": True})
        except Exception as e:
            logger.error(f"[{self.incident_id}] Ошибка playbook: {e}\n{traceback.format_exc()}")
            self._emit_telemetry("playbook_failed", {"error": str(e)})
            self.rollback()
            raise

    @abstractmethod
    def run(self):
        """
        Основная логика сценария реагирования. Должна быть реализована в каждом конкретном playbook.
        """
        pass

    def register_action(self, action_id: str, rollback_callback: Optional[Any] = None):
        self.executed_steps.append(action_id)
        if rollback_callback:
            rollback_handler_registry.register(self.incident_id, action_id, rollback_callback)
        self._log_step(action_id)

    def rollback(self):
        logger.warning(f"[{self.incident_id}] Выполняется откат playbook...")
        try:
            rollback_handler_registry.execute(self.incident_id)
            self._emit_telemetry("playbook_rollback", {"rolled_back": True})
        except Exception as e:
            logger.critical(f"[{self.incident_id}] Откат не удался: {e}")
            self._emit_telemetry("playbook_rollback_failed", {"error": str(e)})
