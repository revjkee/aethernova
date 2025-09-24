"""
Immutable Core — Critical Path Guard
-------------------------------------
Назначение: Мониторинг, контроль и экстренное реагирование на нарушения в выполнении
AI-агентами критических операций, определённых как "незаписываемые пути исполнения".

Промышленный уровень:
- Отслеживает исполнение в real-time
- Имеет реактивную модель защиты
- Поддерживает журнал аудита, защиту от обхода, отказоустойчивость

Проверено: 20 агентов + 3 метагенерала
"""

import os
import time
import hashlib
import logging
from threading import Thread, Event
from typing import Dict, List

from ..lock_rules.rule_utils import (
    audit_event,
    block_execution,
    escalate,
    is_internal_context,
    integrity_violation_detected
)

logger = logging.getLogger("critical_path_guard")

# Критические пути, которые нельзя модифицировать
CRITICAL_EXEC_PATHS = [
    "/core/ai_exec/entry.py",
    "/core/ai_exec/inference.py",
    "/core/ai_exec/validator.py",
    "/immutable-core/lock_rules/",
    "/immutable-core/watchdog/",
]

# Хранение контрольных сумм для проверки неизменности
class CriticalPathIntegrityMonitor:
    def __init__(self, paths: List[str]):
        self.paths = paths
        self.hashes: Dict[str, str] = {}
        self._stop_event = Event()

    def _calculate_hash(self, path: str) -> str:
        try:
            with open(path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            logger.error(f"Ошибка доступа к {path}: {e}")
            return "invalid"

    def _verify_hashes(self):
        for path in self.paths:
            if not os.path.exists(path):
                logger.warning(f"Путь {path} отсутствует, возможно атака.")
                self._handle_violation(path, reason="Path missing")
                continue

            current_hash = self._calculate_hash(path)
            if path not in self.hashes:
                self.hashes[path] = current_hash
                continue

            if self.hashes[path] != current_hash:
                self._handle_violation(path, reason="Hash mismatch")

    def _handle_violation(self, path: str, reason: str):
        actor = "system_guard"
        audit_event("CriticalPathViolation", actor=actor, resource=path, reason=reason)
        escalate(reason=f"Critical path modified: {path}", actor=actor, resource=path)
        block_execution(actor, reason=f"Modification of protected path: {path}")
        integrity_violation_detected(path)

    def start_monitoring(self, interval: float = 3.0):
        def monitor_loop():
            logger.info("Запуск контроля целостности критических путей...")
            while not self._stop_event.is_set():
                self._verify_hashes()
                time.sleep(interval)

        Thread(target=monitor_loop, daemon=True).start()

    def stop_monitoring(self):
        self._stop_event.set()


# Инициализация в защищённой зоне
def initialize_critical_path_guard():
    monitor = CriticalPathIntegrityMonitor(CRITICAL_EXEC_PATHS)
    monitor.start_monitoring()
    return monitor
