# Запись истории проверок
# audit_trail_logger.py
# Модуль записи истории проверок в CI/CD для полной трассируемости и аудита

import os
import json
import threading
import datetime
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class AuditTrailLogger:
    """
    Запись истории проверок с детализацией:
    - Время запуска и окончания проверки
    - Тип проверки и результат
    - Сообщения и ошибки
    - Идентификатор сессии/деплоя
    """

    _lock = threading.Lock()

    def __init__(self, log_dir: str):
        self.log_dir = log_dir
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

    def _get_log_path(self, session_id: str) -> str:
        filename = f"audit_{session_id}.json"
        return os.path.join(self.log_dir, filename)

    def log_event(self, session_id: str, event_name: str, status: str, details: Optional[Dict[str, Any]] = None):
        """
        Записать событие проверки в лог.

        :param session_id: Уникальный идентификатор сессии или деплоя
        :param event_name: Имя проверки (например, 'bandit', 'flake8')
        :param status: Статус ('passed', 'failed', 'error')
        :param details: Дополнительные данные (сообщения, ошибки и т.п.)
        """
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"
        record = {
            "timestamp": timestamp,
            "event": event_name,
            "status": status,
            "details": details or {}
        }

        log_path = self._get_log_path(session_id)

        with self._lock:
            if os.path.exists(log_path):
                try:
                    with open(log_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                except Exception as e:
                    logger.error(f"Ошибка чтения лог файла {log_path}: {e}")
                    data = []
            else:
                data = []

            data.append(record)

            try:
                with open(log_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            except Exception as e:
                logger.error(f"Ошибка записи в лог файл {log_path}: {e}")

    def get_audit_trail(self, session_id: str) -> Optional[list]:
        """
        Получить всю историю логов по сессии

        :param session_id: Идентификатор сессии/деплоя
        :return: Список событий или None
        """
        log_path = self._get_log_path(session_id)
        if not os.path.exists(log_path):
            return None
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Ошибка чтения лог файла {log_path}: {e}")
            return None

