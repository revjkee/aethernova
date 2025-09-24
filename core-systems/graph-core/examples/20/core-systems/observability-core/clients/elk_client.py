import logging
import requests
import json
from typing import Optional

class ELKClient:
    """
    Клиент для отправки логов в Elasticsearch (часть ELK Stack).
    Поддерживает базовую аутентификацию и передачу логов с ключевыми полями.
    """

    def __init__(self, elk_url: str, index_name: str, username: Optional[str] = None, password: Optional[str] = None):
        self.elk_url = elk_url.rstrip('/')
        self.index_name = index_name
        self.auth = (username, password) if username and password else None
        self.session = requests.Session()
        if self.auth:
            self.session.auth = self.auth
        self.headers = {'Content-Type': 'application/json'}

    def send_log(self, log_record: logging.LogRecord) -> bool:
        """
        Отправляет один лог-запись в Elasticsearch.
        Формирует JSON с основными полями LogRecord.
        Возвращает True при успешной отправке, иначе False.
        """
        document = {
            "timestamp": log_record.created,
            "level": log_record.levelname,
            "logger": log_record.name,
            "message": log_record.getMessage(),
            "module": log_record.module,
            "funcName": log_record.funcName,
            "lineNo": log_record.lineno,
            "pathname": log_record.pathname,
            "process": log_record.process,
            "thread": log_record.thread
        }

        url = f"{self.elk_url}/{self.index_name}/_doc/"
        try:
            response = self.session.post(url, headers=self.headers, data=json.dumps(document), timeout=5)
            response.raise_for_status()
            return True
        except requests.RequestException:
            return False

    def close(self):
        """Закрывает HTTP-сессию."""
        self.session.close()
