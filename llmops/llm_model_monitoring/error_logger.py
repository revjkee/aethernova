# llmops/monitoring/error_logger.py

import logging
import threading
from datetime import datetime


class ErrorLogger:
    """
    Модуль для централизованного логирования ошибок в системе.
    Обеспечивает потокобезопасный сбор и хранение ошибок с таймстампом.
    """

    def __init__(self, log_file: str = "error_log.txt"):
        """
        Инициализация логгера с указанием файла для записи.
        :param log_file: путь к файлу лога
        """
        self.log_file = log_file
        self.lock = threading.Lock()
        logging.basicConfig(
            filename=self.log_file,
            filemode='a',
            format='%(asctime)s - %(levelname)s - %(message)s',
            level=logging.ERROR
        )

    def log_error(self, error_message: str, context: str = ""):
        """
        Записать ошибку в лог с дополнительным контекстом.
        :param error_message: текст ошибки
        :param context: дополнительная информация (опционально)
        """
        timestamp = datetime.utcnow().isoformat()
        full_message = f"{timestamp} - ERROR - {error_message}"
        if context:
            full_message += f" | Context: {context}"
        with self.lock:
            logging.error(full_message)

    def get_recent_errors(self, max_lines: int = 100):
        """
        Получить последние строки из файла лога.
        :param max_lines: максимальное количество строк
        :return: список строк лога
        """
        with self.lock:
            try:
                with open(self.log_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                return lines[-max_lines:]
            except FileNotFoundError:
                return []

    def clear_log(self):
        """
        Очистить файл лога.
        """
        with self.lock:
            open(self.log_file, 'w').close()

# Конец файла
