# quantum-lab/utils/logger.py

import logging
import sys
from logging.handlers import RotatingFileHandler

class Logger:
    """
    Класс для настройки и управления логированием в системе.
    Поддерживает вывод в консоль и в файл с ротацией.
    """

    def __init__(self, 
                 name: str = "quantum_lab", 
                 log_file: str = "quantum_lab.log",
                 level=logging.INFO,
                 max_bytes: int = 10 * 1024 * 1024,
                 backup_count: int = 5):
        """
        Инициализация логгера с настройками.

        :param name: имя логгера
        :param log_file: путь к файлу лога
        :param level: уровень логирования
        :param max_bytes: максимальный размер файла лога для ротации
        :param backup_count: количество резервных файлов
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)

        formatter = logging.Formatter(
            fmt='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        # Обработчик вывода в консоль
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

        # Обработчик вывода в файл с ротацией
        file_handler = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count, encoding='utf-8')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    def get_logger(self):
        """
        Возвращает объект логгера для использования.

        :return: logging.Logger
        """
        return self.logger

