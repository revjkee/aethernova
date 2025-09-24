import logging
import sys
from logging.handlers import RotatingFileHandler


def setup_logger(name: str = "app_logger", level=logging.INFO, log_file: str = "app.log") -> logging.Logger:
    """
    Настройка логгера с ротацией файлов и выводом в stdout.
    :param name: имя логгера
    :param level: уровень логирования
    :param log_file: файл для логов с ротацией
    :return: настроенный логгер
    """

    logger = logging.getLogger(name)
    logger.setLevel(level)
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Потоковый обработчик (stdout)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    # Файловый обработчик с ротацией
    file_handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    logger.propagate = False

    return logger


logger = setup_logger()
