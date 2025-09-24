import logging
import logging.handlers
import os
import sys

LOG_DIR = os.path.join(os.path.dirname(__file__), '../../logs')
LOG_FILE = os.path.join(LOG_DIR, 'deployment.log')
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
BACKUP_COUNT = 5

def ensure_log_dir():
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)

def get_logger(name='deployment_logger'):
    ensure_log_dir()

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    if not logger.hasHandlers():
        # Формат логов с timestamp, уровнем и сообщением
        formatter = logging.Formatter('%(asctime)s | %(levelname)-8s | %(message)s')

        # Ротация логов по размеру с бэкапами
        file_handler = logging.handlers.RotatingFileHandler(
            LOG_FILE, maxBytes=MAX_LOG_SIZE, backupCount=BACKUP_COUNT, encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)

        # Вывод в stdout, INFO и выше
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger

logger = get_logger()

def debug(msg):
    logger.debug(msg)

def info(msg):
    logger.info(msg)

def warning(msg):
    logger.warning(msg)

def error(msg):
    logger.error(msg)

def critical(msg):
    logger.critical(msg)
