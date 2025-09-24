import logging
import logging.config
from pathlib import Path
from logging.handlers import RotatingFileHandler

LOGS_DIR = Path("logs")
LOGS_DIR.mkdir(exist_ok=True)

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "handlers": {
        "bot_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "default",
            "filename": LOGS_DIR / "bot.log",
            "maxBytes": 2_000_000,  # 2MB
            "backupCount": 3,
            "encoding": "utf-8",
        },
        "api_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "default",
            "filename": LOGS_DIR / "api.log",
            "maxBytes": 2_000_000,
            "backupCount": 3,
            "encoding": "utf-8",
        },
        "worker_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "default",
            "filename": LOGS_DIR / "worker.log",
            "maxBytes": 2_000_000,
            "backupCount": 3,
            "encoding": "utf-8",
        },
        "redis_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "default",
            "filename": LOGS_DIR / "redis.log",
            "maxBytes": 2_000_000,
            "backupCount": 3,
            "encoding": "utf-8",
        },
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "default",
            "level": "DEBUG",
        },
    },
    "loggers": {
        "bot": {
            "handlers": ["bot_file", "console"],
            "level": "INFO",
            "propagate": False
        },
        "api": {
            "handlers": ["api_file", "console"],
            "level": "INFO",
            "propagate": False
        },
        "worker": {
            "handlers": ["worker_file", "console"],
            "level": "INFO",
            "propagate": False
        },
        "BookingService": {
            "handlers": ["redis_file"],
            "level": "INFO",
            "propagate": False
        },
        "AdminService": {
            "handlers": ["redis_file"],
            "level": "INFO",
            "propagate": False
        },
        "TimeslotService": {
            "handlers": ["redis_file"],
            "level": "INFO",
            "propagate": False
        },
    }
}


def setup_logging():
    logging.config.dictConfig(LOGGING_CONFIG)
