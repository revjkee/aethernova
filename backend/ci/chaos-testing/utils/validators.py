import logging
import os
import shutil
import socket
from pathlib import Path

logger = logging.getLogger("chaos_validators")
logger.setLevel(logging.INFO)

def validate_interface(interface: str) -> bool:
    """Проверяет, существует ли указанный сетевой интерфейс"""
    try:
        interfaces = os.listdir('/sys/class/net')
        if interface in interfaces:
            return True
        logger.warning(f"Интерфейс '{interface}' не найден в системе.")
        return False
    except Exception as e:
        logger.error(f"Ошибка при проверке интерфейсов: {e}", exc_info=True)
        return False

def validate_binary(binary_name: str) -> bool:
    """Проверяет, доступна ли исполняемая утилита в PATH"""
    path = shutil.which(binary_name)
    if path:
        return True
    logger.warning(f"Утилита '{binary_name}' не найдена в PATH.")
    return False

def validate_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """Проверяет, доступен ли указанный TCP-порт"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        logger.warning(f"Порт {port} на хосте {host} недоступен.")
        return False

def validate_file_exists(file_path: str) -> bool:
    """Проверяет, существует ли указанный файл"""
    path = Path(file_path)
    if path.is_file():
        return True
    logger.warning(f"Файл '{file_path}' не существует.")
    return False
