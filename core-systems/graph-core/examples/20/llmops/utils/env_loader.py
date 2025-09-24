import os
from typing import Optional, Dict
from dotenv import load_dotenv, find_dotenv

class EnvLoader:
    """
    Утилита для загрузки и управления переменными окружения.
    Поддерживает загрузку из .env файлов с возможностью переопределения системных переменных.
    """

    @staticmethod
    def load_env(dotenv_path: Optional[str] = None, override: bool = False) -> None:
        """
        Загружает переменные окружения из файла .env.
        
        :param dotenv_path: путь к .env файлу, если None — ищет автоматически.
        :param override: если True, переменные из .env перезапишут уже установленные в окружении.
        """
        if dotenv_path is None:
            dotenv_path = find_dotenv()
        if dotenv_path:
            load_dotenv(dotenv_path, override=override)

    @staticmethod
    def get_env_var(key: str, default: Optional[str] = None) -> Optional[str]:
        """
        Получить переменную окружения с ключом key.
        Возвращает default, если переменная не установлена.
        """
        return os.getenv(key, default)

    @staticmethod
    def get_env_vars(keys: Optional[list[str]] = None) -> Dict[str, Optional[str]]:
        """
        Получить словарь переменных окружения для заданных ключей.
        Если keys не указан, возвращает все переменные окружения.
        """
        if keys is None:
            return dict(os.environ)
        return {key: os.getenv(key) for key in keys}

    @staticmethod
    def set_env_var(key: str, value: str) -> None:
        """
        Установить или обновить переменную окружения.
        """
        os.environ[key] = value
