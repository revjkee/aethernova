import os
import json
import yaml
from typing import Any, Dict, Optional

class ConfigParser:
    """
    Универсальный парсер конфигурационных файлов с поддержкой JSON и YAML.
    Обеспечивает валидацию ключевых параметров и загрузку с безопасной обработкой ошибок.
    """

    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config: Dict[str, Any] = {}

    def load(self) -> None:
        """
        Загружает конфигурацию из файла, автоматически определяя формат по расширению.
        Поддерживаются JSON и YAML.
        """
        if not os.path.isfile(self.config_path):
            raise FileNotFoundError(f"Конфигурационный файл не найден: {self.config_path}")

        ext = os.path.splitext(self.config_path)[1].lower()
        with open(self.config_path, "r", encoding="utf-8") as f:
            if ext in ['.yaml', '.yml']:
                self.config = yaml.safe_load(f)
            elif ext == '.json':
                self.config = json.load(f)
            else:
                raise ValueError(f"Неподдерживаемый формат конфигурации: {ext}")

        if not isinstance(self.config, dict):
            raise ValueError("Конфигурационный файл должен содержать словарь верхнего уровня")

    def get(self, key: str, default: Optional[Any] = None) -> Any:
        """
        Получить значение из конфигурации по ключу, с возможностью указания значения по умолчанию.
        """
        return self.config.get(key, default)

    def require(self, key: str) -> Any:
        """
        Получить обязательный параметр из конфигурации.
        Если ключ отсутствует, возбуждает исключение.
        """
        if key not in self.config:
            raise KeyError(f"Обязательный параметр конфигурации отсутствует: {key}")
        return self.config[key]

    def validate(self, required_keys: list[str]) -> None:
        """
        Проверяет наличие всех обязательных ключей в конфигурации.
        """
        missing = [k for k in required_keys if k not in self.config]
        if missing:
            raise KeyError(f"Отсутствуют обязательные параметры конфигурации: {missing}")

