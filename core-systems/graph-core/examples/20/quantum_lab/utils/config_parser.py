# quantum-lab/utils/config_parser.py

import yaml
import json
import os

class ConfigParser:
    """
    Класс для парсинга конфигурационных файлов различных форматов:
    YAML и JSON.
    Позволяет загружать, валидировать и получать настройки из файлов.
    """

    SUPPORTED_FORMATS = ('yaml', 'yml', 'json')

    def __init__(self, filepath: str):
        """
        Инициализация с путем к файлу конфигурации.
        Проверяет существование и формат файла.

        :param filepath: Путь к конфигурационному файлу
        """
        self.filepath = filepath
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Файл конфигурации не найден: {filepath}")

        ext = filepath.split('.')[-1].lower()
        if ext not in self.SUPPORTED_FORMATS:
            raise ValueError(f"Поддерживаются только форматы: {self.SUPPORTED_FORMATS}")

        self.format = ext
        self.config = None

    def load(self) -> dict:
        """
        Загрузка и парсинг конфигурации из файла.
        :return: dict с настройками
        """
        with open(self.filepath, 'r', encoding='utf-8') as f:
            if self.format in ('yaml', 'yml'):
                self.config = yaml.safe_load(f)
            elif self.format == 'json':
                self.config = json.load(f)
            else:
                raise ValueError(f"Неподдерживаемый формат: {self.format}")

        if not isinstance(self.config, dict):
            raise ValueError("Конфигурация должна быть словарём")

        return self.config

    def get(self, key: str, default=None):
        """
        Получить значение настройки по ключу с возможностью задать значение по умолчанию.
        Поддерживает ключи с точечной нотацией для вложенных настроек.

        :param key: ключ настройки, например 'database.host'
        :param default: значение по умолчанию, если ключ не найден
        :return: значение настройки или default
        """
        if self.config is None:
            raise RuntimeError("Конфигурация не загружена. Вызовите load() перед get().")

        keys = key.split('.')
        value = self.config
        for k in keys:
            if not isinstance(value, dict) or k not in value:
                return default
            value = value[k]
        return value

