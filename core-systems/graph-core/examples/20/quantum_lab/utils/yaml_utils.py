# quantum-lab/utils/yaml_utils.py

import yaml
from yaml.representer import Representer
from yaml.constructor import ConstructorError
from typing import Any

# Расширение стандартного YAML для поддержки более сложных типов и валидации

class YAMLExtensions:
    """
    Класс с утилитами для расширенной работы с YAML:
    - безопасная загрузка с обработкой ошибок
    - поддержка дополнительных кастомных тегов и типов
    - сохранение с правильной сериализацией нестандартных объектов
    """

    @staticmethod
    def safe_load(yaml_str: str) -> Any:
        """
        Безопасно загружает YAML из строки с обработкой исключений.

        :param yaml_str: строка YAML
        :return: загруженный объект Python
        """
        try:
            return yaml.safe_load(yaml_str)
        except yaml.YAMLError as e:
            raise ConstructorError(f"Ошибка загрузки YAML: {e}")

    @staticmethod
    def safe_load_file(file_path: str) -> Any:
        """
        Безопасно загружает YAML из файла.

        :param file_path: путь к YAML файлу
        :return: загруженный объект Python
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return YAMLExtensions.safe_load(content)

    @staticmethod
    def dump(data: Any, file_path: str = None, *, default_flow_style: bool = False) -> str | None:
        """
        Сериализация объекта в YAML строку или запись в файл.

        :param data: объект для сериализации
        :param file_path: опционально, путь для сохранения
        :param default_flow_style: использовать потоковый стиль (False — блоковый)
        :return: YAML строка, если файл не указан
        """
        yaml_str = yaml.dump(data, default_flow_style=default_flow_style, allow_unicode=True)
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(yaml_str)
            return None
        return yaml_str


# Добавление поддержки пользовательских объектов (пример)
def datetime_representer(dumper, data):
    return dumper.represent_scalar('!datetime', data.isoformat())

yaml.add_representer(type(None), lambda dumper, value: dumper.represent_scalar('tag:yaml.org,2002:null', 'null'))
# Пример кастомных тегов и расширений можно добавить по необходимости


