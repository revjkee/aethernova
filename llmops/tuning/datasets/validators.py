"""
llmops.tuning.datasets.validators

Модуль валидации датасетов:
- Проверка корректности формата данных
- Проверка полноты и отсутствия пропусков
- Валидация типов данных и ключевых полей
- Логирование и выдача ошибок для корректировки
"""

from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class DatasetValidator:
    """
    Класс для комплексной проверки качества и формата датасета.
    Принимает список примеров (dict) и валидирует их по набору правил.
    """

    def __init__(self, required_fields: Optional[List[str]] = None):
        """
        :param required_fields: список обязательных ключей в каждом примере
        """
        self.required_fields = required_fields or ["input", "output"]

    def validate(self, dataset: List[Dict[str, Any]]) -> bool:
        """
        Проверяет весь датасет.
        Возвращает True, если датасет валиден, иначе False.
        """
        valid = True
        for idx, example in enumerate(dataset):
            if not self._validate_example(example, idx):
                valid = False
        return valid

    def _validate_example(self, example: Dict[str, Any], idx: int) -> bool:
        """
        Проверка одного примера датасета.
        """
        for field in self.required_fields:
            if field not in example:
                logger.error(f"Пример {idx}: отсутствует обязательное поле '{field}'")
                return False
            if example[field] is None or example[field] == "":
                logger.error(f"Пример {idx}: поле '{field}' пустое")
                return False
            if not isinstance(example[field], (str, list, dict)):
                logger.error(f"Пример {idx}: поле '{field}' имеет некорректный тип: {type(example[field])}")
                return False
        return True


def validate_schema(example: Dict[str, Any], schema: Dict[str, type]) -> bool:
    """
    Простая валидация примера по схеме {ключ: тип}.
    Возвращает True, если типы совпадают, иначе False.
    """
    for key, expected_type in schema.items():
        if key not in example:
            logger.error(f"Пример не содержит ключ '{key}'")
            return False
        if not isinstance(example[key], expected_type):
            logger.error(f"Ключ '{key}' имеет тип {type(example[key])}, ожидается {expected_type}")
            return False
    return True


if __name__ == "__main__":
    # Демонстрация использования
    sample_dataset = [
        {"input": "Hello world", "output": "Привет мир"},
        {"input": "Test", "output": ""},
        {"input": None, "output": "Ответ"}
    ]

    validator = DatasetValidator()
    is_valid = validator.validate(sample_dataset)
    print(f"Валидация датасета пройдена: {is_valid}")

    schema = {"input": str, "output": str}
    for i, example in enumerate(sample_dataset):
        print(f"Пример {i} соответствует схеме: {validate_schema(example, schema)}")
