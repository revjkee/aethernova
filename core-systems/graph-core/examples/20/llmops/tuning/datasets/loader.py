"""
llmops.tuning.datasets.loader

Модуль загрузки и первичной обработки датасетов для обучения моделей.
Обеспечивает поддержку различных форматов, фильтрацию и базовую валидацию данных.
"""

import os
import json
import logging
from typing import List, Dict, Union, Iterator

logger = logging.getLogger(__name__)

class DatasetLoader:
    """
    Класс для загрузки и инициализации датасетов.
    Поддерживает загрузку из JSON, JSONL, CSV и других популярных форматов.
    """

    def __init__(self, filepath: str, file_format: str = "jsonl", filter_func=None):
        """
        Инициализация загрузчика.
        
        :param filepath: Путь к файлу с датасетом.
        :param file_format: Формат файла ('json', 'jsonl', 'csv').
        :param filter_func: Функция для фильтрации записей (принимает dict, возвращает bool).
        """
        self.filepath = filepath
        self.file_format = file_format.lower()
        self.filter_func = filter_func

        if not os.path.isfile(self.filepath):
            logger.error(f"Файл датасета не найден: {self.filepath}")
            raise FileNotFoundError(f"Файл датасета не найден: {self.filepath}")

        supported_formats = {'json', 'jsonl', 'csv'}
        if self.file_format not in supported_formats:
            logger.error(f"Неподдерживаемый формат файла: {self.file_format}")
            raise ValueError(f"Неподдерживаемый формат файла: {self.file_format}")

    def load(self) -> Iterator[Dict]:
        """
        Генератор загрузки данных из файла с фильтрацией.
        """
        if self.file_format == 'jsonl':
            yield from self._load_jsonl()
        elif self.file_format == 'json':
            yield from self._load_json()
        elif self.file_format == 'csv':
            yield from self._load_csv()

    def _load_jsonl(self) -> Iterator[Dict]:
        """Загрузка из JSONL (по одной JSON записи на строку)."""
        with open(self.filepath, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, start=1):
                try:
                    data = json.loads(line)
                    if self.filter_func is None or self.filter_func(data):
                        yield data
                except json.JSONDecodeError as e:
                    logger.warning(f"Ошибка парсинга JSONL на строке {line_num}: {e}")

    def _load_json(self) -> Iterator[Dict]:
        """Загрузка из JSON (один массив объектов)."""
        with open(self.filepath, 'r', encoding='utf-8') as f:
            try:
                data_list = json.load(f)
                if not isinstance(data_list, list):
                    logger.error("JSON файл должен содержать массив объектов")
                    raise ValueError("JSON файл должен содержать массив объектов")
                for i, item in enumerate(data_list):
                    if self.filter_func is None or self.filter_func(item):
                        yield item
            except json.JSONDecodeError as e:
                logger.error(f"Ошибка парсинга JSON файла: {e}")

    def _load_csv(self) -> Iterator[Dict]:
        """Загрузка из CSV (использует встроенный csv модуль)."""
        import csv
        with open(self.filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if self.filter_func is None or self.filter_func(row):
                    yield row


def example_filter(record: Dict) -> bool:
    """
    Пример функции фильтрации, исключающей пустые записи и с ограничением длины текста.
    """
    text = record.get('text') or record.get('content') or ''
    return bool(text) and len(text) > 10


if __name__ == "__main__":
    # Пример использования
    loader = DatasetLoader('path/to/dataset.jsonl', 'jsonl', filter_func=example_filter)
    for record in loader.load():
        print(record)
