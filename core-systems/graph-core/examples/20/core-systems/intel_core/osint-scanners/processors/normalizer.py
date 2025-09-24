from .base_processor import BaseProcessor
import unicodedata
import re

class DataNormalizer(BaseProcessor):
    """
    Класс для нормализации данных в OSINT системе.
    Приводит текстовые данные к единому формату, убирает лишние символы, нормализует Unicode.
    """

    def __init__(self):
        super().__init__()

    def normalize_text(self, text: str) -> str:
        """
        Нормализует строку:
        - приводит к нижнему регистру
        - убирает лишние пробелы
        - нормализует Unicode (NFKC)
        - убирает специальные символы (кроме базовой пунктуации)

        :param text: Входной текст
        :return: Нормализованный текст
        """
        if not isinstance(text, str):
            return ""

        # Unicode нормализация
        text = unicodedata.normalize('NFKC', text)

        # Приведение к нижнему регистру
        text = text.lower()

        # Удаление лишних пробелов
        text = re.sub(r'\s+', ' ', text).strip()

        # Удаление спецсимволов (оставляем буквы, цифры, базовую пунктуацию)
        text = re.sub(r'[^a-z0-9а-яё .,!?-]', '', text)

        return text

    def process(self, data):
        """
        Нормализовать данные.
        Ожидается, что data — это список словарей с текстовыми полями.

        :param data: Список словарей
        :return: Нормализованный список словарей
        """
        if not self.validate(data):
            return []

        normalized = []
        for item in data:
            norm_item = {}
            for key, value in item.items():
                if isinstance(value, str):
                    norm_item[key] = self.normalize_text(value)
                else:
                    norm_item[key] = value
            normalized.append(norm_item)
        return normalized

    def validate(self, data) -> bool:
        """
        Проверка корректности входных данных.

        :param data: Входные данные
        :return: True если данные — итерируемый список словарей, иначе False
        """
        if data is None:
            return False
        try:
            iter(data)
        except TypeError:
            return False

        for item in data:
            if not isinstance(item, dict):
                return False
        return True
