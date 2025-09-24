# llmops/serving/request_normalizer.py

import re
import unicodedata
from typing import Dict, Any

class RequestNormalizer:
    """
    Класс для нормализации и препроцессинга входящих запросов (промптов) перед передачей в LLM.
    Обеспечивает стандартизацию, очистку и минимизацию шума в данных.
    """

    def __init__(self, lowercase: bool = True, remove_punctuation: bool = True, 
                 normalize_unicode: bool = True, collapse_whitespace: bool = True):
        self.lowercase = lowercase
        self.remove_punctuation = remove_punctuation
        self.normalize_unicode = normalize_unicode
        self.collapse_whitespace = collapse_whitespace

        # Регулярное выражение для удаления пунктуации (если нужно)
        self.punct_pattern = re.compile(r'[^\w\s]', re.UNICODE)

    def normalize_text(self, text: str) -> str:
        if self.normalize_unicode:
            text = unicodedata.normalize('NFKC', text)

        if self.lowercase:
            text = text.lower()

        if self.remove_punctuation:
            text = self.punct_pattern.sub('', text)

        if self.collapse_whitespace:
            text = re.sub(r'\s+', ' ', text).strip()

        return text

    def normalize_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Нормализует поля запроса с текстом. 
        Ожидается, что в request_data есть ключ 'prompt' или 'text'.
        """

        normalized = request_data.copy()

        if 'prompt' in normalized and isinstance(normalized['prompt'], str):
            normalized['prompt'] = self.normalize_text(normalized['prompt'])

        if 'text' in normalized and isinstance(normalized['text'], str):
            normalized['text'] = self.normalize_text(normalized['text'])

        # Дополнительно можно нормализовать другие текстовые поля при необходимости

        return normalized
