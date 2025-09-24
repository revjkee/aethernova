# observability/dashboards/filters/pii_filter.py

import logging
import re
from typing import Dict, Tuple

logger = logging.getLogger("pii_filter")

PII_PATTERNS = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "phone": re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)(?:\(?\d{1,4}\)?[-.\s]?){1,4}\d{1,4}\b"),
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b"),
    "cookie": re.compile(r"(?:sessionid|sid|auth_token|csrftoken)=\w+"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,16}\b")
}

MASKING_TOKEN = "[REDACTED_PII]"


class PiiFilter:
    """
    Фильтр PII-данных — выявляет и маскирует персональные данные в событиях.
    """

    def __init__(self):
        self.redacted_fields = []

    def sanitize(self, event: Dict) -> Dict:
        """
        Проверяет и маскирует поля события на наличие PII.
        Возвращает обновлённое событие и добавляет 'pii_masked: true'.
        """
        enriched = event.copy()
        enriched["pii_masked"] = False

        for key, value in event.items():
            if isinstance(value, str):
                redacted_value, was_masked = self._mask_pii(value)
                if was_masked:
                    enriched[key] = redacted_value
                    enriched["pii_masked"] = True
                    self.redacted_fields.append((key, value))

        return enriched

    def _mask_pii(self, text: str) -> Tuple[str, bool]:
        original = text
        masked = text
        was_masked = False

        for label, pattern in PII_PATTERNS.items():
            if pattern.search(masked):
                masked = pattern.sub(MASKING_TOKEN, masked)
                was_masked = True

        return masked, was_masked

    def get_redacted(self) -> Dict:
        """
        Возвращает список полей, где были найдены и замаскированы PII.
        """
        return self.redacted_fields

    def reset(self):
        """
        Сброс истории замаскированных значений.
        """
        self.redacted_fields.clear()
