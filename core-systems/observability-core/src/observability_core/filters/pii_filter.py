# observability/dashboards/filters/pii_filter.py

import logging
import re
from typing import Any

logger = logging.getLogger("pii_filter")

PII_PATTERNS = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "phone": re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)(?:\(?\d{1,4}\)?[-.\s]?){1,4}\d{1,4}\b"),
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b"),
    "cookie": re.compile(r"(?:sessionid|sid|auth_token|csrftoken)=\w+"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
}

MASKING_TOKEN = "[REDACTED_PII]"


class PiiFilter:
    """
    Фильтр PII-данных — выявляет и маскирует персональные данные в событиях.
    """

    def __init__(self):
        self.redacted_fields: list[str] = []

    def sanitize(self, event: dict) -> dict:
        """
        Проверяет и маскирует поля события на наличие PII.
        Возвращает обновлённое событие и добавляет 'pii_masked: true'.
        """
        self.redacted_fields.clear()
        enriched = self._sanitize_value(event, path="")
        enriched["pii_masked"] = bool(self.redacted_fields)
        return enriched

    def filter(self, event: dict) -> dict:
        return self.sanitize(event)

    def _sanitize_value(self, value: Any, *, path: str) -> Any:
        if isinstance(value, dict):
            return {
                key: self._sanitize_value(
                    item,
                    path=f"{path}.{key}" if path else str(key),
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [
                self._sanitize_value(item, path=f"{path}[{index}]")
                for index, item in enumerate(value)
            ]
        if isinstance(value, str):
            masked, was_masked = self._mask_pii(value)
            if was_masked:
                self.redacted_fields.append(path)
            return masked
        return value

    def _mask_pii(self, text: str) -> tuple[str, bool]:
        masked = text
        was_masked = False

        for pattern in PII_PATTERNS.values():
            if pattern.search(masked):
                masked = pattern.sub(MASKING_TOKEN, masked)
                was_masked = True

        return masked, was_masked

    def get_redacted(self) -> list[str]:
        """
        Возвращает список полей, где были найдены и замаскированы PII.
        """
        return self.redacted_fields

    def reset(self):
        """
        Сброс истории замаскированных значений.
        """
        self.redacted_fields.clear()


PIIFilter = PiiFilter
