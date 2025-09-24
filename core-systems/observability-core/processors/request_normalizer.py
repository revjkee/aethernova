# observability/dashboards/processors/request_normalizer.py

import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


class RequestNormalizer:
    """
    Унифицированный нормализатор входных запросов.
    Обеспечивает:
    - Приведение форматов к стандарту
    - Очистку мусора
    - Контекстное извлечение для трассировки
    - Поддержка Zero-Trust логирования
    """

    def __init__(self, default_model: str = "gpt-4", enforce_schema: bool = True):
        self.default_model = default_model
        self.enforce_schema = enforce_schema

    def normalize(self, raw_request: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw_request, dict):
            raise ValueError("Request must be a dictionary")

        normalized = {
            "user_id": raw_request.get("user_id") or raw_request.get("uid") or "anonymous",
            "session_id": raw_request.get("session_id") or raw_request.get("sid") or None,
            "input": raw_request.get("input") or raw_request.get("query") or "",
            "model": raw_request.get("model") or self.default_model,
            "metadata": raw_request.get("metadata", {}),
            "context": raw_request.get("context", {}),
        }

        # Простейшая схема валидации
        if self.enforce_schema:
            if not isinstance(normalized["input"], str):
                raise ValueError("Input must be a string")
            if not normalized["input"].strip():
                raise ValueError("Input cannot be empty")

        logger.debug(f"Normalized request: {normalized}")
        return normalized
