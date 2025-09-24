# observability/dashboards/processors/response_postprocessor.py

import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


class ResponsePostProcessor:
    """
    Обогащает и фильтрует ответы модели перед финальной доставкой.
    Обеспечивает:
    - Обогащение мета-данными
    - Маскирование чувствительных данных
    - Трассировку токенов и latency
    - Интеграцию с PII фильтрами и политиками ретенции
    """

    def __init__(self, enable_token_masking: bool = True, add_trace_info: bool = True):
        self.enable_token_masking = enable_token_masking
        self.add_trace_info = add_trace_info

    def postprocess(self, response: Dict[str, Any], trace_id: str = None) -> Dict[str, Any]:
        if not isinstance(response, dict):
            raise ValueError("Response must be a dictionary")

        processed = dict(response)  # делаем копию

        # Маскирование токенов
        if self.enable_token_masking and "output" in processed:
            processed["output"] = self._mask_tokens(processed["output"])

        # Трассировка
        if self.add_trace_info and trace_id:
            processed["trace_id"] = trace_id

        logger.debug(f"Postprocessed response: {processed}")
        return processed

    def _mask_tokens(self, text: str) -> str:
        """
        Простая маскировка токенов (например, api_key, secret, jwt)
        Можно расширить на основе regex или внешнего словаря
        """
        sensitive_tokens = ["api_key", "secret", "jwt", "access_token"]
        for token in sensitive_tokens:
            text = text.replace(token, "[MASKED]")
        return text
