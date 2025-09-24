# observability/dashboards/tools/log_redactor.py

import re
from typing import Dict, Any, List, Optional, Pattern


class LogRedactor:
    """
    Удаляет/маскирует чувствительные данные в логах.
    Использует регулярные выражения для поиска и замены
    персональных данных, токенов, секретов и прочего.
    """

    DEFAULT_PATTERNS = {
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "credit_card": r"\b(?:\d[ -]*?){13,16}\b",
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "jwt": r"eyJ[a-zA-Z0-9-_=]+?\.[a-zA-Z0-9-_=]+?\.[a-zA-Z0-9-_.+/=]*",
        "bearer_token": r"Bearer\s+[a-zA-Z0-9\-._~+/]+=*",
        "api_key": r"(?i)(api_key|apikey|token|secret)[\"':= ]+\s*[a-zA-Z0-9\-._~+/]{8,}"
    }

    def __init__(
        self,
        custom_patterns: Optional[Dict[str, str]] = None,
        mask: str = "[REDACTED]"
    ):
        self.patterns: Dict[str, Pattern] = {}
        self.mask = mask
        self._compile_patterns(custom_patterns or {})

    def _compile_patterns(self, custom: Dict[str, str]):
        combined = self.DEFAULT_PATTERNS.copy()
        combined.update(custom)
        self.patterns = {name: re.compile(pattern) for name, pattern in combined.items()}

    def redact(self, message: str) -> str:
        redacted = message
        for name, pattern in self.patterns.items():
            redacted = pattern.sub(self.mask, redacted)
        return redacted

    def redact_log(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """
        Обрабатывает лог-запись — проходит по значениям и маскирует все строки.
        """
        redacted_log = {}
        for key, value in log.items():
            if isinstance(value, str):
                redacted_log[key] = self.redact(value)
            else:
                redacted_log[key] = value
        return redacted_log
