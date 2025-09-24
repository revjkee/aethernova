import logging
import re

class SafeLogger:
    """
    Класс для безопасного логирования, который автоматически маскирует конфиденциальные данные.
    Обеспечивает запись логов без утечки чувствительной информации.
    """

    SENSITIVE_PATTERNS = [
        re.compile(r'(?i)(password|passwd|pwd|token|apikey|secret)[=:]\s*[^,\s]+'),  # пароли, токены и ключи
        re.compile(r'(?i)creditcard[=:]\s*\d{12,19}'),  # номера кредитных карт
        re.compile(r'(?i)ssn[=:]\s*\d{3}-\d{2}-\d{4}'),  # номера соц. страхования (SSN)
        re.compile(r'(?i)(bearer|jwt)\s+[A-Za-z0-9\-._~+/]+=*'),  # Bearer токены
    ]

    MASK = "[REDACTED]"

    def __init__(self, logger_name: str = __name__):
        self.logger = logging.getLogger(logger_name)
        if not self.logger.hasHandlers():
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def _mask_sensitive(self, message: str) -> str:
        """
        Маскирует чувствительные данные в сообщении.

        :param message: Исходное сообщение лога
        :return: Сообщение с замаскированными данными
        """
        for pattern in self.SENSITIVE_PATTERNS:
            message = pattern.sub(lambda m: m.group(0).split('=')[0] + '=' + self.MASK, message)
        return message

    def info(self, msg: str):
        self.logger.info(self._mask_sensitive(msg))

    def warning(self, msg: str):
        self.logger.warning(self._mask_sensitive(msg))

    def error(self, msg: str):
        self.logger.error(self._mask_sensitive(msg))

    def debug(self, msg: str):
        self.logger.debug(self._mask_sensitive(msg))

    def critical(self, msg: str):
        self.logger.critical(self._mask_sensitive(msg))
