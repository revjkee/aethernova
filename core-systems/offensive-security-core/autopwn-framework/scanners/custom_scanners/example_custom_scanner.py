# autopwn-framework/scanners/custom_scanners/example_custom_scanner.py

from core.scanner_base import ScannerBase
from core.vuln_report import VulnerabilityReport
from utils.network import fetch_url
from utils.logging import log_info, log_error, log_debug
from utils.fingerprint import FingerprintUtils
from thirdparty.payload_generator import PayloadFactory

class ExampleCustomScanner(ScannerBase):
    """
    ExampleCustomScanner — шаблон пользовательского сканера для расширения AutoPwn Framework.
    Назначение: сканирует URL на наличие CVE-2024-XXXX у веб-сервера nginx.
    """

    SCANNER_ID = "EXAMPLE-CUSTOM-001"
    NAME = "Nginx CVE-2024-XXXX Scanner"
    DESCRIPTION = "Проверяет наличие уязвимости CVE-2024-XXXX в nginx серверах."

    def __init__(self, target, options=None):
        super().__init__(target, options)
        self.fingerprint = None
        self.payload = None

    async def initialize(self):
        """Подгрузка сигнатур и генерация полезной нагрузки."""
        self.fingerprint = await FingerprintUtils.get_tech_stack(self.target)
        self.payload = PayloadFactory.create("cve_2024_xxxx")
        log_debug(f"[{self.SCANNER_ID}] Fingerprint: {self.fingerprint}")
        log_debug(f"[{self.SCANNER_ID}] Payload initialized.")

    async def is_applicable(self) -> bool:
        """Проверка, применим ли сканер к цели (например, используется nginx)."""
        return "nginx" in self.fingerprint.lower()

    async def scan(self) -> list[VulnerabilityReport]:
        """Основная логика сканирования."""
        if not await self.is_applicable():
            log_info(f"[{self.SCANNER_ID}] Цель не использует nginx — пропуск.")
            return []

        try:
            vulnerable = await self._probe()
            if vulnerable:
                return [self._report()]
        except Exception as e:
            log_error(f"[{self.SCANNER_ID}] Ошибка во время сканирования: {e}")
        return []

    async def _probe(self) -> bool:
        """Отправка запроса с эксплойтом и анализ ответа."""
        url = f"{self.target}/vulnerable_endpoint"
        headers = {"User-Agent": "AutoPwnScanner"}
        data = self.payload.to_dict()
        response = await fetch_url(url, method="POST", data=data, headers=headers)
        log_debug(f"[{self.SCANNER_ID}] Ответ от сервера: {response.status}")
        return response and "vulnerable" in response.text.lower()

    def _report(self) -> VulnerabilityReport:
        """Формирование отчета об уязвимости."""
        return VulnerabilityReport(
            target=self.target,
            scanner_id=self.SCANNER_ID,
            name=self.NAME,
            description=self.DESCRIPTION,
            severity="HIGH",
            evidence="Сервер ответил уязвимым шаблоном.",
            recommendation="Обновите nginx до последней версии или примените патч."
        )
