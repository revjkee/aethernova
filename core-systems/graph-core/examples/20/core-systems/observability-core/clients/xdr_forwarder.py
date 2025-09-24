import aiohttp
import asyncio
import logging
from typing import Optional, Dict, Any

class XDRForwarder:
    """
    Асинхронный клиент для передачи логов и событий в различные XDR-платформы:
    Cortex XDR, CrowdStrike Falcon, Wazuh.
    """

    def __init__(self, platform: str, api_key: str, endpoint: Optional[str] = None):
        """
        :param platform: Название платформы ('cortex_xdr', 'falcon', 'wazuh')
        :param api_key: API ключ для аутентификации
        :param endpoint: URL API платформы, если нестандартный
        """
        self.platform = platform.lower()
        self.api_key = api_key
        self.session = aiohttp.ClientSession()
        self.endpoint = endpoint or self._default_endpoint()

    def _default_endpoint(self) -> str:
        if self.platform == 'cortex_xdr':
            return 'https://api-xdr.paloaltonetworks.com/public_api/v1/logs/ingest'
        if self.platform == 'falcon':
            return 'https://api.crowdstrike.com/logs/queries/submissions/v1'
        if self.platform == 'wazuh':
            return 'https://wazuh.example.com/manager/api/v4/logs'
        raise ValueError(f"Unknown platform: {self.platform}")

    async def send_logs(self, logs: list) -> bool:
        """
        Отправка логов в выбранную XDR платформу.

        :param logs: Список словарей с логами
        :return: True при успешной отправке, False при ошибке
        """
        headers = self._build_headers()
        payload = self._prepare_payload(logs)

        try:
            async with self.session.post(self.endpoint, json=payload, headers=headers) as resp:
                if resp.status in (200, 202):
                    return True
                else:
                    text = await resp.text()
                    logging.error(f"XDRForwarder: Ошибка отправки логов на {self.platform}, статус {resp.status}, ответ: {text}")
        except Exception as e:
            logging.error(f"XDRForwarder: Исключение при отправке логов на {self.platform}: {e}")

        return False

    def _build_headers(self) -> Dict[str, str]:
        if self.platform == 'cortex_xdr':
            return {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
        if self.platform == 'falcon':
            return {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
        if self.platform == 'wazuh':
            return {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
        return {}

    def _prepare_payload(self, logs: list) -> Any:
        # Универсальная упаковка, при необходимости можно доработать под формат платформы
        if self.platform == 'cortex_xdr':
            return {"logs": logs}
        if self.platform == 'falcon':
            return {"requests": logs}
        if self.platform == 'wazuh':
            return {"data": logs}
        return logs

    async def close(self):
        await self.session.close()
