import logging
import aiohttp
from typing import Optional, Dict, Any

class SplunkClient:
    """
    Клиент для интеграции с Splunk HTTP Event Collector (HEC).
    Позволяет отправлять логи и события в Splunk асинхронно.
    """

    def __init__(self, hec_url: str, token: str, verify_ssl: bool = True, timeout: int = 10):
        """
        :param hec_url: URL HEC (например, https://splunk.example.com:8088/services/collector)
        :param token: Токен авторизации для HEC
        :param verify_ssl: Проверять SSL сертификат
        :param timeout: Таймаут запросов в секундах
        """
        self.hec_url = hec_url
        self.token = token
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = aiohttp.ClientSession()

    async def send_event(self, event: Dict[str, Any], index: Optional[str] = None, sourcetype: Optional[str] = None) -> bool:
        """
        Отправить событие в Splunk.
        :param event: Словарь с данными события (логом)
        :param index: Название индекса Splunk (если нужно)
        :param sourcetype: Тип источника события (если нужно)
        :return: True при успешной отправке, False при ошибке
        """
        payload = {
            "event": event
        }
        if index:
            payload["index"] = index
        if sourcetype:
            payload["sourcetype"] = sourcetype

        headers = {
            "Authorization": f"Splunk {self.token}",
            "Content-Type": "application/json"
        }

        try:
            async with self.session.post(self.hec_url, json=payload, headers=headers, ssl=self.verify_ssl, timeout=self.timeout) as resp:
                if resp.status == 200:
                    return True
                else:
                    logging.error(f"SplunkClient: Ошибка отправки события, статус: {resp.status}")
        except Exception as e:
            logging.error(f"SplunkClient: Исключение при отправке события: {e}")

        return False

    async def close(self):
        """
        Закрыть сессию aiohttp.
        """
        await self.session.close()
