import asyncio
import logging
from typing import Optional, Dict, Any
import aiohttp

class AIAnalyzerClient:
    """
    Клиент для анализа логов с помощью внешнего ИИ-сервиса.
    Отправляет текст лога на ИИ API для выявления аномалий, классификации инцидентов и рекомендации действий.
    """

    def __init__(self, api_url: str, api_key: str, timeout: int = 10):
        self.api_url = api_url
        self.api_key = api_key
        self.timeout = timeout
        self.session = aiohttp.ClientSession()

    async def analyze_log(self, log_record: logging.LogRecord) -> Optional[Dict[str, Any]]:
        """
        Асинхронно отправляет лог на ИИ-сервис и возвращает результат анализа.
        :param log_record: объект LogRecord
        :return: словарь с результатами анализа или None при ошибке
        """
        payload = {
            "timestamp": log_record.created,
            "level": log_record.levelname,
            "message": log_record.getMessage(),
            "logger": log_record.name,
            "module": log_record.module,
            "filename": log_record.filename,
            "funcName": log_record.funcName,
            "lineNo": log_record.lineno,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        try:
            async with self.session.post(self.api_url, json=payload, headers=headers, timeout=self.timeout) as response:
                if response.status == 200:
                    result = await response.json()
                    return result
                else:
                    logging.error(f"AIAnalyzerClient: Ошибка ответа от ИИ сервиса: {response.status}")
        except Exception as e:
            logging.error(f"AIAnalyzerClient: Исключение при запросе к ИИ сервису: {e}")
        return None

    async def close(self):
        await self.session.close()
