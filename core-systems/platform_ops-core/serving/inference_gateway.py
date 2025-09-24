# llmops/serving/inference_gateway.py

import asyncio
import logging
from typing import List, Dict, Any, Optional
import aiohttp

logger = logging.getLogger(__name__)

class InferenceGateway:
    """
    InferenceGateway - распределённый шлюз для маршрутизации запросов
    к множеству LLM (Large Language Models) API с агрегацией результатов.
    
    Основные функции:
    - Параллельное отправление запросов к разным моделям
    - Обработка таймаутов и ошибок
    - Сбор и ранжирование ответов
    - Поддержка расширяемости для новых моделей
    """

    def __init__(self, endpoints: Dict[str, str], timeout: float = 10.0):
        """
        :param endpoints: словарь с именами моделей и URL их API
        :param timeout: максимальное время ожидания ответа от модели
        """
        self.endpoints = endpoints
        self.timeout = timeout

    async def _fetch(self, session: aiohttp.ClientSession, url: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Асинхронный запрос к одному endpoint
        """
        try:
            async with session.post(url, json=payload, timeout=self.timeout) as response:
                if response.status == 200:
                    data = await response.json()
                    logger.debug(f"Response from {url}: {data}")
                    return data
                else:
                    logger.error(f"Non-200 status from {url}: {response.status}")
        except asyncio.TimeoutError:
            logger.warning(f"Timeout from {url}")
        except Exception as e:
            logger.error(f"Exception from {url}: {str(e)}")
        return None

    async def infer(self, prompt: str) -> Dict[str, Any]:
        """
        Запускает параллельные запросы ко всем LLM, возвращает собранные ответы.
        """
        payload = {"prompt": prompt}
        async with aiohttp.ClientSession() as session:
            tasks = [self._fetch(session, url, payload) for url in self.endpoints.values()]
            responses = await asyncio.gather(*tasks)
        
        # Фильтруем успешные ответы
        results = {model: resp for model, resp in zip(self.endpoints.keys(), responses) if resp is not None}
        
        # Можно добавить логику ранжирования или агрегации
        return results

# Ниже может быть добавлен интерфейс для запуска из CLI или интеграции с FastAPI/Flask

if __name__ == "__main__":
    import sys
    import asyncio

    # Пример инициализации с несколькими моделями
    endpoints = {
        "ChatGPT": "http://localhost:8001/api/v1/generate",
        "Claude": "http://localhost:8002/api/v1/generate",
        "Gemini": "http://localhost:8003/api/v1/generate"
    }

    gateway = InferenceGateway(endpoints=endpoints)

    prompt = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "Hello world"

    result = asyncio.run(gateway.infer(prompt))
    print(result)
