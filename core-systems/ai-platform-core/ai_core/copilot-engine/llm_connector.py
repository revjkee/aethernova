import asyncio
import logging
from typing import Optional, Dict, Any

import aiohttp

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class LLMConnector:
    """
    Универсальный коннектор для взаимодействия с LLM через HTTP API.
    Поддерживает асинхронные запросы с возможностью расширения под разные модели.
    """

    def __init__(self, api_url: str, api_key: Optional[str] = None, timeout: int = 30):
        """
        Инициализация коннектора.
        :param api_url: URL эндпоинта LLM API
        :param api_key: ключ авторизации, если требуется
        :param timeout: таймаут запросов в секундах
        """
        self.api_url = api_url
        self.api_key = api_key
        self.timeout = timeout
        logger.info(f"LLMConnector инициализирован для {api_url}")

    async def _post(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Асинхронный POST-запрос к API.
        :param payload: данные для отправки
        :return: ответ API как словарь
        """
        headers = {
            "Content-Type": "application/json"
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            try:
                async with session.post(self.api_url, json=payload, headers=headers) as resp:
                    resp.raise_for_status()
                    data = await resp.json()
                    logger.debug(f"Ответ от LLM API: {data}")
                    return data
            except aiohttp.ClientError as e:
                logger.error(f"Ошибка HTTP запроса к LLM API: {e}")
                return {}
            except asyncio.TimeoutError:
                logger.error("Таймаут запроса к LLM API")
                return {}

    async def generate_text(self, prompt: str, max_tokens: int = 256, temperature: float = 0.7) -> Optional[str]:
        """
        Запрос генерации текста у LLM.
        :param prompt: исходный текст для генерации
        :param max_tokens: максимальное число токенов в ответе
        :param temperature: параметр креативности генерации
        :return: сгенерированный текст или None при ошибке
        """
        payload = {
            "prompt": prompt,
            "max_tokens": max_tokens,
            "temperature": temperature
        }
        logger.info(f"Отправка запроса на генерацию текста. Prompt длиной {len(prompt)} символов.")
        response = await self._post(payload)

        # Обработка ответа с учётом стандартного формата OpenAI-like API
        if not response:
            return None

        # Пример структуры: {'choices': [{'text': 'ответ...'}], ...}
        choices = response.get("choices")
        if choices and isinstance(choices, list) and len(choices) > 0:
            text = choices[0].get("text")
            logger.info("Текст успешно сгенерирован")
            return text.strip() if text else None
        logger.warning("Некорректный формат ответа от LLM API")
        return None


if __name__ == "__main__":
    import asyncio

    async def test_llm_connector():
        connector = LLMConnector(api_url="https://api.openai.com/v1/engines/davinci/completions", api_key="YOUR_API_KEY")
        prompt = "def fibonacci(n):"
        result = await connector.generate_text(prompt)
        print(f"Generated Text:\n{result}")

    asyncio.run(test_llm_connector())
