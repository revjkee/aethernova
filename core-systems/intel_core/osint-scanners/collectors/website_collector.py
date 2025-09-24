import asyncio
import aiohttp
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class WebsiteCollector:
    """
    Асинхронный сборщик данных с сайтов.
    Отвечает за загрузку HTML страниц и первичную обработку контента.
    """

    def __init__(self, base_url: str, session: Optional[aiohttp.ClientSession] = None):
        self.base_url = base_url
        self.session = session or aiohttp.ClientSession()

    async def fetch_page(self, path: str = "") -> Optional[str]:
        """
        Асинхронно загружает страницу по указанному пути.

        :param path: Относительный путь на сайте
        :return: Текст HTML страницы или None в случае ошибки
        """
        url = f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    logger.debug(f"Успешно загружена страница: {url}")
                    return content
                else:
                    logger.error(f"Ошибка загрузки страницы {url}: HTTP {response.status}")
                    return None
        except Exception as e:
            logger.error(f"Исключение при загрузке страницы {url}: {e}")
            return None

    async def close(self):
        """
        Корректно закрывает сессию aiohttp.
        """
        await self.session.close()

