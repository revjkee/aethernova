import asyncio
import aiohttp
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class ForumCollector:
    """
    Асинхронный сборщик данных с форумов.
    Предназначен для загрузки страниц форумов, учитывая особенности пагинации и структуры.
    """

    def __init__(self, base_url: str, session: Optional[aiohttp.ClientSession] = None):
        self.base_url = base_url
        self.session = session or aiohttp.ClientSession()

    async def fetch_page(self, path: str = "") -> Optional[str]:
        """
        Загружает страницу форума по заданному пути.

        :param path: Относительный URL форума
        :return: HTML страницы или None при ошибке
        """
        url = f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    logger.debug(f"Успешно загружена страница форума: {url}")
                    return content
                else:
                    logger.error(f"Ошибка HTTP {response.status} при загрузке {url}")
                    return None
        except Exception as e:
            logger.error(f"Исключение при загрузке страницы форума {url}: {e}")
            return None

    async def close(self):
        """
        Корректно закрывает HTTP сессию.
        """
        await self.session.close()
