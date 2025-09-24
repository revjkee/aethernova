import requests
from bs4 import BeautifulSoup
from .base_parser import BaseParser

class WebsiteParser(BaseParser):
    """
    Парсер для стандартных HTML сайтов.
    Использует requests для загрузки страницы и BeautifulSoup для парсинга HTML.
    """

    def fetch_data(self) -> str:
        """
        Загружает HTML содержимое страницы по URL.
        :return: HTML как строка
        """
        response = requests.get(self.source_url, timeout=10)
        response.raise_for_status()
        return response.text

    def parse(self, raw_data: str) -> dict:
        """
        Извлекает структурированные данные из HTML.
        Здесь пример извлечения заголовка и текста абзацев.
        :param raw_data: HTML страница
        :return: Словарь с данными
        """
        soup = BeautifulSoup(raw_data, 'html.parser')
        title = soup.title.string if soup.title else ''
        paragraphs = [p.get_text(strip=True) for p in soup.find_all('p')]
        return {
            'url': self.source_url,
            'title': title,
            'paragraphs': paragraphs
        }
