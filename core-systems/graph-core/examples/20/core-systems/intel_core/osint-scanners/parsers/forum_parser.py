import requests
from bs4 import BeautifulSoup
from .base_parser import BaseParser

class ForumParser(BaseParser):
    """
    Парсер форумов с поддержкой извлечения тем, сообщений и авторов.
    Использует requests для загрузки HTML и BeautifulSoup для разбора структуры.
    """

    def fetch_data(self) -> str:
        """
        Загружает HTML страницы форума по URL.
        :return: HTML в виде строки
        """
        response = requests.get(self.source_url, timeout=10)
        response.raise_for_status()
        return response.text

    def parse(self, raw_data: str) -> dict:
        """
        Извлекает темы, сообщения и авторов из HTML страницы форума.
        Возвращает данные в структурированном виде.
        :param raw_data: HTML страницы форума
        :return: Словарь с ключами: topics - список тем с сообщениями и авторами
        """
        soup = BeautifulSoup(raw_data, 'html.parser')

        topics = []
        # Примерная логика: находим контейнеры с темами
        topic_blocks = soup.find_all('div', class_='topic')  # Класс зависит от структуры форума

        for block in topic_blocks:
            title_tag = block.find('a', class_='topic-title')
            author_tag = block.find('span', class_='author-name')
            posts_tags = block.find_all('div', class_='post-message')

            title = title_tag.get_text(strip=True) if title_tag else ''
            author = author_tag.get_text(strip=True) if author_tag else ''
            posts = [post.get_text(strip=True) for post in posts_tags]

            topics.append({
                'title': title,
                'author': author,
                'posts': posts
            })

        return {
            'url': self.source_url,
            'topics': topics
        }
