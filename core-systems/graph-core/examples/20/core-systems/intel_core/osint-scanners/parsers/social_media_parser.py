import requests
from bs4 import BeautifulSoup
from .base_parser import BaseParser

class SocialMediaParser(BaseParser):
    """
    Парсер социальных сетей для извлечения постов, комментариев и информации о пользователях.
    Использует requests для загрузки и BeautifulSoup для парсинга HTML.
    """

    def fetch_data(self) -> str:
        """
        Загружает страницу социальной сети по заданному URL.
        :return: HTML-код страницы
        """
        response = requests.get(self.source_url, timeout=10)
        response.raise_for_status()
        return response.text

    def parse(self, raw_data: str) -> dict:
        """
        Парсит HTML, извлекая посты, авторов и комментарии.
        Возвращает структурированные данные.
        :param raw_data: HTML страницы
        :return: Словарь с ключами: posts - список постов с авторами и комментариями
        """
        soup = BeautifulSoup(raw_data, 'html.parser')

        posts = []
        # Примерная структура: контейнеры постов с классом 'post'
        post_blocks = soup.find_all('div', class_='post')

        for post in post_blocks:
            author_tag = post.find('span', class_='author-name')
            content_tag = post.find('div', class_='post-content')
            comment_tags = post.find_all('div', class_='comment')

            author = author_tag.get_text(strip=True) if author_tag else ''
            content = content_tag.get_text(strip=True) if content_tag else ''
            comments = [c.get_text(strip=True) for c in comment_tags]

            posts.append({
                'author': author,
                'content': content,
                'comments': comments
            })

        return {
            'url': self.source_url,
            'posts': posts
        }
