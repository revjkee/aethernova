import re
import logging
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)

def clean_text(text: str) -> str:
    """
    Очистка текста от лишних пробелов, специальных символов и HTML-тегов.
    :param text: Исходный текст
    :return: Очищенный текст
    """
    if not text:
        return ''
    # Удаляем HTML-теги (простейший способ)
    clean = re.sub(r'<[^>]+>', '', text)
    # Удаляем лишние пробелы и символы перевода строки
    clean = re.sub(r'\s+', ' ', clean).strip()
    return clean

def is_valid_url(url: str) -> bool:
    """
    Проверка валидности URL.
    :param url: URL для проверки
    :return: True если URL валидный, иначе False
    """
    try:
        result = urlparse(url)
        return all([result.scheme in ('http', 'https'), result.netloc])
    except Exception:
        return False

def normalize_url(base_url: str, link: str) -> str:
    """
    Нормализация ссылки: превращение относительного URL в абсолютный.
    :param base_url: Базовый URL страницы
    :param link: Относительная или абсолютная ссылка
    :return: Абсолютный URL
    """
    try:
        return urljoin(base_url, link)
    except Exception as e:
        logger.warning(f"Error normalizing URL {link} with base {base_url}: {e}")
        return link

def safe_get(dictionary: dict, key: str, default=None):
    """
    Безопасное получение значения из словаря.
    :param dictionary: словарь
    :param key: ключ
    :param default: значение по умолчанию
    :return: значение или default
    """
    if not isinstance(dictionary, dict):
        return default
    return dictionary.get(key, default)
