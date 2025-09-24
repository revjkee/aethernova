import socket
import requests
import logging

logger = logging.getLogger(__name__)

def is_host_reachable(host: str, port: int = 80, timeout: float = 3.0) -> bool:
    """
    Проверяет, доступен ли хост по указанному порту.
    
    :param host: IP или доменное имя хоста.
    :param port: Порт для проверки (по умолчанию 80).
    :param timeout: Время ожидания соединения в секундах.
    :return: True, если хост доступен, иначе False.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logger.debug(f"Host {host}:{port} недоступен: {e}")
        return False

def http_get(url: str, headers: dict = None, timeout: float = 5.0) -> requests.Response:
    """
    Выполняет HTTP GET запрос.
    
    :param url: URL для запроса.
    :param headers: Заголовки запроса.
    :param timeout: Таймаут запроса в секундах.
    :return: Объект ответа requests.Response.
    :raises: requests.RequestException при ошибках.
    """
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        return response
    except requests.RequestException as e:
        logger.error(f"Ошибка HTTP GET {url}: {e}")
        raise

def resolve_hostname(hostname: str) -> str:
    """
    Преобразует доменное имя в IP адрес.
    
    :param hostname: Доменное имя.
    :return: IP адрес в строковом формате.
    :raises: socket.gaierror если имя не разрешается.
    """
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.gaierror as e:
        logger.error(f"Не удалось разрешить hostname {hostname}: {e}")
        raise
