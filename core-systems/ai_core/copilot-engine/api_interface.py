# ai-core/copilot-engine/api_interface.py

import logging
import os
from typing import Optional, Dict, Any

import requests

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class APIInterface:
    """
    Универсальный интерфейс для работы с внешними API (LLM, внутренние сервисы).
    Поддерживает синхронные запросы, управление ключами, базовую обработку ошибок.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: int = 30
    ):
        """
        Инициализация интерфейса.
        :param base_url: базовый URL для всех запросов
        :param api_key: ключ для авторизации (если требуется)
        :param timeout: таймаут запросов в секундах
        """
        self.base_url = base_url or os.getenv("COPILOT_API_URL", "")
        self.api_key = api_key or os.getenv("COPILOT_API_KEY", "")
        self.timeout = timeout

        if not self.base_url:
            logger.warning("APIInterface: base_url не задан")
        else:
            logger.info(f"APIInterface инициализирован с URL: {self.base_url}")

    def _build_headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def post(
        self,
        endpoint: str,
        payload: Dict[str, Any],
        params: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Синхронный POST-запрос.
        :param endpoint: путь относительно base_url
        :param payload: тело запроса
        :param params: query parameters
        :return: ответ в виде словаря или None при ошибке
        """
        url = f"{self.base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        try:
            logger.debug(f"POST {url} | Payload: {payload} | Params: {params}")
            resp = requests.post(
                url,
                json=payload,
                params=params,
                headers=self._build_headers(),
                timeout=self.timeout
            )
            resp.raise_for_status()
            data = resp.json()
            logger.info(f"Успешный POST {url} | Status: {resp.status_code}")
            return data
        except requests.RequestException as e:
            logger.error(f"Ошибка при POST {url}: {e}")
            return None

    def get(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Синхронный GET-запрос.
        :param endpoint: путь относительно base_url
        :param params: query parameters
        :return: ответ в виде словаря или None при ошибке
        """
        url = f"{self.base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        try:
            logger.debug(f"GET {url} | Params: {params}")
            resp = requests.get(
                url,
                params=params,
                headers=self._build_headers(),
                timeout=self.timeout
            )
            resp.raise_for_status()
            data = resp.json()
            logger.info(f"Успешный GET {url} | Status: {resp.status_code}")
            return data
        except requests.RequestException as e:
            logger.error(f"Ошибка при GET {url}: {e}")
            return None

    def health_check(self) -> bool:
        """
        Проверка доступности сервиса.
        :return: True, если сервис отвечает, иначе False.
        """
        resp = self.get("health")
        healthy = resp is not None and resp.get("status") == "ok"
        logger.info(f"Health check: {'OK' if healthy else 'FAIL'}")
        return healthy


if __name__ == "__main__":
    # Пример использования
    api = APIInterface()
    if api.health_check():
        result = api.post("generate", {"prompt": "Hello, world"}, params={"max_tokens": 10})
        print(f"Response: {result}")
