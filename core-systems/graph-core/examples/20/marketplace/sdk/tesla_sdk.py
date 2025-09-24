import requests
import threading
from typing import Optional, Dict, Any

class TeslaSDK:
    """
    SDK для взаимодействия с Tesla Marketplace API.
    Обеспечивает безопасные и потокобезопасные запросы.
    """

    BASE_URL = "https://api.tesla-marketplace.com/v1"

    def __init__(self, api_key: str, timeout: int = 10):
        self.api_key = api_key
        self.timeout = timeout
        self._lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        })

    def _request(self, method: str, endpoint: str, params: Optional[Dict[str, Any]] = None,
                 data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self.BASE_URL}{endpoint}"
        with self._lock:
            response = self.session.request(method, url, params=params, json=data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()

    def get_product(self, product_id: str) -> Dict[str, Any]:
        """
        Получить информацию о товаре по ID.
        """
        return self._request("GET", f"/products/{product_id}")

    def list_products(self, category: Optional[str] = None, limit: int = 50) -> Dict[str, Any]:
        """
        Получить список товаров с опциональной фильтрацией по категории.
        """
        params = {"limit": limit}
        if category:
            params["category"] = category
        return self._request("GET", "/products", params=params)

    def create_order(self, user_id: str, product_id: str, quantity: int = 1) -> Dict[str, Any]:
        """
        Создать заказ пользователя.
        """
        data = {
            "user_id": user_id,
            "product_id": product_id,
            "quantity": quantity
        }
        return self._request("POST", "/orders", data=data)

    def get_order_status(self, order_id: str) -> Dict[str, Any]:
        """
        Получить статус заказа по ID.
        """
        return self._request("GET", f"/orders/{order_id}")

    def cancel_order(self, order_id: str) -> Dict[str, Any]:
        """
        Отменить заказ по ID.
        """
        return self._request("POST", f"/orders/{order_id}/cancel")

