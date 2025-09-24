# market_api_adapter.py

import logging
import time
import random
import requests
from typing import Dict, Optional, Any
from threading import Lock
from datetime import datetime, timedelta

logger = logging.getLogger("market_api_adapter")
logger.setLevel(logging.INFO)

class MarketAPIAdapter:
    """
    Унифицированный адаптер для подключения к рыночным данным.
    Поддерживает REST и mock, кеширование, логирование, контроль отказов.
    """

    def __init__(self,
                 symbol: str = "BTCUSDT",
                 mode: str = "mock",  # 'mock' или 'rest'
                 api_url: Optional[str] = None,
                 cache_ttl: int = 5):
        self.symbol = symbol
        self.mode = mode
        self.api_url = api_url or "https://api.binance.com/api/v3/ticker/24hr?symbol=BTCUSDT"
        self.cache_ttl = timedelta(seconds=cache_ttl)
        self.last_data: Optional[Dict[str, Any]] = None
        self.last_fetch: Optional[datetime] = None
        self.lock = Lock()

    def _fetch_from_rest(self) -> Dict[str, Any]:
        try:
            response = requests.get(self.api_url, timeout=2)
            response.raise_for_status()
            data = response.json()
            return {
                "symbol": data.get("symbol", self.symbol),
                "price": float(data["lastPrice"]),
                "rsi": random.uniform(30, 70),  # Пример, требуется реальный RSI
                "macd": random.uniform(-0.2, 0.2),
                "volume": float(data.get("volume", 0)),
                "volatility": random.uniform(0.01, 0.05)
            }
        except Exception as e:
            logger.error(f"[ADAPTER] Ошибка запроса API: {e}")
            raise

    def _fetch_mock(self) -> Dict[str, Any]:
        return {
            "symbol": self.symbol,
            "price": round(random.uniform(28000, 31000), 2),
            "rsi": round(random.uniform(25, 75), 2),
            "macd": round(random.uniform(-0.3, 0.3), 3),
            "volume": random.randint(500_000, 900_000),
            "volatility": round(random.uniform(0.015, 0.04), 4)
        }

    def get_market_data(self) -> Dict[str, Any]:
        with self.lock:
            now = datetime.utcnow()
            if self.last_data and self.last_fetch and (now - self.last_fetch) < self.cache_ttl:
                logger.debug("[ADAPTER] Возвращение кешированных данных.")
                return self.last_data

            try:
                if self.mode == "rest":
                    data = self._fetch_from_rest()
                else:
                    data = self._fetch_mock()
                self.last_data = data
                self.last_fetch = now
                logger.info(f"[ADAPTER] Данные получены: {data}")
                return data
            except Exception as e:
                logger.warning(f"[ADAPTER] Сбой получения данных: {e}")
                return self.last_data or {}

    def reset_cache(self):
        with self.lock:
            self.last_data = None
            self.last_fetch = None
            logger.info("[ADAPTER] Кеш сброшен.")
