# market_cache.py

import threading
import time
from typing import Dict, Optional, List, Any
import logging

logger = logging.getLogger("market_cache")
logger.setLevel(logging.INFO)


class MarketCache:
    """
    Кэш маркет-данных для ускорения доступа и минимизации запросов к внешним API.
    """

    def __init__(self, expiration_seconds: int = 10, max_depth: int = 100):
        self._cache: Dict[str, Dict[str, Any]] = {}  # symbol -> market_data
        self._timestamps: Dict[str, float] = {}       # symbol -> last_update_time
        self.expiration_seconds = expiration_seconds
        self.max_depth = max_depth
        self._lock = threading.Lock()

    def update(self, symbol: str, data: Dict[str, Any]):
        """
        Обновляет котировки по инструменту.
        """
        with self._lock:
            self._cache[symbol] = data
            self._timestamps[symbol] = time.time()
            logger.debug(f"[CACHE] Обновлены данные для {symbol}: {data}")

    def get(self, symbol: str) -> Optional[Dict[str, Any]]:
        """
        Возвращает актуальные данные по инструменту, если не устарели.
        """
        with self._lock:
            if symbol not in self._cache:
                logger.warning(f"[CACHE] Нет данных по {symbol}")
                return None

            age = time.time() - self._timestamps[symbol]
            if age > self.expiration_seconds:
                logger.warning(f"[CACHE] Данные по {symbol} устарели ({age:.2f}s)")
                return None

            return self._cache[symbol]

    def bulk_update(self, updates: Dict[str, Dict[str, Any]]):
        """
        Массовое обновление котировок.
        """
        with self._lock:
            for symbol, data in updates.items():
                self._cache[symbol] = data
                self._timestamps[symbol] = time.time()
            logger.debug(f"[CACHE] Массовое обновление {len(updates)} символов")

    def clear_expired(self):
        """
        Удаляет устаревшие записи.
        """
        now = time.time()
        with self._lock:
            expired = [sym for sym, ts in self._timestamps.items() if now - ts > self.expiration_seconds]
            for sym in expired:
                del self._cache[sym]
                del self._timestamps[sym]
                logger.info(f"[CACHE] Очистка устаревшего: {sym}")

    def keys(self) -> List[str]:
        """
        Список всех символов в кэше.
        """
        with self._lock:
            return list(self._cache.keys())

    def snapshot(self) -> Dict[str, Dict[str, Any]]:
        """
        Снимок актуального состояния кэша.
        """
        with self._lock:
            return {k: v.copy() for k, v in self._cache.items()}
