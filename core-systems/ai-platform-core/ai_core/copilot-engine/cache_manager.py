import time
import threading
from typing import Optional, Dict, Any

class CacheManager:
    """
    Управление кэшем подсказок и ответов AI Copilot Engine.
    Обеспечивает быстрый доступ к ранее вычисленным результатам и снижает нагрузку на модель.
    """

    def __init__(self, ttl_seconds: int = 300):
        """
        :param ttl_seconds: Время жизни кэша в секундах.
        """
        self.ttl_seconds = ttl_seconds
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()

    def set(self, key: str, value: Any) -> None:
        """
        Сохраняет значение в кэш с текущей меткой времени.
        """
        with self.lock:
            self.cache[key] = {
                "value": value,
                "timestamp": time.time()
            }

    def get(self, key: str) -> Optional[Any]:
        """
        Получает значение из кэша, если оно актуально.
        Если запись устарела или отсутствует — возвращает None.
        """
        with self.lock:
            entry = self.cache.get(key)
            if entry:
                age = time.time() - entry["timestamp"]
                if age <= self.ttl_seconds:
                    return entry["value"]
                else:
                    # Удаляем устаревший кэш
                    del self.cache[key]
            return None

    def invalidate(self, key: str) -> None:
        """
        Принудительно удаляет запись из кэша по ключу.
        """
        with self.lock:
            if key in self.cache:
                del self.cache[key]

    def clear(self) -> None:
        """
        Полностью очищает весь кэш.
        """
        with self.lock:
            self.cache.clear()

    def cleanup(self) -> None:
        """
        Удаляет все устаревшие записи из кэша.
        Можно запускать периодически в фоне.
        """
        with self.lock:
            now = time.time()
            keys_to_delete = [k for k, v in self.cache.items() if now - v["timestamp"] > self.ttl_seconds]
            for k in keys_to_delete:
                del self.cache[k]

# Пример использования:
# cache = CacheManager(ttl_seconds=600)
# cache.set("user_prompt_123", "cached response")
# result = cache.get("user_prompt_123")
