import time
import threading
from typing import Dict

class RateLimiter:
    """
    Ограничение количества запросов к LLM (Large Language Model).
    Реализует токен-бакет или фиксированное окно для контроля частоты вызовов.
    """

    def __init__(self, max_requests: int, period_seconds: int):
        """
        :param max_requests: Максимальное число запросов за период.
        :param period_seconds: Длина периода ограничения в секундах.
        """
        self.max_requests = max_requests
        self.period = period_seconds
        self.lock = threading.Lock()
        self.request_timestamps: Dict[str, list[float]] = {}

    def _cleanup_old_requests(self, timestamps: list[float], now: float) -> list[float]:
        """
        Удаляет старые запросы вне текущего периода.
        """
        cutoff = now - self.period
        return [ts for ts in timestamps if ts > cutoff]

    def allow_request(self, client_id: str) -> bool:
        """
        Проверяет, можно ли разрешить новый запрос от клиента с client_id.
        Возвращает True, если запрос разрешён, иначе False.
        """
        now = time.time()
        with self.lock:
            timestamps = self.request_timestamps.get(client_id, [])
            timestamps = self._cleanup_old_requests(timestamps, now)

            if len(timestamps) < self.max_requests:
                timestamps.append(now)
                self.request_timestamps[client_id] = timestamps
                return True
            else:
                # Превышен лимит
                self.request_timestamps[client_id] = timestamps
                return False

    def get_remaining_quota(self, client_id: str) -> int:
        """
        Возвращает число оставшихся запросов в текущем периоде для клиента.
        """
        now = time.time()
        with self.lock:
            timestamps = self.request_timestamps.get(client_id, [])
            timestamps = self._cleanup_old_requests(timestamps, now)
            remaining = max(0, self.max_requests - len(timestamps))
            return remaining

    def reset(self, client_id: str) -> None:
        """
        Сбрасывает все запросы клиента, очищая историю.
        """
        with self.lock:
            if client_id in self.request_timestamps:
                del self.request_timestamps[client_id]

# Пример использования:
# limiter = RateLimiter(max_requests=100, period_seconds=60)
# if limiter.allow_request("user_123"):
#     # выполнять запрос к LLM
# else:
#     # отклонить запрос с сообщением о превышении лимита
