import time
from typing import Dict, List

class RateLimiter:
    def __init__(self, max_requests: int, period_seconds: int):
        self.max_requests = max_requests
        self.period_seconds = period_seconds
        self.clients: Dict[str, List[float]] = {}

    def is_allowed(self, client_id: str) -> bool:
        now = time.time()
        window_start = now - self.period_seconds

        if client_id not in self.clients:
            self.clients[client_id] = []

        # Оставляем только запросы в пределах текущего временного окна
        request_times = [t for t in self.clients[client_id] if t > window_start]

        if len(request_times) >= self.max_requests:
            return False

        request_times.append(now)
        self.clients[client_id] = request_times
        return True

    def reset(self, client_id: str):
        if client_id in self.clients:
            self.clients.pop(client_id)

    def update_limits(self, max_requests: int = None, period_seconds: int = None):
        if max_requests is not None:
            self.max_requests = max_requests
        if period_seconds is not None:
            self.period_seconds = period_seconds
