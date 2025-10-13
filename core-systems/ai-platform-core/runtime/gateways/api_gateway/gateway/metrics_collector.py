import time
from typing import Dict, Optional
from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST

class MetricsCollector:
    def __init__(self, registry: Optional[CollectorRegistry] = None):
        self.registry = registry or CollectorRegistry()

        # Счётчик запросов по статусам и методам
        self.request_counter = Counter(
            'api_requests_total',
            'Total number of API requests',
            ['method', 'endpoint', 'status_code'],
            registry=self.registry
        )

        # Гистограмма для времени обработки запросов
        self.request_latency = Histogram(
            'api_request_latency_seconds',
            'Latency of API requests in seconds',
            ['method', 'endpoint'],
            registry=self.registry,
            buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]
        )

        # Gauge для текущего числа активных запросов
        self.active_requests = Gauge(
            'api_active_requests',
            'Current number of active API requests',
            ['endpoint'],
            registry=self.registry
        )

    def start_request(self, method: str, endpoint: str):
        self.active_requests.labels(endpoint=endpoint).inc()
        start_time = time.time()
        return start_time

    def end_request(self, method: str, endpoint: str, status_code: int, start_time: float):
        duration = time.time() - start_time
        self.request_counter.labels(method=method, endpoint=endpoint, status_code=str(status_code)).inc()
        self.request_latency.labels(method=method, endpoint=endpoint).observe(duration)
        self.active_requests.labels(endpoint=endpoint).dec()

    def export_metrics(self) -> bytes:
        """Возвращает метрики в формате Prometheus для HTTP-эндпоинта."""
        return generate_latest(self.registry)

    def get_content_type(self) -> str:
        return CONTENT_TYPE_LATEST
