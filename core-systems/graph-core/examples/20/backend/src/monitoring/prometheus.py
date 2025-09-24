from prometheus_client import Counter, Gauge, Histogram, Summary, start_http_server
import time
import logging

logger = logging.getLogger(__name__)

# Метрики Prometheus
REQUEST_COUNT = Counter(
    'teslaai_request_count', 'Количество обработанных запросов', ['endpoint', 'method', 'status_code']
)
REQUEST_LATENCY = Histogram(
    'teslaai_request_latency_seconds', 'Задержка обработки запроса в секундах', ['endpoint']
)
IN_PROGRESS = Gauge(
    'teslaai_inprogress_requests', 'Количество запросов в обработке'
)

def start_metrics_server(port: int = 8000):
    """
    Запуск HTTP сервера для Prometheus metrics.
    """
    try:
        start_http_server(port)
        logger.info(f"Prometheus metrics server started on port {port}")
    except Exception as e:
        logger.error(f"Ошибка запуска Prometheus сервера: {e}")
        raise

def record_request(endpoint: str, method: str, status_code: int, duration: float):
    """
    Обновление метрик после обработки запроса.
    """
    REQUEST_COUNT.labels(endpoint=endpoint, method=method, status_code=str(status_code)).inc()
    REQUEST_LATENCY.labels(endpoint=endpoint).observe(duration)

class InProgressTracker:
    """
    Контекстный менеджер для подсчёта текущих выполняемых запросов.
    Используется с `with`.
    """
    def __enter__(self):
        IN_PROGRESS.inc()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        IN_PROGRESS.dec()

# Пример использования
if __name__ == "__main__":
    start_metrics_server(8000)
    while True:
        with InProgressTracker():
            start_time = time.time()
            # Имитация работы
            time.sleep(0.5)
            duration = time.time() - start_time
            record_request('/example', 'GET', 200, duration)
