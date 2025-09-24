from prometheus_client import start_http_server, Counter, Gauge, Histogram
import logging
import threading

class PrometheusExporter:
    """
    Экспортер метрик логирования для Prometheus.
    Позволяет отслеживать количество логов по уровням, а также время обработки событий.
    """

    def __init__(self, port: int = 8000):
        # Метрики счетчики для уровней логов
        self.log_levels_counter = Counter(
            'app_log_level_total',
            'Количество логов по уровням',
            ['level']
        )
        # Гистограмма времени обработки логов (например, время генерации)
        self.log_processing_time = Histogram(
            'app_log_processing_seconds',
            'Время обработки логов в секундах'
        )
        # Гейдж для текущего состояния (например, количество логов в очереди)
        self.log_queue_size = Gauge(
            'app_log_queue_size',
            'Текущий размер очереди логов'
        )
        # Запуск HTTP сервера экспорта метрик в отдельном потоке
        self._start_server(port)

    def _start_server(self, port):
        thread = threading.Thread(target=start_http_server, args=(port,), daemon=True)
        thread.start()

    def record_log(self, log_record: logging.LogRecord, processing_duration: float = 0.0):
        """
        Обновляет метрики по одному лог-записи.
        :param log_record: объект LogRecord из стандартного logging
        :param processing_duration: время обработки лога (опционально)
        """
        level = log_record.levelname.lower()
        self.log_levels_counter.labels(level=level).inc()
        if processing_duration > 0:
            self.log_processing_time.observe(processing_duration)

    def set_queue_size(self, size: int):
        """
        Устанавливает текущее значение размера очереди логов.
        :param size: количество элементов в очереди
        """
        self.log_queue_size.set(size)
