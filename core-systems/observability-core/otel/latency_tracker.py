# observability/dashboards/otel/latency_tracker.py

import time
from functools import wraps
from opentelemetry import metrics
from opentelemetry.metrics import CallbackOptions
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter

# Инициализация Meter
exporter = OTLPMetricExporter(endpoint="http://localhost:4318/v1/metrics")
reader = PeriodicExportingMetricReader(exporter)
provider = MeterProvider(metric_readers=[reader])
metrics.set_meter_provider(provider)
meter = metrics.get_meter("teslaai.latency")

# Гистограмма для измерения задержек
latency_histogram = meter.create_histogram(
    name="teslaai_latency_seconds",
    unit="s",
    description="Время выполнения операций в секундах"
)


def track_latency(operation_name: str = "unknown"):
    """
    Декоратор для замера времени выполнения функции и экспорта в OpenTelemetry.
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            try:
                return await func(*args, **kwargs)
            finally:
                duration = time.perf_counter() - start_time
                latency_histogram.record(duration, attributes={"operation": operation_name})
        return wrapper
    return decorator
