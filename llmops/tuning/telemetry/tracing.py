"""
llmops.tuning.telemetry.tracing

Модуль интеграции OpenTelemetry для трассировки и мониторинга fine-tuning и RLHF процессов.
Обеспечивает автоматический сбор и экспорт метрик и трейсов.
"""

from opentelemetry import trace, metrics
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider, export as trace_export
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import ConsoleMetricExporter, PeriodicExportingMetricReader

import logging
import os

logger = logging.getLogger("llmops.tuning.telemetry.tracing")

# Инициализация провайдера ресурсов с базовыми атрибутами
resource = Resource.create({
    "service.name": "llmops-finetuning",
    "service.version": "1.0.0",
    "environment": os.getenv("ENVIRONMENT", "development")
})

# Настройка провайдера трейсинга
trace_provider = TracerProvider(resource=resource)
trace.set_tracer_provider(trace_provider)

# Экспортер для вывода в консоль (можно заменить на Jaeger, Zipkin, OTLP и др.)
console_exporter = ConsoleSpanExporter()
span_processor = BatchSpanProcessor(console_exporter)
trace_provider.add_span_processor(span_processor)

# Получаем трейсера
tracer = trace.get_tracer(__name__)

# Настройка провайдера метрик
metric_reader = PeriodicExportingMetricReader(ConsoleMetricExporter(), export_interval_millis=5000)
meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
metrics.set_meter_provider(meter_provider)
meter = metrics.get_meter(__name__)

# Пример создания счетчика метрик
training_step_counter = meter.create_counter(
    name="training_steps",
    description="Number of training steps executed",
    unit="1"
)

def start_training_span(name: str):
    """
    Создать и запустить span для отслеживания этапа обучения.
    Использование:
        with start_training_span("load_data"):
            # код
    """
    return tracer.start_as_current_span(name)

def add_training_step(count: int = 1):
    """
    Увеличить счетчик шагов обучения.
    """
    training_step_counter.add(count)

# Инициализация может быть расширена для подключения OTLP, Jaeger и других бекендов

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger.info("Starting OpenTelemetry tracing example")

    with start_training_span("example_training"):
        logger.info("Simulating training step")
        add_training_step(10)

