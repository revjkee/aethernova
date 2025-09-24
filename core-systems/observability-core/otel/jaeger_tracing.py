# observability/dashboards/otel/jaeger_tracing.py

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.logging import LoggingInstrumentor
from opentelemetry.sdk.trace.sampling import ALWAYS_ON
import logging


def init_jaeger_tracing(service_name: str = "teslaai-core", endpoint: str = "http://localhost:4318/v1/traces"):
    """
    Инициализирует OpenTelemetry tracing и экспортирует в Jaeger через OTLP HTTP.
    """
    # Ресурсы, идентифицирующие сервис
    resource = Resource(attributes={
        "service.name": service_name
    })

    # Трейсер провайдер
    tracer_provider = TracerProvider(resource=resource, sampler=ALWAYS_ON)
    trace.set_tracer_provider(tracer_provider)

    # Экспортер OTLP -> Jaeger
    otlp_exporter = OTLPSpanExporter(endpoint=endpoint)
    span_processor = BatchSpanProcessor(otlp_exporter)
    tracer_provider.add_span_processor(span_processor)

    # Инструментируем стандартные библиотеки логирования
    LoggingInstrumentor().instrument(set_logging_format=True)

    # Логирование успешной инициализации
    logging.getLogger("otel").info(f"OpenTelemetry Jaeger initialized at {endpoint}")


def instrument_fastapi(app):
    """
    Инструментирует FastAPI-приложение для автоматического трейсинга всех роутов.
    """
    FastAPIInstrumentor.instrument_app(app, tracer_provider=trace.get_tracer_provider())
