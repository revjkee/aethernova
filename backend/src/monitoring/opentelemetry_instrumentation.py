from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter, OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter as OTLPHTTPSpanExporter
import logging

logger = logging.getLogger(__name__)

def setup_tracer(service_name: str = "TeslaAI-Service"):
    """
    Настройка OpenTelemetry Tracer с экспортом в OTLP и консоль.
    """
    resource = Resource(attributes={"service.name": service_name})

    provider = TracerProvider(resource=resource)
    trace.set_tracer_provider(provider)

    # Экспортеры для отладки и для отправки в коллектор
    console_exporter = ConsoleSpanExporter()
    otlp_exporter = OTLPHTTPSpanExporter(endpoint="http://localhost:4318/v1/traces")

    # Обработчики спанов
    provider.add_span_processor(BatchSpanProcessor(console_exporter))
    provider.add_span_processor(BatchSpanProcessor(otlp_exporter))

    logger.info(f"Tracer initialized for service: {service_name}")

def instrument_app(app):
    """
    Инструментирование FastAPI приложения и HTTP-клиентов.
    """
    try:
        FastAPIInstrumentor.instrument_app(app)
        RequestsInstrumentor().instrument()
        logger.info("OpenTelemetry instrumentation enabled for FastAPI and Requests")
    except Exception as e:
        logger.error(f"Ошибка при инструментировании: {e}")
        raise
