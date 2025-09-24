from opentelemetry import trace
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
import logging

logger = logging.getLogger(__name__)

def setup_jaeger_tracer(
    service_name: str = "TeslaAI-Service",
    agent_host_name: str = "localhost",
    agent_port: int = 6831
):
    """
    Настройка OpenTelemetry Tracer с экспортом спанов в Jaeger.
    """

    resource = Resource(attributes={"service.name": service_name})

    tracer_provider = TracerProvider(resource=resource)
    trace.set_tracer_provider(tracer_provider)

    jaeger_exporter = JaegerExporter(
        agent_host_name=agent_host_name,
        agent_port=agent_port,
    )

    span_processor = BatchSpanProcessor(jaeger_exporter)
    tracer_provider.add_span_processor(span_processor)

    logger.info(f"Jaeger tracer initialized for service: {service_name} at {agent_host_name}:{agent_port}")

def get_tracer():
    """
    Получить экземпляр трассировщика.
    """
    return trace.get_tracer(__name__)
