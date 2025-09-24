# observability/dashboards/otel/opentelemetry_instrumentation.py

from opentelemetry.instrumentation.asyncpg import AsyncPGInstrumentor
from opentelemetry.instrumentation.celery import CeleryInstrumentor
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.instrumentation.logging import LoggingInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor
from opentelemetry.instrumentation.grpc import GrpcInstrumentorClient, GrpcInstrumentorServer


def init_all_instrumentations(app=None, sqlalchemy_engine=None, enable_grpc=True):
    """
    Инициализация всех поддерживаемых OpenTelemetry инструментаторов.
    """
    # FastAPI routes
    if app is not None:
        FastAPIInstrumentor.instrument_app(app)

    # Redis
    RedisInstrumentor().instrument()

    # HTTP клиенты
    RequestsInstrumentor().instrument()
    HTTPXClientInstrumentor().instrument()

    # Celery (если используется)
    CeleryInstrumentor().instrument()

    # SQLAlchemy
    if sqlalchemy_engine:
        SQLAlchemyInstrumentor().instrument(engine=sqlalchemy_engine)

    # PostgreSQL async (если используется)
    AsyncPGInstrumentor().instrument()

    # GRPC (опционально)
    if enable_grpc:
        GrpcInstrumentorClient().instrument()
        GrpcInstrumentorServer().instrument()

    # Логгирование (добавляет trace_id и span_id в логи)
    LoggingInstrumentor().instrument(set_logging_format=True)
