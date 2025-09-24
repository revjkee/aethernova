# observability/dashboards/exporters/prometheus_exporter.py

from prometheus_client import (
    start_http_server,
    Counter,
    Gauge,
    Histogram,
    Summary,
    CollectorRegistry,
    exposition,
)
from prometheus_client.core import REGISTRY
from threading import Thread
import time
import logging

logger = logging.getLogger("prometheus_exporter")

# Глобальный реестр, если нужно использовать кастомный
registry = CollectorRegistry()

# === Метрики: базовые и расширенные ===
LLM_REQUESTS_TOTAL = Counter(
    "llm_total_requests",
    "Total number of LLM requests processed",
    ["model", "endpoint", "status"],
    registry=registry,
)

LLM_RESPONSE_LATENCY = Histogram(
    "llm_response_latency_seconds",
    "Latency of responses in seconds",
    ["model", "endpoint"],
    buckets=(0.1, 0.3, 0.5, 1, 2, 5, 10),
    registry=registry,
)

LLM_INTERNAL_ERROR_TOTAL = Counter(
    "llm_internal_error_total",
    "Total internal server errors",
    ["model", "error_type"],
    registry=registry,
)

LLM_TOKEN_USAGE = Gauge(
    "llm_token_usage_total",
    "Tokens consumed per inference",
    ["model", "user_tier"],
    registry=registry,
)

LLM_MODEL_LOAD_LATENCY = Summary(
    "llm_model_load_latency_seconds",
    "Model load latency in seconds",
    ["model"],
    registry=registry,
)

RL_AGENT_REWARD = Gauge(
    "rl_agent_reward_total",
    "Reward metric for RL agents",
    ["agent_id", "phase"],
    registry=registry,
)

ZERO_TRUST_ACCESS_DENIED = Counter(
    "zero_trust_access_denied_total",
    "Number of access denials due to Zero Trust policy",
    ["user_id", "resource", "reason"],
    registry=registry,
)


# === Запуск сервера экспорта метрик ===
def start_prometheus_exporter(port: int = 8000):
    """
    Запускает Prometheus-совместимый HTTP endpoint для экспорта метрик.
    """
    def _run():
        try:
            logger.info(f"Starting Prometheus exporter on port {port}")
            start_http_server(port, registry=registry)
            while True:
                time.sleep(60)
        except Exception as e:
            logger.exception("Failed to start Prometheus exporter: %s", e)

    thread = Thread(target=_run, daemon=True)
    thread.start()
