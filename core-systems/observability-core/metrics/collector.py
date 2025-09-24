import time
import logging
import threading
import socket
from prometheus_client import start_http_server, CollectorRegistry, Gauge, Counter, push_to_gateway
from opentelemetry import metrics as otel_metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter

# -------- CONFIG -------- #
PROM_PUSHGATEWAY = "http://localhost:9091"
OTEL_ENDPOINT = "http://localhost:4318/v1/metrics"
EXPORT_INTERVAL_SEC = 15
COLLECTOR_PORT = 8010
HOSTNAME = socket.gethostname()
AGENT_NAMESPACE = "genesis_collector"

# -------- LOGGING -------- #
logger = logging.getLogger("MetricsCollector")
logger.setLevel(logging.INFO)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
logger.addHandler(stream_handler)

# -------- PROMETHEUS REGISTRY -------- #
registry = CollectorRegistry()

cpu_gauge = Gauge(f"{AGENT_NAMESPACE}_cpu_usage", "CPU usage", ["instance"], registry=registry)
mem_gauge = Gauge(f"{AGENT_NAMESPACE}_memory_usage", "Memory usage", ["instance"], registry=registry)
agents_count = Gauge(f"{AGENT_NAMESPACE}_connected_agents", "Number of active agents", ["instance"], registry=registry)
collector_uptime = Counter(f"{AGENT_NAMESPACE}_uptime_seconds_total", "Collector uptime counter", ["instance"], registry=registry)

# -------- OPENTELEMETRY SETUP -------- #
meter_provider = MeterProvider()
metric_exporter = OTLPMetricExporter(endpoint=OTEL_ENDPOINT, insecure=True)
reader = PeriodicExportingMetricReader(metric_exporter, export_interval_millis=EXPORT_INTERVAL_SEC * 1000)
meter_provider._sdk_config.metric_readers.append(reader)
otel_metrics.set_meter_provider(meter_provider)
meter = otel_metrics.get_meter("genesis.collector")

# -------- OTEL METRICS -------- #
otel_cpu = meter.create_observable_gauge(
    name=f"{AGENT_NAMESPACE}.cpu.load",
    description="System CPU load",
    callbacks=[lambda options: [otel_metrics.Observation(42.0)]],  # Replace with real callback
)

otel_mem = meter.create_observable_gauge(
    name=f"{AGENT_NAMESPACE}.mem.usage",
    description="System memory usage",
    callbacks=[lambda options: [otel_metrics.Observation(8192.0)]],  # Replace with real callback
)

# -------- RUNTIME COLLECTOR -------- #
class MetricsCollector:
    def __init__(self):
        self.running = True
        self.start_time = time.time()

    def collect(self):
        while self.running:
            try:
                import psutil
                cpu = psutil.cpu_percent()
                mem = psutil.virtual_memory().used / 1024**2

                # Update Prometheus metrics
                cpu_gauge.labels(instance=HOSTNAME).set(cpu)
                mem_gauge.labels(instance=HOSTNAME).set(mem)
                agents_count.labels(instance=HOSTNAME).set(self._detect_agents())
                collector_uptime.labels(instance=HOSTNAME).inc(EXPORT_INTERVAL_SEC)

                # Push to Prometheus Pushgateway
                push_to_gateway(PROM_PUSHGATEWAY, job="genesis_collector", registry=registry)
                logger.info("Pushed metrics: CPU=%.1f%%, MEM=%.1fMB", cpu, mem)
            except Exception as e:
                logger.exception("Collector error")
            time.sleep(EXPORT_INTERVAL_SEC)

    def _detect_agents(self):
        # Stub: replace with real detection (Redis, registry, service mesh etc.)
        return 7

    def run(self):
        threading.Thread(target=self.collect, daemon=True).start()

# -------- MAIN ENTRY -------- #
if __name__ == "__main__":
    logger.info("Starting metrics collector on port %d", COLLECTOR_PORT)
    start_http_server(COLLECTOR_PORT)
    collector = MetricsCollector()
    collector.run()
    while True:
        time.sleep(3600)
