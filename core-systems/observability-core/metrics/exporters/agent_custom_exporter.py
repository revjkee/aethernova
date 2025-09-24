import time
import json
import socket
import psutil
import threading
import logging
from prometheus_client import Gauge, Counter, start_http_server
from uuid import uuid4

# -------- CONFIG -------- #
EXPORT_PORT = 8004
SCRAPE_INTERVAL = 10
AGENT_ID = str(uuid4())
INSTANCE = socket.gethostname()
NAMESPACE = "genesis_agent"

# -------- LOGGER -------- #
logger = logging.getLogger("AgentCustomExporter")
logger.setLevel(logging.INFO)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
logger.addHandler(stream_handler)

# -------- METRICS -------- #
agent_cpu_usage = Gauge(f"{NAMESPACE}_cpu_usage_percent", "Agent CPU usage", ["agent_id", "instance"])
agent_memory_usage = Gauge(f"{NAMESPACE}_memory_usage_bytes", "Agent memory usage in bytes", ["agent_id", "instance"])
agent_active_tasks = Gauge(f"{NAMESPACE}_active_tasks", "Current number of active tasks", ["agent_id", "instance"])
agent_errors_total = Counter(f"{NAMESPACE}_errors_total", "Total runtime errors", ["agent_id", "instance", "error_type"])
agent_telemetry_events = Counter(f"{NAMESPACE}_telemetry_events_total", "Number of telemetry events", ["agent_id", "instance", "event_type"])
agent_latency = Gauge(f"{NAMESPACE}_latency_ms", "Average latency per task", ["agent_id", "instance"])
agent_health_score = Gauge(f"{NAMESPACE}_health_score", "Composite agent health (0–100)", ["agent_id", "instance"])

# -------- MOCK DATA FUNCTION (for extension via socket/agent hooks) -------- #
def simulate_agent_runtime():
    return {
        "active_tasks": psutil.cpu_count(logical=False),
        "latency": round(5 + 5 * psutil.cpu_percent() / 100, 2),
        "telemetry": [
            {"type": "action_exec", "count": 4},
            {"type": "sensor_event", "count": 3},
            {"type": "error_detected", "count": 1}
        ],
        "errors": [{"type": "timeout", "count": 1}],
        "health_score": 95
    }

# -------- EXPORTER LOOP -------- #
class AgentExporter:
    def __init__(self):
        self.running = True

    def collect_metrics(self):
        while self.running:
            try:
                cpu = psutil.cpu_percent()
                mem = psutil.virtual_memory().used

                agent_cpu_usage.labels(agent_id=AGENT_ID, instance=INSTANCE).set(cpu)
                agent_memory_usage.labels(agent_id=AGENT_ID, instance=INSTANCE).set(mem)

                runtime = simulate_agent_runtime()

                agent_active_tasks.labels(agent_id=AGENT_ID, instance=INSTANCE).set(runtime["active_tasks"])
                agent_latency.labels(agent_id=AGENT_ID, instance=INSTANCE).set(runtime["latency"])
                agent_health_score.labels(agent_id=AGENT_ID, instance=INSTANCE).set(runtime["health_score"])

                for event in runtime["telemetry"]:
                    agent_telemetry_events.labels(
                        agent_id=AGENT_ID,
                        instance=INSTANCE,
                        event_type=event["type"]
                    ).inc(event["count"])

                for error in runtime["errors"]:
                    agent_errors_total.labels(
                        agent_id=AGENT_ID,
                        instance=INSTANCE,
                        error_type=error["type"]
                    ).inc(error["count"])

                logger.info("Agent metrics exported: CPU %.2f%%, Latency %.2f ms", cpu, runtime["latency"])
            except Exception as e:
                logger.exception("Exporter failed during collection")
            time.sleep(SCRAPE_INTERVAL)

    def run(self):
        threading.Thread(target=self.collect_metrics, daemon=True).start()

# -------- MAIN -------- #
if __name__ == "__main__":
    logger.info("Starting Agent Custom Exporter on port %d", EXPORT_PORT)
    start_http_server(EXPORT_PORT)
    exporter = AgentExporter()
    exporter.run()
    while True:
        time.sleep(3600)
