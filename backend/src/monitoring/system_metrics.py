# path: backend/src/monitoring/system_metrics.py

import os
import psutil
import socket
import logging
import time
from datetime import datetime
from prometheus_client import Gauge, start_http_server, CollectorRegistry, push_to_gateway
from utils.alerting import notify_guard

# === Конфигурация ===
LOG_FILE = "/var/log/teslaai/system_metrics.log"
PUSHGATEWAY_URL = os.getenv("PUSHGATEWAY_URL", "http://localhost:9091")
INSTANCE_LABEL = socket.gethostname()

# === Настройка логгера ===
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s'
)

# === Метрики Prometheus ===
registry = CollectorRegistry()

cpu_usage = Gauge('cpu_usage_percent', 'CPU usage percentage', ['instance'], registry=registry)
mem_usage = Gauge('memory_usage_percent', 'Memory usage percentage', ['instance'], registry=registry)
disk_usage = Gauge('disk_usage_percent', 'Disk usage percentage', ['instance'], registry=registry)
net_sent = Gauge('network_sent_bytes', 'Bytes sent over network', ['instance'], registry=registry)
net_recv = Gauge('network_recv_bytes', 'Bytes received over network', ['instance'], registry=registry)
io_read = Gauge('disk_read_bytes', 'Disk read bytes', ['instance'], registry=registry)
io_write = Gauge('disk_write_bytes', 'Disk write bytes', ['instance'], registry=registry)

# === Обработка ===
def collect_metrics():
    try:
        # CPU
        cpu = psutil.cpu_percent(interval=1)
        cpu_usage.labels(INSTANCE_LABEL).set(cpu)

        # Memory
        mem = psutil.virtual_memory().percent
        mem_usage.labels(INSTANCE_LABEL).set(mem)

        # Disk
        disk = psutil.disk_usage('/').percent
        disk_usage.labels(INSTANCE_LABEL).set(disk)

        # Network
        net = psutil.net_io_counters()
        net_sent.labels(INSTANCE_LABEL).set(net.bytes_sent)
        net_recv.labels(INSTANCE_LABEL).set(net.bytes_recv)

        # IO
        io = psutil.disk_io_counters()
        io_read.labels(INSTANCE_LABEL).set(io.read_bytes)
        io_write.labels(INSTANCE_LABEL).set(io.write_bytes)

        # Push
        push_to_gateway(PUSHGATEWAY_URL, job="system_metrics", registry=registry)
        logging.info(f"[METRICS] OK | cpu={cpu}%, mem={mem}%, disk={disk}%")

        # Аномалии
        if cpu > 90 or mem > 90 or disk > 95:
            notify_guard(event_type="resource_anomaly", message=f"High usage: CPU={cpu} MEM={mem} DISK={disk}")

    except Exception as e:
        logging.error(f"[METRICS] ERROR: {e}")
        notify_guard(event_type="monitoring_error", message=str(e), critical=True)

# === Основной цикл ===
def main():
    start_http_server(8001)  # локальный endpoint для /metrics
    logging.info("System metrics monitor started")
    while True:
        collect_metrics()
        time.sleep(15)

if __name__ == "__main__":
    main()
