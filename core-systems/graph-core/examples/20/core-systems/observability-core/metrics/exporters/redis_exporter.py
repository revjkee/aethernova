import time
import logging
import socket
import redis
import prometheus_client
from prometheus_client import Gauge, Counter, start_http_server
from threading import Thread

# -------- CONFIG -------- #
REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_DB = 0
EXPORTER_PORT = 8002
SCRAPE_INTERVAL_SEC = 10
NAMESPACE = "genesis_redis"
INSTANCE = socket.gethostname()

# -------- LOGGER -------- #
logger = logging.getLogger("RedisExporter")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
logger.addHandler(handler)

# -------- METRICS -------- #
redis_up = Gauge(f"{NAMESPACE}_up", "Redis availability", ["instance"])
redis_used_memory = Gauge(f"{NAMESPACE}_used_memory_bytes", "Memory used by Redis", ["instance"])
redis_connected_clients = Gauge(f"{NAMESPACE}_connected_clients", "Connected clients", ["instance"])
redis_total_commands_processed = Counter(f"{NAMESPACE}_total_commands", "Total Redis commands processed", ["instance"])
redis_latency = Gauge(f"{NAMESPACE}_latency_ms", "Ping latency to Redis", ["instance"])
redis_evicted_keys = Counter(f"{NAMESPACE}_evicted_keys_total", "Number of evicted keys", ["instance"])
redis_expired_keys = Counter(f"{NAMESPACE}_expired_keys_total", "Number of expired keys", ["instance"])
redis_keyspace_hits = Counter(f"{NAMESPACE}_keyspace_hits_total", "Cache hits", ["instance"])
redis_keyspace_misses = Counter(f"{NAMESPACE}_keyspace_misses_total", "Cache misses", ["instance"])
redis_error_count = Counter(f"{NAMESPACE}_errors_total", "Total exporter errors", ["type", "instance"])

# -------- EXPORTER -------- #
class RedisMetricsExporter:
    def __init__(self, host, port, db):
        self.redis_client = redis.Redis(host=host, port=port, db=db, socket_timeout=3)
        self.running = True

    def ping_latency(self) -> float:
        start = time.time()
        self.redis_client.ping()
        return (time.time() - start) * 1000

    def collect_metrics(self):
        while self.running:
            try:
                info = self.redis_client.info()
                latency = self.ping_latency()

                redis_up.labels(instance=INSTANCE).set(1)
                redis_latency.labels(instance=INSTANCE).set(latency)
                redis_used_memory.labels(instance=INSTANCE).set(info.get("used_memory", 0))
                redis_connected_clients.labels(instance=INSTANCE).set(info.get("connected_clients", 0))
                redis_total_commands_processed.labels(instance=INSTANCE).inc(info.get("total_commands_processed", 0))
                redis_evicted_keys.labels(instance=INSTANCE).inc(info.get("evicted_keys", 0))
                redis_expired_keys.labels(instance=INSTANCE).inc(info.get("expired_keys", 0))
                redis_keyspace_hits.labels(instance=INSTANCE).inc(info.get("keyspace_hits", 0))
                redis_keyspace_misses.labels(instance=INSTANCE).inc(info.get("keyspace_misses", 0))

                logger.debug("Metrics collected: latency %.2f ms, mem %d bytes", latency, info.get("used_memory", 0))
            except redis.RedisError as e:
                redis_up.labels(instance=INSTANCE).set(0)
                redis_error_count.labels(type="connection", instance=INSTANCE).inc()
                logger.error("Redis error: %s", e)
            except Exception as e:
                redis_error_count.labels(type="collector", instance=INSTANCE).inc()
                logger.exception("Unexpected error during metric collection")

            time.sleep(SCRAPE_INTERVAL_SEC)

    def run(self):
        thread = Thread(target=self.collect_metrics)
        thread.daemon = True
        thread.start()

# -------- MAIN -------- #
if __name__ == "__main__":
    logger.info("Starting Redis Exporter on port %s", EXPORTER_PORT)
    start_http_server(EXPORTER_PORT)
    exporter = RedisMetricsExporter(REDIS_HOST, REDIS_PORT, REDIS_DB)
    exporter.run()
    while True:
        time.sleep(3600)
