import time
import logging
import socket
import psycopg2
from prometheus_client import Gauge, Counter, start_http_server
from threading import Thread

# -------- CONFIG -------- #
DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "postgres",
    "user": "postgres",
    "password": "securepassword"
}
EXPORTER_PORT = 8003
SCRAPE_INTERVAL_SEC = 15
NAMESPACE = "genesis_postgres"
INSTANCE = socket.gethostname()

# -------- LOGGER -------- #
logger = logging.getLogger("PostgresExporter")
logger.setLevel(logging.INFO)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
logger.addHandler(stream_handler)

# -------- METRICS -------- #
pg_up = Gauge(f"{NAMESPACE}_up", "PostgreSQL availability", ["instance"])
pg_connections = Gauge(f"{NAMESPACE}_active_connections", "Current active connections", ["instance"])
pg_cache_hit_ratio = Gauge(f"{NAMESPACE}_cache_hit_ratio", "Cache hit ratio", ["instance"])
pg_deadlocks = Counter(f"{NAMESPACE}_deadlocks_total", "Total deadlocks detected", ["instance"])
pg_xact_commit = Counter(f"{NAMESPACE}_xact_commit_total", "Number of transactions committed", ["instance"])
pg_xact_rollback = Counter(f"{NAMESPACE}_xact_rollback_total", "Number of transactions rolled back", ["instance"])
pg_db_size = Gauge(f"{NAMESPACE}_database_size_bytes", "Database size", ["instance"])
pg_replication_lag = Gauge(f"{NAMESPACE}_replication_lag_bytes", "Replication lag in bytes", ["instance"])
pg_query_latency = Gauge(f"{NAMESPACE}_query_latency_ms", "Simple SELECT latency", ["instance"])
pg_error_count = Counter(f"{NAMESPACE}_errors_total", "Total exporter errors", ["type", "instance"])

# -------- EXPORTER -------- #
class PostgresExporter:
    def __init__(self, config):
        self.config = config
        self.running = True

    def connect(self):
        return psycopg2.connect(**self.config)

    def measure_latency(self, cursor):
        start = time.time()
        cursor.execute("SELECT 1;")
        _ = cursor.fetchone()
        return (time.time() - start) * 1000

    def collect_metrics(self):
        while self.running:
            try:
                conn = self.connect()
                cursor = conn.cursor()

                # Latency
                latency = self.measure_latency(cursor)
                pg_query_latency.labels(instance=INSTANCE).set(latency)

                # General info
                cursor.execute("SELECT count(*) FROM pg_stat_activity;")
                pg_connections.labels(instance=INSTANCE).set(cursor.fetchone()[0])

                cursor.execute("""
                    SELECT sum(blks_hit) / nullif(sum(blks_hit) + sum(blks_read), 0)
                    FROM pg_stat_database;
                """)
                ratio = cursor.fetchone()[0] or 0
                pg_cache_hit_ratio.labels(instance=INSTANCE).set(ratio)

                cursor.execute("SELECT sum(deadlocks) FROM pg_stat_database;")
                pg_deadlocks.labels(instance=INSTANCE).inc(cursor.fetchone()[0] or 0)

                cursor.execute("SELECT sum(xact_commit), sum(xact_rollback) FROM pg_stat_database;")
                commits, rollbacks = cursor.fetchone()
                pg_xact_commit.labels(instance=INSTANCE).inc(commits or 0)
                pg_xact_rollback.labels(instance=INSTANCE).inc(rollbacks or 0)

                cursor.execute("SELECT pg_database_size(current_database());")
                pg_db_size.labels(instance=INSTANCE).set(cursor.fetchone()[0])

                cursor.execute("""
                    SELECT CASE WHEN pg_is_in_recovery()
                    THEN pg_last_xlog_receive_location() - pg_last_xlog_replay_location()
                    ELSE 0 END;
                """)
                lag = cursor.fetchone()[0] or 0
                pg_replication_lag.labels(instance=INSTANCE).set(lag)

                pg_up.labels(instance=INSTANCE).set(1)
                conn.close()

                logger.debug("Metrics collected. Latency: %.2f ms, Connections: %d", latency, pg_connections)

            except psycopg2.Error as e:
                pg_up.labels(instance=INSTANCE).set(0)
                pg_error_count.labels(type="db", instance=INSTANCE).inc()
                logger.error("PostgreSQL error: %s", e)
            except Exception as e:
                pg_error_count.labels(type="internal", instance=INSTANCE).inc()
                logger.exception("Exporter error")
            time.sleep(SCRAPE_INTERVAL_SEC)

    def run(self):
        Thread(target=self.collect_metrics, daemon=True).start()

# -------- MAIN -------- #
if __name__ == "__main__":
    logger.info("Starting Postgres Exporter on port %s", EXPORTER_PORT)
    start_http_server(EXPORTER_PORT)
    exporter = PostgresExporter(DB_CONFIG)
    exporter.run()
    while True:
        time.sleep(3600)
