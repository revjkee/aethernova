import time
import logging
import prometheus_client
from prometheus_client import Gauge, Counter, start_http_server
from kafka import KafkaConsumer, TopicPartition, errors as kafka_errors
from threading import Thread
from typing import List, Dict
import socket

# -------- CONFIG -------- #
KAFKA_BROKERS = ["localhost:9092"]
EXPORTER_PORT = 8001
SCRAPE_INTERVAL_SEC = 15
CONSUMER_GROUP = "monitoring_exporter_group"
AI_TAG = "genesis_kafka_exporter_v1"

# -------- LOGGER -------- #
logger = logging.getLogger("KafkaExporter")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
logger.addHandler(ch)

# -------- METRICS -------- #
kafka_lag = Gauge(
    "genesis_kafka_lag",
    "Kafka consumer lag per partition",
    ["topic", "partition", "group", "instance"]
)
kafka_messages_total = Counter(
    "genesis_kafka_messages_total",
    "Total messages processed per topic",
    ["topic", "instance"]
)
kafka_error_count = Counter(
    "genesis_kafka_exporter_errors_total",
    "Total errors during Kafka metric export",
    ["type", "instance"]
)
kafka_health = Gauge(
    "genesis_kafka_exporter_health",
    "Health status of the Kafka exporter (1=healthy, 0=fail)",
    ["instance"]
)

# -------- EXPORTER -------- #
class KafkaMetricsExporter:
    def __init__(self, brokers: List[str]):
        self.brokers = brokers
        self.hostname = socket.gethostname()
        self.running = True
        self.consumer = None
        self.connect()

    def connect(self):
        try:
            self.consumer = KafkaConsumer(
                bootstrap_servers=self.brokers,
                group_id=CONSUMER_GROUP,
                client_id="genesis_exporter",
                request_timeout_ms=3000,
                session_timeout_ms=6000,
                api_version_auto_timeout_ms=2000
            )
            kafka_health.labels(instance=self.hostname).set(1)
            logger.info("Connected to Kafka brokers: %s", self.brokers)
        except kafka_errors.KafkaError as e:
            kafka_health.labels(instance=self.hostname).set(0)
            kafka_error_count.labels(type="connection", instance=self.hostname).inc()
            logger.error("Kafka connection failed: %s", e)

    def get_topics_partitions(self) -> Dict[str, List[int]]:
        try:
            topic_data = {}
            metadata = self.consumer.topics()
            for topic in metadata:
                partitions = self.consumer.partitions_for_topic(topic)
                if partitions:
                    topic_data[topic] = list(partitions)
            return topic_data
        except Exception as e:
            kafka_error_count.labels(type="metadata", instance=self.hostname).inc()
            logger.warning("Failed to fetch topic metadata: %s", e)
            return {}

    def collect_metrics(self):
        while self.running:
            try:
                topic_data = self.get_topics_partitions()
                for topic, partitions in topic_data.items():
                    for partition in partitions:
                        tp = TopicPartition(topic, partition)
                        self.consumer.assign([tp])
                        self.consumer.seek_to_end(tp)
                        end_offset = self.consumer.position(tp)
                        self.consumer.seek_to_beginning(tp)
                        start_offset = self.consumer.position(tp)
                        lag = end_offset - start_offset
                        kafka_lag.labels(topic=topic, partition=str(partition), group=CONSUMER_GROUP, instance=self.hostname).set(lag)
                        kafka_messages_total.labels(topic=topic, instance=self.hostname).inc(lag)
                        logger.debug(f"[{topic}-{partition}] Lag: {lag}")
                time.sleep(SCRAPE_INTERVAL_SEC)
            except Exception as e:
                kafka_error_count.labels(type="metrics", instance=self.hostname).inc()
                kafka_health.labels(instance=self.hostname).set(0)
                logger.exception("Failed during metrics collection")
                time.sleep(SCRAPE_INTERVAL_SEC * 2)

    def run(self):
        thread = Thread(target=self.collect_metrics)
        thread.start()

# -------- MAIN -------- #
if __name__ == "__main__":
    logger.info("Starting Genesis Kafka Exporter on port %s", EXPORTER_PORT)
    start_http_server(EXPORTER_PORT)
    exporter = KafkaMetricsExporter(KAFKA_BROKERS)
    exporter.run()
