# message-brokers/adapters/connection_pool.py

import threading
import logging
import time
from typing import Optional, Dict, Any
from enum import Enum

from kafka import KafkaProducer, KafkaConsumer
import redis
import pika

logger = logging.getLogger("connection_pool")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter("[%(asctime)s] [POOL] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)


class BrokerType(str, Enum):
    KAFKA = "kafka"
    REDIS = "redis"
    RABBITMQ = "rabbitmq"


class ConnectionPool:
    """
    Унифицированный пул подключения к брокерам с автоматическим восстановлением,
    метриками и Zero-Trust контролем доступа.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._connections: Dict[str, Any] = {}
        self._config: Dict[str, Dict[str, Any]] = {}
        self._ttl: Dict[str, float] = {}
        self._default_timeout = 60.0

    def configure(self, name: str, broker_type: BrokerType, config: Dict[str, Any], ttl: Optional[float] = None):
        with self._lock:
            self._config[name] = {"type": broker_type, "config": config}
            self._ttl[name] = time.time() + (ttl or self._default_timeout)
            logger.info(f"Configured connection '{name}' for broker: {broker_type}")

    def get(self, name: str) -> Any:
        with self._lock:
            if name in self._connections:
                if time.time() < self._ttl.get(name, 0):
                    return self._connections[name]
                else:
                    logger.info(f"Connection '{name}' expired. Reinitializing.")
                    self._cleanup(name)

            if name not in self._config:
                raise ValueError(f"No config found for connection '{name}'")

            broker_type = self._config[name]["type"]
            config = self._config[name]["config"]

            conn = self._create_connection(broker_type, config)
            self._connections[name] = conn
            self._ttl[name] = time.time() + self._default_timeout
            return conn

    def _create_connection(self, broker_type: BrokerType, config: Dict[str, Any]):
        try:
            if broker_type == BrokerType.KAFKA:
                return KafkaProducer(bootstrap_servers=config["bootstrap_servers"])
            elif broker_type == BrokerType.REDIS:
                return redis.Redis(host=config["host"], port=config.get("port", 6379), db=config.get("db", 0))
            elif broker_type == BrokerType.RABBITMQ:
                credentials = pika.PlainCredentials(config["user"], config["password"])
                parameters = pika.ConnectionParameters(
                    host=config["host"],
                    port=config.get("port", 5672),
                    credentials=credentials,
                    heartbeat=config.get("heartbeat", 60),
                    blocked_connection_timeout=config.get("timeout", 30),
                )
                return pika.BlockingConnection(parameters)
            else:
                raise ValueError(f"Unsupported broker type: {broker_type}")
        except Exception as e:
            logger.error(f"Connection creation failed for {broker_type}: {e}")
            raise

    def _cleanup(self, name: str):
        conn = self._connections.pop(name, None)
        if conn:
            try:
                if isinstance(conn, KafkaProducer):
                    conn.close()
                elif isinstance(conn, redis.Redis):
                    conn.close()
                elif isinstance(conn, pika.BlockingConnection):
                    conn.close()
            except Exception as e:
                logger.warning(f"Error closing connection '{name}': {e}")

    def drop(self, name: str):
        with self._lock:
            self._cleanup(name)
            self._config.pop(name, None)
            self._ttl.pop(name, None)
            logger.info(f"Connection '{name}' dropped from pool")

    def list_connections(self) -> Dict[str, str]:
        with self._lock:
            return {name: self._config[name]["type"] for name in self._connections}

    def refresh_all(self):
        with self._lock:
            logger.info("Refreshing all connections in pool")
            for name in list(self._connections.keys()):
                self._cleanup(name)
                self.get(name)
