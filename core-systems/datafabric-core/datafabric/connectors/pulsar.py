# datafabric-core/datafabric/connectors/pulsar.py
from __future__ import annotations

import json
import logging
import os
import signal
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Literal, Optional, Protocol, Sequence, Tuple, Union

try:
    import pulsar  # Apache Pulsar Python client
except Exception as e:  # pragma: no cover
    raise RuntimeError(
        "pulsar-client is required. Install: pip install pulsar-client"
    ) from e

# ======================================================================================
# Логи и типы
# ======================================================================================

logger = logging.getLogger("datafabric.pulsar")

CompressionType = Literal["none", "lz4", "zlib", "zstd", "snappy"]
SubscriptionType = Literal["exclusive", "shared", "failover", "key_shared"]
RoutingMode = Literal["round_robin", "single_partition", "custom"]
AckMode = Literal["auto", "manual"]

# ======================================================================================
# Метрики (минимальный интерфейс)
# ======================================================================================

class MetricsSink(Protocol):
    def incr(self, name: str, value: int = 1, tags: Optional[Dict[str, str]] = None) -> None: ...
    def observe(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None: ...

class NullMetrics:
    def incr(self, name: str, value: int = 1, tags: Optional[Dict[str, str]] = None) -> None:
        return
    def observe(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        return

# ======================================================================================
# Сериализация/десериализация
# ======================================================================================

class Serializer(Protocol):
    def __call__(self, payload: Any) -> bytes: ...

class Deserializer(Protocol):
    def __call__(self, raw: bytes) -> Any: ...

def bytes_serializer(payload: Union[bytes, bytearray, memoryview, str]) -> bytes:
    if isinstance(payload, (bytes, bytearray, memoryview)):
        return bytes(payload)
    if isinstance(payload, str):
        return payload.encode("utf-8")
    raise TypeError("bytes_serializer accepts bytes or str")

def json_serializer(payload: Any) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def json_deserializer(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8"))

# Простейшая схема "passthrough" (bytes)
def bytes_deserializer(raw: bytes) -> bytes:
    return raw

# ======================================================================================
# Конфигурация клиента/продюсера/консюмера
# ======================================================================================

@dataclass(frozen=True)
class PulsarAuth:
    mode: Literal["none", "token"] = "none"
    token: Optional[str] = None  # для mode=token поддерживается "token:xxx" или просто токен

@dataclass(frozen=True)
class PulsarTLS:
    enable: bool = False
    validate_hostname: bool = True
    trust_certs_file_path: Optional[str] = None

@dataclass(frozen=True)
class ClientConfig:
    service_url: str = "pulsar://localhost:6650"
    io_threads: int = 1
    message_listener_threads: int = 1
    operation_timeout_seconds: int = 30
    connection_timeout_ms: int = 10000
    auth: PulsarAuth = PulsarAuth()
    tls: PulsarTLS = PulsarTLS()

@dataclass(frozen=True)
class ProducerConfig:
    topic: str = "persistent://public/default/data"
    producer_name: Optional[str] = None  # стабильное имя включает атрибуты для дедупликации
    batching_enabled: bool = True
    batching_max_messages: int = 1000
    batching_max_publish_delay_ms: int = 5
    send_timeout_ms: int = 30000
    block_if_queue_full: bool = True
    max_pending_messages: int = 5000
    compression: CompressionType = "zstd"
    routing_mode: RoutingMode = "round_robin"
    message_router: Optional[Callable[[pulsar.Message, int], int]] = None  # при routing_mode="custom"
    # Ключевые опции
    deliver_after_ms: Optional[int] = None  # отложенная доставка
    encryption_key_reader: Optional[Any] = None  # при необходимости KMS

@dataclass(frozen=True)
class DeadLetterPolicy:
    max_redeliver_count: int = 5
    dead_letter_topic: Optional[str] = None
    retry_letter_topic: Optional[str] = None

@dataclass(frozen=True)
class ConsumerConfig:
    topics: Union[str, Sequence[str]] = "persistent://public/default/data"
    subscription_name: str = "datafabric-sub"
    subscription_type: SubscriptionType = "key_shared"
    ack_timeout_ms: int = 30000
    negative_ack_redelivery_delay_ms: int = 10000
    receiver_queue_size: int = 1000
    dead_letter: Optional[DeadLetterPolicy] = DeadLetterPolicy()
    regex_subscription_mode: Optional[int] = None  # pulsar.RegexSubscriptionMode.PersistentOnly и т.д.
    initial_position: Literal["latest", "earliest"] = "latest"
    read_compacted: bool = False
    ack_mode: AckMode = "manual"  # manual — контроль в приложении
    # Десериализация
    deserializer: Deserializer = json_deserializer

# ======================================================================================
# Вспомогательные функции
# ======================================================================================

def _compression(ct: CompressionType) -> int:
    mapping = {
        "none": pulsar.CompressionType.NONE,
        "lz4": pulsar.CompressionType.LZ4,
        "zlib": pulsar.CompressionType.ZLIB,
        "zstd": pulsar.CompressionType.ZSTD,
        "snappy": pulsar.CompressionType.SNAPPY,
    }
    return mapping[ct]

def _subscription(st: SubscriptionType) -> pulsar._pulsar.SubscriptionType:
    mapping = {
        "exclusive": pulsar.SubscriptionType.Exclusive,
        "shared": pulsar.SubscriptionType.Shared,
        "failover": pulsar.SubscriptionType.Failover,
        "key_shared": pulsar.SubscriptionType.KeyShared,
    }
    return mapping[st]

def _initial_position(pos: Literal["latest", "earliest"]) -> int:
    return pulsar.InitialPosition.Latest if pos == "latest" else pulsar.InitialPosition.Earliest

def _build_auth(auth: PulsarAuth) -> Optional[Any]:
    if auth.mode == "none":
        return None
    if auth.mode == "token":
        token = auth.token or os.getenv("PULSAR_TOKEN") or ""
        if token.startswith("token:"):
            token = token
        else:
            token = f"token:{token}"
        return pulsar.AuthenticationToken(token)
    return None

# ======================================================================================
# Коннектор
# ======================================================================================

class PulsarConnector:
    """
    Высокоуровневый коннектор: управляет Client/Producer/Consumer, потокобезопасен,
    совместим с asyncio (операции не блокируют event loop), обеспечивает graceful shutdown.
    """

    def __init__(
        self,
        client_cfg: ClientConfig,
        metrics: Optional[MetricsSink] = None,
    ) -> None:
        self.client_cfg = client_cfg
        self.metrics = metrics or NullMetrics()
        self._client: Optional[pulsar.Client] = None
        self._lock = threading.RLock()
        self._closed = False
        self._signal_installed = False

    # ------------------------ lifecycle ------------------------

    def _ensure_client(self) -> pulsar.Client:
        with self._lock:
            if self._client is not None:
                return self._client

            auth = _build_auth(self.client_cfg.auth)

            kwargs: Dict[str, Any] = dict(
                service_url=self.client_cfg.service_url,
                io_threads=self.client_cfg.io_threads,
                message_listener_threads=self.client_cfg.message_listener_threads,
                operation_timeout_seconds=self.client_cfg.operation_timeout_seconds,
                connection_timeout_ms=self.client_cfg.connection_timeout_ms,
                authentication=auth,
            )

            if self.client_cfg.tls.enable:
                kwargs.update(
                    {
                        "tls_validate_hostname": self.client_cfg.tls.validate_hostname,
                        "tls_trust_certs_file_path": self.client_cfg.tls.trust_certs_file_path or "",
                        "use_tls": True,
                    }
                )

            self._client = pulsar.Client(**kwargs)
            logger.info("pulsar.client.created", extra={"service_url": self.client_cfg.service_url})
            self._install_sig_handlers_once()
            return self._client

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                if self._client is not None:
                    self._client.close()
            finally:
                self._client = None
                logger.info("pulsar.client.closed")

    def _install_sig_handlers_once(self) -> None:
        if self._signal_installed:
            return
        self._signal_installed = True

        def _handler(signum, frame):
            logger.warning("pulsar.connector.signal", extra={"signum": signum})
            self.close()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, _handler)
            except Exception:
                # внутри некоторых рантаймов (gunicorn workers) нельзя переопределить
                pass

    # ------------------------ producer ------------------------

    def create_producer(
        self,
        cfg: ProducerConfig,
        serializer: Serializer = json_serializer,
    ) -> "PulsarProducer":
        client = self._ensure_client()
        return PulsarProducer(client, cfg, serializer, self.metrics)

    # ------------------------ consumer ------------------------

    def create_consumer(
        self,
        cfg: ConsumerConfig,
    ) -> "PulsarConsumer":
        client = self._ensure_client()
        return PulsarConsumer(client, cfg, self.metrics)

# ======================================================================================
# Продюсер
# ======================================================================================

class PulsarProducer:
    def __init__(
        self,
        client: pulsar.Client,
        cfg: ProducerConfig,
        serializer: Serializer,
        metrics: MetricsSink,
    ) -> None:
        self.cfg = cfg
        self.serializer = serializer
        self.metrics = metrics
        self._producer = self._build(client)
        self._closed = False

    def _build(self, client: pulsar.Client) -> pulsar.Producer:
        kwargs: Dict[str, Any] = dict(
            topic=self.cfg.topic,
            producer_name=self.cfg.producer_name,
            send_timeout_millis=self.cfg.send_timeout_ms,
            block_if_queue_full=self.cfg.block_if_queue_full,
            max_pending_messages=self.cfg.max_pending_messages,
            batching_enabled=self.cfg.batching_enabled,
            batching_max_messages=self.cfg.batching_max_messages,
            batching_max_publish_delay_ms=self.cfg.batching_max_publish_delay_ms,
            compression_type=_compression(self.cfg.compression),
        )

        # Маршрутизация (для partitioned topic)
        if self.cfg.routing_mode == "round_robin":
            kwargs["hashing_scheme"] = pulsar.HashingScheme.JavaStringHash
            kwargs["message_routing_mode"] = pulsar.MessageRoutingMode.RoundRobinPartition
        elif self.cfg.routing_mode == "single_partition":
            kwargs["message_routing_mode"] = pulsar.MessageRoutingMode.SinglePartition
        elif self.cfg.routing_mode == "custom" and self.cfg.message_router:
            kwargs["message_router"] = self.cfg.message_router
            kwargs["message_routing_mode"] = pulsar.MessageRoutingMode.CustomPartition

        # Шифрование/отложенная доставка
        if self.cfg.encryption_key_reader is not None:
            kwargs["crypto_key_reader"] = self.cfg.encryption_key_reader

        producer = client.create_producer(**kwargs)
        logger.info("pulsar.producer.created", extra={"topic": self.cfg.topic, "producer_name": self.cfg.producer_name})
        return producer

    def close(self) -> None:
        if self._closed:
            return
        self._producer.close()
        self._closed = True
        logger.info("pulsar.producer.closed", extra={"topic": self.cfg.topic})

    # Надёжная отправка с ретраями и джиттер‑бэкоффом.
    def send(
        self,
        payload: Any,
        *,
        key: Optional[str] = None,
        properties: Optional[Dict[str, str]] = None,
        event_time_ms: Optional[int] = None,
        deliver_after_ms: Optional[int] = None,
        max_retries: int = 5,
        base_delay_ms: int = 50,
        max_delay_ms: int = 5000,
    ) -> pulsar.MessageId:
        body = self.serializer(payload)

        attempt = 0
        while True:
            try:
                msg_id = self._producer.send(
                    body,
                    partition_key=key,
                    properties=properties or {},
                    event_timestamp=event_time_ms or 0,
                    deliver_after_ms=deliver_after_ms or self.cfg.deliver_after_ms or 0,
                )
                self.metrics.incr("pulsar.producer.sent", tags={"topic": self.cfg.topic})
                return msg_id
            except Exception as e:
                if attempt >= max_retries:
                    self.metrics.incr("pulsar.producer.error", tags={"topic": self.cfg.topic})
                    logger.exception("pulsar.producer.send.failed", extra={"topic": self.cfg.topic})
                    raise
                delay = _jitter_backoff(attempt, base_delay_ms, max_delay_ms)
                time.sleep(delay)
                attempt += 1

def _jitter_backoff(attempt: int, base_ms: int, max_ms: int) -> float:
    # экспоненциальный рост с полным джиттером
    import random
    exp = min(max_ms, base_ms * (2 ** attempt))
    return random.uniform(base_ms, exp) / 1000.0

# ======================================================================================
# Консюмер
# ======================================================================================

class PulsarConsumer:
    def __init__(
        self,
        client: pulsar.Client,
        cfg: ConsumerConfig,
        metrics: MetricsSink,
    ) -> None:
        self.cfg = cfg
        self.metrics = metrics
        self._consumer = self._build(client)
        self._closed = False

    def _build(self, client: pulsar.Client) -> pulsar.Consumer:
        subscription_type = _subscription(self.cfg.subscription_type)

        # Dead Letter Policy
        dlp = None
        if self.cfg.dead_letter:
            kwargs_dlp: Dict[str, Any] = dict(
                max_redeliver_count=self.cfg.dead_letter.max_redeliver_count,
            )
            if self.cfg.dead_letter.dead_letter_topic:
                kwargs_dlp["dead_letter_topic"] = self.cfg.dead_letter.dead_letter_topic
            if self.cfg.dead_letter.retry_letter_topic:
                kwargs_dlp["retry_letter_topic"] = self.cfg.dead_letter.retry_letter_topic
            dlp = pulsar.DeadLetterPolicy(**kwargs_dlp)

        topics = self.cfg.topics
        if isinstance(topics, (list, tuple)):
            topic_spec = topics
        else:
            topic_spec = topics

        kwargs: Dict[str, Any] = dict(
            topic=topic_spec,
            subscription_name=self.cfg.subscription_name,
            subscription_type=subscription_type,
            receiver_queue_size=self.cfg.receiver_queue_size,
            negative_ack_redelivery_delay_ms=self.cfg.negative_ack_redelivery_delay_ms,
            ack_timeout_millis=self.cfg.ack_timeout_ms,
            dead_letter_policy=dlp,
            read_compacted=self.cfg.read_compacted,
            initial_position=_initial_position(self.cfg.initial_position),
        )

        consumer = client.subscribe(**kwargs)
        logger.info(
            "pulsar.consumer.created",
            extra={
                "topics": topic_spec,
                "subscription_name": self.cfg.subscription_name,
                "subscription_type": self.cfg.subscription_type,
            },
        )
        return consumer

    def close(self) -> None:
        if self._closed:
            return
        self._consumer.close()
        self._closed = True
        logger.info("pulsar.consumer.closed", extra={"subscription": self.cfg.subscription_name})

    # Блокирующая итерация. Совместимость с asyncio: вызывать через run_in_executor.
    def poll(
        self,
        timeout_ms: Optional[int] = None,
    ) -> Optional[Tuple[Any, pulsar.Message]]:
        """
        Получает одно сообщение. Возвращает (deserialized_payload, raw_message) или None при timeout.
        """
        try:
            msg: pulsar.Message = self._consumer.receive(timeout_millis=timeout_ms or 1000)
        except pulsar.Timeout:
            return None

        self.metrics.incr("pulsar.consumer.received", tags={"subscription": self.cfg.subscription_name})
        try:
            payload = self.cfg.deserializer(msg.data())
        except Exception:
            # нередкий случай "грязных" данных — NACK, чтобы ушло в ретрай/ДЛК
            self._consumer.negative_acknowledge(msg)
            self.metrics.incr("pulsar.consumer.deserialize_error", tags={"subscription": self.cfg.subscription_name})
            return None

        if self.cfg.ack_mode == "auto":
            self._consumer.acknowledge(msg)
        return (payload, msg)

    def ack(self, msg: pulsar.Message) -> None:
        self._consumer.acknowledge(msg)

    def nack(self, msg: pulsar.Message) -> None:
        self._consumer.negative_acknowledge(msg)

# ======================================================================================
# Упрощённые фабрики
# ======================================================================================

def build_connector(
    client_cfg: ClientConfig,
    metrics: Optional[MetricsSink] = None,
) -> PulsarConnector:
    return PulsarConnector(client_cfg, metrics=metrics)

def build_json_producer(
    connector: PulsarConnector,
    topic: str,
    producer_name: Optional[str] = None,
    compression: CompressionType = "zstd",
) -> PulsarProducer:
    pcfg = ProducerConfig(
        topic=topic,
        producer_name=producer_name,
        compression=compression,
        batching_enabled=True,
        batching_max_messages=1000,
        batching_max_publish_delay_ms=5,
        block_if_queue_full=True,
        max_pending_messages=5000,
    )
    return connector.create_producer(pcfg, serializer=json_serializer)

def build_json_consumer(
    connector: PulsarConnector,
    topics: Union[str, Sequence[str]],
    subscription_name: str,
    subscription_type: SubscriptionType = "key_shared",
    dead_letter_topic: Optional[str] = None,
) -> PulsarConsumer:
    ccfg = ConsumerConfig(
        topics=topics,
        subscription_name=subscription_name,
        subscription_type=subscription_type,
        dead_letter=DeadLetterPolicy(
            max_redeliver_count=5,
            dead_letter_topic=dead_letter_topic,
        ),
        deserializer=json_deserializer,
        ack_mode="manual",
    )
    return connector.create_consumer(ccfg)

# ======================================================================================
# Пример использования (локальный тест): python -m datafabric.connectors.pulsar
# ======================================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    client_cfg = ClientConfig(
        service_url=os.getenv("PULSAR_URL", "pulsar://localhost:6650"),
        auth=PulsarAuth(mode="token" if os.getenv("PULSAR_TOKEN") else "none", token=os.getenv("PULSAR_TOKEN")),
        tls=PulsarTLS(
            enable=os.getenv("PULSAR_TLS", "false").lower() in ("1", "true", "yes"),
            validate_hostname=True,
            trust_certs_file_path=os.getenv("PULSAR_TRUST_CERTS"),
        ),
    )
    connector = build_connector(client_cfg)

    # Producer
    producer = build_json_producer(connector, topic=os.getenv("PULSAR_TOPIC", "persistent://public/default/data"),
                                   producer_name="datafabric-core")

    # Consumer
    consumer = build_json_consumer(
        connector,
        topics=os.getenv("PULSAR_TOPIC", "persistent://public/default/data"),
        subscription_name="datafabric-sub",
        subscription_type="key_shared",
        dead_letter_topic=os.getenv("PULSAR_DLT", "persistent://public/default/data-DLT"),
    )

    try:
        # Отправка тестового сообщения
        mid = producer.send({"hello": "world"}, key="k1", properties={"source": "demo"})
        logger.info("sent", extra={"msg_id": str(mid)})

        # Приём одного сообщения (блокирующе)
        data_msg = consumer.poll(timeout_ms=2000)
        if data_msg:
            payload, msg = data_msg
            logger.info("received", extra={"payload": payload, "key": msg.partition_key()})
            consumer.ack(msg)
        else:
            logger.info("no_message")
    finally:
        producer.close()
        consumer.close()
        connector.close()
