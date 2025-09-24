# message-brokers/queue/kafka_queue.py

import asyncio
import logging
import json
from typing import Callable, Optional, Any

from aiokafka import AIOKafkaProducer, AIOKafkaConsumer, ConsumerRecord
from aiokafka.helpers import create_ssl_context

from .base_queue import BaseQueue, MessageMetadata


class KafkaQueue(BaseQueue):
    """
    Kafka очередь с поддержкой consumer group, безопасной сериализации,
    Zero-Trust обработкой акторов, и наблюдением за latency.
    """

    def __init__(
        self,
        bootstrap_servers: str,
        topic: str,
        group_id: str,
        security_protocol: str = "PLAINTEXT",
        ssl_cafile: Optional[str] = None,
        ssl_certfile: Optional[str] = None,
        ssl_keyfile: Optional[str] = None,
        tracer: Optional[Callable] = None,
    ):
        super().__init__(topic, tracer)
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.group_id = group_id
        self.producer: Optional[AIOKafkaProducer] = None
        self.consumer: Optional[AIOKafkaConsumer] = None

        self.ssl_context = None
        if security_protocol == "SSL":
            self.ssl_context = create_ssl_context(
                cafile=ssl_cafile,
                certfile=ssl_certfile,
                keyfile=ssl_keyfile,
            )

        self.security_protocol = security_protocol

    async def connect_producer(self):
        if self.producer:
            return
        self.producer = AIOKafkaProducer(
            bootstrap_servers=self.bootstrap_servers,
            security_protocol=self.security_protocol,
            ssl_context=self.ssl_context,
            acks="all",  # гарантия доставки
        )
        await self.producer.start()
        self.logger.info("[KafkaQueue] Producer connected")

    async def connect_consumer(self):
        if self.consumer:
            return
        self.consumer = AIOKafkaConsumer(
            self.topic,
            bootstrap_servers=self.bootstrap_servers,
            group_id=self.group_id,
            enable_auto_commit=False,
            security_protocol=self.security_protocol,
            ssl_context=self.ssl_context,
            auto_offset_reset="earliest",
            value_deserializer=lambda x: json.loads(x.decode("utf-8")),
        )
        await self.consumer.start()
        self.logger.info("[KafkaQueue] Consumer connected")

    async def enqueue(self, data: Any, metadata: Optional[MessageMetadata] = None) -> None:
        await self.connect_producer()
        metadata = metadata or MessageMetadata(actor="unknown")

        if not self.validate_actor(metadata):
            return

        payload = {
            "metadata": metadata.to_dict(),
            "data": data
        }

        try:
            await self.producer.send_and_wait(
                topic=self.topic,
                value=json.dumps(payload).encode("utf-8"),
            )
            await self.trace_event("enqueue", payload)
        except Exception as e:
            self.logger.error(f"[KafkaQueue] Enqueue error: {e}")
            await self.trace_event("error", {"error": str(e)})

    async def consume(self, callback: Callable[[dict, ConsumerRecord], Any]) -> None:
        await self.connect_consumer()
        try:
            async for msg in self.consumer:
                try:
                    await self.trace_event("dequeue", msg.value)
                    await callback(msg.value, msg)
                    await self.consumer.commit()
                except Exception as e:
                    self.logger.error(f"[KafkaQueue] Processing error: {e}")
                    await self.trace_event("error", {"error": str(e)})
        finally:
            await self.consumer.stop()

    async def ack(self, msg: ConsumerRecord) -> None:
        """Kafka автоматически коммитит offset, ack обрабатывается через commit()."""
        await self.consumer.commit()
        await self.trace_event("ack", {"offset": msg.offset})

    async def nack(self, msg: ConsumerRecord, requeue: bool = True) -> None:
        """Kafka не поддерживает nack напрямую, offset просто не коммитится."""
        await self.trace_event("nack", {"offset": msg.offset, "requeue": requeue})
