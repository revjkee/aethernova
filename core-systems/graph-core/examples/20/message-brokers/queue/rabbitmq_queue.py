# message-brokers/queue/rabbitmq_queue.py

import asyncio
import json
import logging
from typing import Optional, Callable, Any

import aio_pika
from aio_pika import Message, ExchangeType, IncomingMessage

from .base_queue import BaseQueue, MessageMetadata

class RabbitMQQueue(BaseQueue):
    """Надёжная очередь на RabbitMQ с подтверждениями доставки (ACK/NACK)"""

    def __init__(
        self,
        amqp_url: str,
        queue_name: str,
        exchange_name: str = "",
        routing_key: str = "",
        tracer: Optional[Callable] = None,
    ):
        super().__init__(queue_name, tracer)
        self.amqp_url = amqp_url
        self.exchange_name = exchange_name or queue_name
        self.routing_key = routing_key or queue_name
        self.connection: Optional[aio_pika.RobustConnection] = None
        self.channel: Optional[aio_pika.abc.AbstractChannel] = None
        self.queue: Optional[aio_pika.abc.AbstractQueue] = None
        self.exchange: Optional[aio_pika.abc.AbstractExchange] = None

    async def connect(self):
        if self.connection and not self.connection.is_closed:
            return
        self.connection = await aio_pika.connect_robust(self.amqp_url)
        self.channel = await self.connection.channel(publisher_confirms=True)
        await self.channel.set_qos(prefetch_count=10)

        self.exchange = await self.channel.declare_exchange(
            self.exchange_name, ExchangeType.DIRECT, durable=True
        )

        self.queue = await self.channel.declare_queue(
            self.queue_name, durable=True
        )
        await self.queue.bind(self.exchange, routing_key=self.routing_key)
        self.logger.info(f"[RabbitMQQueue] Connected to {self.amqp_url}")

    async def enqueue(self, data: Any, metadata: Optional[MessageMetadata] = None) -> None:
        await self.connect()
        metadata = metadata or MessageMetadata(actor="unknown")
        if not self.validate_actor(metadata):
            return

        payload = {
            "metadata": metadata.to_dict(),
            "data": data
        }

        body = json.dumps(payload).encode()
        message = Message(
            body=body,
            content_type="application/json",
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
        )

        await self.exchange.publish(message, routing_key=self.routing_key)
        await self.trace_event("enqueue", payload)

    async def consume(self, callback: Callable[[dict, IncomingMessage], Any]) -> None:
        await self.connect()

        async def on_message(message: IncomingMessage):
            async with message.process(requeue=False):
                try:
                    payload = json.loads(message.body.decode())
                    await self.trace_event("dequeue", payload)
                    await callback(payload, message)
                except Exception as e:
                    self.logger.error(f"Failed to process message: {e}")
                    await self.trace_event("error", {"error": str(e)})
                    await message.reject(requeue=True)

        await self.queue.consume(on_message)

    async def ack(self, message: IncomingMessage) -> None:
        try:
            await message.ack()
            await self.trace_event("ack", {"message_id": message.message_id})
        except Exception as e:
            self.logger.error(f"ACK failed: {e}")

    async def nack(self, message: IncomingMessage, requeue: bool = True) -> None:
        try:
            await message.reject(requeue=requeue)
            await self.trace_event("nack", {
                "message_id": message.message_id,
                "requeue": requeue
            })
        except Exception as e:
            self.logger.error(f"NACK failed: {e}")
