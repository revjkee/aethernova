# message-brokers/queue/sqs_queue.py

import asyncio
import json
import logging
from typing import Any, Callable, Optional

import aioboto3
from botocore.exceptions import ClientError

from .base_queue import BaseQueue, MessageMetadata


class SQSQueue(BaseQueue):
    """
    AWS SQS очередь с поддержкой TTL, trace, Zero-Trust actor валидацией
    и унифицированным интерфейсом работы.
    """

    def __init__(
        self,
        queue_url: str,
        aws_region: str = "us-east-1",
        max_messages: int = 10,
        wait_time_seconds: int = 10,
        tracer: Optional[Callable] = None,
    ):
        super().__init__(queue_url, tracer)
        self.queue_url = queue_url
        self.aws_region = aws_region
        self.max_messages = max_messages
        self.wait_time_seconds = wait_time_seconds

    async def enqueue(self, data: Any, metadata: Optional[MessageMetadata] = None, ttl_seconds: int = 0) -> None:
        metadata = metadata or MessageMetadata(actor="unknown")

        if not self.validate_actor(metadata):
            return

        payload = {
            "metadata": metadata.to_dict(),
            "data": data,
        }

        try:
            async with aioboto3.client("sqs", region_name=self.aws_region) as sqs:
                await sqs.send_message(
                    QueueUrl=self.queue_url,
                    MessageBody=json.dumps(payload),
                    DelaySeconds=ttl_seconds,
                    MessageAttributes={
                        "actor": {
                            "StringValue": metadata.actor,
                            "DataType": "String"
                        },
                        "trace_id": {
                            "StringValue": metadata.trace_id,
                            "DataType": "String"
                        }
                    }
                )
                await self.trace_event("enqueue", payload)
        except ClientError as e:
            self.logger.error(f"[SQSQueue] Enqueue error: {e}")
            await self.trace_event("error", {"error": str(e)})

    async def consume(self, callback: Callable[[dict, str], Any]) -> None:
        try:
            async with aioboto3.client("sqs", region_name=self.aws_region) as sqs:
                while True:
                    response = await sqs.receive_message(
                        QueueUrl=self.queue_url,
                        MaxNumberOfMessages=self.max_messages,
                        WaitTimeSeconds=self.wait_time_seconds,
                        MessageAttributeNames=["All"],
                    )

                    messages = response.get("Messages", [])
                    for msg in messages:
                        try:
                            body = json.loads(msg["Body"])
                            await self.trace_event("dequeue", body)
                            await callback(body, msg["ReceiptHandle"])
                        except Exception as e:
                            self.logger.error(f"[SQSQueue] Processing error: {e}")
                            await self.trace_event("error", {"error": str(e)})
        except Exception as e:
            self.logger.error(f"[SQSQueue] Fatal consume error: {e}")

    async def ack(self, receipt_handle: str) -> None:
        async with aioboto3.client("sqs", region_name=self.aws_region) as sqs:
            try:
                await sqs.delete_message(
                    QueueUrl=self.queue_url,
                    ReceiptHandle=receipt_handle
                )
                await self.trace_event("ack", {"receipt": receipt_handle})
            except Exception as e:
                self.logger.error(f"[SQSQueue] Ack error: {e}")
                await self.trace_event("error", {"error": str(e)})

    async def nack(self, receipt_handle: str, requeue: bool = True) -> None:
        """
        AWS SQS не имеет explicit NACK, но можно изменить Timeout для повторной доставки.
        """
        async with aioboto3.client("sqs", region_name=self.aws_region) as sqs:
            if requeue:
                try:
                    await sqs.change_message_visibility(
                        QueueUrl=self.queue_url,
                        ReceiptHandle=receipt_handle,
                        VisibilityTimeout=0
                    )
                    await self.trace_event("nack", {"receipt": receipt_handle, "requeued": True})
                except Exception as e:
                    self.logger.error(f"[SQSQueue] Nack error: {e}")
                    await self.trace_event("error", {"error": str(e)})
