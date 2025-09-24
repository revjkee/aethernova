# agent-mesh/protocols/grpc_bus.py

import asyncio
import grpc
import json
from concurrent import futures
from typing import Callable, Dict

from agent_mesh.core.base_bus import BaseAgentBus
from agent_mesh.core.agent_message import AgentMessage
from agent_mesh.utils.message_schema import validate_message_schema
import logging

from grpc_bus_pb2 import MessageRequest, MessageReply
import grpc_bus_pb2_grpc

logger = logging.getLogger("GRPCBus")


class GRPCBus(BaseAgentBus, grpc_bus_pb2_grpc.AgentBusServicer):
    """
    gRPC-транспорт между агентами.
    Поддерживает двунаправленные потоки: агент может принимать и отправлять сообщения.
    """

    def __init__(self, config: dict):
        super().__init__(config)
        self._server = None
        self._client_channels: Dict[str, grpc.aio.Channel] = {}
        self._client_stubs: Dict[str, grpc_bus_pb2_grpc.AgentBusStub] = {}
        self._callbacks: Dict[str, Callable[[AgentMessage], None]] = {}
        self._host = config.get("host", "localhost")
        self._port = config.get("port", 50051)

    def send(self, message: AgentMessage, target_agent_id: str):
        validate_message_schema(message)
        asyncio.get_event_loop().run_until_complete(self._async_send(message, target_agent_id))

    async def _async_send(self, message: AgentMessage, target_agent_id: str):
        address = f"{self._host}:{self._port}"
        if target_agent_id not in self._client_channels:
            channel = grpc.aio.insecure_channel(address)
            self._client_channels[target_agent_id] = channel
            self._client_stubs[target_agent_id] = grpc_bus_pb2_grpc.AgentBusStub(channel)

        stub = self._client_stubs[target_agent_id]
        payload = json.dumps(message.to_dict())
        request = MessageRequest(sender=message.sender, payload=payload)
        await stub.DeliverMessage(request)
        logger.debug(f"gRPC sent to {target_agent_id}: {message.message_id}")

    def subscribe(self, agent_id: str, callback: Callable[[AgentMessage], None]):
        self._callbacks[agent_id] = callback
        logger.info(f"gRPC subscribed agent {agent_id} to message stream")

    async def DeliverMessage(self, request: MessageRequest, context):
        try:
            data = json.loads(request.payload)
            msg = AgentMessage.from_dict(data)
            callback = self._callbacks.get(msg.sender)
            if callback:
                callback(msg)
            return MessageReply(status="OK")
        except Exception as e:
            logger.error(f"Error in gRPC DeliverMessage: {e}")
            return MessageReply(status="ERROR")

    def start_server(self):
        self._server = grpc.aio.server()
        grpc_bus_pb2_grpc.add_AgentBusServicer_to_server(self, self._server)
        self._server.add_insecure_port(f"{self._host}:{self._port}")
        asyncio.get_event_loop().run_until_complete(self._server.start())
        logger.info(f"gRPC server started at {self._host}:{self._port}")

    def close(self):
        if self._server:
            asyncio.get_event_loop().run_until_complete(self._server.stop(0))
        for channel in self._client_channels.values():
            asyncio.get_event_loop().run_until_complete(channel.close())
        logger.info("gRPC connections closed")
