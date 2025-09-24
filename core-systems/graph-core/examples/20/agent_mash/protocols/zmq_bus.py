# agent-mesh/protocols/zmq_bus.py

import asyncio
import zmq
import zmq.asyncio
import json
from typing import Callable, Dict
from agent_mesh.core.base_bus import BaseAgentBus
from agent_mesh.core.agent_message import AgentMessage
from agent_mesh.utils.message_schema import validate_message_schema
import logging

logger = logging.getLogger("ZMQBus")


class ZMQBus(BaseAgentBus):
    """
    Транспорт на базе ZeroMQ с использованием PUSH/PULL и PUB/SUB паттернов.
    Подходит для низколатентной локальной доставки между агентами.
    """

    def __init__(self, config: dict):
        super().__init__(config)
        self._ctx = zmq.asyncio.Context()
        self._agent_endpoints: Dict[str, str] = config.get("agent_endpoints", {})
        self._push_sockets: Dict[str, zmq.asyncio.Socket] = {}
        self._pull_sockets: Dict[str, zmq.asyncio.Socket] = {}
        self._tasks: Dict[str, asyncio.Task] = {}

    def send(self, message: AgentMessage, target_agent_id: str):
        validate_message_schema(message)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self._async_send(message, target_agent_id))

    async def _async_send(self, message: AgentMessage, target_agent_id: str):
        address = self._agent_endpoints.get(target_agent_id)
        if not address:
            logger.error(f"No ZMQ address configured for agent {target_agent_id}")
            return

        if target_agent_id not in self._push_sockets:
            socket = self._ctx.socket(zmq.PUSH)
            socket.connect(address)
            self._push_sockets[target_agent_id] = socket

        socket = self._push_sockets[target_agent_id]
        await socket.send_json(message.to_dict())
        logger.debug(f"ZMQ sent to {target_agent_id}: {message.message_id}")

    def subscribe(self, agent_id: str, callback: Callable[[AgentMessage], None]):
        if agent_id in self._tasks:
            logger.warning(f"ZMQ subscriber already exists for {agent_id}")
            return

        loop = asyncio.get_event_loop()
        task = loop.create_task(self._async_subscribe(agent_id, callback))
        self._tasks[agent_id] = task
        logger.info(f"ZMQ subscription started for {agent_id}")

    async def _async_subscribe(self, agent_id: str, callback: Callable[[AgentMessage], None]):
        bind_address = self._agent_endpoints.get(agent_id)
        if not bind_address:
            logger.error(f"No ZMQ bind address configured for agent {agent_id}")
            return

        pull_socket = self._ctx.socket(zmq.PULL)
        pull_socket.bind(bind_address)
        self._pull_sockets[agent_id] = pull_socket

        try:
            while True:
                raw = await pull_socket.recv_json()
                msg = AgentMessage.from_dict(raw)
                callback(msg)
        except asyncio.CancelledError:
            logger.info(f"ZMQ listener for {agent_id} cancelled")
        finally:
            pull_socket.close()

    def close(self):
        for sock in self._push_sockets.values():
            sock.close()
        for sock in self._pull_sockets.values():
            sock.close()
        for task in self._tasks.values():
            task.cancel()
        self._ctx.term()
        logger.info("ZMQBus closed")
