# agent-mesh/tests/test_agent_bus.py

import pytest
from agent_mesh.agent_bus import AgentBus
from agent_mesh.core.agent_message import AgentMessage
from agent_mesh.schema.message_types import MessageType


class MockAgent:
    def __init__(self):
        self.received = []

    def handle(self, msg: AgentMessage):
        self.received.append(msg)


@pytest.fixture
def setup_bus():
    bus = AgentBus()
    agent = MockAgent()
    bus.register_handler("mock_task", agent.handle)
    return bus, agent


def test_send_and_receive(setup_bus):
    bus, agent = setup_bus
    msg = AgentMessage(
        sender="test",
        task_type="mock_task",
        payload={"data": "hello"},
        meta={}
    )

    bus.send(msg)
    assert len(agent.received) == 1
    assert agent.received[0].payload["data"] == "hello"


def test_multiple_messages(setup_bus):
    bus, agent = setup_bus

    for i in range(3):
        msg = AgentMessage(
            sender="test",
            task_type="mock_task",
            payload={"index": i},
            meta={}
        )
        bus.send(msg)

    assert len(agent.received) == 3
    assert agent.received[2].payload["index"] == 2


def test_unregistered_task_type():
    bus = AgentBus()
    msg = AgentMessage(
        sender="test",
        task_type="unknown_task",
        payload={"x": 1},
        meta={}
    )

    with pytest.raises(ValueError):
        bus.send(msg)
