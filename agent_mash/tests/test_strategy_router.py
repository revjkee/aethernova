# agent-mesh/tests/test_strategy_router.py

import pytest
from agent_mesh.strategy_router import StrategyRouter
from agent_mesh.core.agent_message import AgentMessage


class MockHandler:
    def __init__(self):
        self.calls = []

    def handle(self, message: AgentMessage):
        self.calls.append(message)


@pytest.fixture
def setup_router():
    router = StrategyRouter()
    handler = MockHandler()
    router.register_strategy("text-generation", handler.handle)
    router.register_strategy("question-answering", handler.handle)
    return router, handler


def test_routing_to_correct_handler(setup_router):
    router, handler = setup_router

    msg = AgentMessage(
        sender="cli",
        task_type="text-generation",
        payload={"text": "test"},
        meta={}
    )

    router.route(msg)

    assert len(handler.calls) == 1
    assert handler.calls[0].payload["text"] == "test"


def test_multiple_task_types(setup_router):
    router, handler = setup_router

    types = ["text-generation", "question-answering"]
    for t in types:
        msg = AgentMessage(
            sender="cli",
            task_type=t,
            payload={"text": f"msg for {t}"},
            meta={}
        )
        router.route(msg)

    assert len(handler.calls) == 2
    assert handler.calls[0].task_type == "text-generation"
    assert handler.calls[1].task_type == "question-answering"


def test_unregistered_strategy():
    router = StrategyRouter()
    msg = AgentMessage(
        sender="api",
        task_type="unknown-task",
        payload={"x": 1},
        meta={}
    )

    with pytest.raises(ValueError):
        router.route(msg)
