# agent-mesh/tests/test_registry.py

import pytest
import time
from agent_mesh.registry.agent_registry import AgentRegistry


@pytest.fixture
def registry():
    return AgentRegistry()


def test_register_agent(registry):
    registry.register("agent_001", agent_type="llm", metadata={"version": "1.0"})

    assert "agent_001" in registry.agents
    info = registry.get_info("agent_001")
    assert info["agent_type"] == "llm"
    assert info["metadata"]["version"] == "1.0"


def test_update_agent_session(registry):
    registry.register("agent_002", agent_type="rl")
    first_update = registry.agents["agent_002"]["last_seen"]

    time.sleep(0.01)
    registry.update_session("agent_002")
    second_update = registry.agents["agent_002"]["last_seen"]

    assert second_update > first_update


def test_get_online_agents(registry):
    registry.register("agent_003", agent_type="rule")
    registry.update_session("agent_003")

    online = registry.get_online_agents(max_age=5)
    assert "agent_003" in online


def test_unregister_agent(registry):
    registry.register("agent_004", agent_type="llm")
    registry.unregister("agent_004")

    assert "agent_004" not in registry.agents
