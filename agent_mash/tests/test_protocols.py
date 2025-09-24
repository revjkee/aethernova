# agent-mesh/tests/test_protocols.py

import pytest
from agent_mesh.core.agent_message import AgentMessage
from agent_mesh.protocols.protocol_llm import LLMProtocol
from agent_mesh.protocols.protocol_rl import RLProtocol
from agent_mesh.protocols.protocol_rule import RuleBasedProtocol


@pytest.fixture
def sample_message():
    return AgentMessage(
        sender="test",
        task_type="text-generation",
        payload={"text": "Привет, агент"},
        meta={"lang": "ru"}
    )


def test_llm_protocol_processing(sample_message):
    protocol = LLMProtocol()
    result = protocol.process(sample_message)
    assert isinstance(result, dict)
    assert "llm_response" in result


def test_rl_protocol_decision(sample_message):
    protocol = RLProtocol()
    result = protocol.process(sample_message)
    assert isinstance(result, dict)
    assert "decision" in result
    assert result["source"] == "rl"


def test_rule_protocol_matching(sample_message):
    protocol = RuleBasedProtocol()
    result = protocol.process(sample_message)
    assert isinstance(result, dict)
    assert result.get("rule_applied") is True
    assert "outcome" in result
