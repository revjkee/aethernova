# backend/ci/chaos-testing/tests/test_chaos_engine.py

import pytest
from unittest.mock import patch, MagicMock
from chaos_testing.chaos_engine import ChaosEngine
from chaos_testing.registry.chaos_registry import ChaosScenario, chaos_registry


class DummyScenario(ChaosScenario):
    """Dummy chaos scenario for test"""
    name: str = "Dummy"
    description: str = "Dummy scenario"
    parameters: dict = {}

    def run(self, **kwargs):
        return f"Ran {self.name} with {kwargs}"


@pytest.fixture
def engine():
    return ChaosEngine()


def test_register_scenario(engine):
    engine.register_scenario("DummyScenario", DummyScenario)
    assert "DummyScenario" in engine.list_scenarios()


def test_execute_scenario_success(engine):
    engine.register_scenario("DummyScenario", DummyScenario)
    result = engine.execute("DummyScenario", name="Test", description="test", parameters={"key": "value"})
    assert "Ran" in result


def test_execute_unregistered_scenario(engine):
    with pytest.raises(ValueError) as exc_info:
        engine.execute("UnknownScenario", name="x", description="x", parameters={})
    assert "Scenario 'UnknownScenario' not found" in str(exc_info.value)


def test_invalid_scenario_type(engine):
    with pytest.raises(TypeError):
        engine.register_scenario("Invalid", dict)  # Not a subclass


def test_registry_auto_import():
    registered = chaos_registry.list()
    assert isinstance(registered, dict)
    assert all("class" in val for val in registered.values())


def test_scenario_parameter_validation():
    chaos_registry.register(DummyScenario)
    valid = chaos_registry.validate_parameters("DummyScenario", {
        "name": "dummy",
        "description": "test",
        "parameters": {}
    })
    assert valid


def test_scenario_invalid_param_type():
    with pytest.raises(ValueError):
        chaos_registry.validate_parameters("DummyScenario", {
            "name": 123,  # should be str
            "description": "desc",
            "parameters": {}
        })


def test_execute_with_logging(engine):
    with patch("chaos_testing.chaos_engine.logger") as mock_logger:
        engine.register_scenario("DummyScenario", DummyScenario)
        engine.execute("DummyScenario", name="Logger", description="desc", parameters={})
        assert mock_logger.info.called
        assert mock_logger.info.call_args[0][0].startswith("Executing scenario")


def test_engine_handles_exception_gracefully(engine):
    class FailingScenario(ChaosScenario):
        name: str = "Fail"
        description: str = "Fails"
        parameters: dict = {}

        def run(self, **kwargs):
            raise RuntimeError("Boom")

    engine.register_scenario("FailingScenario", FailingScenario)

    with pytest.raises(RuntimeError):
        engine.execute("FailingScenario", name="x", description="x", parameters={})
