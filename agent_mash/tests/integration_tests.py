import unittest
from agent_mash.agent_bus import AgentBus
from agent_mash.protocols.communicator import Communicator
from agent_mash.planner.task_orchestrator import TaskOrchestrator
from agent_mash.registry.registry_service import RegistryService


class DummyAgent:
    def __init__(self, name):
        self.name = name
        self.received_payload = None

    def handler(self, payload):
        self.received_payload = payload
        return {"status": "ok", "agent": self.name}


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.registry = RegistryService()
        self.bus = AgentBus()
        self.orchestrator = TaskOrchestrator()
        self.communicator = Communicator(self.bus)

        self.agent_a = DummyAgent("agent_a")
        self.agent_b = DummyAgent("agent_b")

        self.registry.register("agent_a", self.agent_a.handler)
        self.registry.register("agent_b", self.agent_b.handler)

        self.orchestrator.register_agent("agent_a", self.agent_a.handler)
        self.orchestrator.register_agent("agent_b", self.agent_b.handler)

        self.orchestrator.start()

    def tearDown(self):
        self.orchestrator.stop()

    def test_agent_registration(self):
        agents = self.orchestrator.list_registered_agents()
        self.assertIn("agent_a", agents)
        self.assertIn("agent_b", agents)

    def test_task_submission_and_execution(self):
        result = {}

        def callback(response):
            result["data"] = response

        self.orchestrator.submit_task(
            agent_name="agent_a",
            payload={"test": "value"},
            priority=1,
            callback=callback
        )

        # Подождать выполнения
        self.orchestrator._worker_thread.join(timeout=1.5)

        self.assertIn("data", result)
        self.assertEqual(result["data"]["status"], "ok")
        self.assertEqual(result["data"]["agent"], "agent_a")
        self.assertEqual(self.agent_a.received_payload["test"], "value")

    def test_message_routing(self):
        self.bus.register("agent_b", self.agent_b.handler)
        response = self.communicator.send_message("agent_b", {"ping": True})
        self.assertEqual(response["agent"], "agent_b")

    def test_unregistered_agent_message(self):
        response = self.communicator.send_message("unknown_agent", {"test": 123})
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["message"], "Agent not found")


if __name__ == "__main__":
    unittest.main()
