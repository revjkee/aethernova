# agent-mesh/strategies/cli_strategy.py

import logging
from agent_mesh.core.agent_message import AgentMessage
from agent_mesh.agent_bus import AgentBus
from agent_mesh.strategy_router import StrategyRouter
import uuid
import time

logger = logging.getLogger("CLIStrategy")


class CLIStrategy:
    """
    CLI-интерфейс для ввода задач вручную в систему agent-mesh.
    Поддерживает прямую маршрутизацию запросов к агентам.
    """

    def __init__(self, agent_bus: AgentBus, router: StrategyRouter):
        self.agent_id = "cli_strategy"
        self.bus = agent_bus
        self.router = router

    def run(self):
        print("TeslaAI CLI Interface started. Type 'exit' to quit.")
        while True:
            try:
                user_input = input(">>> ").strip()
                if user_input.lower() in {"exit", "quit"}:
                    print("Exiting CLI.")
                    break

                task_type = self._infer_task_type(user_input)
                message = AgentMessage(
                    sender=self.agent_id,
                    task_type=task_type,
                    payload={"text": user_input},
                    meta={
                        "origin": "cli",
                        "session_id": str(uuid.uuid4()),
                        "timestamp": time.time()
                    }
                )

                self.router.route(message)
                print(f"[INFO] Task sent as {task_type}")

            except KeyboardInterrupt:
                print("\n[Interrupted]")
                break
            except Exception as e:
                logger.exception(f"Error in CLI input: {e}")
                print(f"[ERROR] {e}")

    def _infer_task_type(self, text: str) -> str:
        """
        Эвристический выбор task_type по ключевым словам
        """
        lowered = text.lower()
        if any(word in lowered for word in ["почему", "как", "что", "explain"]):
            return "question-answering"
        if any(cmd in lowered for cmd in ["generate", "напиши", "создай", "synthesize"]):
            return "text-generation"
        if "route" in lowered or "plan" in lowered:
            return "planning"
        return "reasoning"
