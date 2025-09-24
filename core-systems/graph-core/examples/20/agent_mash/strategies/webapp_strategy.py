# agent-mesh/strategies/webapp_strategy.py

from fastapi import FastAPI, Request
from pydantic import BaseModel
from agent_mesh.core.agent_message import AgentMessage
from agent_mesh.agent_bus import AgentBus
from agent_mesh.strategy_router import StrategyRouter
import time
import uuid
import logging

logger = logging.getLogger("WebAppStrategy")


class WebAppRequest(BaseModel):
    user_id: str
    input_text: str
    session_id: str
    context: dict = {}


class WebAppStrategy:
    """
    HTTP-интерфейс для приёма задач из WebApp-интерфейса (UI, Telegram MiniApp).
    Подключается к FastAPI-приложению.
    """

    def __init__(self, agent_bus: AgentBus, router: StrategyRouter):
        self.agent_id = "webapp_strategy"
        self.bus = agent_bus
        self.router = router
        self.app = FastAPI()

        @self.app.post("/webapp/task")
        async def receive_task(req: WebAppRequest):
            task_type = self._infer_task_type(req.input_text)

            message = AgentMessage(
                sender=self.agent_id,
                task_type=task_type,
                payload={
                    "text": req.input_text,
                    "user_id": req.user_id,
                    "session_id": req.session_id,
                    "context": req.context,
                },
                meta={
                    "origin": "webapp",
                    "received_at": time.time(),
                    "request_id": str(uuid.uuid4())
                }
            )

            self.router.route(message)
            return {"status": "accepted", "task_type": task_type}

    def _infer_task_type(self, text: str) -> str:
        lowered = text.lower()
        if any(q in lowered for q in ["why", "how", "что", "почему", "как"]):
            return "question-answering"
        if any(c in lowered for c in ["напиши", "generate", "создай", "story", "script"]):
            return "text-generation"
        return "reasoning"

    def get_app(self):
        return self.app
