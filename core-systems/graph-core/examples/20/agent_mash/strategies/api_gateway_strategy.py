# agent-mesh/strategies/api_gateway_strategy.py

from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from agent_mesh.core.agent_message import AgentMessage
from agent_mesh.agent_bus import AgentBus
from agent_mesh.strategy_router import StrategyRouter
import time
import uuid
import logging

logger = logging.getLogger("APIGatewayStrategy")


class APITaskRequest(BaseModel):
    source: str
    input: str
    meta: dict = {}


class APIGatewayStrategy:
    """
    Входной шлюз для REST/gRPC вызовов внешних систем.
    Преобразует запрос в AgentMessage и маршрутизирует через agent-mesh.
    """

    def __init__(self, agent_bus: AgentBus, router: StrategyRouter):
        self.agent_id = "api_gateway"
        self.bus = agent_bus
        self.router = router
        self.app = FastAPI()

        @self.app.post("/api/task")
        async def handle_task(req: APITaskRequest):
            task_type = self._infer_task_type(req.input)

            message = AgentMessage(
                sender=self.agent_id,
                task_type=task_type,
                payload={
                    "text": req.input,
                    "source": req.source
                },
                meta={
                    "origin": "external-api",
                    "request_id": str(uuid.uuid4()),
                    "timestamp": time.time(),
                    **req.meta
                }
            )

            try:
                self.router.route(message)
                return {"status": "accepted", "task_type": task_type}
            except Exception as e:
                logger.exception("Failed to route API task")
                raise HTTPException(status_code=500, detail=str(e))

    def _infer_task_type(self, text: str) -> str:
        lowered = text.lower()
        if any(q in lowered for q in ["why", "how", "что", "почему", "как"]):
            return "question-answering"
        if any(cmd in lowered for cmd in ["generate", "напиши", "story", "create"]):
            return "text-generation"
        if any(r in lowered for r in ["plan", "optimize", "policy"]):
            return "planning"
        return "reasoning"

    def get_app(self):
        return self.app
