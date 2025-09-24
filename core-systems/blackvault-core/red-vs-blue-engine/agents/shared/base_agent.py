# red-vs-blue-engine/agents/shared/base_agent.py

import abc
import logging
from typing import Dict, Optional, Any
from datetime import datetime

from core.security.rbac import check_permissions
from core.monitoring.metrics import agent_metrics_collector
from core.ai.context import AgentContext
from core.logging.tracer import Tracer


logger = logging.getLogger("shared.base_agent")


class BaseAgent(abc.ABC):
    """
    Абстрактный базовый класс для всех агентов (Red/Blue/Hybrid).
    Включает поддержку RBAC, трейсинга, профилирования и стандартного контекста.
    """

    def __init__(
        self,
        agent_id: str,
        role: str,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.agent_id = agent_id
        self.role = role
        self.config = config or {}
        self.context
