# blackvault-core/orchestrator/execution_firewall.py

import logging
from typing import Dict, Any, Optional

from core.models.execution import ExecutionRequest, ExecutionDecision
from core.policy.rbac import check_permission
from core.security.zkp import verify_proof
from core.security.sandbox import RuntimeIsolator
from core.ai.intent_analysis import IntentValidator
from core.telemetry.event_bus import EventBus
from core.utils.tracing import trace_execution

logger = logging.getLogger("execution_firewall")


class ExecutionFirewall:
    """
    Промышленный межмодульный Execution Firewall, обеспечивающий проверку, изоляцию
    и контроль всех исполняемых действий внутри системы TeslaAI Genesis.
    """

    def __init__(
        self,
        isolator: RuntimeIsolator,
        event_bus: EventBus,
        intent_validator: IntentValidator,
    ):
        self.isolator = isolator
        self.event_bus = event_bus
        self.intent_validator = intent_validator

    @trace_execution
    async def authorize(self, request: ExecutionRequest) -> ExecutionDecision:
        """
        Проверяет, разрешено ли выполнение запроса с учётом:
        - ZKP-подписи,
        - политик RBAC,
        - AI-валидации намерений.
        """

        logger.debug(f"Проверка запроса от {request.actor_id} на {request.action}")

        # 1. ZKP-проверка подписи (если присутствует)
        if request.zkp_proof and not verify_proof(request.actor_id, request.zkp_proof):
            logger.warning(f"ZKP-проверка не пройдена: {request.actor_id}")
            return ExecutionDecision(allowed=False, reason="Invalid ZKP proof")

        # 2. Проверка RBAC-доступа
        if not check_permission(request.actor_id, request.action):
            logger.warning(f"RBAC отказано: {request.actor_id} -> {request.action}")
            return ExecutionDecision(allowed=False, reason="RBAC denied")

        # 3. Проверка AI-интента
        is_malicious = await self.intent_validator.is_malicious(request)
        if is_malicious:
            logger.critical(f"AI-блокировка действия: подозрительный интент от {request.actor_id}")
            return ExecutionDecision(allowed=False, reason="AI intent blocked")

        # 4. Изоляция перед допуском (sandbox-level)
        if not await self.isolator.is_safe(request):
            logger.error(f"Изоляция отклонила исполнение запроса: {request.actor_id}")
            return ExecutionDecision(allowed=False, reason="Sandbox isolation failed")

        logger.info(f"Запрос разрешён: {request.actor_id} -> {request.action}")
        await self.event_bus.publish("execution.approved", request.dict())

        return ExecutionDecision(allowed=True)

