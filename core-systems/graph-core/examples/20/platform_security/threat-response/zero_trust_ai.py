import asyncio
from typing import Dict, Any, Optional
from datetime import datetime

from genius_core.security.behavior_graph import BehaviorGraph
from genius_core.security.privilege_manager import PrivilegeManager
from genius_core.security.anomaly_detector import AnomalyDetector
from genius_core.security.policy_enforcer import PolicyEnforcer
from genius_core.security.http_guard import HTTPGuard
from genius_core.security.audit_logger import AuditLogger

from genius_core.security.utils.hash_context import hash_request_context
from genius_core.security.utils.time_window import is_within_time_window
from genius_core.security.utils.ai_vote import AgentConsensus


class ZeroTrustAIAgent:
    """
    Центральный агент координации AI-безопасности.
    Обеспечивает политику нулевого доверия и реакцию на угрозы.
    """

    def __init__(self):
        self.behavior_graph = BehaviorGraph()
        self.privilege_manager = PrivilegeManager()
        self.anomaly_detector = AnomalyDetector()
        self.policy_enforcer = PolicyEnforcer()
        self.http_guard = HTTPGuard()
        self.audit_logger = AuditLogger()
        self.consensus = AgentConsensus()

    async def evaluate_request(self, user_id: str, request: Dict[str, Any], metadata: Dict[str, Any]) -> bool:
        """
        Главная точка входа: проверка запроса на соответствие Zero Trust политике.
        """
        context_hash = hash_request_context(user_id, request, metadata)
        timestamp = datetime.utcnow()

        # 1. Логирование поведения и построение графа
        self.behavior_graph.record_action(user_id, request, timestamp)

        # 2. Проверка привилегий
        if not self.privilege_manager.has_required_privileges(user_id, request):
            self.audit_logger.log_denied(user_id, request, reason="insufficient_privileges")
            return False

        # 3. Инспекция HTTP-параметров
        if not self.http_guard.inspect(request):
            self.audit_logger.log_denied(user_id, request, reason="http_violation")
            return False

        # 4. Аномалия в поведении
        if self.anomaly_detector.is_anomalous(user_id, request, metadata):
            self.audit_logger.log_alert(user_id, request, reason="behavior_anomaly")

        # 5. Принудительная проверка политики (глубокая)
        policy_result = await self.policy_enforcer.enforce(user_id, request)
        if not policy_result.allowed:
            self.audit_logger.log_denied(user_id, request, reason=policy_result.reason)
            return False

        # 6. AI-консенсус: несколько агентов голосуют за доверие
        decision = await self.consensus.vote(user_id=user_id, request=request, context_hash=context_hash)
        if not decision.allowed:
            self.audit_logger.log_denied(user_id, request, reason="ai_consensus_denied")
            return False

        # 7. Временное окно запроса
        if not is_within_time_window(timestamp, policy_result.allowed_window):
            self.audit_logger.log_denied(user_id, request, reason="expired_context")
            return False

        # Успешный допуск
        self.audit_logger.log_approved(user_id, request)
        return True

    async def flag_suspicious_user(self, user_id: str):
        """
        Активное реагирование на угрозу — маркировка пользователя.
        """
        self.privilege_manager.restrict_user(user_id)
        self.audit_logger.log_flagged(user_id, reason="manual_suspicion_flag")

    async def invalidate_session(self, user_id: str):
        """
        Жёсткий сброс сессии пользователя по требованию агента или политикам.
        """
        await self.policy_enforcer.invalidate_session(user_id)
        self.audit_logger.log_termination(user_id, reason="session_invalidated")


# Экспорт для других модулей
__all__ = ["ZeroTrustAIAgent"]
