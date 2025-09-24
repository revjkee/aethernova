from typing import Dict, List, Optional, Union, Set
from datetime import datetime, timedelta
from enum import Enum, auto
import logging

from .zero_trust_ai import ZeroTrustEvaluator
from .behavior_graph import BehaviorGraph

logger = logging.getLogger(__name__)


class AccessLevel(Enum):
    NONE = 0
    READ = 1
    WRITE = 2
    ADMIN = 3


class Role(Enum):
    USER = auto()
    MODERATOR = auto()
    ADMIN = auto()
    SUPERADMIN = auto()
    SYSTEM = auto()


ROLE_HIERARCHY = {
    Role.USER: 0,
    Role.MODERATOR: 1,
    Role.ADMIN: 2,
    Role.SUPERADMIN: 3,
    Role.SYSTEM: 4,
}


class PrivilegeManager:
    """
    Менеджер привилегий на основе RBAC + AI-проверок.
    """

    def __init__(self):
        self.role_map: Dict[str, Role] = {}
        self.permission_matrix: Dict[str, Dict[Role, AccessLevel]] = {}
        self.trust_evaluator = ZeroTrustEvaluator()
        self.behavior_graph = BehaviorGraph()
        self.restricted_roles: Set[Role] = {Role.SYSTEM}

    def assign_role(self, user_id: str, role: Role):
        """
        Назначает роль пользователю.
        """
        self.role_map[user_id] = role
        logger.info(f"Assigned role {role.name} to {user_id}")

    def set_permission(self, resource: str, role: Role, level: AccessLevel):
        """
        Устанавливает уровень доступа для ресурса и роли.
        """
        self.permission_matrix.setdefault(resource, {})[role] = level

    def check_access(
        self,
        user_id: str,
        resource: str,
        action: str,
        request_context: Optional[Dict] = None
    ) -> bool:
        """
        Проверяет, имеет ли пользователь доступ к ресурсу.
        Включает: RBAC, оценку угрозы, анализ поведения.
        """
        role = self.role_map.get(user_id, Role.USER)
        allowed_level = self._get_permission_level(resource, role)
        requested_level = self._map_action_to_level(action)

        if allowed_level.value < requested_level.value:
            logger.warning(f"Access denied: {user_id} lacks permission for {action} on {resource}")
            return False

        # AI-модель нулевого доверия
        if not self.trust_evaluator.evaluate(user_id, request_context):
            logger.warning(f"Access denied by ZeroTrust: {user_id}")
            return False

        # Проверка на аномальное поведение
        if not self._is_behavior_consistent(user_id, request_context):
            logger.warning(f"Access denied due to behavioral anomaly: {user_id}")
            return False

        return True

    def get_user_role(self, user_id: str) -> Role:
        return self.role_map.get(user_id, Role.USER)

    def elevate_privileges(self, user_id: str, target_role: Role) -> bool:
        """
        Повышает привилегии, если доверие достаточно высоко.
        """
        if target_role in self.restricted_roles:
            return False

        trust_score = self.trust_evaluator.get_trust_score(user_id)
        if trust_score >= 0.9 and ROLE_HIERARCHY[target_role] > ROLE_HIERARCHY[self.get_user_role(user_id)]:
            self.assign_role(user_id, target_role)
            logger.info(f"Privilege escalated: {user_id} → {target_role.name}")
            return True
        return False

    def _get_permission_level(self, resource: str, role: Role) -> AccessLevel:
        return self.permission_matrix.get(resource, {}).get(role, AccessLevel.NONE)

    def _map_action_to_level(self, action: str) -> AccessLevel:
        action = action.lower()
        if action in {"view", "read", "status"}:
            return AccessLevel.READ
        if action in {"edit", "update", "write", "post"}:
            return AccessLevel.WRITE
        if action in {"delete", "grant", "configure", "shutdown"}:
            return AccessLevel.ADMIN
        return AccessLevel.NONE

    def _is_behavior_consistent(self, user_id: str, request_context: Optional[Dict]) -> bool:
        """
        Анализ графа поведения на предмет подозрительных отклонений.
        """
        if not request_context:
            return True
        self.behavior_graph.record_action(user_id, request_context)
        recent_path = self.behavior_graph.get_user_path(user_id)
        if "shutdown" in recent_path and "login" not in recent_path:
            return False
        return True


# Экспорт
__all__ = ["PrivilegeManager", "Role", "AccessLevel"]
