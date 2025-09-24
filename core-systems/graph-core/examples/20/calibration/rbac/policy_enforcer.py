import logging
from typing import Dict, List, Optional, Set

logger = logging.getLogger("calibration.rbac")

class AccessDenied(Exception):
    """Ошибка при попытке несанкционированного доступа."""


class Subject:
    """Пользователь или агент, выполняющий действие."""

    def __init__(self, subject_id: str, roles: Optional[Set[str]] = None):
        self.subject_id = subject_id
        self.roles = roles or set()

    def has_role(self, role: str) -> bool:
        return role in self.roles


class PolicyRule:
    """Правило доступа: какая роль может выполнять какие действия над объектами."""

    def __init__(self, role: str, actions: Set[str], resources: Optional[Set[str]] = None):
        self.role = role
        self.actions = actions
        self.resources = resources or {"*"}

    def is_allowed(self, action: str, resource: str) -> bool:
        return action in self.actions and ("*" in self.resources or resource in self.resources)


class PolicyEnforcer:
    """
    Основной модуль RBAC-контроля.
    Управляет политиками и валидирует права доступа в системе калибровки.
    """

    def __init__(self):
        self.policies: List[PolicyRule] = []
        self.superusers: Set[str] = set()

    def add_policy(self, rule: PolicyRule) -> None:
        logger.debug(f"Добавлено правило: роль={rule.role}, действия={rule.actions}, ресурсы={rule.resources}")
        self.policies.append(rule)

    def add_superuser(self, subject_id: str) -> None:
        self.superusers.add(subject_id)
        logger.info(f"Добавлен суперпользователь: {subject_id}")

    def is_action_allowed(self, subject: Subject, action: str, resource: str) -> bool:
        if subject.subject_id in self.superusers:
            logger.debug(f"{subject.subject_id} имеет привилегии суперпользователя")
            return True

        for role in subject.roles:
            for policy in self.policies:
                if policy.role == role and policy.is_allowed(action, resource):
                    logger.debug(f"Доступ разрешён: {subject.subject_id} -> {action} -> {resource}")
                    return True

        logger.warning(f"ОТКАЗ в доступе: {subject.subject_id} -> {action} -> {resource}")
        return False

    def enforce(self, subject: Subject, action: str, resource: str) -> None:
        """
        Основной метод применения политик. Бросает исключение при нарушении.
        """
        if not self.is_action_allowed(subject, action, resource):
            raise AccessDenied(f"Доступ запрещён для {subject.subject_id}: {action} на {resource}")

    def reset_policies(self) -> None:
        self.policies.clear()
        self.superusers.clear()
        logger.info("Политики RBAC сброшены.")


# Примеры действий и ресурсов (для использования в константах)
ACTIONS = {
    "read", "write", "modify", "calibrate", "inject", "delete", "admin"
}

RESOURCES = {
    "parameter:*",
    "parameter:learning_rate",
    "module:chaos_engine",
    "module:calibration_engine",
    "module:dependency_graph"
}
