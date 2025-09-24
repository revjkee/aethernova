# Управление разрешениями
# permissions.py
# Управление разрешениями для системы RBAC TeslaAI Genesis

from typing import Set, Dict
import logging

logger = logging.getLogger("permissions")
logger.setLevel(logging.INFO)

class PermissionRegistry:
    """
    Регистрирует и управляет разрешениями.
    """
    def __init__(self):
        self.permissions: Set[str] = set()

    def register_permission(self, permission: str) -> None:
        if permission in self.permissions:
            logger.warning(f"Разрешение '{permission}' уже зарегистрировано")
            return
        self.permissions.add(permission)
        logger.info(f"Разрешение '{permission}' зарегистрировано")

    def unregister_permission(self, permission: str) -> None:
        if permission not in self.permissions:
            logger.warning(f"Попытка удалить несуществующее разрешение '{permission}'")
            return
        self.permissions.remove(permission)
        logger.info(f"Разрешение '{permission}' удалено")

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def list_permissions(self) -> Set[str]:
        return self.permissions.copy()

    def validate_permissions(self, perms: Set[str]) -> bool:
        """
        Проверяет, что все разрешения в множестве зарегистрированы.
        """
        unknown = perms - self.permissions
        if unknown:
            logger.error(f"Неизвестные разрешения: {unknown}")
            return False
        return True
