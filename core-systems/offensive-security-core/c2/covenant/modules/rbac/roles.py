# Определения ролей
# roles.py
# Определения ролей для системы RBAC TeslaAI Genesis

from typing import Dict, List, Set, Optional
import logging

logger = logging.getLogger("roles")
logger.setLevel(logging.INFO)

class Role:
    """
    Представляет роль в системе: может быть атомарной или иерархической.
    """
    def __init__(self, name: str, permissions: Optional[Set[str]] = None, parents: Optional[List[str]] = None):
        self.name = name
        self.permissions = permissions or set()
        self.parents = parents or []

    def add_permission(self, permission: str):
        self.permissions.add(permission)

    def add_parent(self, parent_role: str):
        if parent_role not in self.parents:
            self.parents.append(parent_role)

    def __repr__(self):
        return f"Role({self.name}, perms={list(self.permissions)}, parents={self.parents})"


class RoleRegistry:
    """
    Центральный регистр всех ролей в системе. Позволяет создавать, валидировать и разрешать иерархии.
    """
    def __init__(self):
        self.roles: Dict[str, Role] = {}

    def register_role(self, name: str, permissions: Optional[List[str]] = None, parents: Optional[List[str]] = None):
        if name in self.roles:
            raise ValueError(f"Роль '{name}' уже зарегистрирована")

        role = Role(name, set(permissions or []), parents)
        self.roles[name] = role
        logger.info(f"Зарегистрирована роль: {role}")

    def get_permissions(self, role_name: str, visited: Optional[Set[str]] = None) -> Set[str]:
        """
        Рекурсивно получает все разрешения для роли, включая родительские.
        """
        if role_name not in self.roles:
            raise ValueError(f"Роль '{role_name}' не найдена")

        if visited is None:
            visited = set()

        if role_name in visited:
            return set()

        visited.add(role_name)
        role = self.roles[role_name]
        permissions = set(role.permissions)

        for parent in role.parents:
            permissions.update(self.get_permissions(parent, visited))

        return permissions

    def role_exists(self, role_name: str) -> bool:
        return role_name in self.roles

    def has_permission(self, role_name: str, permission: str) -> bool:
        return permission in self.get_permissions(role_name)

    def all_roles(self) -> List[str]:
        return list(self.roles.keys())

    def debug_dump(self) -> None:
        for role in self.roles.values():
            logger.debug(f"{role.name}: perms={role.permissions}, parents={role.parents}")
