# Применение правил RBAC к агентам
# enforcer.py
# Применение правил RBAC к агентам в системе TeslaAI Genesis

from typing import Set, Optional
import logging

logger = logging.getLogger("rbac_enforcer")
logger.setLevel(logging.INFO)

class RBACEnforcer:
    def __init__(self, role_registry, permission_registry):
        """
        :param role_registry: объект RoleRegistry (roles.py)
        :param permission_registry: объект PermissionRegistry (permissions.py)
        """
        self.role_registry = role_registry
        self.permission_registry = permission_registry
        self.agent_roles_cache = {}  # Кэш ролей для агентов: {agent_id: Set[role_names]}

    def assign_roles(self, agent_id: str, roles: Set[str]) -> None:
        """
        Назначить набор ролей агенту.
        """
        for role in roles:
            if not self.role_registry.role_exists(role):
                raise ValueError(f"Роль '{role}' не зарегистрирована")
        self.agent_roles_cache[agent_id] = roles
        logger.info(f"Назначены роли агенту '{agent_id}': {roles}")

    def get_agent_roles(self, agent_id: str) -> Set[str]:
        """
        Получить роли агента.
        """
        return self.agent_roles_cache.get(agent_id, set())

    def check_permission(self, agent_id: str, permission: str, context: Optional[dict] = None) -> bool:
        """
        Проверка, имеет ли агент разрешение с учётом ролей и контекста.
        """
        if not self.permission_registry.has_permission(permission):
            logger.warning(f"Разрешение '{permission}' не зарегистрировано")
            return False

        agent_roles = self.get_agent_roles(agent_id)
        if not agent_roles:
            logger.info(f"Агент '{agent_id}' не имеет ролей")
            return False

        for role in agent_roles:
            try:
                if self.role_registry.has_permission(role, permission):
                    # Можно добавить контекстные проверки здесь
                    logger.debug(f"Агент '{agent_id}' с ролью '{role}' имеет разрешение '{permission}'")
                    return True
            except Exception as e:
                logger.error(f"Ошибка проверки разрешения для роли '{role}': {e}")

        logger.info(f"Агент '{agent_id}' не имеет разрешения '{permission}'")
        return False

    def revoke_roles(self, agent_id: str, roles: Set[str]) -> None:
        """
        Отозвать у агента указанные роли.
        """
        current_roles = self.agent_roles_cache.get(agent_id, set())
        new_roles = current_roles - roles
        self.agent_roles_cache[agent_id] = new_roles
        logger.info(f"Отозваны роли у агента '{agent_id}': {roles}")

    def clear_agent_roles(self, agent_id: str) -> None:
        """
        Удалить все роли агента.
        """
        if agent_id in self.agent_roles_cache:
            del self.agent_roles_cache[agent_id]
            logger.info(f"Все роли удалены у агента '{agent_id}'")
