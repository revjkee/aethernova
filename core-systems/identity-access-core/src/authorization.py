"""
Authorization Engine - Identity Access Core
Модуль авторизации и контроля доступа
"""

import asyncio
from typing import Dict, Any, List, Set, Optional
from loguru import logger
from enum import Enum


class Permission(str, Enum):
    """Базовые разрешения"""
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    DELETE = "delete"
    ADMIN = "admin"
    ALL = "*"


class AuthorizationEngine:
    """Движок авторизации и контроля доступа"""
    
    def __init__(self, config: Any):
        self.config = config
        self.policies: Dict[str, Dict[str, Any]] = {}
        self.role_permissions: Dict[str, Set[str]] = {}
        self.resource_acls: Dict[str, Dict[str, Set[str]]] = {}
        
        # Инициализация базовых ролей и политик
        self._initialize_default_roles()
        self._initialize_default_policies()
        
        logger.info("🔐 Authorization Engine инициализирован")
    
    def _initialize_default_roles(self) -> None:
        """Инициализирует роли по умолчанию"""
        self.role_permissions = {
            "superuser": {Permission.ALL},
            "admin": {
                Permission.READ,
                Permission.WRITE,
                Permission.EXECUTE,
                Permission.DELETE,
                Permission.ADMIN
            },
            "emergency": {
                Permission.ALL,
                "emergency_access",
                "system_recovery",
                "bypass_restrictions"
            },
            "user": {
                Permission.READ,
                Permission.WRITE,
                Permission.EXECUTE
            },
            "readonly": {
                Permission.READ
            },
            "guest": {
                Permission.READ
            }
        }
        
        logger.info("✅ Роли по умолчанию инициализированы")
    
    def _initialize_default_policies(self) -> None:
        """Инициализирует политики по умолчанию"""
        self.policies = {
            "default": {
                "allow": [Permission.READ],
                "deny": [],
                "conditions": {}
            },
            "emergency": {
                "allow": [Permission.ALL],
                "deny": [],
                "conditions": {
                    "emergency_mode": True
                }
            },
            "admin_only": {
                "allow": [Permission.ADMIN],
                "deny": [],
                "conditions": {
                    "required_role": "admin"
                }
            }
        }
        
        logger.info("✅ Политики по умолчанию инициализированы")
    
    async def check_permission(
        self,
        user: Dict[str, Any],
        resource: str,
        permission: str
    ) -> bool:
        """
        Проверяет, есть ли у пользователя разрешение на ресурс
        
        Args:
            user: Данные пользователя
            resource: Ресурс для доступа
            permission: Требуемое разрешение
            
        Returns:
            True если доступ разрешен, False иначе
        """
        user_permissions = await self._get_user_permissions(user)
        
        # Проверка универсального разрешения
        if Permission.ALL in user_permissions or "*" in user_permissions:
            logger.debug(f"✅ Универсальный доступ для {user['username']}")
            return True
        
        # Проверка специфичного разрешения
        if permission in user_permissions:
            logger.debug(f"✅ Доступ разрешен: {user['username']} -> {resource} ({permission})")
            return True
        
        # Проверка ACL ресурса
        if await self._check_resource_acl(user, resource, permission):
            logger.debug(f"✅ Доступ разрешен через ACL: {user['username']} -> {resource}")
            return True
        
        logger.warning(f"⛔ Доступ запрещен: {user['username']} -> {resource} ({permission})")
        return False
    
    async def _get_user_permissions(self, user: Dict[str, Any]) -> Set[str]:
        """Получает все разрешения пользователя"""
        permissions = set(user.get('permissions', []))
        
        # Добавление разрешений из ролей
        for role in user.get('roles', []):
            if role in self.role_permissions:
                permissions.update(self.role_permissions[role])
        
        return permissions
    
    async def _check_resource_acl(
        self,
        user: Dict[str, Any],
        resource: str,
        permission: str
    ) -> bool:
        """Проверяет ACL ресурса"""
        if resource not in self.resource_acls:
            return False
        
        acl = self.resource_acls[resource]
        user_id = user.get('user_id')
        
        # Проверка индивидуальных разрешений
        if user_id in acl and permission in acl[user_id]:
            return True
        
        # Проверка групповых разрешений
        for role in user.get('roles', []):
            if role in acl and permission in acl[role]:
                return True
        
        return False
    
    async def grant_permission(
        self,
        user_or_role: str,
        resource: str,
        permission: str
    ) -> bool:
        """Предоставляет разрешение пользователю/роли на ресурс"""
        if resource not in self.resource_acls:
            self.resource_acls[resource] = {}
        
        if user_or_role not in self.resource_acls[resource]:
            self.resource_acls[resource][user_or_role] = set()
        
        self.resource_acls[resource][user_or_role].add(permission)
        logger.info(f"✅ Разрешение предоставлено: {user_or_role} -> {resource} ({permission})")
        
        return True
    
    async def revoke_permission(
        self,
        user_or_role: str,
        resource: str,
        permission: str
    ) -> bool:
        """Отзывает разрешение у пользователя/роли"""
        if resource not in self.resource_acls:
            return False
        
        if user_or_role not in self.resource_acls[resource]:
            return False
        
        self.resource_acls[resource][user_or_role].discard(permission)
        logger.info(f"✅ Разрешение отозвано: {user_or_role} -> {resource} ({permission})")
        
        return True
    
    async def create_role(self, role_name: str, permissions: List[str]) -> bool:
        """Создает новую роль с разрешениями"""
        if role_name in self.role_permissions:
            logger.warning(f"⚠️ Роль уже существует: {role_name}")
            return False
        
        self.role_permissions[role_name] = set(permissions)
        logger.info(f"✅ Роль создана: {role_name}")
        
        return True
    
    async def delete_role(self, role_name: str) -> bool:
        """Удаляет роль"""
        # Защита системных ролей
        if role_name in ["superuser", "admin", "emergency"]:
            logger.error(f"❌ Невозможно удалить системную роль: {role_name}")
            return False
        
        if role_name in self.role_permissions:
            del self.role_permissions[role_name]
            logger.info(f"✅ Роль удалена: {role_name}")
            return True
        
        return False
    
    async def add_permission_to_role(self, role_name: str, permission: str) -> bool:
        """Добавляет разрешение к роли"""
        if role_name not in self.role_permissions:
            logger.warning(f"⚠️ Роль не найдена: {role_name}")
            return False
        
        self.role_permissions[role_name].add(permission)
        logger.info(f"✅ Разрешение добавлено к роли {role_name}: {permission}")
        
        return True
    
    async def remove_permission_from_role(self, role_name: str, permission: str) -> bool:
        """Удаляет разрешение из роли"""
        if role_name not in self.role_permissions:
            return False
        
        self.role_permissions[role_name].discard(permission)
        logger.info(f"✅ Разрешение удалено из роли {role_name}: {permission}")
        
        return True
    
    async def evaluate_policy(
        self,
        policy_name: str,
        user: Dict[str, Any],
        context: Dict[str, Any]
    ) -> bool:
        """Оценивает политику для пользователя в контексте"""
        if policy_name not in self.policies:
            logger.warning(f"⚠️ Политика не найдена: {policy_name}")
            return False
        
        policy = self.policies[policy_name]
        
        # Проверка условий политики
        conditions = policy.get('conditions', {})
        for condition_key, condition_value in conditions.items():
            if context.get(condition_key) != condition_value:
                return False
        
        # Проверка запретов
        denied = policy.get('deny', [])
        user_permissions = await self._get_user_permissions(user)
        if any(perm in user_permissions for perm in denied):
            return False
        
        # Проверка разрешений
        allowed = policy.get('allow', [])
        if Permission.ALL in allowed or "*" in allowed:
            return True
        
        return any(perm in user_permissions for perm in allowed)
    
    def get_role_permissions(self, role_name: str) -> Optional[Set[str]]:
        """Возвращает разрешения роли"""
        return self.role_permissions.get(role_name)
    
    def list_roles(self) -> List[str]:
        """Возвращает список всех ролей"""
        return list(self.role_permissions.keys())
    
    def get_resource_acl(self, resource: str) -> Optional[Dict[str, Set[str]]]:
        """Возвращает ACL ресурса"""
        return self.resource_acls.get(resource)
    
    def get_stats(self) -> Dict[str, Any]:
        """Возвращает статистику авторизации"""
        return {
            "total_roles": len(self.role_permissions),
            "total_policies": len(self.policies),
            "total_resources_with_acl": len(self.resource_acls),
            "roles": list(self.role_permissions.keys())
        }
