import asyncio
from typing import List, Optional
from enum import Enum
from functools import lru_cache

from fastapi import HTTPException, status
from hr_ai.db.models import User, PolicyRule
from hr_ai.db.session import get_session
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


class Permission(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    ADMIN = "admin"


class Resource(str, Enum):
    USERS = "users"
    JOBS = "jobs"
    DASHBOARD = "dashboard"
    PIPELINE = "pipeline"
    ANALYTICS = "analytics"
    SECURITY = "security"
    AUDIT = "audit"
    AI_MODELS = "ai_models"


class RBACException(HTTPException):
    def __init__(self, detail: str = "Permission denied"):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


class RBACChecker:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def has_permission(
        self,
        user_id: str,
        resource: Resource,
        permission: Permission,
        tenant_id: Optional[str] = None
    ) -> bool:
        stmt = select(User).where(User.id == user_id)
        result = await self.session.execute(stmt)
        user: User = result.scalar_one_or_none()

        if not user:
            raise RBACException("User not found")

        if tenant_id and user.tenant_id != tenant_id:
            raise RBACException("Cross-tenant access denied")

        rules = await self._get_rules(user.role, tenant_id)
        for rule in rules:
            if rule.resource == resource and permission in rule.permissions:
                return True

        raise RBACException()

    @staticmethod
    @lru_cache(maxsize=2048)
    async def _get_rules_cached(role: str, tenant_id: str) -> List[PolicyRule]:
        async with get_session() as session:
            stmt = select(PolicyRule).where(
                PolicyRule.role == role,
                PolicyRule.tenant_id == tenant_id,
                PolicyRule.enabled == True
            )
            result = await session.execute(stmt)
            return result.scalars().all()

    async def _get_rules(self, role: str, tenant_id: str) -> List[PolicyRule]:
        # Async cache workaround for lru_cache
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: asyncio.run(self._get_rules_cached(role, tenant_id)))


async def check_access(
    user_id: str,
    resource: Resource,
    permission: Permission,
    tenant_id: Optional[str] = None,
    session: Optional[AsyncSession] = None
):
    internal_session = session or await get_session().__aenter__()
    checker = RBACChecker(internal_session)
    try:
        return await checker.has_permission(user_id, resource, permission, tenant_id)
    finally:
        if session is None:
            await internal_session.close()
