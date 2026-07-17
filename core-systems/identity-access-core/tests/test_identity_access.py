"""
Tests for Identity Access Core
Тесты критической системы аутентификации и авторизации
"""

import pytest
import asyncio
from datetime import datetime, timedelta

# Предполагаем, что система установлена и доступна для импорта
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.authentication import AuthenticationService
from src.authorization import AuthorizationEngine, Permission
from src.session_manager import SessionManager
from config import IdentityAccessCoreEmergencyConfig, config


TEST_EMERGENCY_ADMIN_PASSWORD = "identity-test-emergency-password"


@pytest.fixture
def emergency_config():
    """Explicit test-only opt-in for the legacy break-glass account."""
    return IdentityAccessCoreEmergencyConfig(
        _env_file=None,
        emergency_admin_enabled=True,
        emergency_admin_password=TEST_EMERGENCY_ADMIN_PASSWORD,
        emergency_mfa_disabled=True,
    )


@pytest.fixture
def auth_service(emergency_config):
    """Фикстура для сервиса аутентификации"""
    return AuthenticationService(emergency_config)


@pytest.fixture
def authz_engine():
    """Фикстура для движка авторизации"""
    return AuthorizationEngine(config)


@pytest.fixture
def session_mgr():
    """Фикстура для менеджера сессий"""
    return SessionManager(config)


class TestAuthenticationService:
    """Тесты сервиса аутентификации"""
    
    @pytest.mark.asyncio
    async def test_emergency_admin_exists(self, auth_service):
        """Проверка наличия экстренного администратора"""
        user = auth_service.get_user("emergency_admin")
        assert user is not None
        assert "admin" in user['roles']
        assert "emergency" in user['roles']
    
    @pytest.mark.asyncio
    async def test_emergency_admin_authentication(self, auth_service):
        """Тест аутентификации экстренного админа"""
        user = await auth_service.authenticate(
            "emergency_admin",
            auth_service.config.emergency_admin_password
        )
        assert user is not None
        assert user['username'] == "emergency_admin"
    
    @pytest.mark.asyncio
    async def test_create_user(self, auth_service):
        """Тест создания пользователя"""
        user = await auth_service.create_user(
            username="test_user",
            password="test_password_123",
            email="test@example.com",
            roles=["user"],
            permissions=["read", "write"]
        )
        
        assert user['username'] == "test_user"
        assert user['email'] == "test@example.com"
        assert "user" in user['roles']
    
    @pytest.mark.asyncio
    async def test_invalid_authentication(self, auth_service):
        """Тест неудачной аутентификации"""
        user = await auth_service.authenticate("invalid_user", "wrong_password")
        assert user is None
    
    @pytest.mark.asyncio
    async def test_token_generation(self, auth_service):
        """Тест генерации JWT токена"""
        user = await auth_service.authenticate(
            "emergency_admin",
            auth_service.config.emergency_admin_password
        )
        
        token = await auth_service.generate_token(user, expires_in=3600)
        assert token is not None
        assert isinstance(token, str)
    
    @pytest.mark.asyncio
    async def test_token_verification(self, auth_service):
        """Тест проверки JWT токена"""
        user = await auth_service.authenticate(
            "emergency_admin",
            auth_service.config.emergency_admin_password
        )
        
        token = await auth_service.generate_token(user, expires_in=3600)
        payload = await auth_service.verify_token(token)
        
        assert payload is not None
        assert payload['username'] == "emergency_admin"
    
    @pytest.mark.asyncio
    async def test_account_lockout(self, auth_service):
        """Тест блокировки аккаунта после неудачных попыток"""
        # Создаем тестового пользователя
        await auth_service.create_user(
            username="lockout_test",
            password="correct_password",
            email="lockout@test.com"
        )
        
        # Делаем несколько неудачных попыток входа
        for _ in range(6):
            await auth_service.authenticate("lockout_test", "wrong_password")
        
        # Пытаемся войти с правильным паролем - должно быть заблокировано
        user = await auth_service.authenticate("lockout_test", "correct_password")
        assert user is None


class TestAuthorizationEngine:
    """Тесты движка авторизации"""
    
    @pytest.mark.asyncio
    async def test_superuser_has_all_permissions(self, authz_engine):
        """Тест универсального доступа для superuser"""
        user = {
            "user_id": "test_superuser",
            "username": "test_superuser",
            "roles": ["superuser"],
            "permissions": []
        }
        
        has_permission = await authz_engine.check_permission(
            user, "any_resource", "any_permission"
        )
        assert has_permission is True
    
    @pytest.mark.asyncio
    async def test_admin_permissions(self, authz_engine):
        """Тест разрешений администратора"""
        user = {
            "user_id": "test_admin",
            "username": "test_admin",
            "roles": ["admin"],
            "permissions": []
        }
        
        has_read = await authz_engine.check_permission(user, "resource", Permission.READ)
        has_write = await authz_engine.check_permission(user, "resource", Permission.WRITE)
        has_admin = await authz_engine.check_permission(user, "resource", Permission.ADMIN)
        
        assert has_read is True
        assert has_write is True
        assert has_admin is True
    
    @pytest.mark.asyncio
    async def test_readonly_permissions(self, authz_engine):
        """Тест разрешений readonly роли"""
        user = {
            "user_id": "test_readonly",
            "username": "test_readonly",
            "roles": ["readonly"],
            "permissions": []
        }
        
        has_read = await authz_engine.check_permission(user, "resource", Permission.READ)
        has_write = await authz_engine.check_permission(user, "resource", Permission.WRITE)
        
        assert has_read is True
        assert has_write is False
    
    @pytest.mark.asyncio
    async def test_create_role(self, authz_engine):
        """Тест создания новой роли"""
        result = await authz_engine.create_role(
            "test_role",
            [Permission.READ, Permission.EXECUTE]
        )
        assert result is True
        
        permissions = authz_engine.get_role_permissions("test_role")
        assert Permission.READ in permissions
        assert Permission.EXECUTE in permissions
    
    @pytest.mark.asyncio
    async def test_grant_permission(self, authz_engine):
        """Тест предоставления разрешения на ресурс"""
        result = await authz_engine.grant_permission(
            "test_user",
            "test_resource",
            Permission.WRITE
        )
        assert result is True
        
        user = {
            "user_id": "test_user",
            "username": "test_user",
            "roles": [],
            "permissions": []
        }
        
        has_permission = await authz_engine.check_permission(
            user, "test_resource", Permission.WRITE
        )
        assert has_permission is True


class TestSessionManager:
    """Тесты менеджера сессий"""
    
    @pytest.mark.asyncio
    async def test_create_session(self, session_mgr):
        """Тест создания сессии"""
        user = {
            "user_id": "test_user",
            "username": "test_user",
            "roles": ["user"],
            "permissions": ["read"]
        }
        
        session = await session_mgr.create_session(
            user,
            ip_address="192.168.1.1",
            user_agent="TestAgent/1.0"
        )
        
        assert session is not None
        assert "session_id" in session
        assert "expires_at" in session
    
    @pytest.mark.asyncio
    async def test_validate_session(self, session_mgr):
        """Тест валидации сессии"""
        user = {
            "user_id": "test_user",
            "username": "test_user",
            "roles": ["user"],
            "permissions": ["read"]
        }
        
        session = await session_mgr.create_session(user)
        session_id = session['session_id']
        
        is_valid = await session_mgr.validate_session(session_id)
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_destroy_session(self, session_mgr):
        """Тест уничтожения сессии"""
        user = {
            "user_id": "test_user",
            "username": "test_user",
            "roles": ["user"],
            "permissions": ["read"]
        }
        
        session = await session_mgr.create_session(user)
        session_id = session['session_id']
        
        result = await session_mgr.destroy_session(session_id)
        assert result is True
        
        is_valid = await session_mgr.validate_session(session_id)
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_session_expiration(self, session_mgr):
        """Тест истечения срока сессии"""
        # Временно изменяем таймаут сессии
        original_timeout = session_mgr.session_timeout
        session_mgr.session_timeout = timedelta(seconds=1)
        
        user = {
            "user_id": "test_user",
            "username": "test_user",
            "roles": ["user"],
            "permissions": ["read"]
        }
        
        session = await session_mgr.create_session(user)
        session_id = session['session_id']
        
        # Ждем истечения срока
        await asyncio.sleep(2)
        
        is_valid = await session_mgr.validate_session(session_id)
        assert is_valid is False
        
        # Восстанавливаем оригинальный таймаут
        session_mgr.session_timeout = original_timeout
    
    @pytest.mark.asyncio
    async def test_cleanup_expired_sessions(self, session_mgr):
        """Тест очистки истекших сессий"""
        # Создаем сессию с коротким таймаутом
        original_timeout = session_mgr.session_timeout
        session_mgr.session_timeout = timedelta(seconds=1)
        
        user = {
            "user_id": "test_user",
            "username": "test_user",
            "roles": ["user"],
            "permissions": ["read"]
        }
        
        await session_mgr.create_session(user)
        
        # Ждем истечения срока
        await asyncio.sleep(2)
        
        # Очищаем истекшие сессии
        cleaned_count = await session_mgr.cleanup_expired_sessions()
        assert cleaned_count > 0
        
        # Восстанавливаем оригинальный таймаут
        session_mgr.session_timeout = original_timeout


@pytest.mark.asyncio
async def test_integration_auth_session(auth_service, session_mgr):
    """Интеграционный тест: аутентификация и создание сессии"""
    # Аутентификация
    user = await auth_service.authenticate(
        "emergency_admin",
        auth_service.config.emergency_admin_password
    )
    assert user is not None
    
    # Создание сессии
    session = await session_mgr.create_session(user)
    assert session is not None
    
    # Проверка сессии
    is_valid = await session_mgr.validate_session(session['session_id'])
    assert is_valid is True


@pytest.mark.asyncio
async def test_integration_auth_authz(auth_service, authz_engine):
    """Интеграционный тест: аутентификация и авторизация"""
    # Аутентификация
    user = await auth_service.authenticate(
        "emergency_admin",
        auth_service.config.emergency_admin_password
    )
    assert user is not None
    
    # Проверка разрешений
    has_permission = await authz_engine.check_permission(
        user, "critical_resource", Permission.ADMIN
    )
    assert has_permission is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--asyncio-mode=auto"])
