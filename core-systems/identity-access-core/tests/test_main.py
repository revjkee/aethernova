"""
Тесты для identity-access-core
"""

import pytest
import asyncio
from identity_access_core.main import IdentityAccessCoreCore

class TestIdentityAccessCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = IdentityAccessCoreCore()
        assert core.config.system_name == "identity-access-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = IdentityAccessCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = IdentityAccessCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "identity-access-core"
        assert "version" in status
        assert "is_running" in status
