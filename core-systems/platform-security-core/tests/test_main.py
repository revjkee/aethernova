"""
Тесты для platform-security-core
"""

import pytest
import asyncio
from platform_security_core.main import PlatformSecurityCoreCore

class TestPlatformSecurityCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = PlatformSecurityCoreCore()
        assert core.config.system_name == "platform-security-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = PlatformSecurityCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = PlatformSecurityCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "platform-security-core"
        assert "version" in status
        assert "is_running" in status
