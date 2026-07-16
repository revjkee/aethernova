"""
Тесты для security-core
"""

import pytest
import asyncio
from security_core.main import SecurityCoreCore

class TestSecurityCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = SecurityCoreCore()
        assert core.config.system_name == "security-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = SecurityCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = SecurityCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "security-core"
        assert "version" in status
        assert "is_running" in status
