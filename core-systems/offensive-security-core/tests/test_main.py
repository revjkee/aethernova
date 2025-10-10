"""
Тесты для offensive-security-core
"""

import pytest
import asyncio
from offensive_security_core.main import OffensiveSecurityCoreCore

class TestOffensiveSecurityCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = OffensiveSecurityCoreCore()
        assert core.config.system_name == "offensive-security-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = OffensiveSecurityCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = OffensiveSecurityCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "offensive-security-core"
        assert "version" in status
        assert "is_running" in status
