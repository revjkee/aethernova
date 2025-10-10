"""
Тесты для blackvault-core
"""

import pytest
import asyncio
from blackvault_core.main import BlackvaultCoreCore

class TestBlackvaultCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = BlackvaultCoreCore()
        assert core.config.system_name == "blackvault-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = BlackvaultCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = BlackvaultCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "blackvault-core"
        assert "version" in status
        assert "is_running" in status
