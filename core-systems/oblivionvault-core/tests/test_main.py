"""
Тесты для oblivionvault-core
"""

import pytest
import asyncio
from oblivionvault_core.main import OblivionvaultCoreCore

class TestOblivionvaultCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = OblivionvaultCoreCore()
        assert core.config.system_name == "oblivionvault-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = OblivionvaultCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = OblivionvaultCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "oblivionvault-core"
        assert "version" in status
        assert "is_running" in status
