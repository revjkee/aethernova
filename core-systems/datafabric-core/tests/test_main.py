"""
Тесты для datafabric-core
"""

import pytest
import asyncio
from datafabric_core.main import DatafabricCoreCore

class TestDatafabricCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = DatafabricCoreCore()
        assert core.config.system_name == "datafabric-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = DatafabricCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = DatafabricCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "datafabric-core"
        assert "version" in status
        assert "is_running" in status
