"""
Тесты для physical-integration-core
"""

import pytest
import asyncio
from physical_integration_core.main import PhysicalIntegrationCoreCore

class TestPhysicalIntegrationCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = PhysicalIntegrationCoreCore()
        assert core.config.system_name == "physical-integration-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = PhysicalIntegrationCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = PhysicalIntegrationCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "physical-integration-core"
        assert "version" in status
        assert "is_running" in status
