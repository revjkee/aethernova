"""
Тесты для observability-core
"""

import pytest
import asyncio
from observability_core.main import ObservabilityCoreCore

class TestObservabilityCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = ObservabilityCoreCore()
        assert core.config.system_name == "observability-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = ObservabilityCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = ObservabilityCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "observability-core"
        assert "version" in status
        assert "is_running" in status
