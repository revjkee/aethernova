"""
Тесты для quantumpulse-core
"""

import pytest
import asyncio
from quantumpulse_core.main import QuantumpulseCoreCore

class TestQuantumpulseCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = QuantumpulseCoreCore()
        assert core.config.system_name == "quantumpulse-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = QuantumpulseCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = QuantumpulseCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "quantumpulse-core"
        assert "version" in status
        assert "is_running" in status
