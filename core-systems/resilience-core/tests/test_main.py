"""
Тесты для resilience-core
"""

import pytest
import asyncio
from resilience_core.main import ResilienceCoreCore

class TestResilienceCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = ResilienceCoreCore()
        assert core.config.system_name == "resilience-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = ResilienceCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = ResilienceCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "resilience-core"
        assert "version" in status
        assert "is_running" in status
