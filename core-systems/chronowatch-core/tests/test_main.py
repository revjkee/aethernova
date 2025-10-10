"""
Тесты для chronowatch-core
"""

import pytest
import asyncio
from chronowatch_core.main import ChronowatchCoreCore

class TestChronowatchCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = ChronowatchCoreCore()
        assert core.config.system_name == "chronowatch-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = ChronowatchCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = ChronowatchCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "chronowatch-core"
        assert "version" in status
        assert "is_running" in status
