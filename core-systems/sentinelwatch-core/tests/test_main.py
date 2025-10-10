"""
Тесты для sentinelwatch-core
"""

import pytest
import asyncio
from sentinelwatch_core.main import SentinelwatchCoreCore

class TestSentinelwatchCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = SentinelwatchCoreCore()
        assert core.config.system_name == "sentinelwatch-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = SentinelwatchCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = SentinelwatchCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "sentinelwatch-core"
        assert "version" in status
        assert "is_running" in status
