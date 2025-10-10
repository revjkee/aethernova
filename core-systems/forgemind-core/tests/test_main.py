"""
Тесты для forgemind-core
"""

import pytest
import asyncio
from forgemind_core.main import ForgemindCoreCore

class TestForgemindCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = ForgemindCoreCore()
        assert core.config.system_name == "forgemind-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = ForgemindCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = ForgemindCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "forgemind-core"
        assert "version" in status
        assert "is_running" in status
