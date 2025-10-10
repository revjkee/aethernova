"""
Тесты для genius-core
"""

import pytest
import asyncio
from genius_core.main import GeniusCoreCore

class TestGeniusCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = GeniusCoreCore()
        assert core.config.system_name == "genius-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = GeniusCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = GeniusCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "genius-core"
        assert "version" in status
        assert "is_running" in status
