"""
Тесты для omnimind-core
"""

import pytest
import asyncio
from omnimind_core.main import OmnimindCoreCore

class TestOmnimindCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = OmnimindCoreCore()
        assert core.config.system_name == "omnimind-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = OmnimindCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = OmnimindCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "omnimind-core"
        assert "version" in status
        assert "is_running" in status
