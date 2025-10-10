"""
Тесты для mythos-core
"""

import pytest
import asyncio
from mythos_core.main import MythosCoreCore

class TestMythosCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = MythosCoreCore()
        assert core.config.system_name == "mythos-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = MythosCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = MythosCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "mythos-core"
        assert "version" in status
        assert "is_running" in status
