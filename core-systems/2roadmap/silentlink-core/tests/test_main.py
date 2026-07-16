"""
Тесты для silentlink-core
"""

import pytest
import asyncio
from silentlink_core.main import SilentlinkCoreCore

class TestSilentlinkCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = SilentlinkCoreCore()
        assert core.config.system_name == "silentlink-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = SilentlinkCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = SilentlinkCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "silentlink-core"
        assert "version" in status
        assert "is_running" in status
