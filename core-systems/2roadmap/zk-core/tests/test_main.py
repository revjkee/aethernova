"""
Тесты для zk-core
"""

import pytest
import asyncio
from zk_core.main import ZkCoreCore

class TestZkCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = ZkCoreCore()
        assert core.config.system_name == "zk-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = ZkCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = ZkCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "zk-core"
        assert "version" in status
        assert "is_running" in status
