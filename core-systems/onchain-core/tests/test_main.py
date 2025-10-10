"""
Тесты для onchain-core
"""

import pytest
import asyncio
from onchain_core.main import OnchainCoreCore

class TestOnchainCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = OnchainCoreCore()
        assert core.config.system_name == "onchain-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = OnchainCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = OnchainCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "onchain-core"
        assert "version" in status
        assert "is_running" in status
