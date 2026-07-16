"""
Тесты для aethernova-chain-core
"""

import pytest
import asyncio
from aethernova_chain_core.main import AethernovaChainCoreCore

class TestAethernovaChainCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = AethernovaChainCoreCore()
        assert core.config.system_name == "aethernova-chain-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = AethernovaChainCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = AethernovaChainCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "aethernova-chain-core"
        assert "version" in status
        assert "is_running" in status
