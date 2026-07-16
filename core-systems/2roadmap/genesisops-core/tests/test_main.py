"""
Тесты для genesisops-core
"""

import pytest
import asyncio
from genesisops_core.main import GenesisopsCoreCore

class TestGenesisopsCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = GenesisopsCoreCore()
        assert core.config.system_name == "genesisops-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = GenesisopsCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = GenesisopsCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "genesisops-core"
        assert "version" in status
        assert "is_running" in status
