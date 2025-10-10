"""
Тесты для evolution-core
"""

import pytest
import asyncio
from evolution_core.main import EvolutionCoreCore

class TestEvolutionCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = EvolutionCoreCore()
        assert core.config.system_name == "evolution-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = EvolutionCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = EvolutionCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "evolution-core"
        assert "version" in status
        assert "is_running" in status
