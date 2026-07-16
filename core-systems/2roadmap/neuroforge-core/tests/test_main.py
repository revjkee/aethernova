"""
Тесты для neuroforge-core
"""

import pytest
import asyncio
from neuroforge_core.main import NeuroforgeCoreCore

class TestNeuroforgeCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = NeuroforgeCoreCore()
        assert core.config.system_name == "neuroforge-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = NeuroforgeCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = NeuroforgeCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "neuroforge-core"
        assert "version" in status
        assert "is_running" in status
