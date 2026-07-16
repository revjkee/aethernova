"""
Тесты для graph-core
"""

import pytest
import asyncio
from graph_core.main import GraphCoreCore

class TestGraphCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = GraphCoreCore()
        assert core.config.system_name == "graph-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = GraphCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = GraphCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "graph-core"
        assert "version" in status
        assert "is_running" in status
