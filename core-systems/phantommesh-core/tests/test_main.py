"""
Тесты для phantommesh-core
"""

import pytest
import asyncio
from phantommesh_core.main import PhantommeshCoreCore

class TestPhantommeshCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = PhantommeshCoreCore()
        assert core.config.system_name == "phantommesh-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = PhantommeshCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = PhantommeshCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "phantommesh-core"
        assert "version" in status
        assert "is_running" in status
