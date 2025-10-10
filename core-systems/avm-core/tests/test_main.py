"""
Тесты для avm-core
"""

import pytest
import asyncio
from avm_core.main import AvmCoreCore

class TestAvmCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = AvmCoreCore()
        assert core.config.system_name == "avm-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = AvmCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = AvmCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "avm-core"
        assert "version" in status
        assert "is_running" in status
