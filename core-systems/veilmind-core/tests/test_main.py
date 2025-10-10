"""
Тесты для veilmind-core
"""

import pytest
import asyncio
from veilmind_core.main import VeilmindCoreCore

class TestVeilmindCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = VeilmindCoreCore()
        assert core.config.system_name == "veilmind-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = VeilmindCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = VeilmindCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "veilmind-core"
        assert "version" in status
        assert "is_running" in status
