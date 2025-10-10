"""
Тесты для sageai-core
"""

import pytest
import asyncio
from sageai_core.main import SageaiCoreCore

class TestSageaiCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = SageaiCoreCore()
        assert core.config.system_name == "sageai-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = SageaiCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = SageaiCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "sageai-core"
        assert "version" in status
        assert "is_running" in status
