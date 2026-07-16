"""
Тесты для cybersecurity-core
"""

import pytest
import asyncio
from cybersecurity_core.main import CybersecurityCoreCore

class TestCybersecurityCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = CybersecurityCoreCore()
        assert core.config.system_name == "cybersecurity-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = CybersecurityCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = CybersecurityCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "cybersecurity-core"
        assert "version" in status
        assert "is_running" in status
