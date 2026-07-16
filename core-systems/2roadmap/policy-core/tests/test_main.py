"""
Тесты для policy-core
"""

import pytest
import asyncio
from policy_core.main import PolicyCoreCore

class TestPolicyCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = PolicyCoreCore()
        assert core.config.system_name == "policy-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = PolicyCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = PolicyCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "policy-core"
        assert "version" in status
        assert "is_running" in status
