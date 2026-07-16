"""
Тесты для zero-trust-core
"""

import pytest
import asyncio
from zero_trust_core.main import ZeroTrustCoreCore

class TestZeroTrustCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = ZeroTrustCoreCore()
        assert core.config.system_name == "zero-trust-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = ZeroTrustCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = ZeroTrustCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "zero-trust-core"
        assert "version" in status
        assert "is_running" in status
