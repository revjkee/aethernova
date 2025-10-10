"""
Тесты для platform_ops-core
"""

import pytest
import asyncio
from platform_ops_core.main import PlatformOpsCoreCore

class TestPlatformOpsCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = PlatformOpsCoreCore()
        assert core.config.system_name == "platform_ops-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = PlatformOpsCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = PlatformOpsCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "platform_ops-core"
        assert "version" in status
        assert "is_running" in status
