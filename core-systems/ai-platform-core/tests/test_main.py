"""
Тесты для ai-platform-core
"""

import pytest
import asyncio
from ai_platform_core.main import AiPlatformCoreCore

class TestAiPlatformCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = AiPlatformCoreCore()
        assert core.config.system_name == "ai-platform-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = AiPlatformCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = AiPlatformCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "ai-platform-core"
        assert "version" in status
        assert "is_running" in status
