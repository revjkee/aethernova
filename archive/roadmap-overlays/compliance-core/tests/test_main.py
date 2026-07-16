"""
Тесты для compliance-core
"""

import pytest
import asyncio
from compliance_core.main import ComplianceCoreCore

class TestComplianceCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = ComplianceCoreCore()
        assert core.config.system_name == "compliance-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = ComplianceCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = ComplianceCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "compliance-core"
        assert "version" in status
        assert "is_running" in status
