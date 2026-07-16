"""
Тесты для ledger-core
"""

import pytest
import asyncio
from ledger_core.main import LedgerCoreCore

class TestLedgerCoreCore:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = LedgerCoreCore()
        assert core.config.system_name == "ledger-core"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = LedgerCoreCore()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = LedgerCoreCore()
        status = core.get_status()
        
        assert status["system_name"] == "ledger-core"
        assert "version" in status
        assert "is_running" in status
