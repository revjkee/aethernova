"""
Основная блокчейн инфраструктура и децентрализованные операции
ВОССТАНОВЛЕНО для aethernova-chain-core
Критическая система категории: Blockchain Foundation
"""

import asyncio
import json
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
from loguru import logger

from config import config
from src.block import Block, Transaction
from src.chain import Blockchain
from src.consensus import ConsensusEngine, ConsensusType
from src.smart_contracts import ContractManager


class AethernovaChainCore:
    """
    КРИТИЧЕСКАЯ СИСТЕМА: Основная блокчейн инфраструктура
    
    Категория: Blockchain Foundation
    Критические функции: Blockchain consensus, Transaction processing, Smart contract execution
    """
    
    def __init__(self):
        self.config = config
        self.is_running = False
        self.emergency_mode = True
        self.components: Dict[str, Any] = {}
        self.metrics: Dict[str, Any] = {}
        
        # Критические компоненты Blockchain
        self.blockchain: Optional[Blockchain] = None
        self.consensus_engine: Optional[ConsensusEngine] = None
        self.contract_manager: Optional[ContractManager] = None
        
        # Логирование
        logger.add(
            f"logs/aethernova-chain-core.emergency.log",
            format="{time:YYYY-MM-DD HH:mm:ss} | EMERGENCY | {level} | {message}",
            level="INFO",
            rotation="1 day",
            retention="30 days"
        )
        
        logger.critical(f"🚨 ВОССТАНОВЛЕНИЕ AETHERNOVA-CHAIN-CORE АКТИВИРОВАНО")
        
    async def _initialize_critical_components(self) -> None:
        """Инициализирует критические компоненты блокчейна"""
        try:
            # Инициализация блокчейна
            chain_file = "data/blockchain.json"
            self.blockchain = await Blockchain.load_from_file(chain_file)
            if not self.blockchain:
                self.blockchain = Blockchain(difficulty=4)
            
            # Инициализация consensus engine
            self.consensus_engine = ConsensusEngine(
                consensus_type=ConsensusType.PROOF_OF_WORK,
                min_validators=3
            )
            
            # Добавляем несколько валидаторов для тестирования
            self.consensus_engine.add_validator("miner_001", 1000.0)
            self.consensus_engine.add_validator("miner_002", 1500.0)
            self.consensus_engine.add_validator("miner_003", 2000.0)
            
            # Инициализация contract manager
            self.contract_manager = ContractManager()
            
            # Регистрация компонентов
            self.components["blockchain"] = self.blockchain
            self.components["consensus"] = self.consensus_engine
            self.components["contracts"] = self.contract_manager
            
            logger.critical("⛓️ Blockchain критические компоненты инициализированы")
            
        except Exception as e:
            logger.error(f"❌ Ошибка инициализации компонентов: {e}")
            raise
    
    async def emergency_initialize(self) -> bool:
        """ЭКСТРЕННАЯ инициализация системы"""
        try:
            logger.critical(f"🚨 ЭКСТРЕННАЯ ИНИЦИАЛИЗАЦИЯ {self.config.system_name} начата")
            
            # Инициализация критических компонентов
            await self._initialize_critical_components()
            
            # Настройка мониторинга
            await self._emergency_monitoring_setup()
            
            logger.critical(f"✅ ЭКСТРЕННАЯ ИНИЦИАЛИЗАЦИЯ {self.config.system_name} ЗАВЕРШЕНА")
            return True
            
        except Exception as e:
            logger.critical(f"💀 КРИТИЧЕСКАЯ ОШИБКА ЭКСТРЕННОЙ ИНИЦИАЛИЗАЦИИ: {e}")
            return False
    
    async def emergency_start(self) -> None:
        """ЭКСТРЕННЫЙ запуск системы"""
        if not await self.emergency_initialize():
            raise RuntimeError("💀 ЭКСТРЕННАЯ ИНИЦИАЛИЗАЦИЯ ПРОВАЛЕНА")
        
        self.is_running = True
        self.emergency_mode = True
        
        logger.critical(f"🚨 {self.config.system_name} ЗАПУЩЕНА В ЭКСТРЕННОМ РЕЖИМЕ")
        
        try:
            while self.is_running:
                await self._emergency_processing_loop()
                await asyncio.sleep(1.0)  # Обработка каждую секунду
                
        except KeyboardInterrupt:
            logger.critical("⚠️ ПОЛУЧЕН СИГНАЛ ЭКСТРЕННОЙ ОСТАНОВКИ")
        finally:
            await self.emergency_stop()
    
    async def emergency_stop(self) -> None:
        """ЭКСТРЕННАЯ остановка системы"""
        logger.critical("🛑 ЭКСТРЕННАЯ ОСТАНОВКА СИСТЕМЫ...")
        self.is_running = False
        
        # Сохранение цепи
        if self.blockchain:
            await self.blockchain.save_to_file("data/blockchain.json")
        
        logger.critical(f"🔒 {self.config.system_name} ЭКСТРЕННО ОСТАНОВЛЕНА")
    
    async def _emergency_monitoring_setup(self) -> None:
        """Настройка экстренного мониторинга"""
        self.metrics = {
            "start_time": datetime.now().isoformat(),
            "emergency_mode": True,
            "processed_blocks": 0,
            "processed_transactions": 0,
            "error_count": 0,
            "last_health_check": datetime.now().isoformat(),
            "uptime_seconds": 0
        }
        
        logger.critical("📊 Экстренный мониторинг активирован")
    
    async def _emergency_processing_loop(self) -> None:
        """Основной цикл экстренной обработки"""
        # Blockchain обработка
        await self._process_pending_transactions()
        await self._mine_new_block()
        
        # Обновление метрик
        self.metrics["last_health_check"] = datetime.now().isoformat()
        start_time = datetime.fromisoformat(self.metrics["start_time"])
        self.metrics["uptime_seconds"] = (datetime.now() - start_time).total_seconds()
    
    async def _process_pending_transactions(self) -> None:
        """Обработка ожидающих транзакций"""
        # Заглушка для будущей реализации очереди транзакций
        pass
    
    async def _mine_new_block(self) -> None:
        """Майнинг нового блока если есть транзакции"""
        if self.blockchain and len(self.blockchain.pending_transactions) > 0:
            block = await self.blockchain.mine_pending_transactions("miner_001")
            if block:
                self.metrics["processed_blocks"] += 1
                self.metrics["processed_transactions"] += len(block.transactions)
    
    def get_status(self) -> Dict[str, Any]:
        """Получение статуса системы"""
        status = {
            "system_name": self.config.system_name,
            "version": self.config.version,
            "category": "Blockchain Foundation",
            "emergency_mode": self.emergency_mode,
            "is_running": self.is_running,
            "components": list(self.components.keys()),
            "metrics": self.metrics,
            "uptime": self.metrics.get("uptime_seconds", 0)
        }
        
        if self.blockchain:
            status["blockchain"] = self.blockchain.get_chain_stats()
        
        if self.consensus_engine:
            status["consensus"] = self.consensus_engine.get_stats()
        
        if self.contract_manager:
            status["contracts"] = self.contract_manager.get_stats()
        
        return status
    
    async def emergency_health_check(self) -> Dict[str, Any]:
        """ЭКСТРЕННАЯ проверка работоспособности"""
        checks = {
            "system_running": self.is_running,
            "emergency_mode_active": self.emergency_mode,
            "components_initialized": len(self.components) > 0,
            "blockchain_initialized": self.blockchain is not None,
            "consensus_initialized": self.consensus_engine is not None,
            "contracts_initialized": self.contract_manager is not None,
        }
        
        # Проверка валидности цепи
        if self.blockchain:
            checks["chain_valid"] = self.blockchain.is_chain_valid()
        
        # Определяем общий статус
        if all(checks.values()):
            status = "emergency_operational" if self.emergency_mode else "healthy"
        else:
            status = "critical_failure"
        
        return {
            "status": status,
            "emergency_mode": self.emergency_mode,
            "timestamp": datetime.now().isoformat(),
            "checks": checks,
            "metrics": self.metrics,
            "uptime_seconds": self.metrics.get("uptime_seconds", 0)
        }
    
    # Public API методы для работы с блокчейном
    
    async def add_transaction(self, sender: str, receiver: str, amount: float, data: Dict[str, Any] = None) -> bool:
        """Добавляет транзакцию в блокчейн"""
        if not self.blockchain:
            return False
        
        tx = Transaction(
            sender=sender,
            receiver=receiver,
            amount=amount,
            timestamp=datetime.now().timestamp(),
            data=data
        )
        
        return self.blockchain.add_transaction(tx)
    
    async def mine_block(self, miner_address: str) -> Optional[Block]:
        """Майнит блок"""
        if not self.blockchain:
            return None
        
        return await self.blockchain.mine_pending_transactions(miner_address)
    
    async def deploy_contract(self, contract_id: str, owner: str, code: str) -> bool:
        """Деплоит смарт-контракт"""
        if not self.contract_manager:
            return False
        
        try:
            await self.contract_manager.deploy_contract(contract_id, owner, code)
            return True
        except Exception as e:
            logger.error(f"❌ Ошибка деплоя контракта: {e}")
            return False
    
    async def call_contract(
        self,
        contract_id: str,
        function_name: str,
        args: Dict[str, Any],
        caller: str
    ) -> Dict[str, Any]:
        """Вызывает функцию смарт-контракта"""
        if not self.contract_manager:
            return {"success": False, "error": "Contract manager not initialized"}
        
        return await self.contract_manager.call_contract(
            contract_id,
            function_name,
            args,
            caller
        )
    
    def get_balance(self, address: str) -> float:
        """Получает баланс адреса"""
        if not self.blockchain:
            return 0.0
        
        return self.blockchain.get_balance(address)
    
    def get_transaction_history(self, address: str) -> List[Transaction]:
        """Получает историю транзакций"""
        if not self.blockchain:
            return []
        
        return self.blockchain.get_transaction_history(address)


# API для экстренного создания экземпляра
async def create_emergency_chain_instance() -> AethernovaChainCore:
    """Создает экземпляр системы в экстренном режиме"""
    instance = AethernovaChainCore()
    await instance.emergency_initialize()
    return instance


# Экстренный запуск
async def emergency_main():
    """Экстренный запуск системы"""
    logger.critical("🚨 АКТИВАЦИЯ ЭКСТРЕННОГО РЕЖИМА AETHERNOVA-CHAIN-CORE")
    core = AethernovaChainCore()
    await core.emergency_start()


# Для прямого запуска
async def main():
    await emergency_main()


if __name__ == "__main__":
    asyncio.run(main())
