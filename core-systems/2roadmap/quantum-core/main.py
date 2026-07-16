"""
Quantum-Resistant Cryptography Core - Main System
Post-quantum cryptographic primitives and blockchain integration
ВОССТАНОВЛЕНО для quantum-core
Критическая система категории: Quantum Cryptography
"""

import asyncio
import json
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
from loguru import logger

from config import config
from src.kyber_kem import KyberKEM
from src.sphincs_plus import SphincsPlus
from src.quantum_crypto import QuantumCrypto, QuantumKeypair


class QuantumResistantCryptoCore:
    """
    КРИТИЧЕСКАЯ СИСТЕМА: Quantum-Resistant Cryptography
    
    Категория: Quantum Cryptography
    Критические функции: Post-quantum encryption, Quantum-safe signatures, Blockchain integration
    """
    
    def __init__(self):
        self.config = config
        self.is_running = False
        self.emergency_mode = True
        self.components: Dict[str, Any] = {}
        self.metrics: Dict[str, Any] = {}
        
        # Криптографические компоненты
        self.quantum_crypto: Optional[QuantumCrypto] = None
        self.kyber_kem: Optional[KyberKEM] = None
        self.sphincs_plus: Optional[SphincsPlus] = None
        
        # Хранилище ключей
        self.keypairs: Dict[str, QuantumKeypair] = {}
        
        # Логирование
        logger.add(
            f"logs/quantum-crypto.emergency.log",
            format="{time:YYYY-MM-DD HH:mm:ss} | EMERGENCY | {level} | {message}",
            level="INFO",
            rotation="1 day",
            retention="30 days"
        )
        
        logger.critical(f"🚨 ВОССТАНОВЛЕНИЕ QUANTUM-RESISTANT-CRYPTO-CORE АКТИВИРОВАНО")
    
    async def _initialize_critical_components(self) -> None:
        """Инициализирует критические криптографические компоненты"""
        try:
            # Инициализация Quantum Crypto (unified API)
            self.quantum_crypto = QuantumCrypto(
                security_level=128,  # SPHINCS+-128
                kyber_level=512      # Kyber-512
            )
            
            # Инициализация отдельных компонентов
            self.kyber_kem = KyberKEM(security_level=512)
            self.sphincs_plus = SphincsPlus(security_level=128, variant="simple")
            
            # Регистрация компонентов
            self.components["quantum_crypto"] = self.quantum_crypto
            self.components["kyber_kem"] = self.kyber_kem
            self.components["sphincs_plus"] = self.sphincs_plus
            
            logger.critical("⚛️ Quantum-resistant криптографические компоненты инициализированы")
            
        except Exception as e:
            logger.error(f"❌ Ошибка инициализации компонентов: {e}")
            raise

    async def emergency_initialize(self) -> bool:
        """ЭКСТРЕННАЯ инициализация системы"""
        try:
            logger.critical(f"🚨 ЭКСТРЕННАЯ ИНИЦИАЛИЗАЦИЯ {self.config.system_name} начата")
            
            # Инициализация компонентов
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
                await asyncio.sleep(1.0)
                
        except KeyboardInterrupt:
            logger.critical("⚠️ ПОЛУЧЕН СИГНАЛ ЭКСТРЕННОЙ ОСТАНОВКИ")
        finally:
            await self.emergency_stop()
    
    async def emergency_stop(self) -> None:
        """ЭКСТРЕННАЯ остановка системы"""
        logger.critical("🛑 ЭКСТРЕННАЯ ОСТАНОВКА СИСТЕМЫ...")
        self.is_running = False
        
        # Сохранение ключей
        await self._save_keypairs()
        
        logger.critical(f"🔒 {self.config.system_name} ЭКСТРЕННО ОСТАНОВЛЕНА")
    
    async def _emergency_monitoring_setup(self) -> None:
        """Настройка экстренного мониторинга"""
        self.metrics = {
            "start_time": datetime.now().isoformat(),
            "emergency_mode": True,
            "generated_keypairs": 0,
            "encryption_operations": 0,
            "decryption_operations": 0,
            "signing_operations": 0,
            "verification_operations": 0,
            "error_count": 0,
            "last_health_check": datetime.now().isoformat(),
            "uptime_seconds": 0
        }
        
        logger.critical("📊 Экстренный мониторинг активирован")
    
    async def _emergency_processing_loop(self) -> None:
        """Основной цикл экстренной обработки"""
        # Обновление метрик
        self.metrics["last_health_check"] = datetime.now().isoformat()
        start_time = datetime.fromisoformat(self.metrics["start_time"])
        self.metrics["uptime_seconds"] = (datetime.now() - start_time).total_seconds()
    
    # Public API
    
    async def generate_keypair(self, keypair_id: str) -> QuantumKeypair:
        """Генерирует quantum-resistant keypair"""
        if not self.quantum_crypto:
            raise RuntimeError("Quantum crypto not initialized")
        
        keypair = self.quantum_crypto.generate_keypair()
        self.keypairs[keypair_id] = keypair
        
        self.metrics["generated_keypairs"] += 1
        
        logger.info(f"Generated keypair: {keypair_id}")
        
        return keypair
    
    async def encrypt_data(self, data: bytes, recipient_public_key: bytes) -> Dict[str, Any]:
        """Шифрует данные quantum-resistant алгоритмом"""
        if not self.quantum_crypto:
            raise RuntimeError("Quantum crypto not initialized")
        
        encrypted = self.quantum_crypto.encrypt(data, recipient_public_key)
        
        self.metrics["encryption_operations"] += 1
        
        logger.info(f"Encrypted data ({len(data)} bytes)")
        
        return encrypted
    
    async def decrypt_data(self, encrypted_data: Dict[str, bytes], secret_key: bytes) -> bytes:
        """Расшифровывает данные"""
        if not self.quantum_crypto:
            raise RuntimeError("Quantum crypto not initialized")
        
        decrypted = self.quantum_crypto.decrypt(encrypted_data, secret_key)
        
        self.metrics["decryption_operations"] += 1
        
        logger.info(f"Decrypted data ({len(decrypted)} bytes)")
        
        return decrypted
    
    async def sign_message(self, message: bytes, secret_key: bytes) -> bytes:
        """Подписывает сообщение quantum-resistant подписью"""
        if not self.quantum_crypto:
            raise RuntimeError("Quantum crypto not initialized")
        
        signature = self.quantum_crypto.sign(message, secret_key)
        
        self.metrics["signing_operations"] += 1
        
        logger.info(f"Signed message ({len(message)} bytes)")
        
        return signature.signature
    
    async def verify_signature(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Верифицирует quantum-resistant подпись"""
        if not self.quantum_crypto:
            raise RuntimeError("Quantum crypto not initialized")
        
        valid = self.quantum_crypto.verify(message, signature, public_key)
        
        self.metrics["verification_operations"] += 1
        
        logger.info(f"Verified signature: {valid}")
        
        return valid
    
    # Blockchain Integration
    
    async def sign_transaction(self, transaction_data: Dict[str, Any], keypair_id: str) -> Dict[str, Any]:
        """Подписывает blockchain транзакцию"""
        if keypair_id not in self.keypairs:
            raise ValueError(f"Keypair {keypair_id} not found")
        
        keypair = self.keypairs[keypair_id]
        
        signed_tx = self.quantum_crypto.sign_transaction(
            transaction_data,
            keypair.sig_secret_key
        )
        
        logger.info(f"Signed transaction with keypair: {keypair_id}")
        
        return signed_tx
    
    async def verify_transaction(self, transaction_data: Dict[str, Any], public_key: bytes) -> bool:
        """Верифицирует quantum-resistant подпись транзакции"""
        valid = self.quantum_crypto.verify_transaction(transaction_data, public_key)
        
        logger.info(f"Verified transaction: {valid}")
        
        return valid
    
    async def encrypt_smart_contract(self, contract_code: str, recipient_public_key: bytes) -> Dict[str, Any]:
        """Шифрует смарт-контракт"""
        encrypted = self.quantum_crypto.encrypt_smart_contract(
            contract_code,
            recipient_public_key
        )
        
        logger.info(f"Encrypted smart contract")
        
        return encrypted
    
    async def decrypt_smart_contract(self, encrypted_contract: Dict[str, Any], keypair_id: str) -> str:
        """Расшифровывает смарт-контракт"""
        if keypair_id not in self.keypairs:
            raise ValueError(f"Keypair {keypair_id} not found")
        
        keypair = self.keypairs[keypair_id]
        
        contract_code = self.quantum_crypto.decrypt_smart_contract(
            encrypted_contract,
            keypair.kem_secret_key
        )
        
        logger.info(f"Decrypted smart contract")
        
        return contract_code
    
    # Key Management
    
    async def _save_keypairs(self) -> None:
        """Сохраняет keypairs в файл"""
        try:
            Path("data").mkdir(exist_ok=True)
            
            keypairs_data = {}
            for keypair_id, keypair in self.keypairs.items():
                keypairs_data[keypair_id] = {
                    "kem_public_key": keypair.kem_public_key.hex(),
                    "kem_secret_key": keypair.kem_secret_key.hex(),
                    "sig_public_key": keypair.sig_public_key.hex(),
                    "sig_secret_key": keypair.sig_secret_key.hex(),
                    "security_level": keypair.security_level,
                    "algorithm": keypair.algorithm
                }
            
            with open("data/quantum_keypairs.json", "w") as f:
                json.dump(keypairs_data, f, indent=2)
            
            logger.info(f"Saved {len(self.keypairs)} keypairs")
            
        except Exception as e:
            logger.error(f"Failed to save keypairs: {e}")
    
    async def load_keypairs(self) -> None:
        """Загружает keypairs из файла"""
        try:
            with open("data/quantum_keypairs.json", "r") as f:
                keypairs_data = json.load(f)
            
            for keypair_id, data in keypairs_data.items():
                keypair = QuantumKeypair(
                    kem_public_key=bytes.fromhex(data["kem_public_key"]),
                    kem_secret_key=bytes.fromhex(data["kem_secret_key"]),
                    sig_public_key=bytes.fromhex(data["sig_public_key"]),
                    sig_secret_key=bytes.fromhex(data["sig_secret_key"]),
                    security_level=data["security_level"],
                    algorithm=data["algorithm"]
                )
                self.keypairs[keypair_id] = keypair
            
            logger.info(f"Loaded {len(self.keypairs)} keypairs")
            
        except FileNotFoundError:
            logger.info("No existing keypairs file")
        except Exception as e:
            logger.error(f"Failed to load keypairs: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Получение статуса системы"""
        status = {
            "system_name": self.config.system_name,
            "version": self.config.version,
            "category": "Quantum Cryptography",
            "emergency_mode": self.emergency_mode,
            "is_running": self.is_running,
            "components": list(self.components.keys()),
            "metrics": self.metrics,
            "uptime": self.metrics.get("uptime_seconds", 0),
            "keypairs_count": len(self.keypairs)
        }
        
        return status
    
    async def emergency_health_check(self) -> Dict[str, Any]:
        """ЭКСТРЕННАЯ проверка работоспособности"""
        checks = {
            "system_running": self.is_running,
            "emergency_mode_active": self.emergency_mode,
            "components_initialized": len(self.components) > 0,
            "quantum_crypto_initialized": self.quantum_crypto is not None,
            "kyber_kem_initialized": self.kyber_kem is not None,
            "sphincs_plus_initialized": self.sphincs_plus is not None,
        }
        
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


# API для экстренного создания экземпляра
async def create_emergency_crypto_instance() -> QuantumResistantCryptoCore:
    """Создает экземпляр системы в экстренном режиме"""
    instance = QuantumResistantCryptoCore()
    await instance.emergency_initialize()
    return instance


# Экстренный запуск
async def emergency_main():
    """Экстренный запуск системы"""
    logger.critical("🚨 АКТИВАЦИЯ ЭКСТРЕННОГО РЕЖИМА QUANTUM-RESISTANT-CRYPTO-CORE")
    core = QuantumResistantCryptoCore()
    await core.emergency_start()


# Для прямого запуска
async def main():
    await emergency_main()


if __name__ == "__main__":
    asyncio.run(main())
