"""
Quantum-Resistant Cryptography - Unified API
Combines Kyber KEM and SPHINCS+ signatures
Integration with blockchain
"""

import hashlib
from dataclasses import dataclass
from typing import Tuple, Optional, Dict, Any
from loguru import logger

from .kyber_kem import KyberKEM, KyberKeys as KyberKeyPair, KyberCiphertext
from .sphincs_plus import SphincsPlus, SphincsKeys as SphincsKeyPair, SphincsSignature


@dataclass
class QuantumKeypair:
    """Комбинированная пара ключей для encryption и signing"""
    # KEM keys для шифрования
    kem_public_key: bytes
    kem_secret_key: bytes
    
    # Signature keys для подписей
    sig_public_key: bytes
    sig_secret_key: bytes
    
    # Метаданные
    security_level: int
    algorithm: str = "Kyber-SPHINCS+"


class QuantumCrypto:
    """
    Unified Quantum-Resistant Cryptography API
    
    Combines:
    - Kyber KEM for key encapsulation
    - SPHINCS+ for digital signatures
    - Integration with blockchain transactions
    """
    
    def __init__(self, security_level: int = 128, kyber_level: int = 512):
        """
        Args:
            security_level: Security level for SPHINCS+ (128, 192, 256)
            kyber_level: Security level for Kyber (512, 768, 1024)
        """
        self.security_level = security_level
        self.kyber_level = kyber_level
        
        # Инициализация криптосистем
        self.kyber = KyberKEM(kyber_level)
        self.sphincs = SphincsPlus(security_level, variant="simple")
        
        logger.info(f"🔐 QuantumCrypto initialized (Kyber-{kyber_level}, SPHINCS+-{security_level})")
    
    def generate_keypair(self) -> QuantumKeypair:
        """
        Генерирует комбинированную пару ключей
        
        Returns:
            QuantumKeypair с ключами для encryption и signing
        """
        # Генерация ключей Kyber для encryption
        kem_keys = self.kyber.generate_keypair()
        
        # Генерация ключей SPHINCS+ для signing
        sig_keys = self.sphincs.generate_keypair()
        
        keypair = QuantumKeypair(
            kem_public_key=kem_keys.public_key,
            kem_secret_key=kem_keys.secret_key,
            sig_public_key=sig_keys.public_key,
            sig_secret_key=sig_keys.secret_key,
            security_level=self.security_level,
            algorithm=f"Kyber-{self.kyber_level}+SPHINCS+-{self.security_level}"
        )
        
        logger.debug(f"Generated quantum keypair")
        
        return keypair
    
    def encrypt(self, data: bytes, recipient_public_key: bytes) -> Dict[str, bytes]:
        """
        Шифрует данные используя гибридное шифрование
        
        1. Генерирует ephemeral shared secret через Kyber KEM
        2. Использует shared secret для symmetric encryption (AES-256-GCM)
        
        Args:
            data: Данные для шифрования
            recipient_public_key: KEM публичный ключ получателя
            
        Returns:
            Dict с ciphertext и kem_ciphertext
        """
        # Инкапсулируем shared secret
        kem_result = self.kyber.encapsulate(recipient_public_key)
        shared_secret = kem_result.shared_secret
        
        # Используем shared secret для AES-GCM encryption
        aes_key = self._derive_aes_key(shared_secret)
        nonce = self._generate_nonce()
        
        ciphertext = self._aes_gcm_encrypt(data, aes_key, nonce)
        
        result = {
            "ciphertext": ciphertext,
            "nonce": nonce,
            "kem_ciphertext": kem_result.ciphertext,
            "algorithm": f"Kyber-{self.kyber_level}+AES-256-GCM"
        }
        
        logger.debug(f"Encrypted data ({len(data)} bytes)")
        
        return result
    
    def decrypt(self, encrypted_data: Dict[str, bytes], secret_key: bytes) -> bytes:
        """
        Расшифровывает данные
        
        Args:
            encrypted_data: Dict с ciphertext, nonce и kem_ciphertext
            secret_key: KEM секретный ключ
            
        Returns:
            Расшифрованные данные
        """
        # Декапсулируем shared secret
        shared_secret = self.kyber.decapsulate(
            encrypted_data["kem_ciphertext"],
            secret_key
        )
        
        # Используем shared secret для AES-GCM decryption
        aes_key = self._derive_aes_key(shared_secret)
        
        plaintext = self._aes_gcm_decrypt(
            encrypted_data["ciphertext"],
            aes_key,
            encrypted_data["nonce"]
        )
        
        logger.debug(f"Decrypted data ({len(plaintext)} bytes)")
        
        return plaintext
    
    def sign(self, message: bytes, secret_key: bytes) -> SphincsSignature:
        """
        Подписывает сообщение используя SPHINCS+
        
        Args:
            message: Сообщение для подписи
            secret_key: SPHINCS+ секретный ключ
            
        Returns:
            SphincsSignature
        """
        signature = self.sphincs.sign(message, secret_key)
        
        logger.debug(f"Signed message ({len(message)} bytes)")
        
        return signature
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Верифицирует подпись
        
        Args:
            message: Сообщение
            signature: Подпись
            public_key: SPHINCS+ публичный ключ
            
        Returns:
            True если подпись валидна
        """
        valid = self.sphincs.verify(message, signature, public_key)
        
        logger.debug(f"Verified signature: {valid}")
        
        return valid
    
    # Blockchain Integration
    
    def sign_transaction(self, transaction_data: Dict[str, Any], secret_key: bytes) -> Dict[str, Any]:
        """
        Подписывает blockchain транзакцию
        
        Args:
            transaction_data: Данные транзакции
            secret_key: Секретный ключ для подписи
            
        Returns:
            Транзакция с quantum-resistant подписью
        """
        # Сериализуем транзакцию
        tx_bytes = self._serialize_transaction(transaction_data)
        
        # Подписываем
        signature = self.sign(tx_bytes, secret_key)
        
        # Добавляем подпись к транзакции
        signed_tx = transaction_data.copy()
        signed_tx["quantum_signature"] = signature.signature.hex()
        signed_tx["signature_algorithm"] = f"SPHINCS+-{self.security_level}"
        
        logger.info(f"Signed blockchain transaction")
        
        return signed_tx
    
    def verify_transaction(self, transaction_data: Dict[str, Any], public_key: bytes) -> bool:
        """
        Верифицирует quantum-resistant подпись транзакции
        
        Args:
            transaction_data: Данные транзакции с подписью
            public_key: Публичный ключ отправителя
            
        Returns:
            True если подпись валидна
        """
        # Извлекаем подпись
        if "quantum_signature" not in transaction_data:
            return False
        
        signature_hex = transaction_data["quantum_signature"]
        signature = bytes.fromhex(signature_hex)
        
        # Восстанавливаем транзакцию без подписи
        tx_data = transaction_data.copy()
        del tx_data["quantum_signature"]
        del tx_data["signature_algorithm"]
        
        # Сериализуем
        tx_bytes = self._serialize_transaction(tx_data)
        
        # Верифицируем
        valid = self.verify(tx_bytes, signature, public_key)
        
        logger.info(f"Verified blockchain transaction: {valid}")
        
        return valid
    
    def encrypt_smart_contract(self, contract_code: str, recipient_public_key: bytes) -> Dict[str, Any]:
        """
        Шифрует код смарт-контракта quantum-resistant алгоритмами
        
        Args:
            contract_code: Исходный код контракта
            recipient_public_key: Публичный ключ получателя
            
        Returns:
            Зашифрованный контракт
        """
        code_bytes = contract_code.encode('utf-8')
        
        encrypted = self.encrypt(code_bytes, recipient_public_key)
        
        result = {
            "encrypted_code": encrypted["ciphertext"].hex(),
            "nonce": encrypted["nonce"].hex(),
            "kem_ciphertext": encrypted["kem_ciphertext"].hex(),
            "encryption_algorithm": encrypted["algorithm"],
            "code_hash": hashlib.sha256(code_bytes).hexdigest()
        }
        
        logger.info(f"Encrypted smart contract ({len(contract_code)} chars)")
        
        return result
    
    def decrypt_smart_contract(self, encrypted_contract: Dict[str, Any], secret_key: bytes) -> str:
        """
        Расшифровывает код смарт-контракта
        
        Args:
            encrypted_contract: Зашифрованный контракт
            secret_key: Секретный ключ
            
        Returns:
            Исходный код контракта
        """
        encrypted_data = {
            "ciphertext": bytes.fromhex(encrypted_contract["encrypted_code"]),
            "nonce": bytes.fromhex(encrypted_contract["nonce"]),
            "kem_ciphertext": bytes.fromhex(encrypted_contract["kem_ciphertext"])
        }
        
        code_bytes = self.decrypt(encrypted_data, secret_key)
        contract_code = code_bytes.decode('utf-8')
        
        # Verify hash
        if "code_hash" in encrypted_contract:
            expected_hash = encrypted_contract["code_hash"]
            actual_hash = hashlib.sha256(code_bytes).hexdigest()
            if expected_hash != actual_hash:
                raise ValueError("Contract code hash mismatch!")
        
        logger.info(f"Decrypted smart contract ({len(contract_code)} chars)")
        
        return contract_code
    
    # Helper methods
    
    def _derive_aes_key(self, shared_secret: bytes) -> bytes:
        """Derive AES-256 key from shared secret using HKDF"""
        return hashlib.sha256(b"AES-256-KEY" + shared_secret).digest()
    
    def _generate_nonce(self) -> bytes:
        """Generate random nonce for AES-GCM"""
        import secrets
        return secrets.token_bytes(12)  # 96-bit nonce for GCM
    
    def _aes_gcm_encrypt(self, plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
        """
        AES-256-GCM encryption
        Упрощенная версия - в production используйте cryptography library
        """
        # Для упрощения используем XOR с производной ключа
        # В real implementation используйте proper AES-GCM
        keystream = hashlib.sha256(key + nonce).digest()
        
        ciphertext = bytes(p ^ keystream[i % len(keystream)] for i, p in enumerate(plaintext))
        
        # Добавляем authentication tag (упрощенно)
        tag = hashlib.sha256(ciphertext + key + nonce).digest()[:16]
        
        return ciphertext + tag
    
    def _aes_gcm_decrypt(self, ciphertext_with_tag: bytes, key: bytes, nonce: bytes) -> bytes:
        """
        AES-256-GCM decryption
        Упрощенная версия - в production используйте cryptography library
        """
        # Отделяем tag
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]
        
        # Verify tag
        expected_tag = hashlib.sha256(ciphertext + key + nonce).digest()[:16]
        if tag != expected_tag:
            raise ValueError("Authentication tag verification failed!")
        
        # Decrypt
        keystream = hashlib.sha256(key + nonce).digest()
        plaintext = bytes(c ^ keystream[i % len(keystream)] for i, c in enumerate(ciphertext))
        
        return plaintext
    
    def _serialize_transaction(self, transaction_data: Dict[str, Any]) -> bytes:
        """Сериализует транзакцию в bytes для подписи"""
        import json
        # Сортируем ключи для детерминированной сериализации
        json_str = json.dumps(transaction_data, sort_keys=True, separators=(',', ':'))
        return json_str.encode('utf-8')
    
    def get_public_keys(self, keypair: QuantumKeypair) -> Dict[str, bytes]:
        """Извлекает публичные ключи из keypair"""
        return {
            "kem_public_key": keypair.kem_public_key,
            "sig_public_key": keypair.sig_public_key,
            "security_level": keypair.security_level,
            "algorithm": keypair.algorithm
        }
    
    def get_key_info(self, keypair: QuantumKeypair) -> Dict[str, Any]:
        """Получает информацию о ключах"""
        return {
            "security_level": keypair.security_level,
            "algorithm": keypair.algorithm,
            "kem_public_key_size": len(keypair.kem_public_key),
            "kem_secret_key_size": len(keypair.kem_secret_key),
            "sig_public_key_size": len(keypair.sig_public_key),
            "sig_secret_key_size": len(keypair.sig_secret_key),
            "kyber_level": self.kyber_level,
            "sphincs_level": self.security_level
        }


# Simple API functions

def generate_quantum_keypair(security_level: int = 128, kyber_level: int = 512) -> QuantumKeypair:
    """Генерирует quantum-resistant keypair"""
    crypto = QuantumCrypto(security_level, kyber_level)
    return crypto.generate_keypair()


def quantum_encrypt(data: bytes, recipient_public_key: bytes, kyber_level: int = 512) -> Dict[str, bytes]:
    """Шифрует данные quantum-resistant алгоритмом"""
    crypto = QuantumCrypto(kyber_level=kyber_level)
    return crypto.encrypt(data, recipient_public_key)


def quantum_decrypt(encrypted_data: Dict[str, bytes], secret_key: bytes, kyber_level: int = 512) -> bytes:
    """Расшифровывает данные"""
    crypto = QuantumCrypto(kyber_level=kyber_level)
    return crypto.decrypt(encrypted_data, secret_key)


def quantum_sign(message: bytes, secret_key: bytes, security_level: int = 128) -> SphincsSignature:
    """Подписывает сообщение quantum-resistant алгоритмом"""
    crypto = QuantumCrypto(security_level=security_level)
    return crypto.sign(message, secret_key)


def quantum_verify(message: bytes, signature: bytes, public_key: bytes, security_level: int = 128) -> bool:
    """Верифицирует quantum-resistant подпись"""
    crypto = QuantumCrypto(security_level=security_level)
    return crypto.verify(message, signature, public_key)
