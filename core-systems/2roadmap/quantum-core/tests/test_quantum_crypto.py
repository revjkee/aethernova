"""
Comprehensive Tests for Quantum-Resistant Cryptography Core
ВОССТАНОВЛЕНО - Test Suite для quantum-core
"""

import pytest
import asyncio
import json
from pathlib import Path

# Import the components we're testing
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.kyber_kem import KyberKEM
from src.sphincs_plus import SphincsPlus
from src.quantum_crypto import QuantumCrypto, QuantumKeypair
from main import QuantumResistantCryptoCore


class TestKyberKEM:
    """Tests for Kyber KEM (Lattice-based post-quantum cryptography)"""
    
    def test_kyber_keypair_generation(self):
        """Test Kyber keypair generation for different security levels"""
        for level in [512, 768, 1024]:
            kyber = KyberKEM(security_level=level)
            public_key, secret_key = kyber.generate_keypair()
            
            assert public_key is not None
            assert secret_key is not None
            assert isinstance(public_key, bytes)
            assert isinstance(secret_key, bytes)
            assert len(public_key) > 0
            assert len(secret_key) > 0
    
    def test_kyber_encapsulation_decapsulation(self):
        """Test Kyber encapsulation and decapsulation"""
        kyber = KyberKEM(security_level=512)
        public_key, secret_key = kyber.generate_keypair()
        
        # Encapsulate (generate shared secret)
        ciphertext, shared_secret1 = kyber.encapsulate(public_key)
        
        assert ciphertext is not None
        assert shared_secret1 is not None
        assert isinstance(ciphertext, bytes)
        assert isinstance(shared_secret1, bytes)
        
        # Decapsulate (recover shared secret)
        shared_secret2 = kyber.decapsulate(ciphertext, secret_key)
        
        assert shared_secret2 is not None
        assert isinstance(shared_secret2, bytes)
        
        # Shared secrets should match
        assert shared_secret1 == shared_secret2
    
    def test_kyber_different_security_levels(self):
        """Test that different Kyber security levels work correctly"""
        for level in [512, 768, 1024]:
            kyber = KyberKEM(security_level=level)
            public_key, secret_key = kyber.generate_keypair()
            ciphertext, ss1 = kyber.encapsulate(public_key)
            ss2 = kyber.decapsulate(ciphertext, secret_key)
            assert ss1 == ss2


class TestSphincsPlus:
    """Tests for SPHINCS+ (Hash-based post-quantum signatures)"""
    
    def test_sphincs_keypair_generation(self):
        """Test SPHINCS+ keypair generation"""
        for level in [128, 192, 256]:
            sphincs = SphincsPlus(security_level=level, variant="simple")
            public_key, secret_key = sphincs.generate_keypair()
            
            assert public_key is not None
            assert secret_key is not None
            assert isinstance(public_key, bytes)
            assert isinstance(secret_key, bytes)
    
    def test_sphincs_sign_verify(self):
        """Test SPHINCS+ signature generation and verification"""
        sphincs = SphincsPlus(security_level=128, variant="simple")
        public_key, secret_key = sphincs.generate_keypair()
        
        message = b"Test message for quantum-resistant signature"
        
        # Sign the message
        signature = sphincs.sign(message, secret_key)
        
        assert signature is not None
        assert signature.signature is not None
        assert isinstance(signature.signature, bytes)
        
        # Verify the signature
        is_valid = sphincs.verify(message, signature.signature, public_key)
        
        assert is_valid is True
    
    def test_sphincs_invalid_signature(self):
        """Test that invalid signatures are rejected"""
        sphincs = SphincsPlus(security_level=128, variant="simple")
        public_key, secret_key = sphincs.generate_keypair()
        
        message = b"Original message"
        signature = sphincs.sign(message, secret_key)
        
        # Try to verify with different message
        tampered_message = b"Tampered message"
        is_valid = sphincs.verify(tampered_message, signature.signature, public_key)
        
        assert is_valid is False
    
    def test_sphincs_different_variants(self):
        """Test different SPHINCS+ variants"""
        for variant in ["simple", "robust"]:
            sphincs = SphincsPlus(security_level=128, variant=variant)
            public_key, secret_key = sphincs.generate_keypair()
            message = b"Test message"
            signature = sphincs.sign(message, secret_key)
            is_valid = sphincs.verify(message, signature.signature, public_key)
            assert is_valid is True


class TestQuantumCrypto:
    """Tests for unified QuantumCrypto API"""
    
    def test_quantum_crypto_keypair_generation(self):
        """Test unified keypair generation"""
        qc = QuantumCrypto(security_level=128, kyber_level=512)
        keypair = qc.generate_keypair()
        
        assert keypair is not None
        assert isinstance(keypair, QuantumKeypair)
        assert keypair.kem_public_key is not None
        assert keypair.kem_secret_key is not None
        assert keypair.sig_public_key is not None
        assert keypair.sig_secret_key is not None
        assert keypair.security_level == 128
        assert keypair.algorithm == "Kyber-512+SPHINCS+-128"
    
    def test_quantum_crypto_encrypt_decrypt(self):
        """Test hybrid encryption/decryption"""
        qc = QuantumCrypto(security_level=128, kyber_level=512)
        keypair = qc.generate_keypair()
        
        plaintext = b"Secret data that needs quantum-resistant protection"
        
        # Encrypt
        encrypted = qc.encrypt(plaintext, keypair.kem_public_key)
        
        assert "ciphertext" in encrypted
        assert "nonce" in encrypted
        assert "kem_ciphertext" in encrypted
        
        # Decrypt
        decrypted = qc.decrypt(encrypted, keypair.kem_secret_key)
        
        assert decrypted == plaintext
    
    def test_quantum_crypto_sign_verify(self):
        """Test message signing and verification"""
        qc = QuantumCrypto(security_level=128, kyber_level=512)
        keypair = qc.generate_keypair()
        
        message = b"Important message that needs quantum-safe signature"
        
        # Sign
        signature = qc.sign(message, keypair.sig_secret_key)
        
        assert signature is not None
        assert signature.signature is not None
        
        # Verify
        is_valid = qc.verify(message, signature.signature, keypair.sig_public_key)
        
        assert is_valid is True
    
    def test_quantum_crypto_transaction_signing(self):
        """Test blockchain transaction signing"""
        qc = QuantumCrypto(security_level=128, kyber_level=512)
        keypair = qc.generate_keypair()
        
        tx_data = {
            "from": "0x1234567890abcdef",
            "to": "0xfedcba0987654321",
            "amount": 100,
            "nonce": 42,
            "gas": 21000
        }
        
        # Sign transaction
        signed_tx = qc.sign_transaction(tx_data, keypair.sig_secret_key)
        
        assert "transaction_data" in signed_tx
        assert "signature" in signed_tx
        assert "timestamp" in signed_tx
        
        # Verify transaction
        is_valid = qc.verify_transaction(signed_tx, keypair.sig_public_key)
        
        assert is_valid is True
    
    def test_quantum_crypto_smart_contract_encryption(self):
        """Test smart contract encryption/decryption"""
        qc = QuantumCrypto(security_level=128, kyber_level=512)
        keypair = qc.generate_keypair()
        
        contract_code = """
        contract TestContract {
            uint256 public value;
            
            function setValue(uint256 _value) public {
                value = _value;
            }
        }
        """
        
        # Encrypt contract
        encrypted = qc.encrypt_smart_contract(contract_code, keypair.kem_public_key)
        
        assert "encrypted_code" in encrypted
        assert "nonce" in encrypted
        assert "kem_ciphertext" in encrypted
        
        # Decrypt contract
        decrypted_code = qc.decrypt_smart_contract(encrypted, keypair.kem_secret_key)
        
        assert decrypted_code == contract_code


@pytest.mark.asyncio
class TestQuantumResistantCryptoCore:
    """Tests for the main QuantumResistantCryptoCore system"""
    
    async def test_core_initialization(self):
        """Test core system initialization"""
        core = QuantumResistantCryptoCore()
        assert core is not None
        assert core.emergency_mode is True
        assert core.is_running is False
        
        # Initialize
        success = await core.emergency_initialize()
        assert success is True
        assert core.quantum_crypto is not None
        assert core.kyber_kem is not None
        assert core.sphincs_plus is not None
    
    async def test_core_generate_keypair(self):
        """Test keypair generation through core API"""
        core = QuantumResistantCryptoCore()
        await core.emergency_initialize()
        
        keypair = await core.generate_keypair("test_keypair_1")
        
        assert keypair is not None
        assert "test_keypair_1" in core.keypairs
        assert core.metrics["generated_keypairs"] == 1
    
    async def test_core_encrypt_decrypt(self):
        """Test encryption/decryption through core API"""
        core = QuantumResistantCryptoCore()
        await core.emergency_initialize()
        
        keypair = await core.generate_keypair("test_keypair_2")
        data = b"Test data for quantum encryption"
        
        # Encrypt
        encrypted = await core.encrypt_data(data, keypair.kem_public_key)
        assert core.metrics["encryption_operations"] == 1
        
        # Decrypt
        decrypted = await core.decrypt_data(encrypted, keypair.kem_secret_key)
        assert decrypted == data
        assert core.metrics["decryption_operations"] == 1
    
    async def test_core_sign_verify(self):
        """Test signing/verification through core API"""
        core = QuantumResistantCryptoCore()
        await core.emergency_initialize()
        
        keypair = await core.generate_keypair("test_keypair_3")
        message = b"Test message for quantum signature"
        
        # Sign
        signature = await core.sign_message(message, keypair.sig_secret_key)
        assert core.metrics["signing_operations"] == 1
        
        # Verify
        is_valid = await core.verify_signature(message, signature, keypair.sig_public_key)
        assert is_valid is True
        assert core.metrics["verification_operations"] == 1
    
    async def test_core_blockchain_integration(self):
        """Test blockchain integration through core API"""
        core = QuantumResistantCryptoCore()
        await core.emergency_initialize()
        
        keypair = await core.generate_keypair("blockchain_keypair")
        
        tx_data = {
            "from": "0xabc123",
            "to": "0xdef456",
            "amount": 50,
            "nonce": 1
        }
        
        # Sign transaction
        signed_tx = await core.sign_transaction(tx_data, "blockchain_keypair")
        assert "signature" in signed_tx
        
        # Verify transaction
        is_valid = await core.verify_transaction(signed_tx, keypair.sig_public_key)
        assert is_valid is True
    
    async def test_core_smart_contract_operations(self):
        """Test smart contract encryption/decryption through core API"""
        core = QuantumResistantCryptoCore()
        await core.emergency_initialize()
        
        keypair = await core.generate_keypair("contract_keypair")
        
        contract_code = "contract Test { uint256 value; }"
        
        # Encrypt
        encrypted = await core.encrypt_smart_contract(contract_code, keypair.kem_public_key)
        assert "encrypted_code" in encrypted
        
        # Decrypt
        decrypted = await core.decrypt_smart_contract(encrypted, "contract_keypair")
        assert decrypted == contract_code
    
    async def test_core_health_check(self):
        """Test emergency health check"""
        core = QuantumResistantCryptoCore()
        await core.emergency_initialize()
        
        health = await core.emergency_health_check()
        
        assert health["status"] == "emergency_operational"
        assert health["emergency_mode"] is True
        assert health["checks"]["quantum_crypto_initialized"] is True
        assert health["checks"]["kyber_kem_initialized"] is True
        assert health["checks"]["sphincs_plus_initialized"] is True
    
    async def test_core_get_status(self):
        """Test get status"""
        core = QuantumResistantCryptoCore()
        await core.emergency_initialize()
        
        await core.generate_keypair("status_test_keypair")
        
        status = core.get_status()
        
        assert status["system_name"] == "quantum-core"
        assert status["category"] == "Quantum Cryptography"
        assert status["emergency_mode"] is True
        assert status["keypairs_count"] == 1
        assert "quantum_crypto" in status["components"]


# Performance and stress tests
class TestPerformance:
    """Performance tests for quantum crypto operations"""
    
    def test_kyber_performance(self):
        """Test Kyber KEM performance"""
        kyber = KyberKEM(security_level=512)
        
        # Measure keypair generation
        import time
        start = time.time()
        for _ in range(10):
            kyber.generate_keypair()
        keypair_time = time.time() - start
        
        # Should complete 10 keypair generations in reasonable time
        assert keypair_time < 5.0  # 5 seconds for 10 operations
    
    def test_sphincs_performance(self):
        """Test SPHINCS+ performance"""
        sphincs = SphincsPlus(security_level=128, variant="simple")
        public_key, secret_key = sphincs.generate_keypair()
        
        message = b"Performance test message"
        
        # Measure signing
        import time
        start = time.time()
        for _ in range(10):
            sphincs.sign(message, secret_key)
        sign_time = time.time() - start
        
        # Should complete 10 signatures in reasonable time
        assert sign_time < 10.0  # 10 seconds for 10 operations


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
