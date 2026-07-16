"""
Quantum-Resistant Cryptography Core
Post-Quantum Cryptographic Primitives
"""

from .kyber_kem import (
    KyberKEM,
    KyberKeys,
    KyberCiphertext,
    kyber_keygen,
    kyber_encaps,
    kyber_decaps,
)

from .sphincs_plus import (
    SphincsPlus,
    SphincsKeys,
    SphincsSignature,
    sphincs_keygen,
    sphincs_sign,
    sphincs_verify,
)

from .quantum_crypto import (
    QuantumCrypto,
    generate_quantum_keypair,
    quantum_encrypt,
    quantum_decrypt,
    quantum_sign,
    quantum_verify,
)


__all__ = [
    # Kyber KEM
    "KyberKEM",
    "KyberKeys",
    "KyberCiphertext",
    "kyber_keygen",
    "kyber_encaps",
    "kyber_decaps",
    
    # SPHINCS+
    "SphincsPlus",
    "SphincsKeys",
    "SphincsSignature",
    "sphincs_keygen",
    "sphincs_sign",
    "sphincs_verify",
    
    # Unified API
    "QuantumCrypto",
    "generate_quantum_keypair",
    "quantum_encrypt",
    "quantum_decrypt",
    "quantum_sign",
    "quantum_verify",
]
