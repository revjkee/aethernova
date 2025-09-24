# phantommesh-core/api_gateway/key_exchange_service.py

import os
import time
import hmac
import hashlib
import logging
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

logger = logging.getLogger("key_exchange_service")
logger.setLevel(logging.DEBUG)

SESSION_TIMEOUT = 180  # сек
HKDF_INFO = b"phantommesh-zk-handshake"

class EphemeralSession:
    def __init__(self, agent_pub: bytes, shared_key: bytes, timestamp: float):
        self.agent_pub = agent_pub
        self.shared_key = shared_key
        self.timestamp = timestamp

    def is_expired(self) -> bool:
        return (time.time() - self.timestamp) > SESSION_TIMEOUT

class KeyExchangeService:
    def __init__(self):
        self.identity_key: X25519PrivateKey = X25519PrivateKey.generate()
        self.identity_pub: X25519PublicKey = self.identity_key.public_key()
        self.sessions: Dict[str, EphemeralSession] = {}

    def get_public_key_bytes(self) -> bytes:
        return self.identity_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def perform_handshake(self, agent_id: str, agent_pub_bytes: bytes, zk_proof: Optional[bytes]) -> bytes:
        # Проверка ZK-доказательства (заглушка, заменяется на zk-SNARK проверку)
        if not self._validate_zk(agent_id, agent_pub_bytes, zk_proof):
            raise ValueError("Invalid ZK proof")

        agent_pub = X25519PublicKey.from_public_bytes(agent_pub_bytes)
        shared_secret = self.identity_key.exchange(agent_pub)

        derived_key = self._derive_key(shared_secret)
        self.sessions[agent_id] = EphemeralSession(agent_pub_bytes, derived_key, time.time())

        logger.info(f"[HANDSHAKE] Новый сеанс с {agent_id}, key fingerprint: {self._fingerprint(derived_key)}")
        return self.identity_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def encrypt_for_agent(self, agent_id: str, plaintext: bytes) -> bytes:
        session = self.sessions.get(agent_id)
        if not session or session.is_expired():
            raise ValueError("No valid session")

        nonce = os.urandom(12)
        aead = ChaCha20Poly1305(session.shared_key)
        ciphertext = aead.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt_from_agent(self, agent_id: str, data: bytes) -> bytes:
        session = self.sessions.get(agent_id)
        if not session or session.is_expired():
            raise ValueError("No valid session")

        nonce = data[:12]
        ciphertext = data[12:]
        aead = ChaCha20Poly1305(session.shared_key)
        return aead.decrypt(nonce, ciphertext, None)

    def _derive_key(self, shared_secret: bytes) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=HKDF_INFO,
        )
        return hkdf.derive(shared_secret)

    def _validate_zk(self, agent_id: str, pub_bytes: bytes, zk_proof: Optional[bytes]) -> bool:
        # Заменяется на реальную SNARK/Σ-протокольную проверку
        if zk_proof is None:
            return False
        digest = hmac.new(agent_id.encode(), pub_bytes, hashlib.sha256).digest()
        return hmac.compare_digest(digest[:16], zk_proof[:16])

    def cleanup_expired_sessions(self):
        now = time.time()
        expired = [k for k, v in self.sessions.items() if v.is_expired()]
        for k in expired:
            del self.sessions[k]
            logger.debug(f"[HANDSHAKE] Сеанс {k} истёк")

    def _fingerprint(self, key: bytes) -> str:
        return hashlib.sha256(key).hexdigest()[:16]
