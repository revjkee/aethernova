# zk-core/zk/zk_access_control.py

import hashlib
from typing import Dict, Optional
from dataclasses import dataclass

from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

from .zk_commitment_layer import PedersenCommitment, CommitmentFactory


@dataclass
class AccessProof:
    proof_hash: str
    proof_commitment: int
    nonce: bytes


class ZKAccessControl:
    """
    Модуль Zero-Knowledge Access Control: проверка прав без раскрытия сущностей.
    """

    def __init__(self):
        self.factory = CommitmentFactory()
        self.commit_scheme = self.factory.create_pedersen()

        # Хранилище NFT/DAO zk-доступов
        self.zk_registry: Dict[str, AccessProof] = {}

    def generate_proof(self, user_id: str, access_level: int) -> AccessProof:
        """
        Генерация zk-доказательства доступа на основе user_id и уровня (например, NFT tier).
        """
        nonce = get_random_bytes(32)
        value = int.from_bytes(HKDF(user_id.encode(), 32, salt=nonce, hashmod=SHA256), "big")
        commitment, rand = self.commit_scheme.commit(value * access_level)
        proof_hash = hashlib.sha256(f"{commitment}:{access_level}".encode()).hexdigest()
        self.zk_registry[user_id] = AccessProof(proof_hash, commitment, nonce)
        return self.zk_registry[user_id]

    def verify_proof(self, user_id: str, access_level: int, proof: AccessProof) -> bool:
        """
        Проверка zk-доступа.
        """
        value = int.from_bytes(HKDF(user_id.encode(), 32, salt=proof.nonce, hashmod=SHA256), "big")
        expected_commitment, _ = self.commit_scheme.commit(value * access_level, None)
        expected_hash = hashlib.sha256(f"{expected_commitment}:{access_level}".encode()).hexdigest()
        return proof.proof_commitment == expected_commitment and proof.proof_hash == expected_hash

    def has_access(self, user_id: str, required_level: int) -> bool:
        """
        Проверка наличия прав без раскрытия деталей.
        """
        proof = self.zk_registry.get(user_id)
        if not proof:
            return False
        return self.verify_proof(user_id, required_level, proof)


# Пример использования
if __name__ == "__main__":
    zk_access = ZKAccessControl()
    user = "0xDA0_NFT_user"
    tier = 3

    proof = zk_access.generate_proof(user, tier)
    assert zk_access.verify_proof(user, tier, proof)
    assert zk_access.has_access(user, tier)

    print(f"Access granted for user '{user}' with tier {tier}")
