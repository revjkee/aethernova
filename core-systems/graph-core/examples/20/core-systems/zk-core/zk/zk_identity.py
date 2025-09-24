import hashlib
import secrets
import time
from typing import Optional

from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder
from pydantic import BaseModel, Field

from zk.zk_utils import generate_zk_proof, verify_zk_proof

class ZKIdentity(BaseModel):
    """
    Представляет сущность с ZK-удостоверением.
    Используется для анонимной верификации личности и подписи сообщений без раскрытия данных.
    """

    public_key: str = Field(..., description="Публичный ключ в hex формате")
    identity_commitment: str = Field(..., description="Коммитмент личности, используемый в ZK-протоколах")
    created_at: float = Field(default_factory=time.time, description="Время создания сущности")

    class Config:
        frozen = True


class ZKIdentityManager:
    """
    Менеджер для создания, хранения и проверки ZK-удостоверений личности.
    """

    def __init__(self):
        self._identities: dict[str, ZKIdentity] = {}

    def create_identity(self) -> ZKIdentity:
        """
        Генерирует новую сущность ZKIdentity.
        """
        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key
        public_key_hex = verify_key.encode(encoder=HexEncoder).decode()

        identity_commitment = self._commit_identity(public_key_hex)
        identity = ZKIdentity(
            public_key=public_key_hex,
            identity_commitment=identity_commitment
        )
        self._identities[public_key_hex] = identity
        return identity

    def get_identity(self, public_key_hex: str) -> Optional[ZKIdentity]:
        return self._identities.get(public_key_hex)

    def verify_identity(self, proof: dict, public_key_hex: str) -> bool:
        """
        Проверяет доказательство знания личности без раскрытия самой личности.
        """
        identity = self.get_identity(public_key_hex)
        if not identity:
            return False
        return verify_zk_proof(proof, identity.identity_commitment)

    def _commit_identity(self, public_key_hex: str) -> str:
        """
        Создаёт коммитмент на основе публичного ключа.
        """
        salt = secrets.token_hex(16)
        raw = f"{salt}:{public_key_hex}"
        return hashlib.sha256(raw.encode()).hexdigest()
