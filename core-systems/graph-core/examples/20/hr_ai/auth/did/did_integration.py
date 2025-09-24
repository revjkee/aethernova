# onchain/dao-governance/did_integration.py

import json
from typing import Optional, Dict, Any
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
import base58

class DIDIntegration:
    """
    Новый: модуль интеграции DID (Decentralized Identifiers) для DAO.
    Обеспечивает создание, управление и верификацию DID и DID документов,
    подписанных с помощью Ed25519 ключей.
    """

    def __init__(self):
        # Хранилище DID документов: did -> did_document
        self.did_documents: Dict[str, Dict[str, Any]] = {}

    def generate_keypair(self) -> Dict[str, str]:
        """
        Генерирует пару ключей Ed25519 и возвращает их в base58 кодировке.
        """
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        return {
            "private_key": base58.b58encode(priv_bytes).decode(),
            "public_key": base58.b58encode(pub_bytes).decode()
        }

    def create_did(self, public_key_base58: str) -> str:
        """
        Создаёт DID на основе public key.
        Формат DID: did:example:<base58(public_key)>
        """
        did = f"did:example:{public_key_base58}"
        return did

    def build_did_document(self, did: str, public_key_base58: str) -> Dict[str, Any]:
        """
        Строит DID документ с необходимыми полями и публичным ключом.
        """
        doc = {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": did,
            "verificationMethod": [{
                "id": f"{did}#key-1",
                "type": "Ed25519VerificationKey2018",
                "controller": did,
                "publicKeyBase58": public_key_base58
            }],
            "authentication": [f"{did}#key-1"]
        }
        self.did_documents[did] = doc
        return doc

    def sign_message(self, message: str, private_key_base58: str) -> str:
        """
        Подписывает сообщение приватным ключом Ed25519.
        Возвращает подпись в base58.
        """
        priv_bytes = base58.b58decode(private_key_base58.encode())
        private_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
        signature = private_key.sign(message.encode())
        return base58.b58encode(signature).decode()

    def verify_signature(self, message: str, signature_base58: str, public_key_base58: str) -> bool:
        """
        Проверяет подпись сообщения с помощью публичного ключа Ed25519.
        """
        pub_bytes = base58.b58decode(public_key_base58.encode())
        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        signature = base58.b58decode(signature_base58.encode())
        try:
            public_key.verify(signature, message.encode())
            return True
        except InvalidSignature:
            return False

    def resolve_did(self, did: str) -> Optional[Dict[str, Any]]:
        """
        Разрешение DID в DID документ.
        В реальном мире будет обращение к децентрализованному реестру.
        """
        return self.did_documents.get(did)

    def export_did_document(self, did: str) -> Optional[str]:
        """
        Возвращает DID документ в формате JSON строки.
        """
        doc = self.resolve_did(did)
        if doc:
            return json.dumps(doc, indent=2)
        return None


