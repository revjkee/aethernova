import json
import hashlib
import hmac
from typing import Any, Dict, Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend


def _serialize_metadata(metadata: Dict[str, Any]) -> bytes:
    """
    Безопасная сериализация метаинформации плагина
    """
    try:
        return json.dumps(metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except Exception:
        raise ValueError("Failed to serialize plugin metadata")


# === HMAC Signing ===

def sign_hmac(metadata: Dict[str, Any], secret_key: str) -> str:
    """
    Подписывает метаданные HMAC-SHA256
    """
    serialized = _serialize_metadata(metadata)
    return hmac.new(secret_key.encode(), serialized, hashlib.sha256).hexdigest()


def verify_hmac(metadata: Dict[str, Any], signature: str, secret_key: str) -> bool:
    """
    Проверяет HMAC-подпись
    """
    expected = sign_hmac(metadata, secret_key)
    return hmac.compare_digest(expected, signature)


# === RSA Signing ===

def generate_rsa_key_pair() -> (bytes, bytes):
    """
    Генерация приватного и публичного RSA-ключа
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_bytes, pub_bytes


def sign_rsa(metadata: Dict[str, Any], private_key_pem: bytes) -> bytes:
    """
    Подпись RSA-SHA256
    """
    private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
    serialized = _serialize_metadata(metadata)
    return private_key.sign(
        serialized,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )


def verify_rsa(metadata: Dict[str, Any], signature: bytes, public_key_pem: bytes) -> bool:
    """
    Проверка RSA-подписи
    """
    try:
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
        serialized = _serialize_metadata(metadata)
        public_key.verify(
            signature,
            serialized,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


# === Zero-Knowledge Placeholder ===

def zk_stub_sign(metadata: Dict[str, Any]) -> str:
    """
    Заглушка ZK-подписи для будущего zkSNARK/zkSTARK
    """
    serialized = _serialize_metadata(metadata)
    zk_hash = hashlib.sha256(serialized + b"zk").hexdigest()
    return f"zk::{zk_hash}"


def zk_stub_verify(metadata: Dict[str, Any], signature: str) -> bool:
    """
    Проверка ZK-заглушки (псевдо-проверка)
    """
    expected = zk_stub_sign(metadata)
    return signature == expected
