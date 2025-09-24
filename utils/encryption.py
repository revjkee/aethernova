# utils/encryption.py

import os
from typing import Tuple, Union
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode


AES_KEY_SIZE = 32  # 256 bits
AES_IV_SIZE = 12   # 96 bits, recommended for GCM


def generate_aes_key() -> bytes:
    """Генерирует безопасный AES256 ключ"""
    return os.urandom(AES_KEY_SIZE)


def generate_iv() -> bytes:
    """Генерация безопасного IV для AES-GCM"""
    return os.urandom(AES_IV_SIZE)


def aes_encrypt(plaintext: Union[str, bytes], key: bytes, iv: bytes) -> Tuple[str, str]:
    """
    Шифрует данные через AES-256-GCM

    Returns:
        ciphertext_b64, tag_b64
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()

    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return b64encode(ciphertext).decode(), b64encode(encryptor.tag).decode()


def aes_decrypt(ciphertext_b64: str, tag_b64: str, key: bytes, iv: bytes) -> str:
    """Расшифровка данных через AES-GCM"""
    ciphertext = b64decode(ciphertext_b64)
    tag = b64decode(tag_b64)

    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()


def sha256_hash(data: Union[str, bytes]) -> str:
    """SHA-256 хэш от строки или байтов"""
    if isinstance(data, str):
        data = data.encode()
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize().hex()


def hmac_sign(key: bytes, data: Union[str, bytes]) -> str:
    """Подписывает данные через HMAC-SHA256"""
    if isinstance(data, str):
        data = data.encode()
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize().hex()


def verify_hmac(key: bytes, data: Union[str, bytes], signature: str) -> bool:
    """Проверка HMAC-подписи"""
    try:
        if isinstance(data, str):
            data = data.encode()
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        h.verify(bytes.fromhex(signature))
        return True
    except Exception:
        return False
