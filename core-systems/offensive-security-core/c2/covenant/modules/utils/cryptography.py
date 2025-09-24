# Шифрование/расшифровка
# cryptography.py
# Модуль для надёжного шифрования и расшифровки данных
# Используется современная криптография: AES-GCM для симметричного шифрования
# и RSA для асимметричного шифрования (ключи, подписи)

import os
from base64 import b64encode, b64decode
from typing import Tuple, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend


class SymmetricCrypto:
    """
    Класс для симметричного шифрования/расшифровки с помощью AES-GCM.
    Ключ должен быть 256 бит (32 байта).
    """

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Ключ должен быть длиной 32 байта (256 бит).")
        self.key = key
        self.aesgcm = AESGCM(self.key)

    def encrypt(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> str:
        """
        Шифрует данные, возвращает base64 строку: nonce + ciphertext + tag
        """
        nonce = os.urandom(12)  # 96 бит nonce, рекомендовано для GCM
        ct = self.aesgcm.encrypt(nonce, plaintext, associated_data)
        encrypted = nonce + ct
        return b64encode(encrypted).decode('utf-8')

    def decrypt(self, encrypted_b64: str, associated_data: Optional[bytes] = None) -> bytes:
        """
        Расшифровывает данные из base64 строки
        """
        encrypted = b64decode(encrypted_b64)
        nonce = encrypted[:12]
        ct = encrypted[12:]
        return self.aesgcm.decrypt(nonce, ct, associated_data)


class AsymmetricCrypto:
    """
    Класс для асимметричного шифрования и подписей с использованием RSA 4096 бит.
    """

    def __init__(self,
                 private_key_pem: Optional[bytes] = None,
                 public_key_pem: Optional[bytes] = None):
        if private_key_pem:
            self.private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            )
        else:
            self.private_key = None

        if public_key_pem:
            self.public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
        else:
            self.public_key = None

    @staticmethod
    def generate_keys() -> Tuple[bytes, bytes]:
        """
        Генерация пары ключей RSA 4096 бит, возвращает PEM private и public ключи
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_pem, public_pem

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Шифрование публичным ключом RSA (используется OAEP)
        """
        if not self.public_key:
            raise ValueError("Публичный ключ не инициализирован")

        ciphertext = self.public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Расшифровка приватным ключом RSA
        """
        if not self.private_key:
            raise ValueError("Приватный ключ не инициализирован")

        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    def sign(self, message: bytes) -> bytes:
        """
        Создать цифровую подпись сообщения приватным ключом
        """
        if not self.private_key:
            raise ValueError("Приватный ключ не инициализирован")

        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Проверка цифровой подписи сообщению с помощью публичного ключа
        """
        if not self.public_key:
            raise ValueError("Публичный ключ не инициализирован")
        try:
            self.public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
