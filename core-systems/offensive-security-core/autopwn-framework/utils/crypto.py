import hashlib
import hmac
import secrets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Хэширование SHA256
def sha256(data: bytes) -> bytes:
    """
    Возвращает SHA256 хэш от входных данных.
    """
    digest = hashlib.sha256()
    digest.update(data)
    return digest.digest()

# HMAC с SHA256
def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """
    Возвращает HMAC-SHA256 для данных с заданным ключом.
    """
    return hmac.new(key, data, hashlib.sha256).digest()

# Генерация случайного безопасного ключа
def generate_secure_key(length: int = 32) -> bytes:
    """
    Генерирует криптографически стойкий случайный ключ заданной длины в байтах.
    """
    return secrets.token_bytes(length)

# Симметричное шифрование AES-GCM
def aes_gcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = None) -> tuple[bytes, bytes, bytes]:
    """
    Шифрует данные с помощью AES-GCM.
    
    :return: (nonce, ciphertext, tag)
    """
    nonce = secrets.token_bytes(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
    ).encryptor()
    if associated_data:
        encryptor.authenticate_additional_data(associated_data)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return nonce, ciphertext, encryptor.tag

def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, associated_data: bytes = None) -> bytes:
    """
    Расшифровывает данные, зашифрованные AES-GCM.
    """
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
    ).decryptor()
    if associated_data:
        decryptor.authenticate_additional_data(associated_data)
    return decryptor.update(ciphertext) + decryptor.finalize()

# Генерация пары RSA ключей
def generate_rsa_keypair(key_size: int = 2048) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Генерирует RSA ключи.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key

# Подпись данных с помощью RSA и SHA256
def rsa_sign(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """
    Подписывает данные приватным ключом RSA.
    """
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256()
    )

# Проверка подписи RSA
def rsa_verify(public_key: rsa.RSAPublicKey, signature: bytes, data: bytes) -> bool:
    """
    Проверяет подпись.
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
