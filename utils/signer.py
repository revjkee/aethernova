# utils/signer.py

from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3
from hashlib import sha256
from typing import Union
import binascii
import hmac

class SigningError(Exception):
    pass

def sign_message(message: str, private_key: str) -> str:
    """
    Подписывает строку message приватным ключом Ethereum.

    Args:
        message (str): исходное сообщение
        private_key (str): приватный ключ в hex-формате

    Returns:
        str: подпись в hex
    """
    try:
        msg = encode_defunct(text=message)
        signed = Account.sign_message(msg, private_key=private_key)
        return signed.signature.hex()
    except Exception as e:
        raise SigningError(f"Signing failed: {e}")

def verify_signature(message: str, signature: str, expected_address: str) -> bool:
    """
    Проверяет соответствие подписи и адреса.

    Args:
        message (str): исходное сообщение
        signature (str): подпись в hex
        expected_address (str): ожидаемый адрес в формате 0x...

    Returns:
        bool: True, если верифицировано
    """
    try:
        msg = encode_defunct(text=message)
        recovered = Account.recover_message(msg, signature=signature)
        return Web3.to_checksum_address(recovered) == Web3.to_checksum_address(expected_address)
    except Exception:
        return False

def keccak_hash(data: Union[str, bytes]) -> str:
    """
    Вычисляет keccak256 хэш строки или байтов.

    Args:
        data (str | bytes): входные данные

    Returns:
        str: хэш в hex
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return Web3.keccak(data).hex()

def sha256_hash(data: Union[str, bytes]) -> str:
    """
    Вычисляет SHA256 хэш строки или байтов.

    Args:
        data (str | bytes): входные данные

    Returns:
        str: хэш в hex
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return sha256(data).hexdigest()

def hmac_sha256(secret: str, message: str) -> str:
    """
    HMAC-SHA256: симметричная подпись сообщений.

    Args:
        secret (str): ключ
        message (str): сообщение

    Returns:
        str: hex-подпись
    """
    return hmac.new(secret.encode(), message.encode(), sha256).hexdigest()
