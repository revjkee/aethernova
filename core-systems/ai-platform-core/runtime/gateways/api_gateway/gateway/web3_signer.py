from typing import Optional
from fastapi import HTTPException
from eth_account import Account
from eth_account.messages import encode_defunct

class Web3SignerVerifier:
    def __init__(self):
        pass

    def verify_signature(self, message: str, signature: str, expected_address: str) -> bool:
        """
        Проверяет подпись пользователя Web3 (например, Metamask).

        message: оригинальное сообщение, которое подписывалось
        signature: цифровая подпись в формате hex
        expected_address: Ethereum адрес пользователя, с которым сравнивается

        Возвращает True, если подпись валидна и соответствует адресу, иначе False.
        """
        try:
            message_encoded = encode_defunct(text=message)
            recovered_address = Account.recover_message(message_encoded, signature=signature)
            return recovered_address.lower() == expected_address.lower()
        except Exception:
            return False

def web3_auth_middleware(message: str, signature: str, expected_address: str):
    verifier = Web3SignerVerifier()
    if not verifier.verify_signature(message, signature, expected_address):
        raise HTTPException(status_code=403, detail="Invalid Web3 signature")

