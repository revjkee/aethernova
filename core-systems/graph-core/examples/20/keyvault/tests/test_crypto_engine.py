# Тесты для модуля keyvault.core.crypto_engine
# Индустриальная верификация: криптографическая безопасность, скорость, ошибки шифрования

import pytest
from cryptography.exceptions import InvalidTag
from keyvault.core.crypto_engine import encrypt_data, decrypt_data, generate_key
import secrets

# === TEST CONFIGURATION ===
PLAINTEXT = b"TeslaAI must remain secure."
ASSOCIATED_DATA = b"vault-metadata"
AES_KEY_SIZE = 32  # 256 бит
NONCE_SIZE = 12    # для AES-GCM
XCHACHA_NONCE_SIZE = 24

@pytest.fixture
def aes_key():
    return generate_key("aes-256")

@pytest.fixture
def xchacha_key():
    return generate_key("xchacha20")

# === AES-256 TESTS ===

def test_encrypt_decrypt_aes_success(aes_key):
    ciphertext, nonce, tag = encrypt_data(PLAINTEXT, aes_key, "aes-256", ASSOCIATED_DATA)
    decrypted = decrypt_data(ciphertext, aes_key, nonce, tag, "aes-256", ASSOCIATED_DATA)
    assert decrypted == PLAINTEXT

def test_decrypt_aes_wrong_key(aes_key):
    ciphertext, nonce, tag = encrypt_data(PLAINTEXT, aes_key, "aes-256", ASSOCIATED_DATA)
    wrong_key = generate_key("aes-256")
    with pytest.raises(InvalidTag):
        decrypt_data(ciphertext, wrong_key, nonce, tag, "aes-256", ASSOCIATED_DATA)

def test_decrypt_aes_tampered_ciphertext(aes_key):
    ciphertext, nonce, tag = encrypt_data(PLAINTEXT, aes_key, "aes-256", ASSOCIATED_DATA)
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0xFF
    with pytest.raises(InvalidTag):
        decrypt_data(bytes(tampered), aes_key, nonce, tag, "aes-256", ASSOCIATED_DATA)

# === XChaCha20 TESTS ===

def test_encrypt_decrypt_xchacha_success(xchacha_key):
    ciphertext, nonce, tag = encrypt_data(PLAINTEXT, xchacha_key, "xchacha20", ASSOCIATED_DATA)
    decrypted = decrypt_data(ciphertext, xchacha_key, nonce, tag, "xchacha20", ASSOCIATED_DATA)
    assert decrypted == PLAINTEXT

def test_decrypt_xchacha_wrong_key(xchacha_key):
    ciphertext, nonce, tag = encrypt_data(PLAINTEXT, xchacha_key, "xchacha20", ASSOCIATED_DATA)
    wrong_key = generate_key("xchacha20")
    with pytest.raises(InvalidTag):
        decrypt_data(ciphertext, wrong_key, nonce, tag, "xchacha20", ASSOCIATED_DATA)

def test_decrypt_xchacha_tampered_tag(xchacha_key):
    ciphertext, nonce, tag = encrypt_data(PLAINTEXT, xchacha_key, "xchacha20", ASSOCIATED_DATA)
    tampered_tag = bytearray(tag)
    tampered_tag[-1] ^= 0xAA
    with pytest.raises(InvalidTag):
        decrypt_data(ciphertext, xchacha_key, nonce, bytes(tampered_tag), "xchacha20", ASSOCIATED_DATA)

# === NEGATIVE TESTS ===

@pytest.mark.parametrize("mode", ["invalidmode", "rsa", "des"])
def test_invalid_mode_raises(aes_key, mode):
    with pytest.raises(ValueError):
        encrypt_data(PLAINTEXT, aes_key, mode, ASSOCIATED_DATA)

# === ENTROPY TEST ===

def test_key_entropy_uniqueness():
    keys = {generate_key("aes-256") for _ in range(100)}
    assert len(keys) == 100, "Generated keys must be unique with high entropy"

# === EDGE CASES ===

def test_empty_plaintext_encryption(aes_key):
    ciphertext, nonce, tag = encrypt_data(b"", aes_key, "aes-256", ASSOCIATED_DATA)
    decrypted = decrypt_data(ciphertext, aes_key, nonce, tag, "aes-256", ASSOCIATED_DATA)
    assert decrypted == b""

def test_large_plaintext_encryption(aes_key):
    large_data = secrets.token_bytes(1024 * 1024)  # 1MB
    ciphertext, nonce, tag = encrypt_data(large_data, aes_key, "aes-256", ASSOCIATED_DATA)
    decrypted = decrypt_data(ciphertext, aes_key, nonce, tag, "aes-256", ASSOCIATED_DATA)
    assert decrypted == large_data
