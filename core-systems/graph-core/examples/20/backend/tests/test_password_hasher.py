# backend/tests/test_password_hasher.py

import pytest
from backend.utils.password_hasher import PasswordHasher

def test_password_hashing_and_verification():
    password = "StrongPass123!"
    hasher = PasswordHasher()

    hashed = hasher.hash_password(password)
    assert isinstance(hashed, str)
    assert hashed != password  # Хэш должен отличаться от исходного пароля

    valid = hasher.verify_password(password, hashed)
    assert valid is True

    invalid = hasher.verify_password("WrongPassword", hashed)
    assert invalid is False

def test_hash_uniqueness():
    password = "RepeatedPassword"
    hasher = PasswordHasher()

    hash1 = hasher.hash_password(password)
    hash2 = hasher.hash_password(password)

    # Из-за соли хэши должны отличаться
    assert hash1 != hash2

if __name__ == "__main__":
    pytest.main()
