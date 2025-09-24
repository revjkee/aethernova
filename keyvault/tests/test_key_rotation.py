import pytest
from datetime import datetime, timedelta
from unittest.mock import patch

from keyvault.core.key_lifecycle import (
    generate_key_pair,
    rotate_key,
    revoke_key,
    is_key_expired,
    schedule_next_rotation,
)
from keyvault.config.key_rotation_schedule import ROTATION_POLICY
from keyvault.core.crypto_engine import encrypt_data, decrypt_data


# ==== Генерация ключей ====

def test_generate_key_pair_integrity():
    key_pair = generate_key_pair(alg="ed25519")
    assert "public_key" in key_pair
    assert "private_key" in key_pair
    assert key_pair["public_key"] != ""
    assert key_pair["private_key"] != ""


# ==== Ротация по расписанию ====

def test_schedule_next_rotation_returns_isoformat():
    iso_time = schedule_next_rotation(interval_days=30)
    assert isinstance(iso_time, str)
    assert datetime.fromisoformat(iso_time)


# ==== Проверка срока действия ====

def test_key_expiry_check():
    past_time = (datetime.utcnow() - timedelta(days=10)).isoformat()
    future_time = (datetime.utcnow() + timedelta(days=10)).isoformat()

    assert is_key_expired(past_time) is True
    assert is_key_expired(future_time) is False


# ==== Ротация ключа вручную ====

def test_rotate_key_success(monkeypatch):
    old_key = {"public_key": "old_pub", "private_key": "old_priv", "created": datetime.utcnow().isoformat()}
    monkeypatch.setattr("keyvault.core.key_lifecycle.generate_key_pair", lambda alg="ed25519": {"public_key": "new_pub", "private_key": "new_priv"})

    new_key = rotate_key(old_key, reason="scheduled_rotation")
    assert new_key["public_key"] == "new_pub"
    assert new_key["reason"] == "scheduled_rotation"


# ==== Аварийная замена ключа ====

def test_rotate_key_emergency(monkeypatch):
    old_key = {"public_key": "old_pub", "private_key": "old_priv", "created": datetime.utcnow().isoformat()}
    monkeypatch.setattr("keyvault.core.key_lifecycle.generate_key_pair", lambda alg="ed25519": {"public_key": "em_pub", "private_key": "em_priv"})

    em_key = rotate_key(old_key, reason="compromise_detected")
    assert em_key["reason"] == "compromise_detected"
    assert em_key["public_key"] == "em_pub"


# ==== Удаление ключа ====

def test_key_revocation_sets_flag():
    key = {"public_key": "pub", "revoked": False}
    revoked_key = revoke_key(key, reason="retired")
    assert revoked_key["revoked"] is True
    assert revoked_key["revoke_reason"] == "retired"


# ==== Проверка сквозного шифрования с новым ключом ====

def test_encryption_decryption_after_rotation():
    key = generate_key_pair()
    plaintext = b"secret message"

    encrypted = encrypt_data(plaintext, key["public_key"])
    decrypted = decrypt_data(encrypted, key["private_key"])
    assert decrypted == plaintext


# ==== Пограничные случаи ====

def test_rotation_with_missing_fields():
    key = {}
    with pytest.raises(KeyError):
        rotate_key(key)

def test_revocation_without_reason_fails():
    key = {"public_key": "x", "revoked": False}
    with pytest.raises(ValueError):
        revoke_key(key, reason=None)
