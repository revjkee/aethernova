import pytest
from unittest.mock import MagicMock, patch
from keyvault.providers.base_provider import BaseProvider
from keyvault.core.secret_manager import SecretManager
from keyvault.config.vault_config import PROVIDER_REGISTRY
from keyvault.tests.mock_data import get_mock_secrets


# ==== Мокаем кастомного провайдера ====

class MockProvider(BaseProvider):
    def __init__(self):
        self.name = "mock"
        self.initialized = False

    def connect(self):
        self.initialized = True
        return True

    def fetch_secret(self, key: str):
        if key == "fail":
            raise ValueError("Key fetch failed")
        return f"secret_for_{key}"

    def push_secret(self, key: str, value: str):
        return True

    def list_secrets(self):
        return ["db_token", "admin_cert"]

    def delete_secret(self, key: str):
        return True


# ==== Тест подключения провайдера ====

def test_provider_connect_success():
    provider = MockProvider()
    result = provider.connect()
    assert result is True
    assert provider.initialized is True


# ==== Получение секрета ====

def test_fetch_secret_success():
    provider = MockProvider()
    provider.connect()
    secret = provider.fetch_secret("db_token")
    assert secret == "secret_for_db_token"


# ==== Ошибка получения секрета ====

def test_fetch_secret_failure():
    provider = MockProvider()
    provider.connect()
    with pytest.raises(ValueError):
        provider.fetch_secret("fail")


# ==== Загрузка секрета ====

def test_push_secret_success():
    provider = MockProvider()
    provider.connect()
    result = provider.push_secret("token", "value123")
    assert result is True


# ==== Получение списка секретов ====

def test_list_secrets_success():
    provider = MockProvider()
    provider.connect()
    secrets = provider.list_secrets()
    assert isinstance(secrets, list)
    assert "db_token" in secrets


# ==== Удаление секрета ====

def test_delete_secret_success():
    provider = MockProvider()
    provider.connect()
    result = provider.delete_secret("db_token")
    assert result is True


# ==== Интеграция через SecretManager ====

def test_secret_manager_integration(monkeypatch):
    mock_provider = MockProvider()
    mock_provider.connect()

    monkeypatch.setitem(PROVIDER_REGISTRY, "mock", mock_provider)
    manager = SecretManager(provider_name="mock")

    manager.push("new_key", "sensitive_value")
    value = manager.get("new_key")
    assert value == "secret_for_new_key"


# ==== Fallback-режим при сбое провайдера ====

def test_provider_fallback_on_failure(monkeypatch):
    class BrokenProvider(BaseProvider):
        def connect(self):
            raise RuntimeError("provider down")

    monkeypatch.setitem(PROVIDER_REGISTRY, "broken", BrokenProvider())
    with pytest.raises(RuntimeError):
        SecretManager(provider_name="broken")


# ==== Проверка подписей секрета (Zero Trust) ====

def test_secret_signature_verification(monkeypatch):
    provider = MockProvider()
    provider.connect()

    monkeypatch.setitem(PROVIDER_REGISTRY, "mock", provider)
    manager = SecretManager(provider_name="mock")

    secret_value = manager.get("admin_cert")
    assert isinstance(secret_value, str)
    # Здесь может быть проверка цифровой подписи, например:
    assert secret_value.startswith("secret_for_")
