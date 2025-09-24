# hr_ai/tests/test_auth.py

import pytest
from unittest.mock import patch, MagicMock
from hr_ai.auth.auth_service import AuthService, AuthError
from hr_ai.auth.token_utils import validate_token, decode_token
from datetime import datetime, timedelta


@pytest.fixture(scope="module")
def auth_service() -> AuthService:
    return AuthService(secret_key="TEST_SECRET", token_expiry_minutes=15)


@pytest.fixture
def valid_user_credentials() -> dict:
    return {"username": "testuser", "password": "securePass123"}


def test_generate_token_structure(auth_service, valid_user_credentials):
    token = auth_service.generate_token(**valid_user_credentials)
    assert isinstance(token, str)
    assert len(token.split(".")) == 3, "Token must be in JWT format"


def test_token_validation_success(auth_service, valid_user_credentials):
    token = auth_service.generate_token(**valid_user_credentials)
    is_valid = validate_token(token, secret_key="TEST_SECRET")
    assert is_valid is True


def test_token_validation_failure():
    invalid_token = "invalid.token.structure"
    is_valid = validate_token(invalid_token, secret_key="TEST_SECRET")
    assert is_valid is False


def test_token_expiry_behavior(auth_service, valid_user_credentials):
    token = auth_service.generate_token(**valid_user_credentials, expiry_minutes=-1)
    is_valid = validate_token(token, secret_key="TEST_SECRET")
    assert is_valid is False, "Expired token must be rejected"


def test_decode_token_fields(auth_service, valid_user_credentials):
    token = auth_service.generate_token(**valid_user_credentials)
    payload = decode_token(token, secret_key="TEST_SECRET")
    assert isinstance(payload, dict)
    assert "username" in payload
    assert payload["username"] == "testuser"


def test_authentication_success(auth_service, valid_user_credentials):
    token = auth_service.authenticate(**valid_user_credentials)
    assert isinstance(token, str)
    assert validate_token(token, secret_key="TEST_SECRET") is True


def test_authentication_failure(auth_service):
    with pytest.raises(AuthError, match="Invalid credentials"):
        auth_service.authenticate("invalid_user", "wrong_pass")


@patch("hr_ai.auth.auth_service.AuthService.generate_token")
def test_token_generation_invocation(mock_generate, auth_service):
    mock_generate.return_value = "mock.token.value"
    token = auth_service.generate_token("admin", "admin123")
    assert token == "mock.token.value"
    mock_generate.assert_called_once()
