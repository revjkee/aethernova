from __future__ import annotations

import pytest
from pydantic import ValidationError

from config import IdentityAccessCoreEmergencyConfig
from src.authentication import AuthenticationService


def test_default_configuration_does_not_create_privileged_identity() -> None:
    settings = IdentityAccessCoreEmergencyConfig(_env_file=None)

    service = AuthenticationService(settings)

    assert settings.emergency_admin_enabled is False
    assert settings.emergency_auth_bypass is False
    assert service.get_user("emergency_admin") is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"emergency_auth_bypass": True},
        {
            "emergency_admin_enabled": True,
            "emergency_admin_password": "CHANGE_IMMEDIATELY",
            "emergency_mfa_disabled": True,
        },
        {
            "emergency_admin_enabled": True,
            "emergency_admin_password": "short",
            "emergency_mfa_disabled": True,
        },
        {
            "emergency_admin_enabled": True,
            "emergency_admin_password": "explicit-test-break-glass-password",
            "emergency_mfa_disabled": False,
        },
    ],
)
def test_unsafe_privileged_configuration_is_rejected(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        IdentityAccessCoreEmergencyConfig(_env_file=None, **overrides)


def test_public_settings_exclude_secret_material() -> None:
    settings = IdentityAccessCoreEmergencyConfig(
        _env_file=None,
        emergency_encryption_key="synthetic-encryption-secret",
        emergency_admin_password="synthetic-disabled-admin-password",
    )

    public = settings.public_dict()

    assert "emergency_encryption_key" not in public
    assert "emergency_admin_password" not in public
