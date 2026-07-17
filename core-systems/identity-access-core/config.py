"""Fail-closed settings for the legacy Identity Access recovery runtime."""

from __future__ import annotations

import secrets
from typing import Any

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


UNSAFE_ADMIN_PASSWORDS = {
    "admin",
    "change_me",
    "change-me",
    "change_immediately",
    "password",
}


class IdentityAccessCoreEmergencyConfig(BaseSettings):
    """Validated recovery settings with privileged access disabled by default."""

    model_config = SettingsConfigDict(
        env_file=".env.emergency",
        env_prefix="IDENTITY_ACCESS_CORE_EMERGENCY_",
        case_sensitive=False,
        extra="ignore",
    )

    # Основные настройки
    system_name: str = Field(default="identity-access-core", description="Имя системы")
    version: str = Field(
        default="1.0.0-EMERGENCY",
        description="Версия системы (экстренная)",
    )
    emergency_mode: bool = Field(default=True, description="Экстренный режим")
    debug: bool = Field(default=False, description="Отладка")

    # Экстренные настройки логирования
    log_level: str = Field(
        default="CRITICAL",
        description="Уровень логирования (экстренный)",
    )
    log_format: str = Field(
        default="{time} | EMERGENCY | {level} | {message}",
        description="Формат экстренных логов",
    )
    emergency_log_retention: int = Field(
        default=90,
        description="Хранение экстренных логов (дней)",
    )

    # Настройки интеграции
    integration_enabled: bool = Field(
        default=True,
        description="Включить интеграцию с другими системами",
    )
    core_systems_path: str = Field(
        default="/workspaces/aethernova/core-systems",
        description="Путь к core-системам",
    )
    emergency_bypass_integration: bool = Field(
        default=True,
        description="Обходить недоступные интеграции",
    )

    # ЭКСТРЕННЫЕ настройки безопасности
    emergency_security_mode: bool = Field(
        default=True,
        description="Экстренный режим безопасности",
    )
    emergency_admin_enabled: bool = Field(
        default=False,
        description="Экстренный админ доступ",
    )
    emergency_encryption_key: str = Field(
        default_factory=lambda: secrets.token_hex(32),
        description="Экстренный ключ шифрования",
        repr=False,
    )
    emergency_session_timeout: int = Field(
        default=3600,
        description="Таймаут экстренных сессий (сек)",
    )

    # Экстренные настройки производительности
    emergency_processing_interval: float = Field(
        default=0.1,
        description="Интервал экстренной обработки (сек)",
    )
    emergency_backup_interval: int = Field(
        default=300,
        description="Интервал экстренного бэкапа (сек)",
    )
    emergency_health_check_interval: int = Field(
        default=30,
        description="Интервал экстренных health checks (сек)",
    )
    max_emergency_retries: int = Field(
        default=10,
        description="Максимум экстренных попыток",
    )

    # ЭКСТРЕННЫЕ Identity & Access настройки
    emergency_auth_bypass: bool = Field(
        default=False,
        description="Экстренный обход аутентификации",
    )
    emergency_admin_password: str | None = Field(
        default=None,
        description="Экстренный пароль админа",
        repr=False,
    )
    emergency_session_limit: int = Field(
        default=100,
        description="Лимит экстренных сессий",
    )
    emergency_mfa_disabled: bool = Field(
        default=False,
        description="Отключить MFA в экстренном режиме",
    )

    @model_validator(mode="after")
    def validate_privileged_recovery_access(
        self,
    ) -> "IdentityAccessCoreEmergencyConfig":
        if self.emergency_auth_bypass:
            raise ValueError("emergency authentication bypass is not supported")

        if not self.emergency_admin_enabled:
            return self

        password = self.emergency_admin_password
        if password is None or len(password) < 16:
            raise ValueError(
                "emergency admin requires an explicit password "
                "of at least 16 characters"
            )
        if password.strip().lower() in UNSAFE_ADMIN_PASSWORDS:
            raise ValueError("emergency admin password is an unsafe placeholder")
        if not self.emergency_mfa_disabled:
            raise ValueError(
                "legacy emergency admin has no MFA flow; enabling it requires "
                "explicit emergency_mfa_disabled=true acknowledgement"
            )
        return self

    def public_dict(self) -> dict[str, Any]:
        """Return settings safe for status responses, logs, and backups."""

        return self.model_dump(
            exclude={"emergency_admin_password", "emergency_encryption_key"}
        )


# Глобальный экземпляр ЭКСТРЕННОЙ конфигурации
config = IdentityAccessCoreEmergencyConfig()
