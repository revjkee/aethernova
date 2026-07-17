"""Runtime settings for Aethernova Observability Core."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class ObservabilityCoreConfig(BaseSettings):
    """Validated settings loaded from environment variables or ``.env``."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="OBSERVABILITY_CORE_",
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore",
    )

    system_name: str = "observability-core"
    version: str = "1.1.0"
    environment: str = "development"
    debug: bool = False

    log_level: str = "INFO"
    collection_interval_seconds: float = Field(default=15.0, gt=0)
    alert_check_interval_seconds: float = Field(default=30.0, gt=0)
    trace_sampling_rate: float = Field(default=0.1, ge=0.0, le=1.0)
    retention_days: int = Field(default=30, ge=1)

    integration_enabled: bool = True
    core_systems_path: Path = Field(default_factory=lambda: Path.cwd().parent)
    integration_systems: list[str] = Field(
        default_factory=lambda: ["engine-core", "automation-core", "resilience-core"]
    )
    required_systems: list[str] = Field(default_factory=list)

    security_enabled: bool = True
    encryption_key: SecretStr | None = None

    def public_dict(self) -> dict[str, Any]:
        """Return configuration safe for status endpoints and logs."""

        return self.model_dump(exclude={"encryption_key"})


config = ObservabilityCoreConfig()
