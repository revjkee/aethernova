# TeslaAI WebUI — Industrial Settings v2.0
# Генерация 20 агентами и 3 метагенералами
# Обеспечивает безопасную, гибкую и защищённую конфигурацию UI слоя

import os
from pydantic import BaseSettings, Field, validator

class WebUISettings(BaseSettings):
    ENVIRONMENT: str = Field("development", env="WEBUI_ENV")
    UI_HOST: str = Field("0.0.0.0", env="WEBUI_HOST")
    UI_PORT: int = Field(8080, env="WEBUI_PORT")

    SESSION_SECRET_KEY: str = Field(..., env="WEBUI_SECRET_KEY")
    CSRF_TOKEN_EXPIRY: int = Field(900, description="в секундах", env="WEBUI_CSRF_TTL")

    ENABLE_WEBSOCKETS: bool = Field(True, env="WEBUI_WS_ENABLED")
    ENABLE_OAUTH: bool = Field(True, env="WEBUI_OAUTH_ENABLED")

    API_BASE_URL: str = Field("http://localhost:8000/api", env="WEBUI_API_URL")
    WEBSOCKET_URL: str = Field("ws://localhost:8000/ws", env="WEBUI_WS_URL")

    UI_THEME: str = Field("dark", env="WEBUI_THEME")  # dark | light | corporate

    @validator("SESSION_SECRET_KEY")
    def check_secret_key_strength(cls, v):
        if len(v) < 32:
            raise ValueError("SESSION_SECRET_KEY слишком короткий (минимум 32 символа)")
        return v

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


# Глобальный доступ к конфигурации
settings = WebUISettings()

# Защита от саботажа (проверка ключевых параметров)
if settings.is_production and settings.SESSION_SECRET_KEY == "REPLACE_ME":
    raise RuntimeError("Запуск в проде с небезопасным ключом сессии запрещён.")
