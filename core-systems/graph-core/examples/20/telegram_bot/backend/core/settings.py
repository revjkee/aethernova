from pydantic_settings import BaseSettings
from pydantic import Field, validator
from typing import List, Optional


class Settings(BaseSettings):
    """
    Главные настройки приложения, загружаются из переменных окружения и .env файла.
    """

    telegram_token: str = Field(..., env="TELEGRAM_TOKEN")
    redis_url: str = Field("redis://localhost:6379/0", env="REDIS_URL")
    database_url: str = Field(..., env="DATABASE_URL")
    admin_ids: List[int] = Field(default_factory=list, env="ADMIN_IDS")

    # Дополнительные поля из окружения
    ton_payment_token: Optional[str] = Field(None, env="TON_PAYMENT_TOKEN")
    webapp_url: Optional[str] = Field(None, env="WEBAPP_URL")
    postgres_user: Optional[str] = Field(None, env="POSTGRES_USER")
    postgres_password: Optional[str] = Field(None, env="POSTGRES_PASSWORD")
    postgres_db: Optional[str] = Field(None, env="POSTGRES_DB")
    rabbitmq_user: Optional[str] = Field(None, env="RABBITMQ_USER")
    rabbitmq_password: Optional[str] = Field(None, env="RABBITMQ_PASSWORD")

    @validator("admin_ids", pre=True)
    def parse_admin_ids(cls, v):
        if isinstance(v, str):
            return [int(i.strip()) for i in v.split(",") if i.strip().isdigit()]
        if isinstance(v, list):
            return v
        return []

    class Config:
        env_file = "/app/.env"
        env_file_encoding = "utf-8"
        extra = "ignore"


settings = Settings()

# Отладочный вывод
print("Loaded settings:", settings.model_dump())
