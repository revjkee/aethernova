from pydantic import Field, validator
from pydantic_settings import BaseSettings
from typing import List


class BotConfig(BaseSettings):
    telegram_token: str = Field(..., env="TELEGRAM_TOKEN")
    ton_payment_token: str = Field(..., env="TON_PAYMENT_TOKEN")
    database_url: str = Field(..., env="DATABASE_URL")
    webapp_url: str = Field(..., env="WEBAPP_URL")
    postgres_user: str = Field(..., env="POSTGRES_USER")
    postgres_password: str = Field(..., env="POSTGRES_PASSWORD")
    postgres_db: str = Field(..., env="POSTGRES_DB")
    rabbitmq_user: str = Field(..., env="RABBITMQ_USER")
    rabbitmq_password: str = Field(..., env="RABBITMQ_PASSWORD")
    redis_url: str = Field("redis://localhost:6379/0", env="REDIS_URL")
    admin_ids: List[int] = Field(default_factory=list, env="ADMIN_IDS")
    telegram_webapp_url: str = Field(default="https://your-webapp-domain.com", env="TELEGRAM_WEBAPP_URL")

    @validator("admin_ids", pre=True)
    def parse_admin_ids(cls, v):
        if isinstance(v, str):
            return [int(i.strip()) for i in v.split(",") if i.strip().isdigit()]
        if isinstance(v, list):
            return v
        return []

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        allow_population_by_field_name = True


config = BotConfig()
