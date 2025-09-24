# ueba/alerts/alert_schema.py
# Схема и структура UEBA алертов

from typing import Dict, Optional
from pydantic import BaseModel, Field, validator
from datetime import datetime
import re

VALID_LEVELS = {"info", "low", "medium", "high", "critical"}
VALID_ACTOR_TYPES = {"user", "service", "agent", "llm", "token"}

class Alert(BaseModel):
    id: str = Field(..., description="Уникальный UUID алерта")
    timestamp: str = Field(..., description="Временная метка UTC ISO 8601")
    level: str = Field(..., description="Уровень угрозы (info, low, medium, high, critical)")
    entity_id: str = Field(..., description="ID сущности (пользователь, сервис и т.п.)")
    actor_type: str = Field(..., description="Тип сущности (user, service, agent, llm, token)")
    score: float = Field(..., ge=0.0, le=1.0, description="Риск-скоринг по шкале 0.0–1.0")
    tag: str = Field(..., description="Метка или категория поведения/угрозы")
    metadata: Optional[Dict] = Field(default_factory=dict, description="Доп. контекст, включая сигнатуру поведения, правила и трассировку")

    @validator("timestamp")
    def validate_timestamp(cls, v):
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except Exception:
            raise ValueError("timestamp должен быть в формате ISO 8601")
        return v

    @validator("level")
    def validate_level(cls, v):
        if v not in VALID_LEVELS:
            raise ValueError(f"Неверный уровень: {v}")
        return v

    @validator("actor_type")
    def validate_actor_type(cls, v):
        if v not in VALID_ACTOR_TYPES:
            raise ValueError(f"actor_type должен быть одним из: {VALID_ACTOR_TYPES}")
        return v

    @validator("id")
    def validate_uuid(cls, v):
        uuid_regex = re.compile(r"^[a-f0-9\-]{36}$", re.IGNORECASE)
        if not uuid_regex.match(v):
            raise ValueError("id должен быть UUID v4 формата")
        return v

    @validator("tag")
    def validate_tag(cls, v):
        if not v or not isinstance(v, str):
            raise ValueError("tag должен быть непустой строкой")
        return v
