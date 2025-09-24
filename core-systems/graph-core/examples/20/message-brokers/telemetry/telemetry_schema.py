# message-brokers/telemetry/telemetry_schema.py

from enum import Enum
from typing import Optional, List, Dict, Union
from pydantic import BaseModel, Field, conint, constr
from datetime import datetime


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TelemetryType(str, Enum):
    LATENCY = "latency"
    ANOMALY = "anomaly"
    SECURITY = "security"
    USAGE = "usage"
    CUSTOM = "custom"


class EntityType(str, Enum):
    USER = "user"
    AGENT = "agent"
    SERVICE = "service"
    TOKEN = "token"


class TelemetryPacket(BaseModel):
    """
    Стандартизированная телеметрия для системы обработки событий и рисков.
    """
    event_id: constr(min_length=8, max_length=64)
    event_type: TelemetryType
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    risk_level: RiskLevel
    source: str = Field(..., description="Источник события: имя сервиса или компонента")
    entity_id: Optional[str] = Field(None, description="ID пользователя, агента, токена и т.д.")
    entity_type: Optional[EntityType] = None
    tags: Optional[List[str]] = []
    metrics: Optional[Dict[str, Union[float, int]]] = {}
    metadata: Optional[Dict[str, str]] = {}
    signed: Optional[bool] = Field(default=True, description="Была ли верифицирована подпись")
    trace_id: Optional[str] = Field(None, description="Trace ID для связывания событий")
    span_id: Optional[str] = None

    class Config:
        schema_extra = {
            "example": {
                "event_id": "evt_abc1234567",
                "event_type": "anomaly",
                "timestamp": "2025-07-25T11:04:52.123Z",
                "risk_level": "high",
                "source": "ai_inference_service",
                "entity_id": "user_5471",
                "entity_type": "user",
                "tags": ["llm", "command_injection"],
                "metrics": {"latency_ms": 472, "tokens_used": 129},
                "metadata": {"node": "gpu-4-europe", "model": "gpt-neoX"},
                "signed": True,
                "trace_id": "trc-7efb2",
                "span_id": "spn-01c8a"
            }
        }
