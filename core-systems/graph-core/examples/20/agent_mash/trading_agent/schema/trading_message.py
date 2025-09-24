# trading_message.py

from enum import Enum
from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, validator


class ActionType(str, Enum):
    BUY = "buy"
    SELL = "sell"
    HOLD = "hold"
    CANCEL = "cancel"
    UPDATE = "update"


class SignalMessage(BaseModel):
    """
    Стандартизированное сообщение сигнала от стратегии
    """
    id: str = Field(..., description="Уникальный идентификатор сигнала (UUID)")
    strategy_name: str
    action: ActionType
    confidence: float = Field(..., ge=0.0, le=1.0)
    timestamp: datetime
    symbol: str
    price: float
    volume: float
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)

    @validator("confidence")
    def validate_confidence(cls, v):
        if v < 0 or v > 1:
            raise ValueError("Confidence must be in [0.0, 1.0]")
        return round(v, 4)


class ExecutionReport(BaseModel):
    """
    Отчёт о выполнении торгового сигнала
    """
    order_id: str
    signal_id: str
    executed_price: float
    executed_volume: float
    execution_time: datetime
    status: str
    error: Optional[str] = None
    latency_ms: Optional[int] = None


class TradeEvent(BaseModel):
    """
    Событие торговли для записи в журнал и передачи в аналитику
    """
    trade_id: str
    symbol: str
    action: ActionType
    price: float
    quantity: float
    pnl: Optional[float]
    timestamp: datetime
    strategy: Optional[str]
    comment: Optional[str] = None


class KafkaEnvelope(BaseModel):
    """
    Универсальная обёртка для передачи сообщений через брокер
    """
    topic: str
    payload: Dict[str, Any]
    schema_version: str = "1.0.0"
    timestamp: datetime = Field(default_factory=datetime.utcnow)
