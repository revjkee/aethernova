# order_schema.py

from enum import Enum
from typing import Optional, Dict, Literal, Union
from datetime import datetime
from pydantic import BaseModel, Field, validator


class OrderType(str, Enum):
    MARKET = "market"
    LIMIT = "limit"
    STOP = "stop"
    STOP_LIMIT = "stop_limit"


class OrderSide(str, Enum):
    BUY = "buy"
    SELL = "sell"


class TimeInForce(str, Enum):
    GTC = "GTC"   # Good Till Canceled
    IOC = "IOC"   # Immediate or Cancel
    FOK = "FOK"   # Fill or Kill


class OrderStatus(str, Enum):
    PENDING = "pending"
    FILLED = "filled"
    CANCELLED = "cancelled"
    REJECTED = "rejected"
    EXPIRED = "expired"
    PARTIAL = "partial_fill"


class BrokerInfo(BaseModel):
    """
    Метаинформация о брокере и маршруте исполнения
    """
    broker_name: str = Field(..., example="Binance", description="Имя брокера или шлюза")
    api_endpoint: Optional[str]
    order_id: Optional[str]
    route_id: Optional[str]
    latency_ms: Optional[int]


class OrderRequest(BaseModel):
    """
    Запрос на размещение ордера
    """
    symbol: str
    side: OrderSide
    order_type: OrderType
    quantity: float = Field(..., gt=0)
    price: Optional[float] = Field(None, gt=0)
    stop_price: Optional[float] = Field(None, gt=0)
    time_in_force: Optional[TimeInForce] = TimeInForce.GTC
    client_order_id: Optional[str]
    strategy_tag: Optional[str]
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Optional[Dict[str, Union[str, float, int]]] = Field(default_factory=dict)

    @validator("price")
    def validate_limit_price(cls, v, values):
        if values.get("order_type") in {OrderType.LIMIT, OrderType.STOP_LIMIT} and v is None:
            raise ValueError("Price must be provided for LIMIT or STOP_LIMIT orders")
        return v


class OrderResponse(BaseModel):
    """
    Ответ на запрос ордера
    """
    status: OrderStatus
    order_id: str
    filled_quantity: float
    avg_fill_price: Optional[float]
    message: Optional[str]
    executed_at: datetime
    broker_info: BrokerInfo


class CancelOrderRequest(BaseModel):
    """
    Запрос на отмену ордера
    """
    order_id: str
    symbol: str
    strategy_tag: Optional[str]
    requested_at: datetime = Field(default_factory=datetime.utcnow)


class OrderEvent(BaseModel):
    """
    Событие, публикуемое брокером или системой мониторинга
    """
    event_type: Literal["submitted", "filled", "cancelled", "partial_fill", "error"]
    order_id: str
    timestamp: datetime
    detail: Dict[str, Union[str, float, int]]
