# agent_mash/interfaces/contracts.py
# Industrial contracts for agent_mash ecosystem.
# Standard-library first. Optional Pydantic v2 support when available.

from __future__ import annotations

import abc
import dataclasses
import datetime as _dt
import decimal as _dec
import enum
import json
import math
import os
import typing as t
import uuid


__all__ = [
    # core primitives
    "ContractError",
    "ValidationError",
    "SerializationError",
    "InvariantError",
    "NotSupportedError",
    "TimeoutError",
    "NotFoundError",
    "UnauthorizedError",
    "ConflictError",
    "RateLimitError",
    "ExternalServiceError",
    "IdempotencyError",
    "ensure",
    "utcnow",
    "is_utc",
    "as_utc",
    "isoformat_z",
    "json_dumps",
    "json_loads",
    # ids
    "TraceId",
    "RequestId",
    "TenantId",
    "UserId",
    "AgentId",
    "RunId",
    "ModelId",
    "DatasetId",
    "StrategyId",
    "OrderId",
    "PositionId",
    "ExecutionId",
    # enums
    "Severity",
    "EventKind",
    "AssetClass",
    "OrderSide",
    "OrderType",
    "TimeInForce",
    "OrderStatus",
    "PositionSide",
    "Decision",
    "RiskLevel",
    # value objects
    "Money",
    "Asset",
    "Instrument",
    "MarketMeta",
    "Quote",
    "Candle",
    "Position",
    "Order",
    "Fill",
    "RiskSignal",
    "PolicyDecision",
    "Action",
    "Observation",
    "Reward",
    "EpisodeMetrics",
    "BacktestResult",
    # event/audit
    "Event",
    "AuditRecord",
    "ErrorEnvelope",
    # protocols
    "Clock",
    "Logger",
    "Metrics",
    "EventBus",
    "KVStore",
    "BlobStore",
    "FeatureStore",
    "Broker",
    "Exchange",
    "Strategy",
    "Planner",
    "Memory",
    "Policy",
    "RiskEngine",
    "Backtester",
]

# Optional Pydantic v2 integration
_PYDANTIC_AVAILABLE = False
try:
    from pydantic import BaseModel as _PBaseModel  # type: ignore
    from pydantic import ConfigDict as _PConfigDict  # type: ignore
    from pydantic import Field as _PField  # type: ignore

    _PYDANTIC_AVAILABLE = True
except Exception:
    _PBaseModel = object  # type: ignore
    _PConfigDict = object  # type: ignore
    _PField = lambda default=None, **kwargs: default  # type: ignore


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ContractError(Exception):
    """Base exception for all contract-layer errors."""


class ValidationError(ContractError):
    """Raised when input fails validation."""


class SerializationError(ContractError):
    """Raised when serialization/deserialization fails."""


class InvariantError(ContractError):
    """Raised when an invariant is violated at runtime."""


class NotSupportedError(ContractError):
    """Raised when an operation is not supported by an implementation."""


class TimeoutError(ContractError):
    """Raised when an operation times out."""


class NotFoundError(ContractError):
    """Raised when a resource was not found."""


class UnauthorizedError(ContractError):
    """Raised when authentication/authorization fails."""


class ConflictError(ContractError):
    """Raised on conflict (optimistic locking, already exists, etc.)."""


class RateLimitError(ContractError):
    """Raised on rate limiting."""


class ExternalServiceError(ContractError):
    """Raised when an external dependency fails."""


class IdempotencyError(ContractError):
    """Raised when idempotency semantics are violated."""


def ensure(cond: bool, msg: str, exc: type[Exception] = InvariantError) -> None:
    if not cond:
        raise exc(msg)


# ---------------------------------------------------------------------------
# Time helpers (UTC only)
# ---------------------------------------------------------------------------


def utcnow() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


def is_utc(dt: _dt.datetime) -> bool:
    return dt.tzinfo is not None and dt.tzinfo.utcoffset(dt) == _dt.timedelta(0)


def as_utc(dt: _dt.datetime) -> _dt.datetime:
    if dt.tzinfo is None:
        raise ValidationError("datetime must be timezone-aware (UTC required)")
    return dt.astimezone(_dt.timezone.utc)


def isoformat_z(dt: _dt.datetime) -> str:
    dt_utc = as_utc(dt)
    s = dt_utc.isoformat(timespec="milliseconds")
    if s.endswith("+00:00"):
        s = s[:-6] + "Z"
    return s


# ---------------------------------------------------------------------------
# JSON helpers (stable, safe defaults)
# ---------------------------------------------------------------------------


def _json_default(obj: object) -> object:
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    if isinstance(obj, (uuid.UUID,)):
        return str(obj)
    if isinstance(obj, _dt.datetime):
        return isoformat_z(obj)
    if isinstance(obj, _dt.date):
        return obj.isoformat()
    if isinstance(obj, _dt.timedelta):
        return obj.total_seconds()
    if isinstance(obj, _dec.Decimal):
        return str(obj)
    if isinstance(obj, enum.Enum):
        return obj.value
    if hasattr(obj, "to_dict") and callable(getattr(obj, "to_dict")):
        return t.cast(t.Any, obj).to_dict()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def json_dumps(payload: object, *, sort_keys: bool = True) -> str:
    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=sort_keys,
            default=_json_default,
        )
    except Exception as e:
        raise SerializationError(f"json_dumps failed: {e}") from e


def json_loads(payload: str) -> object:
    try:
        return json.loads(payload)
    except Exception as e:
        raise SerializationError(f"json_loads failed: {e}") from e


# ---------------------------------------------------------------------------
# Strong IDs (NewType)
# ---------------------------------------------------------------------------

TraceId = t.NewType("TraceId", str)
RequestId = t.NewType("RequestId", str)
TenantId = t.NewType("TenantId", str)
UserId = t.NewType("UserId", str)

AgentId = t.NewType("AgentId", str)
RunId = t.NewType("RunId", str)
ModelId = t.NewType("ModelId", str)
DatasetId = t.NewType("DatasetId", str)
StrategyId = t.NewType("StrategyId", str)

OrderId = t.NewType("OrderId", str)
PositionId = t.NewType("PositionId", str)
ExecutionId = t.NewType("ExecutionId", str)


def _new_id(prefix: str) -> str:
    # Prefix + ULID-like sortable timestamp + uuid4 for uniqueness
    ts = utcnow().strftime("%Y%m%d%H%M%S%f")
    return f"{prefix}_{ts}_{uuid.uuid4().hex}"


def new_trace_id() -> TraceId:
    return TraceId(_new_id("trc"))


def new_request_id() -> RequestId:
    return RequestId(_new_id("req"))


def new_run_id() -> RunId:
    return RunId(_new_id("run"))


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Severity(str, enum.Enum):
    debug = "debug"
    info = "info"
    warning = "warning"
    error = "error"
    critical = "critical"


class EventKind(str, enum.Enum):
    # system
    heartbeat = "heartbeat"
    health = "health"
    metric = "metric"
    audit = "audit"
    # trading
    market = "market"
    signal = "signal"
    decision = "decision"
    order = "order"
    fill = "fill"
    position = "position"
    risk = "risk"
    # backtesting
    backtest = "backtest"
    # errors
    error = "error"


class AssetClass(str, enum.Enum):
    crypto = "crypto"
    fx = "fx"
    equity = "equity"
    futures = "futures"
    options = "options"
    commodity = "commodity"
    index = "index"
    other = "other"


class OrderSide(str, enum.Enum):
    buy = "buy"
    sell = "sell"


class OrderType(str, enum.Enum):
    market = "market"
    limit = "limit"
    stop = "stop"
    stop_limit = "stop_limit"
    take_profit = "take_profit"
    take_profit_limit = "take_profit_limit"


class TimeInForce(str, enum.Enum):
    gtc = "gtc"  # good till canceled
    ioc = "ioc"  # immediate or cancel
    fok = "fok"  # fill or kill
    day = "day"


class OrderStatus(str, enum.Enum):
    new = "new"
    accepted = "accepted"
    partially_filled = "partially_filled"
    filled = "filled"
    canceled = "canceled"
    rejected = "rejected"
    expired = "expired"


class PositionSide(str, enum.Enum):
    long = "long"
    short = "short"
    flat = "flat"


class Decision(str, enum.Enum):
    allow = "allow"
    deny = "deny"
    abstain = "abstain"


class RiskLevel(str, enum.Enum):
    none = "none"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


# ---------------------------------------------------------------------------
# Models (dataclasses + optional Pydantic wrappers)
# ---------------------------------------------------------------------------

Decimal = _dec.Decimal


def _d(x: t.Union[str, int, float, Decimal]) -> Decimal:
    if isinstance(x, Decimal):
        return x
    if isinstance(x, int):
        return Decimal(x)
    if isinstance(x, float):
        if not math.isfinite(x):
            raise ValidationError("float must be finite")
        return Decimal(str(x))
    if isinstance(x, str):
        try:
            return Decimal(x)
        except Exception as e:
            raise ValidationError(f"invalid decimal: {x}") from e
    raise ValidationError(f"unsupported decimal input: {type(x).__name__}")


def _non_empty(s: str, field: str) -> str:
    if not isinstance(s, str) or not s.strip():
        raise ValidationError(f"{field} must be a non-empty string")
    return s.strip()


def _non_negative(dv: Decimal, field: str) -> Decimal:
    if dv < 0:
        raise ValidationError(f"{field} must be >= 0")
    return dv


def _positive(dv: Decimal, field: str) -> Decimal:
    if dv <= 0:
        raise ValidationError(f"{field} must be > 0")
    return dv


@dataclasses.dataclass(frozen=True, slots=True)
class Money:
    amount: Decimal
    currency: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "currency", _non_empty(self.currency, "currency"))
        object.__setattr__(self, "amount", _d(self.amount))

    def to_dict(self) -> dict[str, t.Any]:
        return {"amount": str(self.amount), "currency": self.currency}


@dataclasses.dataclass(frozen=True, slots=True)
class Asset:
    symbol: str
    asset_class: AssetClass = AssetClass.other

    def __post_init__(self) -> None:
        object.__setattr__(self, "symbol", _non_empty(self.symbol, "symbol"))

    def to_dict(self) -> dict[str, t.Any]:
        return {"symbol": self.symbol, "asset_class": self.asset_class.value}


@dataclasses.dataclass(frozen=True, slots=True)
class Instrument:
    base: Asset
    quote: Asset
    venue: str  # exchange/broker identifier
    symbol: str  # canonical symbol at venue
    lot_size: Decimal = Decimal("1")

    def __post_init__(self) -> None:
        object.__setattr__(self, "venue", _non_empty(self.venue, "venue"))
        object.__setattr__(self, "symbol", _non_empty(self.symbol, "symbol"))
        object.__setattr__(self, "lot_size", _positive(_d(self.lot_size), "lot_size"))

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "base": self.base.to_dict(),
            "quote": self.quote.to_dict(),
            "venue": self.venue,
            "symbol": self.symbol,
            "lot_size": str(self.lot_size),
        }


@dataclasses.dataclass(frozen=True, slots=True)
class MarketMeta:
    instrument: Instrument
    tick_size: Decimal
    min_qty: Decimal
    max_qty: Decimal | None = None
    min_notional: Decimal | None = None
    price_precision: int | None = None
    qty_precision: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "tick_size", _positive(_d(self.tick_size), "tick_size"))
        object.__setattr__(self, "min_qty", _positive(_d(self.min_qty), "min_qty"))
        if self.max_qty is not None:
            object.__setattr__(self, "max_qty", _positive(_d(self.max_qty), "max_qty"))
            ensure(self.max_qty >= self.min_qty, "max_qty must be >= min_qty", ValidationError)
        if self.min_notional is not None:
            object.__setattr__(self, "min_notional", _positive(_d(self.min_notional), "min_notional"))
        if self.price_precision is not None:
            ensure(self.price_precision >= 0, "price_precision must be >= 0", ValidationError)
        if self.qty_precision is not None:
            ensure(self.qty_precision >= 0, "qty_precision must be >= 0", ValidationError)

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "instrument": self.instrument.to_dict(),
            "tick_size": str(self.tick_size),
            "min_qty": str(self.min_qty),
            "max_qty": str(self.max_qty) if self.max_qty is not None else None,
            "min_notional": str(self.min_notional) if self.min_notional is not None else None,
            "price_precision": self.price_precision,
            "qty_precision": self.qty_precision,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class Quote:
    instrument: Instrument
    ts: _dt.datetime
    bid: Decimal
    ask: Decimal
    bid_size: Decimal | None = None
    ask_size: Decimal | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "ts", as_utc(self.ts))
        object.__setattr__(self, "bid", _positive(_d(self.bid), "bid"))
        object.__setattr__(self, "ask", _positive(_d(self.ask), "ask"))
        ensure(self.ask >= self.bid, "ask must be >= bid", ValidationError)
        if self.bid_size is not None:
            object.__setattr__(self, "bid_size", _non_negative(_d(self.bid_size), "bid_size"))
        if self.ask_size is not None:
            object.__setattr__(self, "ask_size", _non_negative(_d(self.ask_size), "ask_size"))

    def mid(self) -> Decimal:
        return (self.bid + self.ask) / Decimal(2)

    def spread(self) -> Decimal:
        return self.ask - self.bid

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "instrument": self.instrument.to_dict(),
            "ts": isoformat_z(self.ts),
            "bid": str(self.bid),
            "ask": str(self.ask),
            "bid_size": str(self.bid_size) if self.bid_size is not None else None,
            "ask_size": str(self.ask_size) if self.ask_size is not None else None,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class Candle:
    instrument: Instrument
    ts_open: _dt.datetime
    ts_close: _dt.datetime
    o: Decimal
    h: Decimal
    l: Decimal
    c: Decimal
    v: Decimal | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "ts_open", as_utc(self.ts_open))
        object.__setattr__(self, "ts_close", as_utc(self.ts_close))
        ensure(self.ts_close > self.ts_open, "ts_close must be > ts_open", ValidationError)

        o = _positive(_d(self.o), "o")
        h = _positive(_d(self.h), "h")
        l = _positive(_d(self.l), "l")
        c = _positive(_d(self.c), "c")

        ensure(h >= max(o, c, l), "h must be >= o/c/l", ValidationError)
        ensure(l <= min(o, c, h), "l must be <= o/c/h", ValidationError)

        object.__setattr__(self, "o", o)
        object.__setattr__(self, "h", h)
        object.__setattr__(self, "l", l)
        object.__setattr__(self, "c", c)

        if self.v is not None:
            object.__setattr__(self, "v", _non_negative(_d(self.v), "v"))

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "instrument": self.instrument.to_dict(),
            "ts_open": isoformat_z(self.ts_open),
            "ts_close": isoformat_z(self.ts_close),
            "o": str(self.o),
            "h": str(self.h),
            "l": str(self.l),
            "c": str(self.c),
            "v": str(self.v) if self.v is not None else None,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class Position:
    position_id: PositionId
    instrument: Instrument
    side: PositionSide
    qty: Decimal
    avg_price: Decimal | None
    opened_at: _dt.datetime
    updated_at: _dt.datetime
    realized_pnl: Decimal = Decimal("0")
    unrealized_pnl: Decimal | None = None
    meta: dict[str, t.Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "opened_at", as_utc(self.opened_at))
        object.__setattr__(self, "updated_at", as_utc(self.updated_at))
        ensure(self.updated_at >= self.opened_at, "updated_at must be >= opened_at", ValidationError)

        qty = _d(self.qty)
        ensure(qty >= 0, "qty must be >= 0", ValidationError)
        object.__setattr__(self, "qty", qty)

        if self.side == PositionSide.flat:
            ensure(qty == 0, "flat position must have qty=0", ValidationError)
        else:
            ensure(qty > 0, "non-flat position must have qty>0", ValidationError)

        if self.avg_price is not None:
            object.__setattr__(self, "avg_price", _positive(_d(self.avg_price), "avg_price"))

        object.__setattr__(self, "realized_pnl", _d(self.realized_pnl))
        if self.unrealized_pnl is not None:
            object.__setattr__(self, "unrealized_pnl", _d(self.unrealized_pnl))

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "position_id": str(self.position_id),
            "instrument": self.instrument.to_dict(),
            "side": self.side.value,
            "qty": str(self.qty),
            "avg_price": str(self.avg_price) if self.avg_price is not None else None,
            "opened_at": isoformat_z(self.opened_at),
            "updated_at": isoformat_z(self.updated_at),
            "realized_pnl": str(self.realized_pnl),
            "unrealized_pnl": str(self.unrealized_pnl) if self.unrealized_pnl is not None else None,
            "meta": self.meta,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class Order:
    order_id: OrderId
    instrument: Instrument
    side: OrderSide
    order_type: OrderType
    time_in_force: TimeInForce
    qty: Decimal
    price: Decimal | None = None
    stop_price: Decimal | None = None
    status: OrderStatus = OrderStatus.new
    created_at: _dt.datetime = dataclasses.field(default_factory=utcnow)
    updated_at: _dt.datetime = dataclasses.field(default_factory=utcnow)
    client_order_id: str | None = None
    idempotency_key: str | None = None
    meta: dict[str, t.Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "created_at", as_utc(self.created_at))
        object.__setattr__(self, "updated_at", as_utc(self.updated_at))
        ensure(self.updated_at >= self.created_at, "updated_at must be >= created_at", ValidationError)

        qty = _positive(_d(self.qty), "qty")
        object.__setattr__(self, "qty", qty)

        if self.price is not None:
            object.__setattr__(self, "price", _positive(_d(self.price), "price"))
        if self.stop_price is not None:
            object.__setattr__(self, "stop_price", _positive(_d(self.stop_price), "stop_price"))

        if self.order_type in (OrderType.limit, OrderType.stop_limit, OrderType.take_profit_limit):
            ensure(self.price is not None, "limit-style order requires price", ValidationError)

        if self.order_type in (OrderType.stop, OrderType.stop_limit, OrderType.take_profit, OrderType.take_profit_limit):
            ensure(self.stop_price is not None, "stop/tp order requires stop_price", ValidationError)

        if self.client_order_id is not None:
            object.__setattr__(self, "client_order_id", _non_empty(self.client_order_id, "client_order_id"))
        if self.idempotency_key is not None:
            object.__setattr__(self, "idempotency_key", _non_empty(self.idempotency_key, "idempotency_key"))

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "order_id": str(self.order_id),
            "instrument": self.instrument.to_dict(),
            "side": self.side.value,
            "order_type": self.order_type.value,
            "time_in_force": self.time_in_force.value,
            "qty": str(self.qty),
            "price": str(self.price) if self.price is not None else None,
            "stop_price": str(self.stop_price) if self.stop_price is not None else None,
            "status": self.status.value,
            "created_at": isoformat_z(self.created_at),
            "updated_at": isoformat_z(self.updated_at),
            "client_order_id": self.client_order_id,
            "idempotency_key": self.idempotency_key,
            "meta": self.meta,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class Fill:
    execution_id: ExecutionId
    order_id: OrderId
    instrument: Instrument
    ts: _dt.datetime
    side: OrderSide
    qty: Decimal
    price: Decimal
    fee: Money | None = None
    liquidity_flag: str | None = None  # maker/taker or exchange specific
    meta: dict[str, t.Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "ts", as_utc(self.ts))
        object.__setattr__(self, "qty", _positive(_d(self.qty), "qty"))
        object.__setattr__(self, "price", _positive(_d(self.price), "price"))
        if self.liquidity_flag is not None:
            object.__setattr__(self, "liquidity_flag", _non_empty(self.liquidity_flag, "liquidity_flag"))

    def notional(self) -> Decimal:
        return self.qty * self.price

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "execution_id": str(self.execution_id),
            "order_id": str(self.order_id),
            "instrument": self.instrument.to_dict(),
            "ts": isoformat_z(self.ts),
            "side": self.side.value,
            "qty": str(self.qty),
            "price": str(self.price),
            "fee": self.fee.to_dict() if self.fee is not None else None,
            "liquidity_flag": self.liquidity_flag,
            "meta": self.meta,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class RiskSignal:
    ts: _dt.datetime
    level: RiskLevel
    code: str
    message: str
    context: dict[str, t.Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "ts", as_utc(self.ts))
        object.__setattr__(self, "code", _non_empty(self.code, "code"))
        object.__setattr__(self, "message", _non_empty(self.message, "message"))

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "ts": isoformat_z(self.ts),
            "level": self.level.value,
            "code": self.code,
            "message": self.message,
            "context": self.context,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class PolicyDecision:
    ts: _dt.datetime
    decision: Decision
    reason: str
    risk_level: RiskLevel = RiskLevel.none
    signals: tuple[RiskSignal, ...] = ()
    constraints: dict[str, t.Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "ts", as_utc(self.ts))
        object.__setattr__(self, "reason", _non_empty(self.reason, "reason"))

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "ts": isoformat_z(self.ts),
            "decision": self.decision.value,
            "reason": self.reason,
            "risk_level": self.risk_level.value,
            "signals": [s.to_dict() for s in self.signals],
            "constraints": self.constraints,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class Action:
    # Generic action for RL/agent loop; trading-specific actions can be stored in payload.
    action_type: str
    payload: dict[str, t.Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "action_type", _non_empty(self.action_type, "action_type"))

    def to_dict(self) -> dict[str, t.Any]:
        return {"action_type": self.action_type, "payload": self.payload}


@dataclasses.dataclass(frozen=True, slots=True)
class Observation:
    ts: _dt.datetime
    # Core features observed by agent; can include quotes/candles/positions etc as serialized payload.
    features: dict[str, t.Any]
    meta: dict[str, t.Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "ts", as_utc(self.ts))
        ensure(isinstance(self.features, dict), "features must be a dict", ValidationError)

    def to_dict(self) -> dict[str, t.Any]:
        return {"ts": isoformat_z(self.ts), "features": self.features, "meta": self.meta}


@dataclasses.dataclass(frozen=True, slots=True)
class Reward:
    ts: _dt.datetime
    value: Decimal
    components: dict[str, Decimal] = dataclasses.field(default_factory=dict)
    meta: dict[str, t.Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "ts", as_utc(self.ts))
        object.__setattr__(self, "value", _d(self.value))
        comps: dict[str, Decimal] = {}
        for k, v in self.components.items():
            comps[_non_empty(str(k), "components.key")] = _d(v)
        object.__setattr__(self, "components", comps)

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "ts": isoformat_z(self.ts),
            "value": str(self.value),
            "components": {k: str(v) for k, v in self.components.items()},
            "meta": self.meta,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class EpisodeMetrics:
    run_id: RunId
    started_at: _dt.datetime
    finished_at: _dt.datetime
    steps: int
    total_reward: Decimal
    meta: dict[str, t.Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "started_at", as_utc(self.started_at))
        object.__setattr__(self, "finished_at", as_utc(self.finished_at))
        ensure(self.finished_at >= self.started_at, "finished_at must be >= started_at", ValidationError)
        ensure(isinstance(self.steps, int) and self.steps >= 0, "steps must be int >= 0", ValidationError)
        object.__setattr__(self, "total_reward", _d(self.total_reward))

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "run_id": str(self.run_id),
            "started_at": isoformat_z(self.started_at),
            "finished_at": isoformat_z(self.finished_at),
            "steps": self.steps,
            "total_reward": str(self.total_reward),
            "meta": self.meta,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class BacktestResult:
    run_id: RunId
    strategy_id: StrategyId
    started_at: _dt.datetime
    finished_at: _dt.datetime
    equity_curve: tuple[tuple[_dt.datetime, Decimal], ...]
    metrics: dict[str, Decimal]
    trades: int
    meta: dict[str, t.Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "started_at", as_utc(self.started_at))
        object.__setattr__(self, "finished_at", as_utc(self.finished_at))
        ensure(self.finished_at >= self.started_at, "finished_at must be >= started_at", ValidationError)
        ensure(isinstance(self.trades, int) and self.trades >= 0, "trades must be int >= 0", ValidationError)

        curve: list[tuple[_dt.datetime, Decimal]] = []
        last_ts: _dt.datetime | None = None
        for ts, v in self.equity_curve:
            tsu = as_utc(ts)
            dv = _d(v)
            if last_ts is not None:
                ensure(tsu >= last_ts, "equity_curve must be non-decreasing by timestamp", ValidationError)
            curve.append((tsu, dv))
            last_ts = tsu
        object.__setattr__(self, "equity_curve", tuple(curve))

        mm: dict[str, Decimal] = {}
        for k, v in self.metrics.items():
            mm[_non_empty(str(k), "metrics.key")] = _d(v)
        object.__setattr__(self, "metrics", mm)

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "run_id": str(self.run_id),
            "strategy_id": str(self.strategy_id),
            "started_at": isoformat_z(self.started_at),
            "finished_at": isoformat_z(self.finished_at),
            "equity_curve": [(isoformat_z(ts), str(v)) for ts, v in self.equity_curve],
            "metrics": {k: str(v) for k, v in self.metrics.items()},
            "trades": self.trades,
            "meta": self.meta,
        }


# ---------------------------------------------------------------------------
# Event and audit envelopes
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class Event:
    kind: EventKind
    ts: _dt.datetime
    trace_id: TraceId
    payload: dict[str, t.Any]
    severity: Severity = Severity.info
    source: str | None = None  # component/service name
    tenant_id: TenantId | None = None
    user_id: UserId | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "ts", as_utc(self.ts))
        if self.source is not None:
            object.__setattr__(self, "source", _non_empty(self.source, "source"))
        ensure(isinstance(self.payload, dict), "payload must be dict", ValidationError)

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "kind": self.kind.value,
            "ts": isoformat_z(self.ts),
            "trace_id": str(self.trace_id),
            "payload": self.payload,
            "severity": self.severity.value,
            "source": self.source,
            "tenant_id": str(self.tenant_id) if self.tenant_id is not None else None,
            "user_id": str(self.user_id) if self.user_id is not None else None,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class AuditRecord:
    ts: _dt.datetime
    trace_id: TraceId
    actor: str
    action: str
    resource: str
    outcome: str
    details: dict[str, t.Any] = dataclasses.field(default_factory=dict)
    tenant_id: TenantId | None = None
    user_id: UserId | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "ts", as_utc(self.ts))
        object.__setattr__(self, "actor", _non_empty(self.actor, "actor"))
        object.__setattr__(self, "action", _non_empty(self.action, "action"))
        object.__setattr__(self, "resource", _non_empty(self.resource, "resource"))
        object.__setattr__(self, "outcome", _non_empty(self.outcome, "outcome"))
        ensure(isinstance(self.details, dict), "details must be dict", ValidationError)

    def to_event(self, *, source: str | None = None) -> Event:
        return Event(
            kind=EventKind.audit,
            ts=self.ts,
            trace_id=self.trace_id,
            payload=self.to_dict(),
            severity=Severity.info,
            source=source,
            tenant_id=self.tenant_id,
            user_id=self.user_id,
        )

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "ts": isoformat_z(self.ts),
            "trace_id": str(self.trace_id),
            "actor": self.actor,
            "action": self.action,
            "resource": self.resource,
            "outcome": self.outcome,
            "details": self.details,
            "tenant_id": str(self.tenant_id) if self.tenant_id is not None else None,
            "user_id": str(self.user_id) if self.user_id is not None else None,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class ErrorEnvelope:
    ts: _dt.datetime
    trace_id: TraceId
    error_type: str
    message: str
    retryable: bool = False
    context: dict[str, t.Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "ts", as_utc(self.ts))
        object.__setattr__(self, "error_type", _non_empty(self.error_type, "error_type"))
        object.__setattr__(self, "message", _non_empty(self.message, "message"))
        ensure(isinstance(self.context, dict), "context must be dict", ValidationError)

    @classmethod
    def from_exc(
        cls,
        exc: BaseException,
        *,
        trace_id: TraceId,
        retryable: bool | None = None,
        context: dict[str, t.Any] | None = None,
    ) -> "ErrorEnvelope":
        et = type(exc).__name__
        msg = str(exc) or et
        rb = retryable if retryable is not None else isinstance(exc, (TimeoutError, RateLimitError, ExternalServiceError))
        return cls(
            ts=utcnow(),
            trace_id=trace_id,
            error_type=et,
            message=msg,
            retryable=rb,
            context=context or {},
        )

    def to_event(self, *, source: str | None = None) -> Event:
        sev = Severity.error if not self.retryable else Severity.warning
        return Event(kind=EventKind.error, ts=self.ts, trace_id=self.trace_id, payload=self.to_dict(), severity=sev, source=source)

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "ts": isoformat_z(self.ts),
            "trace_id": str(self.trace_id),
            "error_type": self.error_type,
            "message": self.message,
            "retryable": self.retryable,
            "context": self.context,
        }


# ---------------------------------------------------------------------------
# Protocols (implementation contracts)
# ---------------------------------------------------------------------------

@t.runtime_checkable
class Clock(t.Protocol):
    def now(self) -> _dt.datetime:
        """Return timezone-aware UTC timestamp."""
        ...


@t.runtime_checkable
class Logger(t.Protocol):
    def log(self, severity: Severity, message: str, *, trace_id: TraceId | None = None, **fields: t.Any) -> None:
        ...

    def debug(self, message: str, *, trace_id: TraceId | None = None, **fields: t.Any) -> None:
        ...

    def info(self, message: str, *, trace_id: TraceId | None = None, **fields: t.Any) -> None:
        ...

    def warning(self, message: str, *, trace_id: TraceId | None = None, **fields: t.Any) -> None:
        ...

    def error(self, message: str, *, trace_id: TraceId | None = None, **fields: t.Any) -> None:
        ...

    def critical(self, message: str, *, trace_id: TraceId | None = None, **fields: t.Any) -> None:
        ...


@t.runtime_checkable
class Metrics(t.Protocol):
    def incr(self, name: str, value: int = 1, *, tags: dict[str, str] | None = None) -> None:
        ...

    def gauge(self, name: str, value: float, *, tags: dict[str, str] | None = None) -> None:
        ...

    def timing_ms(self, name: str, value_ms: float, *, tags: dict[str, str] | None = None) -> None:
        ...


@t.runtime_checkable
class EventBus(t.Protocol):
    async def publish(self, event: Event) -> None:
        ...

    async def publish_many(self, events: t.Sequence[Event]) -> None:
        ...

    async def subscribe(self, kinds: t.Sequence[EventKind]) -> t.AsyncIterator[Event]:
        ...


@t.runtime_checkable
class KVStore(t.Protocol):
    async def get(self, key: str) -> bytes | None:
        ...

    async def set(self, key: str, value: bytes, *, ttl_seconds: int | None = None) -> None:
        ...

    async def delete(self, key: str) -> None:
        ...

    async def compare_and_set(self, key: str, expected: bytes | None, value: bytes, *, ttl_seconds: int | None = None) -> bool:
        ...


@t.runtime_checkable
class BlobStore(t.Protocol):
    async def put(self, key: str, data: bytes, *, content_type: str | None = None) -> None:
        ...

    async def get(self, key: str) -> bytes | None:
        ...

    async def exists(self, key: str) -> bool:
        ...

    async def delete(self, key: str) -> None:
        ...


@t.runtime_checkable
class FeatureStore(t.Protocol):
    async def write_observation(self, *, run_id: RunId, obs: Observation) -> None:
        ...

    async def read_observations(
        self,
        *,
        run_id: RunId,
        since: _dt.datetime | None = None,
        until: _dt.datetime | None = None,
        limit: int | None = None,
    ) -> list[Observation]:
        ...


@t.runtime_checkable
class Broker(t.Protocol):
    async def get_balance(self) -> dict[str, Money]:
        ...

    async def get_positions(self) -> list[Position]:
        ...

    async def get_open_orders(self, *, instrument: Instrument | None = None) -> list[Order]:
        ...

    async def cancel_order(self, order_id: OrderId) -> Order:
        ...

    async def cancel_all(self, *, instrument: Instrument | None = None) -> list[Order]:
        ...


@t.runtime_checkable
class Exchange(t.Protocol):
    async def get_market_meta(self, instrument: Instrument) -> MarketMeta:
        ...

    async def get_quote(self, instrument: Instrument) -> Quote:
        ...

    async def stream_quotes(self, instrument: Instrument) -> t.AsyncIterator[Quote]:
        ...

    async def place_order(self, order: Order) -> Order:
        ...

    async def get_order(self, order_id: OrderId) -> Order:
        ...

    async def stream_fills(self, *, instrument: Instrument | None = None) -> t.AsyncIterator[Fill]:
        ...


@t.runtime_checkable
class Strategy(t.Protocol):
    strategy_id: StrategyId

    async def on_quote(self, quote: Quote, *, trace_id: TraceId) -> None:
        ...

    async def on_candle(self, candle: Candle, *, trace_id: TraceId) -> None:
        ...

    async def propose_action(self, obs: Observation, *, trace_id: TraceId) -> Action | None:
        ...


@t.runtime_checkable
class Planner(t.Protocol):
    async def plan(self, obs: Observation, *, trace_id: TraceId) -> list[Action]:
        ...


@t.runtime_checkable
class Memory(t.Protocol):
    async def remember(self, *, run_id: RunId, item: dict[str, t.Any], trace_id: TraceId) -> None:
        ...

    async def recall(
        self,
        *,
        run_id: RunId,
        query: dict[str, t.Any],
        limit: int = 20,
        trace_id: TraceId,
    ) -> list[dict[str, t.Any]]:
        ...


@t.runtime_checkable
class Policy(t.Protocol):
    async def evaluate(self, *, run_id: RunId, action: Action, obs: Observation, trace_id: TraceId) -> PolicyDecision:
        ...


@t.runtime_checkable
class RiskEngine(t.Protocol):
    async def assess(self, *, run_id: RunId, obs: Observation, trace_id: TraceId) -> tuple[RiskLevel, tuple[RiskSignal, ...]]:
        ...


@t.runtime_checkable
class Backtester(t.Protocol):
    async def run(
        self,
        *,
        strategy: Strategy,
        instrument: Instrument,
        start: _dt.datetime,
        end: _dt.datetime,
        initial_cash: Money,
        trace_id: TraceId,
    ) -> BacktestResult:
        ...


# ---------------------------------------------------------------------------
# Optional Pydantic models (if installed)
# ---------------------------------------------------------------------------

if _PYDANTIC_AVAILABLE:

    class _PBase(_PBaseModel):  # type: ignore
        model_config = _PConfigDict(  # type: ignore
            extra="forbid",
            frozen=True,
            validate_assignment=True,
            str_strip_whitespace=True,
        )

    class MoneyModel(_PBase):
        amount: str = _PField(..., description="Decimal string")  # type: ignore
        currency: str = _PField(..., min_length=1)  # type: ignore

    class EventModel(_PBase):
        kind: EventKind
        ts: _dt.datetime
        trace_id: TraceId
        payload: dict[str, t.Any]
        severity: Severity = Severity.info
        source: str | None = None
        tenant_id: TenantId | None = None
        user_id: UserId | None = None


# ---------------------------------------------------------------------------
# Environment contract surface (strict)
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True, slots=True)
class _RuntimeInfo:
    pid: int
    hostname: str
    service: str
    env: str

    @staticmethod
    def collect(*, service: str) -> "_RuntimeInfo":
        return _RuntimeInfo(
            pid=os.getpid(),
            hostname=_non_empty(os.uname().nodename if hasattr(os, "uname") else "unknown", "hostname"),
            service=_non_empty(service, "service"),
            env=_non_empty(os.environ.get("AET_ENV", "dev"), "env"),
        )


# End of file
