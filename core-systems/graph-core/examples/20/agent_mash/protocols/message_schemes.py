from enum import Enum
from typing import TypedDict, Literal, Optional, Union, Dict, Any
from datetime import datetime


class MessageType(str, Enum):
    COMMAND = "command"
    EVENT = "event"
    HEARTBEAT = "heartbeat"
    SIGNAL = "signal"
    METACOMM = "metacomm"
    ERROR = "error"
    DIAGNOSTIC = "diagnostic"


class MessageHeader(TypedDict):
    sender: str
    receiver: str
    timestamp: str
    type: MessageType
    trace_id: Optional[str]
    priority: Optional[Literal["low", "normal", "high", "critical"]]


class CommandPayload(TypedDict):
    action: str
    args: Optional[Dict[str, Any]]
    timeout: Optional[int]


class EventPayload(TypedDict):
    event_name: str
    data: Optional[Dict[str, Any]]


class HeartbeatPayload(TypedDict):
    status: Literal["online", "degraded", "offline"]
    uptime: float
    cpu_load: float
    memory_usage: float


class SignalPayload(TypedDict):
    channel: str
    value: Union[int, str, float, bool]
    encryption: Optional[str]


class MetaCommPayload(TypedDict):
    control_type: Literal["sync", "reset", "rekey", "update"]
    token: Optional[str]
    parameters: Optional[Dict[str, Any]]


class ErrorPayload(TypedDict):
    code: int
    message: str
    origin: Optional[str]


class DiagnosticPayload(TypedDict):
    probe_id: str
    result: Dict[str, Any]
    level: Literal["info", "warning", "critical"]


class Envelope(TypedDict):
    header: MessageHeader
    payload: Union[
        CommandPayload,
        EventPayload,
        HeartbeatPayload,
        SignalPayload,
        MetaCommPayload,
        ErrorPayload,
        DiagnosticPayload,
    ]
