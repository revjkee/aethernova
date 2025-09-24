# SPDX-License-Identifier: Apache-2.0
"""
Self-Inhibitor Interfaces (Ports)
=================================

Назначение:
  Строгие интерфейсы (порт/адаптер) для слоя самоблокировок (self-inhibitor)
  интеллектуальных агентов: политики (Rego/другие), лимитирование, сканирование
  контента, редактирование секретов, фильтрация URL, телеметрия, кэш и часы.

Дизайн:
  - Только стандартная библиотека (typing/dataclasses/enum/abc/contextlib).
  - Протоколы совместимы с sync/async (методы допускают async-реализацию).
  - DTO неизменяемые (frozen dataclasses) и сериализуемые в JSON.
  - Единая шкала строгости Severity и унифицированные коды причин.

Совместимость:
  - Политики могут быть реализованы через OPA (Rego), локальный движок или иное.
  - Rate limiting — память/Redis и пр. через адаптеры к портам ниже.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import (
    Any,
    AsyncIterator,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    Union,
    runtime_checkable,
)

# ------------------------------- Версия API ----------------------------------

SELF_INHIBITOR_API_VERSION = "1.0.0"

# ------------------------------- Базовые типы --------------------------------


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    DEFAULT_DENY = "default_deny"


class Obligation(str, Enum):
    REDACT_SECRETS = "redact_secrets"
    REDACT_PII = "redact_pii"
    TRUNCATE_INPUT = "truncate_input"
    SANDBOX_ROUTE = "sandbox_route"
    HUMAN_REVIEW = "human_review"


# ------------------------------- Доменные DTO --------------------------------


@dataclass(frozen=True)
class Actor:
    id: str
    roles: Tuple[str, ...] = field(default_factory=tuple)
    tenant: Optional[str] = None
    ip: Optional[str] = None
    sensitive_access: bool = False
    attrs: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ModelInfo:
    name: str
    provider: Optional[str] = None
    attrs: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Content:
    text: Optional[str] = None
    lang: Optional[str] = None
    length: int = 0
    mime: Optional[str] = None
    attrs: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolCall:
    name: str
    args: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Cost:
    prompt_tokens: int = 0
    max_tokens: int = 0
    est_tokens: int = 0
    attrs: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Request:
    """
    Описывает единичный запрос агента, подлежащий проверке self-inhibitor.
    """
    action: str
    actor: Actor
    model: ModelInfo
    content: Content
    tools: Tuple[ToolCall, ...] = field(default_factory=tuple)
    urls: Tuple[str, ...] = field(default_factory=tuple)
    cost: Cost = field(default_factory=Cost)
    env: Mapping[str, Any] = field(default_factory=dict)  # stage, region, etc.


@dataclass(frozen=True)
class PIIInfo:
    has: bool = False
    kinds: Tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class SafetySignals:
    injection_score: float = 0.0  # 0..1
    toxicity: float = 0.0         # 0..1
    pii: PIIInfo = field(default_factory=PIIInfo)
    attrs: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class LimitSnapshot:
    """
    Снимок лимита/счетчика для принятия решения без состояния внутри политики.
    reset_at — абсолютные секунды Epoch, когда лимит сбрасывается.
    """
    current: int = 0          # для rpm/concurrency
    used: int = 0             # для квот (например, токены)
    limit: int = 0
    reset_at: Optional[float] = None


@dataclass(frozen=True)
class UsageSnapshot:
    per_user_rpm: LimitSnapshot = field(default_factory=LimitSnapshot)
    global_concurrency: LimitSnapshot = field(default_factory=LimitSnapshot)
    tenant_tokens_daily: LimitSnapshot = field(default_factory=LimitSnapshot)


@dataclass(frozen=True)
class InhibitInput:
    request: Request
    safety: Optional[SafetySignals] = None
    usage: Optional[UsageSnapshot] = None
    api_version: str = SELF_INHIBITOR_API_VERSION


@dataclass(frozen=True)
class Reason:
    """
    Машиночитаемая причина (code) и человекочитаемое сообщение (message).
    strategy — компонент, породивший причину (policy/rate/…).
    """
    code: str
    message: str
    severity: Severity = Severity.HIGH
    strategy: Optional[str] = None
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Decision:
    """
    Итоговое решение self-inhibitor.
    """
    effect: Effect
    allowed: bool
    severity: Severity
    reasons: Tuple[Reason, ...] = field(default_factory=tuple)
    obligations: Tuple[Obligation, ...] = field(default_factory=tuple)
    retry_after: float = 0.0  # секунды; рекомендация для клиента
    limits: Mapping[str, Any] = field(default_factory=dict)
    audit: Mapping[str, Any] = field(default_factory=dict)

    @staticmethod
    def allow(
        obligations: Iterable[Obligation] = (),
        limits: Mapping[str, Any] = None,
        audit: Mapping[str, Any] = None,
    ) -> "Decision":
        return Decision(
            effect=Effect.ALLOW,
            allowed=True,
            severity=Severity.LOW,
            reasons=tuple(),
            obligations=tuple(obligations),
            retry_after=0.0,
            limits=dict(limits or {}),
            audit=dict(audit or {}),
        )

    @staticmethod
    def deny(
        reasons: Iterable[Reason],
        *,
        severity: Severity = Severity.HIGH,
        retry_after: float = 0.0,
        obligations: Iterable[Obligation] = (),
        limits: Mapping[str, Any] = None,
        audit: Mapping[str, Any] = None,
        effect: Effect = Effect.DENY,
    ) -> "Decision":
        rs = tuple(reasons)
        # если нет явной строгости — берем максимум из причин
        if severity is None and rs:
            sev_order = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
            worst = max(rs, key=lambda r: sev_order[r.severity])
            severity = worst.severity
        return Decision(
            effect=effect,
            allowed=False,
            severity=severity or Severity.HIGH,
            reasons=rs,
            obligations=tuple(obligations),
            retry_after=max(0.0, float(retry_after)),
            limits=dict(limits or {}),
            audit=dict(audit or {}),
        )


# ------------------------------- Исключения ----------------------------------


class SelfInhibitorError(RuntimeError):
    pass


class PolicyEvaluationError(SelfInhibitorError):
    pass


class RateLimitExceeded(SelfInhibitorError):
    def __init__(self, decision: Decision):
        super().__init__(f"rate limited: retry_after={decision.retry_after:.3f}s")
        self.decision = decision


# --------------------------------- ПОРТЫ -------------------------------------


@runtime_checkable
class ClockPort(Protocol):
    """
    Источник времени.
    now(): монотонные секунды; wall(): UNIX time.
    """
    def now(self) -> float: ...
    def wall(self) -> float: ...


@runtime_checkable
class CachePort(Protocol):
    """
    Кэш решений/сигналов. Значения должны быть JSON-сериализуемыми.
    """
    async def get(self, key: str) -> Optional[Mapping[str, Any]]: ...
    async def set(self, key: str, value: Mapping[str, Any], ttl_s: int) -> None: ...
    async def delete(self, key: str) -> None: ...
    async def clear(self) -> None: ...


@runtime_checkable
class TelemetryPort(Protocol):
    """
    Телеметрия/трейсинг. Реализации: OpenTelemetry, логгер и т.п.
    """
    async def event(self, name: str, attributes: Mapping[str, Any] = ...) -> None: ...
    async def metric(self, name: str, value: Union[int, float], attributes: Mapping[str, Any] = ...) -> None: ...
    def span(self, name: str, attributes: Mapping[str, Any] = ...) -> AsyncIterator[None]: ...


@runtime_checkable
class PolicyEnginePort(Protocol):
    """
    Порт движка политик (OPA/Rego или иной).
    """
    async def evaluate(self, payload: InhibitInput) -> Decision: ...
    async def reload(self) -> None: ...
    async def health(self) -> Mapping[str, Any]: ...


@runtime_checkable
class RateLimiterPort(Protocol):
    """
    Порт лимитирования. Возвращает Decision для унификации с PolicyEngine.
    """
    async def allow(self, context: Mapping[str, Any]) -> Decision: ...
    async def release(self, context: Mapping[str, Any]) -> None: ...


@runtime_checkable
class ContentScannerPort(Protocol):
    """
    Порт анализа контента и приватности.
    """
    async def injection_score(self, text: str) -> float: ...
    async def toxicity_score(self, text: str) -> float: ...
    async def detect_pii(self, text: str) -> PIIInfo: ...
    async def redact_pii(self, text: str, kinds: Iterable[str] = ...) -> str: ...


@runtime_checkable
class SecretsRedactorPort(Protocol):
    """
    Порт редакции секретов (по ENV/хранилищу).
    """
    async def redact(self, text: str, secrets: Optional[Mapping[str, str]] = ...) -> str: ...


@runtime_checkable
class URLFilterPort(Protocol):
    """
    Порт проверки URL на соответствие allow/deny, CIDR, схеме и пр.
    """
    async def is_allowed(self, url: str) -> bool: ...
    async def explain(self, url: str) -> Mapping[str, Any]: ...


@runtime_checkable
class QuotaSnapshotPort(Protocol):
    """
    Порт получения снимков счетчиков/квот для входа в PolicyEngine.
    """
    async def snapshot(self, req: Request) -> UsageSnapshot: ...


@runtime_checkable
class SelfInhibitorServicePort(Protocol):
    """
    Фасадный порт доменного сервиса self-inhibitor.
    Реализация агрегирует PolicyEngine, RateLimiter и сканеры.
    """
    async def decide(self, payload: InhibitInput) -> Decision: ...
    async def warmup(self) -> None: ...
    async def health(self) -> Mapping[str, Any]: ...


# --------------------------- Утилиты сериализации ----------------------------


def to_serializable(obj: Any) -> Any:
    """
    Преобразует DTO/Enum в JSON-совместимые структуры.
    """
    if hasattr(obj, "__dataclass_fields__"):
        return {k: to_serializable(v) for k, v in asdict(obj).items()}
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, (tuple, list)):
        return [to_serializable(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): to_serializable(v) for k, v in obj.items()}
    return obj


# ------------------------------- Экспорт API ---------------------------------

__all__ = [
    "SELF_INHIBITOR_API_VERSION",
    # Enums
    "Severity",
    "Effect",
    "Obligation",
    # DTO
    "Actor",
    "ModelInfo",
    "Content",
    "ToolCall",
    "Cost",
    "Request",
    "PIIInfo",
    "SafetySignals",
    "LimitSnapshot",
    "UsageSnapshot",
    "InhibitInput",
    "Reason",
    "Decision",
    # Errors
    "SelfInhibitorError",
    "PolicyEvaluationError",
    "RateLimitExceeded",
    # Ports
    "ClockPort",
    "CachePort",
    "TelemetryPort",
    "PolicyEnginePort",
    "RateLimiterPort",
    "ContentScannerPort",
    "SecretsRedactorPort",
    "URLFilterPort",
    "QuotaSnapshotPort",
    "SelfInhibitorServicePort",
    # Utils
    "to_serializable",
]
