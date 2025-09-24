# core-systems/genius_core/security/self_inhibitor/interfaces/types.py
from __future__ import annotations

import json
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Any, Dict, Mapping, MutableMapping, Optional, Protocol, runtime_checkable, Callable, ContextManager, TypeVar

__all__ = [
    "EpochSeconds",
    "JSON",
    "DecisionReason",
    "SelfInhibitDecision",
    "SelfInhibitError",
    "SelfInhibitDenied",
    "GuardProtocol",
    "StrategyProtocol",
    "http_status_for",
]

# -------- Алиасы --------

EpochSeconds = float
JSON = Any


# -------- Причины решений (стабильные коды для API/логов/алертов) --------

class DecisionReason(str, Enum):
    OK = "ok"                    # разрешено
    COOLDOWN = "cooldown"        # кулдаун активен (экспоненциальный backoff)
    CIRCUIT_OPEN = "circuit_open"# circuit breaker в состоянии open
    RATE_LIMIT = "rate_limit"    # внешнее ограничение скорости
    POLICY_DENY = "policy_deny"  # политика/ABAC отклонила
    ERROR = "error"              # техническая ошибка/неопределенность


# -------- Результат решения (универсальная переносимая форма) --------

@dataclass(slots=True)
class SelfInhibitDecision:
    allowed: bool
    reason: DecisionReason = DecisionReason.OK
    retry_after_s: float = 0.0
    cooldown_until_ts: EpochSeconds = 0.0
    strikes: float = 0.0
    key: str = ""
    strategy_id: str = ""                 # идентификатор стратегии (например, "cooldown/v1")
    next_penalty_s: float = 0.0           # прогноз следующего окна (если применимо)
    meta: Dict[str, Any] = field(default_factory=dict)  # произвольные дополнительные поля (необязательно)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["reason"] = self.reason.value
        return d

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "SelfInhibitDecision":
        return SelfInhibitDecision(
            allowed=bool(d.get("allowed", False)),
            reason=DecisionReason(str(d.get("reason", DecisionReason.ERROR.value))),
            retry_after_s=float(d.get("retry_after_s", 0.0)),
            cooldown_until_ts=float(d.get("cooldown_until_ts", 0.0)),
            strikes=float(d.get("strikes", 0.0)),
            key=str(d.get("key", "")),
            strategy_id=str(d.get("strategy_id", "")),
            next_penalty_s=float(d.get("next_penalty_s", 0.0)),
            meta=dict(d.get("meta") or {}),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))

    @property
    def denied(self) -> bool:
        return not self.allowed

    @property
    def retryable(self) -> bool:
        """Можно ли повторить (обычно для кулдаунов/скоростных лимитов)."""
        return self.reason in {DecisionReason.COOLDOWN, DecisionReason.RATE_LIMIT, DecisionReason.CIRCUIT_OPEN}


# -------- Исключения для PEP/EPP слоёв --------

class SelfInhibitError(Exception):
    """Базовая ошибка self-inhibitor."""

class SelfInhibitDenied(SelfInhibitError):
    """
    Исключение для режима raise_on_deny.
    Содержит переносимую SelfInhibitDecision.
    """
    def __init__(self, decision: SelfInhibitDecision):
        super().__init__(f"Denied ({decision.reason.value}); retry_after={decision.retry_after_s:.3f}s key='{decision.key}'")
        self.decision = decision


# -------- Протоколы (контракты) --------

TDecision = TypeVar("TDecision", bound=SelfInhibitDecision)

@runtime_checkable
class GuardProtocol(ContextManager[TDecision], Protocol):
    """
    Протокол guard-контекста, предоставляемого стратегией.
    Пример использования:
        with strategy.guard(key) as dec:
            if not dec.allowed: return 429
            # do work...
            # успешный выход коммитит success; исключение трактуется как failure.
    """
    @property
    def decision(self) -> TDecision: ...
    def success(self) -> TDecision: ...
    def failure(self, *, weight: float = 1.0) -> TDecision: ...
    # __enter__() -> TDecision
    # __exit__(exc_type, exc, tb) -> bool


Clock = Callable[[], EpochSeconds]

@runtime_checkable
class StrategyProtocol(Protocol):
    """
    Единый контракт для всех стратегий self-inhibitor (кулдаун, circuit breaker и т.п.).
    Реализация не должна делать жёстких предположений о хранилище.
    """
    @property
    def id(self) -> str:
        """
        Стабильный идентификатор стратегии/версии (например, "cooldown/v1").
        Нужен для телеметрии и трассировки.
        """
        ...

    def evaluate(self, key: str, *, now_ts: Optional[EpochSeconds] = None) -> SelfInhibitDecision:
        """
        Проверка возможности выполнения действия по ключу.
        Не изменяет состояние.
        """
        ...

    def commit(self, key: str, *, success: bool, weight: float = 1.0, now_ts: Optional[EpochSeconds] = None) -> SelfInhibitDecision:
        """
        Фиксирует исход операции и возвращает актуальное решение после коммита.
        """
        ...

    def guard(self, key: str, *, raise_on_deny: bool = False, now_ts: Optional[EpochSeconds] = None) -> GuardProtocol:
        """
        Контекст-менеджер, оформляющий evaluate/commit с автоматикой:
          - на входе: evaluate
          - на успешном выходе: commit(success=True)
          - при исключении: commit(success=False)
          - при raise_on_deny=True: выбрасывает SelfInhibitDenied
        """
        ...


# -------- Утилиты сопоставления решений с HTTP-кодами --------

_HTTP_MAP: Dict[DecisionReason, int] = {
    DecisionReason.OK: 200,
    DecisionReason.COOLDOWN: 429,
    DecisionReason.RATE_LIMIT: 429,
    DecisionReason.CIRCUIT_OPEN: 503,   # временная недоступность
    DecisionReason.POLICY_DENY: 403,
    DecisionReason.ERROR: 500,
}

def http_status_for(decision: SelfInhibitDecision) -> int:
    """
    Рекомендуемый HTTP-код для данного решения (для REST шлюзов/проксей).
    """
    return _HTTP_MAP.get(decision.reason, 500)
