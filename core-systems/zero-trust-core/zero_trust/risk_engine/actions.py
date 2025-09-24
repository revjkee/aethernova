# file: zero-trust-core/zero_trust/risk_engine/actions.py
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

# ==============================================================================
# Типы, решения, контекст
# ==============================================================================

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class RiskAction(str, Enum):
    ALLOW = "allow"
    STEP_UP = "step_up"
    DENY = "deny"
    QUARANTINE = "quarantine"
    LIMIT_SCOPE = "limit_scope"


@dataclass(frozen=True)
class RiskDecision:
    """
    Итоговое решение риск‑движка (см. HTTP / GraphQL слои).
    """
    score: float
    level: RiskLevel
    action: RiskAction
    reasons: List[str] = field(default_factory=list)
    limited_scope: Optional[List[str]] = None  # используется в LIMIT_SCOPE


@dataclass
class ActionContext:
    """
    Контекст применения решения (минимальный набор для Zero Trust).
    """
    tenant_id: Optional[str]
    user_id: Optional[str]
    session_id: Optional[str]
    device_id: Optional[str]
    request_id: str
    occurred_at_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    idempotency_key: Optional[str] = None
    network: Optional[Dict[str, object]] = None
    posture: Optional[Dict[str, object]] = None
    attributes: Dict[str, object] = field(default_factory=dict)


@dataclass
class ActionResult:
    """
    Сводный результат применения действия.
    """
    name: str
    applied: bool
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    details: Dict[str, object] = field(default_factory=dict)


@dataclass
class PlanResult:
    """
    Итог применения всего плана.
    """
    plan: List[str]
    results: List[ActionResult]
    decision: RiskDecision
    request_id: str


# ==============================================================================
# Интерфейсы интеграций (реализуются в вашем приложении)
# ==============================================================================

class SessionManager(ABC):
    @abstractmethod
    def end_session(self, session_id: str, reason: str) -> None:
        ...

    @abstractmethod
    def require_step_up(self, session_id: str, methods: Sequence[str], grace_seconds: int) -> None:
        ...

    @abstractmethod
    def set_bindings(self, session_id: str, *, sticky_ip: Optional[str] = None, sticky_asn: Optional[int] = None) -> None:
        ...


class TokenService(ABC):
    @abstractmethod
    def revoke_all(self, session_id: Optional[str], user_id: Optional[str], reason: str) -> None:
        ...

    @abstractmethod
    def limit_scope(self, session_id: Optional[str], user_id: Optional[str], scope: Sequence[str]) -> None:
        ...

    @abstractmethod
    def set_ttl(self, session_id: Optional[str], access_ttl_seconds: int) -> None:
        ...

    @abstractmethod
    def rotate_refresh(self, session_id: Optional[str]) -> None:
        ...


class QuarantineService(ABC):
    @abstractmethod
    def quarantine_device(self, device_id: str, severity: str, ttl_seconds: int, reason: str) -> None:
        ...


class Publisher(ABC):
    """
    Унифицированная публикация событий (SIEM, шина событий, аудиты).
    """
    @abstractmethod
    def publish(self, event_name: str, payload: Dict[str, object]) -> None:
        ...


@dataclass
class Services:
    session: SessionManager
    tokens: TokenService
    quarantine: QuarantineService
    bus: Publisher


# ==============================================================================
# Идемпотентность (in-memory). В проде вынесите в Redis/БД.
# ==============================================================================

class IdempotencyStore:
    def __init__(self, ttl_seconds: int = 600, secret: Optional[bytes] = None) -> None:
        self._ttl = ttl_seconds
        self._secret = secret or hashlib.sha256(b"ztc-risk-actions").digest()
        self._data: Dict[str, Tuple[int, str]] = {}
        self._lock = threading.Lock()

    def _hash(self, key: str) -> str:
        mac = hmac.new(self._secret, key.encode("utf-8"), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(mac).decode("ascii").rstrip("=")

    def check_or_put(self, key: str) -> bool:
        """
        True — ключ новый (можно выполнять действие),
        False — повтор в пределах TTL (следует пропустить или отвечать 200 с тем же результатом).
        """
        now = int(time.time() * 1000)
        h = self._hash(key)
        with self._lock:
            # lazy cleanup
            expired = [k for k, (ts, _) in self._data.items() if now - ts > self._ttl * 1000]
            for k in expired:
                self._data.pop(k, None)
            if h in self._data:
                ts, _ = self._data[h]
                if now - ts <= self._ttl * 1000:
                    return False
            self._data[h] = (now, uuid.uuid4().hex)
            return True


# Глобальный стор по умолчанию; можете инжектить свой
IDEMPOTENCY = IdempotencyStore()


# ==============================================================================
# Базовый класс действия и реализации
# ==============================================================================

class Action(ABC):
    """
    Базовый класс для всех действий.
    """
    name: str = "action"
    idempotent: bool = True

    def __init__(self, logger: Optional[logging.Logger] = None) -> None:
        self.log = logger or logging.getLogger("zero_trust.risk.actions")

    def _make_key(self, ctx: ActionContext) -> Optional[str]:
        if not self.idempotent:
            return None
        raw = f"{self.name}:{ctx.tenant_id}:{ctx.user_id}:{ctx.session_id}:{ctx.device_id}:{ctx.idempotency_key}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _audit(self, bus: Publisher, event: str, ctx: ActionContext, desc: Dict[str, object]) -> None:
        payload = {
            "event": event,
            "request_id": ctx.request_id,
            "tenant_id": ctx.tenant_id,
            "user_id": ctx.user_id,
            "session_id": ctx.session_id,
            "device_id": ctx.device_id,
            "occurred_at_ms": ctx.occurred_at_ms,
            "details": desc,
        }
        try:
            bus.publish(event, payload)
        except Exception as e:
            # Аудит не должен валить бизнес‑операцию
            self.log.warning("audit_publish_failed event=%s err=%s", event, e, extra={"event": event, "error": str(e)})

    def execute(self, ctx: ActionContext, decision: RiskDecision, services: Services) -> ActionResult:
        key = self._make_key(ctx)
        if key is not None:
            fresh = IDEMPOTENCY.check_or_put(key)
            if not fresh:
                self.log.info("idempotent_skip action=%s request_id=%s", self.name, ctx.request_id)
                return ActionResult(name=self.name, applied=False, warnings=["idempotent_skip"])

        try:
            result = self._run(ctx, decision, services)
            self._audit(services.bus, f"risk.action.{self.name}", ctx, result.details or {"ok": True})
            return result
        except Exception as e:
            self.log.exception("action_failed action=%s request_id=%s error=%s", self.name, ctx.request_id, e)
            return ActionResult(name=self.name, applied=False, errors=[str(e)])

    @abstractmethod
    def _run(self, ctx: ActionContext, decision: RiskDecision, services: Services) -> ActionResult:
        ...


# ---- Конкретные действия ------------------------------------------------------

@dataclass
class AllowAction(Action):
    """
    Ничего не делает, кроме телеметрии и, по желанию, мягкой ротации refresh.
    """
    rotate_refresh: bool = False
    reduce_ttl_seconds: Optional[int] = None
    name: str = "allow"

    def _run(self, ctx: ActionContext, decision: RiskDecision, services: Services) -> ActionResult:
        details: Dict[str, object] = {"level": decision.level, "score": decision.score}
        if self.rotate_refresh and ctx.session_id:
            services.tokens.rotate_refresh(ctx.session_id)
            details["rotated_refresh"] = True
        if self.reduce_ttl_seconds and ctx.session_id:
            services.tokens.set_ttl(ctx.session_id, self.reduce_ttl_seconds)
            details["access_ttl_seconds"] = self.reduce_ttl_seconds
        self.log.info("allow action applied request_id=%s", ctx.request_id, extra={"decision": decision.level})
        return ActionResult(name=self.name, applied=True, details=details)


@dataclass
class StepUpAction(Action):
    """
    Требует прохождения усиленной аутентификации для активной сессии.
    """
    methods: Sequence[str] = field(default_factory=lambda: ("webauthn_platform", "webauthn_cross_platform", "totp"))
    grace_seconds: int = 300
    name: str = "step_up"

    def _run(self, ctx: ActionContext, decision: RiskDecision, services: Services) -> ActionResult:
        if not ctx.session_id:
            return ActionResult(name=self.name, applied=False, warnings=["no_session_id"])
        services.session.require_step_up(ctx.session_id, self.methods, self.grace_seconds)
        details = {"methods": list(self.methods), "grace_seconds": self.grace_seconds}
        self.log.info("step_up requested session=%s methods=%s", ctx.session_id, self.methods)
        return ActionResult(name=self.name, applied=True, details=details)


@dataclass
class LimitScopeAction(Action):
    """
    Урезает права/скопы текущей сессии/пользователя.
    """
    scope: Sequence[str] = field(default_factory=list)
    access_ttl_seconds: Optional[int] = 600
    name: str = "limit_scope"

    def _run(self, ctx: ActionContext, decision: RiskDecision, services: Services) -> ActionResult:
        scope = list(self.scope or decision.limited_scope or [])
        if not scope:
            return ActionResult(name=self.name, applied=False, warnings=["empty_scope"])
        services.tokens.limit_scope(ctx.session_id, ctx.user_id, scope)
        if self.access_ttl_seconds and ctx.session_id:
            services.tokens.set_ttl(ctx.session_id, self.access_ttl_seconds)
        details = {"scope": scope, "access_ttl_seconds": self.access_ttl_seconds}
        self.log.warning("scope_limited session=%s scope=%s", ctx.session_id, scope)
        return ActionResult(name=self.name, applied=True, details=details)


@dataclass
class DenyAction(Action):
    """
    Немедленно прекращает доступ: закрытие сессии и отзыв всех токенов.
    """
    reason: str = "RISK_DENY"
    name: str = "deny"

    def _run(self, ctx: ActionContext, decision: RiskDecision, services: Services) -> ActionResult:
        if ctx.session_id:
            services.session.end_session(ctx.session_id, self.reason)
        services.tokens.revoke_all(ctx.session_id, ctx.user_id, self.reason)
        details = {"reason": self.reason}
        self.log.error("access_denied session=%s user=%s reason=%s", ctx.session_id, ctx.user_id, self.reason)
        return ActionResult(name=self.name, applied=True, details=details)


@dataclass
class QuarantineAction(Action):
    """
    Помещает устройство в карантин и отзывает доступ.
    """
    severity: str = "HIGH"
    ttl_seconds: int = 24 * 3600
    reason: str = "RISK_QUARANTINE"
    name: str = "quarantine"

    def _run(self, ctx: ActionContext, decision: RiskDecision, services: Services) -> ActionResult:
        if not ctx.device_id:
            return ActionResult(name=self.name, applied=False, warnings=["no_device_id"])
        services.quarantine.quarantine_device(ctx.device_id, self.severity, self.ttl_seconds, self.reason)
        if ctx.session_id:
            services.session.end_session(ctx.session_id, self.reason)
        services.tokens.revoke_all(ctx.session_id, ctx.user_id, self.reason)
        details = {"device_id": ctx.device_id, "severity": self.severity, "ttl_seconds": self.ttl_seconds, "reason": self.reason}
        self.log.error("device_quarantined device=%s severity=%s", ctx.device_id, self.severity)
        return ActionResult(name=self.name, applied=True, details=details)


# ==============================================================================
# Реестр действий и планирование
# ==============================================================================

class ActionRegistry:
    """
    Регистрирует фабрики действий по имени.
    """
    def __init__(self) -> None:
        self._reg: Dict[str, callable[..., Action]] = {}

    def register(self, name: str, factory: callable[..., Action]) -> "ActionRegistry":
        self._reg[name] = factory
        return self

    def create(self, name: str, **kwargs) -> Action:
        if name not in self._reg:
            raise KeyError(f"action not registered: {name}")
        return self._reg[name](**kwargs)

    def available(self) -> List[str]:
        return sorted(self._reg.keys())


REGISTRY = ActionRegistry() \
    .register("allow", lambda **kw: AllowAction(**kw)) \
    .register("step_up", lambda **kw: StepUpAction(**kw)) \
    .register("deny", lambda **kw: DenyAction(**kw)) \
    .register("quarantine", lambda **kw: QuarantineAction(**kw)) \
    .register("limit_scope", lambda **kw: LimitScopeAction(**kw))


@dataclass
class PlannerConfig:
    """
    Конфигурация планировщика: что делать на каждом уровне риска.
    """
    low: List[Tuple[str, Dict[str, object]]] = field(default_factory=lambda: [("allow", {"rotate_refresh": False})])
    medium: List[Tuple[str, Dict[str, object]]] = field(default_factory=lambda: [("step_up", {"grace_seconds": 300})])
    high: List[Tuple[str, Dict[str, object]]] = field(default_factory=lambda: [
        ("step_up", {"grace_seconds": 0}),
        ("limit_scope", {"access_ttl_seconds": 300}),
    ])
    critical: List[Tuple[str, Dict[str, object]]] = field(default_factory=lambda: [
        ("deny", {"reason": "RISK_CRITICAL"}),
    ])
    unknown: List[Tuple[str, Dict[str, object]]] = field(default_factory=lambda: [("step_up", {"grace_seconds": 300})])


class Planner:
    """
    Планировщик действий на основе уровня риска и запрошенного действия.
    """
    def __init__(self, cfg: Optional[PlannerConfig] = None) -> None:
        self.cfg = cfg or PlannerConfig()

    def build_plan(self, decision: RiskDecision) -> List[Action]:
        plan: List[Action] = []
        # Базовый набор по уровню риска
        level = decision.level
        table = {
            RiskLevel.LOW: self.cfg.low,
            RiskLevel.MEDIUM: self.cfg.medium,
            RiskLevel.HIGH: self.cfg.high,
            RiskLevel.CRITICAL: self.cfg.critical,
            RiskLevel.UNKNOWN: self.cfg.unknown,
        }[level]

        for name, params in table:
            # Если действие limit_scope без scope, а решение указывает limited_scope — подставим его
            if name == "limit_scope" and not params.get("scope") and decision.limited_scope:
                params = {**params, "scope": decision.limited_scope}
            plan.append(REGISTRY.create(name, **params))

        # Явное действие из решения (если отличается) добавим в конец цепочки
        explicit = decision.action.value
        if explicit not in [a.name for a in plan]:
            # Подставим разумные параметры
            extra_params: Dict[str, object] = {}
            if explicit == "limit_scope" and decision.limited_scope:
                extra_params["scope"] = decision.limited_scope
            plan.append(REGISTRY.create(explicit, **extra_params))
        return plan


# ==============================================================================
# Исполнитель плана
# ==============================================================================

class Executor:
    def __init__(self, services: Services, logger: Optional[logging.Logger] = None) -> None:
        self.services = services
        self.log = logger or logging.getLogger("zero_trust.risk.actions")

    def execute(self, plan: Iterable[Action], ctx: ActionContext, decision: RiskDecision) -> PlanResult:
        results: List[ActionResult] = []
        names: List[str] = []
        for action in plan:
            names.append(action.name)
            res = action.execute(ctx, decision, self.services)
            results.append(res)
        return PlanResult(plan=names, results=results, decision=decision, request_id=ctx.request_id)


# ==============================================================================
# Пример "no-op" реализаций сервисов для разработки/тестов
# ==============================================================================

class _NoOpSession(SessionManager):
    def end_session(self, session_id: str, reason: str) -> None:
        logging.getLogger("zero_trust.risk.actions.noop").info("end_session session=%s reason=%s", session_id, reason)

    def require_step_up(self, session_id: str, methods: Sequence[str], grace_seconds: int) -> None:
        logging.getLogger("zero_trust.risk.actions.noop").info("require_step_up session=%s methods=%s grace=%s", session_id, methods, grace_seconds)

    def set_bindings(self, session_id: str, *, sticky_ip: Optional[str] = None, sticky_asn: Optional[int] = None) -> None:
        logging.getLogger("zero_trust.risk.actions.noop").info("set_bindings session=%s sticky_ip=%s sticky_asn=%s", session_id, sticky_ip, sticky_asn)


class _NoOpTokens(TokenService):
    def revoke_all(self, session_id: Optional[str], user_id: Optional[str], reason: str) -> None:
        logging.getLogger("zero_trust.risk.actions.noop").warning("revoke_all session=%s user=%s reason=%s", session_id, user_id, reason)

    def limit_scope(self, session_id: Optional[str], user_id: Optional[str], scope: Sequence[str]) -> None:
        logging.getLogger("zero_trust.risk.actions.noop").warning("limit_scope session=%s user=%s scope=%s", session_id, user_id, scope)

    def set_ttl(self, session_id: Optional[str], access_ttl_seconds: int) -> None:
        logging.getLogger("zero_trust.risk.actions.noop").info("set_ttl session=%s ttl=%s", session_id, access_ttl_seconds)

    def rotate_refresh(self, session_id: Optional[str]) -> None:
        logging.getLogger("zero_trust.risk.actions.noop").info("rotate_refresh session=%s", session_id)


class _NoOpQuarantine(QuarantineService):
    def quarantine_device(self, device_id: str, severity: str, ttl_seconds: int, reason: str) -> None:
        logging.getLogger("zero_trrust.risk.actions.noop").error("quarantine device=%s severity=%s ttl=%s reason=%s", device_id, severity, ttl_seconds, reason)


class _NoOpBus(Publisher):
    def publish(self, event_name: str, payload: Dict[str, object]) -> None:
        logging.getLogger("zero_trust.risk.actions.audit").info("%s %s", event_name, json.dumps(payload, separators=(",", ":"), ensure_ascii=False))


def demo_services() -> Services:
    """
    Быстрый набор no-op сервисов для локальных тестов.
    """
    return Services(session=_NoOpSession(), tokens=_NoOpTokens(), quarantine=_NoOpQuarantine(), bus=_NoOpBus())


# ==============================================================================
# Утилиты и экспорт
# ==============================================================================

__all__ = [
    "RiskLevel",
    "RiskAction",
    "RiskDecision",
    "ActionContext",
    "ActionResult",
    "PlanResult",
    "SessionManager",
    "TokenService",
    "QuarantineService",
    "Publisher",
    "Services",
    "IdempotencyStore",
    "IDEMPOTENCY",
    "Action",
    "AllowAction",
    "StepUpAction",
    "LimitScopeAction",
    "DenyAction",
    "QuarantineAction",
    "ActionRegistry",
    "REGISTRY",
    "PlannerConfig",
    "Planner",
    "Executor",
    "demo_services",
]
