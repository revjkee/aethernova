# agent_mash/governance/ai_governor.py
# Industrial-grade AI governance gate for trading-agent decisions.
# Focus: deterministic decision identity, policy enforcement, escalation, veto, rate-limits, audit trail.

from __future__ import annotations

import asyncio
import dataclasses
import enum
import hashlib
import json
import logging
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any, Final, Optional

try:
    from pydantic import BaseModel, Field, ConfigDict
except Exception as _e:  # pragma: no cover
    raise RuntimeError("pydantic is required for agent_mash.governance.ai_governor") from _e


_LOG: Final[logging.Logger] = logging.getLogger(__name__)


class DecisionStatus(str, enum.Enum):
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"
    REQUIRE_APPROVAL = "require_approval"
    DEFER = "defer"


class DecisionSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyAction(str, enum.Enum):
    PASS_ = "pass"
    DENY = "deny"
    ESCALATE = "escalate"
    REQUIRE_APPROVAL = "require_approval"
    DEFER = "defer"


class GovernorError(RuntimeError):
    pass


class PolicyViolation(GovernorError):
    pass


class GovernorDefer(GovernorError):
    pass


class AuditSinkError(GovernorError):
    pass


class DecisionRequest(BaseModel):
    """
    Governance вход: намерение/решение, которое агент хочет выполнить.
    """
    model_config = ConfigDict(extra="forbid")

    actor_id: str = Field(min_length=1, max_length=256)
    agent_id: str = Field(min_length=1, max_length=256)
    tenant_id: Optional[str] = Field(default=None, max_length=256)

    intent: str = Field(min_length=1, max_length=512)
    operation: str = Field(min_length=1, max_length=256)

    scope: Optional[str] = Field(default=None, max_length=256)
    risk_tier: Optional[str] = Field(default=None, max_length=64)

    # Доп. контекст строго через JSON-совместимые типы
    context: dict[str, Any] = Field(default_factory=dict)

    # Идентификатор корреляции (трассировка/аудит)
    trace_id: Optional[str] = Field(default=None, max_length=256)

    # Время события (секунды epoch). Если не задано — ставим при обработке.
    ts: Optional[float] = Field(default=None)

    def normalized_payload(self) -> dict[str, Any]:
        """
        Нормализованный payload для детерминированного хэширования.
        Исключает несущественные поля, зависит от intent/operation/context.
        """
        return {
            "actor_id": self.actor_id,
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "intent": self.intent,
            "operation": self.operation,
            "scope": self.scope,
            "risk_tier": self.risk_tier,
            "context": _json_sanitize(self.context),
        }


class DecisionOutcome(BaseModel):
    """
    Governance выход: итоговое решение и причины.
    """
    model_config = ConfigDict(extra="forbid")

    decision_id: str = Field(min_length=16, max_length=256)
    status: DecisionStatus
    severity: DecisionSeverity
    reason: str = Field(min_length=1, max_length=2048)

    # Какие политики сработали и что сделали
    applied_policies: list[str] = Field(default_factory=list)

    # Время принятия решения
    ts: float

    # Доп. данные для аудита/объяснимости (строго JSON-типы)
    evidence: dict[str, Any] = Field(default_factory=dict)

    # Эскалация/апрувал
    escalation_target: Optional[str] = Field(default=None, max_length=256)
    approval_group: Optional[str] = Field(default=None, max_length=256)

    # Технические поля
    trace_id: Optional[str] = Field(default=None, max_length=256)


class GovernorLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Rate limit: токены в секунду на actor_id или agent_id
    max_decisions_per_sec: float = Field(default=20.0, gt=0.0)
    burst: int = Field(default=40, ge=1)

    # Максимальный размер контекста (в байтах JSON) на вход
    max_context_bytes: int = Field(default=64_000, ge=1_024)

    # Таймаут выполнения одной политики
    policy_timeout_sec: float = Field(default=0.25, gt=0.0)

    # Максимум политик в цепочке
    max_policies: int = Field(default=64, ge=1)


class GovernorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Детерминированный хэш: соль для пространства решений
    decision_salt: str = Field(default="agent_mash:ai_governor:v1", min_length=8, max_length=256)

    limits: GovernorLimits = Field(default_factory=GovernorLimits)

    # Поведение по умолчанию, если политики не дали запрет/эскалацию
    default_severity: DecisionSeverity = DecisionSeverity.LOW

    # Если политика вернула DEFER — сколько секунд ждать (для внешнего планировщика)
    default_defer_seconds: float = Field(default=0.2, gt=0.0)

    # Включить строгий режим: любое исключение в политике = DENY
    strict_policy_fail_closed: bool = Field(default=True)

    # Политика/группа апрува по умолчанию (если требуется approval)
    default_approval_group: Optional[str] = Field(default=None, max_length=256)

    # Цель эскалации по умолчанию (если требуется escalation)
    default_escalation_target: Optional[str] = Field(default=None, max_length=256)


@dataclasses.dataclass(frozen=True)
class PolicyResult:
    action: PolicyAction
    policy_name: str
    reason: str
    severity: DecisionSeverity = DecisionSeverity.LOW
    evidence: dict[str, Any] = dataclasses.field(default_factory=dict)
    escalation_target: Optional[str] = None
    approval_group: Optional[str] = None


PolicyFn = Callable[[DecisionRequest], Awaitable[PolicyResult]]


class AuditSink:
    """
    Интерфейс аудита. Реализацию можно вынести в отдельный модуль (Kafka/DB/HTTP).
    """
    async def emit(self, event: dict[str, Any]) -> None:  # pragma: no cover
        raise NotImplementedError


class NullAuditSink(AuditSink):
    async def emit(self, event: dict[str, Any]) -> None:
        return


class TokenBucket:
    """
    Потокобезопасный token-bucket для rate limiting.
    """
    __slots__ = ("_rate", "_capacity", "_tokens", "_ts", "_lock")

    def __init__(self, rate_per_sec: float, capacity: int) -> None:
        self._rate = float(rate_per_sec)
        self._capacity = float(capacity)
        self._tokens = float(capacity)
        self._ts = time.monotonic()
        self._lock = asyncio.Lock()

    async def consume(self, tokens: float = 1.0) -> bool:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._ts
            self._ts = now

            self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)

            if self._tokens >= tokens:
                self._tokens -= tokens
                return True

            return False


class AIGovernor:
    """
    Центральная точка принятия governance-решений.
    """

    def __init__(
        self,
        config: GovernorConfig | None = None,
        policies: Sequence[PolicyFn] | None = None,
        audit_sink: AuditSink | None = None,
    ) -> None:
        self._cfg = config or GovernorConfig()
        self._policies: list[PolicyFn] = list(policies or [])
        self._audit: AuditSink = audit_sink or NullAuditSink()

        self._buckets_by_actor: dict[str, TokenBucket] = {}
        self._buckets_by_agent: dict[str, TokenBucket] = {}
        self._buckets_lock = asyncio.Lock()

    @property
    def config(self) -> GovernorConfig:
        return self._cfg

    def register_policy(self, policy: PolicyFn) -> None:
        if len(self._policies) >= self._cfg.limits.max_policies:
            raise GovernorError("policy limit exceeded")
        self._policies.append(policy)

    async def decide(self, req: DecisionRequest) -> DecisionOutcome:
        ts = float(req.ts) if req.ts is not None else time.time()
        trace_id = req.trace_id

        self._validate_request(req)

        decision_id = self._compute_decision_id(req)
        await self._rate_limit(req, decision_id=decision_id, ts=ts)

        applied: list[str] = []
        evidence: dict[str, Any] = {}

        # По умолчанию — allow
        final_status = DecisionStatus.ALLOW
        final_severity = self._cfg.default_severity
        final_reason = "allowed by default"
        escalation_target = None
        approval_group = None

        try:
            for policy in self._policies:
                res = await self._run_policy(policy, req)
                applied.append(res.policy_name)

                if res.evidence:
                    evidence.setdefault("policies", {})
                    evidence["policies"][res.policy_name] = _json_sanitize(res.evidence)

                # Накапливаем максимальную severity по цепочке
                final_severity = _max_severity(final_severity, res.severity)

                if res.action == PolicyAction.PASS_:
                    continue

                if res.action == PolicyAction.DENY:
                    final_status = DecisionStatus.DENY
                    final_reason = res.reason
                    break

                if res.action == PolicyAction.ESCALATE:
                    final_status = DecisionStatus.ESCALATE
                    final_reason = res.reason
                    escalation_target = res.escalation_target or self._cfg.default_escalation_target
                    break

                if res.action == PolicyAction.REQUIRE_APPROVAL:
                    final_status = DecisionStatus.REQUIRE_APPROVAL
                    final_reason = res.reason
                    approval_group = res.approval_group or self._cfg.default_approval_group
                    break

                if res.action == PolicyAction.DEFER:
                    final_status = DecisionStatus.DEFER
                    final_reason = res.reason
                    break

        except Exception as e:
            if self._cfg.strict_policy_fail_closed:
                final_status = DecisionStatus.DENY
                final_reason = "policy execution failed (fail-closed)"
                evidence.setdefault("errors", [])
                evidence["errors"].append(
                    {"type": type(e).__name__, "message": str(e)}
                )
            else:
                final_status = DecisionStatus.ESCALATE
                final_reason = "policy execution failed (fail-open escalate)"
                evidence.setdefault("errors", [])
                evidence["errors"].append(
                    {"type": type(e).__name__, "message": str(e)}
                )
                escalation_target = self._cfg.default_escalation_target

        out = DecisionOutcome(
            decision_id=decision_id,
            status=final_status,
            severity=final_severity,
            reason=final_reason,
            applied_policies=applied,
            ts=ts,
            evidence=_json_sanitize(evidence),
            escalation_target=escalation_target,
            approval_group=approval_group,
            trace_id=trace_id,
        )

        await self._audit_decision(req=req, out=out)
        return out

    def _validate_request(self, req: DecisionRequest) -> None:
        # Контекст должен быть JSON-совместимым и ограниченным по размеру
        try:
            raw = json.dumps(_json_sanitize(req.context), separators=(",", ":"), ensure_ascii=False)
        except Exception as e:
            raise PolicyViolation("context is not JSON-serializable") from e

        if len(raw.encode("utf-8")) > self._cfg.limits.max_context_bytes:
            raise PolicyViolation("context size limit exceeded")

    def _compute_decision_id(self, req: DecisionRequest) -> str:
        payload = req.normalized_payload()
        packed = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

        h = hashlib.blake2b(digest_size=16, person=self._cfg.decision_salt.encode("utf-8"))
        h.update(packed)
        return h.hexdigest()

    async def _rate_limit(self, req: DecisionRequest, decision_id: str, ts: float) -> None:
        lim = self._cfg.limits
        actor_bucket = await self._get_bucket(self._buckets_by_actor, req.actor_id, lim.max_decisions_per_sec, lim.burst)
        agent_bucket = await self._get_bucket(self._buckets_by_agent, req.agent_id, lim.max_decisions_per_sec, lim.burst)

        ok_actor = await actor_bucket.consume(1.0)
        ok_agent = await agent_bucket.consume(1.0)

        if ok_actor and ok_agent:
            return

        await self._audit.emit(
            {
                "type": "governor.rate_limit",
                "ts": ts,
                "decision_id": decision_id,
                "actor_id": req.actor_id,
                "agent_id": req.agent_id,
                "tenant_id": req.tenant_id,
                "trace_id": req.trace_id,
                "ok_actor": ok_actor,
                "ok_agent": ok_agent,
            }
        )

        raise GovernorDefer("rate limited")

    async def _get_bucket(
        self,
        store: dict[str, TokenBucket],
        key: str,
        rate: float,
        burst: int,
    ) -> TokenBucket:
        async with self._buckets_lock:
            b = store.get(key)
            if b is None:
                b = TokenBucket(rate_per_sec=rate, capacity=burst)
                store[key] = b
            return b

    async def _run_policy(self, policy: PolicyFn, req: DecisionRequest) -> PolicyResult:
        timeout = self._cfg.limits.policy_timeout_sec
        try:
            res = await asyncio.wait_for(policy(req), timeout=timeout)
        except asyncio.TimeoutError as e:
            raise PolicyViolation("policy timeout") from e

        # Жёсткая нормализация результата
        if not isinstance(res, PolicyResult):
            raise PolicyViolation("policy returned invalid result type")

        if not res.policy_name:
            raise PolicyViolation("policy_name is required")

        if not res.reason:
            raise PolicyViolation("policy reason is required")

        return PolicyResult(
            action=res.action,
            policy_name=res.policy_name,
            reason=res.reason,
            severity=res.severity,
            evidence=_json_sanitize(res.evidence),
            escalation_target=res.escalation_target,
            approval_group=res.approval_group,
        )

    async def _audit_decision(self, req: DecisionRequest, out: DecisionOutcome) -> None:
        event = {
            "type": "governor.decision",
            "ts": out.ts,
            "decision_id": out.decision_id,
            "status": out.status.value,
            "severity": out.severity.value,
            "reason": out.reason,
            "actor_id": req.actor_id,
            "agent_id": req.agent_id,
            "tenant_id": req.tenant_id,
            "operation": req.operation,
            "intent": req.intent,
            "scope": req.scope,
            "risk_tier": req.risk_tier,
            "trace_id": out.trace_id,
            "applied_policies": list(out.applied_policies),
            "escalation_target": out.escalation_target,
            "approval_group": out.approval_group,
            "evidence": _json_sanitize(out.evidence),
        }

        try:
            await self._audit.emit(event)
        except Exception as e:
            _LOG.exception("audit sink failed")
            raise AuditSinkError("audit sink failed") from e


def _json_sanitize(obj: Any) -> Any:
    """
    Приводит объект к JSON-совместимому виду без потери ключевой структуры.
    """
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, enum.Enum):
        return obj.value
    if isinstance(obj, Mapping):
        return {str(k): _json_sanitize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_json_sanitize(v) for v in obj]
    if dataclasses.is_dataclass(obj):
        return _json_sanitize(dataclasses.asdict(obj))
    if hasattr(obj, "model_dump"):  # pydantic v2
        return _json_sanitize(obj.model_dump())
    if hasattr(obj, "dict"):  # pydantic v1
        return _json_sanitize(obj.dict())
    return str(obj)


_SEVERITY_ORDER: Final[dict[DecisionSeverity, int]] = {
    DecisionSeverity.LOW: 0,
    DecisionSeverity.MEDIUM: 1,
    DecisionSeverity.HIGH: 2,
    DecisionSeverity.CRITICAL: 3,
}


def _max_severity(a: DecisionSeverity, b: DecisionSeverity) -> DecisionSeverity:
    return a if _SEVERITY_ORDER[a] >= _SEVERITY_ORDER[b] else b
