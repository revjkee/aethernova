# agent_mash/hr/agent.py
# Industrial-grade HR Agent core.
# Purpose: orchestrate HR workflows (screening, interview scheduling, offer pipeline, onboarding)
# with strict schemas, idempotency, auditability, policy gates, and async-first design.

from __future__ import annotations

import asyncio
import dataclasses
import enum
import hashlib
import json
import logging
import time
import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any, Final, Optional

try:
    from pydantic import BaseModel, ConfigDict, Field
except Exception as _e:  # pragma: no cover
    raise RuntimeError("pydantic is required for agent_mash.hr.agent") from _e


_LOG: Final[logging.Logger] = logging.getLogger(__name__)


class HRStage(str, enum.Enum):
    APPLIED = "applied"
    SCREENING = "screening"
    INTERVIEW = "interview"
    OFFER = "offer"
    HIRED = "hired"
    REJECTED = "rejected"
    ONBOARDING = "onboarding"
    CLOSED = "closed"


class HRDecision(str, enum.Enum):
    ADVANCE = "advance"
    HOLD = "hold"
    REJECT = "reject"
    REQUEST_INFO = "request_info"


class HRError(RuntimeError):
    pass


class HRPolicyViolation(HRError):
    pass


class HRTransientError(HRError):
    pass


class HRConflictError(HRError):
    pass


class HRTimeoutError(HRError):
    pass


class CandidateProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    candidate_id: str = Field(min_length=8, max_length=128)
    full_name: str = Field(min_length=1, max_length=256)
    email: Optional[str] = Field(default=None, max_length=320)
    phone: Optional[str] = Field(default=None, max_length=64)

    location: Optional[str] = Field(default=None, max_length=128)
    timezone: Optional[str] = Field(default=None, max_length=64)

    # Ссылки (LinkedIn/GitHub/Portfolio) строго как список URL-строк
    links: list[str] = Field(default_factory=list)

    # Резюме / заметки в свободной форме
    summary: Optional[str] = Field(default=None, max_length=4000)

    # Структурированная информация
    skills: list[str] = Field(default_factory=list)
    years_experience: Optional[float] = Field(default=None, ge=0.0, le=80.0)

    # Метаданные
    created_ts: float = Field(default_factory=lambda: time.time())


class PositionProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    position_id: str = Field(min_length=6, max_length=128)
    title: str = Field(min_length=1, max_length=256)
    department: Optional[str] = Field(default=None, max_length=128)
    location: Optional[str] = Field(default=None, max_length=128)
    employment_type: Optional[str] = Field(default=None, max_length=64)  # full-time/contract/etc

    required_skills: list[str] = Field(default_factory=list)
    nice_to_have_skills: list[str] = Field(default_factory=list)

    # Условия
    salary_min: Optional[int] = Field(default=None, ge=0)
    salary_max: Optional[int] = Field(default=None, ge=0)
    currency: Optional[str] = Field(default=None, max_length=8)

    # Порог для автопродвижения
    screening_threshold: float = Field(default=0.70, ge=0.0, le=1.0)


class HRContext(BaseModel):
    """
    Контекст заявки кандидата для данной позиции.
    """
    model_config = ConfigDict(extra="forbid")

    tenant_id: Optional[str] = Field(default=None, max_length=128)
    position: PositionProfile
    candidate: CandidateProfile

    stage: HRStage = HRStage.APPLIED

    # История событий и заметок
    notes: list[str] = Field(default_factory=list)

    # Служебные признаки/метрики (скоры и т. п.)
    features: dict[str, Any] = Field(default_factory=dict)

    # Корреляция и аудит
    trace_id: Optional[str] = Field(default=None, max_length=128)
    request_id: str = Field(default_factory=lambda: uuid.uuid4().hex)

    ts: float = Field(default_factory=lambda: time.time())


class HRActionType(str, enum.Enum):
    ADD_NOTE = "add_note"
    SET_STAGE = "set_stage"
    REQUEST_INFO = "request_info"
    SCHEDULE_INTERVIEW = "schedule_interview"
    SEND_OFFER = "send_offer"
    CLOSE = "close"


class HRAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_type: HRActionType
    payload: dict[str, Any] = Field(default_factory=dict)


class HRResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision_id: str = Field(min_length=16, max_length=256)
    decision: HRDecision
    stage_before: HRStage
    stage_after: HRStage
    score: float = Field(ge=0.0, le=1.0)
    reason: str = Field(min_length=1, max_length=4000)

    actions: list[HRAction] = Field(default_factory=list)

    applied_policies: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)

    ts: float
    trace_id: Optional[str] = Field(default=None, max_length=128)
    request_id: str = Field(min_length=8, max_length=128)


class HRAuditSink:
    async def emit(self, event: dict[str, Any]) -> None:  # pragma: no cover
        raise NotImplementedError


class NullHRAuditSink(HRAuditSink):
    async def emit(self, event: dict[str, Any]) -> None:
        return


@dataclasses.dataclass(frozen=True)
class HRPolicyResult:
    policy_name: str
    # Если policy блокирует действие — ставим violated=True
    violated: bool
    reason: str
    evidence: dict[str, Any] = dataclasses.field(default_factory=dict)


HRPolicyFn = Callable[[HRContext], Awaitable[HRPolicyResult]]


class HRScoringModel:
    """
    Интерфейс скоринга. Реальную модель можно подключать отдельно.
    """
    async def score(self, ctx: HRContext) -> tuple[float, dict[str, Any]]:  # pragma: no cover
        raise NotImplementedError


class HeuristicScoringModel(HRScoringModel):
    """
    Детерминированный эвристический скоринг без внешних зависимостей.
    Это безопасный baseline для промышленного каркаса.
    """
    async def score(self, ctx: HRContext) -> tuple[float, dict[str, Any]]:
        pos = ctx.position
        cand = ctx.candidate

        req = {_norm_skill(s) for s in pos.required_skills if s}
        nice = {_norm_skill(s) for s in pos.nice_to_have_skills if s}
        have = {_norm_skill(s) for s in cand.skills if s}

        req_hit = len(req & have)
        nice_hit = len(nice & have)

        req_score = (req_hit / len(req)) if req else 0.5
        nice_score = (nice_hit / len(nice)) if nice else 0.0

        exp = cand.years_experience if cand.years_experience is not None else 0.0
        exp_score = min(1.0, exp / 5.0)  # saturate at 5y

        # Веса фиксированы и детерминированы
        score = (0.65 * req_score) + (0.15 * nice_score) + (0.20 * exp_score)
        score = max(0.0, min(1.0, float(score)))

        evidence = {
            "required_skills_total": len(req),
            "required_skills_hit": req_hit,
            "nice_skills_total": len(nice),
            "nice_skills_hit": nice_hit,
            "years_experience": exp,
            "req_score": req_score,
            "nice_score": nice_score,
            "exp_score": exp_score,
        }
        return score, evidence


class HRLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Размер features/notes ограничиваем, чтобы не превращать контекст в мусор
    max_notes: int = Field(default=200, ge=1)
    max_note_len: int = Field(default=2000, ge=64)

    max_features_keys: int = Field(default=256, ge=16)
    max_feature_value_len: int = Field(default=8000, ge=256)

    # Таймауты
    scoring_timeout_sec: float = Field(default=1.0, gt=0.0)
    policy_timeout_sec: float = Field(default=0.35, gt=0.0)

    # Идемпотентность: окно для повторов
    idempotency_window_sec: float = Field(default=3600.0, gt=0.0)


class HRConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision_salt: str = Field(default="agent_mash:hr:agent:v1", min_length=8, max_length=256)
    limits: HRLimits = Field(default_factory=HRLimits)

    # Пороговый скор по умолчанию, если позиция не задала свой
    default_screening_threshold: float = Field(default=0.70, ge=0.0, le=1.0)

    # Поведение при сбое policy: fail-closed
    strict_policy_fail_closed: bool = Field(default=True)


class IdempotencyStore:
    """
    Интерфейс хранилища идемпотентности.
    """
    async def get(self, key: str) -> Optional[dict[str, Any]]:  # pragma: no cover
        raise NotImplementedError

    async def set(self, key: str, value: dict[str, Any], ttl_sec: float) -> None:  # pragma: no cover
        raise NotImplementedError


class InMemoryIdempotencyStore(IdempotencyStore):
    """
    Минимальная in-memory реализация. Для прод — заменить на Redis/DB.
    """
    def __init__(self) -> None:
        self._data: dict[str, tuple[float, dict[str, Any]]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[dict[str, Any]]:
        async with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            exp_ts, val = item
            if time.time() > exp_ts:
                self._data.pop(key, None)
                return None
            return val

    async def set(self, key: str, value: dict[str, Any], ttl_sec: float) -> None:
        async with self._lock:
            self._data[key] = (time.time() + float(ttl_sec), value)


class HRAgent:
    """
    HR-агент с промышленным каркасом:
    - строгие схемы входа/выхода
    - скоринг (плагин)
    - политики (цепочка)
    - аудит
    - идемпотентность
    """

    def __init__(
        self,
        config: HRConfig | None = None,
        scoring_model: HRScoringModel | None = None,
        policies: Sequence[HRPolicyFn] | None = None,
        audit_sink: HRAuditSink | None = None,
        idempotency: IdempotencyStore | None = None,
    ) -> None:
        self._cfg = config or HRConfig()
        self._scorer = scoring_model or HeuristicScoringModel()
        self._policies: list[HRPolicyFn] = list(policies or [])
        self._audit: HRAuditSink = audit_sink or NullHRAuditSink()
        self._idem: IdempotencyStore = idempotency or InMemoryIdempotencyStore()

    @property
    def config(self) -> HRConfig:
        return self._cfg

    def register_policy(self, policy: HRPolicyFn) -> None:
        self._policies.append(policy)

    async def run(self, ctx: HRContext) -> HRResult:
        self._validate_context(ctx)

        # Idempotency key включает request_id, position_id, candidate_id и stage.
        idem_key = self._idempotency_key(ctx)
        cached = await self._idem.get(idem_key)
        if cached is not None:
            try:
                return HRResult.model_validate(cached)
            except Exception:
                # Если кэш битый — игнорируем и считаем заново.
                pass

        stage_before = ctx.stage

        score, score_evidence = await self._score(ctx)
        policies_applied, policy_evidence = await self._apply_policies(ctx)

        threshold = float(ctx.position.screening_threshold) if ctx.position.screening_threshold is not None else float(
            self._cfg.default_screening_threshold
        )

        decision, stage_after, actions, reason = self._decide(
            ctx=ctx,
            score=score,
            threshold=threshold,
            policies_applied=policies_applied,
        )

        decision_id = self._decision_id(ctx, score=score, threshold=threshold, decision=decision.value, stage_after=stage_after.value)

        out = HRResult(
            decision_id=decision_id,
            decision=decision,
            stage_before=stage_before,
            stage_after=stage_after,
            score=score,
            reason=reason,
            actions=actions,
            applied_policies=policies_applied,
            evidence=_json_sanitize(
                {
                    "scoring": score_evidence,
                    "policies": policy_evidence,
                    "threshold": threshold,
                }
            ),
            ts=time.time(),
            trace_id=ctx.trace_id,
            request_id=ctx.request_id,
        )

        await self._audit_emit(ctx, out)

        # Сохраняем идемпотентный результат
        await self._idem.set(
            idem_key,
            out.model_dump(),
            ttl_sec=self._cfg.limits.idempotency_window_sec,
        )

        return out

    def _validate_context(self, ctx: HRContext) -> None:
        lim = self._cfg.limits

        if len(ctx.notes) > lim.max_notes:
            raise HRPolicyViolation("notes limit exceeded")

        for n in ctx.notes:
            if len(n) > lim.max_note_len:
                raise HRPolicyViolation("note length limit exceeded")

        if len(ctx.features.keys()) > lim.max_features_keys:
            raise HRPolicyViolation("features keys limit exceeded")

        # Проверяем JSON-совместимость features
        try:
            raw = json.dumps(_json_sanitize(ctx.features), separators=(",", ":"), ensure_ascii=False)
        except Exception as e:
            raise HRPolicyViolation("features is not JSON-serializable") from e

        if len(raw.encode("utf-8")) > lim.max_feature_value_len * max(1, len(ctx.features)):
            # верхняя оценка на размер; точная проверка потребует обхода всех значений
            raise HRPolicyViolation("features size limit exceeded")

    async def _score(self, ctx: HRContext) -> tuple[float, dict[str, Any]]:
        try:
            score, evidence = await asyncio.wait_for(
                self._scorer.score(ctx),
                timeout=self._cfg.limits.scoring_timeout_sec,
            )
        except asyncio.TimeoutError as e:
            raise HRTimeoutError("scoring timeout") from e
        except Exception as e:
            raise HRTransientError("scoring failed") from e

        score = float(max(0.0, min(1.0, score)))
        return score, _json_sanitize(evidence)

    async def _apply_policies(self, ctx: HRContext) -> tuple[list[str], dict[str, Any]]:
        applied: list[str] = []
        evidence: dict[str, Any] = {}

        for pol in self._policies:
            try:
                res = await asyncio.wait_for(pol(ctx), timeout=self._cfg.limits.policy_timeout_sec)
            except asyncio.TimeoutError as e:
                if self._cfg.strict_policy_fail_closed:
                    raise HRPolicyViolation("policy timeout (fail-closed)") from e
                res = HRPolicyResult(policy_name=getattr(pol, "__name__", "policy"), violated=True, reason="policy timeout")

            except Exception as e:
                if self._cfg.strict_policy_fail_closed:
                    raise HRPolicyViolation("policy error (fail-closed)") from e
                res = HRPolicyResult(policy_name=getattr(pol, "__name__", "policy"), violated=True, reason="policy error")

            if not isinstance(res, HRPolicyResult):
                raise HRPolicyViolation("policy returned invalid result type")

            if not res.policy_name:
                raise HRPolicyViolation("policy_name is required")

            applied.append(res.policy_name)
            evidence[res.policy_name] = {
                "violated": bool(res.violated),
                "reason": str(res.reason),
                "evidence": _json_sanitize(res.evidence),
            }

            if res.violated:
                # Блокирующая политика: сразу стоп
                raise HRPolicyViolation(f"policy violated: {res.policy_name}: {res.reason}")

        return applied, _json_sanitize(evidence)

    def _decide(
        self,
        ctx: HRContext,
        score: float,
        threshold: float,
        policies_applied: list[str],
    ) -> tuple[HRDecision, HRStage, list[HRAction], str]:
        stage = ctx.stage
        actions: list[HRAction] = []

        # Базовая логика:
        # - APPLIED -> SCREENING (если score >= threshold)
        # - иначе HOLD + REQUEST_INFO (если нет данных)
        # - Если stage уже дальше — не откатываем, только advance/hold/reject
        if stage in (HRStage.REJECTED, HRStage.CLOSED, HRStage.HIRED):
            return HRDecision.HOLD, stage, actions, "terminal stage"

        if stage == HRStage.APPLIED:
            if score >= threshold:
                actions.append(HRAction(action_type=HRActionType.SET_STAGE, payload={"stage": HRStage.SCREENING.value}))
                actions.append(HRAction(action_type=HRActionType.ADD_NOTE, payload={"note": "auto-advanced to screening"}))
                return HRDecision.ADVANCE, HRStage.SCREENING, actions, "score above threshold"
            else:
                missing = _infer_missing_candidate_info(ctx.candidate)
                if missing:
                    actions.append(
                        HRAction(
                            action_type=HRActionType.REQUEST_INFO,
                            payload={"fields": missing},
                        )
                    )
                    actions.append(
                        HRAction(
                            action_type=HRActionType.ADD_NOTE,
                            payload={"note": "requested missing candidate info"},
                        )
                    )
                    return HRDecision.REQUEST_INFO, HRStage.APPLIED, actions, "score below threshold and missing info"
                actions.append(HRAction(action_type=HRActionType.ADD_NOTE, payload={"note": "held after initial screening"}))
                return HRDecision.HOLD, HRStage.APPLIED, actions, "score below threshold"

        if stage == HRStage.SCREENING:
            if score >= threshold:
                actions.append(HRAction(action_type=HRActionType.SET_STAGE, payload={"stage": HRStage.INTERVIEW.value}))
                actions.append(HRAction(action_type=HRActionType.SCHEDULE_INTERVIEW, payload={"mode": "auto"}))
                return HRDecision.ADVANCE, HRStage.INTERVIEW, actions, "passed screening"
            actions.append(HRAction(action_type=HRActionType.ADD_NOTE, payload={"note": "screening hold"}))
            return HRDecision.HOLD, HRStage.SCREENING, actions, "screening hold"

        if stage == HRStage.INTERVIEW:
            # Решение по интервью обычно внешнее, здесь только safe-hold
            actions.append(HRAction(action_type=HRActionType.ADD_NOTE, payload={"note": "awaiting interview feedback"}))
            return HRDecision.HOLD, HRStage.INTERVIEW, actions, "waiting interview feedback"

        if stage == HRStage.OFFER:
            actions.append(HRAction(action_type=HRActionType.ADD_NOTE, payload={"note": "offer stage managed externally"}))
            return HRDecision.HOLD, HRStage.OFFER, actions, "offer in progress"

        if stage == HRStage.ONBOARDING:
            actions.append(HRAction(action_type=HRActionType.ADD_NOTE, payload={"note": "onboarding in progress"}))
            return HRDecision.HOLD, HRStage.ONBOARDING, actions, "onboarding in progress"

        # fallback
        actions.append(HRAction(action_type=HRActionType.ADD_NOTE, payload={"note": "no rule matched, holding"}))
        return HRDecision.HOLD, stage, actions, "no rule matched"

    def _idempotency_key(self, ctx: HRContext) -> str:
        payload = {
            "tenant_id": ctx.tenant_id,
            "request_id": ctx.request_id,
            "position_id": ctx.position.position_id,
            "candidate_id": ctx.candidate.candidate_id,
            "stage": ctx.stage.value,
        }
        packed = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        h = hashlib.blake2b(digest_size=16, person=self._cfg.decision_salt.encode("utf-8"))
        h.update(packed)
        return "idem:" + h.hexdigest()

    def _decision_id(self, ctx: HRContext, score: float, threshold: float, decision: str, stage_after: str) -> str:
        payload = {
            "tenant_id": ctx.tenant_id,
            "position_id": ctx.position.position_id,
            "candidate_id": ctx.candidate.candidate_id,
            "request_id": ctx.request_id,
            "stage_before": ctx.stage.value,
            "stage_after": stage_after,
            "decision": decision,
            "score": round(float(score), 6),
            "threshold": round(float(threshold), 6),
        }
        packed = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        h = hashlib.blake2b(digest_size=16, person=self._cfg.decision_salt.encode("utf-8"))
        h.update(packed)
        return h.hexdigest()

    async def _audit_emit(self, ctx: HRContext, out: HRResult) -> None:
        event = {
            "type": "hr.agent.decision",
            "ts": out.ts,
            "decision_id": out.decision_id,
            "tenant_id": ctx.tenant_id,
            "position_id": ctx.position.position_id,
            "candidate_id": ctx.candidate.candidate_id,
            "stage_before": out.stage_before.value,
            "stage_after": out.stage_after.value,
            "decision": out.decision.value,
            "score": out.score,
            "reason": out.reason,
            "actions": [a.model_dump() for a in out.actions],
            "applied_policies": list(out.applied_policies),
            "trace_id": out.trace_id,
            "request_id": out.request_id,
            "evidence": _json_sanitize(out.evidence),
        }
        try:
            await self._audit.emit(event)
        except Exception as e:
            _LOG.exception("HR audit sink failed")
            raise HRError("audit sink failed") from e


def _norm_skill(s: str) -> str:
    return " ".join(s.strip().lower().split())


def _infer_missing_candidate_info(c: CandidateProfile) -> list[str]:
    missing: list[str] = []
    if not c.email:
        missing.append("email")
    if not c.phone:
        missing.append("phone")
    if not c.skills:
        missing.append("skills")
    return missing


def _json_sanitize(obj: Any) -> Any:
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
    if hasattr(obj, "model_dump"):
        return _json_sanitize(obj.model_dump())
    if hasattr(obj, "dict"):
        return _json_sanitize(obj.dict())
    return str(obj)
