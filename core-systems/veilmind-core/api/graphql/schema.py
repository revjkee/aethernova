# -*- coding: utf-8 -*-
"""
GraphQL schema for veilmind-core (Strawberry).
Особенности:
  - Query: health, serverInfo, getConsent
  - Mutation: decide, scoreRisk, setConsent, emitTelemetry
  - Синтетический PDP/скоринг риска как fallback (можно заменить на реальные сервисы через context)
  - Идемпотентность через Idempotency-Key, корреляция X-Trace-Id
  - Единая ошибка Problem (RFC 7807-стиль) и union-результаты
  - Ограничение глубины запроса: QueryDepthLimiter
  - Безопасные дефолты и строгие enum’ы/типы
"""
from __future__ import annotations

import os
import time
from dataclasses import field
from typing import Any, Dict, List, Optional, Tuple, Union, TypedDict

import strawberry
from strawberry.extensions import QueryDepthLimiter
from strawberry.scalars import JSON
from strawberry.types import Info

# ============================== КОНТЕКСТ И КОНСТАНТЫ ==========================

VEILMIND_VERSION = os.getenv("VEILMIND_VERSION", "dev")
STARTED_AT = int(time.time())

# Ожидаем, что ASGI-слой (например, FastAPI) кладёт в контекст:
# - request: starlette.requests.Request (или совместимый)
# - services: dict с ключами 'pdp', 'consent', 'telemetry' (по желанию)
class GraphQLContext(TypedDict, total=False):
    request: Any
    services: Dict[str, Any]


TRACE_HEADER = "X-Trace-Id"
IDEMPOTENCY_HEADER = "Idempotency-Key"


def _trace_id(info: Info[GraphQLContext, Any]) -> str:
    req = info.context.get("request")
    try:
        tid = req.headers.get(TRACE_HEADER) if req and req.headers else None
    except Exception:
        tid = None
    return tid or f"{int(time.time()*1000):x}"


def _idempotency_key(info: Info[GraphQLContext, Any], provided: Optional[str]) -> Optional[str]:
    if provided:
        return provided
    req = info.context.get("request")
    try:
        return req.headers.get(IDEMPOTENCY_HEADER) if req and req.headers else None
    except Exception:
        return None


# ============================== ДОМЕННЫЕ ENUM/ТИПЫ ============================

@strawberry.enum
class Action(Enum):
    READ = "read"
    LIST = "list"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"


@strawberry.enum
class DecisionAction(Enum):
    ALLOW = "allow"
    STEP_UP = "step_up"
    QUARANTINE = "quarantine"
    DENY = "deny"


@strawberry.enum
class RiskBand(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@strawberry.enum
class ConsentStateEnum(Enum):
    ALLOW = "allow"
    DENY = "deny"
    PROMPT = "prompt"


@strawberry.type
class Problem:
    """Единый формат ошибки в data (дополнительно к GraphQL errors)."""
    title: str
    status: int
    detail: Optional[str] = None
    trace_id: Optional[str] = strawberry.field(name="traceId", default=None)


# -------- Входные типы --------

@strawberry.input
class SubjectInput:
    user_id: Optional[str] = None
    user_groups: Optional[List[str]] = None
    privilege: Optional[strawberry.enum(Enum)("Privilege", ["admin", "ops", "user"])] = None  # краткий enum
    device_id: Optional[str] = None
    posture_id: Optional[str] = None
    session_id: Optional[str] = None
    mfa_satisfied: Optional[bool] = None


@strawberry.input
class ResourceInput:
    id: Optional[str] = None
    labels: Optional[JSON] = None  # например, {"sensitivity": "high"}


@strawberry.input
class EnvironmentInput:
    ip: Optional[str] = None
    geo: Optional[str] = None
    asn: Optional[int] = None
    user_agent: Optional[str] = None
    timestamp: Optional[str] = None  # RFC3339


@strawberry.input
class DecisionRequestInput:
    subject: SubjectInput
    action: Action
    resource: ResourceInput
    environment: Optional[EnvironmentInput] = None
    context: Optional[JSON] = None
    idempotency_key: Optional[str] = strawberry.field(name="idempotencyKey", default=None)


@strawberry.input
class RiskScoreRequestInput:
    subject: SubjectInput
    resource: Optional[ResourceInput] = None
    action: Optional[Action] = None
    environment: Optional[EnvironmentInput] = None
    signals: Optional[JSON] = None


@strawberry.input
class ConsentSetInput:
    subject_id: str
    changes: JSON  # {"analytics":"allow", "ads":"deny"}
    evidence: Optional[JSON] = None


@strawberry.input
class TelemetryEventInput:
    type: strawberry.enum(Enum)("TelemetryType", ["access", "risk", "audit", "custom"])  # узкий enum
    ts: Optional[str] = None
    subject: Optional[JSON] = None
    fields: Optional[JSON] = None


# -------- Выходные типы --------

@strawberry.type
class ScoreDetails:
    total: float
    band: RiskBand
    explanations: Optional[JSON] = None


@strawberry.type
class Decision:
    decision: DecisionAction
    reason: Optional[str] = None
    score: Optional[ScoreDetails] = None
    obligations: Optional[JSON] = None
    policy: Optional[JSON] = None
    trace_id: Optional[str] = strawberry.field(name="traceId", default=None)


@strawberry.type
class ConsentKV:
    purpose: str
    state: ConsentStateEnum


# -------- Union-результаты (успех | проблема) --------

DecisionResult = strawberry.union("DecisionResult", (Decision, Problem))
ScoreResult = strawberry.union("ScoreResult", (ScoreDetails, Problem))
ConsentResult = strawberry.union("ConsentResult", (strawberry.list(ConsentKV), Problem))
TelemetryResult = strawberry.union("TelemetryResult", (strawberry.scalar(int), Problem))


# ============================== СИНТЕТИЧЕСКАЯ ЛОГИКА ==========================

def _synthetic_score(req: RiskScoreRequestInput) -> Tuple[float, RiskBand, list]:
    """Стабильный детерминированный скоринг (совместим со схемой risk.yaml)."""
    comps: list[tuple[str, float]] = []

    # Привилегии пользователя
    priv = (req.subject.privilege.value if req.subject.privilege else None)
    comps.append(("user.privilege_level", {"admin": 15.0, "ops": 8.0, "user": 0.0}.get(priv, 0.0)))

    # Риск действия
    if req.action:
        comps.append(("app.action_risk", {
            Action.READ: 0.0, Action.LIST: 2.0, Action.WRITE: 10.0, Action.DELETE: 16.0, Action.ADMIN: 22.0
        }[req.action]))

    # Чувствительность ресурса
    sens = None
    if req.resource and req.resource.labels and isinstance(req.resource.labels, dict):
        sens = req.resource.labels.get("sensitivity")
    comps.append(("app.resource_sensitivity", {"low": 0.0, "medium": 6.0, "high": 12.0, "secret": 20.0}.get(sens, 0.0)))

    # Репутация IP 0..1 -> 0..18
    ti = (req.signals or {}).get("threat_intel") if isinstance(req.signals, dict) else None
    rep = float(ti.get("score", 0.0)) if isinstance(ti, dict) else 0.0
    comps.append(("network.ip_reputation", max(0.0, min(1.0, rep)) * 18.0))

    # Риск от IdP 0..1 -> 0..25
    idp = (req.signals or {}).get("idp") if isinstance(req.signals, dict) else None
    idp_risk = float(idp.get("risk_score", 0.0)) if isinstance(idp, dict) else 0.0
    comps.append(("user.risk.idp_last_login", max(0.0, min(1.0, idp_risk)) * 25.0))

    # Постура устройства 0..100 -> 0..30
    posture = (req.signals or {}).get("posture") if isinstance(req.signals, dict) else None
    posture_score = float(posture.get("score", 0.0)) if isinstance(posture, dict) else 0.0
    comps.append(("device.posture_score", max(0.0, min(100.0, posture_score)) * 0.30))

    total = sum(v for _, v in comps)
    if total <= 29.999:
        band = RiskBand.LOW
    elif total <= 59.999:
        band = RiskBand.MEDIUM
    elif total <= 79.999:
        band = RiskBand.HIGH
    else:
        band = RiskBand.CRITICAL

    explanations = [{"key": k, "score": round(v, 3)} for k, v in comps]
    return round(total, 3), band, explanations


def _action_from_band(band: RiskBand) -> DecisionAction:
    return {
        RiskBand.LOW: DecisionAction.ALLOW,
        RiskBand.MEDIUM: DecisionAction.STEP_UP,
        RiskBand.HIGH: DecisionAction.QUARANTINE,
        RiskBand.CRITICAL: DecisionAction.DENY,
    }[band]


# ============================== РЕЗОЛВЕРЫ =====================================

@strawberry.type
class Query:
    @strawberry.field(description="Liveness/readiness и версия.")
    def health(self, info: Info[GraphQLContext, Any]) -> JSON:
        return {
            "status": "ok",
            "ready": True,
            "version": VEILMIND_VERSION,
            "startedAt": STARTED_AT,
            "now": int(time.time()),
            "traceId": _trace_id(info),
        }

    @strawberry.field(description="Информация о сервере и окружении.")
    def server_info(self, info: Info[GraphQLContext, Any]) -> JSON:
        req = info.context.get("request")
        ua = None
        try:
            ua = req.headers.get("user-agent") if req and req.headers else None
        except Exception:
            ua = None
        return {
            "name": "veilmind-core/graphql",
            "version": VEILMIND_VERSION,
            "client": {"userAgent": ua},
            "traceId": _trace_id(info),
        }

    @strawberry.field(description="Получить текущие согласия субъекта (список ключ-значение).")
    def get_consent(
        self,
        info: Info[GraphQLContext, Any],
        subject_id: str,
        purposes: Optional[List[str]] = None,
    ) -> ConsentResult:
        trace = _trace_id(info)
        svc = (info.context.get("services") or {}).get("consent")
        try:
            if svc:
                raw: Dict[str, str] = svc.get_state(subject_id, purposes=purposes)  # ожидаемый контракт
            else:
                # Синтетический fallback: пустые/deny для нерегулируемых целей
                raw = {p: "deny" for p in (purposes or [])}
            pairs = [ConsentKV(purpose=k, state=ConsentStateEnum(raw[k])) for k in raw]
            return pairs  # type: ignore[return-value]
        except Exception as e:
            return Problem(title="Consent retrieval failed", status=500, detail=str(e), trace_id=trace)


@strawberry.type
class Mutation:
    @strawberry.mutation(description="Принять решение PEP/PDP по запросу доступа.")
    def decide(self, info: Info[GraphQLContext, Any], input: DecisionRequestInput) -> DecisionResult:
        trace = _trace_id(info)
        idemp = _idempotency_key(info, input.idempotency_key)
        try:
            # Если подключён реальный PDP — используем его
            svc = (info.context.get("services") or {}).get("pdp")
            if svc:
                result = svc.decide(input, trace_id=trace, idempotency_key=idemp)  # контракт сервиса
                return Decision(**result)  # type: ignore[arg-type, return-value]

            # Иначе — синтетический fallback
            score_total, band, expl = _synthetic_score(
                RiskScoreRequestInput(
                    subject=input.subject,
                    resource=input.resource,
                    action=input.action,
                    environment=input.environment,
                    signals=(input.context or {}).get("signals") if isinstance(input.context, dict) else None,
                )
            )
            action = _action_from_band(band)

            # Guardrail: админ + опасные действия по secret/high → deny
            sens = None
            if input.resource.labels and isinstance(input.resource.labels, dict):
                sens = input.resource.labels.get("sensitivity")
            if (input.subject.privilege and input.subject.privilege.value == "admin") and \
               (input.action in (Action.DELETE, Action.ADMIN)) and \
               (sens in ("high", "secret")):
                action = DecisionAction.DENY

            dec = Decision(
                decision=action,
                reason="synthetic_policy",
                score=ScoreDetails(total=score_total, band=band, explanations=expl),
                obligations=(
                    {"type": "mfa", "params": {"methods": ["webauthn", "totp"], "timeoutSeconds": 120}}
                    if action == DecisionAction.STEP_UP else None
                ),
                policy={"version": "synthetic-1", "matchedRule": f"band:{band.value}"},
                trace_id=trace,
            )
            return dec
        except Exception as e:
            return Problem(title="Decision failed", status=500, detail=str(e), trace_id=trace)

    @strawberry.mutation(description="Рассчитать риск-скор по входным сигналам.")
    def score_risk(self, info: Info[GraphQLContext, Any], input: RiskScoreRequestInput) -> ScoreResult:
        trace = _trace_id(info)
        try:
            svc = (info.context.get("services") or {}).get("pdp")
            if svc and hasattr(svc, "score"):
                out = svc.score(input, trace_id=trace)  # контракт сервиса
                return ScoreDetails(**out)  # type: ignore[arg-type, return-value]
            total, band, expl = _synthetic_score(input)
            return ScoreDetails(total=total, band=band, explanations=expl)
        except Exception as e:
            return Problem(title="Risk scoring failed", status=500, detail=str(e), trace_id=trace)

    @strawberry.mutation(description="Установить/изменить согласия.")
    def set_consent(self, info: Info[GraphQLContext, Any], input: ConsentSetInput) -> ConsentResult:
        trace = _trace_id(info)
        try:
            svc = (info.context.get("services") or {}).get("consent")
            if not svc:
                return Problem(title="Consent service unavailable", status=503, detail="no service", trace_id=trace)
            svc.set_state(input.subject_id, changes=dict(input.changes), evidence=input.evidence or {}, trace_id=trace)
            raw = svc.get_state(input.subject_id, purposes=None)
            pairs = [ConsentKV(purpose=k, state=ConsentStateEnum(raw[k])) for k in raw]
            return pairs  # type: ignore[return-value]
        except Exception as e:
            return Problem(title="Consent update failed", status=500, detail=str(e), trace_id=trace)

    @strawberry.mutation(description="Отправить пакет телеметрии (возвращает число принятых событий).")
    def emit_telemetry(self, info: Info[GraphQLContext, Any], events: List[TelemetryEventInput]) -> TelemetryResult:
        trace = _trace_id(info)
        try:
            if len(events) > 1000:
                return Problem(title="Too many events", status=413, detail="max 1000", trace_id=trace)
            svc = (info.context.get("services") or {}).get("telemetry")
            accepted = 0
            if svc:
                accepted = svc.emit([e.__dict__ for e in events], trace_id=trace)  # контракт сервиса
            else:
                accepted = len(events)  # синтетический успех
            return accepted  # type: ignore[return-value]
        except Exception as e:
            return Problem(title="Telemetry failed", status=500, detail=str(e), trace_id=trace)


# ============================== СХЕМА =========================================

schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    extensions=[
        QueryDepthLimiter(max_depth=10),  # защита от слишком глубоких запросов
    ],
)

# ПРИМЕЧАНИЕ:
# 1) В FastAPI добавьте:
#    from strawberry.fastapi import GraphQLRouter
#    graphql_app = GraphQLRouter(schema, context_getter=lambda request: {"request": request, "services": {...}})
#    app.include_router(graphql_app, prefix="/graphql")
# 2) Авторизацию (Bearer/HMAC) выполняйте в ASGI-миддлваре и/или в context_getter.
