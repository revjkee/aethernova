# file: zero-trust-core/api/graphql/schema.py
from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import json
import typing as t

import strawberry
from strawberry.dataloader import DataLoader
from strawberry.permission import BasePermission
from strawberry.types import Info
from strawberry.schema.config import StrawberryConfig

# =========================
# Контекст и сервисы
# =========================

@dataclasses.dataclass(frozen=True)
class UserCtx:
    sub: str
    scopes: t.FrozenSet[str]
    tenant_id: t.Optional[str] = None

@dataclasses.dataclass
class RiskService:
    """
    Адаптер к доменному слою риска.
    Ожидаемые методы должны быть реализованы и внедрены при инициализации GraphQL.
    """
    async def evaluate_risk(self, payload: dict) -> dict: ...
    async def ingest_event(self, payload: dict, *, idempotency_key: t.Optional[str]) -> dict: ...
    async def list_events(self, *, first: int, after: t.Optional[str]) -> tuple[list[dict], t.Optional[str]]: ...
    async def get_event(self, event_id: str) -> t.Optional[dict]: ...
    async def batch_get_events(self, ids: list[str]) -> list[t.Optional[dict]]: ...
    async def current_risk_by_session(self, session_id: str) -> dict: ...
    async def list_providers(self) -> dict: ...

@dataclasses.dataclass
class Services:
    risk: RiskService

@dataclasses.dataclass
class Loaders:
    risk_event: DataLoader[str, t.Optional[dict]]

@dataclasses.dataclass
class GraphQLContext:
    user: UserCtx
    services: Services
    request_id: str
    loaders: Loaders
    now: dt.datetime = dataclasses.field(default_factory=lambda: dt.datetime.now(dt.timezone.utc))

# =========================
# Утилиты: ID/курсор/время
# =========================

def b64e(raw: str) -> str:
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")

def b64d(enc: str) -> str:
    pad = "=" * (-len(enc) % 4)
    return base64.urlsafe_b64decode(enc + pad).decode("utf-8")

def to_global_id(typename: str, id_: str) -> strawberry.ID:
    return strawberry.ID(b64e(f"{typename}:{id_}"))

def from_global_id(gid: strawberry.ID) -> tuple[str, str]:
    raw = b64d(str(gid))
    typename, id_ = raw.split(":", 1)
    return typename, id_

def to_iso_z(dtobj: dt.datetime) -> str:
    if dtobj.tzinfo is None:
        dtobj = dtobj.replace(tzinfo=dt.timezone.utc)
    return dtobj.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# =========================
# Права доступа (скоупы)
# =========================

class RequireScope(BasePermission):
    required_scope: str = ""

    message = "Insufficient scope"

    def has_permission(self, source: t.Any, info: Info, **kwargs) -> bool:  # type: ignore[override]
        user: UserCtx = info.context.user
        return self.required_scope in user.scopes

class ScopeRiskRead(RequireScope):
    required_scope = "ztc.risk.read"

class ScopeRiskWrite(RequireScope):
    required_scope = "ztc.risk.write"

class ScopeRiskEvaluate(RequireScope):
    required_scope = "ztc.risk.evaluate"

# =========================
# Графовые типы/enum'ы
# =========================

@strawberry.enum
class Platform:
    WINDOWS = "WINDOWS"
    MACOS = "MACOS"
    LINUX = "LINUX"
    IOS = "IOS"
    ANDROID = "ANDROID"
    OTHER = "OTHER"

@strawberry.enum
class TriState:
    YES = "YES"
    NO = "NO"
    UNKNOWN = "UNKNOWN"

@strawberry.enum
class RiskLevel:
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"

@strawberry.enum
class RiskAction:
    ALLOW = "allow"
    STEP_UP = "step_up"
    DENY = "deny"
    QUARANTINE = "quarantine"

@strawberry.type
class Error:
    code: str
    message: str

# Входные модели
@strawberry.input
class RiskSignalIn:
    name: str
    value: float
    weight: float = 0.2
    reason: t.Optional[str] = None

@strawberry.input
class NetworkContextIn:
    ip: t.Optional[str] = None
    asn: t.Optional[int] = None
    geo_country: t.Optional[str] = None  # ISO-3166-1 alpha-2
    vpn_or_tor: t.Optional[bool] = None

@strawberry.input
class DevicePostureIn:
    platform: t.Optional[Platform] = None
    os_version: t.Optional[str] = None
    disk_encryption: t.Optional[TriState] = None
    screen_lock: t.Optional[TriState] = None
    firewall: t.Optional[TriState] = None
    av_realtime: t.Optional[TriState] = None
    mdm_enrolled: t.Optional[TriState] = None
    labels: t.Optional[t.Dict[str, str]] = None

@strawberry.input
class RiskEvaluateInput:
    tenant_id: t.Optional[str] = None
    session_id: t.Optional[str] = None
    user_id: t.Optional[str] = None
    device_id: t.Optional[str] = None
    network: t.Optional[NetworkContextIn] = None
    posture: t.Optional[DevicePostureIn] = None
    signals: t.List[RiskSignalIn] = strawberry.field(default_factory=list)
    thresholds: t.Optional[t.Dict[strawberry.enum_value(str), float]] = None  # keys: medium/high/critical

@strawberry.input
class RiskEventIn:
    event_id: t.Optional[str] = None
    occurred_at_ms: t.Optional[int] = None
    tenant_id: t.Optional[str] = None
    user_id: t.Optional[str] = None
    device_id: t.Optional[str] = None
    session_id: t.Optional[str] = None
    network: t.Optional[NetworkContextIn] = None
    posture: t.Optional[DevicePostureIn] = None
    signals: t.List[RiskSignalIn] = strawberry.field(default_factory=list)
    note: t.Optional[str] = None
    producer: t.Optional[str] = None

# Выходные модели
@strawberry.type
class RiskDecision:
    score: float
    level: RiskLevel
    action: RiskAction
    reasons: t.List[str]

@strawberry.type
class EvaluateRiskPayload:
    request_id: str
    evaluated_at: str
    subject: t.Optional[str]
    decision: RiskDecision

@strawberry.interface
class Node:
    id: strawberry.ID

@strawberry.type
class RiskEvent(Node):
    occurred_at: str
    tenant_id: t.Optional[str]
    user_id: t.Optional[str]
    device_id: t.Optional[str]
    session_id: t.Optional[str]
    network: t.Optional[str]  # JSON string for compactness
    posture: t.Optional[str]  # JSON string for compactness
    score: float
    level: RiskLevel
    reasons: t.List[str]
    note: t.Optional[str]
    producer: t.Optional[str]

    @staticmethod
    def from_dict(d: dict) -> "RiskEvent":
        rid = d.get("id") or d.get("event_id")  # domain → GQL
        network = d.get("network")
        posture = d.get("posture")
        return RiskEvent(
            id=to_global_id("RiskEvent", str(rid)),
            occurred_at=d.get("occurred_at") or d.get("occurred_at_iso") or d.get("occurred_at_str"),
            tenant_id=d.get("tenant_id"),
            user_id=d.get("user_id"),
            device_id=d.get("device_id"),
            session_id=d.get("session_id"),
            network=json.dumps(network) if network is not None else None,
            posture=json.dumps(posture) if posture is not None else None,
            score=float(d.get("score")),
            level=RiskLevel(d.get("level", "UNKNOWN")),
            reasons=list(d.get("reasons") or []),
            note=d.get("note"),
            producer=d.get("producer"),
        )

@strawberry.type
class PageInfo:
    has_next_page: bool
    end_cursor: t.Optional[str] = None

@strawberry.type
class RiskEventEdge:
    cursor: str
    node: RiskEvent

@strawberry.type
class RiskEventConnection:
    edges: t.List[RiskEventEdge]
    page_info: PageInfo

@strawberry.type
class RiskProvider:
    name: str
    version: str
    weights_default: t.Optional[t.Dict[str, float]] = None

# =========================
# DataLoader
# =========================

async def _batch_load_events(ids: list[str], info: Info) -> list[t.Optional[dict]]:
    svc: RiskService = info.context.services.risk
    # Если у сервиса нет батча — деградация до параллельных одиночных запросов.
    if hasattr(svc, "batch_get_events"):
        return await svc.batch_get_events(ids)
    res: list[t.Optional[dict]] = []
    for eid in ids:
        res.append(await svc.get_event(eid))
    return res

def make_loaders(services: Services) -> Loaders:
    # Оборачиваем load_fn лямбдой, чтобы получить Info из контекста (стандартный приём Strawberry не передаёт Info в load_fn).
    # Используем curry через замыкание.
    async def load_fn(keys: list[str]) -> list[t.Optional[dict]]:
        raise RuntimeError("Use _batch_load_events via field resolver with Info")
    # В резолвере мы вручную вызовем _batch_load_events.
    # Для совместимости с API DataLoader создаём заглушку; фактическая партия выполняется из резолвера.
    return Loaders(risk_event=DataLoader(load_fn=load_fn))  # type: ignore[arg-type]

# =========================
# Query
# =========================

@strawberry.type
class Query:

    @strawberry.field(permission_classes=[ScopeRiskRead])
    async def risk_providers(self, info: Info) -> list[RiskProvider]:
        svc: RiskService = info.context.services.risk
        data = await svc.list_providers()
        providers = []
        for p in data.get("providers", []):
            providers.append(RiskProvider(
                name=p.get("name"),
                version=p.get("version"),
                weights_default=p.get("weights_default")))
        return providers

    @strawberry.field(permission_classes=[ScopeRiskRead])
    async def risk_event(self, info: Info, id: strawberry.ID) -> t.Optional[RiskEvent]:
        typename, eid = from_global_id(id)
        if typename != "RiskEvent":
            return None
        svc: RiskService = info.context.services.risk
        data = await svc.get_event(eid)
        return RiskEvent.from_dict(data) if data else None

    @strawberry.field(permission_classes=[ScopeRiskRead])
    async def risk_events(
        self,
        info: Info,
        first: int = 100,
        after: t.Optional[str] = None
    ) -> RiskEventConnection:
        first = max(1, min(first, 500))
        svc: RiskService = info.context.services.risk
        items, next_cur = await svc.list_events(first=first, after=after)
        edges = [RiskEventEdge(cursor=b64e(f"{it.get('occurred_at')}:{it.get('id')}"), node=RiskEvent.from_dict(it)) for it in items]
        page_info = PageInfo(has_next_page=bool(next_cur), end_cursor=next_cur)
        return RiskEventConnection(edges=edges, page_info=page_info)

    @strawberry.field(permission_classes=[ScopeRiskRead])
    async def current_risk_by_session(self, info: Info, session_id: str) -> RiskDecision:
        svc: RiskService = info.context.services.risk
        data = await svc.current_risk_by_session(session_id)
        return RiskDecision(
            score=float(data["score"]),
            level=RiskLevel(data.get("level", "UNKNOWN")),
            action=RiskAction(data.get("action", "allow")),
            reasons=list(data.get("reasons") or []),
        )

# =========================
# Mutation
# =========================

@strawberry.type
class Mutation:

    @strawberry.mutation(permission_classes=[ScopeRiskEvaluate])
    async def evaluate_risk(self, info: Info, input: RiskEvaluateInput) -> EvaluateRiskPayload:
        svc: RiskService = info.context.services.risk
        payload = json.loads(json.dumps(dataclasses.asdict(input), default=str)) if dataclasses.is_dataclass(input) else input.__dict__  # type: ignore
        data = await svc.evaluate_risk(payload)
        decision = data.get("decision") or {}
        return EvaluateRiskPayload(
            request_id=str(data.get("request_id") or info.context.request_id),
            evaluated_at=str(data.get("evaluated_at") or to_iso_z(info.context.now)),
            subject=data.get("subject"),
            decision=RiskDecision(
                score=float(decision.get("score", 0.0)),
                level=RiskLevel(decision.get("level", "UNKNOWN")),
                action=RiskAction(decision.get("action", "allow")),
                reasons=list(decision.get("reasons") or []),
            )
        )

    @strawberry.mutation(permission_classes=[ScopeRiskWrite])
    async def ingest_risk_event(
        self,
        info: Info,
        input: RiskEventIn,
        idempotency_key: t.Optional[str] = None
    ) -> RiskEvent:
        svc: RiskService = info.context.services.risk
        # Преобразуем в плоский dict для сервиса
        def to_plain(obj: t.Any) -> t.Any:
            if obj is None:
                return None
            if isinstance(obj, (str, int, float, bool)):
                return obj
            if isinstance(obj, dt.datetime):
                return int(obj.timestamp() * 1000)
            if isinstance(obj, list):
                return [to_plain(x) for x in obj]
            if isinstance(obj, dict):
                return {k: to_plain(v) for k, v in obj.items()}
            # strawberry input → dict
            if hasattr(obj, "__dict__"):
                return {k: to_plain(v) for k, v in obj.__dict__.items()}
            return obj

        payload = to_plain(input)
        data = await svc.ingest_event(payload, idempotency_key=idempotency_key)
        return RiskEvent.from_dict(data)

# =========================
# Subscription (опционально)
# =========================

@strawberry.type
class Subscription:

    @strawberry.subscription(permission_classes=[ScopeRiskRead])
    async def risk_event_stream(self, info: Info, tenant_id: t.Optional[str] = None) -> t.AsyncGenerator[RiskEvent, None]:
        """
        Ожидается, что в контексте есть pubsub/очередь; здесь пример с асинхронной очередью в ctx.
        Реализуйте прокладку к вашей шине событий (Kafka/NATS/WebSocket bridge).
        """
        queue = getattr(info.context, "risk_events_queue", None)
        if queue is None:
            # Пустой генератор (нет источника)
            if False:
                yield  # type: ignore  # pragma: no cover
            return
        while True:
            evt = await queue.get()
            if tenant_id and evt.get("tenant_id") != tenant_id:
                continue
            yield RiskEvent.from_dict(evt)

# =========================
# Схема
# =========================

schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    subscription=Subscription,
    config=StrawberryConfig(auto_camel_case=True),
)
