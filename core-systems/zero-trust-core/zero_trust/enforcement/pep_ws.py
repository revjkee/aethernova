# zero-trust-core/zero_trust/enforcement/pep_ws.py
# -*- coding: utf-8 -*-
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass, asdict
from enum import Enum
from http import HTTPStatus
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional, Tuple

# ---------- Optional imports and safe fallbacks ----------
try:
    from zero_trust_core.api.http.errors import AppError, ErrorCode, redact
except Exception:  # pragma: no cover
    class ErrorCode(str, Enum):
        UNAUTHENTICATED = "UNAUTHENTICATED"
        FORBIDDEN = "FORBIDDEN"
        INVALID_INPUT = "INVALID_INPUT"
        POLICY_VIOLATION = "POLICY_VIOLATION"
        STEP_UP_REQUIRED = "STEP_UP_REQUIRED"
        MFA_ENROLL_REQUIRED = "MFA_ENROLL_REQUIRED"
        INTERNAL = "INTERNAL"

    class AppError(Exception):
        def __init__(self, code: ErrorCode, detail: str = "", http_status: int = 500, **kw: Any) -> None:
            self.code = code
            self.detail = detail
            self.http_status = http_status
            self.title = code.value
            super().__init__(f"{code}: {detail}")

    def redact(obj: Any, sensitive_keys=("authorization", "cookie", "token", "password")) -> Any:
        return obj

try:
    # Типы из WS-сервера (для привязки authorizer/policy_evaluator)
    from zero_trust_core.api.ws.server import ZeroTrustWsServer, WsMsgType  # type: ignore
    # Контекст идентичности из ws.server
    from zero_trust_core.api.ws.server import IdentityContext  # type: ignore
except Exception:  # pragma: no cover
    ZeroTrustWsServer = Any  # type: ignore
    class WsMsgType(str, Enum):  # minimal
        SUBSCRIBE = "subscribe"
        UNSUBSCRIBE = "unsubscribe"
        EVAL_AUTHORIZE = "evalAuthorize"
        LOG_AUDIT = "logAudit"
        RECORD_RISK = "recordRisk"
    @dataclass
    class IdentityContext:  # type: ignore
        tenant_id: str
        subject_id: str
        session_id: Optional[str]
        roles: list
        trust: int
        risk: str
        attributes: Dict[str, Any]

# ---------- Logger ----------
logger = logging.getLogger("zero_trust.enforcement.pep_ws")


# ---------- Local types ----------
class DecisionEffect(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    CHALLENGE = "CHALLENGE"


@dataclass
class Obligation:
    requireFactorAnyOf: Optional[list] = None
    sessionMaxTTL: Optional[int] = None  # seconds
    watermark: Optional[bool] = None
    redactFields: Optional[list] = None
    logJustification: Optional[bool] = None


@dataclass
class PolicyDecision:
    effect: DecisionEffect
    reason: Optional[str] = None
    obligations: Optional[list] = None  # list[Obligation] as dicts
    policy: Optional[str] = None
    rule: Optional[str] = None


# PDP сигнатура: (ident: IdentityContext, resource_urn: str, action: str, ctx: dict) -> PolicyDecision
PdpCallable = Callable[[IdentityContext, str, str, Dict[str, Any]], Awaitable[PolicyDecision]]

# Поставщик постуры: (ident) -> dict { "compliance": "COMPLIANT"/"NON_COMPLIANT"/"UNKNOWN", "score": int, ... }
PostureProvider = Callable[[IdentityContext], Awaitable[Dict[str, Any]]]


# ---------- Вспомогательные ----------
def _h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")


def _now() -> float:
    return time.time()


# ---------- LRU TTL cache ----------
class LruTtlCache:
    def __init__(self, maxsize: int = 10000, ttl_sec: int = 60) -> None:
        self.maxsize = maxsize
        self.ttl = ttl_sec
        self._d: OrderedDict[str, Tuple[float, Any]] = OrderedDict()
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            ent = self._d.get(key)
            if not ent:
                return None
            ts, val = ent
            if _now() - ts > self.ttl:
                self._d.pop(key, None)
                return None
            self._d.move_to_end(key, last=True)
            return val

    async def set(self, key: str, value: Any) -> None:
        async with self._lock:
            self._d[key] = (_now(), value)
            self._d.move_to_end(key, last=True)
            while len(self._d) > self.maxsize:
                self._d.popitem(last=False)


# ---------- WsPEP ----------
class WsPEP:
    """
    Policy Enforcement Point for WebSocket operations.
    Включает:
      - пороги trust/risk и обязательность COMPLIANT постуры
      - привязку к арендатору (URN-шаблоны)
      - кэш PDP решений
      - CHALLENGE/step-up по обязательствам
      - подписку на risk-сигналы для динамического отзыва.
    """

    def __init__(
        self,
        *,
        trust_min: int = 60,
        risk_deny_levels: Tuple[str, ...] = ("CRITICAL",),
        require_compliant_posture: bool = True,
        deny_on_unknown_posture: bool = False,
        mfa_min_level: int = 1,
        pdp: Optional[PdpCallable] = None,
        posture_provider: Optional[PostureProvider] = None,
        cache_maxsize: int = 20000,
        cache_ttl_sec: int = 60,
    ) -> None:
        self.trust_min = int(trust_min)
        self.risk_deny_levels = set(level.upper() for level in risk_deny_levels)
        self.require_compliant_posture = bool(require_compliant_posture)
        self.deny_on_unknown_posture = bool(deny_on_unknown_posture)
        self.mfa_min_level = int(mfa_min_level)
        self._pdp = pdp
        self._posture_provider = posture_provider
        self._cache = LruTtlCache(maxsize=cache_maxsize, ttl_sec=cache_ttl_sec)
        # актуальные запреты: session_id -> reason
        self._revoked_sessions: Dict[str, str] = {}
        # последние уровни риска: subject_id -> level
        self._subject_risk: Dict[str, str] = {}

    # ---- Public API to bind WS server ----
    def wire_ws_server(self, server: ZeroTrustWsServer) -> None:
        """
        Подставляет authorizer/policy_evaluator в ZeroTrustWsServer.
        """
        server.authorizer = self._authorizer  # type: ignore
        server.policy_evaluator = self._policy_evaluator  # type: ignore

    async def attach_pubsub(self, pubsub: Any) -> None:
        """
        Подписывается на каналы 'risk' и 'session:revoke' PubSub (совместим с api.ws.server.InMemory/Redis PubSub).
        """
        async def _on_risk(_ch: str, msg: Dict[str, Any]) -> None:
            sid = str(msg.get("subjectId") or "")
            level = str(msg.get("severity") or "").upper() or "UNKNOWN"
            if sid:
                self._subject_risk[sid] = level

        async def _on_revoke(_ch: str, msg: Dict[str, Any]) -> None:
            sess = str(msg.get("sessionId") or "")
            reason = str(msg.get("reason") or "revoked")
            if sess:
                self._revoked_sessions[sess] = reason

        await pubsub.subscribe("risk", _on_risk)
        await pubsub.subscribe("session:revoke", _on_revoke)

    # ---- Authorizer hook for subscribe/unsubscribe, etc. ----
    async def _authorizer(self, ident: IdentityContext, action: str, resource: str) -> None:
        """
        Бросает AppError при запрете или необходимости step-up.
        """
        await self._pre_checks(ident)

        # Ресурс может быть именем канала (ws.server передает channel)
        # Нормализуем в URN
        urn = self._as_resource_urn(ident.tenant_id, resource)
        decision = await self._authorize_cached(ident, urn, action, ctx={})
        if decision.effect == DecisionEffect.ALLOW:
            return
        if decision.effect == DecisionEffect.CHALLENGE:
            self._raise_step_up(decision)
        # DENY
        raise AppError(ErrorCode.FORBIDDEN, detail=decision.reason or "Denied", http_status=HTTPStatus.FORBIDDEN)

    # ---- PDP wrapper for evalAuthorize message ----
    async def _policy_evaluator(self, ident: IdentityContext, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Возвращает структуру решения для ws.server.evaluateAuthorize.
        """
        await self._pre_checks(ident)
        resource = str(payload.get("resourceUrn") or payload.get("resource") or "")
        action = str(payload.get("action") or "READ")
        ctx = dict(payload.get("context") or {})
        urn = resource if resource.startswith("urn:") else self._as_resource_urn(ident.tenant_id, resource)
        decision = await self._authorize_cached(ident, urn, action, ctx=ctx)
        return {
            "effect": decision.effect.value,
            "reason": decision.reason,
            "obligations": decision.obligations or [],
            "policy": decision.policy,
            "rule": decision.rule,
        }

    # ---- Core enforcement path ----
    async def _pre_checks(self, ident: IdentityContext) -> None:
        # Отзыв сессии
        if ident.session_id and ident.session_id in self._revoked_sessions:
            reason = self._revoked_sessions.get(ident.session_id, "revoked")
            raise AppError(ErrorCode.FORBIDDEN, detail=f"Session revoked: {reason}", http_status=HTTPStatus.FORBIDDEN)

        # Риск
        risk = (ident.risk or "UNKNOWN").upper()
        dyn_risk = self._subject_risk.get(ident.subject_id, risk)
        if dyn_risk in self.risk_deny_levels:
            raise AppError(ErrorCode.FORBIDDEN, detail=f"Risk level {dyn_risk} not allowed", http_status=HTTPStatus.FORBIDDEN)

        # Trust
        if int(ident.trust or 0) < self.trust_min:
            raise AppError(ErrorCode.STEP_UP_REQUIRED, detail=f"Trust {ident.trust} below required {self.trust_min}",
                           http_status=HTTPStatus.UNAUTHORIZED)

        # Постура
        if self._posture_provider:
            try:
                p = await self._posture_provider(ident)
                comp = str(p.get("compliance") or "UNKNOWN").upper()
                if comp == "NON_COMPLIANT" and self.require_compliant_posture:
                    raise AppError(ErrorCode.POLICY_VIOLATION, detail="Device posture non-compliant", http_status=HTTPStatus.FORBIDDEN)
                if comp == "UNKNOWN" and self.deny_on_unknown_posture:
                    raise AppError(ErrorCode.POLICY_VIOLATION, detail="Device posture unknown", http_status=HTTPStatus.FORBIDDEN)
            except AppError:
                raise
            except Exception as e:
                # Безопасно: при сбое провайдера — запрет по политике
                raise AppError(ErrorCode.POLICY_VIOLATION, detail="Posture provider failure", http_status=HTTPStatus.FORBIDDEN) from e

    async def _authorize_cached(self, ident: IdentityContext, urn: str, action: str, *, ctx: Dict[str, Any]) -> PolicyDecision:
        key = self._cache_key(ident, urn, action, ctx)
        cached = await self._cache.get(key)
        if cached:
            return cached
        decision = await self._authorize(ident, urn, action, ctx=ctx)
        await self._cache.set(key, decision)
        return decision

    async def _authorize(self, ident: IdentityContext, urn: str, action: str, *, ctx: Dict[str, Any]) -> PolicyDecision:
        # Соблюдаем многоарендность: URN обязан начинаться с tenant-префикса
        tenant_prefix = f"urn:tenant:{ident.tenant_id}:"
        if not urn.startswith(tenant_prefix):
            return PolicyDecision(effect=DecisionEffect.DENY, reason="TENANT_SCOPE_MISMATCH")

        # Внешний PDP
        if self._pdp:
            try:
                dec = await self._pdp(ident, urn, action, ctx)
            except Exception as e:
                logger.exception("pdp_failure urn=%s action=%s err=%s", urn, action, str(e))
                return PolicyDecision(effect=DecisionEffect.DENY, reason="PDP_FAILURE")
            # Доп. защита: Step-up если требуется фактор, а уровень MFA низкий
            if dec.effect == DecisionEffect.ALLOW and dec.obligations:
                req_level = self._required_mfa_level(dec.obligations)
                if req_level is not None and self._current_mfa_level(ident) < req_level:
                    return PolicyDecision(effect=DecisionEffect.CHALLENGE, reason="STEP_UP_REQUIRED", obligations=dec.obligations)
            return dec

        # Без PDP — безопасный дефолт (минимальный доступ)
        # 1) Разрешаем SUBSCRIBE/UNSUBSCRIBE только на каналы своего арендатора:
        #    urn:tenant:{tid}:topic:{name}
        # 2) Остальное — DENY.
        allow = urn.startswith(tenant_prefix + "topic:")
        if allow:
            # Возможность потребовать step-up для привилегированных каналов
            if urn.startswith(tenant_prefix + "topic:admin"):
                if self._current_mfa_level(ident) < self.mfa_min_level:
                    return PolicyDecision(
                        effect=DecisionEffect.CHALLENGE,
                        reason="ADMIN_CHANNEL_STEP_UP",
                        obligations=[asdict(Obligation(requireFactorAnyOf=["WEBAUTHN", "TOTP"]))],
                        policy="default",
                        rule="admin_channel_requires_step_up",
                    )
            return PolicyDecision(effect=DecisionEffect.ALLOW, reason="DEFAULT_ALLOW_TOPIC", policy="default", rule="tenant_topic_allow")
        return PolicyDecision(effect=DecisionEffect.DENY, reason="DEFAULT_DENY")

    # ---- Helpers ----
    def _as_resource_urn(self, tenant_id: str, resource: str) -> str:
        # Если уже URN — возвращаем как есть
        if resource.startswith("urn:"):
            return resource
        # Если это имя канала — нормализуем в topic
        # Пример: "risk" -> urn:tenant:{tid}:topic:risk
        return f"urn:tenant:{tenant_id}:topic:{resource}"

    def _cache_key(self, ident: IdentityContext, urn: str, action: str, ctx: Dict[str, Any]) -> str:
        base = {
            "t": ident.tenant_id,
            "s": ident.subject_id,
            "u": urn,
            "a": action,
            "mfa": self._current_mfa_level(ident),
            "ctx": ctx,
        }
        return _h(_canonical_json(base))

    def _current_mfa_level(self, ident: IdentityContext) -> int:
        # Ожидаем mfaLevel в claims/attributes или 0 по умолчанию
        try:
            return int(ident.attributes.get("mfaLevel", 0))
        except Exception:
            return 0

    def _required_mfa_level(self, obligations: Optional[list]) -> Optional[int]:
        if not obligations:
            return None
        # Простая эвристика: если требуется WEBAUTHN/U2F/BIOMETRIC — уровень 2, если TOTP/SMS/EMAIL — уровень 1
        factors = []
        for ob in obligations:
            if not isinstance(ob, Mapping):
                continue
            f = ob.get("requireFactorAnyOf")
            if isinstance(f, (list, tuple)):
                factors.extend([str(x).upper() for x in f])
        if not factors:
            return None
        strong = {"WEBAUTHN", "U2F", "BIOMETRIC", "PASSKEY"}
        if any(f in strong for f in factors):
            return 2
        return 1

    def _raise_step_up(self, decision: PolicyDecision) -> None:
        # Если политика явно просит фактор — вернем STEP_UP/MFA_ENROLL с деталями
        obligations = decision.obligations or []
        if obligations:
            # Если у пользователя нет факторов — потребуем enroll
            raise AppError(ErrorCode.STEP_UP_REQUIRED,
                           detail=decision.reason or "Step-up required",
                           http_status=HTTPStatus.UNAUTHORIZED,
                           )
        raise AppError(ErrorCode.STEP_UP_REQUIRED, detail=decision.reason or "Step-up required", http_status=HTTPStatus.UNAUTHORIZED)


# ---------- Фабрики и интеграция ----------
async def default_posture_provider(ident: IdentityContext) -> Dict[str, Any]:
    """
    Заглушка: если нет провайдера постуры — считаем UNKNOWN.
    В проде замените на вызов PostureEngine.evaluate_batch с кэшем.
    """
    return {"compliance": "UNKNOWN", "score": 0}


async def default_pdp(ident: IdentityContext, urn: str, action: str, ctx: Dict[str, Any]) -> PolicyDecision:
    """
    Безопасный дефолт PDP (тенант-scope и admin-каналы только со step-up).
    """
    pep = WsPEP()  # локально используем логику нормализации и step-up эвристику
    mfa_level = pep._current_mfa_level(ident)
    tenant_prefix = f"urn:tenant:{ident.tenant_id}:"
    if not urn.startswith(tenant_prefix):
        return PolicyDecision(effect=DecisionEffect.DENY, reason="TENANT_SCOPE_MISMATCH")
    if urn.startswith(tenant_prefix + "topic:admin"):
        if mfa_level < 1:
            return PolicyDecision(effect=DecisionEffect.CHALLENGE,
                                  reason="ADMIN_CHANNEL_STEP_UP",
                                  obligations=[asdict(Obligation(requireFactorAnyOf=["WEBAUTHN", "TOTP"]))],
                                  policy="default", rule="admin_step_up")
    if urn.startswith(tenant_prefix + "topic:"):
        return PolicyDecision(effect=DecisionEffect.ALLOW, reason="DEFAULT_ALLOW_TOPIC", policy="default", rule="tenant_topic_allow")
    return PolicyDecision(effect=DecisionEffect.DENY, reason="DEFAULT_DENY")


def build_pep(
    *,
    trust_min: int = 60,
    risk_deny_levels: Tuple[str, ...] = ("CRITICAL",),
    require_compliant_posture: bool = True,
    deny_on_unknown_posture: bool = False,
    mfa_min_level: int = 1,
    pdp: Optional[PdpCallable] = None,
    posture_provider: Optional[PostureProvider] = None,
) -> WsPEP:
    return WsPEP(
        trust_min=trust_min,
        risk_deny_levels=risk_deny_levels,
        require_compliant_posture=require_compliant_posture,
        deny_on_unknown_posture=deny_on_unknown_posture,
        mfa_min_level=mfa_min_level,
        pdp=pdp or default_pdp,
        posture_provider=posture_provider or default_posture_provider,
    )


def wire_ws_server(server: ZeroTrustWsServer, pep: Optional[WsPEP] = None) -> WsPEP:
    """
    Простой хелпер: создает или подключает PEP к WS-серверу.
    """
    p = pep or build_pep()
    p.wire_ws_server(server)
    return p


# ---------- __all__ ----------
__all__ = [
    "WsPEP",
    "DecisionEffect",
    "PolicyDecision",
    "Obligation",
    "PdpCallable",
    "PostureProvider",
    "build_pep",
    "wire_ws_server",
]
