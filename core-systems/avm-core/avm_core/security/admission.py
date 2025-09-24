from __future__ import annotations

import fnmatch
import ipaddress
import json
import threading
import time
from dataclasses import dataclass, field
from enum import Enum, IntEnum, auto
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple


# =========
# Ошибки
# =========

class AdmissionError(Exception):
    """Базовая ошибка admission-контроллера."""


class PolicyLoadError(AdmissionError):
    """Ошибка загрузки/парсинга политики."""


class RateLimitError(AdmissionError):
    """Ошибка подсистемы лимитов."""


# =========================
# Вспомогательные структуры
# =========================

class DecisionEffect(Enum):
    ALLOW = "allow"
    DENY = "deny"


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    UNKNOWN = "unknown"


class LogLevel(IntEnum):
    DEBUG = 10
    INFO = 20
    WARN = 30
    ERROR = 40


@dataclass(frozen=True)
class DeviceAttestation:
    compliant: bool = False
    managed: bool = False
    secure_boot: bool = False


@dataclass(frozen=True)
class RiskSignal:
    score: int = 0  # 0..100
    level: RiskLevel = RiskLevel.UNKNOWN
    ts: float = field(default_factory=lambda: time.time())


@dataclass(frozen=True)
class AuthContext:
    subject: str
    roles: Tuple[str, ...] = field(default_factory=tuple)
    tenant_id: Optional[str] = None
    amr: Tuple[str, ...] = field(default_factory=tuple)  # методы аутентификации (mfa, hwk, pwd)
    acr: Optional[str] = None  # уровень гарантии
    scopes: Tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class MtlsContext:
    required: bool
    used: bool
    spiffe_id: Optional[str] = None


@dataclass(frozen=True)
class RequestContext:
    # Идентификация запроса
    method: str
    path: str
    client_ip: str
    headers: Mapping[str, str]
    # Контекст безопасности
    auth: Optional[AuthContext] = None
    device: Optional[DeviceAttestation] = None
    risk: Optional[RiskSignal] = None
    mtls: Optional[MtlsContext] = None
    # Среда выполнения
    namespace: Optional[str] = None
    geo_country: Optional[str] = None
    trace_id: Optional[str] = None
    received_at: float = field(default_factory=lambda: time.time())


@dataclass(frozen=True)
class Obligation:
    """Обязанности, которые должен выполнить вызывающий перед допуском."""
    id: str
    params: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Decision:
    effect: DecisionEffect
    reason: str
    policy_id: str
    obligations: Tuple[Obligation, ...] = field(default_factory=tuple)
    ttl_seconds: int = 5
    trace_id: Optional[str] = None

    @property
    def allowed(self) -> bool:
        return self.effect is DecisionEffect.ALLOW


# =====================
# Утилиты сопоставления
# =====================

def _match_path(patterns: Sequence[str], path: str) -> bool:
    """Глоб‑совпадение с поддержкой '**'."""
    for p in patterns:
        # Нормализуем: '/v1/keys/**' сопоставляется с началом пути
        if "**" in p or "*" in p:
            if fnmatch.fnmatch(path, p):
                return True
        else:
            if path == p or path.startswith(p.rstrip("/") + "/"):
                return True
    return False


def _in_cidrs(ip: str, cidrs: Sequence[str]) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs:
        try:
            if ip_obj in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def _now() -> float:
    return time.time()


# ===========================
# Интерфейсы (Порты/Адаптеры)
# ===========================

class PolicyAdapter:
    """Интерфейс адаптера политики. Возвращает решение по контексту."""

    def evaluate(self, ctx: RequestContext) -> Decision:
        raise NotImplementedError


class RateLimiter:
    """Интерфейс ограничителя скорости."""

    def allow(self, key: str, cost: int = 1) -> bool:
        raise NotImplementedError


class QuotaManager:
    """Интерфейс квотирования (например, суточные лимиты)."""

    def consume(self, key: str, amount: int = 1) -> bool:
        raise NotImplementedError


class AuditSink:
    """Интерфейс аудита решений admission."""

    def log_decision(self, ctx: RequestContext, decision: Decision, level: LogLevel = LogLevel.INFO) -> None:
        raise NotImplementedError


# =========================
# Реализации по умолчанию
# =========================

class JsonAuditSink(AuditSink):
    """Структурированный JSON‑аудит. Потокобезопасен, не выкидывает исключения наружу."""

    def __init__(self, stream: Any = None, min_level: LogLevel = LogLevel.INFO) -> None:
        self._stream = stream or _StdStream()
        self._min_level = min_level
        self._lock = threading.Lock()

    def log_decision(self, ctx: RequestContext, decision: Decision, level: LogLevel = LogLevel.INFO) -> None:
        if level < self._min_level:
            return
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            "level": int(level),
            "component": "admission",
            "effect": decision.effect.value,
            "reason": decision.reason,
            "policy_id": decision.policy_id,
            "trace_id": decision.trace_id or ctx.trace_id,
            "method": ctx.method,
            "path": ctx.path,
            "client_ip": ctx.client_ip,
            "tenant": (ctx.auth.tenant_id if ctx.auth else None),
            "roles": (list(ctx.auth.roles) if ctx.auth else None),
            "mtls_used": (ctx.mtls.used if ctx.mtls else None),
            "spiffe_id": (ctx.mtls.spiffe_id if ctx.mtls else None),
            "obligations": [o.id for o in decision.obligations],
        }
        with self._lock:
            try:
                self._stream.write(json.dumps(payload, ensure_ascii=False) + "\n")
            except Exception:
                # Никогда не падаем в бою из-за аудита.
                pass


class _StdStream:
    """Обёртка stdout/stderr для тестируемости."""
    def write(self, s: str) -> None:  # pragma: no cover - простая обёртка
        print(s, end="")


class MemoryTokenBucket(RateLimiter):
    """In‑memory токен‑бакет: простой безопасный fallback, потокобезопасный."""

    def __init__(self, capacity: int, refill_per_sec: float) -> None:
        if capacity <= 0 or refill_per_sec <= 0:
            raise RateLimitError("capacity and refill_per_sec must be > 0")
        self._capacity = capacity
        self._tokens = float(capacity)
        self._refill = float(refill_per_sec)
        self._updated = _now()
        self._lock = threading.Lock()

    def allow(self, key: str, cost: int = 1) -> bool:  # key для совместимости, в памяти один бакет
        with self._lock:
            now = _now()
            elapsed = now - self._updated
            self._updated = now
            self._tokens = min(self._capacity, self._tokens + elapsed * self._refill)
            if self._tokens >= cost:
                self._tokens -= cost
                return True
            return False


class MemoryQuota(QuotaManager):
    """Простая суточная квота в памяти."""

    def __init__(self, daily_limit: int) -> None:
        if daily_limit < 0:
            raise AdmissionError("daily_limit must be >= 0")
        self._limit = daily_limit
        self._counts: MutableMapping[Tuple[str, str], int] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _day_key() -> str:
        return time.strftime("%Y-%m-%d", time.gmtime())

    def consume(self, key: str, amount: int = 1) -> bool:
        if amount <= 0:
            return True
        with self._lock:
            k = (self._day_key(), key)
            cur = self._counts.get(k, 0)
            if cur + amount > self._limit:
                return False
            self._counts[k] = cur + amount
            return True


class TTLCache:
    """Минимальный TTL‑кэш решений (потокобезопасный)."""

    def __init__(self, maxsize: int = 2048) -> None:
        self._maxsize = maxsize
        self._data: Dict[str, Tuple[float, Decision]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Decision]:
        with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            exp, val = item
            if exp < _now():
                del self._data[key]
                return None
            return val

    def put(self, key: str, decision: Decision, ttl_seconds: int) -> None:
        with self._lock:
            if len(self._data) >= self._maxsize:
                # Простейшая эвикция: удалить произвольный первый ключ.
                self._data.pop(next(iter(self._data)))
            self._data[key] = (_now() + max(ttl_seconds, 1), decision)


# ========================================
# Примитивный YAML‑адаптер политики (RBAC)
# ========================================

try:
    import yaml  # type: ignore
except Exception as exc:  # pragma: no cover - импорт оценивается во время рантайма
    yaml = None  # noqa: N816


class YamlPolicyAdapter(PolicyAdapter):
    """
    Минимальный адаптер политики из YAML‑файла.
    Поддерживает ключи:
      policy.default_decision: "deny"|"allow"
      public_endpoints: [{ path }]
      internal_mtls_paths: [pattern]
      tenant_isolation: { enforce: bool, header: "X-Tenant-Id", cidr_allow: [cidr...] }
      rbac: [ { paths, methods, roles_any_of, step_up_required?, max_risk_score?, geo_allow? } ]
      rate_limits: { ip/user/service: { window_seconds, burst, sustained_per_minute } }  # информация для внешних систем
      risk: { disallow_levels: ["high"], max_score: 100 }
    """

    def __init__(self, policy_id: str, yaml_text: str) -> None:
        if yaml is None:
            raise PolicyLoadError("PyYAML is not available")
        try:
            raw = yaml.safe_load(yaml_text) or {}
        except Exception as exc:  # pragma: no cover
            raise PolicyLoadError(f"Failed to parse YAML: {exc}") from exc
        self._pid = policy_id
        self._cfg = self._normalize(raw)

    @staticmethod
    def _normalize(raw: Mapping[str, Any]) -> Mapping[str, Any]:
        def _seq(v: Any) -> List[Any]:
            if v is None:
                return []
            if isinstance(v, (list, tuple)):
                return list(v)
            return [v]

        policy = dict(raw or {})
        # defaults
        policy.setdefault("policy", {}).setdefault("default_decision", "deny")
        policy.setdefault("public_endpoints", [])
        policy.setdefault("internal_mtls_paths", [])
        policy.setdefault("tenant_isolation", {"enforce": True, "header": "X-Tenant-Id"})
        policy.setdefault("rbac", [])
        policy.setdefault("risk", {"disallow_levels": ["high"], "max_score": 100})
        # normalize lists
        for it in policy.get("public_endpoints", []):
            it["path"] = it.get("path", "/v1/healthz")
        policy["internal_mtls_paths"] = _seq(policy.get("internal_mtls_paths"))
        rbac_rules = []
        for r in policy.get("rbac", []):
            rbac_rules.append({
                "paths": _seq(r.get("paths", [])),
                "methods": [m.upper() for m in _seq(r.get("methods", []))],
                "roles_any_of": [str(x) for x in _seq(r.get("roles_any_of", []))],
                "step_up_required": bool(r.get("step_up_required", False)),
                "max_risk_score": int(r.get("max_risk_score", 100)),
                "geo_allow": [str(x) for x in _seq(r.get("geo_allow", []))],
            })
        policy["rbac"] = rbac_rules
        return policy

    # ---- Основная оценка ----
    def evaluate(self, ctx: RequestContext) -> Decision:
        pid = self._pid
        # 0) Контекст обязателен (Zero‑Trust)
        if ctx.auth is None:
            return Decision(
                effect=DecisionEffect.DENY,
                reason="missing-auth-context",
                policy_id=pid,
                obligations=(),
                ttl_seconds=3,
                trace_id=ctx.trace_id,
            )

        # 1) Публичные точки (healthz и т.п.)
        for ep in self._cfg.get("public_endpoints", []):
            if _match_path([ep.get("path", "")], ctx.path) and ctx.method.upper() == ep.get("method", "GET").upper():
                return Decision(
                    effect=DecisionEffect.ALLOW,
                    reason="public-endpoint",
                    policy_id=pid,
                    obligations=(),
                    ttl_seconds=5,
                    trace_id=ctx.trace_id,
                )

        # 2) Внутренние пути -> требуется mTLS
        mtls_paths: List[str] = list(self._cfg.get("internal_mtls_paths", []))
        if mtls_paths and _match_path(mtls_paths, ctx.path):
            if ctx.mtls is None or not ctx.mtls.used:
                return Decision(
                    effect=DecisionEffect.DENY,
                    reason="mtls-required",
                    policy_id=pid,
                    obligations=(),
                    ttl_seconds=5,
                    trace_id=ctx.trace_id,
                )
            # Доп. проверка SPIFFE‑префикса (если задано в заголовке)
            spiffe = (ctx.mtls.spiffe_id or "") if ctx.mtls else ""
            allowed_prefix = "spiffe://aethernova/internal/"
            if spiffe and not spiffe.startswith(allowed_prefix):
                return Decision(
                    effect=DecisionEffect.DENY,
                    reason="spiffe-prefix-mismatch",
                    policy_id=pid,
                    obligations=(),
                    ttl_seconds=10,
                    trace_id=ctx.trace_id,
                )

        # 3) Мультиарендность (tenant isolation)
        ti = self._cfg.get("tenant_isolation", {})
        if ti.get("enforce", True):
            tenant = ctx.auth.tenant_id or ""
            if not tenant:
                return Decision(
                    effect=DecisionEffect.DENY,
                    reason="tenant-missing",
                    policy_id=pid,
                    obligations=(),
                    ttl_seconds=5,
                    trace_id=ctx.trace_id,
                )
            cidr_allow = list(ti.get("cidr_allow", []))
            if cidr_allow and not _in_cidrs(ctx.client_ip, cidr_allow):
                return Decision(
                    effect=DecisionEffect.DENY,
                    reason="tenant-network-not-allowed",
                    policy_id=pid,
                    obligations=(),
                    ttl_seconds=10,
                    trace_id=ctx.trace_id,
                )

        # 4) Риск‑гейт
        risk_cfg = self._cfg.get("risk", {})
        rs = ctx.risk or RiskSignal(score=0, level=RiskLevel.UNKNOWN)
        disallow_levels = {RiskLevel(h) if isinstance(h, RiskLevel) else RiskLevel(h.lower()) for h in risk_cfg.get("disallow_levels", [])}
        if rs.level in disallow_levels or rs.score > int(risk_cfg.get("max_score", 100)):
            return Decision(
                effect=DecisionEffect.DENY,
                reason="risk-threshold-exceeded",
                policy_id=pid,
                obligations=(),
                ttl_seconds=10,
                trace_id=ctx.trace_id,
            )

        # 5) RBAC‑правила (deny‑overrides: первым делом ищем точное совпадение)
        method = ctx.method.upper()
        for rule in self._cfg.get("rbac", []):
            if rule["methods"] and method not in rule["methods"]:
                continue
            if not _match_path(rule["paths"], ctx.path):
                continue

            # Проверка ролей
            if rule["roles_any_of"]:
                principal_roles = set(r.lower() for r in ctx.auth.roles)
                allowed_roles = set(r.lower() for r in rule["roles_any_of"])
                if principal_roles.isdisjoint(allowed_roles):
                    return Decision(
                        effect=DecisionEffect.DENY,
                        reason="role-not-authorized",
                        policy_id=pid,
                        obligations=(),
                        ttl_seconds=10,
                        trace_id=ctx.trace_id,
                    )

            # Гео‑ограничение (если задано)
            geo_allow = rule.get("geo_allow") or []
            if geo_allow and ctx.geo_country and ctx.geo_country.upper() not in {g.upper() for g in geo_allow}:
                return Decision(
                    effect=DecisionEffect.DENY,
                    reason="geo-not-allowed",
                    policy_id=pid,
                    obligations=(),
                    ttl_seconds=10,
                    trace_id=ctx.trace_id,
                )

            # Step‑up MFA (если требуется для правила)
            obligations: List[Obligation] = []
            if bool(rule.get("step_up_required", False)):
                amr = {a.lower() for a in (ctx.auth.amr or ())}
                acr = (ctx.auth.acr or "").lower()
                phishing_resistant = "phishing-resistant" in acr or "fido" in amr or "hwk" in amr or "mfa" in amr
                if not phishing_resistant:
                    obligations.append(Obligation(id="mfa_required", params={"reason": "step-up-required"}))

            # Доп. риск для правила
            max_risk_score = int(rule.get("max_risk_score", 100))
            if rs.score > max_risk_score:
                return Decision(
                    effect=DecisionEffect.DENY,
                    reason="rule-risk-threshold-exceeded",
                    policy_id=pid,
                    obligations=tuple(obligations),
                    ttl_seconds=10,
                    trace_id=ctx.trace_id,
                )

            # Успех по правилу (с учётом возможных обязанностей)
            return Decision(
                effect=DecisionEffect.ALLOW,
                reason="rbac-allow",
                policy_id=pid,
                obligations=tuple(obligations),
                ttl_seconds=5,
                trace_id=ctx.trace_id,
            )

        # 6) По умолчанию
        default_decision = str(self._cfg.get("policy", {}).get("default_decision", "deny")).lower()
        if default_decision == "allow":
            return Decision(
                effect=DecisionEffect.ALLOW,
                reason="default-allow",
                policy_id=pid,
                obligations=(),
                ttl_seconds=2,
                trace_id=ctx.trace_id,
            )
        return Decision(
            effect=DecisionEffect.DENY,
            reason="default-deny",
            policy_id=pid,
            obligations=(),
            ttl_seconds=10,
            trace_id=ctx.trace_id,
        )


# ======================
# Контроллер Admission
# ======================

class AdmissionController:
    """
    Центральный контроллер принятия решений (admission).
    Реализует:
      - deny‑overrides, Zero‑Trust;
      - кэширование решений по (subject, method, path, tenant, roles, risk, mtls-used);
      - интеграцию с лимитами (IP/пользователь/сервис) и квотами;
      - аудит решений;
      - расширяемые адаптеры политики.
    """

    def __init__(
        self,
        policy: PolicyAdapter,
        audit: Optional[AuditSink] = None,
        rate_limit_ip: Optional[RateLimiter] = None,
        rate_limit_user: Optional[RateLimiter] = None,
        rate_limit_service: Optional[RateLimiter] = None,
        quotas: Optional[QuotaManager] = None,
        cache: Optional[TTLCache] = None,
    ) -> None:
        self._policy = policy
        self._audit = audit or JsonAuditSink()
        self._rl_ip = rate_limit_ip
        self._rl_user = rate_limit_user
        self._rl_service = rate_limit_service
        self._quotas = quotas
        self._cache = cache or TTLCache()

    # ---- Публичный API ----
    def admit(self, ctx: RequestContext, quota_key: Optional[str] = None, quota_cost: int = 1) -> Decision:
        cache_key = self._cache_key(ctx)
        cached = self._cache.get(cache_key)
        if cached is not None:
            self._audit.log_decision(ctx, cached, level=LogLevel.DEBUG)
            return cached

        # Лимиты: IP
        if self._rl_ip and not self._rl_ip.allow(key=f"ip:{ctx.client_ip}", cost=1):
            d = Decision(
                effect=DecisionEffect.DENY,
                reason="rate-limit-ip",
                policy_id="admission",
                obligations=(),
                ttl_seconds=5,
                trace_id=ctx.trace_id,
            )
            self._audit.log_decision(ctx, d, level=LogLevel.WARN)
            return d

        # Лимиты: пользователь/сервис
        principal = (ctx.auth.subject if ctx.auth else "")
        is_service = bool(ctx.mtls and ctx.mtls.used and (ctx.mtls.spiffe_id or "").startswith("spiffe://"))
        if is_service and self._rl_service and not self._rl_service.allow(key=f"svc:{principal}", cost=1):
            d = Decision(
                effect=DecisionEffect.DENY,
                reason="rate-limit-service",
                policy_id="admission",
                obligations=(),
                ttl_seconds=5,
                trace_id=ctx.trace_id,
            )
            self._audit.log_decision(ctx, d, level=LogLevel.WARN)
            return d
        if not is_service and self._rl_user and not self._rl_user.allow(key=f"user:{principal}", cost=1):
            d = Decision(
                effect=DecisionEffect.DENY,
                reason="rate-limit-user",
                policy_id="admission",
                obligations=(),
                ttl_seconds=5,
                trace_id=ctx.trace_id,
            )
            self._audit.log_decision(ctx, d, level=LogLevel.WARN)
            return d

        # Политика
        decision = self._policy.evaluate(ctx)

        # Квоты
        if decision.allowed and self._quotas and quota_key:
            if not self._quotas.consume(key=quota_key, amount=max(quota_cost, 1)):
                decision = Decision(
                    effect=DecisionEffect.DENY,
                    reason="quota-exceeded",
                    policy_id=decision.policy_id,
                    obligations=decision.obligations,
                    ttl_seconds=10,
                    trace_id=decision.trace_id or ctx.trace_id,
                )

        # Кэширование
        self._cache.put(cache_key, decision, decision.ttl_seconds)
        # Аудит
        lvl = LogLevel.INFO if decision.allowed else LogLevel.WARN
        self._audit.log_decision(ctx, decision, level=lvl)
        return decision

    # ---- Вспомогательные методы ----
    @staticmethod
    def _cache_key(ctx: RequestContext) -> str:
        subject = (ctx.auth.subject if ctx.auth else "")
        tenant = (ctx.auth.tenant_id if ctx.auth else "")
        roles = ",".join(sorted(r.lower() for r in (ctx.auth.roles if ctx.auth else ())))
        risk = f"{(ctx.risk.score if ctx.risk else -1)}:{(ctx.risk.level.value if ctx.risk else 'na')}"
        mtls_used = "1" if (ctx.mtls and ctx.mtls.used) else "0"
        return "|".join([subject, tenant, roles, ctx.method.upper(), ctx.path, risk, mtls_used, ctx.client_ip])


# ===================
# Фабрики и билдеры
# ===================

def build_default_controller(
    policy_yaml_text: str,
    policy_id: str = "authz.yaml",
    rl_ip_capacity: int = 300,
    rl_ip_refill_per_sec: float = 5.0,
    rl_user_capacity: int = 120,
    rl_user_refill_per_sec: float = 2.0,
    rl_service_capacity: int = 900,
    rl_service_refill_per_sec: float = 15.0,
    quota_daily: int = 250_000,
) -> AdmissionController:
    """
    Сборка готового admission‑контроллера:
      - YAML‑политика (см. YamlPolicyAdapter);
      - in‑memory rate‑limits и квоты как безопасный fallback;
      - JSON‑аудит в stdout.
    В продакшене рекомендуется заменить лимиты/квоты на внешние провайдеры (Redis и т.п.).
    """
    adapter = YamlPolicyAdapter(policy_id=policy_id, yaml_text=policy_yaml_text)
    audit = JsonAuditSink()
    rl_ip = MemoryTokenBucket(capacity=rl_ip_capacity, refill_per_sec=rl_ip_refill_per_sec)
    rl_user = MemoryTokenBucket(capacity=rl_user_capacity, refill_per_sec=rl_user_refill_per_sec)
    rl_svc = MemoryTokenBucket(capacity=rl_service_capacity, refill_per_sec=rl_service_refill_per_sec)
    quotas = MemoryQuota(daily_limit=quota_daily)
    cache = TTLCache()
    return AdmissionController(
        policy=adapter,
        audit=audit,
        rate_limit_ip=rl_ip,
        rate_limit_user=rl_user,
        rate_limit_service=rl_svc,
        quotas=quotas,
        cache=cache,
    )


# ===========================
# Публичные типы для импорта
# ===========================

__all__ = [
    "AdmissionError",
    "PolicyLoadError",
    "RateLimitError",
    "DecisionEffect",
    "RiskLevel",
    "LogLevel",
    "DeviceAttestation",
    "RiskSignal",
    "AuthContext",
    "MtlsContext",
    "RequestContext",
    "Obligation",
    "Decision",
    "PolicyAdapter",
    "RateLimiter",
    "QuotaManager",
    "AuditSink",
    "JsonAuditSink",
    "MemoryTokenBucket",
    "MemoryQuota",
    "TTLCache",
    "YamlPolicyAdapter",
    "AdmissionController",
    "build_default_controller",
]
