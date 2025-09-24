# veilmind-core/veilmind/consent/enforcement.py
# -*- coding: utf-8 -*-
"""
VeilMind — Consent Enforcement

Промышленный механизм принудительного применения согласий:
- ConsentEnforcer: синхронный фасад над ConsentMechanism с TTL‑кэшем.
- ASGI middleware для FastAPI/Starlette: маршрутизация путей/методов к целям обработки.
- Декораторы для прикладной логики/воркеров.
- Детектор GPC, эвристики региона/возраста из заголовков.
- Безопасная деградация при отсутствии внешних зависимостей (Starlette и т.п.).

НЕ хранит PII. Все идентификаторы пользователя — внешние стабильные строки,
которые хэшируются внутри ConsentMechanism (см. veilmind/dp/mechanisms.py).
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Pattern, Sequence, Tuple, Union

# Мягкие зависимости на Starlette/FastAPI для ASGI middleware
try:  # pragma: no cover
    from starlette.types import ASGIApp, Receive, Scope, Send
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
except Exception:  # pragma: no cover
    ASGIApp = object  # type: ignore
    Receive = Send = Scope = Any  # type: ignore
    Request = Response = object  # type: ignore
    JSONResponse = None  # type: ignore

# Внутренние механизмы согласий
from veilmind.dp.mechanisms import (
    ConsentMechanism,
    DecisionResult,
    Purpose,
    Decision,  # ALLOW/DENY/...
)

__all__ = [
    "Rule",
    "ConsentEnforcer",
    "ConsentMiddleware",
    "attach_fastapi",
    "enforce_purpose",
    "detect_gpc",
    "infer_region",
    "infer_age",
]

# ---------------------------------------------------------------------------
# Вспомогательные структуры
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Rule:
    """
    Описание правила сопоставления HTTP‑запросов цели обработки.

    pattern: regex для пути (например, r"^/analytics/.*")
    methods: список HTTP‑методов (по умолчанию любые)
    purpose: один из Purpose.*
    """
    pattern: Pattern[str]
    purpose: str
    methods: Tuple[str, ...] = tuple()

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "Rule":
        pat = re.compile(str(d["pattern"]))
        pur = str(d["purpose"])
        mets = tuple(m.upper() for m in d.get("methods", []) if isinstance(m, str))
        return Rule(pattern=pat, purpose=pur, methods=mets)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ulid_like() -> str:
    # Без зависимости от внешних библиотек используем uuid4.hex
    return uuid.uuid4().hex


# ---------------------------------------------------------------------------
# TTL‑кэш решений
# ---------------------------------------------------------------------------

class _TTLCache:
    def __init__(self, capacity: int = 10000, default_ttl_sec: float = 60.0, allow_negative: bool = True) -> None:
        self.capacity = int(capacity)
        self.default_ttl = float(default_ttl_sec)
        self.allow_negative = bool(allow_negative)
        self._data: Dict[str, Tuple[float, Dict[str, Any]]] = {}

    def _prune(self) -> None:
        if len(self._data) <= self.capacity:
            return
        # Удаляем самые старые по истечению
        now = time.monotonic()
        # Быстрая эвакуация: удалить 10% случайно по истечению
        to_del = []
        for k, (exp, _) in list(self._data.items())[: max(1, self.capacity // 10)]:
            if exp <= now:
                to_del.append(k)
        for k in to_del:
            self._data.pop(k, None)
        # Если всё ещё переполнен — удалить из начала
        while len(self._data) > self.capacity:
            self._data.pop(next(iter(self._data)))

    def put(self, key: str, value: Dict[str, Any], ttl: Optional[float] = None, negative: bool = False) -> None:
        if negative and not self.allow_negative:
            return
        exp = time.monotonic() + (ttl if ttl is not None else self.default_ttl)
        self._data[key] = (exp, value)
        self._prune()

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        item = self._data.get(key)
        if not item:
            return None
        exp, val = item
        if exp < time.monotonic():
            self._data.pop(key, None)
            return None
        return val

    def invalidate(self, prefix: Optional[str] = None) -> int:
        if not prefix:
            n = len(self._data)
            self._data.clear()
            return n
        keys = [k for k in self._data if k.startswith(prefix)]
        for k in keys:
            self._data.pop(k, None)
        return len(keys)


# ---------------------------------------------------------------------------
# Базовый Enforcer
# ---------------------------------------------------------------------------

class ConsentEnforcer:
    """
    Высокоуровневый фасад для применения согласий в коде приложений.

    Использование:
      enforcer = ConsentEnforcer(mechanism)
      res = enforcer.ensure_allowed(user_id="u1", purpose=Purpose.ANALYTICS.value, region="EEA", age=25, gpc=False)
      if not res["allowed"]: ...  # вернуть 403

    Кэширование:
      ключ = (policy_version, user_id, region, age_bucket, gpc, purpose)
      TTL на ALLOW: 60с или до истечения согласия (минимум)
      TTL на DENY: 30с
    """
    def __init__(self,
                 mechanism: ConsentMechanism,
                 cache_capacity: int = 50000,
                 positive_ttl_sec: float = 60.0,
                 negative_ttl_sec: float = 30.0,
                 allow_negative_cache: bool = True) -> None:
        self.mech = mechanism
        self.cache_pos = _TTLCache(capacity=cache_capacity, default_ttl_sec=positive_ttl_sec, allow_negative=True)
        self.cache_neg = _TTLCache(capacity=max(1024, cache_capacity // 10), default_ttl_sec=negative_ttl_sec, allow_negative=allow_negative_cache)

    @staticmethod
    def _age_bucket(age: Optional[int]) -> str:
        if age is None:
            return "na"
        # 0-12, 13-15, 16-17, 18-25, 26-40, 41-65, 66+
        brks = [(0, 12), (13, 15), (16, 17), (18, 25), (26, 40), (41, 65)]
        for lo, hi in brks:
            if lo <= age <= hi:
                return f"{lo}-{hi}"
        return "66+"

    def _cache_key(self, user_id: str, purpose: str, region: Optional[str], age: Optional[int], gpc: bool) -> str:
        return "|".join([
            self.mech.policy.version,
            user_id or "anon",
            (region or "EEA").upper(),
            self._age_bucket(age),
            "GPC1" if gpc else "GPC0",
            purpose,
        ])

    def _ttl_from_expires(self, expires_at: Optional[datetime], default_ttl: float) -> float:
        if not expires_at:
            return default_ttl
        now = datetime.now(timezone.utc)
        delta = (expires_at - now).total_seconds()
        return max(1.0, min(default_ttl, delta))

    def ensure_allowed(self,
                       user_id: str,
                       purpose: str,
                       region: Optional[str],
                       age: Optional[int],
                       gpc: bool,
                       request_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Возвращает словарь с решением. Не поднимает исключений — для HTTP слой это удобнее.
        """
        key = self._cache_key(user_id, purpose, region, age, gpc)
        cached = self.cache_pos.get(key) or self.cache_neg.get(key)
        if cached:
            return {**cached, "cached": True}

        dr: DecisionResult = self.mech.decide(user_id=user_id, purpose_id=purpose, region=region, age=age, gpc_signal=gpc)
        allowed = dr.decision in (Decision.ALLOW,)

        result: Dict[str, Any] = {
            "allowed": allowed,
            "decision": dr.decision.value,
            "reason": dr.reason,
            "purpose": dr.purpose_id,
            "policy_version": dr.policy_version,
            "effective_region": dr.effective_region,
            "require_banner": dr.require_banner,
            "expires_at": dr.expires_at.replace(tzinfo=timezone.utc).isoformat() if dr.expires_at else None,
            "ts": _now_iso(),
            "request_id": request_id or _ulid_like(),
        }

        if allowed:
            ttl = self._ttl_from_expires(dr.expires_at, self.cache_pos.default_ttl)
            self.cache_pos.put(key, result, ttl=ttl, negative=False)
        else:
            self.cache_neg.put(key, result, ttl=None, negative=True)

        # Аудит только в случае запрета/истечения для явности
        if not allowed:
            try:
                self.mech.audit.write({
                    "type": "enforcement",
                    "action": "deny",
                    "purpose": dr.purpose_id,
                    "reason": dr.reason,
                    "policy_version": dr.policy_version,
                    "effective_region": dr.effective_region,
                    "request_id": result["request_id"],
                    "ts": result["ts"],
                })
            except Exception:
                pass

        return result

    def invalidate_user(self, user_id: str) -> int:
        """
        Инвалидация кэша по пользователю (например, после изменения согласий).
        """
        pref = f"{self.mech.policy.version}|{user_id}|"
        return self.cache_pos.invalidate(pref) + self.cache_neg.invalidate(pref)


# ---------------------------------------------------------------------------
# Утилиты извлечения контекста из HTTP
# ---------------------------------------------------------------------------

def detect_gpc(headers: Mapping[str, str]) -> bool:
    """
    Детектирование Global Privacy Control:
      - 'Sec-GPC: 1' (браузерная спецификация)
      - 'GPC: 1' (legacy/прокси)
    """
    v = headers.get("sec-gpc") or headers.get("Sec-GPC") or headers.get("GPC") or headers.get("gpc")
    return str(v).strip() == "1"


def infer_region(headers: Mapping[str, str], default_region: str = "EEA") -> str:
    """
    Эвристика региона пользователя:
      - X-Region (прямой сигнал от фронтенда/идентификации)
      - CF-IPCountry / X-Geo-Country (CDN/edge)
      - иначе default_region
    """
    for k in ("X-Region", "x-region", "CF-IPCountry", "cf-ipcountry", "X-Geo-Country", "x-geo-country"):
        if k in headers and headers[k]:
            return str(headers[k]).upper()
    return default_region


def infer_age(headers: Mapping[str, str]) -> Optional[int]:
    """
    Эвристика возраста: X-User-Age или X-Age. Возраст может не передаваться.
    """
    for k in ("X-User-Age", "x-user-age", "X-Age", "x-age"):
        v = headers.get(k)
        if v:
            try:
                age = int(str(v).strip())
                return age if 0 <= age <= 120 else None
            except Exception:
                return None
    return None


def _extract_user_id(headers: Mapping[str, str]) -> str:
    """
    Извлечение идентификатора пользователя из заголовков:
      - X-User-ID (стабильный ID)
      - Authorization: Bearer <sub> (если прокинут upstream)
      - X-Device-ID (как fallback для device-level consent; может привести к запрету при prior_consent)
    """
    if headers.get("X-User-ID"):
        return str(headers["X-User-ID"])
    auth = headers.get("Authorization", "")
    if auth.startswith("Bearer ") and len(auth.split()) == 2:
        # В реальных системах sub/email извлекается после валидации JWT. Здесь используем токен как идентификатор последней инстанции.
        return auth.split(" ", 1)[1].strip()
    if headers.get("X-Device-ID"):
        return str(headers["X-Device-ID"])
    return ""


# ---------------------------------------------------------------------------
# ASGI Middleware
# ---------------------------------------------------------------------------

class ConsentMiddleware:
    """
    ASGI middleware для принудительного применения согласий по правилам маршрутизации.
    Пример подключения (FastAPI):
        app.add_middleware(
            ConsentMiddleware,
            enforcer=enforcer,
            rules=[
                {"pattern": r"^/analytics/.*", "methods": ["POST"], "purpose": "analytics"},
                {"pattern": r"^/ads/.*",       "purpose": "ads_personalization"},
            ],
            allowlist_paths=[r"^/healthz/.*", r"^/metrics$"],
            manage_url="/privacy/manage"
        )
    """
    def __init__(self,
                 app: ASGIApp,
                 enforcer: ConsentEnforcer,
                 rules: Sequence[Union[Rule, Mapping[str, Any]]],
                 allowlist_paths: Sequence[str] | None = None,
                 manage_url: str = "/privacy/manage",
                 deny_status: int = 403) -> None:
        self.app = app
        self.enforcer = enforcer
        self.rules: List[Rule] = [r if isinstance(r, Rule) else Rule.from_dict(r) for r in (rules or ())]
        self.allowlist: List[Pattern[str]] = [re.compile(p) for p in (allowlist_paths or [])]
        self.manage_url = manage_url
        self.deny_status = int(deny_status)

    def _match_rule(self, path: str, method: str) -> Optional[Rule]:
        for r in self.rules:
            if r.pattern.search(path) and (not r.methods or method in r.methods):
                return r
        return None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:  # type: ignore[override]
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "/")
        method = scope.get("method", "GET").upper()
        headers = {k.decode("latin1"): v.decode("latin1") for k, v in scope.get("headers", [])}

        # Allowlist — пропускаем без проверок
        for p in self.allowlist:
            if p.search(path):
                await self.app(scope, receive, send)
                return

        rule = self._match_rule(path, method)
        if not rule:
            await self.app(scope, receive, send)
            return

        # Контекст пользователя
        region = infer_region(headers)
        age = infer_age(headers)
        gpc = detect_gpc(headers)
        user_id = _extract_user_id(headers)
        req_id = headers.get("X-Request-ID") or _ulid_like()

        # Принятие решения
        result = self.enforcer.ensure_allowed(
            user_id=user_id,
            purpose=rule.purpose,
            region=region,
            age=age,
            gpc=gpc,
            request_id=req_id,
        )

        # Если запрещено — вернем 403 с машинописным телом.
        if not result["allowed"]:
            body = {
                "error": "consent_required" if result.get("require_banner") else "forbidden",
                "detail": result.get("reason"),
                "purpose": result.get("purpose"),
                "policy_version": result.get("policy_version"),
                "effective_region": result.get("effective_region"),
                "manage_url": self.manage_url,
                "request_id": result.get("request_id"),
                "ts": result.get("ts"),
            }
            # Отправка ответа вручную через ASGI send (без зависимостей)
            headers_out = [
                (b"content-type", b"application/json; charset=utf-8"),
                (b"x-consent-decision", result.get("decision", "DENY").encode("latin1")),
                (b"x-consent-policy-version", result.get("policy_version", "").encode("latin1")),
                (b"x-consent-effective-region", result.get("effective_region", "").encode("latin1")),
                (b"x-request-id", result.get("request_id", "").encode("latin1")),
            ]
            if self.manage_url:
                headers_out.append((b"link", f'<{self.manage_url}>; rel="privacy-policy"'.encode("latin1")))

            await send({
                "type": "http.response.start",
                "status": self.deny_status,
                "headers": headers_out,
            })
            await send({
                "type": "http.response.body",
                "body": json.dumps(body, ensure_ascii=False).encode("utf-8"),
                "more_body": False,
            })
            return

        # Разрешено — прокинем запрос дальше и добавим заголовки на ответ
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers_list = message.setdefault("headers", [])
                headers_list.extend([
                    (b"x-consent-decision", result.get("decision", "ALLOW").encode("latin1")),
                    (b"x-consent-policy-version", result.get("policy_version", "").encode("latin1")),
                    (b"x-consent-effective-region", result.get("effective_region", "").encode("latin1")),
                    (b"x-request-id", result.get("request_id", "").encode("latin1")),
                ])
            await send(message)

        await self.app(scope, receive, send_wrapper)


# ---------------------------------------------------------------------------
# Декораторы для прикладной логики (функции/корутины)
# ---------------------------------------------------------------------------

def enforce_purpose(enforcer: ConsentEnforcer,
                    purpose: Union[str, Purpose],
                    region_provider: Callable[[], Optional[str]] | None = None,
                    age_provider: Callable[[], Optional[int]] | None = None,
                    gpc_provider: Callable[[], bool] | None = None,
                    user_provider: Callable[[], str] | None = None):
    """
    Декоратор для бизнес‑функций/воркеров.

    Пример:
        @enforce_purpose(enforcer, Purpose.ANALYTICS)
        async def send_analytics(user_id: str, payload: dict): ...

        # где user_provider может выглядеть так:
        user_provider=lambda: current_user.id
    """
    purpose_id = purpose.value if isinstance(purpose, Purpose) else str(purpose)

    def _wrap(func: Callable[..., Any]):
        if asyncio.iscoroutinefunction(func):
            async def _async_inner(*args, **kwargs):
                uid = user_provider() if user_provider else kwargs.get("user_id", "") or ""
                reg = (region_provider() if region_provider else None) or "EEA"
                age = age_provider()() if callable(age_provider) and callable(age_provider()) else (age_provider() if age_provider else None)  # type: ignore
                gpc = gpc_provider() if gpc_provider else False
                res = enforcer.ensure_allowed(uid, purpose_id, reg, age, gpc)
                if not res["allowed"]:
                    raise PermissionError(f"Consent denied: {res.get('reason')} for purpose {purpose_id}")
                return await func(*args, **kwargs)
            return _async_inner
        else:
            def _inner(*args, **kwargs):
                uid = user_provider() if user_provider else kwargs.get("user_id", "") or ""
                reg = (region_provider() if region_provider else None) or "EEA"
                age = age_provider()() if callable(age_provider) and callable(age_provider()) else (age_provider() if age_provider else None)  # type: ignore
                gpc = gpc_provider() if gpc_provider else False
                res = enforcer.ensure_allowed(uid, purpose_id, reg, age, gpc)
                if not res["allowed"]:
                    raise PermissionError(f"Consent denied: {res.get('reason')} for purpose {purpose_id}")
                return func(*args, **kwargs)
            return _inner
    return _wrap


# ---------------------------------------------------------------------------
# Утилита быстрого подключения к FastAPI
# ---------------------------------------------------------------------------

def attach_fastapi(app: Any,
                   mechanism: ConsentMechanism,
                   rules: Sequence[Union[Rule, Mapping[str, Any]]],
                   allowlist_paths: Sequence[str] | None = None,
                   manage_url: str = "/privacy/manage",
                   deny_status: int = 403,
                   cache_capacity: int = 50000,
                   positive_ttl_sec: float = 60.0,
                   negative_ttl_sec: float = 30.0,
                   allow_negative_cache: bool = True) -> ConsentEnforcer:
    """
    Быстрое подключение к FastAPI/Starlette:
        enforcer = attach_fastapi(app, mechanism, rules=[...])
    """
    enforcer = ConsentEnforcer(
        mechanism=mechanism,
        cache_capacity=cache_capacity,
        positive_ttl_sec=positive_ttl_sec,
        negative_ttl_sec=negative_ttl_sec,
        allow_negative_cache=allow_negative_cache,
    )
    try:  # pragma: no cover
        # FastAPI имеет интерфейс add_middleware
        app.add_middleware(
            ConsentMiddleware,
            enforcer=enforcer,
            rules=rules,
            allowlist_paths=allowlist_paths or [],
            manage_url=manage_url,
            deny_status=deny_status,
        )
    except Exception:
        # Если это не FastAPI/Starlette — вернуть enforcer, мидлвару можно подключить вручную
        pass
    return enforcer


# ---------------------------------------------------------------------------
# Пример конфигурации правил (соответствует configs/consent.yaml->enforcement.server.reject_if_no_consent_for)
# ---------------------------------------------------------------------------

DEFAULT_RULES: List[Dict[str, Any]] = [
    {"pattern": r"^/analytics/.*", "methods": ["POST", "GET"], "purpose": Purpose.ANALYTICS.value},
    {"pattern": r"^/ads/.*",       "methods": ["GET"],         "purpose": Purpose.ADS.value},
]

DEFAULT_ALLOWLIST: List[str] = [
    r"^/healthz/.*",
    r"^/metrics$",
]

# ---------------------------------------------------------------------------
# Самопроверка (локальный запуск)
# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    from veilmind.dp.mechanisms import build_default_mechanism

    mech = build_default_mechanism()
    enforcer = ConsentEnforcer(mechanism=mech)

    uid = "01J2ZK5R3TS6Q4H2P8XWY9ABCD"
    # До согласия — analytics в EEA запрещена
    print(enforcer.ensure_allowed(uid, Purpose.ANALYTICS.value, region="EEA", age=25, gpc=False))
    # Даём согласие
    mech.grant(uid, Purpose.ANALYTICS.value, region="EEA", source="web")
    # Теперь разрешено
    print(enforcer.ensure_allowed(uid, Purpose.ANALYTICS.value, region="EEA", age=25, gpc=False))
