# -*- coding: utf-8 -*-
"""
Genius Core — Self Inhibitor — OPA Adapter

Назначение:
- Делегирование части решений по безопасностной политике в Open Policy Agent (OPA) через REST API.
- Композиция результата OPA с локальным SelfInhibitionEvaluator (консервативная).
- Устойчивость: таймауты, ретраи, экспоненциальный бэк-офф, circuit breaker, LRU-кэш.
- Наблюдаемость: Prometheus-метрики и OpenTelemetry-спаны (опционально).

Контракт OPA:
- Запрос: POST {base_url}/v1/data/{decision_path}
  Body: { "input": { "text": <str>, "context": <object> } }
- Ответ (варианты):
  1) {"result": true|false}
  2) {"result": {"allow": bool, "action": "ALLOW|WARN|REDACT|BLOCK|ESCALATE",
                 "reasons": [str], "score": 0..100,
                 "categories": ["SELF_HARM", ...],
                 "obligations": {"redact": true, ...}}}

Безопасность:
- Секреты (API-токены) не логируются.
- При fail_closed=true — сбои OPA трактуются как запрет (BLOCK/ESCALATE).
- При fail_closed=false — сбои OPA трактуются как "не влияет" (ALLOW).

Внимание: пути/политики вашего кластера OPA могут отличаться. I cannot verify this.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

# -------- Опциональные зависимости --------
try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

try:
    from pydantic import BaseSettings, BaseModel, Field, validator  # type: ignore
    _PYD = True
except Exception:  # pragma: no cover
    _PYD = False
    class BaseSettings:  # type: ignore
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
    class BaseModel:  # type: ignore
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
    def Field(default=None, **_): return default  # type: ignore
    def validator(*_a, **_k):
        def _wrap(fn): return fn
        return _wrap

try:
    from prometheus_client import Counter, Histogram, Gauge  # type: ignore
    _PROM = True
except Exception:  # pragma: no cover
    _PROM = False
    class _Noop:
        def labels(self, *a, **k): return self
        def inc(self, *a, **k): pass
        def observe(self, *a, **k): pass
        def set(self, *a, **k): pass
    Counter = Histogram = Gauge = _Noop  # type: ignore

try:
    from opentelemetry import trace  # type: ignore
    _OTEL = True
except Exception:  # pragma: no cover
    _OTEL = False
    trace = None  # type: ignore

# -------- Совместимость с внутренними типами --------
try:
    from genius_core.security.self_inhibitor.evaluator import Action, Category  # type: ignore
except Exception:  # pragma: no cover
    # Фолбэк, если модуль не импортируется на этапе линтинга
    from enum import Enum
    class Action(str, Enum):
        ALLOW = "ALLOW"
        WARN = "WARN"
        REDACT = "REDACT"
        BLOCK = "BLOCK"
        ESCALATE = "ESCALATE"
    class Category(str, Enum):
        PROMPT_INJECTION = "PROMPT_INJECTION"
        SELF_HARM = "SELF_HARM"
        VIOLENCE = "VIOLENCE"
        ILLEGAL = "ILLEGAL"
        CYBER_ABUSE = "CYBER_ABUSE"
        SEXUAL = "SEXUAL"
        HATE = "HATE"
        PII = "PII"
        SECRETS = "SECRETS"
        MEDICAL = "MEDICAL"
        LEGAL = "LEGAL"
        POLITICAL = "POLITICAL"

# -------- Метрики --------
OPA_REQS = Counter("genius_opa_requests_total", "OPA requests", ["result"]) if _PROM else Counter()
OPA_LAT = Histogram("genius_opa_latency_seconds", "OPA latency seconds") if _PROM else Histogram()
OPA_CB  = Gauge("genius_opa_circuit_state", "OPA circuit breaker state (0=closed,1=open)") if _PROM else Gauge()

# -------- Настройки --------
class OPASettings(BaseSettings):
    base_url: str = Field("http://localhost:8181", env="OPA_BASE_URL")
    decision_path: str = Field("genius/self_inhibitor/decision", env="OPA_DECISION_PATH")  # rego: package genius.self_inhibitor
    auth_bearer: Optional[str] = Field(None, env="OPA_BEARER_TOKEN")
    timeout_s: float = Field(1.5, env="OPA_TIMEOUT_S")
    retries: int = Field(1, env="OPA_RETRIES")
    backoff_s: float = Field(0.2, env="OPA_BACKOFF_S")
    verify_tls: bool = Field(True, env="OPA_VERIFY_TLS")
    # Кэш и breaker
    cache_ttl_s: int = Field(15, env="OPA_CACHE_TTL_S")
    cache_size: int = Field(4096, env="OPA_CACHE_SIZE")
    breaker_fail_threshold: int = Field(5, env="OPA_BREAKER_FAIL_THRESHOLD")
    breaker_reset_s: float = Field(10.0, env="OPA_BREAKER_RESET_S")
    # Поведение при сбое
    fail_closed: bool = Field(True, env="OPA_FAIL_CLOSED")  # True => сбоем считаем запрет (консервативно)
    # Сопоставления по умолчанию
    default_allow_action: Action = Field(Action.ALLOW, env="OPA_DEFAULT_ALLOW_ACTION")
    default_deny_action: Action = Field(Action.BLOCK, env="OPA_DEFAULT_DENY_ACTION")

    class Config:
        env_file = os.environ.get("ENV_FILE", None)
        case_sensitive = False

class OPADecision(BaseModel):
    allow: bool
    action: Action
    reasons: List[str] = Field(default_factory=list)
    score: Optional[int] = None
    categories: List[Category] = Field(default_factory=list)
    obligations: Dict[str, Any] = Field(default_factory=dict)
    raw: Optional[Dict[str, Any]] = None  # исходный result

class OPAEvaluation(BaseModel):
    """
    Финальный результат адаптера (после композиции с локальным решением, если передавали).
    """
    action: Action
    reasons: List[str]
    categories: List[Category]
    score: int
    opa: Optional[OPADecision] = None
    local: Optional[Dict[str, Any]] = None

# -------- Простой LRU-кэш с TTL --------
class _LRU:
    def __init__(self, cap: int, ttl_s: int):
        from collections import OrderedDict
        self._od = OrderedDict()
        self.cap = cap
        self.ttl = ttl_s
    def get(self, k):
        now = time.time()
        if k in self._od:
            v, exp = self._od.pop(k)
            if exp > now:
                self._od[k] = (v, exp)
                return v
        return None
    def set(self, k, v):
        exp = time.time() + self.ttl
        if k in self._od:
            self._od.pop(k)
        self._od[k] = (v, exp)
        while len(self._od) > self.cap:
            self._od.popitem(last=False)

# -------- Circuit Breaker --------
@dataclass
class _Breaker:
    fails: int = 0
    opened_at: float = 0.0
    state_open: bool = False
    threshold: int = 5
    reset_after_s: float = 10.0

    def on_success(self):
        self.fails = 0
        if self.state_open and time.time() - self.opened_at > self.reset_after_s:
            self.state_open = False
            self.opened_at = 0.0
    def on_failure(self):
        self.fails += 1
        if self.fails >= self.threshold and not self.state_open:
            self.state_open = True
            self.opened_at = time.time()
    def can_attempt(self) -> bool:
        if not self.state_open:
            return True
        # Полуоткрытый режим по таймеру
        return (time.time() - self.opened_at) > self.reset_after_s

# -------- Основной адаптер --------
class OPAAdapter:
    def __init__(self, settings: Optional[OPASettings] = None):
        self.cfg = settings or OPASettings()
        if httpx is None:
            raise RuntimeError("httpx is required for OPAAdapter")
        self._cache = _LRU(self.cfg.cache_size, self.cfg.cache_ttl_s)
        self._breaker = _Breaker(threshold=self.cfg.breaker_fail_threshold, reset_after_s=self.cfg.breaker_reset_s)

    # ---- Публичный API ----
    async def evaluate(self, text: str, *, context: Optional[Mapping[str, Any]] = None) -> OPADecision:
        """
        Выполнить решение в OPA и вернуть OPADecision.
        """
        key = self._cache_key(text, context)
        cached: Optional[OPADecision] = self._cache.get(key)
        if cached:
            return cached

        if not self._breaker.can_attempt():
            if _PROM: OPA_CB.set(1)
            # breaker открыт — консервативная деградация
            decision = self._degraded_decision(reason="circuit_open")
            self._cache.set(key, decision)
            return decision

        if _PROM: OPA_CB.set(0)
        t0 = time.perf_counter()
        try:
            result = await self._call_opa(text, context or {})
            if _PROM:
                OPA_REQS.labels("ok").inc()
                OPA_LAT.observe(time.perf_counter() - t0)
            self._breaker.on_success()
            dec = self._map_result(result)
            self._cache.set(key, dec)
            return dec
        except Exception as e:
            if _PROM:
                OPA_REQS.labels("error").inc()
            self._breaker.on_failure()
            # деградация
            dec = self._degraded_decision(reason=f"error:{type(e).__name__}")
            self._cache.set(key, dec)
            return dec

    async def compose_with_local(self,
                                 local_action: Action,
                                 local_score: int,
                                 local_categories: Optional[List[Category]] = None,
                                 local_reasons: Optional[List[str]] = None,
                                 *,
                                 text: str,
                                 context: Optional[Mapping[str, Any]] = None) -> OPAEvaluation:
        """
        Выполнить запрос в OPA и консервативно скомбинировать с локальным решением.
        Правила композиции (упорядочивание по строгости): BLOCK > ESCALATE > REDACT > WARN > ALLOW.
        """
        opa_dec = await self.evaluate(text, context=context)

        # Линейный порядок строгости
        order = {Action.BLOCK: 4, Action.ESCALATE: 3, Action.REDACT: 2, Action.WARN: 1, Action.ALLOW: 0}
        final = opa_dec.action if order[opa_dec.action] >= order[local_action] else local_action

        # Счёт конфиденциально агрегируем как max
        score = max(local_score, opa_dec.score or 0)
        cats = sorted(set((local_categories or []) + (opa_dec.categories or [])), key=lambda c: c.value)
        reasons = (local_reasons or []) + (opa_dec.reasons or [])
        return OPAEvaluation(action=final, reasons=reasons, categories=cats, score=score,
                             opa=opa_dec, local={"action": local_action, "score": local_score,
                                                 "categories": local_categories or [], "reasons": local_reasons or []})

    async def ping(self) -> bool:
        """
        Быстрый health-check OPA. Возвращает True/False.
        """
        url = self._url("/health")
        try:
            async with httpx.AsyncClient(timeout=self.cfg.timeout_s, verify=self.cfg.verify_tls) as client:
                r = await client.get(url)
                return r.status_code in (200, 204)
        except Exception:
            return False

    # ---- Внутренние методы ----
    async def _call_opa(self, text: str, context: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Вызов OPA Data API с ретраями и бэк-оффом.
        """
        url = self._url(f"/v1/data/{self.cfg.decision_path}")
        headers = {"Content-Type": "application/json"}
        if self.cfg.auth_bearer:
            headers["Authorization"] = f"Bearer {self.cfg.auth_bearer}"

        # Подготовка входа — строго сериализуем
        payload = {"input": {"text": str(text), "context": _safe_json_like(context)}}

        timeout = httpx.Timeout(self.cfg.timeout_s)
        attempt = 0
        last_err = None
        while attempt <= self.cfg.retries:
            attempt += 1
            span = None
            if _OTEL:
                tracer = trace.get_tracer("genius.opa")  # type: ignore
                span = tracer.start_as_current_span("opa.evaluate", attributes={"attempt": attempt, "path": self.cfg.decision_path})  # type: ignore
                span.__enter__()  # type: ignore
            try:
                async with httpx.AsyncClient(timeout=timeout, verify=self.cfg.verify_tls) as client:
                    r = await client.post(url, headers=headers, json=payload)
                if r.status_code >= 500:
                    # серверная ошибка — ретрай
                    last_err = RuntimeError(f"OPA {r.status_code}")
                    await asyncio.sleep(self.cfg.backoff_s * attempt)
                    continue
                if r.status_code >= 400:
                    # клиентская — не ретраим
                    raise RuntimeError(f"OPA client error {r.status_code}: {r.text[:200]}")
                try:
                    data = r.json()
                except Exception as je:
                    raise RuntimeError(f"OPA invalid JSON: {je}")
                return data
            except Exception as e:
                last_err = e
                await asyncio.sleep(self.cfg.backoff_s * attempt)
            finally:
                if span:
                    span.__exit__(None, None, None)  # type: ignore
        # исчерпали попытки
        raise last_err or RuntimeError("OPA call failed without specific error")

    def _map_result(self, data: Dict[str, Any]) -> OPADecision:
        """
        Унификация различных форматов ответа OPA к OPADecision.
        """
        res = data.get("result", data) if isinstance(data, dict) else data
        # Вариант 1: булево
        if isinstance(res, bool):
            return OPADecision(
                allow=bool(res),
                action=self.cfg.default_allow_action if res else self.cfg.default_deny_action,
                reasons=[],
                score=100 if res else 0,
                categories=[],
                obligations={},
                raw={"allow": bool(res)}
            )
        # Вариант 2: объект
        if isinstance(res, dict):
            allow = bool(res.get("allow", True))
            action = _to_action(res.get("action"), default=(self.cfg.default_allow_action if allow else self.cfg.default_deny_action))
            reasons = [str(x) for x in (res.get("reasons") or [])]
            score = _coerce_int(res.get("score"))
            categories = [_to_category(c) for c in (res.get("categories") or [])]
            obligations = res.get("obligations") or {}
            return OPADecision(allow=allow, action=action, reasons=reasons, score=score,
                               categories=categories, obligations=obligations, raw=res)
        # Неизвестный формат — консервативно
        return OPADecision(
            allow=False if self.cfg.fail_closed else True,
            action=self.cfg.default_deny_action if self.cfg.fail_closed else self.cfg.default_allow_action,
            reasons=["opa_unknown_result"],
            score=0,
            categories=[],
            obligations={},
            raw={"_unparsed": data}
        )

    def _degraded_decision(self, *, reason: str) -> OPADecision:
        """
        Решение при ошибке/брейкере/таймауте.
        """
        if self.cfg.fail_closed:
            return OPADecision(allow=False, action=self.cfg.default_deny_action,
                               reasons=[reason, "fail_closed"], score=0, categories=[], obligations={}, raw={"degraded": True})
        return OPADecision(allow=True, action=self.cfg.default_allow_action,
                           reasons=[reason, "fail_open"], score=100, categories=[], obligations={}, raw={"degraded": True})

    def _url(self, path: str) -> str:
        base = self.cfg.base_url.rstrip("/")
        return base + (path if path.startswith("/") else "/" + path)

    @staticmethod
    def _cache_key(text: str, context: Optional[Mapping[str, Any]]) -> str:
        h = hashlib.blake2b(digest_size=16)
        h.update(text.encode("utf-8"))
        if context:
            try:
                h.update(json.dumps(_safe_json_like(context), sort_keys=True, ensure_ascii=False).encode("utf-8"))
            except Exception:
                pass
        return h.hexdigest()

# -------- Утилиты приведения типов --------
def _to_action(val: Any, *, default: Action) -> Action:
    try:
        if isinstance(val, Action):
            return val
        if isinstance(val, str):
            v = val.strip().upper()
            return Action(v) if v in Action.__members__ else default
    except Exception:
        pass
    return default

def _to_category(val: Any) -> Category:
    try:
        if isinstance(val, Category):
            return val
        if isinstance(val, str):
            v = val.strip().upper()
            return Category(v) if v in Category.__members__ else Category.POLITICAL if v == "POLITICS" else Category.PII if v == "PII" else Category.SECRETS if v == "SECRETS" else Category.CYBER_ABUSE
    except Exception:
        pass
    # дефолтная категория для неизвестных — CYBER_ABUSE (наименее специфичная)
    return Category.CYBER_ABUSE

def _coerce_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except Exception:
        return default

def _safe_json_like(x: Any, depth: int = 4) -> Any:
    """
    Безопасно приводит произвольные мапы к JSON-совместимому виду, с ограничением вложенности.
    """
    if depth <= 0:
        return str(type(x).__name__)
    if x is None or isinstance(x, (bool, int, float, str)):
        return x
    if isinstance(x, (list, tuple)):
        return [_safe_json_like(i, depth - 1) for i in x]
    if isinstance(x, dict):
        out = {}
        for k, v in x.items():
            key = str(k)[:64]
            out[key] = _safe_json_like(v, depth - 1)
        return out
    # прочее
    return str(x)[:256]

# -------- Пример использования (не исполняется при импорте) --------
"""
Пример Rego-политики (в OPA):

package genius.self_inhibitor

default decision = {"allow": true, "action": "ALLOW", "reasons": [], "score": 100, "categories": []}

deny_selfharm {
  contains(input.text, "покончить с собой")
}

deny_selfharm {
  re_match("(?i)\\b(suicide|self[-\\s]?harm)\\b", input.text)
}

decision = {"allow": false, "action": "BLOCK", "reasons": ["self_harm"], "score": 90, "categories": ["SELF_HARM"]} {
  deny_selfharm
}

Инициализация адаптера:

from genius_core.security.self_inhibitor.adapters.opa_adapter import OPAAdapter, OPASettings
opa = OPAAdapter(OPASettings(base_url="http://opa:8181", decision_path="genius/self_inhibitor/decision"))

# Вызов:
res = await opa.evaluate("Мне плохо, хочу покончить с собой", context={"role": "user"})
print(res.action, res.reasons)

# Композиция с локальным результатом:
final = await opa.compose_with_local(local_action=Action.WARN, local_score=40,
                                     local_categories=[Category.MEDICAL],
                                     local_reasons=["local_medical_hint"],
                                     text="...", context={"endpoint": "/chat"})
print(final.action, final.reasons, final.categories)
"""

# Конец файла
