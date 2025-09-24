# neuroforge/adapters/policy_core_adapter.py
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import dataclasses
import fnmatch
import json
import logging
import ssl
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

LOG = logging.getLogger("neuroforge.policy")
if not LOG.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="ts=%(asctime)s lvl=%(levelname)s logger=%(name)s msg=%(message)s",
    )

# -----------------------------
# Типы данных
# -----------------------------

@dataclass(frozen=True)
class Subject:
    id: str
    attributes: Dict[str, Any] = dataclasses.field(default_factory=dict)

@dataclass(frozen=True)
class Resource:
    id: str
    type: str
    attributes: Dict[str, Any] = dataclasses.field(default_factory=dict)

@dataclass(frozen=True)
class Action:
    name: str
    attributes: Dict[str, Any] = dataclasses.field(default_factory=dict)

@dataclass(frozen=True)
class Environment:
    attributes: Dict[str, Any] = dataclasses.field(default_factory=dict)

@dataclass(frozen=True)
class PolicyInput:
    subject: Subject
    action: Action
    resource: Resource
    environment: Environment = dataclasses.field(default_factory=lambda: Environment({}))

@dataclass(frozen=True)
class Obligation:
    key: str
    value: Any

@dataclass(frozen=True)
class PolicyDecision:
    permit: bool
    reason: str = ""
    obligations: Tuple[Obligation, ...] = ()
    used_policy: Optional[str] = None
    advice: Optional[Dict[str, Any]] = None
    raw: Optional[Dict[str, Any]] = None

# -----------------------------
# Утилиты
# -----------------------------

def _get_in(d: Mapping[str, Any], dotted: str) -> Any:
    cur: Any = d
    for part in dotted.split("."):
        if not isinstance(cur, Mapping) or part not in cur:
            return None
        cur = cur[part]
    return cur

def _freeze(obj: Any) -> Any:
    if isinstance(obj, Mapping):
        return tuple(sorted((k, _freeze(v)) for k, v in obj.items()))
    if isinstance(obj, (list, tuple)):
        return tuple(_freeze(x) for x in obj)
    return obj

class TTLCache:
    def __init__(self, maxsize: int = 10000, ttl_seconds: float = 5.0) -> None:
        self.maxsize = int(maxsize)
        self.ttl = float(ttl_seconds)
        self._store: "OrderedDict[Any, Tuple[float, Any]]" = OrderedDict()

    def get(self, key: Any) -> Optional[Any]:
        now = time.time()
        item = self._store.get(key)
        if not item:
            return None
        exp, val = item
        if exp < now:
            self._store.pop(key, None)
            return None
        # LRU promotion
        self._store.move_to_end(key)
        return val

    def put(self, key: Any, val: Any) -> None:
        now = time.time()
        self._store[key] = (now + self.ttl, val)
        self._store.move_to_end(key)
        while len(self._store) > self.maxsize:
            self._store.popitem(last=False)

# -----------------------------
# Базовый интерфейс адаптера
# -----------------------------

class BasePolicyAdapter:
    def evaluate(self, req: PolicyInput) -> PolicyDecision:
        raise NotImplementedError()

    def health(self) -> Dict[str, Any]:
        return {"ok": True, "name": self.__class__.__name__}

# -----------------------------
# Статический ABAC-адаптер
# -----------------------------

@dataclass
class StaticRule:
    name: str
    effect: str  # "permit"|"deny"
    actions: Sequence[str] = field(default_factory=lambda: ["*"])      # fnmatch
    resources: Sequence[str] = field(default_factory=lambda: ["*"])    # fnmatch по resource.type или id:type
    when: Dict[str, Dict[str, Any]] = field(default_factory=dict)      # условия по атрибутам
    obligations: Dict[str, Any] = field(default_factory=dict)
    advice: Dict[str, Any] = field(default_factory=dict)
    reason: str = ""

def _match_cond(attrs: Mapping[str, Any], cond: Mapping[str, Any]) -> bool:
    # Поддержка: eq, ne, in, nin, gt, gte, lt, lte, exists
    for key, ops in cond.items():
        if isinstance(ops, bool):
            ops = {"exists": ops}
        if not isinstance(ops, Mapping):
            ops = {"eq": ops}
        val = _get_in(attrs, key)
        for op, expected in ops.items():
            if op == "eq" and not (val == expected): return False
            if op == "ne" and not (val != expected): return False
            if op == "in" and not (val in set(expected)): return False
            if op == "nin" and not (val not in set(expected)): return False
            if op == "gt" and not (isinstance(val, (int, float)) and val > expected): return False
            if op == "gte" and not (isinstance(val, (int, float)) and val >= expected): return False
            if op == "lt" and not (isinstance(val, (int, float)) and val < expected): return False
            if op == "lte" and not (isinstance(val, (int, float)) and val <= expected): return False
            if op == "exists" and not (bool(val is not None) == bool(expected)): return False
    return True

class StaticPolicyAdapter(BasePolicyAdapter):
    """
    Простой «первый применимый» ABAC с шаблонами действий/ресурсов.
    resources:
      - сопоставляются по resource.type (e.g. "model:*") либо "type:id" (e.g. "model:bert-base")
    """
    def __init__(self, rules: Sequence[StaticRule], default_effect: str = "deny") -> None:
        self.rules = list(rules)
        self.default_effect = default_effect.lower().strip()
        assert self.default_effect in {"permit", "deny"}

    def evaluate(self, req: PolicyInput) -> PolicyDecision:
        act = req.action.name
        res_kind = f"{req.resource.type}:{req.resource.id}"
        res_type = req.resource.type

        # Сводные атрибуты для условий
        attrs = {
            "subject": {"id": req.subject.id, **req.subject.attributes},
            "action": {"name": req.action.name, **req.action.attributes},
            "resource": {"id": req.resource.id, "type": req.resource.type, **req.resource.attributes},
            "env": req.environment.attributes,
        }

        for rule in self.rules:
            if not any(fnmatch.fnmatch(act, p) for p in rule.actions):
                continue
            if not any(fnmatch.fnmatch(res_type, p) or fnmatch.fnmatch(res_kind, p) for p in rule.resources):
                continue
            if not _match_cond(attrs, rule.when):
                continue

            permit = rule.effect.lower() == "permit"
            obligations = tuple(Obligation(k, v) for k, v in (rule.obligations or {}).items())
            return PolicyDecision(
                permit=permit,
                reason=rule.reason or f"Matched static rule {rule.name}",
                obligations=obligations,
                used_policy=rule.name,
                advice=rule.advice or None,
                raw={"adapter": "static"},
            )

        # default
        return PolicyDecision(
            permit=(self.default_effect == "permit"),
            reason="No static rule matched; default={}".format(self.default_effect),
            used_policy=None,
            raw={"adapter": "static"},
        )

# -----------------------------
# OPA HTTP-адаптер (без внешних зависимостей)
# -----------------------------

@dataclass
class OpaConfig:
    url: str                         # e.g. https://opa:8181/v1/data/neuro/policy/allow
    auth_token: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    timeout_sec: float = 1.5
    connect_retries: int = 1
    verify_ssl: bool = True
    ca_path: Optional[Union[str, Path]] = None
    input_wrapper_key: str = "input" # тело запроса {"input": {...}}
    # Ожидаемые поля ответа:
    # 1) boolean в result: {"result": true|false}
    # 2) объект: {"result": {"allow": bool, "obligations": {...}, "advice": {...}, "reason": "..."}}

class OpaHttpAdapter(BasePolicyAdapter):
    def __init__(self, cfg: OpaConfig) -> None:
        self.cfg = cfg
        self._ctx = None  # ssl.SSLContext | None
        if self.cfg.url.startswith("https"):
            self._ctx = ssl.create_default_context(cafile=str(self.cfg.ca_path) if self.cfg.ca_path else None)
            if not self.cfg.verify_ssl:
                self._ctx.check_hostname = False
                self._ctx.verify_mode = ssl.CERT_NONE

    def _http_post_json(self, url: str, body: Dict[str, Any]) -> Dict[str, Any]:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url=url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        for k, v in (self.cfg.headers or {}).items():
            req.add_header(k, v)
        if self.cfg.auth_token:
            req.add_header("Authorization", f"Bearer {self.cfg.auth_token}")

        attempt = 0
        last_err: Optional[Exception] = None
        while attempt <= max(0, int(self.cfg.connect_retries)):
            try:
                with urllib.request.urlopen(req, timeout=self.cfg.timeout_sec, context=self._ctx) as resp:
                    b = resp.read()
                    return json.loads(b.decode("utf-8"))
            except urllib.error.URLError as e:
                last_err = e
                attempt += 1
                if attempt > self.cfg.connect_retries:
                    break
                time.sleep(0.05 * attempt)
            except Exception as e:
                last_err = e
                break
        raise RuntimeError(f"OPA request failed: {last_err}")

    def evaluate(self, req: PolicyInput) -> PolicyDecision:
        payload = {
            "subject": {"id": req.subject.id, **req.subject.attributes},
            "action": {"name": req.action.name, **req.action.attributes},
            "resource": {"id": req.resource.id, "type": req.resource.type, **req.resource.attributes},
            "env": req.environment.attributes,
        }
        body = {self.cfg.input_wrapper_key: payload}
        t0 = time.time()
        try:
            resp = self._http_post_json(self.cfg.url, body)
        except Exception as e:
            LOG.warning("OPA unreachable: %s", e)
            return PolicyDecision(permit=False, reason=f"OPA error: {e}", raw={"adapter": "opa", "error": str(e)})
        dt = (time.time() - t0) * 1000.0

        result = resp.get("result", None)
        if isinstance(result, bool):
            return PolicyDecision(permit=result, reason=f"OPA boolean result (latency={dt:.1f}ms)", raw={"adapter": "opa"})
        if isinstance(result, Mapping):
            allow = bool(result.get("allow", False))
            obligations = tuple(Obligation(k, v) for k, v in (result.get("obligations") or {}).items())
            return PolicyDecision(
                permit=allow,
                reason=str(result.get("reason", f"OPA object result (latency={dt:.1f}ms)")),
                obligations=obligations,
                used_policy=str(result.get("policy", "")) or None,
                advice=result.get("advice"),
                raw={"adapter": "opa"},
            )
        return PolicyDecision(permit=False, reason="OPA invalid response format", raw={"adapter": "opa", "resp": resp})

# -----------------------------
# Композитный адаптер (policy combining)
# -----------------------------

@dataclass
class CompositeConfig:
    strategy: str = "first-applicable"  # "deny-overrides"|"permit-overrides"|"first-applicable"
    ttl_cache_sec: float = 2.0
    cache_maxsize: int = 20000
    trace: bool = True  # опциональная трассировка OTEL, если доступна

class CompositePolicyAdapter(BasePolicyAdapter):
    def __init__(self, adapters: Sequence[BasePolicyAdapter], cfg: CompositeConfig = CompositeConfig()) -> None:
        assert adapters, "At least one adapter required"
        self.adapters = list(adapters)
        self.cfg = cfg
        self.cache = TTLCache(maxsize=cfg.cache_maxsize, ttl_seconds=cfg.ttl_cache_sec)
        # opentelemetry — опционально
        self._tracer = None
        if cfg.trace:
            try:
                from opentelemetry import trace  # type: ignore
                self._tracer = trace.get_tracer("neuroforge.policy")
            except Exception:
                self._tracer = None

    def _span(self, name: str):
        if self._tracer:
            return self._tracer.start_as_current_span(name)  # type: ignore
        # no-op context manager
        class _Nop:
            def __enter__(self): return None
            def __exit__(self, *args): return False
        return _Nop()

    def evaluate(self, req: PolicyInput) -> PolicyDecision:
        key = _freeze(dataclasses.asdict(req))
        cached = self.cache.get(key)
        if cached is not None:
            return cached

        with self._span("policy.evaluate"):
            strat = self.cfg.strategy.lower().strip()
            last: Optional[PolicyDecision] = None

            if strat == "first-applicable":
                for ad in self.adapters:
                    d = ad.evaluate(req)
                    if d.used_policy or d.reason:  # любое осмысленное решение
                        last = d
                    if d.permit or (not d.permit and d.used_policy):
                        self.cache.put(key, d)
                        return d
                # ничего явного — вернём последнее или deny
                result = last or PolicyDecision(permit=False, reason="No adapter matched")
                self.cache.put(key, result)
                return result

            if strat == "deny-overrides":
                decision: Optional[PolicyDecision] = None
                for ad in self.adapters:
                    d = ad.evaluate(req)
                    if d.permit and decision is None:
                        decision = d
                    if not d.permit:  # deny побеждает
                        self.cache.put(key, d)
                        return d
                res = decision or PolicyDecision(permit=False, reason="No permit found")
                self.cache.put(key, res)
                return res

            if strat == "permit-overrides":
                deny_decision: Optional[PolicyDecision] = None
                for ad in self.adapters:
                    d = ad.evaluate(req)
                    if d.permit:
                        self.cache.put(key, d)
                        return d
                    deny_decision = deny_decision or d
                res = deny_decision or PolicyDecision(permit=False, reason="No permit found")
                self.cache.put(key, res)
                return res

            # fallback
            for ad in self.adapters:
                d = ad.evaluate(req)
                if d.permit:
                    self.cache.put(key, d)
                    return d
                last = d
            res = last or PolicyDecision(permit=False, reason="No adapter matched")
            self.cache.put(key, res)
            return res

# -----------------------------
# Фабрики и загрузка из файла
# -----------------------------

def load_static_rules(path: Union[str, Path]) -> List[StaticRule]:
    """
    Формат JSON/YAML:
      - name: "admin-all"
        effect: "permit"
        actions: ["*"]
        resources: ["*"]
        when:
          subject.roles: {in: ["admin"]}
        obligations:
          audit: true
        reason: "Admins can do everything"

    YAML поддерживается, если установлен PyYAML.
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(p)
    text = p.read_text(encoding="utf-8")
    data: Any
    if p.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except Exception as e:
            raise RuntimeError("PyYAML is required to load YAML rules") from e
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)

    rules: List[StaticRule] = []
    for item in data or []:
        rules.append(
            StaticRule(
                name=str(item["name"]),
                effect=str(item.get("effect", "deny")),
                actions=item.get("actions") or ["*"],
                resources=item.get("resources") or ["*"],
                when=item.get("when") or {},
                obligations=item.get("obligations") or {},
                advice=item.get("advice") or {},
                reason=item.get("reason") or "",
            )
        )
    return rules

# -----------------------------
# Примеры использования (докстринг)
# -----------------------------

__doc__ = """
Пример (статические правила):
    from neuroforge.adapters.policy_core_adapter import (
        Subject, Action, Resource, Environment,
        PolicyInput, StaticRule, StaticPolicyAdapter, CompositePolicyAdapter, CompositeConfig
    )

    rules = [
        StaticRule(
            name="admin-all",
            effect="permit",
            actions=["*"],
            resources=["*"],
            when={"subject.roles": {"in": ["admin"]}},
            obligations={"audit": True},
            reason="Admins can perform any action",
        ),
        StaticRule(
            name="readonly-models",
            effect="permit",
            actions=["model.read", "model.list"],
            resources=["model:*"],
            when={"subject.tier": {"in": ["free","pro"]}},
        ),
        StaticRule(
            name="deny-default",
            effect="deny",
            actions=["*"],
            resources=["*"],
            when={},
            reason="Default deny",
        ),
    ]

    static_adapter = StaticPolicyAdapter(rules, default_effect="deny")
    composite = CompositePolicyAdapter([static_adapter], CompositeConfig(strategy="first-applicable"))

    req = PolicyInput(
        subject=Subject(id="u1", attributes={"roles": ["admin"], "tier": "pro"}),
        action=Action(name="model.delete"),
        resource=Resource(id="bert-base", type="model", attributes={"owner": "u2"}),
        environment=Environment(attributes={"ip": "10.0.0.1"}),
    )
    dec = composite.evaluate(req)
    assert dec.permit

Пример (OPA):
    from neuroforge.adapters.policy_core_adapter import OpaHttpAdapter, OpaConfig
    opa = OpaHttpAdapter(OpaConfig(
        url="http://opa:8181/v1/data/neuro/policy/allow",
        timeout_sec=1.0,
        connect_retries=1,
    ))
    dec = opa.evaluate(req)  # ожидает {"result": true/false} или {"result":{"allow":true,"reason":"..."}}.
"""
