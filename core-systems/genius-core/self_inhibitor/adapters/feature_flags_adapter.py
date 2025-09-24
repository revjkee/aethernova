# -*- coding: utf-8 -*-
"""
Genius Core — Feature Flags Adapter (Self-Inhibitor)
---------------------------------------------------
Назначение:
  Единый слой работы с фичефлагами для модулей безопасности (self-inhibitor):
    - Мульти-провайдер: InMemory, Env, File(JSON/YAML), HTTP(ETag) + Chain.
    - Потокобезопасный кэш с TTL, фоновой подгрузкой (необязательно).
    - Валидируемая модель флага, сложные условия (all/any/not), проценты раскатки,
      детерминированный выбор варианта, приоритеты правил (first-match-wins).
    - Нулевые внешние зависимости (yaml — опционально).

Ключевые методы:
  - is_enabled(key, ctx, default=False, explain=False)
  - get_variant(key, ctx, default="control", explain=False)
  - get_value(key, ctx, default=None, type_hint=("bool"|"int"|"float"|"str"|"json"), explain=False)

Контекст:
  Любой dict-подобный объект, обычно:
    {
      "env": "prod|staging|dev",
      "tenant": "t-123",
      "user": "u-42",
      "rpc": "/omni.Chat/Complete",
      "method": "POST",
      "country": "SE",
      ...произвольные атрибуты...
    }

Интеграция (пример):
    adapter = FeatureFlagsAdapter.from_env(
        default_env=os.getenv("OMNI_ENV", "dev"),
        file_path=os.getenv("FF_FILE", "/etc/genius/flags.yaml"),
        http_url=os.getenv("FF_URL"),
        http_ttl=30,
        chain_order=("env", "file", "http")  # приоритет слева направо
    )

    if adapter.is_enabled("self_inhibitor.pii", {"env": "prod", "tenant": "acme"}):
        ...

Структура флага (JSON/YAML):
  key: "self_inhibitor.pii"
  type: "bool" | "int" | "float" | "str" | "json" | "variant"
  enabled: true
  default: true      # значение по умолчанию/вариант (для type=variant -> строка)
  variants:          # для type=variant — веса
    control: 50
    treatment: 50
  rules:             # first-match-wins
    - when:
        all:
          - { attr: "env", op: "in", values: ["prod", "staging"] }
          - { attr: "tenant", op: "not_in", values: ["blocked-co"] }
      rollout: 100               # 0..100 (проценты)
      salt: "pii-2025"           # опционно; влияет на хэш
      seed: "user"               # атрибут контекста для детерминированности (например "user"|"tenant")
      value: true                # переопределение default для bool/int/float/str/json
      variant_overrides:         # переопределение весов (для type=variant)
        control: 20
        treatment: 80

Безопасность:
  - Никаких eval; только явные операторы.
  - Запросы HTTP читаются через urllib, с таймаутами и If-None-Match.
  - Валидация и игнорирование некорректных флагов с логированием.

Лицензия: внутренняя.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

# ---------- опциональный YAML ----------
try:
    import yaml  # type: ignore
    _HAS_YAML = True
except Exception:
    _HAS_YAML = False

# ---------- логгер ----------
_log = logging.getLogger("genius.feature_flags")
if not _log.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(message)s"))
    _log.addHandler(_h)
_log.setLevel(getattr(logging, os.getenv("GENIUS_FLAGS_LOG_LEVEL", "INFO").upper(), logging.INFO))


# ============================================================
# Модель флага и условия
# ============================================================

@dataclass
class Condition:
    attr: Optional[str] = None
    op: Optional[str] = None
    value: Any = None
    values: Optional[List[Any]] = None
    regex: Optional[str] = None

@dataclass
class Rule:
    when: Dict[str, Any] = field(default_factory=dict)  # {"all":[Condition...]} | {"any":[...]} | {"not": {...}}
    rollout: int = 100
    salt: Optional[str] = None
    seed: Optional[str] = None  # имя атрибута контекста ("user"/"tenant"/...)
    value: Any = None           # для простых типов
    variant_overrides: Optional[Dict[str, int]] = None  # для type=variant

@dataclass
class FeatureFlag:
    key: str
    type: str = "bool"  # "bool"|"int"|"float"|"str"|"json"|"variant"
    enabled: bool = True
    default: Any = None
    variants: Optional[Dict[str, int]] = None
    rules: List[Rule] = field(default_factory=list)
    description: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    updated_at: Optional[float] = None


# ============================================================
# Утилиты
# ============================================================

def _now() -> float:
    return time.time()

def _get(ctx: Mapping[str, Any], key: str, default: Any = None) -> Any:
    return ctx.get(key, default) if isinstance(ctx, Mapping) else default

def _to_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default

def _to_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except Exception:
        return default

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _percent_from_hash(s: str) -> float:
    # Первые 15 шестнадцатеричных символов -> int -> [0, 100)
    h = _sha256_hex(s)[:15]
    n = int(h, 16)
    return (n / float(0xFFFFFFFFFFFFFFF)) * 100.0

def _stable_bucket(seed_val: str, key: str, salt: Optional[str] = None) -> float:
    salt = salt or ""
    return _percent_from_hash(f"{key}:{salt}:{seed_val}")

def _weighted_choice(seed_val: str, key: str, weights: Mapping[str, int], salt: Optional[str] = None) -> str:
    total = max(1, sum(max(0, int(w)) for w in weights.values()))
    p = _stable_bucket(seed_val, key, salt) * total / 100.0
    acc = 0.0
    for variant, w in sorted(weights.items()):
        acc += max(0, int(w))
        if p < acc:
            return variant
    # fallback — последний
    return next(reversed(sorted(weights.keys())))

def _match_condition(cond: Mapping[str, Any], ctx: Mapping[str, Any]) -> bool:
    # Поддерживаемые операторы: eq, ne, in, not_in, contains, starts_with, ends_with, match, not_match, gt, gte, lt, lte, exists
    attr = cond.get("attr")
    op = (cond.get("op") or "").lower()
    val = cond.get("value")
    values = cond.get("values")
    rx = cond.get("regex")

    cval = _get(ctx, attr) if attr else None

    if op == "exists":
        return cval is not None

    if op in ("eq", "ne", "gt", "gte", "lt", "lte"):
        left = cval
        right = val
        if op == "eq":  return left == right
        if op == "ne":  return left != right
        try:
            if isinstance(left, (int, float)) and isinstance(right, (int, float)):
                if op == "gt":  return left > right
                if op == "gte": return left >= right
                if op == "lt":  return left < right
                if op == "lte": return left <= right
        except Exception:
            return False
        return False

    if op == "in":
        return cval in (values or [])
    if op == "not_in":
        return cval not in (values or [])
    if op == "contains":
        return isinstance(cval, (list, tuple, set, str)) and (val in cval)
    if op == "starts_with":
        return isinstance(cval, str) and isinstance(val, str) and cval.startswith(val)
    if op == "ends_with":
        return isinstance(cval, str) and isinstance(val, str) and cval.endswith(val)
    if op == "match":
        try:
            return re.search(rx or val or "", str(cval) if cval is not None else "") is not None
        except re.error:
            return False
    if op == "not_match":
        try:
            return re.search(rx or val or "", str(cval) if cval is not None else "") is None
        except re.error:
            return True

    return False

def _match_when(when: Mapping[str, Any], ctx: Mapping[str, Any]) -> bool:
    if not when:
        return True
    if "all" in when:
        return all(_match_condition(c, ctx) for c in when.get("all", []))
    if "any" in when:
        lst = when.get("any", [])
        return any(_match_condition(c, ctx) for c in lst) if lst else False
    if "not" in when:
        return not _match_when(when.get("not", {}), ctx)
    return False


# ============================================================
# Провайдеры флагов
# ============================================================

class BaseProvider:
    """Базовый протокол провайдера."""
    def get(self, key: str) -> Optional[FeatureFlag]:
        raise NotImplementedError
    def all(self) -> Dict[str, FeatureFlag]:
        raise NotImplementedError
    def last_update(self) -> float:
        return 0.0

class InMemoryProvider(BaseProvider):
    def __init__(self, flags: Dict[str, FeatureFlag]):
        self._flags = dict(flags)
        self._ts = _now()
    def get(self, key: str) -> Optional[FeatureFlag]:
        return self._flags.get(key)
    def all(self) -> Dict[str, FeatureFlag]:
        return dict(self._flags)
    def last_update(self) -> float:
        return self._ts

class EnvProvider(BaseProvider):
    """
    Чтение простых флагов из окружения.
    Форматы:
      FF_BOOL_self_inhibitor_pii=true
      FF_INT_limit=10
      FF_FLOAT_threshold=0.75
      FF_STR_mode=treatment
      FF_JSON_complex={"a":1}
    Приоритет ниже InMemory, но выше File/HTTP — зависит от порядка в ChainProvider.
    """
    def __init__(self, prefix: str = "FF_"):
        self.prefix = prefix
        self._cache: Dict[str, FeatureFlag] = {}
        self._ts = _now()
        self._load()

    def _norm_key(self, raw: str) -> str:
        # FF_BOOL_self_inhibitor_pii -> self_inhibitor.pii
        k = raw.split("_", 2)[-1]
        return k.replace("__", ".").replace("_", ".")

    def _load(self) -> None:
        for k, v in os.environ.items():
            if not k.startswith(self.prefix):
                continue
            if k.startswith(self.prefix + "BOOL_"):
                key = self._norm_key(k[len(self.prefix + "BOOL_"):])
                self._cache[key] = FeatureFlag(key=key, type="bool", enabled=True, default=str(v).lower() in ("1", "true", "yes"))
            elif k.startswith(self.prefix + "INT_"):
                key = self._norm_key(k[len(self.prefix + "INT_"):])
                self._cache[key] = FeatureFlag(key=key, type="int", enabled=True, default=_to_int(v))
            elif k.startswith(self.prefix + "FLOAT_"):
                key = self._norm_key(k[len(self.prefix + "FLOAT_"):])
                self._cache[key] = FeatureFlag(key=key, type="float", enabled=True, default=_to_float(v))
            elif k.startswith(self.prefix + "STR_"):
                key = self._norm_key(k[len(self.prefix + "STR_"):])
                self._cache[key] = FeatureFlag(key=key, type="str", enabled=True, default=str(v))
            elif k.startswith(self.prefix + "JSON_"):
                key = self._norm_key(k[len(self.prefix + "JSON_"):])
                try:
                    self._cache[key] = FeatureFlag(key=key, type="json", enabled=True, default=json.loads(v))
                except Exception:
                    _log.warning(f"EnvProvider: invalid JSON for {k}")
        self._ts = _now()

    def get(self, key: str) -> Optional[FeatureFlag]:
        return self._cache.get(key)

    def all(self) -> Dict[str, FeatureFlag]:
        return dict(self._cache)

    def last_update(self) -> float:
        return self._ts

class FileProvider(BaseProvider):
    """
    Поддерживает JSON/YAML. Авто-релод при TTL.
    """
    def __init__(self, path: str, ttl: int = 15):
        self.path = path
        self.ttl = max(1, int(ttl))
        self._cache: Dict[str, FeatureFlag] = {}
        self._ts = 0.0
        self._lock = threading.Lock()
        self._mtime = 0.0
        self._refresh(force=True)

    def _parse_flags(self, data: Any) -> Dict[str, FeatureFlag]:
        out: Dict[str, FeatureFlag] = {}
        if isinstance(data, Mapping):
            items = data.get("flags") if "flags" in data else data
        else:
            items = data
        if not isinstance(items, Mapping):
            return out

        for key, entry in items.items():
            try:
                f = self._to_flag(key, entry)
                out[f.key] = f
            except Exception as e:
                _log.warning(f"FileProvider: skip invalid flag {key}: {e}")
        return out

    def _to_flag(self, key: str, entry: Mapping[str, Any]) -> FeatureFlag:
        ftype = str(entry.get("type", "bool")).lower()
        flag = FeatureFlag(
            key=key,
            type=ftype,
            enabled=bool(entry.get("enabled", True)),
            default=entry.get("default"),
            description=entry.get("description"),
            tags=list(entry.get("tags", []) or []),
            updated_at=_now(),
        )
        if ftype == "variant":
            variants = entry.get("variants") or {}
            if not isinstance(variants, Mapping) or not variants:
                raise ValueError("variant flag requires non-empty 'variants'")
            flag.variants = {str(k): int(v) for k, v in variants.items()}
        rules = []
        for r in entry.get("rules", []) or []:
            rules.append(Rule(
                when=r.get("when") or {},
                rollout=int(r.get("rollout", 100)),
                salt=r.get("salt"),
                seed=r.get("seed"),
                value=r.get("value"),
                variant_overrides=(r.get("variant_overrides") or None),
            ))
        flag.rules = rules
        return flag

    def _load_file(self) -> Optional[Dict[str, FeatureFlag]]:
        if not os.path.isfile(self.path):
            return {}
        with open(self.path, "rb") as f:
            content = f.read()
        # Определяем формат
        text = content.decode("utf-8", errors="replace")
        if self.path.endswith((".yml", ".yaml")) and _HAS_YAML:
            data = yaml.safe_load(text)
        else:
            data = json.loads(text)
        return self._parse_flags(data)

    def _refresh(self, force: bool = False) -> None:
        with self._lock:
            if not force and (_now() - self._ts) < self.ttl:
                return
            try:
                mtime = os.path.getmtime(self.path) if os.path.exists(self.path) else 0.0
            except Exception:
                mtime = 0.0
            if not force and mtime == self._mtime:
                self._ts = _now()
                return
            new_flags = self._load_file() or {}
            self._cache = new_flags
            self._mtime = mtime
            self._ts = _now()

    def get(self, key: str) -> Optional[FeatureFlag]:
        self._refresh()
        return self._cache.get(key)

    def all(self) -> Dict[str, FeatureFlag]:
        self._refresh()
        return dict(self._cache)

    def last_update(self) -> float:
        return self._ts

class HttpProvider(BaseProvider):
    """
    Чтение флагов по HTTP(S) JSON/YAML с поддержкой ETag и TTL.
    Формат ответа: как у FileProvider, либо { "flags": { ... } }.
    """
    def __init__(self, url: str, ttl: int = 30, timeout: int = 5):
        import urllib.request  # локальный импорт
        self._urllib = urllib.request
        self.url = url
        self.ttl = max(1, int(ttl))
        self.timeout = max(1, int(timeout))
        self._cache: Dict[str, FeatureFlag] = {}
        self._ts = 0.0
        self._lock = threading.Lock()
        self._etag: Optional[str] = None
        self._refresh(force=True)

    def _fetch(self) -> Optional[bytes]:
        req = self._urllib.Request(self.url)
        if self._etag:
            req.add_header("If-None-Match", self._etag)
        try:
            with self._urllib.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 304:
                    return None
                etag = resp.headers.get("ETag")
                if etag:
                    self._etag = etag
                return resp.read()
        except Exception as e:
            _log.warning(f"HttpProvider: fetch error: {e}")
            return None

    def _parse(self, body: bytes) -> Dict[str, FeatureFlag]:
        text = body.decode("utf-8", errors="replace")
        try:
            data = json.loads(text)
        except Exception:
            if _HAS_YAML:
                data = yaml.safe_load(text)
            else:
                raise
        # такой же формат, как у FileProvider
        fp = FileProvider(path=":http:", ttl=self.ttl)  # используем парсер
        return fp._parse_flags(data)

    def _refresh(self, force: bool = False) -> None:
        with self._lock:
            if not force and (_now() - self._ts) < self.ttl:
                return
            body = self._fetch()
            if body is None:
                # 304 или ошибка — просто продлеваем TTL
                self._ts = _now()
                return
            try:
                self._cache = self._parse(body)
            except Exception as e:
                _log.warning(f"HttpProvider: parse error: {e}")
            self._ts = _now()

    def get(self, key: str) -> Optional[FeatureFlag]:
        self._refresh()
        return self._cache.get(key)

    def all(self) -> Dict[str, FeatureFlag]:
        self._refresh()
        return dict(self._cache)

    def last_update(self) -> float:
        return self._ts

class ChainProvider(BaseProvider):
    """
    Объединяет несколько провайдеров по приоритету.
    При конфликте ключей действует правило: первый провайдер имеет приоритет.
    """
    def __init__(self, providers: Sequence[BaseProvider]):
        self.providers = list(providers)

    def get(self, key: str) -> Optional[FeatureFlag]:
        for p in self.providers:
            f = p.get(key)
            if f is not None:
                return f
        return None

    def all(self) -> Dict[str, FeatureFlag]:
        out: Dict[str, FeatureFlag] = {}
        for p in self.providers:
            for k, v in p.all().items():
                if k not in out:
                    out[k] = v
        return out

    def last_update(self) -> float:
        return max((p.last_update() for p in self.providers), default=0.0)


# ============================================================
# Адаптер и движок оценки
# ============================================================

@dataclass
class EvalResult:
    key: str
    matched_rule_index: Optional[int]
    rollout_passed: bool
    chosen_variant: Optional[str]
    value: Any
    source: str
    reason: Optional[str] = None

class FeatureFlagsAdapter:
    """
    Высокоуровневый фасад.
    """
    def __init__(self, provider: BaseProvider, default_env: str = "dev"):
        self.provider = provider
        self.default_env = default_env
        self._lock = threading.RLock()
        self._cache_ts = 0.0
        self._cache: Dict[str, FeatureFlag] = {}

    # ---------- фабрики ----------
    @staticmethod
    def from_env(
        default_env: str = "dev",
        file_path: Optional[str] = None,
        http_url: Optional[str] = None,
        http_ttl: int = 30,
        chain_order: Sequence[str] = ("env", "file", "http"),
    ) -> "FeatureFlagsAdapter":
        provs: Dict[str, BaseProvider] = {}
        provs["env"] = EnvProvider()
        if file_path:
            provs["file"] = FileProvider(file_path, ttl=15)
        if http_url:
            provs["http"] = HttpProvider(http_url, ttl=int(http_ttl))
        chain: List[BaseProvider] = []
        for name in chain_order:
            if name in provs:
                chain.append(provs[name])
        provider = chain[0] if len(chain) == 1 else ChainProvider(chain)
        return FeatureFlagsAdapter(provider=provider, default_env=default_env)

    # ---------- публичные методы ----------
    def is_enabled(self, key: str, ctx: Mapping[str, Any], default: bool = False, explain: bool = False) -> Union[bool, Tuple[bool, EvalResult]]:
        flag = self._get_flag(key)
        if not flag:
            return (default, self._notfound_result(key, default)) if explain else default
        if flag.type not in ("bool", "variant", "json", "int", "float", "str"):
            return (default, self._badtype_result(key, default)) if explain else default
        res = self._evaluate(flag, ctx)
        # Для variant считаем enabled если вариант не "off" и флаг включен
        if flag.type == "variant":
            enabled = bool(flag.enabled and res.chosen_variant and res.chosen_variant != "off")
        else:
            val = res.value if res.value is not None else flag.default
            enabled = bool(flag.enabled and (val if isinstance(val, bool) else bool(val)))
        return (enabled, res) if explain else enabled

    def get_variant(self, key: str, ctx: Mapping[str, Any], default: str = "control", explain: bool = False) -> Union[str, Tuple[str, EvalResult]]:
        flag = self._get_flag(key)
        if not flag or flag.type != "variant":
            res = self._notfound_result(key, default) if not flag else self._badtype_result(key, default)
            return (default, res) if explain else default
        res = self._evaluate(flag, ctx)
        variant = res.chosen_variant or (flag.default if isinstance(flag.default, str) else default) or default
        return (variant, res) if explain else variant

    def get_value(self, key: str, ctx: Mapping[str, Any], default: Any = None, type_hint: Optional[str] = None, explain: bool = False) -> Union[Any, Tuple[Any, EvalResult]]:
        flag = self._get_flag(key)
        if not flag:
            return (default, self._notfound_result(key, default)) if explain else default
        if type_hint and flag.type != type_hint:
            return (default, self._badtype_result(key, default)) if explain else default
        res = self._evaluate(flag, ctx)
        val = res.value if res.value is not None else flag.default
        # приведение типов
        if flag.type == "int":
            val = _to_int(val, _to_int(default, 0))
        elif flag.type == "float":
            val = _to_float(val, _to_float(default, 0.0))
        elif flag.type == "bool":
            val = bool(val)
        elif flag.type == "json":
            # допускаем str JSON в провайдерах
            if isinstance(val, str):
                try:
                    val = json.loads(val)
                except Exception:
                    pass
        elif flag.type == "str":
            val = str(val)
        return (val, res) if explain else val

    # ---------- внутренняя логика ----------
    def _get_flag(self, key: str) -> Optional[FeatureFlag]:
        # Прямой доступ к провайдеру (кэширование на уровне провайдера).
        return self.provider.get(key)

    def _evaluate(self, flag: FeatureFlag, ctx: Mapping[str, Any]) -> EvalResult:
        # Обогащаем контекст умолчаниями
        if "env" not in ctx:
            ctx = dict(ctx)
            ctx["env"] = self.default_env

        if not flag.enabled:
            return EvalResult(flag.key, None, False, None, flag.default, source="disabled")

        # Правила в порядке объявления: first-match-wins
        for idx, rule in enumerate(flag.rules):
            if not _match_when(rule.when or {}, ctx):
                continue

            # Если указан rollout < 100 — проверяем детерминированное прохождение
            passed = True
            chosen_variant: Optional[str] = None
            if rule.rollout < 100:
                seed_attr = rule.seed or "user"
                seed_val = str(_get(ctx, seed_attr) or _get(ctx, "tenant") or "global")
                percent = _stable_bucket(seed_val, flag.key, rule.salt)
                passed = percent < float(max(0, min(100, rule.rollout)))

            if not passed:
                continue

            # Для variant: считаем выбранный вариант
            if flag.type == "variant":
                weights = dict(flag.variants or {})
                if rule.variant_overrides:
                    weights.update({str(k): int(v) for k, v in rule.variant_overrides.items()})
                seed_attr = rule.seed or "user"
                seed_val = str(_get(ctx, seed_attr) or _get(ctx, "tenant") or "global")
                chosen_variant = _weighted_choice(seed_val, flag.key, weights, rule.salt)
                return EvalResult(flag.key, idx, True, chosen_variant, None, source="rule:variant")

            # Иначе — возврат значения (rule.value, если есть, иначе default)
            value = rule.value if (rule.value is not None) else flag.default
            return EvalResult(flag.key, idx, True, None, value, source="rule:value")

        # Если правил нет/не подошли — для variant используем default вариант, иначе default value
        if flag.type == "variant":
            variant = flag.default if isinstance(flag.default, str) else None
            return EvalResult(flag.key, None, True, variant, None, source="default:variant")
        return EvalResult(flag.key, None, True, None, flag.default, source="default:value")

    # ---------- вспомогательные результаты ----------
    def _notfound_result(self, key: str, default: Any) -> EvalResult:
        return EvalResult(key, None, False, None, default, source="not_found", reason="flag_not_found")
    def _badtype_result(self, key: str, default: Any) -> EvalResult:
        return EvalResult(key, None, False, None, default, source="bad_type", reason="type_mismatch")


# ============================================================
# Специализация для self-inhibitor (удобные шорткаты)
# ============================================================

class SecurityFlags:
    """
    Обёртка-шорткаты для ключевых флагов self-inhibitor.
    Имена ключей совпадают с рекомендациями в правилах/политиках.
    """
    def __init__(self, adapter: FeatureFlagsAdapter):
        self.ff = adapter

    # Включение детекторов
    def pii(self, ctx: Mapping[str, Any]) -> bool:
        return self.ff.is_enabled("self_inhibitor.pii", ctx, default=True)
    def secrets(self, ctx: Mapping[str, Any]) -> bool:
        return self.ff.is_enabled("self_inhibitor.secrets", ctx, default=True)
    def injection(self, ctx: Mapping[str, Any]) -> bool:
        return self.ff.is_enabled("self_inhibitor.injection", ctx, default=True)
    def dangerous_cmds(self, ctx: Mapping[str, Any]) -> bool:
        return self.ff.is_enabled("self_inhibitor.dangerous_cmds", ctx, default=True)
    def output_scan(self, ctx: Mapping[str, Any]) -> bool:
        return self.ff.is_enabled("self_inhibitor.output_scan", ctx, default=True)

    # Режим редактирования (санитизации)
    def redaction_mode(self, ctx: Mapping[str, Any]) -> str:
        return self.ff.get_variant("self_inhibitor.redaction_mode", ctx, default="sanitize")

    # Порог чувствительности (пример числового значения)
    def sensitivity(self, ctx: Mapping[str, Any]) -> float:
        return float(self.ff.get_value("self_inhibitor.sensitivity", ctx, default=0.5, type_hint="float"))


# ============================================================
# Пример локального запуска/демо
# ============================================================

if __name__ == "__main__":
    # Пример: InMemory + File
    flags_data = {
        "self_inhibitor.pii": FeatureFlag(key="self_inhibitor.pii", type="bool", enabled=True, default=True, rules=[
            Rule(when={"all":[{"attr":"env","op":"in","values":["prod","staging"]}]}, rollout=100),
            Rule(when={"any":[{"attr":"tenant","op":"in","values":["beta"]}]}, rollout=50, salt="r1", seed="user", value=True),
        ]),
        "self_inhibitor.redaction_mode": FeatureFlag(
            key="self_inhibitor.redaction_mode", type="variant", enabled=True, default="sanitize",
            variants={"sanitize": 70, "passthrough": 30},
            rules=[
                Rule(when={"all":[{"attr":"env","op":"eq","value":"dev"}]}, rollout=100, variant_overrides={"sanitize": 30, "passthrough": 70})
            ]
        ),
        "self_inhibitor.sensitivity": FeatureFlag(
            key="self_inhibitor.sensitivity", type="float", enabled=True, default=0.6,
            rules=[Rule(when={"all":[{"attr":"tenant","op":"eq","value":"highrisk"}]}, rollout=100, value=0.8)]
        ),
    }
    adapter = FeatureFlagsAdapter(
        provider=ChainProvider([InMemoryProvider(flags_data), EnvProvider()]),
        default_env=os.getenv("OMNI_ENV", "dev"),
    )
    ctx = {"env": os.getenv("OMNI_ENV", "dev"), "tenant": "acme", "user": "u1", "rpc": "/omni.Chat/Complete"}

    enabled, explain = adapter.is_enabled("self_inhibitor.pii", ctx, explain=True)
    print(json.dumps(dataclasses.asdict(explain), indent=2))
    print("pii enabled:", enabled)
    print("mode:", adapter.get_variant("self_inhibitor.redaction_mode", ctx))
    print("sensitivity:", adapter.get_value("self_inhibitor.sensitivity", ctx, type_hint="float"))
