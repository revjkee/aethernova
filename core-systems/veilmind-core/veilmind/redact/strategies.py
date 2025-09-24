# -*- coding: utf-8 -*-
"""
VeilMind Core — Redaction Strategies

Промышленная реализация стратегий редактирования данных:
- MaskStrategy: маскирование с сохранением головы/хвоста
- HashStrategy: детерминированный хеш (SHA-256/512/BLAKE2) с солью/пространством имен
- RemoveStrategy: удаление значения (placeholder/null/drop)
- TokenizeStrategy: детерминированная HMAC-токенизация (псевдонимизация)
- CompositeStrategy: последовательное применение нескольких стратегий
- StrategyRegistry: фабрика стратегий по имени
- ProfileSelector: выбор стратегии по категории/синку/профилю конфигурации
- Утилиты: нормализация Unicode, ограничение кардинальности/длины, сэмплинг

ENV (совпадает с configs/redaction.yaml):
  VEILMIND_PII_SALT        — соль для хеширования (если нет в конфиге)
  VEILMIND_TOKEN_SECRET    — секрет для токенизации (если нет в конфиге)
  VEILMIND_ENV             — метка окружения для телеметрии (опционально)
  VEILMIND_REGION          — регион (опционально)

API (основное):
  apply_strategy(name, value, ctx, **params) -> (result, meta)
  select_strategy(profile_cfg, category, sink) -> callable Strategy
  limit_cardinality(labels: dict, limit: int) -> dict
  truncate_value(s: str, limit: int) -> str

Контракт Strategy.apply возвращает кортеж (value, meta), где meta — словарь
с техническими деталями (например, algo, salt_used, token_ns, removed=True и т.п.).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import random
import string
import time
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Protocol, Tuple, Union, runtime_checkable

# ------------------------------
# Контекст редактирования
# ------------------------------

@dataclass(frozen=True)
class RedactionContext:
    """
    Контекст применения стратегии.
    """
    path: str = "$"
    category: str = "pii"           # denylist|pii|sensitive|weak
    detector: Optional[str] = None  # имя детектора/правила (если есть)
    source: Optional[str] = None    # http|grpc|db|process|files
    sink: Optional[str] = None      # logs|metrics|traces|other
    profile: Optional[str] = None   # имя профиля редактирования
    timestamp_ns: int = field(default_factory=lambda: time.time_ns())


# ------------------------------
# Утилиты
# ------------------------------

def normalize_unicode(value: Any, form: str = "NFKC") -> str:
    """
    Безопасно приводит значение к нормализованной Unicode-строке.
    """
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        s = value.decode("utf-8", errors="replace")
    else:
        s = str(value)
    return unicodedata.normalize(form, s)


def truncate_value(s: str, limit: int) -> str:
    if limit <= 0:
        return ""
    if len(s) <= limit:
        return s
    return s[:limit] + "…"


def _base62(data: bytes) -> str:
    """
    Базовая base62 кодировка (URL-safe, без заглавных), для токенов.
    """
    alphabet = string.digits + string.ascii_lowercase + string.ascii_uppercase
    # Переводим байты в большое число
    n = int.from_bytes(data, "big")
    if n == 0:
        return "0"
    chars: List[str] = []
    base = len(alphabet)
    while n:
        n, rem = divmod(n, base)
        chars.append(alphabet[rem])
    return "".join(reversed(chars))


def limit_cardinality(labels: Mapping[str, str], limit: int) -> Dict[str, str]:
    """
    Ограничивает количество лейблов. Избыточные удаляются по стабильному порядку ключей.
    """
    if limit <= 0:
        return {}
    if len(labels) <= limit:
        return dict(labels)
    # стабильная выборка по сортировке ключей
    keys = sorted(labels.keys())
    keep = set(keys[:limit])
    return {k: labels[k] for k in keys if k in keep}


# ------------------------------
# Базовый протокол стратегии
# ------------------------------

@runtime_checkable
class Strategy(Protocol):
    def apply(self, value: Any, ctx: RedactionContext) -> Tuple[Any, Dict[str, Any]]:
        ...


# ------------------------------
# Реализации стратегий
# ------------------------------

@dataclass
class MaskStrategy(Strategy):
    mask_char: str = "*"
    keep_head: int = 2
    keep_tail: int = 2
    max_value_len: int = 4096
    unicode_form: str = "NFKC"

    def apply(self, value: Any, ctx: RedactionContext) -> Tuple[str, Dict[str, Any]]:
        raw = normalize_unicode(value, self.unicode_form)
        raw = truncate_value(raw, self.max_value_len)
        n = len(raw)
        if n <= self.keep_head + self.keep_tail:
            masked = self.mask_char * n
        else:
            masked = f"{raw[:self.keep_head]}{self.mask_char * (n - self.keep_head - self.keep_tail)}{raw[-self.keep_tail:]}"
        return masked, {
            "strategy": "mask",
            "mask_char": self.mask_char,
            "keep_head": self.keep_head,
            "keep_tail": self.keep_tail,
            "truncated": n > self.max_value_len,
        }


@dataclass
class HashStrategy(Strategy):
    algo: str = "sha256"                 # sha256|sha512|blake2b|blake2s
    salt_env: str = "VEILMIND_PII_SALT"
    static_salt: str = ""                # дефолтная соль (не для prod)
    namespace: str = ""                  # влияет на вывод (разные домены)
    prefix: str = ""                     # префикс перед хешем, напр. "sha256:"
    unicode_form: str = "NFKC"
    max_value_len: int = 4096

    def _digest(self, data: bytes, salt: bytes) -> str:
        if self.algo == "sha512":
            h = hashlib.sha512()
        elif self.algo == "blake2b":
            h = hashlib.blake2b(digest_size=32, person=self.namespace.encode()[:16] if self.namespace else None)
        elif self.algo == "blake2s":
            h = hashlib.blake2s(digest_size=32, person=self.namespace.encode()[:8] if self.namespace else None)
        else:
            h = hashlib.sha256()
        h.update(salt)
        h.update(data)
        return h.hexdigest()

    def apply(self, value: Any, ctx: RedactionContext) -> Tuple[str, Dict[str, Any]]:
        s = normalize_unicode(value, self.unicode_form)
        s = truncate_value(s, self.max_value_len)
        salt = os.getenv(self.salt_env) or self.static_salt or ""
        # Хешируем с добавлением namespace и пути, чтобы снижать риск коллизий
        material = f"{self.namespace}|{ctx.path}|{s}".encode("utf-8", errors="ignore")
        digest = self._digest(material, salt.encode("utf-8"))
        pref = self.prefix or f"{self.algo}:"
        return f"{pref}{digest}", {
            "strategy": "hash",
            "algo": self.algo,
            "salt_used": bool(salt),
            "namespace": self.namespace,
            "truncated": len(s) > self.max_value_len,
        }


@dataclass
class RemoveStrategy(Strategy):
    mode: str = "placeholder"            # placeholder|null|drop
    placeholder: str = "[REDACTED]"

    def apply(self, value: Any, ctx: RedactionContext) -> Tuple[Any, Dict[str, Any]]:
        if self.mode == "null":
            return None, {"strategy": "remove", "mode": "null", "removed": True}
        if self.mode == "drop":
            # Сигнал движку удалить ключ на этом path
            return "__DROP_KEY__", {"strategy": "remove", "mode": "drop", "removed": True}
        return self.placeholder, {"strategy": "remove", "mode": "placeholder", "removed": True}


@dataclass
class TokenizeStrategy(Strategy):
    """
    Детерминированная псевдонимизация: HMAC(secret, namespace|path|value) -> base62.
    Непревращаемая, но стабильная в рамках namespace+secret.
    """
    namespace: str = "vmc"
    secret_env: str = "VEILMIND_TOKEN_SECRET"
    static_secret: str = ""              # для non-prod
    length: int = 24                     # длина удерживаемой части токена
    prefix: Optional[str] = None         # итоговый префикс, по умолчанию namespace_
    unicode_form: str = "NFKC"
    max_value_len: int = 4096

    def apply(self, value: Any, ctx: RedactionContext) -> Tuple[str, Dict[str, Any]]:
        s = normalize_unicode(value, self.unicode_form)
        s = truncate_value(s, self.max_value_len)
        secret = os.getenv(self.secret_env) or self.static_secret or ""
        if not secret:
            # fallback: безопаснее вернуть маску, чем детерминизм без секрета
            masked, meta = MaskStrategy().apply(s, ctx)
            meta.update({"fallback": "mask_no_secret"})
            return masked, meta
        msg = f"{self.namespace}|{ctx.path}|{s}".encode("utf-8", errors="ignore")
        mac = hmac.new(secret.encode("utf-8"), msg=msg, digestmod=hashlib.sha256).digest()
        token = _base62(mac)[: max(8, self.length)]
        pref = (self.prefix if self.prefix is not None else f"{self.namespace}_")
        return f"{pref}{token}", {
            "strategy": "tokenize",
            "namespace": self.namespace,
            "length": self.length,
            "truncated": len(s) > self.max_value_len,
        }


@dataclass
class CompositeStrategy(Strategy):
    """
    Последовательное применение нескольких стратегий.
    Пример: сначала удалить большие тела (Remove), затем хеш (Hash) для заголовков аудита.
    """
    chain: List[Strategy] = field(default_factory=list)

    def apply(self, value: Any, ctx: RedactionContext) -> Tuple[Any, Dict[str, Any]]:
        meta: Dict[str, Any] = {"strategy": "composite", "steps": []}
        v = value
        for st in self.chain:
            v, m = st.apply(v, ctx)
            meta["steps"].append(m)
            # Если стратегия вернула маркер удаления — прекращаем
            if v == "__DROP_KEY__":
                break
        return v, meta


# ------------------------------
# Реестр и фабрика стратегий
# ------------------------------

class StrategyRegistry:
    """
    Регистратор стратегий по имени. Позволяет создавать экземпляры с параметрами.
    """
    def __init__(self) -> None:
        self._creators: Dict[str, Any] = {}
        self.register("mask", lambda **kw: MaskStrategy(**kw))
        self.register("hash", lambda **kw: HashStrategy(**kw))
        self.register("remove", lambda **kw: RemoveStrategy(**kw))
        self.register("tokenize", lambda **kw: TokenizeStrategy(**kw))
        self.register("composite", self._make_composite)

    def register(self, name: str, factory) -> None:
        self._creators[name] = factory

    def create(self, name: str, **params) -> Strategy:
        if name not in self._creators:
            raise ValueError(f"Unknown strategy: {name}")
        return self._creators[name](**params)

    def _make_composite(self, **params) -> Strategy:
        chain_cfg = params.get("chain") or []
        chain: List[Strategy] = []
        for item in chain_cfg:
            if not isinstance(item, Mapping):
                raise ValueError("Composite.chain items must be mappings like {'name': 'mask', 'params': {...}}")
            name = str(item.get("name"))
            p = dict(item.get("params") or {})
            chain.append(self.create(name, **p))
        return CompositeStrategy(chain=chain)


REGISTRY = StrategyRegistry()


def apply_strategy(name: str, value: Any, ctx: RedactionContext, **params) -> Tuple[Any, Dict[str, Any]]:
    """
    Упрощенный вызов: создать стратегию по имени и применить к значению.
    """
    st = REGISTRY.create(name, **params)
    return st.apply(value, ctx)


# ------------------------------
# Селектор профилей (sinks/categories)
# ------------------------------

@dataclass
class RedactionProfile:
    """
    Описывает предпочтения стратегий для категорий/синков.

    Пример конфигурации (в терминах configs/redaction.yaml -> redaction_integration.profiles.*):
      sinks: { logs: "mask", traces: "hash", metrics: "hash" }
      pii: "hash"
      sensitive: "mask"
      denylist: "remove"
      weak: "mask"
      params:
        hash: { algo: "sha256", namespace: "vmc" }
        mask: { keep_head: 2, keep_tail: 2, mask_char: "*" }
        remove: { mode: "placeholder" }
        tokenize: { namespace: "vmc" }
    """
    sinks: Mapping[str, str] = field(default_factory=dict)    # logs|metrics|traces -> strategy name
    categories: Mapping[str, str] = field(default_factory=dict)  # pii|sensitive|denylist|weak -> strategy
    params: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)  # per-strategy params
    default_strategy: str = "mask"

    def select(self, category: str, sink: Optional[str]) -> Strategy:
        # Сначала переопределение на уровне sink
        if sink and sink in self.sinks:
            name = self.sinks[sink]
            return REGISTRY.create(name, **dict(self.params.get(name, {})))
        # Затем — по категории
        name = self.categories.get(category, self.default_strategy)
        return REGISTRY.create(name, **dict(self.params.get(name, {})))


def select_strategy(profile_cfg: Mapping[str, Any], category: str, sink: Optional[str]) -> Strategy:
    """
    Быстрый помощник для получения стратегии из "сырой" конфигурации профиля.
    """
    sinks = dict((profile_cfg.get("sinks") or {}))
    cats = {}
    for k in ("pii", "sensitive", "denylist", "weak"):
        v = profile_cfg.get(k)
        if isinstance(v, str) and v:
            cats[k] = v
    params = dict(profile_cfg.get("params") or {})
    profile = RedactionProfile(sinks=sinks, categories=cats, params=params, default_strategy=profile_cfg.get("default", "mask"))
    return profile.select(category, sink)


# ------------------------------
# Постобработка: кардинальность/семплинг
# ------------------------------

def enforce_limits(
    value: Any,
    *,
    cardinality_labels: Optional[Mapping[str, str]] = None,
    label_limit: Optional[int] = None,
    value_limit: Optional[int] = None,
) -> Tuple[Any, Dict[str, Any]]:
    """
    Применяет ограничения: лимит меток и длины значения (к строкам).
    """
    meta: Dict[str, Any] = {}
    if isinstance(value, str) and value_limit:
        before = len(value)
        value = truncate_value(value, value_limit)
        meta["value_truncated"] = before > len(value)
    if cardinality_labels is not None and label_limit is not None:
        kept = limit_cardinality(cardinality_labels, label_limit)
        meta["labels_kept"] = len(kept)
        meta["labels_dropped"] = max(0, len(cardinality_labels) - len(kept))
    return value, meta


def should_sample(enabled: bool, rate: float) -> bool:
    """
    Возвращает True, если событие следует ОБРАБОТАТЬ (не отбросить).
    """
    if not enabled:
        return True
    rate = max(0.0, min(1.0, rate))
    if rate >= 1.0:
        return True
    return random.random() < rate


# ------------------------------
# Пример использования (док‑комментарий)
# ------------------------------
"""
# Пример: выбрать стратегию по профилю и применить
profile_cfg = {
    "sinks": {"logs": "mask", "traces": "hash", "metrics": "hash"},
    "pii": "hash",
    "sensitive": "mask",
    "denylist": "remove",
    "params": {
        "hash": {"algo": "sha256", "namespace": "vmc"},
        "mask": {"keep_head": 2, "keep_tail": 2, "mask_char": "*"},
        "remove": {"mode": "placeholder"},
    },
}
ctx = RedactionContext(path="$.headers.authorization", category="denylist", source="http", sink="logs", profile="hash_low_cardinality")
st = select_strategy(profile_cfg, category=ctx.category, sink=ctx.sink)
result, meta = st.apply("Bearer eyJhbGc...", ctx)
# result -> "[REDACTED]" ; meta -> {"strategy": "remove", ...}
"""
