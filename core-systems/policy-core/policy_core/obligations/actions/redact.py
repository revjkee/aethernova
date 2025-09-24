# -*- coding: utf-8 -*-
"""
policy-core / policy_core / obligations / actions / redact.py

Промышленный модуль обязательств (Obligations) для редакции (redact) данных.
Назначение:
  - Применение обязательств политики к полезной нагрузке ответа/событиям для удаления/маскирования чувствительных данных.
  - Поддержка путевых селекторов (JSON Pointer RFC6901, dot-path, glob-пути с * и [*]).
  - Многостратегийная редакция: mask, remove, replace, hash, tokenize (HMAC), pseudonymize, text-regex.
  - Детекторы PII для строк: email, phone, credit-card (PAN), IBAN, custom regex.
  - Детерминированный токенайзинг через HMAC-SHA256 (идемпотентность).
  - Частичная маскировка (keep_prefix/keep_suffix/keep_last4), сохранение длины, символ маски.
  - Стримовая редакция текста/байтов (построчно).
  - Журналирование событий редакции и безопасные лимиты (max_depth, max_nodes, max_output_bytes).

Внешних зависимостей нет. Совместим с Python 3.10+.

Интеграция:
  - Используйте Redactor.apply_to_obj(...) для редактирования JSON-сериализуемых структур.
  - Используйте Redactor.redact_text(...) / redact_bytes_lines(...) для логов/стримов.
  - Функция apply_obligation(...) — универсальная точка входа из двигателя обязательств.

Авторизация/политики:
  - Предполагается, что PDP выдает список obligations для PEP; для типа "redact" сюда передается конфигурация.

© Aethernova / policy-core
"""

from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import hashlib
import hmac
import io
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Literal, Optional, Tuple, Union, Callable

Json = Union[Dict[str, Any], List[Any], str, int, float, bool, None]

# ----------------------------- Константы и ограничения -----------------------------

DEFAULT_MASK_CHAR = "*"
DEFAULT_TOKEN_PREFIX = "TKN_"
DEFAULT_HASH_PREFIX = "H_"
MAX_DEPTH_DEFAULT = 40
MAX_NODES_DEFAULT = 100_000
MAX_OUTPUT_BYTES_DEFAULT = 10 * 1024 * 1024  # 10 MiB

# Базовые PII/фин. паттерны (консервативно, без агрессивной генерализации)
RE_EMAIL = re.compile(r"(?i)\b([A-Z0-9._%+-]+)@([A-Z0-9.-]+\.[A-Z]{2,})\b")
RE_PHONE = re.compile(r"(?<!\d)(?:\+?\d{1,3}[-\s.]*)?(?:\(?\d{2,4}\)?[-\s.]*)?\d{3}[-\s.]*\d{2,4}(?:[-\s.]*\d{2,4})?(?!\d)")
RE_CC = re.compile(r"(?<!\d)(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})(?!\d)")
RE_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
# Замечание: эти регэкспы предназначены для маскировки, а не валидации.

# ----------------------------- Исключения и события --------------------------------

class RedactionError(Exception):
    pass


@dataclass
class RedactionEvent:
    ts: str
    policy_id: Optional[str]
    obligation_id: Optional[str]
    selector: Optional[str]
    action: str
    reason: Optional[str]
    path: Optional[str]
    old_preview: Optional[str]
    new_preview: Optional[str]


# ----------------------------- Конфигурация редакции -------------------------------

RedactStrategy = Literal["mask", "remove", "replace", "hash", "tokenize", "pseudonymize", "text-regex"]

SelectorType = Literal["pointer", "dot", "glob"]

@dataclass
class StrategyConfig:
    strategy: RedactStrategy = "mask"
    mask_char: str = DEFAULT_MASK_CHAR
    keep_prefix: int = 0
    keep_suffix: int = 0
    keep_last4: bool = False
    preserve_length: bool = True
    replace_with: Optional[Any] = None  # для strategy=replace
    hash_prefix: str = DEFAULT_HASH_PREFIX
    token_prefix: str = DEFAULT_TOKEN_PREFIX
    token_namespace: Optional[str] = None  # для разделения пространств токенов
    secret_b64: Optional[str] = None  # HMAC-ключ в base64 для hash/tokenize
    # Псевдонимизация простых типов (email/phone/cc) — сохраняем формат
    pseudonymize_kind: Optional[Literal["email", "phone", "cc"]] = None
    # Для text-regex
    text_patterns: List[str] = field(default_factory=list)  # список regex-строк
    text_flags: int = re.IGNORECASE

@dataclass
class Selector:
    type: SelectorType
    value: str  # "/a/b", "a.b.c", "a.*.b", "users[*].email"
    # Если указано, то редактируем только ключи, совпадающие с regex на последнем сегменте
    last_key_regex: Optional[str] = None

@dataclass
class Detector:
    email: bool = True
    phone: bool = True
    cc: bool = True
    iban: bool = False
    custom_patterns: List[str] = field(default_factory=list)
    custom_flags: int = re.IGNORECASE

@dataclass
class RedactConfig:
    selectors: List[Selector] = field(default_factory=list)
    strategy: StrategyConfig = field(default_factory=StrategyConfig)
    detectors: Detector = field(default_factory=Detector)
    max_depth: int = MAX_DEPTH_DEFAULT
    max_nodes: int = MAX_NODES_DEFAULT
    max_output_bytes: int = MAX_OUTPUT_BYTES_DEFAULT
    # Поведение при отсутствии совпадений: "ok" или "error"
    on_no_match: Literal["ok", "error"] = "ok"


@dataclass
class RedactionContext:
    policy_id: Optional[str] = None
    obligation_id: Optional[str] = None
    actor: Optional[str] = None
    reason: Optional[str] = None
    correlation_id: Optional[str] = None


# ----------------------------- Вспомогательные функции -----------------------------

def _now_iso() -> str:
    return dt.datetime.utcnow().isoformat(timespec="milliseconds") + "Z"


def _b64_key(secret_b64: Optional[str]) -> bytes:
    if not secret_b64:
        return b""
    try:
        return base64.b64decode(secret_b64)
    except Exception as e:
        raise RedactionError(f"Invalid base64 secret: {e}")


def _hmac_token(val: str, secret: bytes, namespace: Optional[str] = None, prefix: str = DEFAULT_TOKEN_PREFIX) -> str:
    ns = (namespace or "").encode("utf-8")
    msg = ns + b"|" + val.encode("utf-8")
    digest = hmac.new(secret, msg, hashlib.sha256).hexdigest()[:32]
    return f"{prefix}{digest}"


def _hmac_hash(val: str, secret: bytes, prefix: str = DEFAULT_HASH_PREFIX) -> str:
    digest = hmac.new(secret, val.encode("utf-8"), hashlib.sha256).hexdigest()[:40]
    return f"{prefix}{digest}"


def _mask_string(s: str, mask_char: str = DEFAULT_MASK_CHAR, keep_prefix: int = 0, keep_suffix: int = 0,
                 preserve_length: bool = True) -> str:
    if s is None:
        return s
    n = len(s)
    k1 = max(0, min(keep_prefix, n))
    k2 = max(0, min(keep_suffix, n - k1))
    middle_len = max(0, n - k1 - k2)
    middle = mask_char * middle_len if preserve_length else mask_char
    return s[:k1] + middle + (s[-k2:] if k2 else "")


def _mask_digits_keep_last4(s: str, mask_char: str = DEFAULT_MASK_CHAR) -> str:
    digits = [c for c in s if c.isdigit()]
    if len(digits) <= 4:
        return s
    out = []
    keep_from_end = 4
    seen = 0
    for c in reversed(s):
        if c.isdigit():
            if seen < keep_from_end:
                out.append(c)
                seen += 1
            else:
                out.append(mask_char)
        else:
            out.append(c)
    return "".join(reversed(out))


def _pseudonymize_email(s: str, strategy: StrategyConfig) -> str:
    m = RE_EMAIL.search(s)
    if not m:
        return _mask_string(s, strategy.mask_char, 1, 1, True)
    local, dom = m.group(1), m.group(2)
    local_masked = _mask_string(local, strategy.mask_char, keep_prefix=1, keep_suffix=1, preserve_length=True)
    return f"{local_masked}@{dom}"


def _pseudonymize_phone(s: str, strategy: StrategyConfig) -> str:
    m = RE_PHONE.search(s)
    if not m:
        return _mask_digits_keep_last4(s, strategy.mask_char)
    return _mask_digits_keep_last4(m.group(0), strategy.mask_char)


def _pseudonymize_cc(s: str, strategy: StrategyConfig) -> str:
    m = RE_CC.search(s)
    if not m:
        return _mask_digits_keep_last4(s, strategy.mask_char)
    return _mask_digits_keep_last4(m.group(0), strategy.mask_char)


def _numeric_like(s: str) -> bool:
    return bool(re.fullmatch(r"[0-9\-\s]+", s or ""))


def _preview(value: Any, limit: int = 64) -> str:
    try:
        s = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    except Exception:
        s = str(value)
    return (s[:limit] + "...") if len(s) > limit else s


# ----------------------------- Поисковые селекторы путей ---------------------------

def _split_dot_path(path: str) -> List[str]:
    # a.b.c, users[*].email, meta.*.token
    tokens: List[str] = []
    buf = ""
    i = 0
    while i < len(path):
        c = path[i]
        if c == ".":
            if buf:
                tokens.append(buf)
                buf = ""
        else:
            buf += c
        i += 1
    if buf:
        tokens.append(buf)
    return tokens


def _match_glob_segment(seg: str, key: str) -> bool:
    if seg == "*" or seg == "[*]":
        return True
    return seg == key


def _walk_glob(obj: Json, tokens: List[str], path_prefix: str = "") -> Iterator[Tuple[str, Any, Optional[Any]]]:
    """
    Итерирует (json_path, parent, key/index) для совпадающих узлов.
    glob поддерживает * для dict-ключей и [*] для элементов списка.
    """
    if not tokens:
        return
    seg = tokens[0]
    tail = tokens[1:]
    if isinstance(obj, dict):
        for k, v in obj.items():
            if _match_glob_segment(seg, str(k)):
                if not tail:
                    yield (f"{path_prefix}.{k}" if path_prefix else str(k), obj, k)
                else:
                    yield from _walk_glob(v, tail, f"{path_prefix}.{k}" if path_prefix else str(k))
    elif isinstance(obj, list):
        for idx, v in enumerate(obj):
            if seg in ("*", "[*]"):
                if not tail:
                    yield (f"{path_prefix}[{idx}]", obj, idx)
                else:
                    yield from _walk_glob(v, tail, f"{path_prefix}[{idx}]")
    else:
        return


def _resolve_pointer(obj: Json, pointer: str) -> Iterator[Tuple[str, Any, Optional[Any]]]:
    """
    RFC6901 JSON Pointer (ограниченно: возвращает один узел, если существует).
    """
    if pointer == "" or pointer == "/":
        yield ("/", None, None)
        return
    current = obj
    parts = [p.replace("~1", "/").replace("~0", "~") for p in pointer.split("/") if p != ""]
    parent = None
    parent_key: Optional[Union[str, int]] = None
    path = ""
    for p in parts:
        parent = current
        parent_key = p
        path += "/" + p
        if isinstance(current, dict) and p in current:
            current = current[p]
        elif isinstance(current, list) and p.isdigit() and int(p) < len(current):
            parent_key = int(p)
            current = current[int(p)]
        else:
            return
    yield (path, parent, parent_key)


def _resolve_dot_or_glob(obj: Json, sel: str, is_glob: bool) -> Iterator[Tuple[str, Any, Optional[Any]]]:
    tokens = _split_dot_path(sel)
    if not tokens:
        return
    if is_glob:
        yield from _walk_glob(obj, tokens)
    else:
        # Точный dot-путь без wildcard
        cur = obj
        parent = None
        parent_key: Optional[Union[str, int]] = None
        path_acc = []
        for t in tokens:
            parent = cur
            parent_key = t
            path_acc.append(t)
            if isinstance(cur, dict) and t in cur:
                cur = cur[t]
            elif isinstance(cur, list) and t.isdigit() and int(t) < len(cur):
                parent_key = int(t)
                cur = cur[int(t)]
            else:
                return
        yield (".".join(path_acc), parent, parent_key)


def _iter_selector_matches(obj: Json, selector: Selector) -> Iterator[Tuple[str, Any, Optional[Any]]]:
    if selector.type == "pointer":
        yield from _resolve_pointer(obj, selector.value)
    elif selector.type == "dot":
        yield from _resolve_dot_or_glob(obj, selector.value, is_glob=False)
    elif selector.type == "glob":
        yield from _resolve_dot_or_glob(obj, selector.value, is_glob=True)
    else:
        return


# ----------------------------- Применение стратегий --------------------------------

def _strategy_apply(value: Any, strat: StrategyConfig) -> Any:
    # Для сложных типов применяем строковую проекцию только для text-regex;
    # иначе редактируем ТОЛЬКО строковые значения и скалярные.
    if strat.strategy == "remove":
        # Сигнал для вызывающего кода — удалить ключ/элемент
        return dataclasses.MISSING

    if strat.strategy == "replace":
        return strat.replace_with

    if isinstance(value, (dict, list)):
        # не применяем строковые стратегии напрямую
        return value

    if value is None or isinstance(value, bool):
        return value

    s = str(value)

    if strat.strategy == "mask":
        if strat.keep_last4 and _numeric_like(s):
            return _mask_digits_keep_last4(s, strat.mask_char)
        return _mask_string(s, strat.mask_char, strat.keep_prefix, strat.keep_suffix, strat.preserve_length)

    if strat.strategy == "hash":
        secret = _b64_key(strat.secret_b64)
        return _hmac_hash(s, secret, strat.hash_prefix)

    if strat.strategy == "tokenize":
        secret = _b64_key(strat.secret_b64)
        return _hmac_token(s, secret, strat.token_namespace, strat.token_prefix)

    if strat.strategy == "pseudonymize":
        kind = strat.pseudonymize_kind
        if kind == "email":
            return _pseudonymize_email(s, strat)
        if kind == "phone":
            return _pseudonymize_phone(s, strat)
        if kind == "cc":
            return _pseudonymize_cc(s, strat)
        # по умолчанию — маска
        return _mask_string(s, strat.mask_char, 1, 1, True)

    if strat.strategy == "text-regex":
        patterns = [re.compile(p, strat.text_flags) for p in strat.text_patterns]
        masked = s
        for pat in patterns:
            masked = pat.sub(lambda m: _mask_string(m.group(0), strat.mask_char, 0, 0, True), masked)
        return masked

    return value


def _apply_detectors_to_string(s: str, cfg: RedactConfig) -> str:
    out = s
    if cfg.detectors.email:
        out = RE_EMAIL.sub(lambda m: _pseudonymize_email(m.group(0), cfg.strategy), out)
    if cfg.detectors.phone:
        out = RE_PHONE.sub(lambda m: _mask_digits_keep_last4(m.group(0), cfg.strategy.mask_char), out)
    if cfg.detectors.cc:
        out = RE_CC.sub(lambda m: _mask_digits_keep_last4(m.group(0), cfg.strategy.mask_char), out)
    if cfg.detectors.iban:
        out = RE_IBAN.sub(lambda m: _mask_string(m.group(0), cfg.strategy.mask_char, 2, 2, True), out)
    # кастомные
    for pat in cfg.detectors.custom_patterns:
        rx = re.compile(pat, cfg.detectors.custom_flags)
        out = rx.sub(lambda m: _mask_string(m.group(0), cfg.strategy.mask_char, 0, 0, True), out)
    return out


# ----------------------------- Ядро редактора --------------------------------------

class Redactor:
    def __init__(self, cfg: RedactConfig) -> None:
        self.cfg = cfg
        self._events: List[RedactionEvent] = []
        self._nodes_seen = 0

    # --- публичные API ---

    def events(self) -> List[RedactionEvent]:
        return list(self._events)

    def apply_to_obj(self, obj: Json, ctx: Optional[RedactionContext] = None) -> Json:
        """
        Редактирует JSON-объект in-place безопасно (копию для неизменяемых),
        возвращает модифицированную структуру (тот же объект, если возможно).
        """
        self._events.clear()
        ctx = ctx or RedactionContext()
        matches = 0

        # 1) Сначала — адресная редакция по селекторам
        for sel in self.cfg.selectors:
            changed, found = self._apply_selector(obj, sel, ctx)
            matches += found

        # 2) Затем — детекторы текста (PII) на всем объекте (строки)
        def _walk(value: Json, path: str, depth: int) -> Json:
            self._enforce_limits(depth)
            if isinstance(value, dict):
                for k in list(value.keys()):
                    v = value[k]
                    value[k] = _walk(v, f"{path}.{k}" if path else str(k), depth + 1)
                return value
            if isinstance(value, list):
                for i in range(len(value)):
                    value[i] = _walk(value[i], f"{path}[{i}]", depth + 1)
                return value
            if isinstance(value, str):
                before = value
                after = _apply_detectors_to_string(before, self.cfg)
                if after != before:
                    self._log_event(ctx, selector=None, action="detector", reason=self._reason(ctx),
                                    path=path, old_preview=_preview(before), new_preview=_preview(after))
                return after
            return value

        obj = _walk(obj, "", 0)

        if matches == 0 and self.cfg.on_no_match == "error" and self.cfg.selectors:
            raise RedactionError("No matches found for specified selectors")

        # Ограничение на размер вывода
        self._enforce_output_size(obj)
        return obj

    def redact_text(self, text: str, ctx: Optional[RedactionContext] = None) -> str:
        """
        Редактирование свободного текста (логи, сообщения).
        Применяет strategy=text-regex при наличии, затем детекторы.
        """
        self._events.clear()
        ctx = ctx or RedactionContext()

        s = text
        if self.cfg.strategy.strategy == "text-regex" and self.cfg.strategy.text_patterns:
            s2 = _strategy_apply(s, self.cfg.strategy)
            if s2 != s:
                self._log_event(ctx, selector=None, action="text-regex", reason=self._reason(ctx),
                                path=None, old_preview=_preview(s), new_preview=_preview(s2))
            s = s2
        s2 = _apply_detectors_to_string(s, self.cfg)
        if s2 != s:
            self._log_event(ctx, selector=None, action="detector", reason=self._reason(ctx),
                            path=None, old_preview=_preview(s), new_preview=_preview(s2))
        if len(s2.encode("utf-8")) > self.cfg.max_output_bytes:
            raise RedactionError("Output exceeds max_output_bytes")
        return s2

    def redact_bytes_lines(self, stream: Iterable[bytes], encoding: str = "utf-8",
                           ctx: Optional[RedactionContext] = None) -> Iterator[bytes]:
        """
        Построчная редакция байтового стрима (например, tail -f).
        """
        for line in stream:
            try:
                s = line.decode(encoding, errors="replace")
                r = self.redact_text(s, ctx=ctx)
                yield r.encode(encoding)
            except Exception:
                # В случае ошибки — пропускаем линию, не ломаем стрим
                yield line

    # --- внутренние методы ---

    def _apply_selector(self, obj: Json, selector: Selector, ctx: RedactionContext) -> Tuple[bool, int]:
        changed_any = False
        found = 0
        for path, parent, key in _iter_selector_matches(obj, selector):
            if parent is None:
                # корневой объект — селектор "/" для pointer; пропускаем для безопасности
                continue
            found += 1
            before_value = parent[key] if isinstance(parent, (dict, list)) else None
            new_value = _strategy_apply(before_value, self.cfg.strategy)
            if new_value is dataclasses.MISSING:
                # remove
                if isinstance(parent, dict):
                    del parent[key]
                elif isinstance(parent, list) and isinstance(key, int) and 0 <= key < len(parent):
                    parent[key] = None
                changed_any = True
                self._log_event(ctx, selector=selector.value, action="remove", reason=self._reason(ctx),
                                path=path, old_preview=_preview(before_value), new_preview=None)
            elif new_value != before_value:
                if isinstance(parent, (dict, list)):
                    parent[key] = new_value
                    changed_any = True
                    self._log_event(ctx, selector=selector.value, action=self.cfg.strategy.strategy,
                                    reason=self._reason(ctx), path=path,
                                    old_preview=_preview(before_value), new_preview=_preview(new_value))
        return changed_any, found

    def _log_event(self, ctx: RedactionContext, selector: Optional[str], action: str, reason: Optional[str],
                   path: Optional[str], old_preview: Optional[str], new_preview: Optional[str]) -> None:
        ev = RedactionEvent(
            ts=_now_iso(),
            policy_id=ctx.policy_id,
            obligation_id=ctx.obligation_id,
            selector=selector,
            action=action,
            reason=reason,
            path=path,
            old_preview=old_preview,
            new_preview=new_preview,
        )
        self._events.append(ev)

    def _reason(self, ctx: RedactionContext) -> str:
        return ctx.reason or "policy.redact"

    def _enforce_limits(self, depth: int) -> None:
        if depth > self.cfg.max_depth:
            raise RedactionError("Max depth exceeded")
        self._nodes_seen += 1
        if self._nodes_seen > self.cfg.max_nodes:
            raise RedactionError("Max nodes exceeded")

    def _enforce_output_size(self, obj: Json) -> None:
        try:
            b = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        except Exception:
            return
        if len(b) > self.cfg.max_output_bytes:
            raise RedactionError("Output exceeds max_output_bytes")


# ----------------------------- Универсальный вход из Obligations -------------------

def apply_obligation(payload: Json, obligation: Dict[str, Any]) -> Tuple[Json, List[Dict[str, Any]]]:
    """
    Унифицированная точка входа для двигателя обязательств.
    Ожидается объект obligation формата:
    {
      "type": "redact",
      "policy_id": "...",
      "obligation_id": "...",
      "config": {
        "selectors": [
          {"type": "pointer", "value": "/user/email"},
          {"type": "glob", "value": "users[*].phone"},
          {"type": "dot", "value": "payment.card"}
        ],
        "strategy": {
          "strategy": "mask",                # mask|remove|replace|hash|tokenize|pseudonymize|text-regex
          "mask_char": "*",
          "keep_prefix": 1,
          "keep_suffix": 1,
          "keep_last4": true,
          "preserve_length": true,
          "replace_with": null,
          "hash_prefix": "H_",
          "token_prefix": "TKN_",
          "token_namespace": "my-service",
          "secret_b64": "base64-encoded-hmac-key",
          "pseudonymize_kind": "email",     # при strategy=pseudonymize
          "text_patterns": ["(?i)bearer\\s+[a-z0-9._-]+"]
        },
        "detectors": {
          "email": true, "phone": true, "cc": true, "iban": false,
          "custom_patterns": ["(?i)apikey\\s*[:=]\\s*([A-Z0-9-_]{16,})"]
        },
        "max_depth": 40,
        "max_nodes": 100000,
        "max_output_bytes": 10485760,
        "on_no_match": "ok"                 # ok|error
      },
      "context": {
        "actor": "pep-gateway-1",
        "reason": "gdpr.art32"
      }
    }
    Возвращает: (payload_redacted, events_as_dicts)
    """
    if obligation.get("type") != "redact":
        raise RedactionError("Unsupported obligation type")

    cfg_dict = obligation.get("config") or {}
    selectors_cfg = cfg_dict.get("selectors", [])
    selectors = [
        Selector(type=s["type"], value=s["value"], last_key_regex=s.get("last_key_regex"))
        for s in selectors_cfg
    ]
    strat_cfg = cfg_dict.get("strategy", {})
    strategy = StrategyConfig(
        strategy=strat_cfg.get("strategy", "mask"),
        mask_char=strat_cfg.get("mask_char", DEFAULT_MASK_CHAR),
        keep_prefix=int(strat_cfg.get("keep_prefix", 0)),
        keep_suffix=int(strat_cfg.get("keep_suffix", 0)),
        keep_last4=bool(strat_cfg.get("keep_last4", False)),
        preserve_length=bool(strat_cfg.get("preserve_length", True)),
        replace_with=strat_cfg.get("replace_with", None),
        hash_prefix=strat_cfg.get("hash_prefix", DEFAULT_HASH_PREFIX),
        token_prefix=strat_cfg.get("token_prefix", DEFAULT_TOKEN_PREFIX),
        token_namespace=strat_cfg.get("token_namespace", None),
        secret_b64=strat_cfg.get("secret_b64", None),
        pseudonymize_kind=strat_cfg.get("pseudonymize_kind", None),
        text_patterns=list(strat_cfg.get("text_patterns", [])),
        text_flags=re.IGNORECASE,
    )
    det_cfg = cfg_dict.get("detectors", {})
    detectors = Detector(
        email=bool(det_cfg.get("email", True)),
        phone=bool(det_cfg.get("phone", True)),
        cc=bool(det_cfg.get("cc", True)),
        iban=bool(det_cfg.get("iban", False)),
        custom_patterns=list(det_cfg.get("custom_patterns", [])),
        custom_flags=re.IGNORECASE,
    )

    cfg = RedactConfig(
        selectors=selectors,
        strategy=strategy,
        detectors=detectors,
        max_depth=int(cfg_dict.get("max_depth", MAX_DEPTH_DEFAULT)),
        max_nodes=int(cfg_dict.get("max_nodes", MAX_NODES_DEFAULT)),
        max_output_bytes=int(cfg_dict.get("max_output_bytes", MAX_OUTPUT_BYTES_DEFAULT)),
        on_no_match=cfg_dict.get("on_no_match", "ok"),
    )

    ctx_dict = obligation.get("context") or {}
    ctx = RedactionContext(
        policy_id=obligation.get("policy_id"),
        obligation_id=obligation.get("obligation_id"),
        actor=ctx_dict.get("actor"),
        reason=ctx_dict.get("reason"),
        correlation_id=ctx_dict.get("correlation_id"),
    )

    redactor = Redactor(cfg)
    redacted = redactor.apply_to_obj(payload, ctx=ctx)
    events = [dataclasses.asdict(e) for e in redactor.events()]
    return redacted, events


# ----------------------------- Пример локального запуска ---------------------------

if __name__ == "__main__":
    sample_payload = {
        "user": {"email": "alice@example.org", "phone": "+1 202-555-0131"},
        "payment": {"card": "4111 1111 1111 1111"},
        "meta": {"token": "Bearer abcdef-SECRET-xyz"},
        "users": [{"phone": "+46 70 123 45 67", "email": "bob@corp.se"}],
    }

    obligation = {
        "type": "redact",
        "policy_id": "pol-123",
        "obligation_id": "obl-456",
        "config": {
            "selectors": [
                {"type": "pointer", "value": "/payment/card"},
                {"type": "glob", "value": "user.email"},
                {"type": "glob", "value": "users[*].email"},
                {"type": "glob", "value": "meta.token"},
            ],
            "strategy": {
                "strategy": "mask",
                "keep_last4": True,
                "mask_char": "*",
            },
            "detectors": {
                "email": True, "phone": True, "cc": True,
                "custom_patterns": ["(?i)bearer\\s+[a-z0-9\\-]+"],
            },
            "on_no_match": "ok",
        },
        "context": {"actor": "pep", "reason": "gdpr.art32"},
    }

    out, ev = apply_obligation(sample_payload, obligation)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    print(json.dumps(ev, ensure_ascii=False, indent=2))
