# oblivionvault-core/oblivionvault/executors/anonymize.py
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
from dataclasses import dataclass, field
from datetime import date, datetime
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

__all__ = [
    "AnonymizationError",
    "Rule",
    "Policy",
    "PatternRegistry",
    "TokenStore",
    "HMACTokenStore",
    "anonymize_text",
    "anonymize_record",
    "anonymize_stream",
    "safe_default_policy",
]

logger = logging.getLogger(__name__)

# ------------------------- Errors -------------------------

class AnonymizationError(Exception):
    """Domain error for anonymization failures."""


# ------------------------- Rules & Policy -------------------------

Action = str  # "mask" | "redact" | "null" | "hash" | "tokenize" | "generalize"

@dataclass
class Rule:
    """
    Анонимизация для выбранных путей и/или детекторов.

    paths: список dot-path маршрутов с поддержкой:
        - "*"  : один уровень
        - "**" : любое число уровней (хвост)
      Пример: "user.email", "payment.card.number", "metadata.*.email", "notes.**"
    detectors: имена паттернов (из реестра), применяются к строковым значениям.
    action: mask|redact|null|hash|tokenize|generalize
    params: параметры действия (см. ниже).
    """
    paths: List[str] = field(default_factory=list)
    detectors: List[str] = field(default_factory=list)
    action: Action = "mask"
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Policy:
    """
    Политика анонимизации.
    """
    rules: List[Rule] = field(default_factory=list)
    secret: Optional[bytes] = None  # если None — читается из env ANONYMIZE_SECRET
    namespace: str = "default"      # пространство имён для токенов
    # Кастомные паттерны можно добавить/переопределить:
    custom_patterns: Dict[str, str] = field(default_factory=dict)
    # Глобальные настройки:
    redact_token: str = "[REDACTED]"
    hash_algo: str = "sha256"        # для action="hash"
    token_length: int = 16           # base32 длина токена (видимая часть)


# ------------------------- Pattern Registry -------------------------

class PatternRegistry:
    """
    Реестр и компиляция regex-паттернов PII.
    Ключи используются в правилах (detectors).
    """
    DEFAULTS: Mapping[str, str] = {
        # Общее
        "email": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b",
        "phone": r"(?:\+?\d{1,3}[\s\-()]*)?(?:\d[\s\-()]*){6,14}\d",
        "ipv4": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
                r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b",
        "ipv6": r"\b(?:(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|"
                r"(?:[A-Fa-f0-9]{1,4}:){1,7}:|"
                r"(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}|"
                r"(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}|"
                r"(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}|"
                r"(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}|"
                r"(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}|"
                r"[A-Fa-f0-9]{1,4}:(?::[A-Fa-f0-9]{1,4}){1,6}|"
                r":(?::[A-Fa-f0-9]{1,4}){1,7})\b",
        "mac": r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b",
        "url": r"\bhttps?://[^\s/$.?#].[^\s]*\b",
        # Финансовое
        "card": r"\b(?:\d[ -]?){12,19}\b",
        "iban": r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
        # Идентификаторы (общие шаблоны)
        "uuid": r"\b[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[1-5][0-9a-fA-F]{3}\-[89abAB][0-9a-fA-F]{3}\-[0-9a-fA-F]{12}\b",
        "ulid": r"\b[0-9A-HJKMNP-TV-Z]{26}\b",
        # Даты (простая эвристика ISO8601)
        "date": r"\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)?\b",
        # Российские паспорта/ИНН (эвристики)
        "ru_passport": r"\b\d{2}\s?\d{2}\s?\d{6}\b",
        "ru_inn": r"\b\d{10}(\d{2})?\b",
    }

    def __init__(self, custom: Optional[Mapping[str, str]] = None):
        merged = dict(self.DEFAULTS)
        if custom:
            merged.update(custom)
        self.patterns: Dict[str, re.Pattern] = {k: re.compile(v) for k, v in merged.items()}


# ------------------------- Token Store -------------------------

class TokenStore:
    """Интерфейс токен-хранилища (детерминированная псевдонимизация)."""
    def tokenize(self, namespace: str, value: str) -> str:
        raise NotImplementedError


class HMACTokenStore(TokenStore):
    """
    Детерминированный токен на основе HMAC(secret, namespace || value).
    Не хранит состояние. Подходит для псевдонимизации без БД.
    """
    def __init__(self, secret: bytes, token_length: int = 16, algo: str = "sha256"):
        if not secret:
            raise AnonymizationError("Empty secret for HMACTokenStore")
        self._secret = secret
        self._token_len = token_length
        self._algo = algo.lower()
        self._lock = threading.Lock()

    def tokenize(self, namespace: str, value: str) -> str:
        data = f"{namespace}::{value}".encode("utf-8")
        with self._lock:
            digest = hmac.new(self._secret, data, getattr(hashlib, self._algo)).digest()
        b32 = base64.b32encode(digest).decode("ascii").rstrip("=")
        return b32[: self._token_len]


# ------------------------- Utilities -------------------------

def _get_secret(policy: Policy) -> bytes:
    if policy.secret:
        return policy.secret
    env = os.getenv("ANONYMIZE_SECRET")
    if not env:
        raise AnonymizationError("ANONYMIZE_SECRET is not set and policy.secret is None")
    return env.encode("utf-8")


def _path_matches(rule_path: str, actual: str) -> bool:
    """
    Сопоставление путей с wildcard:
    - '*'  — ровно один сегмент
    - '**' — любой хвост (включая пустой)
    """
    rp = rule_path.split(".")
    ap = actual.split(".")
    i = j = 0
    while i < len(rp) and j < len(ap):
        if rp[i] == "**":
            if i == len(rp) - 1:
                return True
            i += 1
            while j < len(ap):
                if _path_matches(".".join(rp[i:]), ".".join(ap[j:])):
                    return True
                j += 1
            return False
        if rp[i] == "*" or rp[i] == ap[j]:
            i += 1
            j += 1
        else:
            return False
    # оставшийся хвост из '**' допустим
    while i < len(rp) and rp[i] == "**":
        i += 1
    return i == len(rp) and j == len(ap)


def _luhn_valid(num: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", num)]
    if len(digits) < 12:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _mask_middle(s: str, keep_left: int = 2, keep_right: int = 2, mask_char: str = "*") -> str:
    if s is None:
        return s
    n = len(s)
    if n <= keep_left + keep_right:
        return mask_char * n
    return s[:keep_left] + mask_char * (n - keep_left - keep_right) + s[-keep_right:]


def _mask_phone(s: str) -> str:
    # Сохраняем формат: заменяем цифры кроме первых 2 и последних 2
    digits = re.sub(r"\D", "", s)
    if not digits:
        return s
    keep_left, keep_right = 2, 2
    masked_digits = _mask_middle(digits, keep_left, keep_right)
    it = iter(masked_digits)
    return "".join(next(it) if ch.isdigit() else ch for ch in s)


def _mask_card(s: str) -> str:
    if not _luhn_valid(s):
        return _mask_middle(re.sub(r"\s", "", s), 1, 1)
    digits = re.sub(r"\D", "", s)
    masked = _mask_middle(digits, 4, 4)
    it = iter(masked)
    return "".join(next(it) if ch.isdigit() else ch for ch in s)


def _hash_value(val: str, secret: bytes, algo: str = "sha256") -> str:
    return getattr(hashlib, algo.lower())(secret + val.encode("utf-8")).hexdigest()


def _generalize_ip(value: str) -> str:
    try:
        ip = ip_address(value)
        if isinstance(ip, IPv4Address):
            return str(ip_network(f"{ip}/24", strict=False).network_address) + "/24"
        elif isinstance(ip, IPv6Address):
            # обобщение до /64
            return str(ip_network(f"{ip}/64", strict=False).network_address) + "/64"
    except ValueError:
        pass
    return "[IP]"


def _generalize_date(value: str) -> str:
    try:
        # ISO-попытки
        if re.match(r"^\d{4}-\d{2}-\d{2}$", value):
            y, m, _ = value.split("-")
            return f"{y}-{m}-01"
        if re.match(r"^\d{4}-\d{2}-\d{2}[T ].*$", value):
            y, m, _ = value.split("-", 2)
            return f"{y}-{m}-01"
    except Exception:
        pass
    return "[DATE]"


# ------------------------- Core text anonymization -------------------------

def anonymize_text(text: str, detectors: Sequence[str], action: Action, params: Mapping[str, Any],
                   registry: PatternRegistry, token_store: Optional[TokenStore] = None,
                   policy: Optional[Policy] = None) -> str:
    """
    Применяет детекторы к произвольному тексту и выполняет заданное действие.
    """
    secret = _get_secret(policy) if policy else os.getenv("ANONYMIZE_SECRET", "").encode("utf-8")
    if action in ("hash", "tokenize") and not secret:
        raise AnonymizationError("Secret required for hash/tokenize")

    def repl_factory(name: str) -> Callable[[re.Match], str]:
        def _repl(m: re.Match) -> str:
            val = m.group(0)
            if action == "redact":
                return (policy.redact_token if policy else "[REDACTED]")
            elif action == "null":
                return "null"
            elif action == "mask":
                if name == "phone":
                    return _mask_phone(val)
                if name == "card":
                    return _mask_card(val)
                keep_l = int(params.get("keep_left", 2))
                keep_r = int(params.get("keep_right", 2))
                mask_ch = str(params.get("mask_char", "*"))[:1]
                return _mask_middle(val, keep_l, keep_r, mask_ch)
            elif action == "hash":
                algo = str(params.get("algo", policy.hash_algo if policy else "sha256"))
                return _hash_value(val, secret, algo)
            elif action == "tokenize":
                ns = str(params.get("namespace", policy.namespace if policy else "default"))
                tl = int(params.get("token_length", policy.token_length if policy else 16))
                ts = token_store or HMACTokenStore(secret, token_length=tl)
                return ts.tokenize(ns, val)
            elif action == "generalize":
                mode = str(params.get("mode", "coarse"))
                if name in ("ipv4", "ipv6"):
                    return _generalize_ip(val)
                if name == "date":
                    return _generalize_date(val)
                if mode == "coarse":
                    return "[PII]"
                return "[PII]"
            else:
                return val
        return _repl

    out = text
    for det in detectors:
        pat = registry.patterns.get(det)
        if not pat:
            raise AnonymizationError(f"Unknown detector: {det}")
        out = pat.sub(repl_factory(det), out)
    return out


# ------------------------- Record anonymization -------------------------

JSON = Union[Dict[str, Any], List[Any], str, int, float, bool, None]

def anonymize_record(record: JSON, policy: Policy, registry: Optional[PatternRegistry] = None,
                     token_store: Optional[TokenStore] = None, _path: str = "") -> JSON:
    """
    Рекурсивная анонимизация JSON-совместимой структуры по политике.
    Правила применяются по совпадению путей и/или по детекторам для строк.
    """
    if registry is None:
        registry = PatternRegistry(policy.custom_patterns)

    def matched_rules(path: str, is_text: bool) -> List[Rule]:
        res: List[Rule] = []
        for r in policy.rules:
            # если paths пуст — правило применяется только к детекторам
            path_ok = (not r.paths) or any(_path_matches(p, path) for p in r.paths)
            if path_ok and (is_text or (not r.detectors)):
                res.append(r)
        return res

    if isinstance(record, dict):
        out: Dict[str, Any] = {}
        for k, v in record.items():
            child_path = f"{_path}.{k}" if _path else k
            out[k] = anonymize_record(v, policy, registry, token_store, child_path)
        return out

    if isinstance(record, list):
        return [
            anonymize_record(v, policy, registry, token_store, f"{_path}.*" if _path else "*")
            for v in record
        ]

    if isinstance(record, str):
        rules = matched_rules(_path or "", is_text=True)
        value = record
        # сначала правила с явным action без детекторов (т.е. для целевого поля)
        for r in (r for r in rules if not r.detectors):
            value = _apply_action_to_value(value, r, policy, token_store)
        # затем правила с детекторами (скан текста)
        for r in (r for r in rules if r.detectors):
            value = anonymize_text(value, r.detectors, r.action, r.params, registry, token_store, policy)
        return value

    # Примитивы (числа, bool, None): по путям можно применить null/redact/hash/tokenize
    rules = matched_rules(_path or "", is_text=False)
    if rules:
        val_str = str(record) if record is not None else ""
        for r in rules:
            if r.detectors:
                continue  # детекторы для нестрок не применяем
            if r.action in ("null", "redact"):
                return None if r.action == "null" else policy.redact_token
            if r.action in ("hash", "tokenize", "mask"):
                # безопаснее перевести в строку и заменить
                val_str = _apply_action_to_value(val_str, r, policy, token_store)
        # Пытаемся привести обратно к исходному типу
        try:
            if isinstance(record, (int, float)) and val_str.isdigit():
                return int(val_str)
        except Exception:
            pass
        return val_str
    return record


def _apply_action_to_value(value: str, rule: Rule, policy: Policy, token_store: Optional[TokenStore]) -> str:
    secret = _get_secret(policy)
    if rule.action == "redact":
        return policy.redact_token
    if rule.action == "null":
        return "null"
    if rule.action == "mask":
        return _mask_middle(
            value,
            int(rule.params.get("keep_left", 1)),
            int(rule.params.get("keep_right", 1)),
            str(rule.params.get("mask_char", "*"))[:1],
        )
    if rule.action == "hash":
        algo = str(rule.params.get("algo", policy.hash_algo))
        return _hash_value(value, secret, algo)
    if rule.action == "tokenize":
        ns = str(rule.params.get("namespace", policy.namespace))
        tl = int(rule.params.get("token_length", policy.token_length))
        ts = token_store or HMACTokenStore(secret, token_length=tl)
        return ts.tokenize(ns, value)
    if rule.action == "generalize":
        mode = str(rule.params.get("mode", "coarse"))
        if mode == "coarse":
            return "[PII]"
        return "[PII]"
    return value


# ------------------------- Streaming anonymization -------------------------

def anonymize_stream(lines: Iterable[str], policy: Policy,
                     registry: Optional[PatternRegistry] = None,
                     token_store: Optional[TokenStore] = None) -> Iterator[str]:
    """
    Построчная потоковая анонимизация (подходит для логов).
    Ограничение: совпадения, пересекающие границы строк, не поддерживаются.
    """
    if registry is None:
        registry = PatternRegistry(policy.custom_patterns)

    # Собираем общий список детекторов из правил для быстрого пути
    detectors: List[str] = sorted(
        {d for r in policy.rules for d in r.detectors if r.detectors}
    )

    # Специальное «строковое правило» по умолчанию — если правило задано по детекторам без путей
    text_only_rules = [r for r in policy.rules if r.detectors and not r.paths]

    for line in lines:
        out = line
        for r in text_only_rules:
            out = anonymize_text(out, r.detectors, r.action, r.params, registry, token_store, policy)
        yield out


# ------------------------- Default policy -------------------------

def safe_default_policy() -> Policy:
    """
    Безопасная дефолт-политика:
    - замена email/phone/ip/uuid/ulid/url на токены
    - карты/IBAN маскируются форматосохраняюще
    - поля с путями *.password, *.ssn, *.secret редактируются
    """
    return Policy(
        rules=[
            Rule(paths=["**.password", "**.secret", "**.ssn"], action="redact"),
            Rule(detectors=["email", "phone", "uuid", "ulid", "url"], action="tokenize"),
            Rule(detectors=["ipv4", "ipv6"], action="generalize", params={"mode": "ip"}),
            Rule(detectors=["card"], action="mask"),
            Rule(detectors=["iban"], action="mask", params={"keep_left": 2, "keep_right": 2}),
        ]
    )


# ------------------------- Minimal CLI for verification -------------------------

def _demo():
    policy = safe_default_policy()
    os.environ.setdefault("ANONYMIZE_SECRET", "change-me-in-prod")
    registry = PatternRegistry()
    text = (
        "User alice@example.com called +1 202-555-0182 at 2025-08-01. "
        "Card 4111 1111 1111 1111, UUID 123e4567-e89b-12d3-a456-426614174000, IP 192.168.1.42"
    )
    print("TEXT IN :", text)
    print("TEXT OUT:", anonymize_text(text, ["email", "phone", "card", "uuid", "ipv4", "date"], "tokenize",
                                      {"namespace": "demo"}, registry, None, policy))
    record = {
        "user": {
            "email": "bob@example.com",
            "password": "P@ssw0rd",
            "phones": ["+49 151 1234567", "+44 20 7946 0958"],
            "profile": {"ip": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
        },
        "payment": {"card": "4111 1111 1111 1111", "iban": "DE89370400440532013000"},
        "notes": "Meet at https://example.com on 2025-08-02",
    }
    pol = Policy(
        rules=[
            Rule(paths=["user.email"], action="tokenize", detectors=[]),
            Rule(paths=["user.password"], action="redact"),
            Rule(paths=["payment.card"], action="mask"),
            Rule(detectors=["url", "date"], action="redact"),
            Rule(detectors=["ipv6"], action="generalize"),
        ]
    )
    out = anonymize_record(record, pol, registry)
    print("JSON OUT:", json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    _demo()
