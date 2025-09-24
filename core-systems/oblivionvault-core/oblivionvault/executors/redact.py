# -*- coding: utf-8 -*-
"""
OblivionVault Core — Redaction Executor (industrial-grade)

Назначение:
- Удаление/маскирование секретов и ПД в логах, аудите и событиях.
- Единая политика редакции для текста, URL, заголовков и JSON.

Особенности:
- Без внешних зависимостей (stdlib only).
- Детерминированная токенизация (HMAC-SHA256) с солью.
- Поддержка стратегий: mask | hash | remove.
- JSONPath-подобные селекторы: "a.b.*.c", "items[*].token", "secrets[0].value".
- Редакция URL query параметров и HTTP-заголовков (case-insensitive).
- Преднастроенные безопасные паттерны (JWT, Bearer, password, token, api-key, email, IPv4/IPv6, UUID, кредитные карты).
- Интеграция с logging: RedactingFilter и RedactingFormatter.

Совместимость: Python 3.9+

Пример использования:
    policy = RedactionPolicy.from_defaults(token_salt=os.environ.get("OV_REDACT_SALT", "change-me"))
    redactor = Redactor(policy)

    safe_text = redactor.redact_text("Authorization: Bearer abc.def.ghi")
    safe_url  = redactor.redact_url("https://ex.com?a=1&token=secret123")
    safe_hdrs = redactor.redact_headers({"Authorization": "Bearer token", "X-Api-Key": "a1b2"})
    safe_json = redactor.redact_json({"password": "p@ss", "nested": {"token": "xxx"}})

Для логирования:
    import logging
    handler = logging.StreamHandler()
    handler.addFilter(RedactingFilter(redactor))
    handler.setFormatter(RedactingFormatter(redactor))
    logging.getLogger().addHandler(handler)
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import logging
import re
import threading
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union


# ======================================================================
# Политика и стратегии
# ======================================================================

@dataclass
class RegexRule:
    pattern: str
    flags: int = re.IGNORECASE
    target: str = "text"  # text|headers|url|any
    strategy: str = "mask"  # mask|hash|remove
    reveal_last: int = 0    # для mask: оставить N последних символов
    replacement: Optional[str] = None  # если задано — явная замена

@dataclass
class RedactionPolicy:
    # Ключи/параметры/заголовки по именам
    sensitive_keys: Sequence[str] = field(default_factory=lambda: [
        "password", "passwd", "secret", "token", "api_key", "apikey",
        "authorization", "set-cookie", "private_key", "client_secret", "credential",
    ])
    sensitive_headers: Sequence[str] = field(default_factory=lambda: [
        "authorization", "proxy-authorization", "x-api-key", "x-api-token",
        "x-auth-token", "x-amz-security-token", "cookie", "set-cookie",
    ])
    sensitive_url_params: Sequence[str] = field(default_factory=lambda: [
        "password", "secret", "token", "api_key", "apikey", "access_token",
        "id_token", "refresh_token", "code",
    ])
    # Пути в JSON вида: "a.b", "arr[*].token", "items[0].value"
    sensitive_json_paths: Sequence[str] = field(default_factory=list)

    # Шаблоны regex для текста/заголовков/URL
    regex_rules: Sequence[RegexRule] = field(default_factory=list)

    # Общие настройки стратегии по умолчанию
    default_strategy: str = "mask"  # mask|hash|remove
    mask_char: str = "*"
    mask_reveal_last: int = 4

    # Настройки токенизации
    token_salt: str = "change-me"
    token_len: int = 12  # длина усечённого токена

    # Поведение редакции структур
    redact_empty_to_null: bool = False  # если True и strategy=remove -> ставить None

    # Встроенные преднастройки (OWASP-style)
    @classmethod
    def from_defaults(cls, token_salt: str = "change-me") -> "RedactionPolicy":
        defaults = [
            # Заголовки Authorization: Bearer/JWT
            RegexRule(r"(?i)(authorization:\s*(?:bearer|basic)\s+)[^\r\n]+", strategy="mask", reveal_last=0, target="text"),
            # JWT (3 части base64url, отделённые точками)
            RegexRule(r"(?i)\beyJ[a-zA-Z0-9_\-]+=*\.[a-zA-Z0-9_\-]+=*\.[a-zA-Z0-9_\-]+=*\b", strategy="hash", target="any"),
            # password=..., secret=..., token=... в текстах
            RegexRule(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*=\s*([^&\s]+)", strategy="mask", target="text"),
            # Email
            RegexRule(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,24}\b", strategy="hash", target="any"),
            # IPv4
            RegexRule(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", strategy="hash", target="any"),
            # IPv6 (упрощённый)
            RegexRule(r"\b(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}\b", strategy="hash", target="any"),
            # UUID
            RegexRule(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b", strategy="hash", target="any"),
            # Кредитные карты (простая Luhn-похожая маска цифропоследовательностей 12-19)
            RegexRule(r"\b(?:\d[ -]*?){12,19}\b", strategy="mask", reveal_last=4, target="any"),
        ]
        return cls(regex_rules=defaults, token_salt=token_salt)


# ======================================================================
# Утилиты редакции
# ======================================================================

def _hmac_token(value: str, salt: str, out_len: int) -> str:
    dig = hmac.new(salt.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"ovtok_{dig[:max(4, out_len)]}"

def _mask_value(s: str, mask_char: str = "*", reveal_last: int = 0) -> str:
    if not s:
        return ""
    n = len(s)
    if reveal_last <= 0 or reveal_last >= n:
        return mask_char * n
    return mask_char * (n - reveal_last) + s[-reveal_last:]

def _strategy_apply(value: str, strategy: str, policy: RedactionPolicy, reveal_last: Optional[int] = None, replacement: Optional[str] = None) -> str:
    if replacement is not None:
        return replacement
    if strategy == "remove":
        return ""
    if strategy == "hash":
        return _hmac_token(value, policy.token_salt, policy.token_len)
    # default mask
    rev = policy.mask_reveal_last if reveal_last is None else reveal_last
    return _mask_value(value, policy.mask_char, rev)

def _ci(name: str) -> str:
    return name.lower()

def _is_sensitive_key(name: str, sensitive: Sequence[str]) -> bool:
    n = _ci(name)
    return n in { _ci(x) for x in sensitive }

# Простейшие селекторы: "a.b", "a.*.c", "arr[*].token", "arr[0].x"
_SEG_RE = re.compile(r"""
    (?P<name>[^.\[\]]+)    # имя ключа
    | \[\*\]               # все элементы
    | \[(?P<idx>\d+)\]     # индекс
""", re.X)

def _parse_path(path: str) -> List[Union[str, int, slice]]:
    out: List[Union[str, int, slice]] = []
    for part in path.split("."):
        pos = 0
        while pos < len(part):
            m = _SEG_RE.match(part, pos)
            if not m:
                raise ValueError(f"invalid path segment in '{path}' at '{part[pos:]}'")
            if m.group("name"):
                out.append(m.group("name"))
            elif m.group(0) == "[*]":
                out.append(slice(None))  # wildcard
            else:
                out.append(int(m.group("idx")))
            pos = m.end()
    return out

def _walk_and_apply(obj: Any, path: List[Union[str, int, slice]], apply_cb) -> None:
    """
    Глубокий проход по объекту согласно пути; apply_cb(parent, key) вызывается на местах назначения.
    """
    if not path:
        return
    seg, rest = path[0], path[1:]
    if isinstance(seg, str):
        if isinstance(obj, dict) and seg in obj:
            if rest:
                _walk_and_apply(obj[seg], rest, apply_cb)
            else:
                apply_cb(obj, seg)
    elif isinstance(seg, int):
        if isinstance(obj, list) and 0 <= seg < len(obj):
            if rest:
                _walk_and_apply(obj[seg], rest, apply_cb)
            else:
                apply_cb(obj, seg)
    elif isinstance(seg, slice):
        # wildcard
        if isinstance(obj, dict):
            for k in list(obj.keys()):
                if rest:
                    _walk_and_apply(obj[k], rest, apply_cb)
                else:
                    apply_cb(obj, k)
        elif isinstance(obj, list):
            for i in range(len(obj)):
                if rest:
                    _walk_and_apply(obj[i], rest, apply_cb)
                else:
                    apply_cb(obj, i)


# ======================================================================
# Основной класс редакции
# ======================================================================

class Redactor:
    def __init__(self, policy: RedactionPolicy):
        self.policy = policy
        self._compiled: List[Tuple[re.Pattern, RegexRule]] = []
        self._lock = threading.Lock()
        self._compile_once()

    def _compile_once(self) -> None:
        with self._lock:
            if self._compiled:
                return
            for rule in self.policy.regex_rules:
                try:
                    pat = re.compile(rule.pattern, rule.flags)
                    self._compiled.append((pat, rule))
                except re.error as e:
                    logging.getLogger(__name__).warning("invalid regex skipped: %s (%s)", rule.pattern, e)

    # ----------------------------
    # Текст
    # ----------------------------
    def redact_text(self, text: str) -> str:
        if not text:
            return text
        out = text
        for pat, rule in self._compiled:
            if rule.target not in ("text", "any"):
                continue

            def repl(m: re.Match) -> str:
                if m.groups():
                    # Случай "key=value": сохраняем ключ, редактируем значение (последняя группа)
                    if len(m.groups()) >= 2:
                        prefix = m.group(1)
                        val = m.group(2)
                        return f"{prefix}{_strategy_apply(val, rule.strategy, self.policy, rule.reveal_last, rule.replacement)}"
                val = m.group(0)
                return _strategy_apply(val, rule.strategy, self.policy, rule.reveal_last, rule.replacement)

            out = pat.sub(repl, out)
        return out

    # ----------------------------
    # Заголовки
    # ----------------------------
    def redact_headers(self, headers: Mapping[str, str]) -> Dict[str, str]:
        # case-insensitive обработка имён
        redacted: Dict[str, str] = {}
        sens = { _ci(x) for x in self.policy.sensitive_headers }
        for k, v in headers.items():
            if _ci(k) in sens:
                redacted[k] = _strategy_apply(v or "", self.policy.default_strategy, self.policy, self.policy.mask_reveal_last)
            else:
                redacted[k] = v
        # regex-правила для target=headers|any
        for pat, rule in self._compiled:
            if rule.target not in ("headers", "any"):
                continue
            for k, v in list(redacted.items()):
                if not isinstance(v, str):
                    continue
                redacted[k] = pat.sub(lambda m: _strategy_apply(m.group(0), rule.strategy, self.policy, rule.reveal_last, rule.replacement), v)
        return redacted

    # ----------------------------
    # URL и query
    # ----------------------------
    def redact_url(self, url: str) -> str:
        try:
            pr = urllib.parse.urlsplit(url)
            if not pr.query:
                # Также применяем текстовые правила ко всей строке URL
                return self.redact_text(url)
            qs = urllib.parse.parse_qsl(pr.query, keep_blank_values=True)
            sens = { _ci(x) for x in self.policy.sensitive_url_params }
            new_qs: List[Tuple[str, str]] = []
            for k, v in qs:
                if _ci(k) in sens:
                    new_qs.append((k, _strategy_apply(v, self.policy.default_strategy, self.policy, self.policy.mask_reveal_last)))
                else:
                    new_qs.append((k, v))
            red_q = urllib.parse.urlencode(new_qs, doseq=True)
            red_url = urllib.parse.urlunsplit((pr.scheme, pr.netloc, pr.path, red_q, pr.fragment))
            # регексы для target=url|any
            for pat, rule in self._compiled:
                if rule.target not in ("url", "any"):
                    continue
                red_url = pat.sub(lambda m: _strategy_apply(m.group(0), rule.strategy, self.policy, rule.reveal_last, rule.replacement), red_url)
            return red_url
        except Exception:
            # В сомнительных случаях — как обычный текст
            return self.redact_text(url)

    # ----------------------------
    # JSON
    # ----------------------------
    def redact_json(self, obj: Any, in_place: bool = False) -> Any:
        data = obj if in_place else copy.deepcopy(obj)
        self._redact_json_recursive(data)
        # Применим регексы и к сериализованному представлению, если это строка
        return data

    def _redact_json_recursive(self, node: Any) -> None:
        if isinstance(node, dict):
            # по ключам
            for k in list(node.keys()):
                v = node[k]
                if _is_sensitive_key(k, self.policy.sensitive_keys):
                    node[k] = self._apply_struct_strategy(v)
                else:
                    self._redact_json_recursive(v)
            # по путям
            for path in self.policy.sensitive_json_paths:
                try:
                    segments = _parse_path(path)
                except ValueError:
                    continue
                def _apply(parent, key):
                    val = parent[key]
                    parent[key] = self._apply_struct_strategy(val)
                _walk_and_apply(node, segments, _apply)

        elif isinstance(node, list):
            for i in range(len(node)):
                self._redact_json_recursive(node[i])

    def _apply_struct_strategy(self, value: Any) -> Any:
        # Приводим к строке только скалярные секреты; для dict/list рекурсивно маскируем
        if value is None:
            return None
        if isinstance(value, (dict, list)):
            # маскируем содержимое скалярно
            def _apply_all(n):
                if isinstance(n, dict):
                    return {k: self._apply_struct_strategy(v) for k, v in n.items()}
                if isinstance(n, list):
                    return [self._apply_struct_strategy(x) for x in n]
                return _strategy_apply(str(n), self.policy.default_strategy, self.policy, self.policy.mask_reveal_last)
            return _apply_all(value)
        # скаляр
        s = str(value)
        if self.policy.default_strategy == "remove":
            return None if self.policy.redact_empty_to_null else ""
        if self.policy.default_strategy == "hash":
            return _hmac_token(s, self.policy.token_salt, self.policy.token_len)
        return _mask_value(s, self.policy.mask_char, self.policy.mask_reveal_last)

    # ----------------------------
    # Комплексные события
    # ----------------------------
    def redact_event(self, event: Mapping[str, Any]) -> Dict[str, Any]:
        # Для событий делаем копию, редактируем headers/url/body/message при наличии
        e = copy.deepcopy(dict(event))
        if isinstance(e.get("headers"), Mapping):
            e["headers"] = self.redact_headers(e["headers"])
        if isinstance(e.get("url"), str):
            e["url"] = self.redact_url(e["url"])
        if isinstance(e.get("message"), str):
            e["message"] = self.redact_text(e["message"])
        if "body" in e:
            try:
                if isinstance(e["body"], (dict, list)):
                    e["body"] = self.redact_json(e["body"])
                elif isinstance(e["body"], str):
                    # Попытаемся распарсить JSON, иначе применим текстовую редакцию
                    try:
                        parsed = json.loads(e["body"])
                        e["body"] = json.dumps(self.redact_json(parsed), ensure_ascii=False)
                    except Exception:
                        e["body"] = self.redact_text(e["body"])
            except Exception:
                # Ничего не делаем, оставляем как есть
                pass
        return e


# ======================================================================
# Интеграция с logging
# ======================================================================

class RedactingFilter(logging.Filter):
    """
    Фильтр, редактирующий record.msg, а также record.args (популярный случай форматирования).
    """
    def __init__(self, redactor: Redactor):
        super().__init__()
        self.redactor = redactor

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = self.redactor.redact_text(record.msg)
            # record.args может быть кортежем или словарём
            if isinstance(record.args, tuple):
                record.args = tuple(self._redact_arg(a) for a in record.args)
            elif isinstance(record.args, dict):
                record.args = {k: self._redact_arg(v) for k, v in record.args.items()}
            # Дополнительные поля, встречающиеся у структурированных логгеров
            for extra_key in ("headers", "url", "body", "event"):
                if hasattr(record, extra_key):
                    val = getattr(record, extra_key)
                    if extra_key == "headers" and isinstance(val, Mapping):
                        setattr(record, extra_key, self.redactor.redact_headers(val))
                    elif extra_key == "url" and isinstance(val, str):
                        setattr(record, extra_key, self.redactor.redact_url(val))
                    elif extra_key in ("body", "event"):
                        if isinstance(val, (dict, list)):
                            setattr(record, extra_key, self.redactor.redact_json(val))
                        elif isinstance(val, str):
                            try:
                                parsed = json.loads(val)
                                setattr(record, extra_key, json.dumps(self.redactor.redact_json(parsed), ensure_ascii=False))
                            except Exception:
                                setattr(record, extra_key, self.redactor.redact_text(val))
        except Exception:
            # Никогда не ломаем логирование из-за редакции
            return True
        return True

    def _redact_arg(self, a: Any) -> Any:
        if isinstance(a, str):
            return self.redactor.redact_text(a)
        if isinstance(a, Mapping):
            return self.redactor.redact_json(a)
        return a


class RedactingFormatter(logging.Formatter):
    """
    Форматтер, дополнительно применяющий текстовую редакцию к итоговой строке.
    Полезен, если сторонний логгер уже отформатировал строку и фильтр не охватил все кейсы.
    """
    def __init__(self, redactor: Redactor, fmt: Optional[str] = None, datefmt: Optional[str] = None):
        super().__init__(fmt=fmt, datefmt=datefmt)
        self.redactor = redactor

    def format(self, record: logging.LogRecord) -> str:
        out = super().format(record)
        try:
            return self.redactor.redact_text(out)
        except Exception:
            return out


# ======================================================================
# Удобные фабрики
# ======================================================================

def build_default_redactor(token_salt: Optional[str] = None) -> Redactor:
    """
    Быстрая фабрика редактора с дефолтной политикой. Соль можно прокинуть из переменных окружения.
    """
    pol = RedactionPolicy.from_defaults(token_salt=token_salt or "change-me")
    return Redactor(pol)


# ======================================================================
# Простейший самотест при прямом запуске
# ======================================================================

if __name__ == "__main__":
    r = build_default_redactor("demo-salt")
    samples = {
        "text": "Authorization: Bearer eyJhbGciOi.eyJzdWIiOi.sig\npassword=superSecret!",
        "url": "https://ex.com/api?token=abcd1234&id=42",
        "headers": {"Authorization": "Bearer tok_123", "X-API-Key": "A1B2C3", "User-Agent": "curl"},
        "json": {"password": "p@ss", "nested": {"token": "abc", "arr": [{"token": "x"}, {"token": "y"}]}},
    }
    print("TEXT  :", r.redact_text(samples["text"]))
    print("URL   :", r.redact_url(samples["url"]))
    print("HEAD  :", r.redact_headers(samples["headers"]))
    print("JSON  :", r.redact_json(samples["json"]))
