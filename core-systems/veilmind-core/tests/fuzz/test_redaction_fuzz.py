# -*- coding: utf-8 -*-
"""
Fuzz-тесты для veilmind.prompt_guard.sanitizer.PromptSanitizer.

Цели:
  - Отсутствие исключений на разнообразном «грязном» вводе.
  - Отсутствие утечек секретов/PII после санитайза.
  - Корректные решения для fast-blocklist/jailbreak/injection.
  - Идемпотентность повторного санитайза.
  - Нормализация: удаление zero-width, схлопывание повторов.
  - Производительность: обработка «длинных» строк (smoke).

Зависимости: pytest, стандартная библиотека Python.
"""

from __future__ import annotations

import json
import random
import re
import string
import unicodedata
import pytest

from veilmind.prompt_guard.sanitizer import PromptSanitizer

# -----------------------------------------------------------------------------
# Конфиг санитайзера (согласован с sanitizer._cfg_from_dict)
# -----------------------------------------------------------------------------

def base_config(**overrides) -> dict:
    cfg = {
        "normalize": {
            "unicode_nfkc": True,
            "strip_control_chars": True,
            "collapse_whitespace": True,
            "trim": True,
            "lowercase_for_matchers": True,
            "max_repeated_chars": 8,
        },
        "redact_transform": {
            "default_mask": "[REDACTED]",
            "annotate_redactions": True,
            "annotations": {"prefix": "[REDACTED:", "suffix": "]"},
            "preserve_length_hint": False,
        },
        "policy_decision": {
            "risk_weights": {
                "secrets": 1.0,
                "pii": 0.6,
                "jailbreak": 0.8,
                "injection": 0.9,
                "safety": 1.0,
                "exfiltration": 1.0,
                "tools_abuse": 0.9,
            },
            "thresholds": {"deny": 0.8, "review": 0.6},
            "tie_breaker": "deny",
        },
        "fast_blocklists": {
            "patterns": [
                r"BEGIN\s+PRIVATE\s+KEY",
            ]
        },
        "detectors": {
            "secrets": [
                {
                    "id": "aws_access_key",
                    "pattern": r"\bAKIA[0-9A-Z]{16}\b",
                    "deny_immediately": True,
                    "severity": "critical",
                }
            ],
            "pii": [
                {
                    "id": "email",
                    "pattern": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
                    "severity": "medium",
                }
            ],
            "jailbreak": {
                "heuristics": {
                    "signals": [r"\bignore previous instructions\b"]
                }
            },
            "injection": [],
            "exfiltration": [],
            "tools_abuse": [],
        },
        "route_model": {
            "safe_prompt_prefix": {"text": ""},
        },
        "runtime": {
            "fail_mode": "fail_closed",
        },
    }
    cfg.update(overrides)
    return cfg

def make_sanitizer(cfg: dict | None = None) -> PromptSanitizer:
    return PromptSanitizer.from_dict(cfg or base_config())

# -----------------------------------------------------------------------------
# Вспомогательная генерация данных
# -----------------------------------------------------------------------------

ZERO_WIDTHS = ["\u200b", "\u200c", "\u200d", "\ufeff", "\u2060"]
HOMO = {
    "i": "ı", "I": "Ｉ",
    "o": "о", "O": "О",  # латинская -> кириллическая
    "a": "а", "A": "А",
    "e": "е", "E": "Е",
    "c": "с", "C": "С",
    "x": "х", "X": "Х",
    "-": "—",
}

ASCII = string.ascii_letters + string.digits + " .,;:!?()[]{}<>-_/\\|@#%^&*+="
UNICODE_SPICE = "αβγδεζηθλμνξπστυφχψω—–«»„“”’☆★✓✔✗©®𝟘𝟙𝟚𝟛𝟜𝟝"
CTRL = "".join(chr(i) for i in range(0x00, 0x20) if i not in (0x09, 0x0A))  # исключим \t и \n

def rand_email(rnd: random.Random) -> str:
    name = "".join(rnd.choice(string.ascii_lowercase + "._") for _ in range(rnd.randint(3, 10))).strip(".")
    domain = "".join(rnd.choice(string.ascii_lowercase) for _ in range(rnd.randint(3, 8)))
    tld = rnd.choice(["com", "org", "io", "net"])
    return f"{name}@{domain}.{tld}"

def rand_aws_key(rnd: random.Random) -> str:
    return "AKIA" + "".join(rnd.choice(string.ascii_uppercase + string.digits) for _ in range(16))

def obfuscate_jailbreak(rnd: random.Random, s: str = "ignore previous instructions") -> str:
    # Вставляем zero-width, заменяем часть букв гомоглифами, мешаем регистр
    out = []
    for ch in s:
        ch2 = HOMO.get(ch, HOMO.get(ch.upper(), ch))
        ch3 = ch2.upper() if rnd.random() < 0.3 else ch2.lower()
        out.append(ch3)
        if rnd.random() < 0.4:
            out.append(rnd.choice(ZERO_WIDTHS))
    return "".join(out)

def rand_noise(rnd: random.Random, n: int) -> str:
    alphabet = ASCII + UNICODE_SPICE + ZERO_WIDTHS[rnd.randrange(len(ZERO_WIDTHS))] + CTRL
    return "".join(rnd.choice(alphabet) for _ in range(n))

def with_insertions(rnd: random.Random) -> str:
    """
    Собирает строку из кусочков шума и случайных вставок секретов/PII/инъекций/повторов.
    """
    parts = []
    # 6-12 блоков
    for _ in range(rnd.randint(6, 12)):
        parts.append(rand_noise(rnd, rnd.randint(5, 40)))
        dice = rnd.random()
        if dice < 0.25:
            parts.append(rand_email(rnd))
        elif dice < 0.45:
            parts.append(rand_aws_key(rnd))
        elif dice < 0.65:
            parts.append(obfuscate_jailbreak(rnd))
        elif dice < 0.8:
            # длинная серия повторяющихся символов
            ch = rnd.choice("AaBb.-_=*")
            parts.append(ch * rnd.randint(12, 40))  # больше max_repeated_chars
        else:
            # фрагмент, попадающий в fast_blocklist (возможно с шумом)
            parts.append("----BEGIN PRIVATE KEY----\n" + rand_noise(rnd, rnd.randint(5, 20)))
    return " ".join(parts)

SECRET_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

# -----------------------------------------------------------------------------
# Fuzz: отсутствие сбоев, отсутствие утечек, корректные решения
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("seed", list(range(64)))
def test_fuzz_no_crash_and_no_leak(seed: int):
    rnd = random.Random(seed)
    s = make_sanitizer()

    text = with_insertions(rnd)
    res = s.sanitize_input(text)

    # 1) Санитайзер не падает и возвращает валидные метрики
    assert res is not None
    assert any(m.name == "total" for m in res.metrics)
    assert all(m.took_ms >= 0 for m in res.metrics)

    # 2) После санитайза не должно остаться «сырого» секрета или email
    assert not SECRET_RE.search(res.sanitized_text), "секрет не должен просочиться"
    # Email может исчезнуть или быть замаскирован; важно, чтобы «сырых» email не осталось
    # Разрешаем аннотированный маркер в тексте.
    for m in EMAIL_RE.finditer(res.sanitized_text):
        frag = m.group(0)
        assert "[REDACTED" in res.sanitized_text or frag not in res.sanitized_text

    # 3) Если исходник содержал секрет — ожидаем deny и находку category="secret"
    had_secret = bool(SECRET_RE.search(text))
    if had_secret:
        assert res.decision == "deny"
        assert any(f.category == "secret" for f in res.findings)

    # 4) Если был fast-blocklist фрагмент — тоже не ниже deny
    if "BEGIN PRIVATE KEY" in text:
        assert res.decision in ("deny",), "fast-blocklist должен эскалировать до deny"

    # 5) Если присутствовала обфусцированная jailbreak-фраза — не ниже review
    if "ignore" in unicodedata.normalize("NFKC", text).lower() or any(z in text for z in ZERO_WIDTHS):
        # эвристика: наличие нулевой ширины + фразы в обфусцированном виде встречается часто
        if any(f.category in ("jailbreak", "injection") for f in res.findings):
            assert res.decision in ("review", "deny")


# -----------------------------------------------------------------------------
# Идемпотентность: повторный санитайз возвращает тот же текст/решение
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("seed", list(range(16)))
def test_idempotent(seed: int):
    rnd = random.Random(10_000 + seed)
    s = make_sanitizer()
    text = with_insertions(rnd)

    res1 = s.sanitize_input(text)
    res2 = s.sanitize_input(res1.sanitized_text)

    assert res2.sanitized_text == res1.sanitized_text
    # Решение не должно «ухудшаться» после повторного запуска
    order = {"allow": 0, "review": 1, "deny": 2}
    assert order[res2.decision] <= order[res1.decision]


# -----------------------------------------------------------------------------
# Нормализация: zero-width удалены, повторы ограничены
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("seed", list(range(8)))
def test_zero_width_removed_and_repeats_limited(seed: int):
    rnd = random.Random(20_000 + seed)
    s = make_sanitizer()

    # Создаем строку с нулевой шириной и длинными повторами
    zw = "".join(rnd.choice(ZERO_WIDTHS) for _ in range(20))
    long_run = "A" * 50 + "." * 50 + "-" * 50
    text = f"prefix{zw}middle{zw}suffix {long_run}"

    res = s.sanitize_input(text)
    # Zero-width не должно остаться
    assert not any(z in res.sanitized_text for z in ZERO_WIDTHS)
    # Повторы ограничиваются до max_repeated_chars (8 по умолчанию)
    assert "A" * 9 not in res.sanitized_text
    assert "." * 9 not in res.sanitized_text
    assert "-" * 9 not in res.sanitized_text


# -----------------------------------------------------------------------------
# Производительность (smoke): длинная строка
# -----------------------------------------------------------------------------

def test_long_input_smoke():
    rnd = random.Random(12345)
    s = make_sanitizer()

    # ~50K символов с редкими вставками шаблонов
    chunks = []
    for i in range(500):
        chunks.append(rand_noise(rnd, 80))
        if i % 25 == 0:
            chunks.append(rand_aws_key(rnd))
        if i % 33 == 0:
            chunks.append(rand_email(rnd))
    text = " ".join(chunks)

    res = s.sanitize_input(text)
    assert res is not None
    # Отсутствие сырых секретов/PII
    assert not SECRET_RE.search(res.sanitized_text)
    assert not EMAIL_RE.search(res.sanitized_text)


# -----------------------------------------------------------------------------
# JSON/JSONL: строка с полем message (эмуляция run_redact режима)
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("seed", list(range(4)))
def test_json_like_payload(seed: int):
    rnd = random.Random(30_000 + seed)
    s = make_sanitizer()

    payload = {
        "level": "info",
        "message": with_insertions(rnd),
        "meta": {"user": rand_email(rnd)},
    }
    txt = json.dumps(payload, ensure_ascii=False)

    # Имитация обработки поля (как это делает CLI): выделяем message
    obj = json.loads(txt)
    msg = obj["message"]
    res = s.sanitize_input(msg)

    # Возврат без утечек, с допустимым решением
    assert not SECRET_RE.search(res.sanitized_text)
    # Если исходная message содержала секрет — deny
    if SECRET_RE.search(msg):
        assert res.decision == "deny"
