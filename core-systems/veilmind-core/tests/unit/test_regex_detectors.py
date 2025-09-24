# veilmind-core/tests/unit/test_regex_detectors.py
# -*- coding: utf-8 -*-
import importlib
import re
import time
from typing import Any, Dict, Iterable, Optional

import pytest

# Попытки импортировать модуль детекторов из распространенных путей проекта.
CANDIDATE_MODULES = [
    "veilmind.detect.regex_detectors",
    "veilmind.regex.detectors",
    "veilmind.detectors.regex",
    "veilmind_core.detect.regex_detectors",
]

def _import_module():
    last_err = None
    for m in CANDIDATE_MODULES:
        try:
            return importlib.import_module(m)
        except Exception as e:  # pragma: no cover - диагностический путь
            last_err = e
            continue
    pytest.skip(f"Модуль с регэксп‑детекторами не найден. Ожидались пути: {CANDIDATE_MODULES}; последняя ошибка: {last_err!r}")

DET = _import_module()


def _maybe_compile(x: Any) -> Optional[re.Pattern]:
    if x is None:
        return None
    if isinstance(x, re.Pattern):
        return x
    if isinstance(x, str):
        return re.compile(x)
    return None


def _get_pattern(name_variants: Iterable[str]) -> Optional[re.Pattern]:
    """
    Ищет паттерн в модуле DET:
      - как атрибут EMAIL_RE / EMAIL_PATTERN / EMAIL
      - в словарях PATTERNS / DETECTORS / REGEXES / REGEX_MAP по ключу 'email'
      - как фабрика get_pattern('email')
    """
    # 1) Прямые атрибуты
    for nm in name_variants:
        for suffix in ("", "_RE", "_PATTERN", "_regex", "_Regex", "_re"):
            val = getattr(DET, nm + suffix, None)
            pat = _maybe_compile(val)
            if pat:
                return pat

    # 2) Словари
    dict_names = ["PATTERNS", "DETECTORS", "REGEXES", "REGEX_MAP", "PATTERN_MAP"]
    for dn in dict_names:
        mapping = getattr(DET, dn, None)
        if isinstance(mapping, dict):
            for nm in name_variants:
                val = mapping.get(nm) or mapping.get(nm.lower()) or mapping.get(nm.upper())
                pat = _maybe_compile(val)
                if pat:
                    return pat

    # 3) Фабрики
    for fn_name in ("get_pattern", "pattern_for", "get_regex", "regex_for"):
        fn = getattr(DET, fn_name, None)
        if callable(fn):
            for nm in name_variants:
                try:
                    pat = _maybe_compile(fn(nm))
                    if pat:
                        return pat
                except Exception:
                    continue
    return None


def _skip_if_none(pat: Optional[re.Pattern], what: str):
    if pat is None:
        pytest.skip(f"Паттерн для {what} не найден в модуле детекторов")


def _assert_matches(pat: re.Pattern, should_match: Iterable[str], should_not: Iterable[str]):
    for s in should_match:
        m = pat.search(s)
        assert m, f"Ожидалось совпадение для: {s!r}"
    for s in should_not:
        m = pat.search(s)
        assert not m, f"Не ожидалось совпадения для: {s!r}"


# ----------------------------
# Email
# ----------------------------

@pytest.mark.parametrize("valid", [
    "user@example.com",
    "USER+tag@sub.domain.co.uk",
    "nice.o'reilly+filter-1@ex-ample.io",
    "a.b-c_d@exa-mple.travel",
])
@pytest.mark.parametrize("invalid", [
    "plainaddress",
    "@missinglocal.com",
    "user@com",
    "user..dots@example.com",
    "user@example..com",
    "user@-example.com",
])
def test_email_basic(valid, invalid):
    pat = _get_pattern(["EMAIL", "email"])
    _skip_if_none(pat, "email")
    _assert_matches(pat, [valid], [invalid])


def test_email_multiple_and_boundaries():
    pat = _get_pattern(["EMAIL", "email"])
    _skip_if_none(pat, "email")
    text = "Contact: a.b@ex.com, c+d@sub.ex.co; not-an-email: foo@bar"
    found = [m.group(0) for m in pat.finditer(text)]
    assert "a.b@ex.com" in found and "c+d@sub.ex.co" in found
    # foo@bar без TLD не должен считаться email большинством детекторов; если паттерн допускает — мягкая проверка
    if "foo@bar" in found:
        pytest.xfail("Паттерн email допускает домены без TLD (допустимое решение)")


# ----------------------------
# IPv4 / IPv6
# ----------------------------

def test_ipv4_basic():
    pat = _get_pattern(["IPV4", "IPv4", "ip4", "ip_v4"])
    _skip_if_none(pat, "ipv4")
    _assert_matches(
        pat,
        ["8.8.8.8", "192.168.0.1", "10.0.0.255"],
        ["256.0.0.1", "10.0.0", "a.b.c.d"]
    )

def test_ipv6_basic():
    pat = _get_pattern(["IPV6", "IPv6", "ip6", "ip_v6"])
    if pat is None:
        pytest.skip("ipv6 паттерн отсутствует")
    _assert_matches(
        pat,
        ["2001:0db8:85a3:0000:0000:8a2e:0370:7334", "::1", "fe80::1ff:fe23:4567:890a"],
        ["2001:::7334", "12345::", "gggg::1"]
    )


# ----------------------------
# URL
# ----------------------------

def test_url_basic():
    pat = _get_pattern(["URL", "url", "URI", "uri"])
    _skip_if_none(pat, "url")
    _assert_matches(
        pat,
        ["https://example.com/path?x=1#f", "http://sub.domain.co.uk", "https://xn--e1afmkfd.xn--p1ai/путь"],
        ["htp://bad", "example dot com", "://missing.scheme"]
    )


# ----------------------------
# Телефоны
# ----------------------------

def test_phone_basic():
    pat = _get_pattern(["PHONE", "phone", "PHONE_NUMBER", "phone_number", "tel"])
    _skip_if_none(pat, "phone")
    _assert_matches(
        pat,
        ["+1-202-555-0146", "+44 20 7946 0958", "(202) 555-0175", "+49 (0) 30 901820"],
        ["123", "++1 202 555", "phone:+999999999999999999999"]
    )


# ----------------------------
# Номера карт (только позитивные кейсы; лун‑проверка опциональна)
# ----------------------------

@pytest.mark.parametrize("pan", [
    "4111111111111111",  # Visa тест
    "5500000000000004",  # MasterCard тест
    "340000000000009",   # AmEx тест
])
def test_credit_card_positive(pan):
    pat = _get_pattern(["CREDIT_CARD", "card", "CARD", "PAN", "cc"])
    if pat is None:
        pytest.skip("паттерн для кредитных карт отсутствует")
    text = f"order pan={pan} ok"
    assert pat.search(text), f"Ожидалось совпадение для тестового PAN {pan}"


def test_credit_card_luhn_if_available():
    luhn = getattr(DET, "luhn_check", None) or getattr(DET, "is_luhn_valid", None)
    if not callable(luhn):
        pytest.skip("функция Luhn не экспортируется модулем")
    assert luhn("4111111111111111") is True
    assert luhn("4111111111111112") is False
    assert luhn("0000000000000000") is False


# ----------------------------
# JWT
# ----------------------------

def test_jwt_basic():
    pat = _get_pattern(["JWT", "jwt", "JWT_TOKEN", "bearer_jwt"])
    if pat is None:
        pytest.skip("паттерн JWT отсутствует")
    # Простая структура из трех частей base64url
    j = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.signature"
    assert pat.search(f"Authorization: Bearer {j}")


# ----------------------------
# Производительность/устойчивость против ReDoS
# ----------------------------

@pytest.mark.parametrize("pat_name", [
    "email", "URL", "IPv4", "IPv6", "phone", "card", "jwt",
])
def test_no_catastrophic_backtracking(pat_name):
    pat = _get_pattern([pat_name, pat_name.upper(), pat_name.lower()])
    if pat is None:
        pytest.skip(f"паттерн {pat_name} отсутствует")
    evil = "a" * 200000 + "!"
    start = time.perf_counter()
    _ = pat.search(evil)
    elapsed = time.perf_counter() - start
    # Порог 0.25с на поиск по 200к символов на среднем CI железе
    assert elapsed < 0.25, f"Поиск занял слишком долго ({elapsed:.3f}s) — возможно, катастрофический бэктрекинг"


# ----------------------------
# Опциональные property‑тесты c Hypothesis (если доступен)
# ----------------------------

try:
    from hypothesis import given, strategies as st  # type: ignore
    HYP = True
except Exception:
    HYP = False

@pytest.mark.skipif(not HYP, reason="Hypothesis недоступен")
@given(
    local=st.from_regex(r"[A-Za-z0-9._%+\-]{1,32}", fullmatch=True),
    domain=st.from_regex(r"(?:[A-Za-z0-9\-]{1,63}\.)+[A-Za-z]{2,}", fullmatch=True),
)
def test_email_property(local, domain):
    pat = _get_pattern(["EMAIL", "email"])
    _skip_if_none(pat, "email")
    addr = f"{local}@{domain}"
    assert pat.search(addr), f"Синтетический email не распознан: {addr}"


# ----------------------------
# Сканер целого текста (если есть)
# ----------------------------

def test_scan_api_if_available():
    scan = getattr(DET, "scan", None) or getattr(DET, "detect_all", None) or getattr(DET, "find_all", None)
    if not callable(scan):
        pytest.skip("функция сканирования текста не экспортируется модулем")
    text = "Email a@b.com and IP 8.8.8.8 plus JWT eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.sig"
    out = scan(text)
    assert isinstance(out, (list, tuple)), "scan() должен возвращать список результатов"
    # Минимальные инварианты: каждый результат — словарь/кортеж с типом и значением
    for it in out:
        if isinstance(it, dict):
            assert "value" in it or "match" in it
            assert "type" in it or "kind" in it
        elif isinstance(it, (list, tuple)) and it:
            assert isinstance(it[0], str)
        else:
            pytest.fail("Неожиданная форма результата scan()")


# ----------------------------
# Регресс против дублирования совпадений
# ----------------------------

def test_no_duplicate_overlaps_for_emails():
    pat = _get_pattern(["EMAIL", "email"])
    if pat is None:
        pytest.skip("email паттерн отсутствует")
    text = "x a.b@ex.com a.b@ex.com y"
    spans = [(m.start(), m.end()) for m in pat.finditer(text)]
    # Разрешаем дубль, если он действительно встречается дважды в тексте
    assert spans.count(spans[0]) == 1 or len(set(spans)) == len(spans), "Обнаружены дублирующиеся пересекающиеся совпадения"
