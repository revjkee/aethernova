# path: core-systems/genius_core/security/self_inhibitor/tests/unit/test_rules_validation.py
from __future__ import annotations

import os
import re
import sys
import time
import threading
from typing import Any, Dict, List, Optional

import pytest

try:
    import yaml  # type: ignore
except Exception as e:
    pytest.skip(f"PyYAML is required for rules validation tests: {e!r}", allow_module_level=True)


# -------------------------
# Путь к YAML с правилами
# -------------------------

def rules_yaml_path() -> str:
    # tests/unit/ -> ../../rules/sensitive_patterns.yaml
    here = os.path.dirname(__file__)
    path = os.path.abspath(
        os.path.join(
            here,
            "..", "..",
            "rules",
            "sensitive_patterns.yaml",
        )
    )
    if not os.path.exists(path):
        # Альтернативный путь из корня репозитория
        alt = os.path.abspath(
            os.path.join(
                here,
                "..", "..", "..", "..",
                "rules",
                "sensitive_patterns.yaml",
            )
        )
        if os.path.exists(alt):
            return alt
    return path


# -------------------------
# Утилиты
# -------------------------

SEVERITIES = {"low", "medium", "high", "critical"}
CONFIDENCE = {"low", "medium", "high"}

DEFAULT_FLAG_MAP = {
    "case_insensitive": re.IGNORECASE,
    "multiline": re.MULTILINE,
    "dotall": re.DOTALL,
}

def _collect_flags(defaults: Dict[str, Any]) -> int:
    flags = 0
    for f in (defaults or {}).get("flags", []):
        flags |= DEFAULT_FLAG_MAP.get(str(f).lower(), 0)
    return flags

def _load_rules() -> Dict[str, Any]:
    path = rules_yaml_path()
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert isinstance(data, dict), "Top-level YAML must be a mapping"
    return data

def _iter_rule_items(data: Dict[str, Any]):
    for grp in data.get("rules", []) or []:
        items = grp.get("items", []) or []
        for it in items:
            yield it, grp

def _search_with_timeout(regex: re.Pattern, text: str, timeout_s: float) -> bool:
    """
    Выполняет regex.search в отдельном потоке с таймаутом.
    Возвращает True/False по факту завершения поиска (а не по совпадению).
    """
    done = {"ok": False}

    def _run():
        try:
            _ = regex.search(text)
            done["ok"] = True
        except Exception:
            done["ok"] = True

    th = threading.Thread(target=_run, daemon=True)
    th.start()
    th.join(timeout_s)
    return done["ok"]

def _luhn_ok(num: str) -> bool:
    digits = [int(c) for c in num if c.isdigit()]
    if len(digits) < 12:
        return False
    s = 0
    odd = len(digits) % 2 == 0
    for i, d in enumerate(digits):
        if (i % 2 == 0) == odd:
            d = d * 2
            if d > 9:
                d -= 9
        s += d
    return s % 10 == 0


# -------------------------
# Тесты схемы и структуры
# -------------------------

def test_yaml_loads_and_schema():
    data = _load_rules()
    assert data.get("version") in (1, "1")
    schema = data.get("schema")
    assert isinstance(schema, str) and schema.endswith(".v1")
    meta = data.get("metadata") or {}
    assert isinstance(meta.get("owner"), str) and meta.get("owner")
    assert isinstance(meta.get("description"), str) and meta.get("description")
    defaults = data.get("defaults") or {}
    assert "actions" in defaults and "redaction" in defaults
    allowlist = data.get("allowlist") or {}
    # allowlist может быть пустым, но если задан — проверим типы
    if "keys_regex" in allowlist:
        assert isinstance(allowlist["keys_regex"], list)


def test_allowlist_regexes_compile():
    data = _load_rules()
    allowlist = data.get("allowlist") or {}
    flags = _collect_flags(data.get("defaults") or {})
    for pat in allowlist.get("keys_regex", []) or []:
        assert isinstance(pat, str) and pat.strip(), "allowlist.keys_regex must be non-empty strings"
        re.compile(pat, flags)


def test_rules_ids_unique_and_required_fields():
    data = _load_rules()
    flags = _collect_flags(data.get("defaults") or {})
    seen_ids = set()
    total = 0
    for rule, grp in _iter_rule_items(data):
        total += 1
        rid = rule.get("id")
        assert isinstance(rid, str) and rid.strip(), "rule id is required"
        assert rid not in seen_ids, f"duplicate rule id: {rid}"
        seen_ids.add(rid)

        # Обязательные поля
        assert isinstance(rule.get("name"), str) and rule["name"].strip(), f"{rid}: name required"
        assert isinstance(rule.get("pattern"), str) and rule["pattern"].strip(), f"{rid}: pattern required"
        assert rule.get("severity") in SEVERITIES, f"{rid}: severity must be one of {SEVERITIES}"
        assert rule.get("confidence") in CONFIDENCE, f"{rid}: confidence must be one of {CONFIDENCE}"
        tags = rule.get("tags")
        assert isinstance(tags, list) and all(isinstance(t, str) for t in tags) and tags, f"{rid}: tags must be non-empty list"

        # Компиляция основного паттерна
        re.compile(rule["pattern"], flags)

        # Компиляция контекста, если есть
        ctx = rule.get("context") or {}
        if "key_regex" in ctx:
            re.compile(ctx["key_regex"], flags)

    assert total > 0, "no rules found in YAML"


def test_examples_match_and_nomatch_behaviour():
    data = _load_rules()
    flags = _collect_flags(data.get("defaults") or {})
    tested = 0
    for rule, _ in _iter_rule_items(data):
        examples = rule.get("examples") or {}
        if not examples:
            continue
        reg = re.compile(rule["pattern"], flags)
        for s in examples.get("match", []) or []:
            assert reg.search(s) is not None, f"{rule['id']}: expected to match example: {s!r}"
            tested += 1
        for s in examples.get("nomatch", []) or []:
            assert reg.search(s) is None, f"{rule['id']}: expected not to match: {s!r}"
            tested += 1
    # Если примеры есть — хотя бы что-то протестировали
    if any((rule.get("examples") for rule, _ in _iter_rule_items(data))):
        assert tested > 0


def test_credit_card_rule_has_luhn_and_detects_valid_cards():
    data = _load_rules()
    flags = _collect_flags(data.get("defaults") or {})
    cc_rule = None
    for rule, _ in _iter_rule_items(data):
        if rule.get("id") == "CREDIT_CARD":
            cc_rule = rule
            break
    if cc_rule is None:
        pytest.skip("CREDIT_CARD rule not present")
    assert cc_rule.get("post_validation") == "luhn", "CREDIT_CARD rule should specify post_validation: luhn"
    reg = re.compile(cc_rule["pattern"], flags)

    valid = [
        "4111111111111111",
        "4242424242424242",
        "5555555555554444",
        "378282246310005",
    ]
    invalid = [
        "4111111111111121",
        "1234567890123456",
        "0000000000000000",
    ]

    for num in valid:
        m = reg.search(num)
        assert m, f"valid test number should match pattern: {num}"
        assert _luhn_ok(num), f"valid test number must pass Luhn: {num}"

    for num in invalid:
        # Может матчиться по шаблону, но Лун не должен проходить
        _ = reg.search(num)  # допускаем совпадение
        assert not _luhn_ok(num), f"invalid test number must fail Luhn: {num}"


@pytest.mark.slow
def test_regexes_do_not_exhibit_extreme_backtracking():
    """
    Грубая проверка производительности: каждое выражение проверяется на большой строке.
    Тест провалится, если поиск не завершится за разумное время (по умолчанию 2.0s на выражение).
    """
    data = _load_rules()
    flags = _collect_flags(data.get("defaults") or {})
    big = "A" * 200_000
    timeout_s = float(os.getenv("RULES_REGEX_TIMEOUT_S", "2.0"))
    worst: List[str] = []

    for rule, _ in _iter_rule_items(data):
        pat = rule["pattern"]
        r = re.compile(pat, flags)
        ok = _search_with_timeout(r, big, timeout_s)
        if not ok:
            worst.append(rule.get("id", pat[:30]))

    assert not worst, f"regex timeout for: {', '.join(worst)}"


def test_boundaries_and_optional_fields_are_well_formed():
    """
    Не все движки используют эти поля, но мы проверяем корректность значений,
    чтобы избежать опечаток в YAML.
    """
    data = _load_rules()
    valid_boundaries = {None, "word"}
    for rule, _ in _iter_rule_items(data):
        b = rule.get("boundaries")
        assert b in valid_boundaries, f"{rule.get('id')}: unknown boundaries={b!r}"

        # Проверяем, что redaction если задан — содержит replacement
        red = rule.get("redaction")
        if red is not None:
            assert isinstance(red.get("replacement"), str) and red["replacement"], f"{rule.get('id')}: redaction.replacement must be set"
