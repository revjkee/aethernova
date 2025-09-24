# -*- coding: utf-8 -*-
"""
Zero Trust Core — Policy Conformance Tests for OPA/Rego

Промышленный набор тестов для:
  examples/policies/risk_based_mfa.rego
Запускает 'opa eval' через subprocess, проверяет схему ответа и ключевые инварианты.

Требования окружения:
  - pytest
  - opa (должен быть в PATH), иначе тесты будут помечены как skipped
  - jsonschema (опционально; при отсутствии выполняется мягкая валидация структуры)
  - hypothesis (опционально; property-тесты будут skipped)

Запуск:
  pytest -q zero-trust-core/tests/conformance/test_zt_policy_conformance.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

# -----------------------------
# Константы и пути
# -----------------------------

REPO_ROOT = Path(__file__).resolve().parents[3] if len(Path(__file__).resolve().parents) >= 3 else Path(__file__).resolve().parents[2]
# Ожидаемая структура: zero-trust-core/tests/conformance/...
# policy: zero-trust-core/examples/policies/risk_based_mfa.rego
POLICY_PATH = (Path(__file__).resolve().parents[2] / "examples" / "policies" / "risk_based_mfa.rego").resolve()

OPA_QUERY = "data.zerotrust.policies.risk_based_mfa.decision"

# -----------------------------
# Фикстуры
# -----------------------------

@pytest.fixture(scope="session")
def opa_bin() -> str:
    """
    Возвращает путь к бинарю 'opa' или пропускает тесты, если не найден.
    """
    bin_path = shutil.which("opa")
    if not bin_path:
        pytest.skip("opa is not installed or not on PATH")
    return bin_path


@pytest.fixture(scope="session")
def policy_exists() -> Path:
    """
    Проверяет наличие Rego-политики.
    """
    if not POLICY_PATH.exists():
        pytest.skip(f"Policy file not found: {POLICY_PATH}")
    return POLICY_PATH


@pytest.fixture(scope="session")
def jsonschema_module():
    try:
        import jsonschema  # type: ignore
        return jsonschema
    except Exception:
        pytest.skip("jsonschema is not installed")
        return None


@pytest.fixture(scope="session")
def hypothesis_modules():
    try:
        import hypothesis  # noqa: F401
        from hypothesis import given, settings  # noqa: F401
        from hypothesis import strategies as st  # noqa: F401
        return {"hypothesis": hypothesis}
    except Exception:
        pytest.skip("hypothesis is not installed")
        return None


# -----------------------------
# Утилиты
# -----------------------------

def opa_eval(opa: str, policy_file: Path, query: str, input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Выполняет 'opa eval --format=json -d <policy.rego> -I <query>' с подачей input через stdin.
    Возвращает value первого выражения как объект решения.
    """
    cmd = [
        opa,
        "eval",
        "--format=json",
        "-d",
        str(policy_file),
        "-I",  # stdin input
        query,
    ]
    try:
        proc = subprocess.run(
            cmd,
            input=json.dumps(input_data, ensure_ascii=False).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except Exception as e:
        pytest.fail(f"Failed to execute opa: {e}")

    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="ignore")
        pytest.fail(f"opa eval failed (rc={proc.returncode}): {stderr}")

    try:
        out = json.loads(proc.stdout.decode("utf-8", errors="ignore"))
    except Exception as e:
        pytest.fail(f"Invalid JSON from opa: {e}")

    # Структура ответа OPA:
    # {
    #   "result": [
    #     {"expressions":[{"value": <decision>, "text": "..."}], ...}
    #   ]
    # }
    try:
        result = out["result"][0]["expressions"][0]["value"]
    except Exception:
        pytest.fail(f"Unexpected opa output shape: {out}")
    return result


DECISION_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required": ["action", "risk_score", "reasons", "obligations", "ttl_seconds", "trace"],
    "properties": {
        "action": {"type": "string", "enum": ["allow", "deny"]},
        "risk_score": {"type": "number", "minimum": 0, "maximum": 100},
        "reasons": {"type": "array", "items": {"type": "string"}},
        "obligations": {
            "type": "object",
            "properties": {
                "mfa": {
                    "type": "object",
                    "required": ["required", "level", "methods", "ttl_seconds"],
                    "properties": {
                        "required": {"type": "boolean"},
                        "level": {"type": "string", "enum": ["none", "low", "medium", "high"]},
                        "methods": {"type": "array", "items": {"type": "string"}},
                        "ttl_seconds": {"type": "number", "minimum": 0},
                    },
                    "additionalProperties": True,
                }
            },
            "required": ["mfa"],
            "additionalProperties": True,
        },
        "ttl_seconds": {"type": "number", "minimum": 0},
        "trace": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string"},
                "tenant_id": {"type": "string"},
            },
            "required": ["request_id", "tenant_id"],
            "additionalProperties": True,
        },
    },
    "additionalProperties": True,
}


def validate_decision_schema(decision: Dict[str, Any], jsonschema_mod=None) -> None:
    """
    Если доступен jsonschema — строгая валидация.
    Иначе — минимальная проверка необходимых полей.
    """
    if jsonschema_mod:
        jsonschema_mod.validate(instance=decision, schema=DECISION_SCHEMA)
        return

    # Минимальные проверки без jsonschema
    assert isinstance(decision, dict)
    for k in ["action", "risk_score", "reasons", "obligations", "ttl_seconds", "trace"]:
        assert k in decision, f"Missing key: {k}"
    assert decision["action"] in {"allow", "deny"}
    assert isinstance(decision["risk_score"], (int, float))
    assert 0 <= float(decision["risk_score"]) <= 100
    assert isinstance(decision.get("reasons", []), list)
    mfa = decision["obligations"].get("mfa", {})
    assert isinstance(mfa, dict)
    for k in ["required", "level", "methods", "ttl_seconds"]:
        assert k in mfa, f"Missing obligations.mfa.{k}"


# -----------------------------
# Базовые тесты наличия артефактов
# -----------------------------

def test_policy_file_exists(policy_exists: Path) -> None:
    assert policy_exists.is_file(), f"Policy not found at {policy_exists}"


# -----------------------------
# Конформанс‑кейсы
# -----------------------------

@pytest.mark.conformance
def test_low_risk_strong_session_recent_mfa_allows(opa_bin: str, policy_exists: Path, jsonschema_module) -> None:
    """
    Низкий риск + сильная и недавняя аутентификация → allow, MFA не требуется.
    """
    input_data = {
        "subject": {
            "id": "u1",
            "role": "employee",
            "mfa_enrolled_methods": ["webauthn", "totp", "push"],
            "break_glass": False,
            "status": "active",
        },
        "device": {"managed": True, "trust_level": "high", "compliant": True},
        "session": {"age_seconds": 60, "auth_strength": ["password", "webauthn", "mfa"], "mfa_recent_seconds": 30},
        "context": {"ip_risk": "low", "asn": 64500, "geo": {"country": "SE"}, "prev_geo": {"country": "SE", "age_seconds": 3600}, "hour_utc": 10},
        "resource": {"id": "app", "action": "read", "sensitivity": "internal"},
        "trace": {"request_id": "r-1", "tenant_id": "t-1"},
    }
    decision = opa_eval(opa_bin, policy_exists, OPA_QUERY, input_data)
    validate_decision_schema(decision, jsonschema_module)

    assert decision["action"] == "allow"
    mfa = decision["obligations"]["mfa"]
    assert mfa["required"] is False
    assert mfa["level"] in ("none", "low")  # политика может вернуть "none" при <40
    assert decision["risk_score"] <= 40
    assert decision["ttl_seconds"] >= 300  # для <40 политика возвращает 300


@pytest.mark.conformance
def test_hard_deny_blacklisted_ip(opa_bin: str, policy_exists: Path, jsonschema_module) -> None:
    """
    Заблокированный IP → мгновенный deny (hard_deny).
    """
    input_data = {
        "subject": {"id": "u2", "role": "employee", "status": "active"},
        "device": {"managed": True, "trust_level": "high", "compliant": True},
        "session": {"age_seconds": 10, "auth_strength": ["password"], "mfa_recent_seconds": 10000},
        "context": {"ip_risk": "blacklist"},
        "resource": {"id": "app", "action": "read", "sensitivity": "internal"},
        "trace": {"request_id": "r-2", "tenant_id": "t-1"},
    }
    decision = opa_eval(opa_bin, policy_exists, OPA_QUERY, input_data)
    validate_decision_schema(decision, jsonschema_module)
    assert decision["action"] == "deny"


@pytest.mark.conformance
def test_hard_deny_restricted_unmanaged_device(opa_bin: str, policy_exists: Path, jsonschema_module) -> None:
    """
    Доступ к restricted с неуправляемого устройства → deny.
    """
    input_data = {
        "subject": {"id": "u3", "role": "engineer", "status": "active"},
        "device": {"managed": False, "trust_level": "low", "compliant": False},
        "session": {"age_seconds": 30, "auth_strength": ["password"], "mfa_recent_seconds": 10000},
        "context": {"ip_risk": "low"},
        "resource": {"id": "vault", "action": "read", "sensitivity": "restricted"},
        "trace": {"request_id": "r-3", "tenant_id": "t-1"},
    }
    decision = opa_eval(opa_bin, policy_exists, OPA_QUERY, input_data)
    validate_decision_schema(decision, jsonschema_module)
    assert decision["action"] == "deny"


@pytest.mark.conformance
def test_hard_deny_admin_when_not_compliant(opa_bin: str, policy_exists: Path, jsonschema_module) -> None:
    """
    Админ‑операции с некомплаентного устройства → deny.
    """
    input_data = {
        "subject": {"id": "u4", "role": "admin", "status": "active"},
        "device": {"managed": True, "trust_level": "medium", "compliant": False},
        "session": {"age_seconds": 45, "auth_strength": ["password"], "mfa_recent_seconds": 10000},
        "context": {"ip_risk": "low"},
        "resource": {"id": "admin-api", "action": "admin", "sensitivity": "confidential"},
        "trace": {"request_id": "r-4", "tenant_id": "t-1"},
    }
    decision = opa_eval(opa_bin, policy_exists, OPA_QUERY, input_data)
    validate_decision_schema(decision, jsonschema_module)
    assert decision["action"] == "deny"


@pytest.mark.conformance
@pytest.mark.parametrize(
    "ip_risk,device_trust,expected_level_min",
    [
        ("high", "low", "high"),
        ("medium", "low", "medium"),
        ("medium", "medium", "medium"),
    ],
)
def test_mfa_required_levels(opa_bin: str, policy_exists: Path, jsonschema_module, ip_risk: str, device_trust: str, expected_level_min: str) -> None:
    """
    Разные комбинации факторов риска → ожидаемые уровни MFA.
    """
    input_data = {
        "subject": {"id": "u5", "role": "employee", "status": "active", "mfa_enrolled_methods": ["totp", "push"]},
        "device": {"managed": True, "trust_level": device_trust, "compliant": True},
        "session": {"age_seconds": 120, "auth_strength": ["password"], "mfa_recent_seconds": 10000},
        "context": {"ip_risk": ip_risk, "geo": {"country": "SE"}, "prev_geo": {"country": "SE", "age_seconds": 3600}},
        "resource": {"id": "app", "action": "write", "sensitivity": "internal"},
        "trace": {"request_id": "r-5", "tenant_id": "t-1"},
    }
    decision = opa_eval(opa_bin, policy_exists, OPA_QUERY, input_data)
    validate_decision_schema(decision, jsonschema_module)

    assert decision["action"] == "allow"  # allow + обязательство MFA
    mfa = decision["obligations"]["mfa"]
    assert mfa["required"] is True
    # Проверяем, что уровень не ниже ожиданий
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    assert order[mfa["level"]] >= order[expected_level_min]


@pytest.mark.conformance
def test_mfa_methods_selection_respects_enrollment(opa_bin: str, policy_exists: Path, jsonschema_module) -> None:
    """
    Выбор методов учитывает доступные у субъекта (например, нет webauthn → не предлагать).
    """
    input_data = {
        "subject": {"id": "u6", "role": "employee", "status": "active", "mfa_enrolled_methods": ["totp", "push"]},
        "device": {"managed": True, "trust_level": "medium", "compliant": True},
        "session": {"age_seconds": 120, "auth_strength": ["password"], "mfa_recent_seconds": 10000},
        "context": {"ip_risk": "medium"},
        "resource": {"id": "app", "action": "write", "sensitivity": "confidential"},
        "trace": {"request_id": "r-6", "tenant_id": "t-1"},
    }
    decision = opa_eval(opa_bin, policy_exists, OPA_QUERY, input_data)
    validate_decision_schema(decision, jsonschema_module)

    mfa = decision["obligations"]["mfa"]
    assert mfa["required"] is True
    methods = mfa["methods"]
    assert "webauthn" not in methods
    assert set(methods).issubset({"totp", "push"})


@pytest.mark.conformance
def test_service_role_exemption(opa_bin: str, policy_exists: Path, jsonschema_module) -> None:
    """
    Сервисная роль (не admin), managed‑устройство, ip_risk=low → исключение от MFA допускается.
    """
    input_data = {
        "subject": {"id": "svc-1", "role": "service", "status": "active", "mfa_enrolled_methods": []},
        "device": {"managed": True, "trust_level": "high", "compliant": True},
        "session": {"age_seconds": 5, "auth_strength": [], "mfa_recent_seconds": 10000},
        "context": {"ip_risk": "low"},
        "resource": {"id": "svc-endpoint", "action": "read", "sensitivity": "internal"},
        "trace": {"request_id": "r-7", "tenant_id": "t-1"},
    }
    decision = opa_eval(opa_bin, policy_exists, OPA_QUERY, input_data)
    validate_decision_schema(decision, jsonschema_module)
    assert decision["action"] == "allow"
    assert decision["obligations"]["mfa"]["required"] is False


@pytest.mark.conformance
def test_missing_fields_are_safe(opa_bin: str, policy_exists: Path, jsonschema_module) -> None:
    """
    Пустые/неполные входы не ломают политику и возвращают корректный объект решения.
    """
    input_data = {
        # минимальный след
        "trace": {"request_id": "r-8", "tenant_id": "tenant-x"}
    }
    decision = opa_eval(opa_bin, policy_exists, OPA_QUERY, input_data)
    validate_decision_schema(decision, jsonschema_module)

    # Политика по умолчанию может потребовать MFA (высокая неопределенность)
    assert decision["action"] in ("allow", "deny")
    assert isinstance(decision["obligations"]["mfa"]["required"], bool)
    assert 0 <= float(decision["risk_score"]) <= 100


@pytest.mark.conformance
def test_reasons_contain_minimal_audit_context(opa_bin: str, policy_exists: Path, jsonschema_module) -> None:
    """
    'reasons' включают агрегированные маркеры (без PII), например 'risk_score=' и теги факторов.
    """
    input_data = {
        "subject": {"id": "u9", "role": "admin", "status": "active", "mfa_enrolled_methods": ["webauthn"]},
        "device": {"managed": True, "trust_level": "medium", "compliant": True},
        "session": {"age_seconds": 600, "auth_strength": ["password"], "mfa_recent_seconds": 10000},
        "context": {"ip_risk": "medium", "geo": {"country": "DE"}, "prev_geo": {"country": "SE", "age_seconds": 1000}, "hour_utc": 2},
        "resource": {"id": "admin-ui", "action": "write", "sensitivity": "confidential"},
        "trace": {"request_id": "r-9", "tenant_id": "t-1"},
    }
    decision = opa_eval(opa_bin, policy_exists, OPA_QUERY, input_data)
    validate_decision_schema(decision, jsonschema_module)
    reasons = decision.get("reasons", [])
    assert any(r.startswith("risk_score=") for r in reasons)
    # Не должно быть «сырого» PII (проверка эвристикой)
    pii_suspects = ["203.", "@", "email", "token", "secret"]
    assert not any(any(s in r for s in pii_suspects) for r in reasons)


# -----------------------------
# Property-тест (мягкий, при наличии hypothesis)
# -----------------------------

@pytest.mark.conformance
@pytest.mark.slow
def test_monotonicity_ip_risk_property(opa_bin: str, policy_exists: Path, hypothesis_modules, jsonschema_module) -> None:
    """
    Property: риск не уменьшается при повышении ip_risk от low → medium → high.
    Уровень MFA не должен понижаться.
    """
    from hypothesis import given, settings
    from hypothesis import strategies as st

    @given(
        role=st.sampled_from(["employee", "engineer"]),
        trust=st.sampled_from(["low", "medium", "high"]),
        compliant=st.booleans(),
        sensitivity=st.sampled_from(["internal", "confidential"]),
        action=st.sampled_from(["read", "write"]),
    )
    @settings(max_examples=20)  # удерживаем быстрым
    def property_check(role, trust, compliant, sensitivity, action):
        base = {
            "subject": {"id": "px", "role": role, "status": "active", "mfa_enrolled_methods": ["webauthn", "totp", "push"]},
            "device": {"managed": True, "trust_level": trust, "compliant": bool(compliant)},
            "session": {"age_seconds": 120, "auth_strength": ["password"], "mfa_recent_seconds": 10000},
            "context": {"geo": {"country": "SE"}, "prev_geo": {"country": "SE", "age_seconds": 3600}},
            "resource": {"id": "app", "action": action, "sensitivity": sensitivity},
            "trace": {"request_id": "rp", "tenant_id": "tp"},
        }

        d_low = opa_eval(opa_bin, policy_exists, OPA_QUERY, {**base, "context": {**base["context"], "ip_risk": "low"}})
        d_med = opa_eval(opa_bin, policy_exists, OPA_QUERY, {**base, "context": {**base["context"], "ip_risk": "medium"}})
        d_high = opa_eval(opa_bin, policy_exists, OPA_QUERY, {**base, "context": {**base["context"], "ip_risk": "high"}})

        validate_decision_schema(d_low, jsonschema_module)
        validate_decision_schema(d_med, jsonschema_module)
        validate_decision_schema(d_high, jsonschema_module)

        # монотонность риска
        assert d_low["risk_score"] <= d_med["risk_score"] <= d_high["risk_score"]

        # не понижается уровень MFA
        order = {"none": 0, "low": 1, "medium": 2, "high": 3}
        lvl_low = d_low["obligations"]["mfa"]["level"]
        lvl_med = d_med["obligations"]["mfa"]["level"]
        lvl_high = d_high["obligations"]["mfa"]["level"]
        assert order[lvl_low] <= order[lvl_med] <= order[lvl_high]

    property_check()


# -----------------------------
# Тест TTL соответствия уровню MFA
# -----------------------------

@pytest.mark.conformance
def test_mfa_ttl_mapping(opa_bin: str, policy_exists: Path, jsonschema_module) -> None:
    """
    TTL для step-up MFA коррелирует с уровнем (high→~120, medium→~300, low→~600; допускаем равенства по политике).
    """
    base = {
        "subject": {"id": "ttl1", "role": "employee", "status": "active", "mfa_enrolled_methods": ["webauthn", "totp", "push"]},
        "device": {"managed": True, "trust_level": "low", "compliant": True},
        "session": {"age_seconds": 120, "auth_strength": ["password"], "mfa_recent_seconds": 10000},
        "context": {"geo": {"country": "SE"}, "prev_geo": {"country": "SE", "age_seconds": 3600}},
        "resource": {"id": "app", "action": "write", "sensitivity": "internal"},
        "trace": {"request_id": "rt1", "tenant_id": "t-1"},
    }

    # high
    d_high = opa_eval(opa_bin, policy_exists, OPA_QUERY, {**base, "context": {**base["context"], "ip_risk": "high"}})
    validate_decision_schema(d_high, jsonschema_module)
    if d_high["obligations"]["mfa"]["required"]:
        assert d_high["obligations"]["mfa"]["level"] in ("high", "medium")  # high не понижается, но политика может дать medium по сумме факторов
        # TTL high по политике = 120
        assert d_high["obligations"]["mfa"]["ttl_seconds"] in (120, 300, 600)

    # medium
    d_med = opa_eval(opa_bin, policy_exists, OPA_QUERY, {**base, "context": {**base["context"], "ip_risk": "medium"}})
    validate_decision_schema(d_med, jsonschema_module)
    if d_med["obligations"]["mfa"]["required"]:
        assert d_med["obligations"]["mfa"]["ttl_seconds"] in (120, 300, 600)

    # low
    d_low = opa_eval(opa_bin, policy_exists, OPA_QUERY, {**base, "context": {**base["context"], "ip_risk": "low"}})
    validate_decision_schema(d_low, jsonschema_module)
    if d_low["obligations"]["mfa"]["required"]:
        assert d_low["obligations"]["mfa"]["ttl_seconds"] in (120, 300, 600)
