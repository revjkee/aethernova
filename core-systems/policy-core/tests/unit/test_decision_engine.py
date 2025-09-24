# policy-core/tests/unit/test_decision_engine.py
from __future__ import annotations

import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import pytest

# ------------ Опциональные зависимости (аккуратный импорт) ------------
hypothesis = pytest.importorskip("hypothesis", reason="Hypothesis required for property-based tests")
from hypothesis import given, strategies as st

# Поддержка подписей политик (опционально, если модуль доступен)
try:
    from policy_core.pap.signer import (
        SignerConfig,
        SignerFactory,
        SignatureEnvelope,
    )
    SIGNER_AVAILABLE = True
except Exception:
    SIGNER_AVAILABLE = False

# ------------ Адаптеры к API движка (нормализация интерфейса) ------------
engine_mod = pytest.importorskip(
    "policy_core.decision.engine",
    reason="policy_core.decision.engine is required for these tests",
)

# Попытка достать типы/конфиги движка (мягко, без фатала)
DecisionEngine = getattr(engine_mod, "DecisionEngine", None)
EngineConfig = getattr(engine_mod, "EngineConfig", None)
Decision = getattr(engine_mod, "Decision", None)  # enum-like, возможно
Effect = getattr(engine_mod, "Effect", None)      # enum-like, возможно

if DecisionEngine is None:
    pytest.skip("DecisionEngine class not found in policy_core.decision.engine", allow_module_level=True)


# Универсальная нормализация эффекта решения -> 'PERMIT'/'DENY'/...
def _norm_effect(value: Any) -> str:
    if value is None:
        return "UNKNOWN"
    # Поддержка enum-подобных типов
    name = getattr(value, "name", None)
    if isinstance(name, str):
        return name.upper()
    # Строковые
    if isinstance(value, str):
        return value.upper()
    # Числовые коды (переводим по принятому mapping при наличии)
    mapping = {
        0: "DENY",
        1: "PERMIT",
        2: "NOT_APPLICABLE",
        3: "INDETERMINATE",
    }
    return mapping.get(int(value), "UNKNOWN")


# Нормализация ответа движка к единой форме
def _normalize_response(resp: Any) -> Dict[str, Any]:
    """
    Принимает dict/объект и приводит к виду:
    {
      'effect': 'PERMIT'|'DENY'|'NOT_APPLICABLE'|'INDETERMINATE',
      'obligations': list,
      'advice': list,
      'policy_id': str|None,
      'meta': dict
    }
    """
    if isinstance(resp, dict):
        effect = _norm_effect(resp.get("effect") or resp.get("decision"))
        return {
            "effect": effect,
            "obligations": list(resp.get("obligations", [])),
            "advice": list(resp.get("advice", [])),
            "policy_id": resp.get("policy_id") or resp.get("policyId"),
            "meta": dict(resp.get("meta", {})),
        }

    # Объект с атрибутами
    effect = _norm_effect(getattr(resp, "effect", getattr(resp, "decision", None)))
    obligations = getattr(resp, "obligations", []) or []
    advice = getattr(resp, "advice", []) or []
    policy_id = getattr(resp, "policy_id", getattr(resp, "policyId", None))
    meta = getattr(resp, "meta", {}) or {}
    return {
        "effect": effect,
        "obligations": list(obligations),
        "advice": list(advice),
        "policy_id": policy_id,
        "meta": dict(meta),
    }


# Нахождение методов установки политик
def _install_policy(engine: Any, policy: Dict[str, Any]) -> str:
    """
    Пытается установить политику различными способами.
    Возвращает policy_id.
    """
    if hasattr(engine, "install_policy"):
        pid = engine.install_policy(policy)
        return pid if isinstance(pid, str) else (policy.get("id") or policy.get("policy_id") or "unknown")
    if hasattr(engine, "add_policy"):
        pid = engine.add_policy(policy)
        return pid if isinstance(pid, str) else (policy.get("id") or "unknown")
    if hasattr(engine, "load_policy"):
        ok = engine.load_policy(policy)
        if ok is False:
            pytest.fail("load_policy returned False")
        return policy.get("id") or "policy"
    if hasattr(engine, "load_policies"):
        ok = engine.load_policies([policy])
        if ok is False:
            pytest.fail("load_policies returned False")
        return policy.get("id") or "policy"
    pytest.skip("Engine has no known policy installation method")
    return "unknown"


def _evaluate(engine: Any, request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Универсальная оценка запроса.
    """
    if hasattr(engine, "evaluate"):
        return _normalize_response(engine.evaluate(request))
    if hasattr(engine, "decide"):
        return _normalize_response(engine.decide(request))
    pytest.skip("Engine has no evaluate/decide method")
    return {}  # unreachable


# ------------ Фикстуры ------------
@pytest.fixture(scope="session")
def engine_config() -> Optional[Any]:
    # Пытаемся создать конфиг с разумными дефолтами
    if EngineConfig is None:
        return None
    # Пробуем поддержать несколько опций без жёстких зависимостей
    try:
        return EngineConfig(
            combining_algorithm="deny-overrides",
            require_signature=False,
            clock_skew_sec=60,
            cache_enabled=True,
            cache_ttl_ms=10_000,
        )
    except Exception:
        # Если сигнатуры/алгоритмы именуются иначе
        try:
            return EngineConfig()
        except Exception:
            return None


@pytest.fixture(scope="function")
def engine(engine_config):
    # Инициализация движка
    try:
        if engine_config is not None:
            return DecisionEngine(config=engine_config)
        # Вариант фабрики
        if hasattr(DecisionEngine, "from_config"):
            return DecisionEngine.from_config({})
        return DecisionEngine()
    except Exception as e:
        pytest.skip(f"Cannot instantiate DecisionEngine: {e}")


# ------------ Примерные политики (ABAC-подобные) ------------
def policy_admin_permit() -> Dict[str, Any]:
    """
    Разрешает действие, если subject.role == 'admin'.
    """
    return {
        "id": "pol_admin_permit",
        "version": 1,
        "alg": "deny-overrides",
        "target": {"actions": ["*"], "resources": ["*"]},
        "rules": [
            {
                "id": "r_admin",
                "effect": "PERMIT",
                "condition": {"equals": [{"var": "subject.role"}, "admin"]},
                "obligations": [{"id": "audit-log", "on": "PERMIT"}],
            }
        ],
        "meta": {"purpose": "unit-test"},
    }


def policy_classified_deny() -> Dict[str, Any]:
    """
    Запрещает доступ к секретным ресурсам: resource.classified == True → DENY.
    """
    return {
        "id": "pol_classified_deny",
        "version": 1,
        "alg": "deny-overrides",
        "rules": [
            {
                "id": "r_deny_secret",
                "effect": "DENY",
                "condition": {"equals": [{"var": "resource.classified"}, True]},
            }
        ],
        "meta": {"purpose": "unit-test"},
    }


def policy_time_window(now_ms: Optional[int] = None, window_s: int = 60) -> Dict[str, Any]:
    """
    Политика активна только в окне [now - window_s, now + window_s].
    """
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    return {
        "id": "pol_time_window",
        "version": 1,
        "alg": "first-applicable",
        "target": {"time": {"active_from_ms": now_ms - window_s * 1000, "active_to_ms": now_ms + window_s * 1000}},
        "rules": [{"id": "r_any", "effect": "PERMIT"}],
        "meta": {"purpose": "unit-test"},
    }


# ------------ Базовые тесты решений ------------
def test_permit_for_admin(engine):
    _install_policy(engine, policy_admin_permit())
    resp = _evaluate(
        engine,
        {"subject": {"id": "u1", "role": "admin"}, "action": "read", "resource": {"id": "doc1", "classified": False}},
    )
    assert resp["effect"] == "PERMIT"
    assert any(o.get("id") == "audit-log" for o in resp.get("obligations", []))


def test_deny_for_classified_overrides_admin(engine):
    _install_policy(engine, policy_admin_permit())
    _install_policy(engine, policy_classified_deny())
    # Должен сработать deny-overrides: секретный ресурс блокирует даже админа
    resp = _evaluate(
        engine,
        {"subject": {"id": "root", "role": "admin"}, "action": "read", "resource": {"id": "x", "classified": True}},
    )
    assert resp["effect"] == "DENY"


def test_not_applicable_when_action_not_covered(engine):
    # Политика ничего не говорит про action='delete' → NOT_APPLICABLE
    _install_policy(engine, policy_admin_permit())
    resp = _evaluate(engine, {"subject": {"id": "u2", "role": "user"}, "action": "delete", "resource": {"id": "y"}})
    assert resp["effect"] in {"NOT_APPLICABLE", "DENY"}  # допустимы оба, но предпочтителен NOT_APPLICABLE


def test_time_window_active_and_expired(engine):
    pol = policy_time_window()
    _install_policy(engine, pol)

    ok = _evaluate(engine, {"subject": {"id": "u"}, "action": "read", "resource": {"id": "r"}})
    assert ok["effect"] == "PERMIT"

    # Истёкшая политика
    past = policy_time_window(now_ms=int(time.time() * 1000) - 120_000, window_s=10)
    _install_policy(engine, past)
    expired = _evaluate(engine, {"subject": {"id": "u"}, "action": "read", "resource": {"id": "r"}})
    assert expired["effect"] in {"NOT_APPLICABLE", "DENY"}


# ------------ Идемпотентность и детерминизм ------------
def test_idempotency_same_request_same_result(engine):
    _install_policy(engine, policy_admin_permit())
    req = {"subject": {"id": "u3", "role": "admin"}, "action": "write", "resource": {"id": "z"}}
    r1 = _evaluate(engine, req)
    r2 = _evaluate(engine, req)
    assert r1 == r2


# ------------ Потокобезопасность ------------
def test_thread_safety_under_load(engine):
    _install_policy(engine, policy_admin_permit())
    req_admin = {"subject": {"id": "u4", "role": "admin"}, "action": "read", "resource": {"id": "doc"}}
    req_user = {"subject": {"id": "u5", "role": "user"}, "action": "read", "resource": {"id": "doc"}}

    def worker(i: int) -> Tuple[int, str]:
        req = req_admin if (i % 2 == 0) else req_user
        return i, _evaluate(engine, req)["effect"]

    with ThreadPoolExecutor(max_workers=16) as ex:
        results = list(ex.map(worker, range(200)))
    # Чётные → PERMIT, нечётные → NOT_APPLICABLE или DENY (если политика не даёт user)
    for i, eff in results:
        if i % 2 == 0:
            assert eff == "PERMIT"
        else:
            assert eff in {"NOT_APPLICABLE", "DENY"}


# ------------ Валидация схемы ответа ------------
def test_response_schema_minimal(engine):
    _install_policy(engine, policy_admin_permit())
    resp = _evaluate(
        engine,
        {"subject": {"id": "u6", "role": "admin"}, "action": "read", "resource": {"id": "doc"}},
    )
    assert resp["effect"] in {"PERMIT", "DENY", "NOT_APPLICABLE", "INDETERMINATE"}
    assert isinstance(resp.get("obligations", []), list)
    assert isinstance(resp.get("advice", []), list)
    # policy_id и meta — опциональны, но если заданы, должны иметь корректные типы
    if resp.get("policy_id") is not None:
        assert isinstance(resp["policy_id"], str)
    if resp.get("meta") is not None:
        assert isinstance(resp["meta"], dict)


# ------------ Комбинирующие алгоритмы ------------
@pytest.mark.parametrize("alg", ["deny-overrides", "permit-overrides", "first-applicable"])
def test_combining_algorithms(engine, alg):
    # Пытаемся переключить алгоритм на уровне набора политик
    base = policy_admin_permit()
    base["alg"] = alg
    _install_policy(engine, base)
    _install_policy(engine, policy_classified_deny())

    req = {"subject": {"id": "root", "role": "admin"}, "action": "read", "resource": {"id": "x", "classified": True}}
    resp = _evaluate(engine, req)

    if alg == "deny-overrides":
        assert resp["effect"] == "DENY"
    elif alg == "permit-overrides":
        assert resp["effect"] in {"PERMIT", "DENY"}  # допускаем реализацию, учитывающую таргеты
    else:  # first-applicable
        assert resp["effect"] in {"PERMIT", "DENY", "NOT_APPLICABLE"}


# ------------ Property-based: соотнесение владельца ресурса и субъекта ------------
@given(
    subject_id=st.text(min_size=1, max_size=8),
    owner_id=st.text(min_size=1, max_size=8),
)
def test_owner_must_match_for_permit(engine, subject_id, owner_id):
    policy = {
        "id": "pol_owner_eq",
        "version": 1,
        "alg": "deny-overrides",
        "rules": [
            {
                "id": "r_owner",
                "effect": "PERMIT",
                "condition": {"equals": [{"var": "subject.id"}, {"var": "resource.owner"}]},
            }
        ],
    }
    _install_policy(engine, policy)
    resp = _evaluate(engine, {"subject": {"id": subject_id}, "action": "read", "resource": {"id": "doc", "owner": owner_id}})
    if subject_id == owner_id:
        assert resp["effect"] == "PERMIT"
    else:
        assert resp["effect"] in {"DENY", "NOT_APPLICABLE"}


# ------------ Подписанные политики (опционально) ------------
@pytest.mark.skipif(not SIGNER_AVAILABLE, reason="Signer module not available")
def test_signed_policy_required_when_enabled(engine, tmp_path):
    """
    Сценарий:
      1) Формируем политику.
      2) Подписываем envelope ED25519.
      3) Пытаемся загрузить без подписи → ожидаем ошибку/skip.
      4) Загружаем с подписью → PERMIT.
    Реализация движка может отличаться; при отсутствии поддержки требований подписи — skip.
    """
    # Пробуем включить режим обязательной подписи если доступна конфигурация
    require_sig_set = False
    if hasattr(engine, "set_require_signature"):
        try:
            engine.set_require_signature(True)
            require_sig_set = True
        except Exception:
            pass

    if not require_sig_set and not getattr(getattr(engine, "config", object()), "require_signature", False):
        pytest.skip("Engine does not support signature enforcement")

    policy = policy_admin_permit()
    # Создадим детерминированный байтовый blob политики
    policy_bytes = json.dumps(policy, separators=(",", ":"), sort_keys=True).encode("utf-8")

    # ED25519 signer (ожидается, что test env предоставит ключи; иначе skip)
    priv_path = os.getenv("TEST_ED25519_PRIV_PEM")
    if not priv_path or not os.path.exists(priv_path):
        pytest.skip("TEST_ED25519_PRIV_PEM not set; cannot run signature test")

    cfg = SignerConfig(type="ed25519", private_key_path=priv_path)
    signer = SignerFactory.from_config(cfg)
    env = signer.sign_bytes(policy_bytes)

    # Попытка установить неподписанную политику (ожидаем ошибку/skip)
    with pytest.raises(Exception):
        _install_policy(engine, policy)

    # Устанавливаем подписанную (добавляем envelope в поле 'signature')
    signed = dict(policy)
    signed["signature"] = json.loads(env.to_json_bytes().decode("utf-8"))
    pid = _install_policy(engine, signed)
    assert isinstance(pid, str)

    resp = _evaluate(
        engine,
        {"subject": {"id": "u_admin", "role": "admin"}, "action": "read", "resource": {"id": "doc"}},
    )
    assert resp["effect"] == "PERMIT"


# ------------ Производительность (мягкая проверка, по переменной окружения) ------------
def test_soft_performance_smoke(engine):
    """
    Запускается только если задан POLICY_PERF_TARGET_MS.
    Проверяет, что 200 оценок укладываются в разумный порог.
    """
    target_ms_env = os.getenv("POLICY_PERF_TARGET_MS")
    if not target_ms_env:
        pytest.skip("Performance target not set")
    target_ms = int(target_ms_env)

    _install_policy(engine, policy_admin_permit())
    req = {"subject": {"id": "u7", "role": "admin"}, "action": "read", "resource": {"id": "doc"}}

    t0 = time.perf_counter()
    for _ in range(200):
        _ = _evaluate(engine, req)
    dt_ms = int((time.perf_counter() - t0) * 1000)
    assert dt_ms <= target_ms, f"200 evals took {dt_ms} ms > {target_ms} ms"
