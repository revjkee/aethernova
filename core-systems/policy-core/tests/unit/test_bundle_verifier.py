# policy-core/tests/unit/test_bundle_verifier.py
# -*- coding: utf-8 -*-
"""
Промышленный набор тестов для верификатора бандлов политик (BundleVerifier).

Контракт (ожидаемый интерфейс policy_core.bundle.verifier):
- BundleVerifier(repo: Optional[PolicyRepository]=..., strict: bool=True, required_signers: Optional[set[str]]=None)
- verify_bundle(bundle: dict, jwks: Optional[dict]=None) -> VerificationReport
    где VerificationReport:
        .ok: bool
        .issues: List[{"severity": "info|warning|error", "code": str, "path": str, "message": str}]
- Исключения:
    - VerificationError: критическая ошибка верификации (при strict=True)
    - BundleFormatError: форматные ошибки бандла до крипто-проверок

Семантика:
- Подпись JWS (compact) покрывает канонический JSON содержимого бандла БЕЗ полей 'signatures' и 'jwks'.
- Поддерживаемые алгоритмы: HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512, EdDSA.
- JWKS обязателен либо передаётся извне резолвером; дублирующиеся kid запрещены.
- Неизменность: любое изменение полезной нагрузки после подписания приводит к ошибке подписи.
- Интеграция PAP: все политики прогоняются через PolicyValidator; ошибки в политике → ошибка бандла.
- Поддержка "required_signers": набор KID, подписи которых обязательны; их отсутствие → ошибка.

Примечание:
- Тесты используют policy_core.utils.jwk для генерации ключей и подписи.
- Если модуль верификатора отсутствует, тесты помечаются как SKIPPED.
"""

from __future__ import annotations

import copy
import json
import time
import typing as _t
from datetime import datetime, timezone

import pytest

# Импортируем JWK/JWS утилиты (являются частью проекта)
from policy_core.utils.jwk import (
    JWK,
    jws_sign_compact,
    b64u_encode,
    b64u_decode,
    dump_jwk_set,
    load_jwk_set,
)
# Флаг доступности криптобэкенда (RSA/EC/OKP)
from policy_core.utils.jwk import _CRYPTO_AVAILABLE as CRYPTO_OK  # noqa: N813 (приватный, но полезный в тестах)

# Импорт для интеграции с PAP валидатором
from policy_core.pap.validator import (
    PolicyValidator,
    ValidationResult,
    ValidationIssue,
    Severity,
    policy_canonical_hash,  # используем каноникализацию из валидатора
)

# Модуль верификатора — может отсутствовать на момент запуска тестов
_verifier = pytest.importorskip(
    "policy_core.bundle.verifier",
    reason="bundle verifier module is not present yet",
)

BundleVerifier = getattr(_verifier, "BundleVerifier", None)
VerificationError = getattr(_verifier, "VerificationError", RuntimeError)
BundleFormatError = getattr(_verifier, "BundleFormatError", ValueError)

assert BundleVerifier is not None, "BundleVerifier must be exported from policy_core.bundle.verifier"


# ---------------------------- ВСПОМОГАТЕЛЬНЫЕ УТИЛИТЫ ----------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def canonical_bundle_payload(bundle: dict) -> bytes:
    """
    Каноническая сериализация полезной нагрузки бандла для подписи:
    исключаем 'signatures' и 'jwks', сортируем ключи.
    """
    payload = {k: v for k, v in bundle.items() if k not in ("signatures", "jwks")}
    # Дополнительно фиксируем хеш полезной нагрузки для детерминизма (необязательно для верификатора)
    payload["_canonical_hash"] = policy_canonical_hash(payload)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def make_policy(policy_id: str = "pol-1", effect: str = "permit") -> dict:
    return {
        "id": policy_id,
        "version": 1,
        "name": f"Policy {policy_id}",
        "priority": 10,
        "enabled": True,
        "tags": ["core:test"],
        "targets": {
            "subjects": ["user:alice"],
            "resources": ["res:doc:123"],
            "actions": ["read"],
        },
        "rules": [
            {
                "id": f"r-{policy_id}-1",
                "effect": effect,
                "condition": {"==": [{"var": "subject.id"}, "user:alice"]},
            }
        ],
    }

def make_bundle(policies: list[dict], meta: dict | None = None) -> dict:
    base_meta = {
        "bundle_id": "bundle-1",
        "format_version": 1,
        "issuer": "policy-core",
        "issued_at": now_iso(),
    }
    if meta:
        base_meta.update(meta)
    return {
        **base_meta,
        "policies": policies,
        # Подписи и JWKS будут добавлены далее
    }

def sign_bundle(bundle: dict, signer: JWK) -> dict:
    """
    Формирует поле signatures[0] с подписью канонического JSON бандла.
    """
    payload = canonical_bundle_payload(bundle)
    header = {"typ": "JWS", "alg": signer.data.get("alg"), "kid": signer.ensure_kid()}
    jws = jws_sign_compact(signer, header, payload)
    out = copy.deepcopy(bundle)
    out.setdefault("signatures", [])
    out["signatures"].append({"kid": signer.data["kid"], "alg": signer.data["alg"], "jws": jws})
    return out

def with_jwks(bundle: dict, keys: list[JWK]) -> dict:
    jwks = json.loads(dump_jwk_set(keys))
    out = copy.deepcopy(bundle)
    out["jwks"] = jwks
    return out


# ---------------------------- ФИКСТУРЫ КЛЮЧЕЙ ----------------------------

@pytest.fixture(scope="module")
def jwk_oct() -> JWK:
    # Симметричный ключ — не требует cryptography
    return JWK.generate_oct(size_bytes=32, alg="HS256", use="sig")

@pytest.fixture(scope="module")
def jwk_rsa() -> JWK:
    if not CRYPTO_OK:
        pytest.skip("cryptography backend is required for RSA")
    return JWK.generate_rsa(bits=2048, alg="RS256", use="sig")

@pytest.fixture(scope="module")
def jwk_pss() -> JWK:
    if not CRYPTO_OK:
        pytest.skip("cryptography backend is required for RSA-PSS")
    return JWK.generate_rsa(bits=2048, alg="PS256", use="sig")

@pytest.fixture(scope="module")
def jwk_ec() -> JWK:
    if not CRYPTO_OK:
        pytest.skip("cryptography backend is required for EC")
    return JWK.generate_ec(crv="P-256", alg="ES256", use="sig")

@pytest.fixture(scope="module")
def jwk_okp() -> JWK:
    if not CRYPTO_OK:
        pytest.skip("cryptography backend is required for Ed25519")
    return JWK.generate_okp(alg="EdDSA", use="sig")


# ---------------------------- ТЕСТЫ УСПЕШНЫХ СЦЕНАРИЕВ ----------------------------

@pytest.mark.parametrize(
    "algo_fixture",
    ["jwk_oct", "jwk_rsa", "jwk_pss", "jwk_ec", "jwk_okp"],
)
def test_verify_bundle_ok(monkeypatch, request, algo_fixture):
    """
    Бандл подписан корректно, JWKS предоставлен, все политики валидны — ok=True.
    """
    signer: JWK = request.getfixturevalue(algo_fixture)
    policies = [make_policy("pol-1", "permit"), make_policy("pol-2", "deny")]
    bundle = make_bundle(policies)
    bundle_signed = sign_bundle(bundle, signer)
    bundle_signed = with_jwks(bundle_signed, [signer.to_public() if signer.data["kty"] != "oct" else signer])

    # Подменяем PolicyValidator.validate_policy, чтобы тест не зависел от деталей проверок
    def _ok_validate_policy(self, policy_input):
        return ValidationResult(issues=[])  # ok=True
    monkeypatch.setattr(PolicyValidator, "validate_policy", _ok_validate_policy, raising=True)

    verifier = BundleVerifier(strict=True)
    report = verifier.verify_bundle(bundle_signed, jwks=bundle_signed.get("jwks"))
    assert hasattr(report, "ok") and hasattr(report, "issues")
    assert report.ok, f"Ожидался ok=True, issues: {report.issues}"


# ---------------------------- ТЕСТЫ ТАМПЕРИНГА ----------------------------

@pytest.mark.parametrize(
    "algo_fixture",
    ["jwk_oct", "jwk_rsa", "jwk_ec", "jwk_okp"],
)
def test_verify_bundle_tamper_detected(monkeypatch, request, algo_fixture):
    """
    Любое изменение полезной нагрузки после подписания должно ломать подпись.
    """
    signer: JWK = request.getfixturevalue(algo_fixture)
    policies = [make_policy("pol-1", "permit")]
    bundle = make_bundle(policies)
    signed = sign_bundle(bundle, signer)
    signed = with_jwks(signed, [signer.to_public() if signer.data["kty"] != "oct" else signer])

    # Тамперим поле name в политике
    signed["policies"][0]["name"] = "Policy pol-1 (tampered)"

    # Валидатор политик пусть возвращает ok=True, чтобы ошибка была именно по подписи
    def _ok_validate_policy(self, policy_input):
        return ValidationResult(issues=[])
    monkeypatch.setattr(PolicyValidator, "validate_policy", _ok_validate_policy, raising=True)

    verifier = BundleVerifier(strict=False)
    report = verifier.verify_bundle(signed, jwks=signed.get("jwks"))
    assert not report.ok, "Ожидалась ошибка подписи после модификации полезной нагрузки"
    assert any(i["code"].startswith("signature.") or "signature" in i["code"] for i in report.issues), report.issues


# ---------------------------- ТЕСТЫ JWKS / KID ----------------------------

def test_duplicate_kid_in_jwks_rejected(jwk_oct):
    """
    JWKS с дублирующимися kid должен отвергаться.
    """
    # Создаём два ключа с одинаковым kid: для oct это легко — копируем объект
    k1 = copy.deepcopy(jwk_oct)
    k2 = copy.deepcopy(jwk_oct)
    # Насильно выравниваем kid
    kid = k1.ensure_kid()
    k2.data["kid"] = kid

    policies = [make_policy("pol-1")]
    bundle = make_bundle(policies)
    bundle = sign_bundle(bundle, k1)
    jwks = json.loads(dump_jwk_set([k1, k2]))

    verifier = BundleVerifier(strict=False)
    with pytest.raises((VerificationError, BundleFormatError)):
        verifier.verify_bundle(bundle, jwks=jwks)


def test_required_signers_enforced(monkeypatch, jwk_oct, jwk_rsa):
    """
    Если заданы required_signers, отсутствие подписи от одного из обязательных KID — ошибка.
    """
    if not CRYPTO_OK:
        pytest.skip("cryptography backend is required for RSA path of this test")

    policies = [make_policy("pol-req")]
    bundle = make_bundle(policies)

    # Подписываем только HS256-ключом
    signed = sign_bundle(bundle, jwk_oct)
    jwks = json.loads(dump_jwk_set([jwk_oct, jwk_rsa.to_public()]))

    # Валидатор политик — ok=True
    def _ok_validate_policy(self, policy_input):
        return ValidationResult(issues=[])
    monkeypatch.setattr(PolicyValidator, "validate_policy", _ok_validate_policy, raising=True)

    # Требуем подписи от обоих KID
    required = {jwk_oct.ensure_kid(), jwk_rsa.ensure_kid()}
    verifier = BundleVerifier(strict=False, required_signers=required)
    report = verifier.verify_bundle(signed, jwks=jwks)
    assert not report.ok, "Ожидалась ошибка: отсутствует подпись от одного из обязательных подписантов"
    assert any("required_signers" in i["code"] or i["code"].endswith("missing_signer") for i in report.issues), report.issues


# ---------------------------- ИНТЕГРАЦИЯ С PAP ВАЛИДАТОРОМ ----------------------------

def test_policy_validation_errors_bubble_up(monkeypatch, jwk_oct):
    """
    Ошибки схемы/семантики политики должны делать бандл невалидным.
    """
    invalid_policy = make_policy("bad")
    # Ломаем обязательные поля умышленно
    invalid_policy.pop("targets")

    bundle = make_bundle([invalid_policy])
    bundle = sign_bundle(bundle, jwk_oct)
    bundle = with_jwks(bundle, [jwk_oct])

    # Валидатор возвращает ошибку по отсутствующему полю
    def _bad_validate_policy(self, policy_input):
        return ValidationResult(issues=[ValidationIssue(
            severity=Severity.ERROR,
            code=_verifier.IssueCode.POLICY_INVALID if hasattr(_verifier, "IssueCode") else "policy.invalid",  # допускаем локальный enum
            message="Missing 'targets'",
            path="$.targets",
        )])
    monkeypatch.setattr(PolicyValidator, "validate_policy", _bad_validate_policy, raising=True)

    verifier = BundleVerifier(strict=False)
    report = verifier.verify_bundle(bundle, jwks=bundle.get("jwks"))
    assert not report.ok, "Ожидалась ошибка из PAP-валидатора"
    assert any("policy" in i["code"] for i in report.issues), report.issues


# ---------------------------- ВАЛИДАЦИЯ ФОРМАТА БАНДЛА ----------------------------

def test_bundle_without_signatures_is_rejected(jwk_oct):
    """
    Поле signatures обязательно: бандл без него должен быть отвергнут.
    """
    policies = [make_policy("no-sig")]
    bundle = make_bundle(policies)
    # намеренно не подписываем

    verifier = BundleVerifier(strict=False)
    with pytest.raises((VerificationError, BundleFormatError)):
        verifier.verify_bundle(bundle, jwks=None)


def test_bundle_signature_header_alg_kid_required(monkeypatch, jwk_oct):
    """
    Заголовок JWS должен содержать alg и kid; отсутствие любого — ошибка.
    """
    policies = [make_policy("hdr")]
    bundle = make_bundle(policies)

    # Сформируем подпись вручную с пустым заголовком
    payload = canonical_bundle_payload(bundle)
    header_b64 = b64u_encode(json.dumps({}, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    payload_b64 = b64u_encode(payload)
    sig = jwk_oct.sign((header_b64 + "." + payload_b64).encode("ascii"))
    bad_jws = header_b64 + "." + payload_b64 + "." + b64u_encode(sig)

    bundle["signatures"] = [{"jws": bad_jws}]  # нет kid/alg
    bundle = with_jwks(bundle, [jwk_oct])

    # Валидатор политик — ok=True
    def _ok_validate_policy(self, policy_input):
        return ValidationResult(issues=[])
    monkeypatch.setattr(PolicyValidator, "validate_policy", _ok_validate_policy, raising=True)

    verifier = BundleVerifier(strict=False)
    report = verifier.verify_bundle(bundle, jwks=bundle["jwks"])
    assert not report.ok
    assert any(i["code"].endswith("missing_alg") or i["code"].endswith("missing_kid") for i in report.issues), report.issues


# ---------------------------- ПАРАМЕТРИЗАЦИЯ АЛГОРИТМОВ ----------------------------

@pytest.mark.skipif(not CRYPTO_OK, reason="cryptography backend required for asymmetric algorithms")
@pytest.mark.parametrize(
    "fixture_name",
    ["jwk_rsa", "jwk_pss", "jwk_ec", "jwk_okp"],
)
def test_verify_multiple_algorithms(monkeypatch, request, fixture_name):
    """
    Кросс-алгоритмическая проверка: бандл должен успешно верифицироваться при разных JWS-алгоритмах.
    """
    signer: JWK = request.getfixturevalue(fixture_name)
    policies = [make_policy("multi-1"), make_policy("multi-2")]
    bundle = make_bundle(policies)
    bundle = sign_bundle(bundle, signer)
    bundle = with_jwks(bundle, [signer.to_public()])

    def _ok_validate_policy(self, policy_input):
        return ValidationResult(issues=[])
    monkeypatch.setattr(PolicyValidator, "validate_policy", _ok_validate_policy, raising=True)

    verifier = BundleVerifier(strict=True)
    report = verifier.verify_bundle(bundle, jwks=bundle["jwks"])
    assert report.ok, f"Алгоритм {signer.data['alg']} должен проходить верификацию"


# ---------------------------- ГРАНИЧНЫЕ СЛУЧАИ ----------------------------

def test_jwks_missing_required_key(monkeypatch, jwk_oct, jwk_rsa):
    """
    Подпись присутствует, но соответствующий ключ не найден в JWKS — ошибка.
    """
    if not CRYPTO_OK:
        pytest.skip("cryptography backend required for RSA branch")

    policies = [make_policy("miss-key")]
    bundle = make_bundle(policies)
    bundle = sign_bundle(bundle, jwk_rsa)  # подписали RSA-ключом
    bundle = with_jwks(bundle, [jwk_oct])  # в JWKS — только HS-ключ

    def _ok_validate_policy(self, policy_input):
        return ValidationResult(issues=[])
    monkeypatch.setattr(PolicyValidator, "validate_policy", _ok_validate_policy, raising=True)

    verifier = BundleVerifier(strict=False)
    report = verifier.verify_bundle(bundle, jwks=bundle["jwks"])
    assert not report.ok
    assert any("key_not_found" in i["code"] or i["code"].endswith(".unknown_kid") for i in report.issues), report.issues


def test_bundle_rejects_extra_fields_in_signature_object(monkeypatch, jwk_oct):
    """
    Объект подписи должен содержать строго допустимые поля; лишние поля — предупреждение или ошибка.
    """
    policies = [make_policy("extra")]
    bundle = make_bundle(policies)
    bundle = sign_bundle(bundle, jwk_oct)
    bundle = with_jwks(bundle, [jwk_oct])

    # Добавим лишнее поле в подпись
    bundle["signatures"][0]["debug"] = {"leak": True}

    def _ok_validate_policy(self, policy_input):
        return ValidationResult(issues=[])
    monkeypatch.setattr(PolicyValidator, "validate_policy", _ok_validate_policy, raising=True)

    verifier = BundleVerifier(strict=False)
    report = verifier.verify_bundle(bundle, jwks=bundle["jwks"])
    # В продакшне обычно это хотя бы WARNING; допускаем ERROR в строгом режиме реализации
    assert any(i["code"].endswith("signature_object.extraneous") or i["severity"] in ("warning", "error") for i in report.issues)


def test_multiple_signatures_any_one_valid_is_ok(monkeypatch, jwk_oct, jwk_rsa):
    """
    Если политика доверяет любому из нескольких подписантов и хотя бы одна подпись валидна, отчёт может быть ok=True.
    """
    if not CRYPTO_OK:
        pytest.skip("cryptography backend required for RSA branch")

    policies = [make_policy("multi-sig")]
    bundle = make_bundle(policies)
    # Подпишем двумя ключами
    bundle = sign_bundle(bundle, jwk_oct)
    bundle = sign_bundle(bundle, jwk_rsa)
    bundle = with_jwks(bundle, [jwk_oct, jwk_rsa.to_public()])

    def _ok_validate_policy(self, policy_input):
        return ValidationResult(issues=[])
    monkeypatch.setattr(PolicyValidator, "validate_policy", _ok_validate_policy, raising=True)

    verifier = BundleVerifier(strict=False)
    report = verifier.verify_bundle(bundle, jwks=bundle["jwks"])
    assert report.ok, report.issues
