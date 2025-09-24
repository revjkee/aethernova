# security-core/tests/conformance/test_jwks_conformance.py
# -*- coding: utf-8 -*-
import base64
import json
import time
from datetime import datetime, timedelta, timezone

import pytest

# Если библиотека для выпуска токенов отсутствует — пропускаем весь набор.
try:
    import jwt as pyjwt  # PyJWT
except Exception as e:  # pragma: no cover
    pytest.skip(f"PyJWT is required for JWKS conformance tests: {e}", allow_module_level=True)

# Конкретизируем ожидаемое API вашей реализации (как в unit-тестах).
try:
    from security.tokens.jwt import (
        JwtService,
        InMemoryKeyStore,
        JwtKey,
        JwtConfig,
        TokenInvalid,
    )
except Exception as e:  # pragma: no cover
    pytest.skip(f"security.tokens.jwt not available: {e}", allow_module_level=True)

# Мок httpx
respx = pytest.importorskip("respx")
import httpx  # noqa: E402

# Криптография для генерации ключей
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1


UTC = timezone.utc

# ---------------------------------------------------------------------------
# Утилиты: генерация ключей и преобразование в JWK
# ---------------------------------------------------------------------------

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def int_to_b64u(i: int, size: int | None = None) -> str:
    # big-endian без знака
    if i == 0:
        raw = b"\x00"
    else:
        length = (i.bit_length() + 7) // 8
        raw = i.to_bytes(length, "big")
    if size is not None and len(raw) < size:
        raw = (b"\x00" * (size - len(raw))) + raw
    return b64u(raw)

def gen_rsa_pair():
    sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pk = sk.public_key()
    sk_pem = sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pk_pem = pk.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pub_nums = pk.public_numbers()
    jwk = {
        "kty": "RSA",
        "n": int_to_b64u(pub_nums.n),
        "e": int_to_b64u(pub_nums.e),
    }
    return sk_pem, pk_pem, jwk

def gen_ec_p256_pair():
    sk = ec.generate_private_key(SECP256R1())
    pk = sk.public_key()
    sk_pem = sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pk_pem = pk.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    nums = pk.public_numbers()
    size = 32  # P-256 координаты по 32 байта
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": int_to_b64u(nums.x, size=size),
        "y": int_to_b64u(nums.y, size=size),
    }
    return sk_pem, pk_pem, jwk

def gen_ed25519_pair():
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()
    sk_pem = sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pk_pem = pk.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    raw = pk.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": b64u(raw),
    }
    return sk_pem, pk_pem, jwk

def jwt_encode(alg: str, kid: str, priv_pem: bytes, claims: dict, headers: dict | None = None) -> str:
    h = {"alg": alg, "typ": "JWT", "kid": kid}
    if headers:
        h.update(headers)
    return pyjwt.encode(claims, priv_pem, algorithm=alg, headers=h)

# ---------------------------------------------------------------------------
# Фикстуры окружения
# ---------------------------------------------------------------------------

@pytest.fixture
def now() -> datetime:
    return datetime.now(UTC)

@pytest.fixture
def base_claims(now) -> dict:
    return {
        "iss": "https://issuer.example",
        "aud": "api://example",
        "sub": "user-1",
        "iat": int(now.timestamp()),
        "nbf": int((now - timedelta(seconds=1)).timestamp()),
        "exp": int((now + timedelta(minutes=10)).timestamp()),
        "jti": "abc-123",
    }

@pytest.fixture
def cfg_jwks() -> JwtConfig:
    # jwks_cache_ttl_sec — малый TTL для проверки обновления
    return JwtConfig(
        allowed_algs={"RS256", "ES256", "EdDSA"},
        default_issuer="https://issuer.example",
        default_audience="api://example",
        jwks_url="https://issuer.example/.well-known/jwks.json",
        jwks_cache_ttl_sec=2,
        require_jwt_typ=True,
        forbid_zip=True,
        forbid_crit=True,
    )

@pytest.fixture
def svc_jwks_only(cfg_jwks) -> JwtService:
    # Пустой локальный keystore — всё будет приходить из JWKS.
    ks = InMemoryKeyStore([])
    return JwtService(keystore=ks, config=cfg_jwks)

# ---------------------------------------------------------------------------
# Позитивные конформанс-тесты (RSA/EC/OKP)
# ---------------------------------------------------------------------------

def test_jwks_rsa_rs256_ok(svc_jwks_only, base_claims):
    sk_pem, _pk_pem, jwk_pub = gen_rsa_pair()
    kid = "rsa1"
    jwk = {**jwk_pub, "kid": kid, "use": "sig", "alg": "RS256"}
    token = jwt_encode("RS256", kid, sk_pem, base_claims)

    with respx.mock(assert_all_called=True) as router:
        router.get("https://issuer.example/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json={"keys": [jwk]})
        )
        out = svc_jwks_only.verify(token)
        assert out["sub"] == base_claims["sub"]

def test_jwks_ec_es256_ok(svc_jwks_only, base_claims):
    sk_pem, _pk_pem, jwk_pub = gen_ec_p256_pair()
    kid = "ec1"
    jwk = {**jwk_pub, "kid": kid, "use": "sig", "alg": "ES256"}
    token = jwt_encode("ES256", kid, sk_pem, base_claims)

    with respx.mock(assert_all_called=True) as router:
        router.get("https://issuer.example/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json={"keys": [jwk]})
        )
        out = svc_jwks_only.verify(token)
        assert out["aud"] == base_claims["aud"]

def test_jwks_okp_eddsa_ok(svc_jwks_only, base_claims):
    sk_pem, _pk_pem, jwk_pub = gen_ed25519_pair()
    kid = "ed1"
    jwk = {**jwk_pub, "kid": kid, "use": "sig", "alg": "EdDSA"}
    token = jwt_encode("EdDSA", kid, sk_pem, base_claims)

    with respx.mock(assert_all_called=True) as router:
        router.get("https://issuer.example/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json={"keys": [jwk]})
        )
        out = svc_jwks_only.verify(token)
        assert out["iss"] == base_claims["iss"]

# ---------------------------------------------------------------------------
# use/alg фильтрация и отбраковка неподходящих JWK
# ---------------------------------------------------------------------------

def test_jwks_ignores_use_enc_and_fails_when_no_sig(svc_jwks_only, base_claims):
    # Единственный ключ с use=enc — проверка должна провалиться.
    sk_pem, _pk_pem, jwk_pub = gen_rsa_pair()
    kid = "rsa-enc"
    bad = {**jwk_pub, "kid": kid, "use": "enc", "alg": "RS256"}
    token = jwt_encode("RS256", kid, sk_pem, base_claims)

    with respx.mock(assert_all_called=True) as router:
        router.get("https://issuer.example/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json={"keys": [bad]})
        )
        with pytest.raises(TokenInvalid):
            svc_jwks_only.verify(token)

def test_jwks_prefers_sig_over_enc(svc_jwks_only, base_claims):
    # В JWKS есть два одинаковых kid: sig и enc. Корректный — use=sig.
    sk_pem, _pk_pem, jwk_pub = gen_rsa_pair()
    kid = "rsa2"
    good = {**jwk_pub, "kid": kid, "use": "sig", "alg": "RS256"}
    enc = {**jwk_pub, "kid": kid, "use": "enc", "alg": "RS256"}
    token = jwt_encode("RS256", kid, sk_pem, base_claims)

    with respx.mock(assert_all_called=True) as router:
        router.get("https://issuer.example/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json={"keys": [enc, good]})
        )
        out = svc_jwks_only.verify(token)
        assert out["sub"] == base_claims["sub"]

def test_jwks_mismatched_alg_is_ignored(svc_jwks_only, base_claims):
    # В JWKS только ключ с неверным alg относительно заголовка токена.
    sk_pem, _pk_pem, jwk_pub = gen_ec_p256_pair()
    kid = "ec-bad"
    bad = {**jwk_pub, "kid": kid, "use": "sig", "alg": "EdDSA"}  # должен быть ES256
    token = jwt_encode("ES256", kid, sk_pem, base_claims)

    with respx.mock(assert_all_called=True) as router:
        router.get("https://issuer.example/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json={"keys": [bad]})
        )
        with pytest.raises(TokenInvalid):
            svc_jwks_only.verify(token)

# ---------------------------------------------------------------------------
# Кэширование JWKS: TTL, повторные вызовы без сети, обновление после истечения TTL
# ---------------------------------------------------------------------------

def test_jwks_cache_ttl_and_refresh(svc_jwks_only, cfg_jwks, base_claims):
    sk_pem, _pk_pem, jwk_pub1 = gen_ed25519_pair()
    kid = "ed-cache"
    jwk1 = {**jwk_pub1, "kid": kid, "use": "sig", "alg": "EdDSA"}
    token = jwt_encode("EdDSA", kid, sk_pem, base_claims)

    with respx.mock(assert_all_called=True) as router:
        # Первый фетч
        router.get(cfg_jwks.jwks_url).mock(return_value=httpx.Response(200, json={"keys": [jwk1]}))
        out1 = svc_jwks_only.verify(token)
        assert out1["sub"] == base_claims["sub"]

        # Повтор сразу — без доп. вызовов сети
        router.assert_all_called()
        out2 = svc_jwks_only.verify(token)
        assert out2["sub"] == base_claims["sub"]

    # Ждём истечения TTL и проверим, что идёт повторный сетевой вызов
    time.sleep(cfg_jwks.jwks_cache_ttl_sec + 0.2)
    with respx.mock(assert_all_called=True) as router:
        router.get(cfg_jwks.jwks_url).mock(return_value=httpx.Response(200, json={"keys": [jwk1]}))
        out3 = svc_jwks_only.verify(token)
        assert out3["sub"] == base_claims["sub"]

# ---------------------------------------------------------------------------
# Ротация ключей: miss по kid => рефреш и успешная проверка
# ---------------------------------------------------------------------------

def test_jwks_kid_miss_then_refresh(svc_jwks_only, cfg_jwks, base_claims):
    # Подпишем токен новым ключом; первый фетч вернёт JWKS без нужного kid, второй — с ним.
    sk_pem, _pk_pem, jwk_pub = gen_rsa_pair()
    kid = "rsa-new"
    token = jwt_encode("RS256", kid, sk_pem, base_claims)
    jwks_empty = {"keys": []}
    jwks_with_key = {"keys": [{**jwk_pub, "kid": kid, "use": "sig", "alg": "RS256"}]}

    with respx.mock(assert_all_called=True) as router:
        router.get(cfg_jwks.jwks_url).mock(
            side_effect=[
                httpx.Response(200, json=jwks_empty),
                httpx.Response(200, json=jwks_with_key),
            ]
        )
        out = svc_jwks_only.verify(token)
        assert out["iss"] == base_claims["iss"]

# ---------------------------------------------------------------------------
# Неоднозначности и ошибки формата
# ---------------------------------------------------------------------------

def test_jwks_no_kid_header_single_key_of_alg_ok(svc_jwks_only, base_claims):
    # Если в токене нет kid, но в JWKS есть ровно один ключ подходящего alg — допускаем.
    sk_pem, _pk_pem, jwk_pub = gen_ed25519_pair()
    jwk = {**jwk_pub, "kid": "ed-single", "use": "sig", "alg": "EdDSA"}

    # Сформируем токен без kid в заголовке
    token = pyjwt.encode(base_claims, sk_pem, algorithm="EdDSA", headers={"typ": "JWT"})

    with respx.mock(assert_all_called=True) as router:
        router.get("https://issuer.example/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json={"keys": [jwk]})
        )
        out = svc_jwks_only.verify(token)
        assert out["aud"] == base_claims["aud"]

def test_jwks_no_kid_header_multiple_keys_same_alg_fails(svc_jwks_only, base_claims):
    # Нет kid и несколько ключей одного alg — проверка должна провалиться (неоднозначность).
    sk1_pem, _pk1_pem, jwk1 = gen_rsa_pair()
    sk2_pem, _pk2_pem, jwk2 = gen_rsa_pair()
    token = pyjwt.encode(base_claims, sk1_pem, algorithm="RS256", headers={"typ": "JWT"})

    jwks = {
        "keys": [
            {**jwk1, "kid": "rsa-a", "use": "sig", "alg": "RS256"},
            {**jwk2, "kid": "rsa-b", "use": "sig", "alg": "RS256"},
        ]
    }
    with respx.mock(assert_all_called=True) as router:
        router.get("https://issuer.example/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json=jwks)
        )
        with pytest.raises(TokenInvalid):
            svc_jwks_only.verify(token)

def test_jwks_malformed_keys_are_ignored_and_fail_if_no_valid_left(svc_jwks_only, base_claims):
    # В JWKS наборе есть битые ключи: неверные base64, отсутствует kty/поля. Должны быть проигнорированы.
    sk_pem, _pk_pem, jwk_good = gen_ec_p256_pair()
    kid = "ec-good"
    good = {**jwk_good, "kid": kid, "use": "sig", "alg": "ES256"}
    bad1 = {"kty": "RSA", "n": "!!!", "e": "AQAB", "kid": "bad1", "use": "sig", "alg": "RS256"}  # битый base64
    bad2 = {"kty": "EC", "crv": "P-256", "x": "AA", "kid": "bad2"}  # не хватает y
    bad3 = {"crv": "Ed25519", "x": "AA", "kid": "bad3"}  # нет kty
    token = jwt_encode("ES256", kid, sk_pem, base_claims)

    with respx.mock(assert_all_called=True) as router:
        router.get("https://issuer.example/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json={"keys": [bad1, bad2, bad3]})
        )
        # Пока нет валидных ключей — отказ
        with pytest.raises(TokenInvalid):
            svc_jwks_only.verify(token)

    # Добавим валидный ключ — проверка пройдёт
    with respx.mock(assert_all_called=True) as router:
        router.get("https://issuer.example/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json={"keys": [bad1, good, bad2]})
        )
        out = svc_jwks_only.verify(token)
        assert out["sub"] == base_claims["sub"]

def test_jwks_duplicate_kid_with_conflicting_material_fails(svc_jwks_only, base_claims):
    # Два JWK с одинаковым kid и alg, но разным материалом — безопаснее отказать.
    sk1_pem, _pk1_pem, jwk1 = gen_rsa_pair()
    _sk2_pem, _pk2_pem, jwk2 = gen_rsa_pair()
    kid = "rsa-conflict"
    good = {**jwk1, "kid": kid, "use": "sig", "alg": "RS256"}
    conflicting = {**jwk2, "kid": kid, "use": "sig", "alg": "RS256"}
    token = jwt_encode("RS256", kid, sk1_pem, base_claims)

    with respx.mock(assert_all_called=True) as router:
        router.get("https://issuer.example/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json={"keys": [good, conflicting]})
        )
        with pytest.raises(TokenInvalid):
            svc_jwks_only.verify(token)
