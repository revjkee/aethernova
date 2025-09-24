# security-core/tests/unit/test_tokens_jwt.py
# -*- coding: utf-8 -*-
import base64
import json
import time
from datetime import datetime, timedelta, timezone

import pytest

# Попытка импортировать специфицируемый модуль.
# Если он отсутствует — пометим весь набор как пропущенный (TDD-дружественно).
try:
    from security.tokens.jwt import (
        JwtService,
        InMemoryKeyStore,
        JwtKey,
        JwtConfig,
        IssueOptions,
        ValidationPolicy,
        TokenInvalid,
        TokenExpired,
        TokenNotYetValid,
        TokenAudienceMismatch,
        TokenIssuerMismatch,
        TokenSubjectMismatch,
    )
except Exception as e:  # pragma: no cover
    pytest.skip(f"security.tokens.jwt not available: {e}", allow_module_level=True)

# Библиотека для генерации тестовых JWT (только для подготовки входных данных)
try:
    import jwt as pyjwt  # PyJWT
except Exception as e:  # pragma: no cover
    pytest.skip(f"PyJWT is required for tests: {e}", allow_module_level=True)

# Криптография для генерации ключей
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519


UTC = timezone.utc


# ----------------------------
# Утилиты генерации ключей
# ----------------------------

def gen_rsa():
    sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pk = sk.public_key()
    sk_pem = sk.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    pk_pem = pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return sk, pk, sk_pem, pk_pem

def gen_ec_p256():
    sk = ec.generate_private_key(ec.SECP256R1())
    pk = sk.public_key()
    sk_pem = sk.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    pk_pem = pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return sk, pk, sk_pem, pk_pem

def gen_ed25519():
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()
    sk_pem = sk.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    pk_pem = pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return sk, pk, sk_pem, pk_pem


# ----------------------------
# Фикстуры окружения
# ----------------------------

@pytest.fixture
def base_claims():
    now = datetime.now(UTC)
    return {
        "iss": "https://auth.example",
        "aud": "api://example",
        "sub": "user-123",
        "iat": int(now.timestamp()),
        "nbf": int((now - timedelta(seconds=1)).timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "jti": "jti-abc",
    }

@pytest.fixture
def cfg():
    return JwtConfig(
        allowed_algs={"RS256", "ES256", "EdDSA"},
        default_issuer="https://auth.example",
        default_audience="api://example",
        default_leeway_sec=60,
        default_max_age_sec=None,
        require_jwt_typ=True,          # тип заголовка должен быть "JWT"
        forbid_zip=True,               # запрещаем zip-компрессию
        forbid_crit=True,              # запрещаем нераспознанные crit
    )

@pytest.fixture
def keystore_rs256():
    _, pk, sk_pem, pk_pem = gen_rsa()
    k_priv = JwtKey(alg="RS256", kid="r1", material=sk_pem, is_private=True, active=True, primary=True)
    k_pub = JwtKey(alg="RS256", kid="r1", material=pk_pem, is_private=False, active=True, primary=False)
    return InMemoryKeyStore([k_priv, k_pub])

@pytest.fixture
def keystore_multi():
    # r1 (primary), r2 (второй ключ), e1 (ES256), ed1 (EdDSA)
    _, _, sk1_pem, pk1_pem = gen_rsa()
    _, _, sk2_pem, pk2_pem = gen_rsa()
    _, _, e_sk_pem, e_pk_pem = gen_ec_p256()
    _, _, ed_sk_pem, ed_pk_pem = gen_ed25519()

    keys = [
        JwtKey(alg="RS256", kid="r1", material=sk1_pem, is_private=True, active=True, primary=True),
        JwtKey(alg="RS256", kid="r1", material=pk1_pem, is_private=False, active=True, primary=False),

        JwtKey(alg="RS256", kid="r2", material=sk2_pem, is_private=True, active=False, primary=False),  # неактивный
        JwtKey(alg="RS256", kid="r2", material=pk2_pem, is_private=False, active=True, primary=False),

        JwtKey(alg="ES256", kid="e1", material=e_sk_pem, is_private=True, active=True, primary=False),
        JwtKey(alg="ES256", kid="e1", material=e_pk_pem, is_private=False, active=True, primary=False),

        JwtKey(alg="EdDSA", kid="ed1", material=ed_sk_pem, is_private=True, active=True, primary=False),
        JwtKey(alg="EdDSA", kid="ed1", material=ed_pk_pem, is_private=False, active=True, primary=False),
    ]
    return InMemoryKeyStore(keys)

@pytest.fixture
def svc_rs256(cfg, keystore_rs256):
    return JwtService(keystore=keystore_rs256, config=cfg)

@pytest.fixture
def svc_multi(cfg, keystore_multi):
    return JwtService(keystore=keystore_multi, config=cfg)


# ----------------------------
# Помощники генерации JWT
# ----------------------------

def jwt_encode(alg, kid, priv_pem, claims, headers=None):
    h = {"alg": alg, "typ": "JWT", "kid": kid}
    if headers:
        h.update(headers)
    return pyjwt.encode(claims, priv_pem, algorithm=alg, headers=h)

def tamper(token: str) -> str:
    # повредим payload (последний символ заменим)
    parts = token.split(".")
    assert len(parts) == 3
    p = parts[1]
    raw = p + ("A" if not p.endswith("A") else "B")
    return ".".join([parts[0], raw, parts[2]])


# ----------------------------
# ТЕСТЫ: базовая валидация
# ----------------------------

def test_verify_rs256_ok(svc_rs256, base_claims, keystore_rs256):
    # выпустим через PyJWT, проверим через сервис
    priv = keystore_rs256.get_by_kid("r1")
    token = jwt_encode("RS256", "r1", priv.material, base_claims)
    out = svc_rs256.verify(token)
    assert out["sub"] == base_claims["sub"]
    assert out["iss"] == base_claims["iss"]
    assert out["aud"] == base_claims["aud"]

@pytest.mark.parametrize("alg_fixture,alg_name,kid", [
    ("keystore_multi", "ES256", "e1"),
    ("keystore_multi", "EdDSA", "ed1"),
])
def test_verify_non_rs_algs_ok(request, cfg, alg_fixture, alg_name, kid, base_claims):
    ks = request.getfixturevalue(alg_fixture)
    svc = JwtService(keystore=ks, config=cfg)
    priv = ks.get_by_kid(kid)
    token = jwt_encode(alg_name, kid, priv.material, base_claims)
    out = svc.verify(token)
    assert out["sub"] == base_claims["sub"]

def test_reject_none_alg(svc_rs256, base_claims, keystore_rs256):
    priv = keystore_rs256.get_by_kid("r1")
    # Сгенерируем токен с alg=none вручную: base64url(header).base64url(payload).
    header = {"alg": "none", "typ": "JWT"}
    h = base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(base_claims, separators=(",", ":"), sort_keys=True).encode()).rstrip(b"=").decode()
    token = f"{h}.{p}."
    with pytest.raises(TokenInvalid):
        svc_rs256.verify(token)

def test_expired_raises(svc_rs256, base_claims, keystore_rs256):
    priv = keystore_rs256.get_by_kid("r1")
    claims = dict(base_claims)
    claims["exp"] = int((datetime.now(UTC) - timedelta(seconds=5)).timestamp())
    token = jwt_encode("RS256", "r1", priv.material, claims)
    with pytest.raises(TokenExpired):
        svc_rs256.verify(token)

def test_not_before_raises(svc_rs256, base_claims, keystore_rs256):
    priv = keystore_rs256.get_by_kid("r1")
    claims = dict(base_claims)
    claims["nbf"] = int((datetime.now(UTC) + timedelta(minutes=5)).timestamp())
    token = jwt_encode("RS256", "r1", priv.material, claims)
    with pytest.raises(TokenNotYetValid):
        svc_rs256.verify(token)

def test_leeway_and_max_age(svc_rs256, base_claims, keystore_rs256, cfg):
    # допустимый leeway
    priv = keystore_rs256.get_by_kid("r1")
    now = int(time.time())
    claims = dict(base_claims)
    claims["iat"] = now - 10
    pol = ValidationPolicy(issuer=cfg.default_issuer, audience=cfg.default_audience, leeway=30, max_age=20)
    token = jwt_encode("RS256", "r1", priv.material, claims)
    out = svc_rs256.verify(token, policy=pol)
    assert out["iat"] == claims["iat"]

    # превышение max_age
    claims["iat"] = now - 3600
    token = jwt_encode("RS256", "r1", priv.material, claims)
    with pytest.raises(TokenExpired):
        svc_rs256.verify(token, policy=pol)

def test_aud_iss_sub_policies(svc_rs256, base_claims, keystore_rs256, cfg):
    priv = keystore_rs256.get_by_kid("r1")
    token = jwt_encode("RS256", "r1", priv.material, base_claims)

    # корректные значения
    pol = ValidationPolicy(issuer="https://auth.example", audience="api://example", require_sub=True, subject="user-123")
    out = svc_rs256.verify(token, policy=pol)
    assert out["sub"] == "user-123"

    # неверный аудит
    pol_bad_aud = ValidationPolicy(issuer="https://auth.example", audience="api://wrong")
    with pytest.raises(TokenAudienceMismatch):
        svc_rs256.verify(token, policy=pol_bad_aud)

    # неверный issuer
    pol_bad_iss = ValidationPolicy(issuer="https://wrong.example", audience="api://example")
    with pytest.raises(TokenIssuerMismatch):
        svc_rs256.verify(token, policy=pol_bad_iss)

    # требуем subject, но другой
    pol_bad_sub = ValidationPolicy(issuer="https://auth.example", audience="api://example", subject="other")
    with pytest.raises(TokenSubjectMismatch):
        svc_rs256.verify(token, policy=pol_bad_sub)

def test_kid_rotation_selects_correct_key(svc_multi, base_claims, keystore_multi):
    # Подпишем токен ключом e1 (ES256), убедимся что сервис найдёт верный pub по kid
    priv = keystore_multi.get_by_kid("e1")
    token = jwt_encode("ES256", "e1", priv.material, base_claims)
    out = svc_multi.verify(token)
    assert out["sub"] == base_claims["sub"]

def test_invalid_signature_rejected(svc_rs256, base_claims, keystore_rs256):
    priv = keystore_rs256.get_by_kid("r1")
    token = jwt_encode("RS256", "r1", priv.material, base_claims)
    bad = tamper(token)
    with pytest.raises(TokenInvalid):
        svc_rs256.verify(bad)

def test_header_typ_and_zip_and_crit_rejected(svc_rs256, base_claims, keystore_rs256):
    priv = keystore_rs256.get_by_kid("r1")

    # Неверный typ
    token_bad_typ = jwt_encode("RS256", "r1", priv.material, base_claims, headers={"typ": "JWS"})
    with pytest.raises(TokenInvalid):
        svc_rs256.verify(token_bad_typ)

    # Запрещённый zip
    token_zip = jwt_encode("RS256", "r1", priv.material, base_claims, headers={"zip": "DEF"})
    with pytest.raises(TokenInvalid):
        svc_rs256.verify(token_zip)

    # Неизвестный crit
    token_crit = jwt_encode("RS256", "r1", priv.material, base_claims, headers={"crit": ["b64"], "b64": False})
    with pytest.raises(TokenInvalid):
        svc_rs256.verify(token_crit)


# ----------------------------
# JWKS интеграционные тесты (мок сети)
# ----------------------------

respx = pytest.importorskip("respx")  # pragma: no cover
import httpx  # noqa: E402


@pytest.fixture
def svc_with_jwks(cfg, keystore_multi):
    # Сервис без локального опубликованного ключа для ed1, чтобы примусить JWKS
    # Оставим только RS256 r1 локально; ed1 придёт из JWKS.
    _, _, _, pk1_pem = gen_rsa()
    ks = InMemoryKeyStore([JwtKey(alg="RS256", kid="r1", material=pk1_pem, is_private=False, active=True, primary=False)])
    # Укажем JWKS endpoint в конфиге
    cfg2 = JwtConfig(**{**cfg.__dict__, "jwks_url": "https://issuer.example/.well-known/jwks.json", "jwks_cache_ttl_sec": 3})
    return JwtService(keystore=ks, config=cfg2)


@pytest.fixture
def jwks_ed1(keystore_multi):
    pub = keystore_multi.get_by_kid("ed1")
    # минимальный JWK (OKP/Ed25519)
    # Для простоты извлечём публичный ключ в PEM и положим как x5c/x5t — но корректнее OKP с crv/x/y.
    # Здесь сымитируем JWK OKP:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric import ed25519 as ed
    pk = ser.load_pem_public_key(pub.material)
    assert isinstance(pk, ed.Ed25519PublicKey)
    raw = pk.public_bytes(Encoding.Raw, PublicFormat.Raw)
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": base64.urlsafe_b64encode(raw).rstrip(b"=").decode(), "kid": "ed1", "alg": "EdDSA", "use": "sig"}
    return {"keys": [jwk]}

@pytest.mark.asyncio
async def test_jwks_fetch_and_cache(svc_with_jwks, jwks_ed1, base_claims, keystore_multi):
    # Подпишем EdDSA токен приватным ed1 (которого нет локально у svc_with_jwks)
    priv_ed = keystore_multi.get_by_kid("ed1")

    token = jwt_encode("EdDSA", "ed1", priv_ed.material, base_claims)

    with respx.mock(assert_all_called=True) as router:
        router.get("https://issuer.example/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json=jwks_ed1)
        )
        out = svc_with_jwks.verify(token)
        assert out["sub"] == base_claims["sub"]

        # Повтор без сети — должен пройти из кэша
        router.assert_all_called()
        out2 = svc_with_jwks.verify(token)
        assert out2["sub"] == base_claims["sub"]

    # По истечении TTL — потребуется повторная загрузка
    time.sleep(3.1)
    with respx.mock(assert_all_called=True) as router:
        router.get("https://issuer.example/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json=jwks_ed1)
        )
        out3 = svc_with_jwks.verify(token)
        assert out3["sub"] == base_claims["sub"]

@pytest.mark.asyncio
async def test_jwks_miss_then_refresh(svc_with_jwks, jwks_ed1, base_claims, keystore_multi):
    # Сначала вернём JWKS без ed1, затем с ed1
    priv_ed = keystore_multi.get_by_kid("ed1")
    token = jwt_encode("EdDSA", "ed1", priv_ed.material, base_claims)

    with respx.mock(assert_all_called=True) as router:
        router.get("https://issuer.example/.well-known/jwks.json").mock(
            side_effect=[
                httpx.Response(200, json={"keys": []}),
                httpx.Response(200, json=jwks_ed1),
            ]
        )
        # Первый вызов должен попытаться обновить кэш и со второй попытки пройти
        out = svc_with_jwks.verify(token)
        assert out["sub"] == base_claims["sub"]


# ----------------------------
# Краевые случаи формата
# ----------------------------

def test_malformed_token(svc_rs256):
    with pytest.raises(TokenInvalid):
        svc_rs256.verify("not.a.jwt")

def test_reject_non_base64_segments(svc_rs256, keystore_rs256, base_claims):
    priv = keystore_rs256.get_by_kid("r1")
    token = jwt_encode("RS256", "r1", priv.material, base_claims)
    h, p, s = token.split(".")
    bad = ".".join([h, p[:-1] + "*", s])
    with pytest.raises(TokenInvalid):
        svc_rs256.verify(bad)
