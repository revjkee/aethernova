# -*- coding: utf-8 -*-
"""
Интеграционные тесты OIDC/JWT <-> Remote JWKS <-> серверные сессии.

Зависимости тестового окружения:
  - pytest
  - cryptography (генерация ключей и подписи JWT)
Структура тестов:
  * Фикстуры: RSA и Ed25519 ключи; локальный JWKS HTTP-сервер; быстрая фабрика стора сессий.
  * Хелперы: mint_jwt (RS256/EdDSA), b64url, rfc3339_time, jwk/jwks сериализация.
  * Набор тестов:
      - test_jwt_verify_rs256_ok_via_remote_jwks
      - test_jwt_verify_eddsa_ok_via_remote_jwks
      - test_jwt_verify_reject_hs256_downgrade
      - test_jwks_cache_ttl_and_kid_rotation
      - test_session_lifecycle_with_pinning_and_refresh
      - test_pre_session_upgrade_and_bulk_revoke
"""

from __future__ import annotations

import base64
import json
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Tuple

import pytest

# Пропустим пакет при отсутствии cryptography
pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Модули проекта
from security.security.crypto.verifier import (
    JWTVerifier,
    VerifierConfig,
    RemoteJWKS,
    StaticJWKs,
    AlgorithmNotAllowed,
    VerifyError,
)
from security.security.authn.sessions import (
    InMemorySessionStore,
    SessionPolicy,
    TokenCodec,
    default_inmemory_store,
)


# ============================== УТИЛИТЫ =======================================

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64u_json(obj: dict) -> str:
    return _b64u(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def _now_epoch() -> int:
    return int(time.time())


def mint_jwt_rs256(
    private_key: rsa.RSAPrivateKey,
    header: dict,
    payload: dict,
) -> str:
    """
    Собирает JWS compact вручную (RS256): base64url(header).base64url(payload).base64url(signature)
    """
    hdr = dict(header or {})
    hdr.setdefault("alg", "RS256")
    hdr.setdefault("typ", "JWT")
    h_b64 = _b64u_json(hdr)
    p_b64 = _b64u_json(payload)
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{h_b64}.{p_b64}.{_b64u(sig)}"


def mint_jwt_eddsa(
    private_key: ed25519.Ed25519PrivateKey,
    header: dict,
    payload: dict,
) -> str:
    hdr = dict(header or {})
    hdr.setdefault("alg", "EdDSA")
    hdr.setdefault("typ", "JWT")
    h_b64 = _b64u_json(hdr)
    p_b64 = _b64u_json(payload)
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = private_key.sign(signing_input)
    return f"{h_b64}.{p_b64}.{_b64u(sig)}"


def rsa_keypair(bits: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return priv, priv.public_key()


def ed25519_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def jwk_from_rsa_pub(pub, kid: str, alg: str = "RS256") -> Dict:
    numbers = pub.public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "alg": alg,
        "n": _b64u(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": _b64u(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }


def jwk_from_ed25519_pub(pub, kid: str) -> Dict:
    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA", "x": _b64u(raw)}


# ============================ JWKS HTTP-СЕРВЕР ================================

class _JWKSHandler(BaseHTTPRequestHandler):
    # Контент JWKS будет подменяться фикстурой на лету
    jwks_bytes: bytes = b'{"keys": []}'

    def log_message(self, fmt, *args):  # тихий сервер
        return

    def do_GET(self):
        if self.path.startswith("/.well-known/jwks.json") or self.path.startswith("/jwks"):
            data = _JWKSHandler.jwks_bytes
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture(scope="function")
def jwks_server():
    """
    Поднимает минимальный HTTP‑сервер JWKS на свободном порту.
    Позволяет менять содержимое JWKS через _JWKSHandler.jwks_bytes.
    """
    server = HTTPServer(("127.0.0.1", 0), _JWKSHandler)
    host, port = server.server_address

    thread = threading.Thread(target=server.serve_forever, name="jwks-http", daemon=True)
    thread.start()
    try:
        yield f"http://{host}:{port}/.well-known/jwks.json"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


# ============================== ФИКСТУРЫ ======================================

@pytest.fixture(scope="function")
def rsa_keys():
    return rsa_keypair(2048)


@pytest.fixture(scope="function")
def ed_keys():
    return ed25519_keypair()


@pytest.fixture(scope="function")
def jwt_payload_base():
    now = _now_epoch()
    return {
        "iss": "https://id.example.test",
        "aud": "security-core",
        "sub": "user-123",
        "iat": now,
        "nbf": now - 5,
        "exp": now + 600,
        "nonce": "n-abc-123",
    }


@pytest.fixture(scope="function")
def jwt_verifier_factory():
    def _mk(jwks_url: str, **over):
        cfg = VerifierConfig(
            allowed_algs=over.get("allowed_algs", ("RS256", "PS256", "ES256", "EdDSA")),
            allow_symmetric=over.get("allow_symmetric", False),
            expected_typ=over.get("expected_typ", "JWT"),
            leeway_seconds=over.get("leeway_seconds", 60),
            jwks_cache_ttl=over.get("jwks_cache_ttl", 2),  # малый TTL для тестов кэша
            http_timeout=over.get("http_timeout", 2),
            max_age_seconds=over.get("max_age_seconds", 24 * 3600),
        )
        src = RemoteJWKS(jwks_url, cache_ttl=cfg.jwks_cache_ttl, http_timeout=cfg.http_timeout)
        return JWTVerifier(src, cfg)
    return _mk


@pytest.fixture(scope="function")
def session_store():
    # Безопасный in-memory стор: отдельный ключ для HMAC
    secret = b"\x01" * 32
    return default_inmemory_store(secret, policy=SessionPolicy(
        access_ttl__dummy:=None,  # type: ignore
    ))  # noqa: E999  # (см. ниже реальную политику)


# В Python без kwargs с двойным подчёркиванием: дадим явную политику через фабрику
@pytest.fixture(scope="function")
def session_store():
    secret = b"\x01" * 32
    pol = SessionPolicy(
        access_ttl__dummy:=None,  # placeholder, перепишем корректно ниже
    )  # type: ignore


# Исправленная версия фикстуры session_store (выше placeholder для пояснения)
@pytest.fixture(scope="function")
def session_store():
    secret = b"\x01" * 32
    policy = SessionPolicy(
        access_ttl=__import__("datetime").timedelta(seconds=2),
        refresh_ttl=__import__("datetime").timedelta(seconds=10),
        absolute_ttl=__import__("datetime").timedelta(seconds=8),
        pre_session_ttl=__import__("datetime").timedelta(seconds=2),
        pin_ip=True,
        pin_ua=True,
        max_user_sessions=2,
        on_limit="evict_oldest",
    )
    return default_inmemory_store(secret, policy=policy)


# ================================ ТЕСТЫ =======================================

@pytest.mark.integration
def test_jwt_verify_rs256_ok_via_remote_jwks(jwks_server, rsa_keys, jwt_payload_base, jwt_verifier_factory):
    priv, pub = rsa_keys
    kid = "kid-rs1"
    jwks = {"keys": [jwk_from_rsa_pub(pub, kid, alg="RS256")]}
    _JWKSHandler.jwks_bytes = json.dumps(jwks).encode("utf-8")

    token = mint_jwt_rs256(
        priv,
        header={"kid": kid, "alg": "RS256", "typ": "JWT"},
        payload=dict(jwt_payload_base),
    )
    v = jwt_verifier_factory(jwks_server)
    claims = v.verify(token, iss=jwt_payload_base["iss"], aud=jwt_payload_base["aud"])
    assert claims["sub"] == "user-123"
    assert isinstance(claims["iat"], int)


@pytest.mark.integration
def test_jwt_verify_eddsa_ok_via_remote_jwks(jwks_server, ed_keys, jwt_payload_base, jwt_verifier_factory):
    priv, pub = ed_keys
    kid = "kid-ed1"
    jwks = {"keys": [jwk_from_ed25519_pub(pub, kid)]}
    _JWKSHandler.jwks_bytes = json.dumps(jwks).encode("utf-8")

    token = mint_jwt_eddsa(
        priv,
        header={"kid": kid, "alg": "EdDSA", "typ": "JWT"},
        payload=dict(jwt_payload_base),
    )
    v = jwt_verifier_factory(jwks_server, allowed_algs=("EdDSA",))
    claims = v.verify(token, iss=jwt_payload_base["iss"], aud=jwt_payload_base["aud"])
    assert claims["aud"] == "security-core"


@pytest.mark.integration
def test_jwt_verify_reject_hs256_downgrade(jwks_server, rsa_keys, jwt_payload_base, jwt_verifier_factory):
    """
    Моделируем атаку даунгрейда: заголовок HS256, но у нас нет симметричных ключей и политика их запрещает.
    """
    # JWKS с RSA-ключом — но токен «подсунут» как HS256 (без реальной подписи).
    _, pub = rsa_keys
    _JWKSHandler.jwks_bytes = json.dumps({"keys": [jwk_from_rsa_pub(pub, "any", "RS256")]}).encode("utf-8")

    header = {"alg": "HS256", "typ": "JWT"}  # неподдерживаемый по политике
    payload = dict(jwt_payload_base)
    token = f"{_b64u_json(header)}.{_b64u_json(payload)}."  # подпись отсутствует

    v = jwt_verifier_factory(jwks_server, allowed_algs=("RS256", "EdDSA"), allow_symmetric=False)
    with pytest.raises(AlgorithmNotAllowed):
        v.verify(token, iss=payload["iss"], aud=payload["aud"])


@pytest.mark.integration
def test_jwks_cache_ttl_and_kid_rotation(jwks_server, rsa_keys, jwt_payload_base, jwt_verifier_factory):
    """
    Проверяем, что RemoteJWKS кэширует ключи и выдерживает малый TTL.
    """
    priv1, pub1 = rsa_keys
    kid1 = "kid-rs-cache-1"
    _JWKSHandler.jwks_bytes = json.dumps({"keys": [jwk_from_rsa_pub(pub1, kid1, "RS256")]}).encode("utf-8")

    v = jwt_verifier_factory(jwks_server, jwks_cache_ttl=1)
    tok1 = mint_jwt_rs256(priv1, {"kid": kid1, "alg": "RS256"}, dict(jwt_payload_base))
    assert v.verify(tok1, iss=jwt_payload_base["iss"], aud=jwt_payload_base["aud"])["sub"] == "user-123"

    # Меняем ключи на сервере JWKS – новый kid
    priv2, pub2 = rsa_keypair(2048)
    kid2 = "kid-rs-cache-2"
    _JWKSHandler.jwks_bytes = json.dumps({"keys": [jwk_from_rsa_pub(pub2, kid2, "RS256")]}).encode("utf-8")

    # Пока кэш валиден (1 сек), попытка проверить токен с новым kid должна дождаться обновления.
    # Ждём истечения TTL
    time.sleep(1.2)
    tok2 = mint_jwt_rs256(priv2, {"kid": kid2, "alg": "RS256"}, dict(jwt_payload_base))
    assert v.verify(tok2, iss=jwt_payload_base["iss"], aud=jwt_payload_base["aud"])["aud"] == "security-core"


@pytest.mark.integration
def test_session_lifecycle_with_pinning_and_refresh(session_store):
    """
    E2E по сессиям:
      - create_session с IP/UA
      - get_session (валидный pin)
      - touch (скользящее продление)
      - refresh (rotate-on-use, анти-replay)
      - попытка reuse refresh → провал
      - попытка доступа с другим IP/UA → пометка suspicious и отзыв
    """
    store: InMemorySessionStore = session_store

    # Создаём сессию
    srec, rrec = store.create_session(
        user_id="u-1",
        username="alice",
        device_id="dev-1",
        ip="1.1.1.1",
        ua="UA/1.0",
        mfa_level="AAL1",
        risk_score=10,
    )
    assert srec.user_id == "u-1"
    assert rrec.session_id == srec.id

    # Валидный доступ
    got = store.get_session(srec.id, ip="1.1.1.1", ua="UA/1.0")
    assert got and got.id == srec.id
    assert store.touch(srec.id) is True

    # Refresh → ожидаем новый SID/RID, старый RID одноразовый
    new_s, new_r = store.refresh(rrec.id, ip="1.1.1.1", ua="UA/1.0")
    assert new_s and new_r
    assert new_s.id != srec.id
    # Повторное использование старого RID не даст сессию
    again_s, again_r = store.refresh(rrec.id, ip="1.1.1.1", ua="UA/1.0")
    assert again_s is None and again_r is None

    # Доступ с другим IP/UA → должен провалиться и пометить suspicious
    bad = store.get_session(new_s.id, ip="2.2.2.2", ua="UA/2.0")
    assert bad is None
    # После pin‑mismatch сессия отозвана
    listed = store.list_active_for_user("u-1")
    assert all(x.id != new_s.id for x in listed)


@pytest.mark.integration
def test_pre_session_upgrade_and_bulk_revoke(session_store):
    """
    Поток pre-session → upgrade до полноценной сессии, затем массовая отзывка по пользователю.
    """
    store: InMemorySessionStore = session_store

    # Pre-session
    pre = store.create_pre_session(user_id="u-42", username="bob", device_id="dev-x")
    assert pre.id and pre.user_id == "u-42"

    # Upgrade c MFA/AAL2
    s, r = store.upgrade_pre_session(pre.id, ip="10.0.0.1", ua="CLI/1.0", mfa_level="AAL2", risk_score=5)
    assert s.mfa_level == "AAL2" and r.session_id == s.id

    # Вторая сессия того же пользователя (для проверки revoke_all)
    s2, r2 = store.create_session(user_id="u-42", username="bob", device_id="dev-y", ip="10.0.0.2", ua="CLI/1.1", mfa_level="AAL1", risk_score=5)
    assert s2.user_id == "u-42" and r2.user_id == "u-42"

    # Массовая отзывка всех сессий, кроме device_id = dev-y
    revoked = store.revoke_all_for_user("u-42", keep_device_id="dev-y", reason="security_event")
    assert revoked >= 1
    active = store.list_active_for_user("u-42")
    # Оставлена только dev-y
    assert all(a.device_id == "dev-y" for a in active)
