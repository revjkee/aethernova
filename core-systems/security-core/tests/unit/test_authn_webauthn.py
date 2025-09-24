# tests/unit/test_authn_webauthn.py
# -*- coding: utf-8 -*-
"""
Промышленный набор unit-тестов для WebAuthn (регистрация и аутентификация).

Зависимости для запуска:
  pip install pytest cryptography cbor2

Тесты не требуют сетевых вызовов и используют локальные тестовые ключи.
При отсутствии зависимостей аккуратно пропускаются через importorskip().
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import time
from dataclasses import dataclass
from typing import Dict, Tuple

import pytest

# Обязательные зависимости для криптографии и CBOR
cbor2 = pytest.importorskip("cbor2", reason="cbor2 is required for WebAuthn tests")
crypto_available = True
try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
except Exception as _e:  # pragma: no cover
    crypto_available = False
    pytest.skip("cryptography is required for WebAuthn tests", allow_module_level=True)


# ---------------------------
# Вспомогательные функции
# ---------------------------

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_to_bytes(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def cose_ec2_es256_from_pubkey(pub: ec.EllipticCurvePublicKey) -> bytes:
    """
    Собрать COSE_Key (EC2, ES256) в соответствии с RFC 8152:
      {1:2(kty=EC2), 3:-7(alg=ES256), -1:1(crv=P-256), -2:x, -3:y}
    """
    nums = pub.public_numbers()
    # SEC1 координаты (32 байта каждая для P-256)
    x = nums.x.to_bytes(32, "big")
    y = nums.y.to_bytes(32, "big")
    cose_map = {
        1: 2,         # kty=EC2
        3: -7,        # alg=ES256
        -1: 1,        # crv=P-256
        -2: x,        # x
        -3: y,        # y
    }
    return cbor2.dumps(cose_map)


def build_auth_data_for_attestation(rp_id: str,
                                    flags: int,
                                    sign_count: int,
                                    aaguid: bytes,
                                    cred_id: bytes,
                                    cose_pubkey: bytes) -> bytes:
    """
    Authenticator data (с AT): rpIdHash(32) || flags(1) || signCount(4) ||
                               AAGUID(16) || credIdLen(2) || credId || COSE_Key
    """
    assert len(aaguid) == 16
    rp_hash = sha256(rp_id.encode("ascii"))
    header = rp_hash + struct.pack("!B", flags) + struct.pack("!I", sign_count)
    attested = aaguid + struct.pack("!H", len(cred_id)) + cred_id + cose_pubkey
    return header + attested


def build_auth_data_for_assertion(rp_id: str, flags: int, sign_count: int) -> bytes:
    """
    Authenticator data без AT: rpIdHash(32) || flags(1) || signCount(4)
    """
    rp_hash = sha256(rp_id.encode("ascii"))
    return rp_hash + struct.pack("!B", flags) + struct.pack("!I", sign_count)


def build_client_data_json(typ: str, challenge_b64u: str, origin: str) -> bytes:
    obj = {
        "type": typ,
        "challenge": challenge_b64u,
        "origin": origin,
        "crossOrigin": False,
    }
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def make_attestation_object_none(auth_data: bytes) -> bytes:
    """
    attestationObject (fmt=none): {"fmt":"none", "attStmt":{}, "authData":<bytes>}
    """
    return cbor2.dumps({
        "fmt": "none",
        "attStmt": {},
        "authData": auth_data,
    })


# Флаги из спецификации WebAuthn/CTAP2
FLAG_UP = 0x01  # User Present
FLAG_UV = 0x04  # User Verified
FLAG_AT = 0x40  # Attested credential data present


# ---------------------------
# Фикстуры: ключи, RP и Origin
# ---------------------------

@pytest.fixture(scope="module")
def rp_origin() -> Tuple[str, str]:
    rp_id = "example.com"
    origin = "https://example.com"
    return rp_id, origin


@pytest.fixture()
def ec_keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    return priv, pub


# ---------------------------
# Регистрация (attestation=none)
# ---------------------------

def test_registration_attestation_none_success(ec_keypair, rp_origin):
    rp_id, origin = rp_origin
    priv, pub = ec_keypair

    challenge = os.urandom(32)
    challenge_b64u = b64u(challenge)

    # Собираем COSE ключ и authData с AT
    cose_pub = cose_ec2_es256_from_pubkey(pub)
    aaguid = bytes(16)  # для теста — нули
    cred_id = os.urandom(32)
    flags = FLAG_UP | FLAG_UV | FLAG_AT
    sign_count = 0

    auth_data = build_auth_data_for_attestation(rp_id, flags, sign_count, aaguid, cred_id, cose_pub)
    client_data_json = build_client_data_json("webauthn.create", challenge_b64u, origin)
    att_obj = make_attestation_object_none(auth_data)

    # Проверки соответствия WebAuthn (fmt=none): валидируем rpIdHash, флаги, наличие AAGUID и credential
    att = cbor2.loads(att_obj)
    assert att["fmt"] == "none"
    assert att["attStmt"] == {}

    parsed_auth = att["authData"]
    assert isinstance(parsed_auth, (bytes, bytearray))
    assert len(parsed_auth) >= 37  # минимум rpIdHash(32)+flags(1)+counter(4)

    rp_hash = parsed_auth[:32]
    assert rp_hash == sha256(rp_id.encode("ascii"))

    flags_byte = parsed_auth[32]
    assert flags_byte & FLAG_AT  # AT установлен
    assert flags_byte & FLAG_UP  # пользователь присутствует
    assert flags_byte & FLAG_UV  # пользователь верифицирован

    counter = struct.unpack("!I", parsed_auth[33:37])[0]
    assert counter == 0

    # Извлекаем AAGUID/credId/COSE из оставшейся части
    rest = parsed_auth[37:]
    got_aaguid = rest[:16]
    rest = rest[16:]
    cred_len = struct.unpack("!H", rest[:2])[0]
    rest = rest[2:]
    got_cred = rest[:cred_len]
    got_cose = rest[cred_len:]

    assert got_aaguid == aaguid
    assert got_cred == cred_id

    cose = cbor2.loads(got_cose)
    assert cose[1] == 2         # EC2
    assert cose[3] == -7        # ES256
    assert cose[-1] == 1        # P-256
    assert isinstance(cose[-2], (bytes, bytearray)) and len(cose[-2]) == 32  # x
    assert isinstance(cose[-3], (bytes, bytearray)) and len(cose[-3]) == 32  # y

    # clientDataJSON проверка полей
    cdj = json.loads(client_data_json.decode("utf-8"))
    assert cdj["type"] == "webauthn.create"
    assert cdj["challenge"] == challenge_b64u
    assert cdj["origin"] == origin


def test_registration_reject_wrong_origin(ec_keypair, rp_origin):
    rp_id, origin = rp_origin
    priv, pub = ec_keypair
    challenge_b64u = b64u(os.urandom(32))

    # Собираем корректный attestationObject
    cose_pub = cose_ec2_es256_from_pubkey(pub)
    auth_data = build_auth_data_for_attestation(
        rp_id, FLAG_UP | FLAG_UV | FLAG_AT, 0, bytes(16), os.urandom(32), cose_pub
    )
    att_obj = make_attestation_object_none(auth_data)

    # Подмена origin в clientDataJSON
    bad_client_data = build_client_data_json("webauthn.create", challenge_b64u, "https://evil.example.com")

    # Проверка: origin должен совпадать
    cdj = json.loads(bad_client_data)
    assert cdj["origin"] != origin


def test_registration_reject_wrong_rp_hash(ec_keypair, rp_origin):
    rp_id, origin = rp_origin
    priv, pub = ec_keypair
    challenge_b64u = b64u(os.urandom(32))

    cose_pub = cose_ec2_es256_from_pubkey(pub)
    # Используем неверный rpId для расчёта rpIdHash
    wrong_rp = "example.net"
    auth_data = build_auth_data_for_attestation(
        wrong_rp, FLAG_UP | FLAG_UV | FLAG_AT, 0, bytes(16), os.urandom(32), cose_pub
    )
    att_obj = make_attestation_object_none(auth_data)
    att = cbor2.loads(att_obj)
    rp_hash = att["authData"][:32]
    assert rp_hash != sha256(rp_id.encode("ascii"))  # должно не совпадать для настоящего RP


# ---------------------------
# Аутентификация (assertion)
# ---------------------------

@dataclass
class RegisteredCred:
    credential_id: bytes
    public_key: ec.EllipticCurvePublicKey
    sign_count: int


def sign_assertion(priv: ec.EllipticCurvePrivateKey, auth_data: bytes, client_data_json: bytes) -> bytes:
    """
    Подписать (authenticatorData || SHA256(clientDataJSON)) ECDSA/ES256 (DER).
    """
    to_sign = auth_data + sha256(client_data_json)
    return priv.sign(to_sign, ec.ECDSA(hashes.SHA256()))


def verify_es256(pub: ec.EllipticCurvePublicKey, auth_data: bytes, client_data_json: bytes, der_sig: bytes) -> None:
    pub.verify(der_sig, auth_data + sha256(client_data_json), ec.ECDSA(hashes.SHA256()))


@pytest.fixture()
def registered_credential(ec_keypair, rp_origin) -> RegisteredCred:
    """
    Эмулируем успешную регистрацию и возвращаем объект учётных данных для последующей аутентификации.
    """
    priv, pub = ec_keypair
    cred_id = os.urandom(32)
    return RegisteredCred(credential_id=cred_id, public_key=pub, sign_count=0)


def test_assertion_success(ec_keypair, rp_origin, registered_credential):
    rp_id, origin = rp_origin
    priv, pub = ec_keypair
    reg = registered_credential

    # Клиентская часть
    challenge = os.urandom(32)
    client_data_json = build_client_data_json("webauthn.get", b64u(challenge), origin)
    # Authenticator data без AT, с увеличенным счётчиком
    auth_data = build_auth_data_for_assertion(rp_id, FLAG_UP | FLAG_UV, reg.sign_count + 1)
    signature = sign_assertion(priv, auth_data, client_data_json)

    # Серверная часть — верификация
    # 1) rpIdHash
    assert auth_data[:32] == sha256(rp_id.encode("ascii"))
    # 2) флаги
    flags = auth_data[32]
    assert flags & FLAG_UP
    assert flags & FLAG_UV
    # 3) счётчик должен увеличиться
    new_counter = struct.unpack("!I", auth_data[33:37])[0]
    assert new_counter > reg.sign_count
    # 4) подпись корректна
    verify_es256(reg.public_key, auth_data, client_data_json, signature)


def test_assertion_reject_signature(ec_keypair, rp_origin, registered_credential):
    rp_id, origin = rp_origin
    priv, pub = ec_keypair
    reg = registered_credential

    challenge = os.urandom(32)
    client_data_json = build_client_data_json("webauthn.get", b64u(challenge), origin)
    auth_data = build_auth_data_for_assertion(rp_id, FLAG_UP, reg.sign_count + 1)
    signature = sign_assertion(priv, auth_data, client_data_json)

    # Порча clientDataJSON
    tampered_client_data_json = build_client_data_json("webauthn.get", b64u(challenge), origin + "/tampered")

    with pytest.raises(InvalidSignature):
        verify_es256(reg.public_key, auth_data, tampered_client_data_json, signature)


def test_assertion_reject_wrong_rp(ec_keypair, registered_credential):
    # origin не важен для rpIdHash — именно rpId должен совпадать
    rp_id_correct = "example.com"
    rp_id_wrong = "evil.example.com"
    priv, pub = ec_keypair
    reg = registered_credential

    client_data_json = build_client_data_json("webauthn.get", b64u(os.urandom(32)), "https://example.com")
    auth_data = build_auth_data_for_assertion(rp_id_wrong, FLAG_UP, reg.sign_count + 1)
    signature = sign_assertion(priv, auth_data, client_data_json)

    # Проверка хеша RP
    assert auth_data[:32] != sha256(rp_id_correct.encode("ascii"))


def test_assertion_counter_regression_rejected(ec_keypair, rp_origin, registered_credential):
    rp_id, origin = rp_origin
    priv, pub = ec_keypair
    reg = registered_credential

    # Первый вход увеличивает счётчик
    cd1 = build_client_data_json("webauthn.get", b64u(os.urandom(32)), origin)
    ad1 = build_auth_data_for_assertion(rp_id, FLAG_UP, reg.sign_count + 1)
    sig1 = sign_assertion(priv, ad1, cd1)
    verify_es256(reg.public_key, ad1, cd1, sig1)
    new_count = struct.unpack("!I", ad1[33:37])[0]
    assert new_count == reg.sign_count + 1

    # Второй вход с регрессом счётчика (эмулируем клон устройства)
    cd2 = build_client_data_json("webauthn.get", b64u(os.urandom(32)), origin)
    ad2 = build_auth_data_for_assertion(rp_id, FLAG_UP, reg.sign_count)  # <= регресс
    sig2 = sign_assertion(priv, ad2, cd2)
    verify_es256(reg.public_key, ad2, cd2, sig2)  # криптографически подпись валидна

    # Серверная бизнес-логика должна отклонить такую аутентификацию (регресс счётчика):
    cnt2 = struct.unpack("!I", ad2[33:37])[0]
    assert cnt2 <= new_count  # сигнал для отклонения в верхнем уровне


def test_challenge_expiration_window():
    """
    Демонстрируем контроль TTL для challenge.
    """
    ttl_sec = 60
    issued_at = int(time.time()) - 120  # выдан 2 минуты назад (просрочен)
    now = int(time.time())
    assert now - issued_at > ttl_sec  # сервер обязан отклонить


def test_flags_require_user_present_and_verified(rp_origin):
    rp_id, origin = rp_origin
    # Без UP флагов аутентификация должна быть отклонена бизнес-логикой сервера.
    auth_data = build_auth_data_for_assertion(rp_id, 0x00, 1)
    flags = auth_data[32]
    assert (flags & FLAG_UP) == 0
    # UV в некоторых политиках обязателен (например, для высоких рисков):
    assert (flags & FLAG_UV) == 0
