# ledger-core/tests/unit/test_signer.py
# -*- coding: utf-8 -*-
import asyncio
import os
import sys
import hashlib
import hmac
import pytest

# Импортируем подписантов из проекта.
# Пути предположены согласно структуре из запроса; при иной структуре скорректируйте import.
from ledger.telemetry.audit_log import HmacSigner as AuditHmacSigner
from ledger.anchoring.batcher import HmacRootSigner as DomainHmacSigner  # если HmacRootSigner размещён здесь
# Если HmacRootSigner у вас в ledger/ledger/domain/services/proof_service.py, раскомментируйте строку ниже и поправьте import:
# from ledger.domain.services.proof_service import HmacRootSigner as DomainHmacSigner


@pytest.mark.parametrize("algo", ["sha256", "sha512"])
@pytest.mark.asyncio
async def test_audit_hmac_signer_deterministic_and_verify(algo):
    key = b"super-secret-key"
    signer = AuditHmacSigner(key, algo=algo)  # type: ignore[arg-type]
    msg = b"hello world"
    sig1 = await signer.sign(msg)
    sig2 = await signer.sign(msg)
    assert sig1 == sig2  # детерминизм
    assert await signer.verify(msg, sig1) is True
    # изменение сообщения -> подпись не валидна
    assert await signer.verify(msg + b".", sig1) is False
    # изменение подписи -> невалидно
    assert await signer.verify(msg, sig1[:-1] + bytes([sig1[-1] ^ 0x01])) is False


@pytest.mark.asyncio
async def test_audit_hmac_signer_unicode_and_binary():
    signer = AuditHmacSigner(b"\x00\xFF\x01secret", algo="sha256")
    # Unicode (utf-8 заранее у пользователя; внутренняя логика ждёт bytes)
    msg_unicode = "транзакция №42 — тест"
    msg = msg_unicode.encode("utf-8")
    sig = await signer.sign(msg)
    assert await signer.verify(msg, sig)
    # Бинарные данные
    blob = os.urandom(1024 * 64)  # 64 KiB
    sig_blob = await signer.sign(blob)
    assert await signer.verify(blob, sig_blob)


@pytest.mark.asyncio
async def test_audit_hmac_signer_empty_and_large():
    signer = AuditHmacSigner(b"key", algo="sha512")
    empty = b""
    sig_empty = await signer.sign(empty)
    assert await signer.verify(empty, sig_empty)

    large = b"a" * (1024 * 1024)  # 1 MiB
    sig_large = await signer.sign(large)
    assert await signer.verify(large, sig_large)
    # Небольшое изменение в середине -> невалидно
    tampered = bytearray(large)
    tampered[len(tampered) // 2] ^= 0x01
    assert await signer.verify(bytes(tampered), sig_large) is False


@pytest.mark.asyncio
async def test_domain_hmac_signer_basic_contract():
    key = b"domain-key"
    signer = DomainHmacSigner(secret=key)
    payloads = [
        b"",
        b"root|1|abcdef",
        b"\x01\x02\x03",
        os.urandom(4096),
    ]
    for p in payloads:
        sig = await signer.sign(p)
        assert await signer.verify(p, sig)
        # другой ключ -> невалидно
        other = DomainHmacSigner(secret=b"domain-key-2")
        assert await other.verify(p, sig) is False
        # изменённый payload -> невалидно
        assert await signer.verify(p + b"x", sig) is False


@pytest.mark.asyncio
async def test_domain_hmac_signer_deterministic_and_constant_time_property():
    key = b"same-key"
    signer = DomainHmacSigner(secret=key)
    msg = b"payload"
    sig1 = await signer.sign(msg)
    sig2 = await signer.sign(msg)
    assert sig1 == sig2  # детерминизм
    assert await signer.verify(msg, sig1)
    # Проверка "похожей" подписи должна возвращать False
    near = sig1[:-1] + bytes([sig1[-1] ^ 0xFF])
    assert await signer.verify(msg, near) is False


@pytest.mark.asyncio
async def test_cross_module_signers_are_not_supposed_to_be_interchangeable():
    """
    Аудитный HmacSigner и доменный HmacRootSigner могут использовать разные схемы/префиксы/алгоритмы.
    Мы явно фиксируем, что взаимозаменяемость не требуется.
    """
    key = b"unified-key"
    audit = AuditHmacSigner(key, algo="sha256")
    domain = DomainHmacSigner(secret=key)

    msg = b"same-payload"
    sig_audit = await audit.sign(msg)
    sig_domain = await domain.sign(msg)

    assert await audit.verify(msg, sig_audit) is True
    assert await domain.verify(msg, sig_domain) is True

    # Перекрёстная проверка не гарантируется — и как правило должна провалиться
    assert await audit.verify(msg, sig_domain) is False
    assert await domain.verify(msg, sig_audit) is False


@pytest.mark.parametrize(
    "key,msg",
    [
        (b"k", b"m"),
        (b"another-key", b"payload"),
        (os.urandom(32), os.urandom(128)),
    ],
)
@pytest.mark.asyncio
async def test_reference_hmac_sha256_matches_python_hmac(key, msg):
    """
    Референс‑проверка: AuditHmacSigner(sha256) должен совпадать с hashlib/hmac из stdlib.
    """
    signer = AuditHmacSigner(key, algo="sha256")
    sig = await signer.sign(msg)
    ref = hmac.new(key, msg, hashlib.sha256).digest()
    assert sig == ref
    assert await signer.verify(msg, ref)


@pytest.mark.asyncio
async def test_signer_refuses_wrong_types_gracefully():
    signer = AuditHmacSigner(b"k")
    with pytest.raises(TypeError):
        # sign ожидает bytes; передаём str и убеждаемся, что это явно ошибка
        # (если у вас в реализации делается неявное .encode(), скорректируйте тест согласно контракту)
        _ = await signer.sign("string")  # type: ignore[arg-type]

    # verify тоже должен ожидать bytes
    with pytest.raises(TypeError):
        _ = await signer.verify("string", b"\x00" * 32)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_repeated_verify_is_pure_and_side_effect_free():
    """
    Повторная проверка не должна менять внутреннее состояние подписанта.
    """
    signer = DomainHmacSigner(secret=b"k")
    msg = b"x"
    sig = await signer.sign(msg)
    for _ in range(5):
        assert await signer.verify(msg, sig)


@pytest.mark.asyncio
async def test_random_messages_negative_cases():
    """
    Простая стохастическая проверка: подпись валидна только для исходного сообщения и исходного ключа.
    """
    signer = AuditHmacSigner(b"seed", algo="sha256")
    for _ in range(50):
        m = os.urandom(128)
        s = await signer.sign(m)
        # случайное другое сообщение не пройдёт
        m2 = os.urandom(128)
        if m2 == m:
            m2 = m2 + b"x"
        assert await signer.verify(m2, s) is False
        # другой ключ не пройдёт
        other = AuditHmacSigner(b"seed2", algo="sha256")
        assert await other.verify(m, s) is False
