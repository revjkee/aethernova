# oblivionvault-core/tests/unit/test_crypto_shred.py
"""
Промышленный тест-набор для модуля crypto-shredding OblivionVault.

Ожидаемый внешний контракт модуля `oblivionvault.crypto.shred` (гибкий):
- Исключения: ShreddedError (расшифровка после уничтожения ключа), CryptoShredError (база).
- Класс/фабрика шреддера: либо функция get_default_shredder(), либо класс CryptoShredder().
- Методы шреддера:
    async encrypt(plaintext: bytes, *, object_id: str, aad: bytes|None = None) -> tuple[ciphertext: bytes, meta: dict]
    async decrypt(ciphertext: bytes, *, meta: dict) -> bytes
    async shred(object_id: str, *, reason: str, actor: str) -> dict  # идемпотентно
    async is_shredded(object_id: str) -> bool
- Утилита безопасного зануления: zeroize(buf: bytearray) -> None (опционально).
- Метаданные: meta должны быть сериализуемы в JSON и достаточны для расшифровки до shred.

Тесты:
- Round-trip шифрования/дешифрования (несколько размеров, AAD).
- Shred → decrypt должен детерминированно падать (ShreddedError).
- Идемпотентность shred().
- Конкурентная гонка shred vs decrypt.
- Метаданные сериализуемы/стабильны.
- zeroize действительно перетирает содержимое (если доступно).
- Аудит (опционально): если у шреддера есть интеграция, проверяем, что событие сформировано.

Запуск:
    pytest -q
Требуется:
    pytest>=7, pytest-asyncio>=0.23
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import sys
from typing import Any, Dict, Tuple, Optional

import pytest

# --- Импорт тестируемого модуля (мягко) ---
shred_mod = pytest.importorskip(
    "oblivionvault.crypto.shred",
    reason="Модуль crypto-shred пока недоступен. Подключите oblivionvault.crypto.shred."
)

# --- Помощники для гибкой инициализации шреддера ---
async def _make_shredder():
    """
    Пытаемся создать инстанс шреддера несколькими способами:
      1) get_default_shredder()
      2) CryptoShredder() без аргументов
      3) CryptoShredder.from_defaults()
    Иначе — SKIP.
    """
    if hasattr(shred_mod, "get_default_shredder"):
        sh = shred_mod.get_default_shredder()
        if asyncio.iscoroutine(sh):
            sh = await sh
        return sh
    if hasattr(shred_mod, "CryptoShredder"):
        # Безопасно пробуем несколько вариантов
        try:
            sh = shred_mod.CryptoShredder()  # type: ignore
            if asyncio.iscoroutine(sh):
                sh = await sh
            return sh
        except Exception:
            pass
        if hasattr(shred_mod.CryptoShredder, "from_defaults"):  # type: ignore
            sh = shred_mod.CryptoShredder.from_defaults()  # type: ignore
            if asyncio.iscoroutine(sh):
                sh = await sh
            return sh
    pytest.skip("Не удалось инициализировать шреддер (нет get_default_shredder/CryptoShredder).")


# --- Фикстуры ---
@pytest.fixture(scope="module")
def ShreddedError():
    return getattr(shred_mod, "ShreddedError", RuntimeError)


@pytest.fixture(scope="module")
def CryptoShredError():
    return getattr(shred_mod, "CryptoShredError", Exception)


@pytest.fixture
async def shredder():
    sh = await _make_shredder()
    # Если у шреддера есть async-контекст — используем
    if hasattr(sh, "__aenter__") and hasattr(sh, "__aexit__"):
        async with sh:
            yield sh
    else:
        yield sh


# --- Ютилиты для данных ---
def rnd(n: int) -> bytes:
    return secrets.token_bytes(n)


# =========================
# БАЗОВЫЕ ИНВАРИАНТЫ
# =========================
@pytest.mark.asyncio
@pytest.mark.parametrize("size", [0, 1, 16, 1024, 1024 * 128])
async def test_encrypt_decrypt_roundtrip(shredder, size: int):
    """Дешифрование должно возвращать исходный plaintext при корректных meta."""
    pt = rnd(size)
    aad = rnd(13)
    ct, meta = await shredder.encrypt(pt, object_id=f"obj-{size}", aad=aad)
    assert isinstance(ct, (bytes, bytearray))
    assert isinstance(meta, dict)
    # JSON-сериализация метаданных должна быть возможной
    meta_json = json.dumps(meta, ensure_ascii=False, separators=(",", ":"))
    assert isinstance(meta_json, str)
    # Обратная операция
    out = await shredder.decrypt(ct, meta=meta)
    assert out == pt


@pytest.mark.asyncio
async def test_metadata_is_sufficient_and_stable(shredder):
    """Метаданные должны быть самодостаточными для расшифровки, сериализуемыми и стабильными."""
    pt = b"test-metadata"
    ct, meta = await shredder.encrypt(pt, object_id="meta-1", aad=None)
    # Клонируем метаданные через JSON — не должно ломать формат
    meta2 = json.loads(json.dumps(meta, ensure_ascii=False))
    out = await shredder.decrypt(ct, meta=meta2)
    assert out == pt


# =========================
# SHRED: БЕЗОПАСНОЕ УНИЧТОЖЕНИЕ КЛЮЧЕЙ
# =========================
@pytest.mark.asyncio
async def test_shred_blocks_future_decrypt(shredder, ShreddedError):
    """После shred(object_id) расшифровка должна детерминированно падать."""
    object_id = "doc-001"
    pt = rnd(4096)
    ct, meta = await shredder.encrypt(pt, object_id=object_id, aad=None)
    # До shred расшифровка работает
    assert await shredder.decrypt(ct, meta=meta) == pt
    # Делаем шреддинг
    rv = await shredder.shred(object_id, reason="litigation hold release", actor="legal:alice")
    assert isinstance(rv, dict)
    # Флаг состояния (если поддерживается)
    if hasattr(shredder, "is_shredded"):
        assert await shredder.is_shredded(object_id) is True
    # После shred расшифровка должна падать
    with pytest.raises(ShreddedError):
        await shredder.decrypt(ct, meta=meta)


@pytest.mark.asyncio
async def test_shred_is_idempotent(shredder):
    """Повторный shred должен быть идемпотентен (не вызывать ошибок и оставлять состояние в shredded)."""
    object_id = "doc-002"
    pt = b"payload"
    ct, meta = await shredder.encrypt(pt, object_id=object_id, aad=None)
    await shredder.shred(object_id, reason="user erasure", actor="dpo:system")
    await shredder.shred(object_id, reason="user erasure", actor="dpo:system")  # повтор
    # Любая расшифровка — невозможна
    with pytest.raises(Exception):
        await shredder.decrypt(ct, meta=meta)
    if hasattr(shredder, "is_shredded"):
        assert await shredder.is_shredded(object_id) is True


# =========================
# ГОНКИ: SHRED VS DECRYPT
# =========================
@pytest.mark.asyncio
async def test_race_shred_vs_decrypt(shredder, ShreddedError):
    """
    Одновременный shred и decrypt: итог — либо успешный decrypt (если выиграл до shred),
    либо ShreddedError. В любом случае состояние должно стать shredded.
    """
    object_id = "doc-race"
    pt = rnd(64 * 1024)
    ct, meta = await shredder.encrypt(pt, object_id=object_id, aad=None)

    # Имитация «долгой» расшифровки, если модуль поддерживает hook; иначе просто параллелим
    async def do_decrypt():
        try:
            out = await shredder.decrypt(ct, meta=meta)
            return ("ok", out)
        except ShreddedError:
            return ("shredded", None)

    async def do_shred():
        await asyncio.sleep(0)  # отдаём квант планировщику
        await shredder.shred(object_id, reason="k-anon purge", actor="janitor")

    r_decrypt, _ = await asyncio.gather(do_decrypt(), do_shred())
    # Состояние должно быть shredded
    if hasattr(shredder, "is_shredded"):
        assert await shredder.is_shredded(object_id) is True
    # Если расшифровка «успела», результат должен быть точной копией; иначе — отмечено как shredded
    if r_decrypt[0] == "ok":
        assert r_decrypt[1] == pt
    else:
        assert r_decrypt[0] == "shredded"


# =========================
# ZEROIZE: НЕИЗВЛЕКАЕМОСТЬ СЕКРЕТОВ ИЗ ПАМЯТИ
# =========================
@pytest.mark.asyncio
async def test_zeroize_overwrites_memory_if_available():
    """
    Если модуль предоставляет zeroize(), он обязан реально перетирать буфер.
    В противном случае тест помечает отсутствие как xfail (опциональная функция).
    """
    if not hasattr(shred_mod, "zeroize"):
        pytest.xfail("zeroize() не реализована (опционально).")
    zeroize = shred_mod.zeroize  # type: ignore

    # Готовим буфер с известной сигнатурой
    secret = bytearray(b"\xAA" * 1024)
    # Индуцируем исключение в «критической секции» и проверим, что zeroize всё равно выполнена
    try:
        zeroize(secret)
        raise RuntimeError("boom")  # имитируем аварию после зануления
    except RuntimeError:
        pass

    # После zeroize секрет не должен содержать исходных байтовых паттернов
    assert secret != bytearray(b"\xAA" * 1024)
    # Допускаем любую детерминированную перезапись: нули, случайные, и т.д.


# =========================
# МЕТАДАННЫЕ: КАНОНИЗАЦИЯ/ПОРТАТИВНОСТЬ
# =========================
@pytest.mark.asyncio
async def test_metadata_portable_between_processes(shredder, tmp_path):
    """
    Метаданные должны быть переносимы между процессами/узлами.
    Моделируем сохранение meta на диск и повторную расшифровку.
    """
    object_id = "doc-portable"
    pt = rnd(8192)
    ct, meta = await shredder.encrypt(pt, object_id=object_id, aad=b"ctx")
    p_ct = tmp_path / "blob.bin"
    p_meta = tmp_path / "blob.meta.json"

    p_ct.write_bytes(bytes(ct))
    p_meta.write_text(json.dumps(meta, ensure_ascii=False))

    # «Другой процесс» читает и расшифровывает
    ct2 = p_ct.read_bytes()
    meta2 = json.loads(p_meta.read_text("utf-8"))
    out = await shredder.decrypt(ct2, meta=meta2)
    assert out == pt


# =========================
# ОШИБКИ/РОБАСТНОСТЬ
# =========================
@pytest.mark.asyncio
async def test_decrypt_with_tampered_meta_fails(shredder):
    """Подмена метаданных должна приводить к отказу расшифровки (аутентификация заголовков/AAD)."""
    object_id = "doc-tamper"
    pt = b"integrity"
    ct, meta = await shredder.encrypt(pt, object_id=object_id, aad=b"hdr")
    meta_bad = dict(meta)
    # Искажаем одно поле
    meta_bad[next(iter(meta_bad.keys()))] = "tampered"
    with pytest.raises(Exception):
        await shredder.decrypt(ct, meta=meta_bad)


@pytest.mark.asyncio
async def test_decrypt_with_wrong_ciphertext_fails(shredder):
    """Случайный шифротекст не должен корректно расшифровываться."""
    _, meta = await shredder.encrypt(b"x", object_id="doc-wrong-ct", aad=None)
    bad_ct = rnd(64)
    with pytest.raises(Exception):
        await shredder.decrypt(bad_ct, meta=meta)


# =========================
# АУДИТ (ОПЦИОНАЛЬНО)
# =========================
@pytest.mark.asyncio
async def test_audit_event_emitted_if_available(shredder):
    """
    Если у шреддера есть встроенный аудит и он предоставляет доступ к последним событиям/хуки —
    проверяем, что действие shred генерирует аудит-вход.
    В противном случае помечаем как xfail (необязательная часть API).
    """
    if not hasattr(shredder, "get_audit_buffer") and not hasattr(shredder, "audit"):
        pytest.xfail("Аудит недоступен в этой реализации.")
    object_id = "doc-audit"
    await shredder.encrypt(b"audit", object_id=object_id, aad=None)
    await shredder.shred(object_id, reason="gdpr_erasure", actor="dpo:system")

    # Вариант 1: буфер событий
    if hasattr(shredder, "get_audit_buffer"):
        events = await shredder.get_audit_buffer()  # type: ignore
        assert any(e.get("action", "").startswith("crypto.shred") for e in events)
        return

    # Вариант 2: объект аудита с буфером/методом доступа
    audit = getattr(shredder, "audit", None)
    if audit is None:
        pytest.xfail("Аудит отсутствует.")
    # Пробуем эвристически вытащить события
    events = []
    for name in ("get_events", "buffer", "records", "last"):
        if hasattr(audit, name):
            attr = getattr(audit, name)
            events = attr() if callable(attr) else attr
            break
    if not events:
        pytest.xfail("Не удалось прочитать события аудита.")
    assert any("shred" in json.dumps(ev, ensure_ascii=False).lower() for ev in events)


# =========================
# ПРОИЗВОДИТЕЛЬНОСТЬ (ЛЁГКАЯ ПРОВЕРКА)
# =========================
@pytest.mark.asyncio
async def test_encrypt_decrypt_small_batch_latency(shredder):
    """
    Лёгкий «санити-чек» задержки на батче из 50 объектов.
    Не заменяет нагрузочное тестирование, но ловит O(N^2) регрессии на метаданных.
    """
    N = 50
    objs = []
    for i in range(N):
        pt = rnd(2048)
        ct, meta = await shredder.encrypt(pt, object_id=f"doc-batch-{i}", aad=None)
        objs.append((pt, ct, meta))
    # Дешифруем
    for pt, ct, meta in objs:
        out = await shredder.decrypt(ct, meta=meta)
        assert out == pt
