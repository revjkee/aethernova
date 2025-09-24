# oblivionvault-core/tests/integration/test_ledger_proof.py
import os
import io
import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

import pytest

# pytest-asyncio нужен для async тестов
pytestmark = pytest.mark.asyncio

# Аккуратно добавим корень репозитория в sys.path, если тесты запускаются из изолированного окружения
import sys
_HERE = Path(__file__).resolve()
for _up in (_HERE.parents[3], _HERE.parents[4] if len(_HERE.parents) >= 5 else None):
    if _up and (_up / "oblivionvault" / "utils" / "hashing.py").exists():
        if str(_up) not in sys.path:
            sys.path.insert(0, str(_up))
        break

from oblivionvault.utils import hashing as hv
from oblivionvault.archive.worm_store import WORMStore, WORMStoreConfig
from oblivionvault.adapters.ledger_core_adapter import (
    build_ledger_adapter,
    LedgerConfig,
    LedgerBackendType,
    make_anchor_request,
    AnchorStatus,
)


@pytest.fixture
def base_dirs(tmp_path: Path):
    base = tmp_path / "ov_demo"
    vault_dir = base / "vault"
    ledger_dir = base / "ledger"
    vault_dir.mkdir(parents=True, exist_ok=True)
    ledger_dir.mkdir(parents=True, exist_ok=True)
    return base, vault_dir, ledger_dir


async def _create_worm_and_ledger(vault_dir: Path, ledger_dir: Path, *, algo: hv.HashAlgo | None = None, chunk_size: int = 4 * 1024 * 1024):
    algo_eff = hv.ensure_algo(algo)
    store = WORMStore(
        WORMStoreConfig(
            base_dir=vault_dir,
            algo=algo_eff,
            chunk_size=chunk_size,
            # Остальные параметры — безопасные дефолты (без принудительного шифрования)
        )
    )
    ledger = build_ledger_adapter(
        LedgerConfig(
            base_dir=ledger_dir,
            backend=LedgerBackendType.FILE,
            db_filename="ledger.sqlite",
            synchronous_full=True,
            tenant="test",
        )
    )
    return store, ledger, algo_eff


async def _write_object(store: WORMStore, payload: bytes):
    return await store.write(payload, metadata={"testcase": "integration"}, actor="pytest")


def _read_sqlite_rows(db_path: Path, sql: str, params: tuple = ()) -> list[tuple]:
    con = sqlite3.connect(str(db_path))
    try:
        cur = con.execute(sql, params)
        return cur.fetchall()
    finally:
        con.close()


def _exec_sqlite(db_path: Path, sql: str, params: tuple = ()) -> None:
    con = sqlite3.connect(str(db_path))
    try:
        con.execute("BEGIN IMMEDIATE;")
        con.execute(sql, params)
        con.commit()
    finally:
        con.close()


async def test_file_ledger_anchor_and_verify_roundtrip(base_dirs):
    base, vault_dir, ledger_dir = base_dirs
    store, ledger, algo_eff = await _create_worm_and_ledger(vault_dir, ledger_dir)

    # Подготовим детерминированный полезный груз
    payload = b"ov-ledger-proof-roundtrip\n" + datetime.now(timezone.utc).isoformat().encode()
    info = await _write_object(store, payload)

    # Базовая проверка WORM
    assert await store.verify(info.content_id)

    # Сформируем канонический запрос на якорение
    req = make_anchor_request(
        content_id=info.content_id,
        merkle_root=info.merkle_root,
        size=info.size,
        metadata=info.metadata,
        tenant="test",
        created_at=info.created_at,
    )

    # Якорим и проверяем квитанцию
    rcpt = await ledger.anchor(req)
    assert rcpt.status in (AnchorStatus.CONFIRMED, AnchorStatus.DUPLICATE)
    assert rcpt.content_id == info.content_id
    assert rcpt.merkle_root == info.merkle_root
    assert rcpt.txid and isinstance(rcpt.txid, str)

    # Verify в ledger
    assert await ledger.verify(info.content_id) is True

    # Сверим, что txid действительно равен хэшу канонического события
    canon_bytes = req.canonical_event()
    expected_txid = hv.hash_bytes(canon_bytes, algo=hv.HashAlgo.auto_best())
    assert rcpt.txid == expected_txid

    await ledger.close()
    await store.close()


async def test_idempotent_anchor_same_object_twice(base_dirs):
    base, vault_dir, ledger_dir = base_dirs
    store, ledger, _ = await _create_worm_and_ledger(vault_dir, ledger_dir)

    payload = os.urandom(1024)
    info = await _write_object(store, payload)

    req = make_anchor_request(
        content_id=info.content_id,
        merkle_root=info.merkle_root,
        size=info.size,
        metadata=info.metadata,
        tenant="test",
        created_at=info.created_at,
    )

    r1 = await ledger.anchor(req)
    r2 = await ledger.anchor(req)

    # Первая запись подтверждена, вторая — дубликат
    assert r1.status == AnchorStatus.CONFIRMED
    assert r2.status == AnchorStatus.DUPLICATE
    assert r1.txid == r2.txid

    # Verify устойчив к дубликатам
    assert await ledger.verify(info.content_id) is True

    await ledger.close()
    await store.close()


async def test_batch_anchor_with_duplicates(base_dirs):
    base, vault_dir, ledger_dir = base_dirs
    store, ledger, _ = await _create_worm_and_ledger(vault_dir, ledger_dir)

    # Подготовим 3 объекта, один из которых будет продублирован
    infos = []
    for i in range(3):
        infos.append(await _write_object(store, b"A" * (256 + i)))

    # Сформируем запросы
    reqs = [
        make_anchor_request(
            content_id=i.content_id,
            merkle_root=i.merkle_root,
            size=i.size,
            metadata=i.metadata,
            tenant="test",
            created_at=i.created_at,
        )
        for i in infos
    ]
    # Добавим дубликат первого
    reqs.append(reqs[0])

    receipts = await ledger.anchor_batch(reqs)
    assert len(receipts) == 4

    statuses = [r.status for r in receipts]
    # Должна быть как минимум одна запись DUPLICATE
    assert any(s == AnchorStatus.DUPLICATE for s in statuses)
    # Остальные CONFIRMED
    assert sum(1 for s in statuses if s == AnchorStatus.CONFIRMED) >= 2

    # Verify для всех трех контент-ид
    for i in infos:
        assert await ledger.verify(i.content_id)

    await ledger.close()
    await store.close()


async def test_tamper_detection_on_metadata_breaks_txid_and_hmac(base_dirs):
    """
    Саботируем запись в SQLite: изменим metadata JSON у первой записи.
    Ожидаем, что verify(content_id) вернет False, так как:
      - txid != hash(canonical_event)
      - hmac_curr != HMAC(key, payload + hmac_prev)
    """
    base, vault_dir, ledger_dir = base_dirs
    store, ledger, _ = await _create_worm_and_ledger(vault_dir, ledger_dir)

    # Запишем и заякорим объект
    info = await _write_object(store, b"tamper-target")
    req = make_anchor_request(
        content_id=info.content_id,
        merkle_root=info.merkle_root,
        size=info.size,
        metadata=info.metadata,
        tenant="test",
        created_at=info.created_at,
    )
    rcpt = await ledger.anchor(req)
    assert rcpt.status == AnchorStatus.CONFIRMED

    # Путь к SQLite
    # Внутреннее поле (private), но для интеграционного теста допустимо
    db_path = Path(ledger_dir) / "ledger.sqlite"

    # Саботаж: заменим metadata на другое значение
    # Найдем строку с нашим content_id
    rows = _read_sqlite_rows(db_path, "SELECT id FROM anchors WHERE content_id=? LIMIT 1", (info.content_id,))
    assert rows, "anchor row not found"
    row_id = int(rows[0][0])

    _exec_sqlite(
        db_path,
        "UPDATE anchors SET metadata=? WHERE id=?",
        (json.dumps({"altered": True}, sort_keys=True, ensure_ascii=False), row_id),
    )

    # Verify должен обнаружить несоответствие
    ok = await ledger.verify(info.content_id)
    assert ok is False

    await ledger.close()
    await store.close()


async def test_tamper_chain_break_via_prev_hmac_mismatch(base_dirs):
    """
    Прервем HMAC-цепочку: изменим hmac_curr у первой записи.
    Ожидаем, что verify для второй записи провалится, т.к. ее hmac_prev перестанет совпадать.
    """
    base, vault_dir, ledger_dir = base_dirs
    store, ledger, _ = await _create_worm_and_ledger(vault_dir, ledger_dir)

    # Две записи
    info1 = await _write_object(store, b"chain-a")
    info2 = await _write_object(store, b"chain-b")

    req1 = make_anchor_request(content_id=info1.content_id, merkle_root=info1.merkle_root, size=info1.size, metadata=info1.metadata, tenant="test", created_at=info1.created_at)
    req2 = make_anchor_request(content_id=info2.content_id, merkle_root=info2.merkle_root, size=info2.size, metadata=info2.metadata, tenant="test", created_at=info2.created_at)

    r1 = await ledger.anchor(req1)
    r2 = await ledger.anchor(req2)
    assert r1.status == AnchorStatus.CONFIRMED
    assert r2.status == AnchorStatus.CONFIRMED

    db_path = Path(ledger_dir) / "ledger.sqlite"

    # Получим id обеих записей
    rows = _read_sqlite_rows(db_path, "SELECT id,content_id FROM anchors ORDER BY id ASC")
    assert len(rows) >= 2
    id1 = int(rows[0][0])
    id2 = int(rows[1][0])

    # Прервем цепочку: подменим hmac_curr первой записи
    _exec_sqlite(db_path, "UPDATE anchors SET hmac_curr=? WHERE id=?", ("00"*32, id1))

    # Verify первой записи провалится (txid может сойтись, но HMAC нет)
    assert await ledger.verify(info1.content_id) is False
    # Verify второй записи тоже провалится, т.к. у нее hmac_prev теперь не равен предыдущему hmac_curr
    assert await ledger.verify(info2.content_id) is False

    await ledger.close()
    await store.close()


async def test_worm_proof_tail_is_present(base_dirs):
    """
    Быстрая проверка: у WORM должен быть пруф и хвост аудита.
    """
    base, vault_dir, ledger_dir = base_dirs
    store, ledger, _ = await _create_worm_and_ledger(vault_dir, ledger_dir)

    info = await _write_object(store, b"proof-payload")
    proof = await store.proof(info.content_id)
    assert "object" in proof and "audit_tail" in proof
    assert isinstance(proof["audit_tail"], list)

    # Нормальная работа verify обеих подсистем
    assert await store.verify(info.content_id) is True

    req = make_anchor_request(
        content_id=info.content_id,
        merkle_root=info.merkle_root,
        size=info.size,
        metadata=info.metadata,
        tenant="test",
        created_at=info.created_at,
    )
    rcpt = await ledger.anchor(req)
    assert rcpt.status in (AnchorStatus.CONFIRMED, AnchorStatus.DUPLICATE)
    assert await ledger.verify(info.content_id) is True

    await ledger.close()
    await store.close()
