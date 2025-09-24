# ledger-core/tests/unit/test_proof_service.py
# -*- coding: utf-8 -*-
"""
Промышленные unit-тесты для подсистемы верификации доказательств:
- Merkle single inclusion
- Merkle batch
- Anchor receipt vs BlockHeader
- Разные алгоритмы хеширования
- Детерминизм audit digest
- CLI-путь (single/batch/anchor) через прямой вызов main()

Зависимости: pytest (стандарт для юнит-тестов).
"""

from __future__ import annotations

import json
import os
import sys
import types
import base64
import hashlib
import runpy
from pathlib import Path

import pytest

# Импорт тестируемых примитивов
from ledger.anchoring.proof_verifier import (
    ProofVerifier,
    MerkleProof,
    BatchMerkleProof,
    Sibling,
    AnchorReceipt,
    SimpleHeader,
    HashAlg,
    VerificationFailed,
    InvalidProofFormat,
    HashAlgorithmError,
)

# Без внешнего процесса: импортируем CLI main как функцию
from ledger.cli.tools import verify_proof as cli_mod


# ----------------------------- Утилиты для тестов -----------------------------

def _h(alg: HashAlg | str):
    if isinstance(alg, str):
        alg = HashAlg(alg)
    if alg == HashAlg.SHA256:
        return lambda b: hashlib.sha256(b).digest()
    if alg == HashAlg.KECCAK256:
        # Используем стандартный SHA3-256 (как в модуле)
        return lambda b: hashlib.sha3_256(b).digest()
    if alg == HashAlg.BLAKE2B_256:
        return lambda b: hashlib.blake2b(b, digest_size=32).digest()
    raise AssertionError("Unsupported alg in tests")

def _build_merkle_tree(leaves: list[bytes], alg: HashAlg = HashAlg.SHA256,
                       leaf_prefix: bytes = b"\x00LEAF", node_prefix: bytes = b"\x01NODE"):
    """
    Строим дерево в соответствии с политикой ProofVerifier: сначала leaf_prefix+leaf -> hash,
    далее node_prefix + concat(left,right) -> hash.
    Возвращает (root: bytes, levels: list[list[bytes]])
    """
    h = _h(alg)
    level = [h(leaf_prefix + x) for x in leaves]
    levels = [level]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]  # дублирование последнего (classic)
            nxt.append(h(node_prefix + left + right))
        level = nxt
        levels.append(level)
    root = level[0]
    return root, levels

def _merkle_proof_for_index(leaves: list[bytes], idx: int, alg: HashAlg = HashAlg.SHA256):
    """
    Возвращает MerkleProof (siblings с позициями) и корень для листа leaves[idx].
    """
    root, levels = _build_merkle_tree(leaves, alg=alg)
    # levels[0] = хешированные листья; levels[-1] = корень
    siblings = []
    cur_index = idx
    for depth, level in enumerate(levels[:-1]):  # до корня
        is_right = (cur_index % 2 == 1)
        sib_index = cur_index - 1 if is_right else cur_index + 1
        if sib_index >= len(level):
            # Случай дублирования последнего
            sib_hash = level[cur_index]
        else:
            sib_hash = level[sib_index]
        pos = "L" if is_right else "R"  # если текущий справа, sibling слева
        siblings.append(Sibling(hash=sib_hash, pos=pos))
        cur_index //= 2
    # Лист в MerkleProof — RAW, так как ProofVerifier сам добавит leaf_prefix при already_hashed=False
    return MerkleProof(leaf=leaves[idx], siblings=tuple(siblings), already_hashed=False), root


# ----------------------------- Тесты Merkle single -----------------------------

@pytest.mark.parametrize("alg", [HashAlg.SHA256, HashAlg.KECCAK256, HashAlg.BLAKE2B_256])
def test_merkle_single_success_all_algs(alg):
    leaves = [b"a", b"b", b"c", b"d", b"e"]
    proof, root = _merkle_proof_for_index(leaves, idx=3, alg=alg)
    v = ProofVerifier(hash_alg=alg)
    # Проверяем вычисление корня и успешную верификацию
    computed = v.compute_root_from_proof(proof)
    assert computed == root
    assert v.verify_merkle_inclusion(proof, root) is True


def test_merkle_single_fail_mismatched_root():
    leaves = [b"a", b"b", b"c", b"d"]
    proof, root = _merkle_proof_for_index(leaves, idx=1, alg=HashAlg.SHA256)
    v = ProofVerifier()
    # Искажаем ожидаемый корень
    bad_root = b"\x00" * 32
    with pytest.raises(VerificationFailed):
        v.verify_merkle_inclusion(proof, bad_root)


def test_merkle_single_invalid_format():
    # Пустые siblings
    with pytest.raises(InvalidProofFormat):
        MerkleProof(leaf=b"x", siblings=tuple(), already_hashed=False)
    # Неверная позиция
    with pytest.raises(InvalidProofFormat):
        Sibling(hash=b"\x01" * 32, pos="X")  # type: ignore


# ----------------------------- Тесты Merkle batch -----------------------------

def test_merkle_batch_success():
    leaves = [b"aa", b"bb", b"cc", b"dd", b"ee", b"ff"]
    proofs = []
    roots = set()
    for i in (0, 2, 5):
        p, r = _merkle_proof_for_index(leaves, i, alg=HashAlg.BLAKE2B_256)
        proofs.append(p)
        roots.add(r)
    assert len(roots) == 1
    batch = BatchMerkleProof(proofs=tuple(proofs), expected_root=roots.pop())
    v = ProofVerifier(hash_alg=HashAlg.BLAKE2B_256)
    assert v.verify_batch(batch) is True


def test_merkle_batch_fail_on_one_proof():
    leaves = [b"1", b"2", b"3", b"4"]
    p0, r = _merkle_proof_for_index(leaves, 0)
    p1, _ = _merkle_proof_for_index(leaves, 1)
    # Подменяем у p1 первый sibling на мусор, нарушая доказательство
    bad_sibs = list(p1.siblings)
    bad_sibs[0] = Sibling(hash=b"\xff" * len(bad_sibs[0].hash), pos=bad_sibs[0].pos)
    p1_bad = MerkleProof(leaf=p1.leaf, siblings=tuple(bad_sibs), already_hashed=p1.already_hashed)

    batch = BatchMerkleProof(proofs=(p0, p1_bad), expected_root=r)
    v = ProofVerifier()
    with pytest.raises(VerificationFailed):
        v.verify_batch(batch)


# ----------------------------- Тесты Anchor vs Header -------------------------

def test_anchor_against_header_success_state_root():
    anchor_root = b"\x11" * 32
    receipt = AnchorReceipt(
        chain_id="ethereum-mainnet",
        anchor_root=anchor_root,
        anchor_location="stateRoot",
        block_height=12345,
        block_root_type="state_root",
    )
    header = SimpleHeader(
        chain_id="ethereum-mainnet",
        height=12345,
        timestamp=1721029384,
        state_root=anchor_root,
        tx_merkle_root=None,
    )
    v = ProofVerifier()
    assert v.verify_anchor_against_header(receipt, header, require_root_match=True) is True


def test_anchor_against_header_mismatch_chain_or_height():
    anchor_root = b"\x22" * 32
    receipt = AnchorReceipt(
        chain_id="eth-mainnet",
        anchor_root=anchor_root,
        anchor_location="stateRoot",
        block_height=10,
        block_root_type="state_root",
    )
    header = SimpleHeader(
        chain_id="eth-mainnet",
        height=11,                     # высота не совпадает
        timestamp=0,
        state_root=anchor_root,
        tx_merkle_root=None,
    )
    v = ProofVerifier()
    with pytest.raises(VerificationFailed):
        v.verify_anchor_against_header(receipt, header, require_root_match=True)


def test_anchor_against_header_mismatch_root_field():
    anchor_root = b"\x33" * 32
    receipt = AnchorReceipt(
        chain_id="chain-x",
        anchor_root=anchor_root,
        anchor_location="stateRoot",
        block_height=77,
        block_root_type="state_root",
    )
    header = SimpleHeader(
        chain_id="chain-x",
        height=77,
        timestamp=0,
        state_root=b"\x00" * 32,  # другой корень
        tx_merkle_root=None,
    )
    v = ProofVerifier()
    with pytest.raises(VerificationFailed):
        v.verify_anchor_against_header(receipt, header, require_root_match=True)


# ----------------------------- Audit digest -----------------------------------

def test_audit_trail_digest_is_deterministic_and_changes_with_root():
    leaves = [b"foo", b"bar", b"baz", b"qux"]
    proof, root = _merkle_proof_for_index(leaves, idx=2, alg=HashAlg.SHA256)
    v = ProofVerifier()
    d1 = v.audit_trail_digest(proof, include_root=root)
    d2 = v.audit_trail_digest(proof, include_root=root)
    assert d1 == d2
    # Смена include_root меняет дайджест
    d3 = v.audit_trail_digest(proof, include_root=b"\x01" * 32)
    assert d3 != d1


# ----------------------------- Hash algorithm guard ---------------------------

def test_hash_algorithm_guard_unsupported_name():
    with pytest.raises(HashAlgorithmError):
        ProofVerifier(hash_alg="unknown-hash")  # type: ignore


# ----------------------------- CLI интеграция ---------------------------------

def _write_json(tmp_path: Path, name: str, obj: dict) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(obj, ensure_ascii=False), encoding="utf-8")
    return p

def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def _hex(b: bytes) -> str:
    return "0x" + b.hex()

def test_cli_single_success(tmp_path: Path, capsys):
    # Подготовка корректного single proof
    leaves = [b"a", b"b", b"c", b"d"]
    proof, root = _merkle_proof_for_index(leaves, idx=1, alg=HashAlg.SHA256)
    proof_json = {
        "leaf": _hex(proof.leaf),
        "already_hashed": False,
        "siblings": [{"hash": _hex(s.hash), "pos": s.pos} for s in proof.siblings],
    }
    proof_file = _write_json(tmp_path, "proof.json", proof_json)

    # Вызов main([...]) напрямую
    rc = cli_mod.main([
        "--mode", "single",
        "--input", str(proof_file),
        "--expected-root", _hex(root),
        "--hash", "sha256",
        "--audit-digest",
        "-v",
    ])
    out = capsys.readouterr().out.strip()
    assert rc == 0
    resp = json.loads(out)
    assert resp["ok"] is True
    assert resp["mode"] == "single"
    assert resp["computed_root"] == _hex(root)

def test_cli_single_fail_wrong_root(tmp_path: Path, capsys):
    leaves = [b"a", b"b"]
    proof, root = _merkle_proof_for_index(leaves, idx=0)
    wrong = b"\xff" * len(root)
    proof_file = _write_json(tmp_path, "proof.json", {
        "leaf": _hex(proof.leaf),
        "already_hashed": False,
        "siblings": [{"hash": _hex(s.hash), "pos": s.pos} for s in proof.siblings],
    })
    rc = cli_mod.main([
        "--mode", "single",
        "--input", str(proof_file),
        "--expected-root", _hex(wrong),
        "--hash", "sha256",
    ])
    out = capsys.readouterr().out.strip()
    assert rc == 2
    resp = json.loads(out)
    assert resp["ok"] is False
    assert resp["error"] in ("verification_failed", "invalid_input")

def test_cli_batch_success(tmp_path: Path, capsys):
    leaves = [b"aa", b"bb", b"cc", b"dd"]
    p0, r = _merkle_proof_for_index(leaves, 0, HashAlg.BLAKE2B_256)
    p1, _ = _merkle_proof_for_index(leaves, 3, HashAlg.BLAKE2B_256)
    batch = {
        "expected_root": _hex(r),
        "proofs": [
            {"leaf": _hex(p0.leaf), "already_hashed": False,
             "siblings": [{"hash": _hex(s.hash), "pos": s.pos} for s in p0.siblings]},
            {"leaf": _hex(p1.leaf), "already_hashed": False,
             "siblings": [{"hash": _hex(s.hash), "pos": s.pos} for s in p1.siblings]},
        ],
    }
    batch_file = _write_json(tmp_path, "batch.json", batch)
    rc = cli_mod.main([
        "--mode", "batch",
        "--input", str(batch_file),
        "--hash", "blake2b_256",
        "--audit-digest",
    ])
    out = capsys.readouterr().out.strip()
    assert rc == 0
    resp = json.loads(out)
    assert resp["ok"] is True
    assert resp["proofs"] == 2
    assert resp["expected_root"] == _hex(r)

def test_cli_anchor_success(tmp_path: Path, capsys):
    anchor_root = b"\x44" * 32
    receipt = {
        "chain_id": "chain-z",
        "anchor_root": _hex(anchor_root),
        "anchor_location": "stateRoot",
        "block_height": 101,
        "block_root_type": "state_root",
        "tx_hash": None,
        "signature": None,
        "signer_id": None,
    }
    header = {
        "chain_id": "chain-z",
        "height": 101,
        "timestamp": 1721029384,
        "tx_merkle_root": None,
        "state_root": _hex(anchor_root),
    }
    rfile = _write_json(tmp_path, "receipt.json", receipt)
    hfile = _write_json(tmp_path, "header.json", header)
    rc = cli_mod.main([
        "--mode", "anchor",
        "--input", str(rfile),
        "--header", str(hfile),
        "--require-root-match",
    ])
    out = capsys.readouterr().out.strip()
    assert rc == 0
    resp = json.loads(out)
    assert resp["ok"] is True
    assert resp["chain_id"] == "chain-z"
    assert resp["block_height"] == 101

def test_cli_anchor_fail_mismatch_root(tmp_path: Path, capsys):
    receipt = {
        "chain_id": "c",
        "anchor_root": _hex(b"\x55" * 32),
        "anchor_location": "stateRoot",
        "block_height": 9,
        "block_root_type": "state_root",
        "tx_hash": None,
        "signature": None,
        "signer_id": None,
    }
    header = {
        "chain_id": "c",
        "height": 9,
        "timestamp": 0,
        "tx_merkle_root": None,
        "state_root": _hex(b"\x00" * 32),
    }
    rfile = _write_json(tmp_path, "r.json", receipt)
    hfile = _write_json(tmp_path, "h.json", header)
    rc = cli_mod.main([
        "--mode", "anchor",
        "--input", str(rfile),
        "--header", str(hfile),
        "--require-root-match",
    ])
    out = capsys.readouterr().out.strip()
    assert rc == 2
    resp = json.loads(out)
    assert resp["ok"] is False
    assert resp["error"] == "verification_failed"


# ----------------------------- Негативные сценарии ввода ---------------------

def test_invalid_batch_structure_raises():
    with pytest.raises(ValueError):
        # expected_root отсутствует
        from ledger.cli.tools.verify_proof import _parse_batch  # type: ignore
        _parse_batch({"proofs": []})  # noqa

def test_invalid_single_structure_raises():
    with pytest.raises(ValueError):
        from ledger.cli.tools.verify_proof import _parse_single  # type: ignore
        _parse_single({"leaf": None, "siblings": []})  # noqa


# ----------------------------- Регресс: already_hashed ------------------------

def test_already_hashed_leaf_path():
    # Эмулируем сценарий, когда leaf уже захеширован вызывающей стороной
    leaves = [b"alpha", b"beta", b"gamma", b"delta"]
    # Построим дерево вручную, и возьмем именно leaf=hash(leaf_prefix+raw)
    root, levels = _build_merkle_tree(leaves, HashAlg.SHA256)
    hashed_leaf = levels[0][2]  # для idx=2
    # Собираем siblings так же, как _merkle_proof_for_index, но передаем already_hashed=True
    proof_raw, _ = _merkle_proof_for_index(leaves, 2, HashAlg.SHA256)
    proof = MerkleProof(leaf=hashed_leaf, siblings=proof_raw.siblings, already_hashed=True)
    v = ProofVerifier(hash_alg=HashAlg.SHA256)
    assert v.verify_merkle_inclusion(proof, root) is True
