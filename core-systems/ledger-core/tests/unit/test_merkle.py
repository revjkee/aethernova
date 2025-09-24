# -*- coding: utf-8 -*-
import os
import random
import binascii

import pytest

from ledger.crypto.hashing import (
    HashAlg,
    merkle_root,
    merkle_proof,
    verify_merkle_proof,
    MerkleHashOrder,
    HashingError,
    is_keccak_available,
    is_blake3_available,
)

# ==========================
# Вспомогательные фикстуры
# ==========================

@pytest.fixture(autouse=True)
def _fix_seed():
    random.seed(1337)


def _hex(b: bytes) -> str:
    return b.hex()


# ==========================
# Точные векторы для SHA-256
# Порядок: lexicographic (с сортировкой пары)
# Источники значений вычислены строго по реализации:
# - пустое дерево: sha256(b"")
# - при нечётном числе листьев последний дублируется
# ==========================

VECTORS_LEX = [
    # (leaves, expected_root_hex)
    ([], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ([b"a"], "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"),
    ([b"a", b"b"], "18d79cb747ea174c59f3a3b41768672526d56fecc58360a99d283d0f9b0a3cc0"),
    ([b"a", b"b", b"c"], "b1da020d217b348265d6578cdfe4cc717bb79b5deaffce7fc167180e9e1ec8c6"),
    ([b"a", b"b", b"c", b"d"], "4c6aae040ffada3d02598207b8485fcbe161c03f4cb3f660e4d341e7496ff3b2"),
    ([b"a", b"b", b"c", b"d", b"e"], "df947ef1b6dda4cb4ef081afd68f255104ccaab2661f2047d2f1a05c5440076f"),
]

# Векторы для left_right порядка (без сортировки пары)
VECTORS_LR = [
    ([b"a", b"b", b"c"], "d31a37ef6ac14a2db1470c4316beb5592e6afd4465022339adafda76a18ffabe"),
    ([b"a", b"b", b"c", b"d"], "14ede5e8e97ad9372327728f5099b95604a39593cac3bd38a343ad76205213e7"),
]


# ==========================
# Тесты корня дерева (known values)
# ==========================

@pytest.mark.parametrize("leaves,expected_hex", VECTORS_LEX)
def test_merkle_root_known_sha256_lex(leaves, expected_hex):
    root = merkle_root(leaves, alg=HashAlg.sha256, order=MerkleHashOrder.lexicographic)
    assert _hex(root) == expected_hex


@pytest.mark.parametrize("leaves,expected_hex", VECTORS_LR)
def test_merkle_root_known_sha256_left_right(leaves, expected_hex):
    root = merkle_root(leaves, alg=HashAlg.sha256, order=MerkleHashOrder.left_right)
    assert _hex(root) == expected_hex


# ==========================
# Пустое дерево
# ==========================

def test_empty_tree_root_is_sha256_empty():
    root = merkle_root([], alg=HashAlg.sha256, order=MerkleHashOrder.lexicographic)
    assert _hex(root) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


# ==========================
# Идемпотентность и детерминизм
# ==========================

def test_merkle_root_deterministic():
    leaves = [os.urandom(16) for _ in range(25)]
    r1 = merkle_root(leaves, HashAlg.sha256, MerkleHashOrder.lexicographic)
    r2 = merkle_root(leaves, HashAlg.sha256, MerkleHashOrder.lexicographic)
    assert r1 == r2


# ==========================
# Доказательства (proofs)
# ==========================

@pytest.mark.parametrize("order", [MerkleHashOrder.lexicographic, MerkleHashOrder.left_right])
def test_merkle_proof_roundtrip(order):
    # Набор из 17 листьев (не степень двойки — проверим дублирование последнего)
    leaves = [f"leaf-{i}".encode() for i in range(17)]
    root = merkle_root(leaves, HashAlg.sha256, order=order)

    # Проверим доказательство для нескольких индексов
    for idx in [0, 1, 2, 8, 16]:
        proof = merkle_proof(leaves, idx, HashAlg.sha256, order=order)
        ok = verify_merkle_proof(leaves[idx], proof, root, HashAlg.sha256)
        assert ok, f"proof should verify for idx={idx}"

        # Подмена листа должна ломать доказательство
        tampered_leaf = b"X" + leaves[idx]
        assert not verify_merkle_proof(tampered_leaf, proof, root, HashAlg.sha256)

        # Подмена пути (если он не пустой) должна ломать доказательство
        if proof.path:
            bad_path = proof.path.copy()
            bad_path[0] = b"\x00" * len(bad_path[0])
            proof_bad = type(proof)(leaves_count=proof.leaves_count, index=proof.index, path=bad_path, order=proof.order)
            assert not verify_merkle_proof(leaves[idx], proof_bad, root, HashAlg.sha256)


def test_merkle_proof_invalid_index_raises():
    leaves = [b"a", b"b"]
    with pytest.raises(HashingError):
        merkle_proof(leaves, 2, HashAlg.sha256, MerkleHashOrder.lexicographic)
    with pytest.raises(HashingError):
        merkle_proof(leaves, -1, HashAlg.sha256, MerkleHashOrder.lexicographic)


# ==========================
# Рандомизированная проверка нескольких наборов
# ==========================

@pytest.mark.parametrize("order", [MerkleHashOrder.lexicographic, MerkleHashOrder.left_right])
def test_randomized_sets(order):
    for n in [1, 2, 3, 4, 7, 8, 15, 16, 31]:
        leaves = [os.urandom(random.randint(1, 64)) for _ in range(n)]
        root = merkle_root(leaves, HashAlg.sha256, order=order)
        # Проверим для 3 случайных индексов (или всех, если мало листьев)
        indices = list(range(n)) if n <= 3 else random.sample(range(n), 3)
        for idx in indices:
            proof = merkle_proof(leaves, idx, HashAlg.sha256, order=order)
            assert verify_merkle_proof(leaves[idx], proof, root, HashAlg.sha256)


# ==========================
# Регресс против "сломанных" реализаций:
# - сортировка пар обязательна для lexicographic, запрещена для left_right
# ==========================

def test_order_semantics_differs():
    leaves = [b"a", b"b", b"c", b"d"]
    r_lex = merkle_root(leaves, HashAlg.sha256, MerkleHashOrder.lexicographic)
    r_lr = merkle_root(leaves, HashAlg.sha256, MerkleHashOrder.left_right)
    assert r_lex != r_lr, "roots must differ between lexicographic and left_right orders"


# ==========================
# (Опционально) Проверить, что другие алгоритмы могут быть недоступны
# Тест лишь документирует ожидание: отсутствие зависимости — не падение, а пропуск
# ==========================

@pytest.mark.skipif(not is_keccak_available(), reason="keccak256 dependency not installed")
def test_keccak_optional_presence():
    leaves = [b"a", b"b", b"c"]
    root = merkle_root(leaves, HashAlg.keccak256, MerkleHashOrder.lexicographic)
    assert isinstance(root, bytes) and len(root) == 32

@pytest.mark.skipif(not is_blake3_available(), reason="blake3 dependency not installed")
def test_blake3_optional_presence():
    leaves = [b"a", b"b", b"c"]
    root = merkle_root(leaves, HashAlg.blake3, MerkleHashOrder.lexicographic)
    assert isinstance(root, bytes) and len(root) == 32
