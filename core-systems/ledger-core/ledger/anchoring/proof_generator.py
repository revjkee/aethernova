# ledger-core/ledger/anchoring/proof_generator.py
from __future__ import annotations

import binascii
import dataclasses as dc
import hashlib
import json
import math
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union

# ---------------------------------------------------------
# Конфигурация/типы
# ---------------------------------------------------------

HashFn = Callable[[bytes], bytes]

def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

@dc.dataclass(frozen=True)
class ProofConfig:
    """
    Конфигурация генератора доказательств.
    """
    algorithm: str = "SHA-256"      # имя алгоритма
    hash_fn: HashFn = _sha256       # функция хеширования
    rfc6962_prefix_leaf: bytes = b"\x00"
    rfc6962_prefix_node: bytes = b"\x01"

    def leaf_hash(self, data: bytes) -> bytes:
        return self.hash_fn(self.rfc6962_prefix_leaf + data)

    def node_hash(self, left: bytes, right: bytes) -> bytes:
        return self.hash_fn(self.rfc6962_prefix_node + left + right)


@dc.dataclass(frozen=True)
class Proof:
    """
    Доказательство включения одного листа.
    """
    algorithm: str
    tree_size: int
    leaf_index: int
    leaf_hash: bytes
    root: bytes
    path: Tuple[bytes, ...]           # снизу вверх: соседи по пути
    ts_ms: int

    # -------- сериализация --------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "tree_size": self.tree_size,
            "leaf_index": self.leaf_index,
            "leaf_hash": self.leaf_hash,
            "root": self.root,
            "path": list(self.path),
            "ts_ms": self.ts_ms,
        }

    def to_json(self) -> str:
        def enc(x: Any) -> Any:
            if isinstance(x, (bytes, bytearray)):
                return "0x" + bytes(x).hex()
            if isinstance(x, dict):
                return {k: enc(v) for k, v in x.items()}
            if isinstance(x, list):
                return [enc(v) for v in x]
            return x
        return json.dumps(enc(self.to_dict()), ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Proof":
        def as_bytes(v: Any) -> bytes:
            if isinstance(v, (bytes, bytearray)):
                return bytes(v)
            if isinstance(v, str) and v.startswith("0x"):
                return bytes.fromhex(v[2:])
            raise TypeError("bytes field must be bytes or 0x-hex string")
        return Proof(
            algorithm=str(d["algorithm"]),
            tree_size=int(d["tree_size"]),
            leaf_index=int(d["leaf_index"]),
            leaf_hash=as_bytes(d["leaf_hash"]),
            root=as_bytes(d["root"]),
            path=tuple(as_bytes(x) for x in d["path"]),
            ts_ms=int(d["ts_ms"]),
        )


class ProofError(Exception):
    pass


# ---------------------------------------------------------
# Построение дерева и доказательств
# ---------------------------------------------------------

class MerkleTree:
    """
    RFC 6962‑совместимое дерево.
    Построение за O(n), доказательства за O(log n).
    """
    __slots__ = ("cfg", "_leaves", "_levels")

    def __init__(self, cfg: Optional[ProofConfig] = None) -> None:
        self.cfg = cfg or ProofConfig()
        self._leaves: List[bytes] = []
        self._levels: List[List[bytes]] = []  # уровень 0: листья (leaf_hash), 1..: узлы

    @staticmethod
    def _is_power_of_two(n: int) -> bool:
        return n > 0 and (n & (n - 1) == 0)

    def add_leaf(self, data: bytes, *, prehashed: bool = False) -> int:
        """
        Добавляет лист. Если prehashed=True, то `data` уже leaf_hash (RFC 6962).
        Возвращает индекс листа.
        """
        if prehashed:
            leaf = data
        else:
            leaf = self.cfg.leaf_hash(data)
        self._leaves.append(leaf)
        return len(self._leaves) - 1

    def add_leaves(self, items: Iterable[bytes], *, prehashed: bool = False) -> Tuple[int, int]:
        """
        Добавляет множество листьев. Возвращает (start_index, count).
        """
        start = len(self._leaves)
        for it in items:
            self.add_leaf(it, prehashed=prehashed)
        return start, len(self._leaves) - start

    def build(self) -> None:
        """
        Строит уровни узлов. Должно вызываться после добавления всех листьев.
        Идемпотентно: переиспользует кэш уровней при неизменных листьях.
        """
        n = len(self._leaves)
        if n == 0:
            self._levels = []
            return
        levels: List[List[bytes]] = [list(self._leaves)]
        while len(levels[-1]) > 1:
            prev = levels[-1]
            cur: List[bytes] = []
            for i in range(0, len(prev), 2):
                if i + 1 < len(prev):
                    cur.append(self.cfg.node_hash(prev[i], prev[i + 1]))
                else:
                    # Нечётный хвост: поднимаем как есть (правило RFC 6962)
                    cur.append(prev[i])
            levels.append(cur)
        self._levels = levels

    @property
    def size(self) -> int:
        return len(self._leaves)

    @property
    def root(self) -> bytes:
        if self.size == 0:
            # Пустое дерево — хеш пустого списка по RFC 6962: hash(leaf_prefix + b"")
            return self.cfg.leaf_hash(b"")
        if not self._levels:
            self.build()
        return self._levels[-1][0]

    def _assert_ready(self) -> None:
        if self.size == 0:
            raise ProofError("tree is empty")
        if not self._levels:
            self.build()

    def prove(self, leaf_index: int) -> Proof:
        """
        Генерирует proof включения для листа с индексом leaf_index.
        """
        self._assert_ready()
        if not (0 <= leaf_index < self.size):
            raise ProofError("leaf_index out of range")
        path: List[bytes] = []
        idx = leaf_index
        for level in range(0, len(self._levels) - 1):
            nodes = self._levels[level]
            is_right = (idx ^ 1)
            if is_right < len(nodes):
                path.append(nodes[is_right])
            else:
                # если соседа нет (нечётный хвост), уровень просто поднимается — без элемента в path
                pass
            idx //= 2
        return Proof(
            algorithm=self.cfg.algorithm,
            tree_size=self.size,
            leaf_index=leaf_index,
            leaf_hash=self._leaves[leaf_index],
            root=self.root,
            path=tuple(path),
            ts_ms=int(time.time() * 1000),
        )

    def prove_many(self, indices: Sequence[int]) -> List[Proof]:
        """
        Пакетная генерация доказательств. Эффективно использует кэш уровней.
        """
        self._assert_ready()
        out: List[Proof] = []
        for i in indices:
            out.append(self.prove(int(i)))
        return out

    # -------- верификация --------

    def verify(self, proof: Proof) -> bool:
        """
        Проверка proof для текущего дерева (сравнивает корни/размер).
        """
        if proof.tree_size != self.size:
            return False
        if proof.algorithm != self.cfg.algorithm:
            return False
        return verify_inclusion(
            leaf_index=proof.leaf_index,
            leaf_hash=proof.leaf_hash,
            root=proof.root,
            path=proof.path,
            cfg=self.cfg,
        )


def verify_inclusion(
    *,
    leaf_index: int,
    leaf_hash: bytes,
    root: bytes,
    path: Sequence[bytes],
    cfg: Optional[ProofConfig] = None,
) -> bool:
    """
    Верификация доказательства включения без знания всего дерева.
    """
    cfg = cfg or ProofConfig()
    idx = leaf_index
    acc = leaf_hash
    level = 0
    for sib in path:
        if idx % 2 == 0:
            # слева — мы; справа — сосед
            acc = cfg.node_hash(acc, sib)
        else:
            # справа — мы; слева — сосед
            acc = cfg.node_hash(sib, acc)
        idx //= 2
        level += 1
    return acc == root


# ---------------------------------------------------------
# Потоковый аккумулятор (append‑only)
# ---------------------------------------------------------

@dc.dataclass
class _Partial:
    height: int   # 2^height листья покрыто
    hash: bytes

class MerkleAccumulator:
    """
    Append‑only аккумулятор (compact ranges) для потоковой обработки.
    Позволяет поддерживать корень без пересчета всего дерева и строить proofs
    по завершении батча (хранит листовые хеши при опции keep_leaves=True).
    """
    def __init__(self, cfg: Optional[ProofConfig] = None, keep_leaves: bool = False) -> None:
        self.cfg = cfg or ProofConfig()
        self._partials: List[_Partial] = []  # стек по высотам
        self._size = 0
        self._leaves: List[bytes] = [] if keep_leaves else None

    @property
    def size(self) -> int:
        return self._size

    def _push_partial(self, h: bytes, height: int) -> None:
        self._partials.append(_Partial(height=height, hash=h))

    def _merge(self) -> None:
        # инвариант: верхние два partial с одинаковой высотой можно объединить
        while len(self._partials) >= 2 and self._partials[-1].height == self._partials[-2].height:
            r = self._partials.pop()
            l = self._partials.pop()
            self._push_partial(self.cfg.node_hash(l.hash, r.hash), l.height + 1)

    def push_leaf(self, data: bytes, *, prehashed: bool = False) -> int:
        leaf = data if prehashed else self.cfg.leaf_hash(data)
        if self._leaves is not None:
            self._leaves.append(leaf)
        self._push_partial(leaf, 0)
        self._size += 1
        self._merge()
        return self._size - 1

    @property
    def root(self) -> bytes:
        if self._size == 0:
            return self.cfg.leaf_hash(b"")
        # сводим все partial снизу вверх (как конкатенацию правых к левым)
        accs = [p.hash for p in self._partials]
        while len(accs) > 1:
            l = accs.pop(0)
            r = accs.pop(0)
            accs.insert(0, self.cfg.node_hash(l, r))
        return accs[0]

    def to_tree(self) -> MerkleTree:
        """
        Материализует полное дерево, если сохранялись листья.
        """
        if self._leaves is None:
            raise ProofError("accumulator constructed without keep_leaves=True")
        t = MerkleTree(self.cfg)
        t.add_leaves(self._leaves, prehashed=True)
        t.build()
        return t


# ---------------------------------------------------------
# Интеграция с доменом Anchor (опционально)
# ---------------------------------------------------------

def leaf_from_anchor_payload_hash(payload_hash_32bytes: bytes, *, cfg: Optional[ProofConfig] = None) -> bytes:
    """
    Получает leaf‑hash из уже посчитанного контент‑хеша (32‑байтный SHA‑256 из AnchorPayload.hash.value).
    """
    cfg = cfg or ProofConfig()
    if not isinstance(payload_hash_32bytes, (bytes, bytearray)) or len(payload_hash_32bytes) != 32:
        raise ProofError("payload hash must be 32 bytes sha256")
    return cfg.leaf_hash(bytes(payload_hash_32bytes))


# ---------------------------------------------------------
# Примеры использования (docstring)
# ---------------------------------------------------------

"""
Пример 1: построение и проверка proof
-------------------------------------
from ledger_core.ledger.anchoring.proof_generator import MerkleTree, ProofConfig, verify_inclusion

cfg = ProofConfig()
tree = MerkleTree(cfg)
tree.add_leaves([b"A", b"B", b"C", b"D"])  # данные будут захешированы как листья RFC 6962
tree.build()

p = tree.prove(2)  # для "C"
assert tree.verify(p)
assert verify_inclusion(leaf_index=p.leaf_index, leaf_hash=p.leaf_hash, root=p.root, path=p.path, cfg=cfg)

Пример 2: пакетные доказательства
---------------------------------
indices = [0, 3]
proofs = tree.prove_many(indices)

Пример 3: потоковое вычисление корня
------------------------------------
acc = MerkleAccumulator(keep_leaves=True)
for chunk in [b"A", b"B", b"C", b"D"]:
    acc.push_leaf(chunk)  # можно prehashed=True, если заранее посчитан leaf_hash
root = acc.root
t = acc.to_tree()
p = t.prove(1)
assert verify_inclusion(leaf_index=p.leaf_index, leaf_hash=p.leaf_hash, root=p.root, path=p.path)

Пример 4: интеграция с AnchorPayload.hash (32‑байт SHA‑256)
-----------------------------------------------------------
from ledger_core.ledger.anchoring.proof_generator import leaf_from_anchor_payload_hash, MerkleTree

# payload_hash.value из AnchorPayload
leaf_h = leaf_from_anchor_payload_hash(payload_hash.value)  # это уже leaf_hash
tree = MerkleTree()
tree.add_leaf(leaf_h, prehashed=True)
tree.build()
"""

# ---------------------------------------------------------
# Небольшие self‑tests при запуске файла напрямую
# ---------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    cfg = ProofConfig()
    t = MerkleTree(cfg)
    t.add_leaves([b"A", b"B", b"C", b"D"])
    t.build()
    p2 = t.prove(2)
    ok = t.verify(p2)
    print("root:", "0x" + t.root.hex())
    print("proof ok:", ok)
    print("proof json:", p2.to_json())
