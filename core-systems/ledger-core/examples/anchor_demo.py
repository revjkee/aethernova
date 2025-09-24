#!/usr/bin/env python3
# ledger-core/examples/anchor_demo.py
"""
Anchor demo: строит Меркле-дерево поверх JSONL событий и формирует "anchor bundle"
с доказательствами включения. Опционально подписывает корень Ed25519 (PEM).
Умеет проверять весь бандл или отдельный proof для leaf.

Примеры:
  # Сборка якоря из файла событий и запись бандла на диск
  python examples/anchor_demo.py build --in events.jsonl --out anchor.json --sign-ed25519 sk.pem

  # Верификация бандла (подпись и все доказательства)
  python examples/anchor_demo.py verify --bundle anchor.json --pub-ed25519 pk.pem

  # Верификация одного доказательства (полезно на стороне потребителя)
  python examples/anchor_demo.py leaf \
      --leaf proof.json \
      --expect-root <hex_root> \
      --payload-file event.json

Формат входных событий: JSONL, каждая строка — объект. Если у объекта есть поле "id",
оно будет использовано как ключ; иначе сгенерируется индекс leaf_N.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    _CRYPTO_OK = True
except Exception:
    _CRYPTO_OK = False


# ==========================
# Утилиты
# ==========================

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")

def b64u_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)

def json_compact(obj: Any) -> bytes:
    """Детерминированная каноникализация JSON: сортировка ключей, компактная запись, UTF‑8."""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def read_jsonl(fp: Iterable[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for i, line in enumerate(fp, 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if not isinstance(obj, dict):
                raise ValueError("line is not a JSON object")
            out.append(obj)
        except Exception as e:
            raise SystemExit(f"Invalid JSON on line {i}: {e}")
    return out


# ==========================
# Merkle
# ==========================

@dataclass(frozen=True)
class Leaf:
    key: str
    payload: Dict[str, Any]
    hash_hex: str  # хэш канонизованного payload: h = sha256(json_compact(payload))

@dataclass(frozen=True)
class Proof:
    """Audit path для одного листа."""
    key: str
    index: int
    leaf_hash: str
    path: List[Tuple[str, str]]  # список (dir, sibling_hash_hex), dir ∈ {"L","R"}

class MerkleTree:
    """
    Полное бинарное дерево. Лист — sha256(payload_canonical).
    При нечётном числе элементов на уровне — дублируем последний (Bitcoin-стиль).
    """
    def __init__(self, leaves_hashes: List[str]) -> None:
        if not leaves_hashes:
            raise ValueError("empty leaves")
        self._leaves = leaves_hashes[:]  # hex
        self._levels: List[List[str]] = []
        self._build()

    def _build(self) -> None:
        cur = self._leaves[:]
        self._levels = [cur]
        while len(cur) > 1:
            nxt: List[str] = []
            it = cur[:]
            if len(it) % 2 == 1:
                it.append(it[-1])
            for i in range(0, len(it), 2):
                a = bytes.fromhex(it[i])
                b = bytes.fromhex(it[i+1])
                nxt.append(hashlib.sha256(a + b).hexdigest())
            cur = nxt
            self._levels.append(cur)

    @property
    def root(self) -> str:
        return self._levels[-1][0]

    @property
    def size(self) -> int:
        return len(self._leaves)

    def proof(self, index: int) -> List[Tuple[str, str]]:
        """Возвращает audit path для листа index: [(dir, sibling_hex), ...]."""
        if index < 0 or index >= len(self._leaves):
            raise IndexError("leaf index out of range")
        path: List[Tuple[str, str]] = []
        pos = index
        for level in self._levels[:-1]:
            # если нечётно, дублируем последний
            effective = level[:] + ([level[-1]] if len(level) % 2 == 1 else [])
            if pos % 2 == 0:
                sibling = effective[pos + 1]
                path.append(("R", sibling))
            else:
                sibling = effective[pos - 1]
                path.append(("L", sibling))
            pos //= 2
        return path

    @staticmethod
    def verify_proof(leaf_hash_hex: str, path: List[Tuple[str, str]], expect_root_hex: str) -> bool:
        cur = bytes.fromhex(leaf_hash_hex)
        for direction, sibling_hex in path:
            sib = bytes.fromhex(sibling_hex)
            if direction == "R":
                cur = hashlib.sha256(cur + sib).digest()
            elif direction == "L":
                cur = hashlib.sha256(sib + cur).digest()
            else:
                raise ValueError("invalid proof direction")
        return cur.hex() == expect_root_hex


# ==========================
# Anchor bundle
# ==========================

@dataclass
class AnchorBundle:
    version: str
    created: str
    hash_alg: str
    canonicalization: str
    tree_size: int
    root: str
    leaves: List[Leaf]
    proofs: List[Proof]
    signature: Optional[Dict[str, str]] = None  # {"alg":"Ed25519","value":b64u(sig)}
    key_info: Optional[Dict[str, str]] = None   # {"kid": "...", "verificationMethod":"..."}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "created": self.created,
            "hash_alg": self.hash_alg,
            "canonicalization": self.canonicalization,
            "tree_size": self.tree_size,
            "root": self.root,
            "leaves": [
                {"key": l.key, "hash": l.hash_hex, "payloadDigest": l.hash_hex}
                for l in self.leaves
            ],
            "proofs": [
                {"key": p.key, "index": p.index, "leaf_hash": p.leaf_hash, "path": p.path}
                for p in self.proofs
            ],
            "signature": self.signature,
            "key_info": self.key_info,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "AnchorBundle":
        leaves = [Leaf(key=i["key"], payload={}, hash_hex=i["hash"]) for i in d.get("leaves", [])]
        proofs = [Proof(key=p["key"], index=int(p["index"]), leaf_hash=p["leaf_hash"], path=[(a, b) for a, b in p["path"]])
                  for p in d.get("proofs", [])]
        return AnchorBundle(
            version=d["version"],
            created=d["created"],
            hash_alg=d["hash_alg"],
            canonicalization=d["canonicalization"],
            tree_size=int(d["tree_size"]),
            root=d["root"],
            leaves=leaves,
            proofs=proofs,
            signature=d.get("signature"),
            key_info=d.get("key_info"),
        )


# ==========================
# Подпись Ed25519
# ==========================

def sign_root_ed25519(root_hex: str, sk_pem_path: Path, kid: Optional[str] = None) -> Tuple[Dict[str, str], Dict[str, str]]:
    if not _CRYPTO_OK:
        raise SystemExit("cryptography not available; install 'cryptography'")
    with open(sk_pem_path, "rb") as f:
        sk = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(sk, ed25519.Ed25519PrivateKey):
        raise SystemExit("private key must be Ed25519")
    msg = json.dumps({"root": root_hex, "alg": "SHA-256", "created": now_iso()}, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = sk.sign(msg)
    signature = {"alg": "Ed25519", "value": b64u(sig), "message": msg.decode("utf-8")}
    key_info = {"kid": kid or "", "verificationMethod": "ed25519-pk-pem"}
    return signature, key_info

def verify_root_ed25519(root_hex: str, signature: Dict[str, str], pk_pem_path: Path) -> bool:
    if not _CRYPTO_OK:
        raise SystemExit("cryptography not available; install 'cryptography'")
    with open(pk_pem_path, "rb") as f:
        pk = serialization.load_pem_public_key(f.read())
    if not isinstance(pk, ed25519.Ed25519PublicKey):
        raise SystemExit("public key must be Ed25519")
    if signature.get("alg") != "Ed25519":
        raise SystemExit("signature.alg != Ed25519")
    msg = signature.get("message", "").encode("utf-8")
    # Проверяем, что в сообщении действительно тот же root
    try:
        payload = json.loads(msg)
    except Exception:
        raise SystemExit("invalid signature.message JSON")
    if payload.get("root") != root_hex or payload.get("alg") != "SHA-256":
        raise SystemExit("signature.message does not match bundle root")
    try:
        pk.verify(b64u_decode(signature["value"]), msg)
        return True
    except InvalidSignature:
        return False


# ==========================
# Команды
# ==========================

def cmd_build(args: argparse.Namespace) -> int:
    # 1) читаем события
    if args.in_file and args.in_file != "-":
        with open(args.in_file, "r", encoding="utf-8") as f:
            events = read_jsonl(f)
    else:
        events = read_jsonl(sys.stdin)

    leaves: List[Leaf] = []
    for idx, ev in enumerate(events):
        key = str(ev.get("id")) if ev.get("id") is not None else f"leaf_{idx}"
        h = sha256_hex(json_compact(ev))
        leaves.append(Leaf(key=key, payload=ev, hash_hex=h))

    # 2) строим Merkle
    tree = MerkleTree([l.hash_hex for l in leaves])

    proofs: List[Proof] = []
    for i, l in enumerate(leaves):
        path = tree.proof(i)
        proofs.append(Proof(key=l.key, index=i, leaf_hash=l.hash_hex, path=path))

    bundle = AnchorBundle(
        version="anchor.v1",
        created=now_iso(),
        hash_alg="SHA-256",
        canonicalization="json-compact",
        tree_size=tree.size,
        root=tree.root,
        leaves=leaves,
        proofs=proofs,
    )

    # 3) подпись корня
    if args.sign_ed25519:
        signature, key_info = sign_root_ed25519(tree.root, Path(args.sign_ed25519), kid=args.kid)
        bundle.signature = signature
        bundle.key_info = key_info

    # 4) запись
    out_str = json.dumps(bundle.to_dict(), ensure_ascii=False, indent=2)
    if args.out and args.out != "-":
        Path(args.out).write_text(out_str, encoding="utf-8")
    else:
        sys.stdout.write(out_str + "\n")

    # 5) опционально выводим краткое резюме
    if args.summary and args.out and args.out != "-":
        sys.stderr.write(f"created: {bundle.created}\nsize: {bundle.tree_size}\nroot: {bundle.root}\n")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    # читаем бандл
    d = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    bundle = AnchorBundle.from_dict(d)

    # 1) проверка структуры
    if bundle.version != "anchor.v1":
        print("Invalid version", file=sys.stderr)
        return 2
    if bundle.hash_alg != "SHA-256" or bundle.canonicalization != "json-compact":
        print("Unsupported hash/c14n", file=sys.stderr)
        return 2
    if bundle.tree_size <= 0 or not bundle.root:
        print("Invalid tree size/root", file=sys.stderr)
        return 2

    # 2) проверка доказательств (по всем или N первым)
    limit = int(args.limit) if args.limit else None
    proofs = bundle.proofs[:limit] if limit else bundle.proofs
    for p in proofs:
        ok = MerkleTree.verify_proof(p.leaf_hash, p.path, bundle.root)
        if not ok:
            print(f"Proof failed for key={p.key}", file=sys.stderr)
            return 3

    # 3) проверка подписи (если задан публичный ключ)
    if args.pub_ed25519:
        if not bundle.signature:
            print("Missing signature in bundle", file=sys.stderr)
            return 4
        ok = verify_root_ed25519(bundle.root, bundle.signature, Path(args.pub_ed25519))
        if not ok:
            print("Root signature invalid", file=sys.stderr)
            return 5

    if args.verbose:
        print(f"ok: root={bundle.root} size={bundle.tree_size} created={bundle.created}")
    return 0


def cmd_leaf(args: argparse.Namespace) -> int:
    # Проверка отдельного доказательства
    proof = json.loads(Path(args.leaf).read_text(encoding="utf-8"))
    # proof формат: {"key": "...", "leaf_hash":"<hex>", "path":[["R","..."],["L","..."],...]}
    leaf_hash = proof["leaf_hash"]
    path = [(a, b) for a, b in proof.get("path", [])]
    expect_root = args.expect_root

    # При желании сверим полезную нагрузку
    if args.payload_file:
        payload = json.loads(Path(args.payload_file).read_text(encoding="utf-8"))
        calc = sha256_hex(json_compact(payload))
        if calc != leaf_hash:
            print("payload digest mismatch", file=sys.stderr)
            return 6

    ok = MerkleTree.verify_proof(leaf_hash, path, expect_root)
    if not ok:
        print("proof invalid", file=sys.stderr)
        return 7
    if args.verbose:
        print("ok")
    return 0


# ==========================
# CLI
# ==========================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="anchor-demo", description="Merkle anchor builder/verifier for JSONL events")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="build anchor bundle from JSONL events")
    b.add_argument("--in", dest="in_file", default="-", help="input JSONL file (default: stdin)")
    b.add_argument("--out", dest="out", default="-", help="output bundle file (default: stdout)")
    b.add_argument("--sign-ed25519", help="sign Merkle root with Ed25519 private key (PEM)")
    b.add_argument("--kid", help="key id for signature", default=None)
    b.add_argument("--summary", action="store_true", help="print summary to stderr")
    b.set_defaults(func=cmd_build)

    v = sub.add_parser("verify", help="verify anchor bundle")
    v.add_argument("--bundle", required=True, help="bundle file (JSON)")
    v.add_argument("--pub-ed25519", help="verify Ed25519 signature with public key (PEM)")
    v.add_argument("--limit", type=int, help="verify only first N proofs")
    v.add_argument("--verbose", action="store_true")
    v.set_defaults(func=cmd_verify)

    l = sub.add_parser("leaf", help="verify single leaf proof")
    l.add_argument("--leaf", required=True, help="proof json file")
    l.add_argument("--expect-root", required=True, help="expected Merkle root (hex)")
    l.add_argument("--payload-file", help="original payload JSON to self-check digest")
    l.add_argument("--verbose", action="store_true")
    l.set_defaults(func=cmd_leaf)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
