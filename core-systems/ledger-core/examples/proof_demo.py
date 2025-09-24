#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import dataclasses
import json
import os
import sys
import time
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# Опциональная интеграция с вашим KeyStore
# Если модуль недоступен, используем локальный Ed25519 (только для примера).
try:
    from ledger.crypto.keystore import from_env as keystore_from_env  # type: ignore
    _HAVE_KEYSTORE = True
except Exception:
    _HAVE_KEYSTORE = False

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    _HAVE_CRYPTO = True
except Exception:
    _HAVE_CRYPTO = False


SCHEMA_VERSION = "1.0.0"
DOMAIN_LEAF = b"ledger-core:merkle:leaf:v1"
DOMAIN_NODE = b"ledger-core:merkle:node:v1"
DOMAIN_ROOT = b"ledger-core:merkle:root:v1"
B64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# ---------------------------
# Каноникализация JSON
# ---------------------------

def canon_json(obj: Any) -> bytes:
    """
    Детерминированная сериализация JSON:
      - сортировка ключей
      - компактные разделители
      - без лишних пробелов
    """
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def h_leaf(payload: Any) -> bytes:
    return sha256(DOMAIN_LEAF + canon_json(payload)).digest()


def h_node(left: bytes, right: bytes) -> bytes:
    return sha256(DOMAIN_NODE + left + right).digest()


def h_root(root: bytes, meta: Dict[str, Any]) -> bytes:
    """Коммитируем метаданные (например, семантику набора/версии)."""
    return sha256(DOMAIN_ROOT + root + canon_json(meta)).digest()


# ---------------------------
# Merkle‑дерево и доказательства
# ---------------------------

@dataclass(frozen=True)
class ProofStep:
    dir: str  # "L" если сосед слева, "R" если справа
    hash_b64: str


@dataclass(frozen=True)
class InclusionProof:
    version: str
    index: int
    total: int
    leaf_hash_b64: str
    root_hash_b64: str
    steps: List[ProofStep]
    # Подписанный корень
    root_signature_b64: Optional[str] = None
    public_key_pem: Optional[str] = None
    signer_key_id: Optional[str] = None
    meta: Dict[str, Any] = dataclasses.field(default_factory=dict)


def build_merkle(leaves_hashes: Sequence[bytes]) -> Tuple[bytes, List[List[bytes]]]:
    """
    Возвращает (root, уровни), где уровни[0] — листья, уровни[-1] — корень.
    При нечётном числе элементов — последний дублируется (ISO/Bitcoin‑style padding).
    """
    if not leaves_hashes:
        raise ValueError("empty leaves")
    levels: List[List[bytes]] = [list(leaves_hashes)]
    cur = levels[0]
    while len(cur) > 1:
        nxt: List[bytes] = []
        it = iter(range(0, len(cur), 2))
        for i in it:
            left = cur[i]
            right = cur[i + 1] if i + 1 < len(cur) else left
            nxt.append(h_node(left, right))
        levels.append(nxt)
        cur = nxt
    return cur[0], levels


def make_proof(levels: List[List[bytes]], index: int) -> List[ProofStep]:
    """
    Генерация маршрута доказательства для листа с индексом index.
    """
    if index < 0 or index >= len(levels[0]):
        raise IndexError("index out of range")
    steps: List[ProofStep] = []
    idx = index
    for lvl in levels[:-1]:
        # Определяем пару
        pair_idx = idx ^ 1  # сосед
        if pair_idx >= len(lvl):
            pair_hash = lvl[idx]  # дублированный
        else:
            pair_hash = lvl[pair_idx]
        # Если сосед слева (pair_idx < idx) — direction = L, иначе R
        direction = "L" if pair_idx < idx else "R"
        steps.append(ProofStep(direction, B64(pair_hash)))
        idx //= 2
    return steps


def verify_proof(leaf_hash: bytes, steps: Sequence[ProofStep]) -> bytes:
    """
    Восстановить корень по листу и шагам.
    """
    cur = leaf_hash
    for s in steps:
        neighbor = base64.urlsafe_b64decode(s.hash_b64 + "==")
        if s.dir == "L":
            cur = h_node(neighbor, cur)
        elif s.dir == "R":
            cur = h_node(cur, neighbor)
        else:
            raise ValueError("invalid step dir")
    return cur


# ---------------------------
# Подпись корня (KeyStore или локально)
# ---------------------------

@dataclass
class SignResult:
    signature_b64: str
    public_key_pem: str
    signer_key_id: str


def sign_root(root_hash: bytes, meta: Dict[str, Any]) -> SignResult:
    """
    Подписывает «связанный» корень h_root(root, meta).
    Если доступен KeyStore — использует его (key_id из ENV LEDGER_SIGN_KEY_ID),
    иначе — локальную пару Ed25519 (для примера).
    """
    commit = h_root(root_hash, meta)

    if _HAVE_KEYSTORE:
        try:
            ks = keystore_from_env()
            key_id = os.getenv("LEDGER_SIGN_KEY_ID", "proof-demo")
            kv, sig = ks.sign(key_id=key_id, data=commit)
            _kv, pem = ks.get_public_key_pem(key_id=key_id, version=kv.version)
            return SignResult(B64(sig), pem, f"{key_id}:{kv.version}")
        except Exception:
            # Падаем на локальную подпись
            pass

    if not _HAVE_CRYPTO:
        raise RuntimeError("cryptography package not available for local signing")

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    sig = priv.sign(commit)
    pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return SignResult(B64(sig), pem, "local-demo:1")


def verify_signature(root_hash: bytes, meta: Dict[str, Any], sig_b64: str, public_key_pem: str) -> bool:
    if not _HAVE_CRYPTO:
        raise RuntimeError("cryptography package not available for verify")
    commit = h_root(root_hash, meta)
    pub = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    assert isinstance(pub, Ed25519PublicKey)
    try:
        pub.verify(base64.urlsafe_b64decode(sig_b64 + "=="), commit)
        return True
    except Exception:
        return False


# ---------------------------
# Высокоуровневые операции
# ---------------------------

def generate_anchor_and_proof(items: Sequence[Any], index: int, *, meta: Optional[Dict[str, Any]] = None) -> InclusionProof:
    """
    items — произвольные JSON‑сериализуемые объекты (записи), index — какая запись доказывается.
    meta — произвольные метаданные набора (например, { "dataset": "anchors", "ts": ... }).
    """
    if not items:
        raise ValueError("items must be non-empty")
    meta = dict(meta or {})
    meta.setdefault("schema_version", SCHEMA_VERSION)
    meta.setdefault("ts", int(time.time()))
    meta.setdefault("domain", "ledger-core/examples/proof_demo")

    leaves = [h_leaf(it) for it in items]
    root, levels = build_merkle(leaves)
    steps = make_proof(levels, index)
    sign_res = sign_root(root, meta)

    return InclusionProof(
        version=SCHEMA_VERSION,
        index=index,
        total=len(items),
        leaf_hash_b64=B64(leaves[index]),
        root_hash_b64=B64(root),
        steps=steps,
        root_signature_b64=sign_res.signature_b64,
        public_key_pem=sign_res.public_key_pem,
        signer_key_id=sign_res.signer_key_id,
        meta=meta,
    )


def verify_inclusion(proof: InclusionProof, payload: Any) -> bool:
    """
    Проверяет, что payload включён в заякоренный набор:
      1) leaf_hash соответствует payload
      2) шаги восстанавливают root_hash
      3) подпись корня корректна
    """
    # 1
    leaf = h_leaf(payload)
    if B64(leaf) != proof.leaf_hash_b64:
        return False

    # 2
    root_calc = verify_proof(leaf, proof.steps)
    if B64(root_calc) != proof.root_hash_b64:
        return False

    # 3 (если подпись присутствует)
    if proof.root_signature_b64 and proof.public_key_pem:
        ok = verify_signature(root_calc, proof.meta or {}, proof.root_signature_b64, proof.public_key_pem)
        if not ok:
            return False

    return True


# ---------------------------
# CLI
# ---------------------------

def _cmd_generate(args: argparse.Namespace) -> int:
    # Вход: либо список JSON‑элементов из файла, либо N фейковых
    if args.input and args.count:
        print("Specify either --input or --count, not both", file=sys.stderr)
        return 2

    if args.input:
        with (open(args.input, "r", encoding="utf-8") if args.input != "-" else sys.stdin) as fh:
            items = json.load(fh)
            if not isinstance(items, list):
                print("Input JSON must be a list", file=sys.stderr)
                return 2
    else:
        n = int(args.count or 4)
        items = [{"id": i, "name": f"item-{i}"} for i in range(n)]

    index = int(args.index or 0)
    proof = generate_anchor_and_proof(items, index, meta=_parse_kv(args.meta))

    out = {
        "proof": dataclasses.asdict(proof),
        "payload": items[index],
    }
    if args.output and args.output != "-":
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(out, fh, ensure_ascii=False, indent=2, sort_keys=True)
    else:
        json.dump(out, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    with (open(args.input, "r", encoding="utf-8") if args.input != "-" else sys.stdin) as fh:
        data = json.load(fh)
    try:
        proof = _proof_from_dict(data["proof"])
        payload = data["payload"]
    except Exception as e:
        print(f"Invalid input: {e}", file=sys.stderr)
        return 2

    ok = verify_inclusion(proof, payload)
    res = {"ok": ok}
    if args.output and args.output != "-":
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(res, fh, ensure_ascii=False, indent=2, sort_keys=True)
    else:
        json.dump(res, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    return 0 if ok else 1


def _parse_kv(items: Optional[List[str]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for it in items or []:
        if "=" not in it:
            continue
        k, v = it.split("=", 1)
        # Попробуем распарсить JSON для значений («умные» метаданные)
        try:
            out[k] = json.loads(v)
        except Exception:
            out[k] = v
    return out


def _proof_from_dict(d: Dict[str, Any]) -> InclusionProof:
    steps = [ProofStep(s["dir"], s["hash_b64"]) for s in d.get("steps", [])]
    return InclusionProof(
        version=d.get("version", SCHEMA_VERSION),
        index=int(d["index"]),
        total=int(d["total"]),
        leaf_hash_b64=d["leaf_hash_b64"],
        root_hash_b64=d["root_hash_b64"],
        steps=steps,
        root_signature_b64=d.get("root_signature_b64"),
        public_key_pem=d.get("public_key_pem"),
        signer_key_id=d.get("signer_key_id"),
        meta=d.get("meta") or {},
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="proof_demo",
        description="Ledger-core Merkle proof demo (anchor, sign, prove, verify).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="Generate anchor+proof JSON")
    g.add_argument("--input", "-i", help="Input JSON list file (or - for stdin)")
    g.add_argument("--count", "-n", help="Generate N synthetic items if no --input", type=int)
    g.add_argument("--index", "-k", help="Index to prove (default 0)", type=int, default=0)
    g.add_argument("--meta", "-m", help="Extra meta as key=value (value may be JSON)", action="append")
    g.add_argument("--output", "-o", help="Output file (or - for stdout)")
    g.set_defaults(func=_cmd_generate)

    v = sub.add_parser("verify", help="Verify proof JSON produced by 'generate'")
    v.add_argument("--input", "-i", help="Input file (or - for stdin)", required=True)
    v.add_argument("--output", "-o", help="Output file (or - for stdout)")
    v.set_defaults(func=_cmd_verify)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
