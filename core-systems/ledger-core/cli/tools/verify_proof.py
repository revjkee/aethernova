# ledger/cli/tools/verify_proof.py
# -*- coding: utf-8 -*-
"""
CLI tool: verify Merkle proofs and anchor receipts for ledger-core.

Usage (examples):
  # Single proof
  python -m ledger.cli.tools.verify_proof --mode single --input proof.json --expected-root 0x... --hash sha256

  # Batch proofs (all converge to same root)
  python -m ledger.cli.tools.verify_proof --mode batch --input batch.json --hash blake2b_256

  # Anchor receipt vs block header
  python -m ledger.cli.tools.verify_proof --mode anchor --input anchor.json --header header.json \
      --require-root-match --sig-plugin mypkg.sigverifiers:Ed25519Verifier

Input JSON schemas (concise):
  SINGLE:
    {
      "leaf": "<hex|base64>",              # raw leaf, unless already_hashed=true
      "already_hashed": false,
      "siblings": [ { "hash": "<hex|base64>", "pos": "L"|"R" }, ... ]
    }

  BATCH:
    {
      "expected_root": "<hex|base64>",
      "proofs": [ <SINGLE>, <SINGLE>, ... ]
    }

  ANCHOR (receipt):
    {
      "chain_id": "ethereum-mainnet",
      "anchor_root": "<hex|base64>",
      "anchor_location": "stateRoot",
      "block_height": 123,
      "block_root_type": "tx_merkle_root" | "state_root" | null,
      "tx_hash": "<hex|base64>|null",
      "signature": "<hex|base64>|null",
      "signer_id": "anchor-service-1"
    }

  HEADER:
    {
      "chain_id": "ethereum-mainnet",
      "height": 123,
      "timestamp": 1721029384,
      "tx_merkle_root": "<hex|base64>|null",
      "state_root": "<hex|base64>|null"
    }

Exit codes:
  0 = verified/success
  2 = verification failed (proof mismatch/signature invalid/etc)
  1 = usage/parse/other error

No external dependencies. Integrates with:
  ledger/anchoring/proof_verifier.py
"""

from __future__ import annotations

import argparse
import base64
import importlib
import json
import logging
import os
import sys
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

# Import verifier primitives from ledger-core
try:
    from ledger.anchoring.proof_verifier import (
        ProofVerifier,
        MerkleProof,
        BatchMerkleProof,
        Sibling,
        AnchorReceipt,
        SimpleHeader,
        HashAlg,
        SignatureVerifier,
        VerificationFailed,
        InvalidProofFormat,
        HashAlgorithmError,
    )
except Exception as _imp_exc:
    print(json.dumps({
        "ok": False,
        "error": "import_error",
        "detail": f"Failed to import ledger.anchoring.proof_verifier: {_imp_exc!s}"
    }, ensure_ascii=False), file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG = logging.getLogger("ledger.cli.verify_proof")
if not LOG.handlers:
    _h = logging.StreamHandler(sys.stderr)
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))
    LOG.addHandler(_h)
LOG.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Helpers: bytes parsing/formatting
# ---------------------------------------------------------------------------

def _b(s: Optional[str]) -> Optional[bytes]:
    if s is None:
        return None
    if not isinstance(s, str):
        raise ValueError("Expected string for bytes field")
    val = s.strip()
    if val.startswith("0x") or val.startswith("0X"):
        val = val[2:]
        if len(val) % 2 == 1:
            val = "0" + val
        return bytes.fromhex(val)
    # try base64
    try:
        return base64.b64decode(val, validate=True)
    except Exception:
        # try raw hex without 0x
        try:
            if len(val) % 2 == 1:
                val = "0" + val
            return bytes.fromhex(val)
        except Exception as exc:
            raise ValueError("Invalid bytes encoding; expected hex or base64") from exc

def _bx(b: Optional[bytes]) -> Optional[str]:
    return None if b is None else "0x" + b.hex()

def _load_json(path: Optional[str]) -> Any:
    if path and path != "-":
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    # stdin
    data = sys.stdin.read()
    return json.loads(data)

def _safe_bool(v: Any, field: str) -> bool:
    if isinstance(v, bool):
        return v
    raise ValueError(f"{field} must be boolean")

# ---------------------------------------------------------------------------
# Signature verifier plug-in loader (optional)
# ---------------------------------------------------------------------------

def _load_sig_plugin(spec: Optional[str]) -> Optional[SignatureVerifier]:
    """
    spec format: 'package.module:ClassName'
    Class must implement SignatureVerifier Protocol.
    """
    if not spec:
        return None
    if ":" not in spec:
        raise ValueError("sig-plugin must be in format 'module.path:ClassName'")
    mod_name, cls_name = spec.split(":", 1)
    mod = importlib.import_module(mod_name)
    cls = getattr(mod, cls_name, None)
    if cls is None:
        raise ValueError(f"Class {cls_name} not found in module {mod_name}")
    inst = cls()  # must be callable without args
    # Protocol check (duck typing)
    if not hasattr(inst, "verify") or not callable(getattr(inst, "verify")):
        raise ValueError("sig-plugin does not implement SignatureVerifier.verify")
    return inst  # type: ignore

# ---------------------------------------------------------------------------
# Parsers for each mode
# ---------------------------------------------------------------------------

def _parse_single(data: Dict[str, Any]) -> MerkleProof:
    leaf = _b(data.get("leaf"))
    if leaf is None:
        raise ValueError("leaf is required")
    siblings_json = data.get("siblings")
    if not isinstance(siblings_json, list) or not siblings_json:
        raise ValueError("siblings must be a non-empty list")
    sibs = []
    for i, s in enumerate(siblings_json):
        if not isinstance(s, dict):
            raise ValueError("each sibling must be an object")
        h = _b(s.get("hash"))
        pos = s.get("pos")
        if h is None or pos not in ("L", "R"):
            raise ValueError("sibling requires 'hash' and 'pos' in {'L','R'}")
        sibs.append(Sibling(hash=h, pos=pos))
    already_hashed = _safe_bool(data.get("already_hashed", False), "already_hashed")
    return MerkleProof(leaf=leaf, siblings=tuple(sibs), already_hashed=already_hashed)

def _parse_batch(data: Dict[str, Any]) -> BatchMerkleProof:
    exp_root = _b(data.get("expected_root"))
    if exp_root is None:
        raise ValueError("expected_root is required for batch")
    proofs_json = data.get("proofs")
    if not isinstance(proofs_json, list) or not proofs_json:
        raise ValueError("proofs must be a non-empty list")
    proofs = tuple(_parse_single(p) for p in proofs_json)
    return BatchMerkleProof(proofs=proofs, expected_root=exp_root)

def _parse_anchor_receipt(data: Dict[str, Any]) -> AnchorReceipt:
    chain_id = data.get("chain_id")
    anchor_root = _b(data.get("anchor_root"))
    anchor_location = data.get("anchor_location")
    block_height = data.get("block_height")
    block_root_type = data.get("block_root_type")
    tx_hash = _b(data.get("tx_hash")) if data.get("tx_hash") is not None else None
    signature = _b(data.get("signature")) if data.get("signature") is not None else None
    signer_id = data.get("signer_id")
    return AnchorReceipt(
        chain_id=chain_id,
        anchor_root=anchor_root,
        anchor_location=anchor_location,
        block_height=int(block_height),
        block_root_type=block_root_type,
        tx_hash=tx_hash,
        signature=signature,
        signer_id=signer_id,
    )

def _parse_header(data: Dict[str, Any]) -> SimpleHeader:
    chain_id = data.get("chain_id")
    height = int(data.get("height"))
    timestamp = int(data.get("timestamp"))
    tx_merkle_root = _b(data.get("tx_merkle_root")) if data.get("tx_merkle_root") is not None else None
    state_root = _b(data.get("state_root")) if data.get("state_root") is not None else None
    return SimpleHeader(
        chain_id=chain_id,
        height=height,
        timestamp=timestamp,
        tx_merkle_root=tx_merkle_root,
        state_root=state_root,
    )

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="verify_proof",
        description="Verify Merkle inclusion proofs and anchor receipts.",
    )
    p.add_argument("--mode", required=True, choices=["single", "batch", "anchor"], help="Verification mode")
    p.add_argument("--input", "-i", required=True, help="Path to input JSON file or '-' for stdin")
    p.add_argument("--expected-root", help="Expected Merkle root (hex/base64) for single mode")
    p.add_argument("--header", help="Path to block header JSON (for anchor mode)")
    p.add_argument("--hash", default="sha256", choices=[h.value for h in HashAlg], help="Hash algorithm for Merkle")
    p.add_argument("--audit-digest", action="store_true", help="Emit audit trail digest")
    p.add_argument("--require-root-match", action="store_true", help="In anchor mode, require header root equals anchor_root when block_root_type set")
    p.add_argument("--sig-plugin", help="Signature verifier plugin 'module.path:ClassName' (anchor mode)")
    p.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (errors only)")
    p.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity")
    args = p.parse_args(argv)

    # Logging level
    if args.quiet:
        LOG.setLevel(logging.ERROR)
    elif args.verbose >= 2:
        LOG.setLevel(logging.DEBUG)
    elif args.verbose == 1:
        LOG.setLevel(logging.INFO)
    else:
        LOG.setLevel(logging.WARNING)

    # Build verifier
    try:
        verifier = ProofVerifier(hash_alg=args.hash)
    except HashAlgorithmError as e:
        _emit({"ok": False, "mode": args.mode, "error": "hash_algorithm_error", "detail": str(e)})
        return 1

    try:
        if args.mode == "single":
            data = _load_json(args.input)
            proof = _parse_single(data)
            expected_root = _b(args.expected_root) if args.expected_root else None
            if expected_root is None:
                raise ValueError("--expected-root is required for --mode single")
            computed_root = verifier.compute_root_from_proof(proof)
            ok = verifier.verify_merkle_inclusion(proof, expected_root)
            out = {
                "ok": bool(ok),
                "mode": "single",
                "hash": args.hash,
                "expected_root": _bx(expected_root),
                "computed_root": _bx(computed_root),
            }
            if args.audit_digest:
                out["audit_digest"] = _bx(verifier.audit_trail_digest(proof, include_root=expected_root))
            _emit(out)
            return 0 if ok else 2

        elif args.mode == "batch":
            data = _load_json(args.input)
            batch = _parse_batch(data)
            ok = verifier.verify_batch(batch)
            out = {
                "ok": bool(ok),
                "mode": "batch",
                "hash": args.hash,
                "expected_root": _bx(batch.expected_root),
                "proofs": len(batch.proofs),
            }
            if args.audit_digest:
                # Emit digests for first N to avoid huge output
                digests = []
                for i, pz in enumerate(batch.proofs[:10]):
                    digests.append(_bx(verifier.audit_trail_digest(pz, include_root=batch.expected_root)))
                out["audit_digest_samples"] = digests
            _emit(out)
            return 0 if ok else 2

        elif args.mode == "anchor":
            data = _load_json(args.input)
            receipt = _parse_anchor_receipt(data)
            if not args.header:
                raise ValueError("--header is required for --mode anchor")
            header = _parse_header(_load_json(args.header))
            sigv = _load_sig_plugin(args.sig_plugin) if args.sig_plugin else None
            ok = verifier.verify_anchor_against_header(
                receipt,
                header,
                require_root_match=bool(args.require_root_match),
                signature_verifier=sigv,
            )
            out = {
                "ok": bool(ok),
                "mode": "anchor",
                "chain_id": receipt.chain_id,
                "block_height": receipt.block_height,
                "block_root_type": receipt.block_root_type,
                "anchor_root": _bx(receipt.anchor_root),
                "header_root_tx": _bx(header.tx_merkle_root),
                "header_root_state": _bx(header.state_root),
                "require_root_match": bool(args.require_root_match),
                "sig_checked": bool(receipt.signature is not None and sigv is not None),
            }
            _emit(out)
            return 0 if ok else 2

        else:
            _emit({"ok": False, "error": "invalid_mode"})
            return 1

    except (VerificationFailed,) as e:
        _emit({"ok": False, "mode": args.mode, "error": "verification_failed", "detail": str(e)})
        return 2
    except (InvalidProofFormat, ValueError) as e:
        _emit({"ok": False, "mode": args.mode, "error": "invalid_input", "detail": str(e)})
        return 1
    except Exception as e:
        _emit({"ok": False, "mode": args.mode, "error": "unexpected_error", "detail": str(e)})
        return 1

def _emit(obj: Dict[str, Any]) -> None:
    """
    Print a single JSON object to stdout, deterministic separators.
    """
    print(json.dumps(obj, ensure_ascii=False, separators=(",", ":")))

if __name__ == "__main__":
    sys.exit(main())
