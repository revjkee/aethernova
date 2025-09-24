# oblivionvault-core/cli/tools/generate_evidence.py
"""
OblivionVault Evidence CLI
Industrial-grade tool to generate and verify immutable evidence bundles.

Features:
- Scan files and compute SHA-256/SHA-512 with parallel hashing and streaming IO
- Deterministic ordering and stable manifest (JSON) with RFC 3339 UTC timestamps
- Merkle tree (SHA-256) root over leaf digests for tamper-evident aggregation
- Rich environment metadata (OS, Python, host, user), optional Git info
- Optional SBOM snapshot of installed Python packages (name, version)
- Optional OpenTelemetry correlation if oblivionvault.observability.tracing is present
- Ed25519 signing (from PEM or raw 32-byte private key), detached signature in manifest
- Bundle packaging to ZIP with optional embedded files
- Offline verification: signature and content integrity, Merkle root recomputation
- Clean exit codes, structured logging, safe defaults

Usage:
  python generate_evidence.py generate PATH [PATH ...] --out evidence.zip
  python generate_evidence.py verify evidence.zip
  python generate_evidence.py show evidence.zip
  python generate_evidence.py keygen --out ed25519.pem

Security notes:
- Do not place secrets into manifest metadata. File paths and sizes are recorded.
- Prefer running on a read-only snapshot for immutable evidence.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import dataclasses
import getpass
import hashlib
import json
import logging
import mimetypes
import os
import platform
import socket
import subprocess
import sys
import time
import uuid
import zipfile
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# Optional Ed25519 support
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    CRYPTO_AVAILABLE = True
except Exception:  # pragma: no cover
    CRYPTO_AVAILABLE = False

# Optional OpenTelemetry tracing glue (best-effort; no hard dependency)
with suppress(Exception):
    from oblivionvault.observability import tracing as ov_tracing  # type: ignore
    ov_tracing.bootstrap_from_env()
    _TRACE = True
with suppress(Exception):
    _TRACE = _TRACE and True  # keep mypy happy
if "_TRACE" not in globals():
    _TRACE = False

LOG = logging.getLogger("oblivionvault.cli.evidence")


# ------------------------------ Utilities ------------------------------

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def read_in_chunks(fp, chunk_size: int = 1024 * 1024):
    while True:
        data = fp.read(chunk_size)
        if not data:
            break
        yield data

def sha256_and_sha512(path: Path) -> Tuple[str, str, int]:
    h256 = hashlib.sha256()
    h512 = hashlib.sha512()
    size = 0
    with path.open("rb") as f:
        for chunk in read_in_chunks(f):
            size += len(chunk)
            h256.update(chunk)
            h512.update(chunk)
    return h256.hexdigest(), h512.hexdigest(), size

def guess_mime(path: Path) -> str:
    mt, _ = mimetypes.guess_type(str(path))
    return mt or "application/octet-stream"

def to_posix_rel(path: Path, root: Path) -> str:
    return PurePosixPath(str(path.relative_to(root))).as_posix()

def is_text(s: str) -> bool:
    try:
        s.encode("utf-8")
        return True
    except Exception:
        return False

def stable_uuid() -> str:
    # UUID v4 default, may switch to v7 when available everywhere
    return str(uuid.uuid4())

def is_hidden(p: Path) -> bool:
    name = p.name
    return name.startswith(".") and name not in (".", "..")

def rfc3339_from_ns(ns: int) -> str:
    return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ------------------------------ Merkle ------------------------------

def merkle_root_sha256(leaves_hex: List[str]) -> str:
    """
    Compute SHA-256 Merkle root given list of hex-encoded leaf hashes.
    Deterministic: leaves are used in given order.
    """
    if not leaves_hex:
        return hashlib.sha256(b"").hexdigest()

    layer = [bytes.fromhex(x) for x in leaves_hex]
    while len(layer) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else left
            nxt.append(hashlib.sha256(left + right).digest())
        layer = nxt
    return layer[0].hex()


# ------------------------------ Git, Env, SBOM ------------------------------

def git_info(cwd: Path) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    def run(args: Sequence[str]) -> Optional[str]:
        try:
            out = subprocess.check_output(args, cwd=str(cwd), stderr=subprocess.DEVNULL, timeout=2)
            return out.decode().strip()
        except Exception:
            return None
    info["commit"] = run(["git", "rev-parse", "HEAD"])
    info["branch"] = run(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    info["dirty"] = bool(run(["git", "status", "--porcelain"]))
    return {k: v for k, v in info.items() if v is not None}

def env_info() -> Dict[str, Any]:
    return {
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
        },
        "python": {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
        },
        "host": {
            "hostname": socket.gethostname(),
            "user": getpass.getuser(),
        },
    }

def sbom_python() -> Dict[str, Any]:
    """
    Minimal Python SBOM snapshot using stdlib importlib.metadata.
    """
    try:
        from importlib.metadata import distributions
    except Exception:
        return {"packages": []}
    pkgs = []
    for d in distributions():
        name = d.metadata.get("Name") or d.metadata.get("Summary") or d.metadata.get("Name", "")
        version = d.version or d.metadata.get("Version") or ""
        lic = d.metadata.get("License") or ""
        if not name:
            continue
        pkgs.append({"name": str(name), "version": str(version), "license": str(lic)})
    pkgs.sort(key=lambda x: (x["name"].lower(), x["version"]))
    return {"packages": pkgs, "generator": "importlib.metadata"}

# ------------------------------ Signer ------------------------------

class SignerError(RuntimeError):
    pass

@dataclasses.dataclass
class SignatureBlock:
    alg: str
    public_key_b64: str
    signature_b64: str
    signed_at_utc: str

class Ed25519Signer:
    """
    Ed25519 signer. Supports:
    - load from PEM (PKCS8) file
    - load from raw hex or base64 32-byte private key via env
      OBLIVIONVAULT_EVIDENCE_SK_B64 or OBLIVIONVAULT_EVIDENCE_SK_HEX
    """
    def __init__(self, pem_path: Optional[Path] = None):
        if not CRYPTO_AVAILABLE:
            raise SignerError("cryptography is not available; install to use signing")
        self._priv: Ed25519PrivateKey
        if pem_path:
            data = pem_path.read_bytes()
            self._priv = serialization.load_pem_private_key(data, password=None)
        else:
            raw = os.getenv("OBLIVIONVAULT_EVIDENCE_SK_B64")
            if raw:
                sk = base64.b64decode(raw)
            else:
                raw_hex = os.getenv("OBLIVIONVAULT_EVIDENCE_SK_HEX")
                sk = bytes.fromhex(raw_hex) if raw_hex else None
            if not sk or len(sk) != 32:
                raise SignerError("no valid 32-byte private key in env; set OBLIVIONVAULT_EVIDENCE_SK_B64 or ..._HEX")
            self._priv = Ed25519PrivateKey.from_private_bytes(sk)

    @staticmethod
    def generate() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
        if not CRYPTO_AVAILABLE:
            raise SignerError("cryptography is not available; cannot generate keys")
        priv = Ed25519PrivateKey.generate()
        return priv, priv.public_key()

    @staticmethod
    def save_pem(priv: Ed25519PrivateKey, out_path: Path) -> None:
        data = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        out_path.write_bytes(data)

    @staticmethod
    def public_key_b64(pub: Ed25519PublicKey) -> str:
        return base64.b64encode(pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )).decode()

    def sign(self, data: bytes) -> SignatureBlock:
        pub = self._priv.public_key()
        sig = self._priv.sign(data)
        return SignatureBlock(
            alg="Ed25519",
            public_key_b64=self.public_key_b64(pub),
            signature_b64=base64.b64encode(sig).decode(),
            signed_at_utc=utc_now_iso(),
        )

    @staticmethod
    def verify(public_key_b64: str, data: bytes, signature_b64: str) -> bool:
        if not CRYPTO_AVAILABLE:
            raise SignerError("cryptography is not available; cannot verify signature")
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        try:
            pub.verify(base64.b64decode(signature_b64), data)
            return True
        except Exception:
            return False


# ------------------------------ Manifest model ------------------------------

@dataclasses.dataclass
class FileEntry:
    path: str
    size: int
    mtime_ns: int
    sha256: str
    sha512: str
    mime: str

@dataclasses.dataclass
class Manifest:
    schema: str
    manifest_id: str
    created_utc: str
    tool: Dict[str, Any]
    subject: Dict[str, Any]
    environment: Dict[str, Any]
    trace: Dict[str, Any]
    files: List[FileEntry]
    merkle: Dict[str, Any]
    sbom: Dict[str, Any]
    signature: Optional[SignatureBlock]

    def to_json_bytes(self) -> bytes:
        def enc(o):
            if dataclasses.is_dataclass(o):
                return dataclasses.asdict(o)
            raise TypeError(f"Not JSON serializable: {type(o)}")
        return json.dumps(dataclasses.asdict(self), default=enc, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


# ------------------------------ Core generation ------------------------------

def scan_files(inputs: List[Path], exclude: List[str], follow_symlinks: bool, allow_hidden: bool) -> Tuple[Path, List[Path]]:
    """
    Returns a common root and a sorted list of file paths to include.
    """
    files: List[Path] = []
    paths: List[Path] = []
    for p in inputs:
        p = p.resolve()
        if p.is_file():
            paths.append(p)
        elif p.is_dir():
            for f in p.rglob("*"):
                if not follow_symlinks and f.is_symlink():
                    continue
                if f.is_file():
                    paths.append(f)
    if not paths:
        raise SystemExit("No files found")
    # Compute common root
    root = Path(os.path.commonpath([str(p.parent if p.is_file() else p) for p in inputs])).resolve()

    # Apply exclude patterns relative to root
    import fnmatch
    def excluded(rel: str) -> bool:
        for pat in exclude:
            if fnmatch.fnmatch(rel, pat):
                return True
        return False

    for p in paths:
        rel = to_posix_rel(p, root)
        if not allow_hidden and any(part.startswith(".") for part in PurePosixPath(rel).parts):
            continue
        if excluded(rel):
            continue
        files.append(p)

    # Deterministic order by relative posix path
    files.sort(key=lambda x: to_posix_rel(x, root))
    return root, files

def hash_files(root: Path, files: List[Path], max_workers: int = max(2, os.cpu_count() or 2)) -> List[FileEntry]:
    entries: List[FileEntry] = []

    def worker(p: Path) -> FileEntry:
        sha256hex, sha512hex, size = sha256_and_sha512(p)
        st = p.stat()
        return FileEntry(
            path=to_posix_rel(p, root),
            size=size,
            mtime_ns=int(st.st_mtime_ns),
            sha256=sha256hex,
            sha512=sha512hex,
            mime=guess_mime(p),
        )

    with cf.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="hash") as ex:
        for entry in ex.map(worker, files):
            entries.append(entry)

    # Deterministic
    entries.sort(key=lambda e: e.path)
    return entries

def build_manifest(
    root: Path,
    inputs: List[Path],
    entries: List[FileEntry],
    attach_files: bool,
    subject_label: Optional[str],
    include_sbom: bool,
    trace_id: Optional[str],
    span_id: Optional[str],
) -> Manifest:
    leaves = [e.sha256 for e in entries]
    merkle = {
        "algo": "sha256",
        "root": merkle_root_sha256(leaves),
        "leaf_order": [e.path for e in entries],  # to recompute deterministically
    }
    subj = {
        "type": "filesystem",
        "inputs": [str(p) for p in inputs],
        "root": str(root),
        "working_dir": str(Path.cwd()),
        "attached_files": bool(attach_files),
    }
    if subject_label:
        subj["label"] = subject_label

    trace = {
        "trace_id": trace_id or "",
        "span_id": span_id or "",
    }

    manifest = Manifest(
        schema="https://oblivionvault.io/specs/evidence/manifest/v1",
        manifest_id=stable_uuid(),
        created_utc=utc_now_iso(),
        tool={"name": "oblivionvault-evidence-cli", "version": "1.0.0"},
        subject=subj,
        environment=env_info(),
        trace=trace,
        files=entries,
        merkle=merkle,
        sbom=sbom_python() if include_sbom else {"packages": []},
        signature=None,
    )
    return manifest


# ------------------------------ Packaging and verification ------------------------------

def write_bundle_zip(
    out_path: Path,
    manifest: Manifest,
    root: Path,
    entries: List[FileEntry],
    embed_files: bool,
) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # Ensure .zip extension if not given
    if out_path.suffix.lower() != ".zip":
        out_path = out_path.with_suffix(".zip")

    with zipfile.ZipFile(str(out_path), mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr("manifest.json", manifest.to_json_bytes())
        # Optional checksums for human reading
        checksums = "\n".join(f"{e.sha256}  {e.path}" for e in entries) + "\n"
        zf.writestr("checksums.sha256", checksums.encode("utf-8"))
        if embed_files:
            for e in entries:
                fs_path = root / e.path
                # Store under files/ with relative path
                zi = zipfile.ZipInfo.from_file(str(fs_path), arcname=str(PurePosixPath("files") / e.path))
                with fs_path.open("rb") as f, zf.open(zi, "w") as dst:
                    for chunk in read_in_chunks(f):
                        dst.write(chunk)

def load_manifest_from_zip(path: Path) -> Tuple[Manifest, zipfile.ZipFile]:
    zf = zipfile.ZipFile(str(path), mode="r")
    try:
        data = zf.read("manifest.json")
    except KeyError:
        zf.close()
        raise SystemExit("manifest.json not found in bundle")
    j = json.loads(data.decode("utf-8"))
    # Rehydrate dataclasses
    files = [FileEntry(**x) for x in j.get("files", [])]
    sig = j.get("signature")
    signature = SignatureBlock(**sig) if sig else None
    manifest = Manifest(
        schema=j.get("schema", ""),
        manifest_id=j.get("manifest_id", ""),
        created_utc=j.get("created_utc", ""),
        tool=j.get("tool", {}),
        subject=j.get("subject", {}),
        environment=j.get("environment", {}),
        trace=j.get("trace", {}),
        files=files,
        merkle=j.get("merkle", {}),
        sbom=j.get("sbom", {"packages": []}),
        signature=signature,
    )
    return manifest, zf

def verify_manifest_signature(manifest: Manifest) -> bool:
    if not manifest.signature:
        LOG.info("Bundle has no signature")
        return True
    data = dataclasses.asdict(manifest)
    data.pop("signature", None)
    payload = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ok = Ed25519Signer.verify(manifest.signature.public_key_b64, payload, manifest.signature.signature_b64)
    return ok

def verify_files_and_merkle(
    manifest: Manifest,
    bundle_zip: zipfile.ZipFile,
    external_root: Optional[Path],
) -> Tuple[bool, List[str]]:
    errors: List[str] = []
    # Determine source of file bytes: embedded or external
    embedded = bool(manifest.subject.get("attached_files"))
    for e in manifest.files:
        if embedded:
            arcname = str(PurePosixPath("files") / e.path)
            try:
                with bundle_zip.open(arcname, "r") as fp:
                    h256 = hashlib.sha256()
                    h512 = hashlib.sha512()
                    size = 0
                    while True:
                        chunk = fp.read(1024 * 1024)
                        if not chunk:
                            break
                        size += len(chunk)
                        h256.update(chunk)
                        h512.update(chunk)
                if h256.hexdigest() != e.sha256 or h512.hexdigest() != e.sha512 or size != e.size:
                    errors.append(f"mismatch for embedded {e.path}")
            except KeyError:
                errors.append(f"missing embedded file {e.path}")
        else:
            # external_root is required
            root = external_root or Path(manifest.subject.get("root", "."))
            fs_path = root / e.path
            if not fs_path.exists():
                errors.append(f"fs file missing {e.path}")
                continue
            h256, h512, size = sha256_and_sha512(fs_path)
            if h256 != e.sha256 or h512 != e.sha512 or size != e.size:
                errors.append(f"mismatch for fs {e.path}")

    # Merkle recomputation
    leaves = [f.sha256 for f in manifest.files]
    recomputed = merkle_root_sha256(leaves)
    if recomputed != manifest.merkle.get("root"):
        errors.append("merkle root mismatch")

    return len(errors) == 0, errors


# ------------------------------ CLI ------------------------------

def cmd_generate(args: argparse.Namespace) -> None:
    if _TRACE:
        tracer = ov_tracing.tracer("oblivionvault.cli.evidence")
        with tracer.start_as_current_span("cmd_generate"):
            _cmd_generate(args)
    else:
        _cmd_generate(args)

def _cmd_generate(args: argparse.Namespace) -> None:
    LOG.info("Scanning inputs")
    inputs = [Path(p) for p in args.inputs]
    root, files = scan_files(inputs, exclude=args.exclude or [], follow_symlinks=args.follow_symlinks, allow_hidden=args.allow_hidden)

    LOG.info("Hashing %d files", len(files))
    entries = hash_files(root, files, max_workers=args.workers)

    trace_id = ""
    span_id = ""
    if _TRACE:
        from opentelemetry import trace as _ot  # type: ignore
        sp = _ot.get_current_span()
        ctx = sp.get_span_context() if sp else None
        if ctx and ctx.is_valid:
            trace_id = f"{ctx.trace_id:032x}"
            span_id = f"{ctx.span_id:016x}"

    manifest = build_manifest(
        root=root,
        inputs=inputs,
        entries=entries,
        attach_files=args.embed_files,
        subject_label=args.label,
        include_sbom=args.include_sbom,
        trace_id=trace_id,
        span_id=span_id,
    )

    if args.sign or args.sign_pem:
        if not CRYPTO_AVAILABLE:
            raise SystemExit("cryptography not available; cannot sign. Install cryptography or run without --sign.")
        signer = Ed25519Signer(Path(args.sign_pem) if args.sign_pem else None)
        data = manifest.to_json_bytes()
        # Sign the manifest excluding signature field
        data_obj = dataclasses.asdict(manifest)
        data_obj.pop("signature", None)
        payload = json.dumps(data_obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        sig = signer.sign(payload)
        manifest.signature = sig

    out = Path(args.out) if args.out else Path(f"evidence-{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.zip")
    LOG.info("Writing bundle %s", out)
    write_bundle_zip(out, manifest, root, entries, embed_files=args.embed_files)
    LOG.info("Done")

def cmd_verify(args: argparse.Namespace) -> None:
    if _TRACE:
        tracer = ov_tracing.tracer("oblivionvault.cli.evidence")
        with tracer.start_as_current_span("cmd_verify"):
            _cmd_verify(args)
    else:
        _cmd_verify(args)

def _cmd_verify(args: argparse.Namespace) -> None:
    bundle = Path(args.bundle)
    manifest, zf = load_manifest_from_zip(bundle)
    try:
        LOG.info("Verifying signature")
        sig_ok = verify_manifest_signature(manifest)
        if not sig_ok:
            raise SystemExit("Signature verification failed")

        LOG.info("Verifying files and Merkle")
        root = Path(args.root) if args.root else None
        ok, errs = verify_files_and_merkle(manifest, zf, external_root=root)
        if not ok:
            for e in errs:
                LOG.error(e)
            raise SystemExit("Verification failed")
        LOG.info("Verification OK")
    finally:
        zf.close()

def cmd_show(args: argparse.Namespace) -> None:
    bundle = Path(args.bundle)
    manifest, zf = load_manifest_from_zip(bundle)
    try:
        js = manifest.to_json_bytes().decode("utf-8")
        print(js)
    finally:
        zf.close()

def cmd_keygen(args: argparse.Namespace) -> None:
    if not CRYPTO_AVAILABLE:
        raise SystemExit("cryptography not available; cannot generate keys")
    priv, pub = Ed25519Signer.generate()
    out = Path(args.out or "ed25519_sk.pem")
    Ed25519Signer.save_pem(priv, out)
    print(f"Private key PEM: {out}")
    print(f"Public key (base64, raw): {Ed25519Signer.public_key_b64(pub)}")

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="oblivionvault-evidence",
        description="Generate and verify immutable evidence bundles for OblivionVault",
    )
    p.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "INFO"), help="Logging level (DEBUG, INFO, WARNING, ERROR)")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="Generate evidence bundle")
    g.add_argument("inputs", nargs="+", help="Files or directories to include")
    g.add_argument("--out", "-o", help="Output bundle path (.zip). Default evidence-<utc>.zip")
    g.add_argument("--exclude", action="append", default=[], help="Glob patterns to exclude relative to common root, e.g. **/*.log")
    g.add_argument("--follow-symlinks", action="store_true", help="Follow symlinks")
    g.add_argument("--allow-hidden", action="store_true", help="Allow hidden files and folders")
    g.add_argument("--workers", type=int, default=max(2, os.cpu_count() or 2), help="Parallel hashing workers")
    g.add_argument("--embed-files", action="store_true", help="Embed source files into the ZIP bundle under files/")
    g.add_argument("--label", help="Optional subject label")
    g.add_argument("--include-sbom", action="store_true", help="Include Python SBOM snapshot")
    # Signing
    g.add_argument("--sign", action="store_true", help="Sign manifest with Ed25519 private key from env")
    g.add_argument("--sign-pem", help="Path to Ed25519 private key PEM (PKCS8) to sign manifest")

    v = sub.add_parser("verify", help="Verify evidence bundle")
    v.add_argument("bundle", help="Path to .zip bundle with manifest.json")
    v.add_argument("--root", help="External filesystem root for content verification when files are not embedded")

    s = sub.add_parser("show", help="Print manifest.json")
    s.add_argument("bundle", help="Path to .zip bundle")

    k = sub.add_parser("keygen", help="Generate Ed25519 keypair")
    k.add_argument("--out", "-o", help="Output PEM path for private key. Default ed25519_sk.pem")

    return p

def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Attach trace correlation if tracing available
    if _TRACE:
        with suppress(Exception):
            ov_tracing.enable_log_correlation(("", "oblivionvault", "uvicorn"))

def main(argv: Optional[Sequence[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.log_level)

    started = time.time()
    try:
        if args.cmd == "generate":
            cmd_generate(args)
        elif args.cmd == "verify":
            cmd_verify(args)
        elif args.cmd == "show":
            cmd_show(args)
        elif args.cmd == "keygen":
            cmd_keygen(args)
        else:
            parser.print_help()
            raise SystemExit(2)
    finally:
        LOG.debug("Elapsed %.3fs", time.time() - started)

if __name__ == "__main__":
    main()
