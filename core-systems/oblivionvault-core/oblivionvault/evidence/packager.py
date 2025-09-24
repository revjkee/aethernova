# oblivionvault-core/oblivionvault/evidence/packager.py
# Industrial-grade Evidence Packager for OblivionVault
# Python 3.10+
from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import datetime as dt
import fnmatch
import getpass
import hashlib
import io
import json
import logging
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Dict, Iterable, Iterator, List, Literal, Optional, Sequence, Tuple

# =========================
# Logging setup (library default: no handlers). CLI sets handlers explicitly.
# =========================
logger = logging.getLogger("oblivionvault.evidence.packager")
logger.addHandler(logging.NullHandler())

# =========================
# Exceptions
# =========================
class EvidenceError(Exception):
    """Base class for evidence packager errors."""

class OpenSSLNotFound(EvidenceError):
    """Raised when OpenSSL is required but not found."""

class VerificationError(EvidenceError):
    """Raised on verification mismatch."""

class PackagingError(EvidenceError):
    """Raised on packaging failure."""

# =========================
# Data Models
# =========================
@dataclasses.dataclass(frozen=True)
class FileEntry:
    logical_path: str        # Path within the archive (DATA/...)
    source_path: Optional[str]  # Original source for reference (not required for in-memory items)
    size: int
    mtime: int               # POSIX timestamp (int)
    mode: int                # File mode (e.g., 0o644)
    sha256: str

@dataclasses.dataclass(frozen=True)
class ChainEvent:
    ts: str                  # ISO8601 UTC
    actor: str               # e.g., user@host or system identity
    action: str              # e.g., "COLLECTED", "PACKAGED", "TRANSFERRED"
    tool: str                # e.g., "oblivionvault-packager/1.0"
    note: Optional[str] = None

@dataclasses.dataclass(frozen=True)
class MerkleTree:
    leaves: List[str]        # hex digests for leaves (SHA-256 of file content)
    root: str                # hex digest of the merkle root

@dataclasses.dataclass(frozen=True)
class Manifest:
    schema_version: str
    created_at_utc: str
    platform: Dict[str, str]
    creator: Dict[str, str]
    package_name: str
    compression: Literal["xz", "gz", "bz2", "none"]
    files: List[FileEntry]
    merkle: MerkleTree
    chain_of_custody: List[ChainEvent]
    annotations: Dict[str, str]
    policies: Dict[str, str]  # retention, classification, etc.
    package_hash_sha256: Optional[str] = None  # filled post-build
    signature: Optional[Dict[str, str]] = None # {"algo": "...", "file": "SIGNATURES/manifest.sig", "cert": "SIGNATURES/cert.pem"}

# =========================
# Utilities
# =========================
_CHUNK = 1024 * 1024  # 1 MiB

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()

def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _iter_files_sorted(root: Path) -> Iterator[Path]:
    for p in sorted(root.rglob("*")):
        if p.is_file():
            yield p

def _is_excluded(path: Path, root: Path, patterns: Sequence[str]) -> bool:
    rel = str(path.relative_to(root)).replace("\\", "/")
    for pat in patterns:
        if fnmatch.fnmatch(rel, pat):
            return True
    return False

def _get_file_mode(p: Path) -> int:
    try:
        return stat.S_IMODE(p.stat().st_mode)
    except Exception:
        return 0o644

def _openssl_available() -> bool:
    return shutil.which("openssl") is not None

def _run_openssl(args: List[str], input_bytes: Optional[bytes] = None) -> bytes:
    if not _openssl_available():
        raise OpenSSLNotFound("OpenSSL CLI not found in PATH")
    proc = subprocess.run(
        ["openssl"] + args,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise EvidenceError(f"OpenSSL error ({' '.join(args)}): {proc.stderr.decode('utf-8', 'ignore')}")
    return proc.stdout

def _now_iso_utc() -> str:
    return dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc).isoformat()

def _merkle_root(hashes: List[str]) -> MerkleTree:
    if not hashes:
        empty = hashlib.sha256(b"").hexdigest()
        return MerkleTree(leaves=[], root=empty)
    level = [bytes.fromhex(h) for h in hashes]
    leaves_hex = [h.hex() for h in level]
    while len(level) > 1:
        nxt: List[bytes] = []
        it = iter(level)
        for left in it:
            right = next(it, left)  # duplicate last if odd
            nxt.append(hashlib.sha256(left + right).digest())
        level = nxt
    return MerkleTree(leaves=leaves_hex, root=level[0].hex())

def _normalize_tarinfo(ti: tarfile.TarInfo, mode: Optional[int] = None, mtime: Optional[int] = None) -> tarfile.TarInfo:
    ti.uid = 0
    ti.gid = 0
    ti.uname = ""
    ti.gname = ""
    if mode is not None:
        ti.mode = mode
    if mtime is not None:
        ti.mtime = mtime
    return ti

def _safe_relpath(p: Path) -> str:
    # Ensure forward slashes and no traversal
    s = str(p).replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    if s.startswith("../"):
        raise PackagingError("Path traversal detected")
    return s

# =========================
# EvidencePackager
# =========================
class EvidencePackager:
    """
    Packages evidence files into a deterministic tar archive with:
    - Per-file SHA-256
    - Merkle root
    - Manifest with metadata and chain-of-custody
    - Optional OpenSSL signing and encryption
    - Sidecar .sha256 for the final package
    """

    def __init__(
        self,
        package_name: str,
        compression: Literal["xz", "gz", "bz2", "none"] = "xz",
        include_hidden: bool = False,
        follow_symlinks: bool = False,
        exclude: Optional[Sequence[str]] = None,
        max_workers: Optional[int] = None,
        annotations: Optional[Dict[str, str]] = None,
        policies: Optional[Dict[str, str]] = None,
        tempdir: Optional[Path] = None,
    ) -> None:
        if compression not in ("xz", "gz", "bz2", "none"):
            raise ValueError("Unsupported compression")
        self.package_name = package_name
        self.compression = compression
        self.include_hidden = include_hidden
        self.follow_symlinks = follow_symlinks
        self.exclude = list(exclude or [])
        self.max_workers = max_workers or max(os.cpu_count() or 2, 2)
        self.annotations = dict(annotations or {})
        self.policies = dict(policies or {})
        self._entries: List[Tuple[str, Optional[Path], int, int, int, str]] = []  # (logical, src, size, mtime, mode, sha256)
        self._chain: List[ChainEvent] = []
        self._tempdir = Path(tempdir) if tempdir else Path(tempfile.mkdtemp(prefix="ovpkg-"))
        self._closed = False
        logger.debug("Initialized EvidencePackager(%s)", self.package_name)

    # ------------- Public API -------------
    def add_chain_event(self, action: str, note: Optional[str] = None, actor: Optional[str] = None, tool: Optional[str] = None) -> None:
        ev = ChainEvent(
            ts=_now_iso_utc(),
            actor=actor or f"{getpass.getuser()}@{platform.node()}",
            action=action,
            tool=tool or f"oblivionvault-packager/{self._version()}",
            note=note,
        )
        self._chain.append(ev)

    def add_path(self, src: Path, logical_prefix: str = "") -> None:
        """
        Add file or directory recursively into the package.
        logical_prefix: optional prefix under DATA/
        """
        src = Path(src).resolve()
        if not src.exists():
            raise FileNotFoundError(f"Path not found: {src}")

        # Collect files
        files: List[Path] = []
        if src.is_file():
            files = [src]
        else:
            for p in _iter_files_sorted(src):
                if not self.include_hidden and p.name.startswith("."):
                    continue
                if self.exclude and _is_excluded(p, src, self.exclude):
                    continue
                if p.is_symlink() and not self.follow_symlinks:
                    continue
                files.append(p)

        logger.info("Hashing %d file(s) from %s", len(files), src)
        # Hash in parallel
        def _hash_one(p: Path) -> Tuple[Path, str]:
            return (p, _sha256_file(p))

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            for p, h in ex.map(_hash_one, files):
                st = p.stat()
                rel = p.relative_to(src) if src.is_dir() else p.name
                logical = f"{logical_prefix}/{rel}".strip("/")
                logical = f"DATA/{_safe_relpath(Path(logical))}"
                self._entries.append((
                    logical,
                    p,
                    st.st_size,
                    int(st.st_mtime),
                    _get_file_mode(p),
                    h,
                ))

    def add_bytes(self, name: str, data: bytes, mode: int = 0o600, mtime: Optional[int] = None) -> None:
        """
        Add in-memory bytes as a file into DATA/.
        """
        logical = f"DATA/{_safe_relpath(Path(name))}"
        tmp = self._tempdir / f"mem-{hashlib.sha1(logical.encode()).hexdigest()}"
        tmp.write_bytes(data)
        if mtime is None:
            mtime = int(dt.datetime.utcnow().timestamp())
        os.chmod(tmp, mode)
        self._entries.append((logical, tmp, len(data), int(mtime), mode, _sha256_bytes(data)))

    def finalize(
        self,
        output_path: Path,
        sign_manifest_with_key: Optional[Path] = None,  # PEM private key for detached signature (OpenSSL)
        sign_cert: Optional[Path] = None,               # PEM certificate to embed (optional)
        encrypt_with_pass_env: Optional[str] = None,    # env var with passphrase (OpenSSL AES-256-CBC)
        openssl_cipher: str = "aes-256-cbc",
        compute_sidecar_hash: bool = True,
    ) -> Path:
        """
        Build the package. Returns the final output path (possibly encrypted).
        If encrypt_with_pass_env is provided, the tar.* is encrypted into *.enc (OpenSSL required).
        """
        if self._closed:
            raise PackagingError("Packager is already finalized")
        self._closed = True

        self._entries.sort(key=lambda t: t[0])  # deterministic order by logical path
        leaves = [e[5] for e in self._entries]
        merkle = _merkle_root(leaves)

        manifest = Manifest(
            schema_version="1.0",
            created_at_utc=_now_iso_utc(),
            platform={
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "python": platform.python_version(),
            },
            creator={
                "user": getpass.getuser(),
                "host": platform.node(),
                "tool": f"oblivionvault-packager/{self._version()}",
            },
            package_name=self.package_name,
            compression=self.compression,
            files=[FileEntry(*e) for e in self._entries],
            merkle=merkle,
            chain_of_custody=self._chain[:],
            annotations=self.annotations,
            policies=self.policies,
        )

        # Build tar archive (optionally compressed)
        tar_mode = {
            "xz": "w:xz",
            "gz": "w:gz",
            "bz2": "w:bz2",
            "none": "w",
        }[self.compression]

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        tmp_tar = output_path if self.compression != "none" else output_path
        # Ensure extension clarity if user passed a dir/name without suffix
        if tmp_tar.suffix == "":
            ext = { "xz": ".tar.xz", "gz": ".tar.gz", "bz2": ".tar.bz2", "none": ".tar" }[self.compression]
            tmp_tar = tmp_tar.with_suffix(ext)

        logger.info("Creating package: %s", tmp_tar)
        with tarfile.open(tmp_tar, mode=tar_mode, format=tarfile.PAX_FORMAT) as tar:
            # Add DATA files
            for logical, src, size, mtime, mode, _h in self._entries:
                ti = tarfile.TarInfo(name=logical)
                ti.size = size
                _normalize_tarinfo(ti, mode=mode, mtime=mtime)
                if src is None:
                    # should not happen (we always wrote temp file for bytes)
                    raise PackagingError("Missing source path for in-memory entry")
                with open(src, "rb") as f:
                    tar.addfile(ti, fileobj=f)

            # Add HASHES/merkle.json
            merkle_json = json.dumps(dataclasses.asdict(manifest.merkle), ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
            ti = tarfile.TarInfo(name="HASHES/merkle.json")
            ti.size = len(merkle_json)
            _normalize_tarinfo(ti, mode=0o644, mtime=int(dt.datetime.utcnow().timestamp()))
            tar.addfile(ti, io.BytesIO(merkle_json))

            # Add META/manifest.json (unsigned at this moment)
            manifest_json = json.dumps(_manifest_to_dict(manifest), ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
            ti = tarfile.TarInfo(name="META/manifest.json")
            ti.size = len(manifest_json)
            _normalize_tarinfo(ti, mode=0o644, mtime=int(dt.datetime.utcnow().timestamp()))
            tar.addfile(ti, io.BytesIO(manifest_json))

            # Optionally add signature for manifest (detached)
            if sign_manifest_with_key:
                if not _openssl_available():
                    raise OpenSSLNotFound("OpenSSL required for signature but not found")
                sig = _run_openssl(["dgst", "-sha256", "-sign", str(sign_manifest_with_key), "-binary"], input_bytes=manifest_json)
                ti = tarfile.TarInfo(name="SIGNATURES/manifest.sig")
                ti.size = len(sig)
                _normalize_tarinfo(ti, mode=0o644, mtime=int(dt.datetime.utcnow().timestamp()))
                tar.addfile(ti, io.BytesIO(sig))
                if sign_cert:
                    cert_bytes = Path(sign_cert).read_bytes()
                    ti = tarfile.TarInfo(name="SIGNATURES/cert.pem")
                    ti.size = len(cert_bytes)
                    _normalize_tarinfo(ti, mode=0o644, mtime=int(dt.datetime.utcnow().timestamp()))
                    tar.addfile(ti, io.BytesIO(cert_bytes))
                manifest.signature = {
                    "algo": "sha256-rsa",
                    "file": "SIGNATURES/manifest.sig",
                    "cert": "SIGNATURES/cert.pem" if sign_cert else "",
                }

        # Compute final package hash and write sidecar
        pkg_hash = _sha256_file(tmp_tar)
        if compute_sidecar_hash:
            Path(str(tmp_tar) + ".sha256").write_text(f"{pkg_hash}  {tmp_tar.name}\n", encoding="utf-8")
        manifest = dataclasses.replace(manifest, package_hash_sha256=pkg_hash)

        # Optional encryption with OpenSSL symmetric cipher
        if encrypt_with_pass_env:
            if not _openssl_available():
                raise OpenSSLNotFound("OpenSSL required for encryption but not found")
            passphrase = os.environ.get(encrypt_with_pass_env)
            if not passphrase:
                raise EvidenceError(f"Passphrase env var {encrypt_with_pass_env} is empty or not set")
            enc_path = tmp_tar.with_suffix(tmp_tar.suffix + ".enc")
            logger.info("Encrypting package with OpenSSL (%s): %s -> %s", openssl_cipher, tmp_tar, enc_path)
            # Use salted symmetric encryption with PBKDF (enc -pbkdf)
            # Note: OpenSSL 3+ supports -pbkdf by default; we pass it for safety.
            _ = _run_openssl([
                "enc", f"-{openssl_cipher}", "-salt", "-pbkdf2",
                "-pass", f"env:{encrypt_with_pass_env}",
                "-in", str(tmp_tar),
                "-out", str(enc_path),
            ])
            final_path = enc_path
        else:
            final_path = tmp_tar

        logger.info("Package created: %s (sha256=%s)", final_path, pkg_hash)
        return final_path

    # ------------- Verification (static) -------------
    @staticmethod
    def verify_package(package_path: Path, pass_env: Optional[str] = None) -> Dict[str, object]:
        """
        Verify package integrity:
        - If encrypted, decrypt to memory (stream) is not feasible; we require a temporary file.
        - Validate SHA-256 sidecar if present.
        - Validate TAR structure, manifest presence.
        - Recompute file hashes and compare with manifest.
        - Recompute merkle root and compare.
        Returns a dict report.
        """
        package_path = Path(package_path)
        tmp: Optional[Path] = None
        to_check = package_path

        # If encrypted, decrypt to temp file using OpenSSL and pass_env
        if package_path.suffix.endswith(".enc"):
            if not _openssl_available():
                raise OpenSSLNotFound("OpenSSL required for decryption but not found")
            if not pass_env or not os.environ.get(pass_env):
                raise EvidenceError("Encrypted package provided but pass_env not set or empty")
            tmp = Path(tempfile.mkstemp(prefix="ovpkg-dec-", suffix=".tar")[1])
            os.close(  # close the fd returned by mkstemp
                next(fd for fd, name in [ (int(tmp.name.split("ovpkg-dec-")[-1].split(".tar")[0] or 0), tmp.name) ] if True)  # dummy close; ensure no fd leak
                if False else 0
            )
            # Better: use a separate mkstemp for path, then write; simpler approach:
            tmp.unlink(missing_ok=True)
            tmp = Path(tempfile.mktemp(prefix="ovpkg-dec-", suffix=".tar"))
            _ = _run_openssl([
                "enc", "-d", "-aes-256-cbc", "-pbkdf2",
                "-pass", f"env:{pass_env}",
                "-in", str(package_path),
                "-out", str(tmp),
            ])
            to_check = tmp

        # Sidecar check (best-effort)
        sidecar = Path(str(to_check) + ".sha256")
        if sidecar.exists():
            content = sidecar.read_text(encoding="utf-8").strip()
            if content:
                recorded = content.split()[0]
                actual = _sha256_file(to_check)
                if recorded != actual:
                    raise VerificationError("Sidecar .sha256 mismatch")

        # Read tar and extract manifest + hashes
        with tarfile.open(to_check, mode="r:*") as tar:
            manifest_bytes = _read_member(tar, "META/manifest.json")
            if manifest_bytes is None:
                raise VerificationError("META/manifest.json not found")
            manifest = _manifest_from_bytes(manifest_bytes)
            # Verify merkle.json consistency
            merkle_bytes = _read_member(tar, "HASHES/merkle.json")
            if merkle_bytes is None:
                raise VerificationError("HASHES/merkle.json not found")
            merkle_json = json.loads(merkle_bytes.decode("utf-8"))
            if merkle_json.get("root") != manifest["merkle"]["root"]:
                raise VerificationError("Merkle root mismatch (manifest vs HASHES/merkle.json)")

            # Optionally verify manifest signature if present
            sig_info = manifest.get("signature")
            sig_ok = None
            sig_error = None
            if sig_info and sig_info.get("file"):
                sig = _read_member(tar, sig_info["file"])
                if sig is None:
                    raise VerificationError("Signature file declared but not found in archive")
                try:
                    # Extract manifest again for canonical verification (already read)
                    if not _openssl_available():
                        raise OpenSSLNotFound("OpenSSL required for signature verification but not found")
                    # If cert is present, use it; otherwise verification responsibility is external.
                    cert_pem = None
                    cert_path = sig_info.get("cert") or ""
                    if cert_path:
                        cert_bytes = _read_member(tar, cert_path)
                        if cert_bytes:
                            cert_pem = cert_bytes
                    # Write temp files for openssl - verify
                    with tempfile.TemporaryDirectory() as td:
                        man = Path(td) / "manifest.json"
                        s = Path(td) / "manifest.sig"
                        man.write_bytes(json.dumps(manifest, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8"))
                        s.write_bytes(sig)
                        if cert_pem:
                            c = Path(td) / "cert.pem"
                            c.write_bytes(cert_pem)
                            # Verify: extract pubkey and verify digest
                            pub = _run_openssl(["x509", "-in", str(c), "-pubkey", "-noout"])
                            pub_path = Path(td) / "pub.pem"
                            pub_path.write_bytes(pub)
                            # OpenSSL CLI doesn't provide a simple detached verify for arbitrary sig with pubkey over file digest;
                            # We simulate by verifying digest: openssl dgst -sha256 -verify pub.pem -signature manifest.sig manifest.json
                            _ = _run_openssl(["dgst", "-sha256", "-verify", str(pub_path), "-signature", str(s), str(man)])
                            sig_ok = True
                        else:
                            # If no cert, we cannot verify here (caller must).
                            sig_ok = None
                except Exception as e:
                    sig_ok = False
                    sig_error = str(e)

            # Recompute per-file hashes
            file_entries = [f for f in manifest["files"]]
            # For deterministic verification: read each member stream and hash
            mismatches: List[Tuple[str, str, str]] = []
            for fe in file_entries:
                member = tar.getmember(fe["logical_path"])
                f = tar.extractfile(member)
                if f is None:
                    raise VerificationError(f"Archive member missing: {fe['logical_path']}")
                h = hashlib.sha256()
                for chunk in iter(lambda: f.read(_CHUNK), b""):
                    h.update(chunk)
                actual = h.hexdigest()
                if actual != fe["sha256"]:
                    mismatches.append((fe["logical_path"], fe["sha256"], actual))

            if mismatches:
                raise VerificationError(f"Hash mismatches: {mismatches[:5]} ... total={len(mismatches)}")

            # Recompute merkle
            recomputed_merkle = _merkle_root([fe["sha256"] for fe in file_entries])
            if recomputed_merkle.root != manifest["merkle"]["root"]:
                raise VerificationError("Merkle root mismatch after recomputation")

        return {
            "package": str(package_path),
            "decrypted_tmp": str(to_check) if to_check != package_path else "",
            "files_verified": len(file_entries),
            "merkle_root": manifest["merkle"]["root"],
            "signature_verified": sig_ok,
            "signature_error": sig_error,
        }

    # ------------- Helpers -------------
    @staticmethod
    def _version() -> str:
        return "1.0.0"

def _read_member(tar: tarfile.TarFile, name: str) -> Optional[bytes]:
    try:
        m = tar.getmember(name)
        f = tar.extractfile(m)
        return f.read() if f else None
    except KeyError:
        return None

def _manifest_to_dict(m: Manifest) -> Dict[str, object]:
    d = dataclasses.asdict(m)
    # Convert dataclasses within to primitives
    d["files"] = [dataclasses.asdict(f) for f in m.files]
    d["chain_of_custody"] = [dataclasses.asdict(e) for e in m.chain_of_custody]
    d["merkle"] = dataclasses.asdict(m.merkle)
    return d

def _manifest_from_bytes(b: bytes) -> Dict[str, object]:
    return json.loads(b.decode("utf-8"))

# =========================
# CLI
# =========================
def _setup_cli_logger(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter("[%(levelname)s] %(message)s")
    handler.setFormatter(formatter)
    logger.setLevel(level)
    logger.handlers.clear()
    logger.addHandler(handler)

def _cmd_pack(args: argparse.Namespace) -> None:
    _setup_cli_logger(args.verbose)
    pkg = EvidencePackager(
        package_name=args.name,
        compression=args.compression,
        include_hidden=args.include_hidden,
        follow_symlinks=args.follow_symlinks,
        exclude=args.exclude or [],
        annotations=_parse_kv(args.annotation),
        policies=_parse_kv(args.policy),
        max_workers=args.workers,
    )
    pkg.add_chain_event("COLLECTION_STARTED")
    for src in args.input:
        p = Path(src)
        logical_prefix = args.prefix or p.stem if p.is_dir() else args.prefix or ""
        pkg.add_path(p, logical_prefix=logical_prefix)
    for item in args.inline or []:
        name, data = item.split("=", 1)
        pkg.add_bytes(name=name, data=data.encode("utf-8"), mode=0o600)
    pkg.add_chain_event("PACKAGING", note="Finalizing package")

    sign_key = Path(args.sign_key) if args.sign_key else None
    sign_cert = Path(args.sign_cert) if args.sign_cert else None
    out = pkg.finalize(
        output_path=Path(args.output),
        sign_manifest_with_key=sign_key,
        sign_cert=sign_cert,
        encrypt_with_pass_env=args.encrypt_env,
        openssl_cipher=args.cipher,
        compute_sidecar_hash=not args.no_sidecar,
    )
    print(str(out))

def _cmd_verify(args: argparse.Namespace) -> None:
    _setup_cli_logger(args.verbose)
    report = EvidencePackager.verify_package(Path(args.package), pass_env=args.pass_env)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))

def _cmd_list(args: argparse.Namespace) -> None:
    _setup_cli_logger(args.verbose)
    with tarfile.open(args.package, mode="r:*") as tar:
        names = sorted(m.name for m in tar.getmembers())
        print("\n".join(names))

def _parse_kv(pairs: Optional[Sequence[str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for s in pairs or []:
        if "=" not in s:
            raise argparse.ArgumentTypeError(f"Expected key=value, got: {s}")
        k, v = s.split("=", 1)
        out[k] = v
    return out

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="oblivionvault-packager", description="OblivionVault Evidence Packager")
    sub = p.add_subparsers(dest="cmd", required=True)

    pp = sub.add_parser("pack", help="Create evidence package")
    pp.add_argument("-i", "--input", nargs="+", required=True, help="Files or directories to include")
    pp.add_argument("-o", "--output", required=True, help="Output path (suffix will be adjusted to compression)")
    pp.add_argument("-n", "--name", required=True, help="Logical package name")
    pp.add_argument("--compression", choices=["xz", "gz", "bz2", "none"], default="xz")
    pp.add_argument("--include-hidden", action="store_true")
    pp.add_argument("--follow-symlinks", action="store_true")
    pp.add_argument("--exclude", nargs="*", default=[], help="Glob patterns relative to added directory")
    pp.add_argument("--annotation", "-A", action="append", help="key=value")
    pp.add_argument("--policy", "-P", action="append", help="key=value")
    pp.add_argument("--inline", "-D", action="append", help="Embed text as file: name=string")
    pp.add_argument("--prefix", help="Logical prefix under DATA/ for directory inputs")
    pp.add_argument("--workers", type=int, default=max(os.cpu_count() or 2, 2), help="Hashing threads")
    pp.add_argument("--sign-key", help="PEM private key to sign manifest (OpenSSL)")
    pp.add_argument("--sign-cert", help="PEM certificate to embed for signature verification")
    pp.add_argument("--encrypt-env", help="Env var with passphrase for OpenSSL encryption")
    pp.add_argument("--cipher", default="aes-256-cbc", help="OpenSSL symmetric cipher (default aes-256-cbc)")
    pp.add_argument("--no-sidecar", action="store_true", help="Do not write .sha256 sidecar for package")
    pp.add_argument("-v", "--verbose", action="count", default=0)
    pp.set_defaults(func=_cmd_pack)

    pv = sub.add_parser("verify", help="Verify evidence package")
    pv.add_argument("package", help="Path to package (encrypted .enc supported with --pass-env)")
    pv.add_argument("--pass-env", help="Env var with passphrase for decryption (if .enc)")
    pv.add_argument("-v", "--verbose", action="count", default=0)
    pv.set_defaults(func=_cmd_verify)

    pl = sub.add_parser("list", help="List archive members")
    pl.add_argument("package", help="Path to package")
    pl.add_argument("-v", "--verbose", action="count", default=0)
    pl.set_defaults(func=_cmd_list)

    return p

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
        return 0
    except EvidenceError as e:
        logger.error(str(e))
        return 2
    except Exception as e:
        logger.exception("Unexpected error: %s", e)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
