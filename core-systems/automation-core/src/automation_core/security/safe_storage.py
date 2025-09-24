# SPDX-License-Identifier: MIT
"""
Secure at-rest storage for small secrets on local filesystem.

Features:
- AES-256-GCM encryption (via cryptography.hazmat.primitives.ciphers.aead.AESGCM).
- Data key derivation per secret/version using HKDF-SHA256 from a 32-byte master key.
- Per-record random salt (32 B) and nonce (12 B) stored alongside ciphertext.
- AAD (associated data) binds name/version/created_at to prevent mix&match.
- Atomic writes (tmp + fsync + os.replace), fsync directory.
- File locking (fcntl on Unix, msvcrt on Windows).
- Versioned secrets: v0000000001, v0000000002, ...
- Master key rotation (re-encrypt in place), backup/restore.
- Minimal dependencies: Python 3.11+, cryptography.

Structure on disk:
  root/
    meta.json                  # storage metadata, key_id, format_version
    secrets/<name>/
      v0000000001.seal         # encrypted blob (salt|nonce|ciphertext)
      v0000000001.meta.json    # metadata: algo, created_at, tags, ttl, key_id, lengths

Notes:
- Designed for small payloads (tokens, API keys, short JSON), not large files.
- Best-effort "shred" (overwrite) is not guaranteed across filesystems. Use delete() accordingly.
"""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import json
import os
import secrets
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, Literal, Optional, Tuple

try:
    # cryptography is required for AESGCM and HKDF
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
except Exception as e:  # pragma: no cover
    raise SystemExit("Missing dependency: cryptography. Install with: pip install cryptography") from e

# Optional platform-specific locking
try:  # Unix
    import fcntl  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

try:  # Windows
    import msvcrt  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    msvcrt = None  # type: ignore[assignment]

__all__ = [
    "SafeStorageError",
    "IntegrityError",
    "LockError",
    "SafeStorage",
    "generate_master_key_b64",
]


# =============================================================================
# Exceptions
# =============================================================================
class SafeStorageError(Exception):
    pass


class IntegrityError(SafeStorageError):
    pass


class LockError(SafeStorageError):
    pass


# =============================================================================
# Small helpers: atomic writes, fsync dir, file lock
# =============================================================================
def _fsync_dir(p: Path) -> None:
    with contextlib.suppress(Exception):
        fd = os.open(p, os.O_RDONLY)
        try:
            os.fsync(fd)  # type: ignore[arg-type]
        finally:
            os.close(fd)


def _atomic_write_bytes(path: Path, data: bytes, *, perms: int | None = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp_path = Path(tmp)
    try:
        with os.fdopen(fd, "wb", closefd=True) as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if perms is not None:
            with contextlib.suppress(Exception):
                os.chmod(tmp_path, perms)
        os.replace(tmp_path, path)
        _fsync_dir(path.parent)
    except Exception:
        with contextlib.suppress(Exception):
            tmp_path.unlink(missing_ok=True)
        raise


def _atomic_write_json(path: Path, payload: Dict[str, Any], *, perms: int | None = 0o600) -> None:
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")
    _atomic_write_bytes(path, blob, perms=perms)


class _FileLock:
    """
    Cross-platform advisory lock on a separate .lock file.

    - Unix: fcntl.flock (shared/exclusive not required here, we use EX).
    - Windows: msvcrt.locking on 1 byte.
    """

    def __init__(self, path: Path, timeout: float = 10.0, poll: float = 0.05) -> None:
        self._lock_path = path.with_name(path.name + ".lock")
        self._fh: Optional[Any] = None
        self._timeout = timeout
        self._poll = poll

    def acquire(self) -> None:
        start = time.monotonic()
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(self._lock_path, "a+b", buffering=0)
        self._fh = fh
        while True:
            try:
                if fcntl is not None:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)  # type: ignore[attr-defined]
                    return
                elif msvcrt is not None:
                    try:
                        msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)  # type: ignore[attr-defined]
                        return
                    except OSError:
                        pass
                else:
                    # Fallback: emulate with create/replace — not strong, but better than nothing
                    if self._lock_path.exists():
                        raise BlockingIOError
                    fd, tmp = tempfile.mkstemp(prefix=self._lock_path.name + ".", dir=self._lock_path.parent)
                    os.close(fd)
                    os.replace(tmp, self._lock_path)
                    return
            except BlockingIOError:
                pass
            if (time.monotonic() - start) >= self._timeout:
                try:
                    fh.close()
                finally:
                    self._fh = None
                raise LockError(f"Timeout acquiring lock for {self._lock_path}")
            time.sleep(self._poll)

    def release(self) -> None:
        fh = self._fh
        if fh is None:
            return
        try:
            if fcntl is not None:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)  # type: ignore[attr-defined]
            elif msvcrt is not None:
                with contextlib.suppress(Exception):
                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]
        finally:
            with contextlib.suppress(Exception):
                fh.close()
            self._fh = None


# =============================================================================
# Key utilities
# =============================================================================
def generate_master_key_b64() -> str:
    """
    Generate a random 32-byte master key for AES-256 and return urlsafe base64 string.
    """
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


def _load_master_key_b64(b64: str) -> bytes:
    raw = base64.urlsafe_b64decode(b64.encode("ascii"))
    if len(raw) != 32:
        raise SafeStorageError("Master key must be 32 bytes (base64-encoded).")
    return raw


def _key_id(master_key: bytes) -> str:
    # stable short identifier for metadata
    from hashlib import sha256

    return sha256(master_key).hexdigest()[:16]


def _hkdf_derive(master_key: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(master_key)


# =============================================================================
# Data model
# =============================================================================
@dataclass(frozen=True)
class SecretMeta:
    name: str
    version: str
    created_at: float
    ttl: float | None
    tags: Dict[str, str]
    key_id: str
    algo: str = "AES-256-GCM"
    kdf: str = "HKDF-SHA256"
    salt_len: int = 32
    nonce_len: int = 12
    ciphertext_len: int | None = None


# =============================================================================
# SafeStorage
# =============================================================================
class SafeStorage:
    """
    Filesystem-based, versioned encrypted storage for small secrets.

    Parameters:
      root_dir: directory to store metadata and secrets.
      master_key_b64: urlsafe base64-encoded 32-byte master key. If None, read from env var.
      env_var: name of env var to read the base64 key from (default SAFE_STORAGE_MASTER_KEY).
    """

    FORMAT_VERSION = 1
    INFO_CONTEXT = b"automation-core/safe-storage:v1"

    def __init__(self, root_dir: str | os.PathLike[str], *, master_key_b64: str | None = None, env_var: str = "SAFE_STORAGE_MASTER_KEY") -> None:
        self.root = Path(root_dir)
        self.meta_path = self.root / "meta.json"
        self.secrets_dir = self.root / "secrets"
        self.env_var = env_var

        if master_key_b64 is None:
            master_key_b64 = os.getenv(env_var)
            if not master_key_b64:
                raise SafeStorageError(
                    f"Master key is required. Provide base64 key via parameter or env var {env_var}."
                )
        self.master_key = _load_master_key_b64(master_key_b64)
        self.key_id = _key_id(self.master_key)

        self.root.mkdir(parents=True, exist_ok=True)
        self._initialize_meta()

    # ---------------- Meta initialization ----------------
    def _initialize_meta(self) -> None:
        if self.meta_path.exists():
            try:
                meta = json.loads(self.meta_path.read_text(encoding="utf-8"))
            except Exception as e:  # pragma: no cover
                raise SafeStorageError(f"Failed to parse meta.json: {e}") from e
            # Basic sanity checks
            if int(meta.get("format_version", 0)) != self.FORMAT_VERSION:
                raise SafeStorageError("Unsupported format_version in meta.json")
            # If meta contains key_id, it should match current
            mk = meta.get("key_id")
            if mk and mk != self.key_id:
                # The on-disk data belongs to different master key; allow but warn.
                pass
            return

        # Create fresh meta
        payload = {
            "format_version": self.FORMAT_VERSION,
            "key_id": self.key_id,
            "created_at": time.time(),
            "aad_context": self.INFO_CONTEXT.decode("ascii"),
        }
        _atomic_write_json(self.meta_path, payload, perms=0o600)

    # ---------------- Paths & helpers ----------------
    def _name_dir(self, name: str) -> Path:
        return self.secrets_dir / name

    def _seal_path(self, name: str, version: str) -> Path:
        return self._name_dir(name) / f"{version}.seal"

    def _meta_path(self, name: str, version: str) -> Path:
        return self._name_dir(name) / f"{version}.meta.json"

    @staticmethod
    def _next_version(existing: Iterable[str]) -> str:
        maxn = 0
        for v in existing:
            with contextlib.suppress(Exception):
                if v.startswith("v"):
                    maxn = max(maxn, int(v[1:]))
        return f"v{maxn+1:010d}"

    @staticmethod
    def _now() -> float:
        return time.time()

    # ---------------- Public API ----------------
    def set(
        self,
        name: str,
        data: bytes | str,
        *,
        ttl: float | None = None,
        tags: Dict[str, str] | None = None,
        encoding: str = "utf-8",
    ) -> str:
        """
        Store secret under name; returns created version (e.g. v0000000001).
        """
        if isinstance(data, str):
            data_bytes = data.encode(encoding)
        else:
            data_bytes = data

        # Ensure dir & locking per name
        ndir = self._name_dir(name)
        ndir.mkdir(parents=True, exist_ok=True)
        lock = _FileLock(ndir)
        lock.acquire()
        try:
            existing = [p.stem for p in ndir.glob("v*.seal")]
            version = self._next_version(existing)
            created_at = self._now()
            salt = secrets.token_bytes(32)
            nonce = secrets.token_bytes(12)

            dk = _hkdf_derive(self.master_key, salt=salt, info=self.INFO_CONTEXT)
            aead = AESGCM(dk)
            aad = f"{name}|{version}|{created_at}".encode("utf-8")
            ct = aead.encrypt(nonce, data_bytes, aad)

            # Write seal: salt|nonce|ciphertext
            seal_path = self._seal_path(name, version)
            blob = salt + nonce + ct
            _atomic_write_bytes(seal_path, blob, perms=0o600)

            # Write metadata
            smeta = SecretMeta(
                name=name,
                version=version,
                created_at=created_at,
                ttl=ttl,
                tags=tags or {},
                key_id=self.key_id,
                ciphertext_len=len(ct),
            )
            _atomic_write_json(self._meta_path(name, version), dataclasses.asdict(smeta), perms=0o600)
            return version
        finally:
            lock.release()

    def get(self, name: str, version: str | None = None, *, encoding: str | None = None) -> bytes | str:
        """
        Retrieve secret bytes (or str if encoding specified).
        """
        ndir = self._name_dir(name)
        if not ndir.exists():
            raise SafeStorageError(f"Secret '{name}' not found")

        if version is None:
            # latest by max version number
            versions = sorted([p.stem for p in ndir.glob("v*.seal")])
            if not versions:
                raise SafeStorageError(f"No versions for secret '{name}'")
            version = versions[-1]

        seal_path = self._seal_path(name, version)
        meta_path = self._meta_path(name, version)
        if not seal_path.exists() or not meta_path.exists():
            raise SafeStorageError("Secret blob or metadata missing/corrupted")

        blob = seal_path.read_bytes()
        if len(blob) < 32 + 12 + 16:  # salt + nonce + min tag
            raise IntegrityError("Seal blob too short")

        salt = blob[:32]
        nonce = blob[32:44]
        ct = blob[44:]

        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        aad = f"{name}|{version}|{meta.get('created_at')}".encode("utf-8")

        dk = _hkdf_derive(self.master_key, salt=salt, info=self.INFO_CONTEXT)
        aead = AESGCM(dk)
        try:
            pt = aead.decrypt(nonce, ct, aad)
        except Exception as e:
            raise IntegrityError("Authentication failed") from e

        if encoding is not None:
            return pt.decode(encoding)
        return pt

    def list(self, name: str | None = None) -> Dict[str, list[str]]:
        """
        List all secrets -> versions; or versions for specific name.
        """
        out: Dict[str, list[str]] = {}
        if name:
            ndir = self._name_dir(name)
            if not ndir.exists():
                return {name: []}
            out[name] = sorted([p.stem for p in ndir.glob("v*.seal")])
            return out

        if not self.secrets_dir.exists():
            return {}
        for ndir in self.secrets_dir.iterdir():
            if ndir.is_dir():
                out[ndir.name] = sorted([p.stem for p in ndir.glob("v*.seal")])
        return out

    def delete(self, name: str, version: str | None = None, *, shred: bool = False) -> None:
        """
        Delete a version or entire secret. 'shred' tries to overwrite before unlink (best effort).
        """
        ndir = self._name_dir(name)
        if not ndir.exists():
            return
        lock = _FileLock(ndir)
        lock.acquire()
        try:
            if version is None:
                # delete all versions
                for p in ndir.glob("v*.seal"):
                    self._unlink_secure(p, shred=shred)
                for p in ndir.glob("v*.meta.json"):
                    self._unlink_secure(p, shred=shred)
                with contextlib.suppress(Exception):
                    ndir.rmdir()
            else:
                self._unlink_secure(self._seal_path(name, version), shred=shred)
                self._unlink_secure(self._meta_path(name, version), shred=shred)
        finally:
            lock.release()

    @staticmethod
    def _unlink_secure(p: Path, *, shred: bool = False) -> None:
        if not p.exists():
            return
        if shred:
            try:
                size = p.stat().st_size
                with open(p, "r+b", buffering=0) as f:
                    f.write(b"\x00" * size)
                    f.flush()
                    os.fsync(f.fileno())
            except Exception:
                pass
        with contextlib.suppress(Exception):
            p.unlink(missing_ok=True)

    # ---------------- Rotation & backup ----------------
    def rotate_master_key(self, new_master_key_b64: str) -> None:
        """
        Re-encrypt all secrets with a new master key (in-place).
        """
        new_master_key = _load_master_key_b64(new_master_key_b64)
        new_key_id = _key_id(new_master_key)

        # For each secret/version: decrypt with old key, re-encrypt under same salt? No: use new salt & nonce.
        for name, versions in self.list().items():
            ndir = self._name_dir(name)
            lock = _FileLock(ndir)
            lock.acquire()
            try:
                for v in versions:
                    # Read old
                    seal_path = self._seal_path(name, v)
                    meta_path = self._meta_path(name, v)
                    meta = json.loads(meta_path.read_text(encoding="utf-8"))
                    blob = seal_path.read_bytes()
                    if len(blob) < 44:
                        raise IntegrityError(f"Corrupted seal: {seal_path}")
                    old_salt = blob[:32]
                    old_nonce = blob[32:44]
                    old_ct = blob[44:]
                    aad = f"{name}|{v}|{meta.get('created_at')}".encode("utf-8")
                    old_dk = _hkdf_derive(self.master_key, salt=old_salt, info=self.INFO_CONTEXT)
                    pt = AESGCM(old_dk).decrypt(old_nonce, old_ct, aad)

                    # New seal
                    new_salt = secrets.token_bytes(32)
                    new_nonce = secrets.token_bytes(12)
                    new_dk = _hkdf_derive(new_master_key, salt=new_salt, info=self.INFO_CONTEXT)
                    new_ct = AESGCM(new_dk).encrypt(new_nonce, pt, aad)
                    new_blob = new_salt + new_nonce + new_ct
                    _atomic_write_bytes(seal_path, new_blob, perms=0o600)

                    # Update key_id in metadata
                    meta["key_id"] = new_key_id
                    _atomic_write_json(meta_path, meta, perms=0o600)
            finally:
                lock.release()

        # Update storage meta
        meta = json.loads(self.meta_path.read_text(encoding="utf-8"))
        meta["key_id"] = new_key_id
        _atomic_write_json(self.meta_path, meta, perms=0o600)

        # Switch in-memory key
        self.master_key = new_master_key
        self.key_id = new_key_id

    def export_backup(self, dst: str | os.PathLike[str]) -> Path:
        """
        Create a tar.gz backup of the entire storage directory (metadata + seals).
        WARNING: backup contains encrypted data and metadata; protect it accordingly.
        """
        dst = Path(dst)
        dst.parent.mkdir(parents=True, exist_ok=True)
        # Use shutil.make_archive requires base name without extension
        base = dst.with_suffix("").as_posix()
        # Create temp copy to avoid races while archiving
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td) / "safe_storage_backup"
            shutil.copytree(self.root, tmp_root, dirs_exist_ok=True)
            # Create archive
            archive = shutil.make_archive(base, "gztar", root_dir=tmp_root.parent, base_dir=tmp_root.name)
        return Path(archive)

    def import_backup(self, src: str | os.PathLike[str]) -> None:
        """
        Extract a previously created tar.gz backup into the storage root (overwrites existing files).
        """
        src = Path(src)
        if not src.exists():
            raise SafeStorageError(f"Backup not found: {src}")
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            shutil.unpack_archive(src, tmp)
            # Find extracted root (expect one directory)
            roots = [p for p in tmp.iterdir() if p.is_dir()]
            if not roots:
                raise SafeStorageError("Backup archive content invalid")
            # Merge into current root
            shutil.copytree(roots[0], self.root, dirs_exist_ok=True)

    # ---------------- Utilities ----------------
    def info(self) -> Dict[str, Any]:
        """
        Return storage metadata and counts.
        """
        meta = {}
        if self.meta_path.exists():
            with contextlib.suppress(Exception):
                meta = json.loads(self.meta_path.read_text(encoding="utf-8"))
        listing = self.list()
        total_versions = sum(len(vs) for vs in listing.values())
        return {
            "root": str(self.root),
            "meta": meta,
            "secrets_count": len(listing),
            "versions_count": total_versions,
            "key_id": self.key_id,
            "format_version": self.FORMAT_VERSION,
        }


# =============================================================================
# CLI demo (optional)
# =============================================================================
if __name__ == "__main__":
    # Minimal smoke test:
    # export SAFE_STORAGE_MASTER_KEY=$(python -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())")
    root = Path(os.environ.get("SAFE_STORAGE_ROOT", "./.safe_store"))
    store = SafeStorage(root, master_key_b64=os.environ.get("SAFE_STORAGE_MASTER_KEY"))
    ver = store.set("example", "s3cr3t", tags={"env": "dev"})
    print("stored:", ver)
    print("read:", store.get("example", encoding="utf-8"))
    print("info:", store.info())
