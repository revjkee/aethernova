# policy_core/pap/versioning.py
# Industrial-grade async policy versioning module (PAP side).
# Features:
# - Strict SemVer (no external deps)
# - Content-addressed storage (SHA-256), dedup
# - HMAC-SHA256 manifest signing (optional)
# - Optimistic concurrency via monotonically increasing revisions
# - Per-policy async locks
# - Diff summary and rollback
# - Status lifecycle and labels/tags
# - Abstract async storage + in-memory and file-backed implementations
# - Detailed logging and typing
from __future__ import annotations

import asyncio
import base64
import dataclasses
import datetime as dt
import difflib
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import re
import secrets
from typing import (
    Any,
    AsyncIterator,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Tuple,
)

LOGGER = logging.getLogger(__name__)
if not LOGGER.handlers:
    # Default safe logger setup (library-friendly)
    handler = logging.StreamHandler()
    fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | policy.versioning | %(message)s"
    )
    handler.setFormatter(fmt)
    LOGGER.addHandler(handler)
LOGGER.setLevel(logging.INFO)


# ----------------------------- Exceptions -----------------------------


class PolicyVersionError(Exception):
    """Base class for policy versioning errors."""


class PolicyNotFound(PolicyVersionError):
    """Requested policy or version does not exist."""


class VersionConflict(PolicyVersionError):
    """Optimistic concurrency conflict or invalid bump/base."""


class IntegrityError(PolicyVersionError):
    """Content integrity or signature verification failed."""


class InvalidVersion(PolicyVersionError):
    """Malformed or unsupported version string."""


class StoreError(PolicyVersionError):
    """Underlying storage layer error."""


# ----------------------------- SemVer -----------------------------


_SEMVER_RE = re.compile(
    r"^(?P<maj>0|[1-9]\d*)\.(?P<min>0|[1-9]\d*)\.(?P<pat>0|[1-9]\d*)"
    r"(?:-(?P<pre>[0-9A-Za-z.-]+))?"
    r"(?:\+(?P<bld>[0-9A-Za-z.-]+))?$"
)


@dataclasses.dataclass(frozen=True, order=False)
class SemVer:
    major: int
    minor: int
    patch: int
    prerelease: Optional[str] = None
    build: Optional[str] = None

    @staticmethod
    def parse(s: str) -> "SemVer":
        m = _SEMVER_RE.match(s)
        if not m:
            raise InvalidVersion(f"Invalid semver: {s}")
        return SemVer(
            int(m.group("maj")),
            int(m.group("min")),
            int(m.group("pat")),
            m.group("pre"),
            m.group("bld"),
        )

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            base += f"-{self.prerelease}"
        if self.build:
            base += f"+{self.build}"
        return base

    def _cmp_tuple(self) -> Tuple[int, int, int, Tuple[Any, ...]]:
        # SemVer compare: prerelease < none
        pre_key: Tuple[Any, ...]
        if self.prerelease is None:
            pre_key = (1,)  # no prerelease sorts after prereleases
        else:
            parts = self.prerelease.split(".")
            norm: List[Any] = []
            for p in parts:
                if p.isdigit():
                    norm.append((0, int(p)))
                else:
                    norm.append((1, p))
            pre_key = (0, *norm)
        return self.major, self.minor, self.patch, pre_key

    def __lt__(self, other: "SemVer") -> bool:
        return self._cmp_tuple() < other._cmp_tuple()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SemVer):
            return False
        return self._cmp_tuple() == other._cmp_tuple()

    def bump(self, kind: str) -> "SemVer":
        k = kind.lower()
        if k == "major":
            return SemVer(self.major + 1, 0, 0)
        if k == "minor":
            return SemVer(self.major, self.minor + 1, 0)
        if k == "patch":
            return SemVer(self.major, self.minor, self.patch + 1)
        raise VersionConflict(f"Unknown bump kind: {kind}")


# ----------------------------- Models -----------------------------


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _ensure_bytes(content: str | bytes) -> bytes:
    return content.encode("utf-8") if isinstance(content, str) else content


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_newlines(b: bytes) -> bytes:
    # Normalize to LF for deterministic hashing/diffing.
    s = b.decode("utf-8", errors="replace")
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    return s.encode("utf-8")


@dataclasses.dataclass(frozen=True)
class PolicyDescriptor:
    policy_id: str
    namespace: Optional[str] = None


@dataclasses.dataclass(frozen=True)
class PolicyContent:
    sha256: str
    size: int
    content_type: str = "text/plain"

    @staticmethod
    def from_bytes(b: bytes, content_type: str = "text/plain") -> "PolicyContent":
        nb = normalize_newlines(b)
        return PolicyContent(
            sha256=sha256_hex(nb),
            size=len(nb),
            content_type=content_type,
        )


@dataclasses.dataclass(frozen=True)
class DiffSummary:
    lines_added: int
    lines_removed: int

    @staticmethod
    def compute(old: bytes, new: bytes) -> "DiffSummary":
        old_lines = old.decode("utf-8", errors="replace").splitlines()
        new_lines = new.decode("utf-8", errors="replace").splitlines()
        diff = difflib.ndiff(old_lines, new_lines)
        added = sum(1 for d in diff if d.startswith("+ "))
        # recompute for removed (need second pass)
        diff2 = difflib.ndiff(old_lines, new_lines)
        removed = sum(1 for d in diff2 if d.startswith("- "))
        return DiffSummary(lines_added=added, lines_removed=removed)


@dataclasses.dataclass(frozen=True)
class PolicyManifest:
    policy_id: str
    namespace: Optional[str]
    version: str
    created_at: str  # ISO 8601 UTC
    created_by: str
    message: str
    parent_version: Optional[str]
    status: str  # active|deprecated|revoked|draft
    labels: Mapping[str, str]
    content_sha256: str
    content_size: int
    content_type: str
    diff: DiffSummary
    signature: Optional[str] = None  # base64 HMAC or None
    storage_uri: Optional[str] = None  # where content resides (optional)
    revision: Optional[int] = None  # set by store

    def to_json(self, include_signature: bool = True) -> str:
        d = dataclasses.asdict(self)
        if not include_signature:
            d["signature"] = None
        return json.dumps(d, ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def from_json(s: str) -> "PolicyManifest":
        d = json.loads(s)
        d["diff"] = DiffSummary(**d["diff"])
        return PolicyManifest(**d)


# ----------------------------- Signing -----------------------------


class ManifestSigner(Protocol):
    def sign(self, manifest: PolicyManifest) -> str: ...
    def verify(self, manifest: PolicyManifest) -> bool: ...


class HMACSigner:
    """
    Simple HMAC-SHA256 signer. Keep the secret safe (e.g., KMS).
    """

    def __init__(self, secret: bytes):
        if not secret:
            raise ValueError("HMAC secret must be non-empty")
        self._secret = secret

    def _payload(self, manifest: PolicyManifest) -> bytes:
        # Exclude signature field
        data = manifest.to_json(include_signature=False).encode("utf-8")
        return data

    def sign(self, manifest: PolicyManifest) -> str:
        mac = hmac.new(self._secret, self._payload(manifest), hashlib.sha256).digest()
        return base64.b64encode(mac).decode("ascii")

    def verify(self, manifest: PolicyManifest) -> bool:
        if manifest.signature is None:
            return False
        try:
            sig = base64.b64decode(manifest.signature.encode("ascii"))
        except Exception:
            return False
        mac = hmac.new(self._secret, self._payload(manifest), hashlib.sha256).digest()
        return hmac.compare_digest(sig, mac)


# ----------------------------- Storage Interface -----------------------------


class AsyncVersionStore(Protocol):
    """
    Abstract async storage interface for policy versions and content.
    Implementations must be safe under concurrent use and use revisions for optimistic locking.
    """

    async def get_latest_manifest(self, policy_id: str) -> PolicyManifest | None: ...
    async def get_manifest(self, policy_id: str, version: str) -> PolicyManifest | None: ...
    async def list_manifests(
        self, policy_id: str, limit: int = 50, cursor: Optional[str] = None
    ) -> Tuple[List[PolicyManifest], Optional[str]]: ...
    async def put_version(
        self,
        manifest: PolicyManifest,
        content: bytes,
        expected_parent_version: Optional[str],
    ) -> PolicyManifest: ...
    async def get_content(self, content_sha256: str) -> bytes | None: ...
    async def has_content(self, content_sha256: str) -> bool: ...


# ----------------------------- In-Memory Store -----------------------------


class InMemoryVersionStore(AsyncVersionStore):
    """
    For testing and small deployments. Not persistent across process restarts.
    """

    def __init__(self) -> None:
        # policy_id -> version -> manifest
        self._manifests: Dict[str, Dict[str, PolicyManifest]] = {}
        # sha -> bytes
        self._content: Dict[str, bytes] = {}
        # policy_id -> latest SemVer
        self._latest: Dict[str, SemVer] = {}
        # policy_id -> int revision counter
        self._revisions: Dict[str, int] = {}
        self._lock = asyncio.Lock()

    async def get_latest_manifest(self, policy_id: str) -> PolicyManifest | None:
        async with self._lock:
            versions = self._manifests.get(policy_id)
            if not versions:
                return None
            # find max semver
            best: Tuple[SemVer, PolicyManifest] | None = None
            for v_str, man in versions.items():
                v = SemVer.parse(v_str)
                if best is None or best[0] < v:
                    best = (v, man)
            return best[1] if best else None

    async def get_manifest(self, policy_id: str, version: str) -> PolicyManifest | None:
        async with self._lock:
            return self._manifests.get(policy_id, {}).get(version)

    async def list_manifests(
        self, policy_id: str, limit: int = 50, cursor: Optional[str] = None
    ) -> Tuple[List[PolicyManifest], Optional[str]]:
        async with self._lock:
            versions = list(self._manifests.get(policy_id, {}).values())
            versions.sort(key=lambda m: SemVer.parse(m.version))
            start = int(cursor) if cursor is not None else 0
            end = min(start + limit, len(versions))
            next_cursor = str(end) if end < len(versions) else None
            return versions[start:end], next_cursor

    async def put_version(
        self,
        manifest: PolicyManifest,
        content: bytes,
        expected_parent_version: Optional[str],
    ) -> PolicyManifest:
        async with self._lock:
            current_latest = self._latest.get(manifest.policy_id)
            if expected_parent_version is None:
                if current_latest is not None:
                    raise VersionConflict(
                        "Initial version exists; expected no parent but latest is present"
                    )
            else:
                # must match latest
                if current_latest is None:
                    raise VersionConflict("No existing versions; parent provided unexpectedly")
                if str(current_latest) != expected_parent_version:
                    raise VersionConflict(
                        f"Parent version mismatch (expected {expected_parent_version}, "
                        f"latest is {current_latest})"
                    )

            # store content if missing
            if manifest.content_sha256 not in self._content:
                self._content[manifest.content_sha256] = content

            # increment revision
            rev = self._revisions.get(manifest.policy_id, 0) + 1
            self._revisions[manifest.policy_id] = rev

            # persist manifest
            by_ver = self._manifests.setdefault(manifest.policy_id, {})
            if manifest.version in by_ver:
                raise VersionConflict("Version already exists")

            stored = dataclasses.replace(manifest, revision=rev)
            by_ver[manifest.version] = stored

            # bump latest
            v = SemVer.parse(manifest.version)
            self._latest[manifest.policy_id] = v if current_latest is None or current_latest < v else current_latest
            return stored

    async def get_content(self, content_sha256: str) -> bytes | None:
        async with self._lock:
            return self._content.get(content_sha256)

    async def has_content(self, content_sha256: str) -> bool:
        async with self._lock:
            return content_sha256 in self._content


# ----------------------------- File Store -----------------------------


class FileVersionStore(AsyncVersionStore):
    """
    Simple file-backed store. Thread-safe via a global async lock; suitable for single-node.
    Layout:
      root/
        manifests/{policy_id}/{version}.json
        content/{sha256}
      indexes/latest/{policy_id}.txt
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.manifests_dir = self.root / "manifests"
        self.content_dir = self.root / "content"
        self.latest_dir = self.root / "indexes" / "latest"
        self._lock = asyncio.Lock()
        for p in (self.manifests_dir, self.content_dir, self.latest_dir):
            p.mkdir(parents=True, exist_ok=True)

    async def get_latest_manifest(self, policy_id: str) -> PolicyManifest | None:
        async with self._lock:
            latest_file = self.latest_dir / f"{policy_id}.txt"
            if not latest_file.exists():
                return None
            version = (await asyncio.to_thread(latest_file.read_text, encoding="utf-8")).strip()
            return await self.get_manifest(policy_id, version)

    async def get_manifest(self, policy_id: str, version: str) -> PolicyManifest | None:
        async with self._lock:
            f = self.manifests_dir / policy_id / f"{version}.json"
            if not f.exists():
                return None
            data = await asyncio.to_thread(f.read_text, encoding="utf-8")
            return PolicyManifest.from_json(data)

    async def list_manifests(
        self, policy_id: str, limit: int = 50, cursor: Optional[str] = None
    ) -> Tuple[List[PolicyManifest], Optional[str]]:
        async with self._lock:
            dirp = self.manifests_dir / policy_id
            if not dirp.exists():
                return [], None
            files = [p for p in dirp.iterdir() if p.suffix == ".json"]
            # sort by semver
            def ver_of(path: Path) -> SemVer:
                return SemVer.parse(path.stem)

            files.sort(key=ver_of)
            start = int(cursor) if cursor is not None else 0
            end = min(start + limit, len(files))
            selected = files[start:end]
            mans: List[PolicyManifest] = []
            for p in selected:
                data = await asyncio.to_thread(p.read_text, encoding="utf-8")
                mans.append(PolicyManifest.from_json(data))
            next_cursor = str(end) if end < len(files) else None
            return mans, next_cursor

    async def put_version(
        self,
        manifest: PolicyManifest,
        content: bytes,
        expected_parent_version: Optional[str],
    ) -> PolicyManifest:
        async with self._lock:
            # read current latest
            latest_file = self.latest_dir / f"{manifest.policy_id}.txt"
            current_latest: Optional[str] = None
            if latest_file.exists():
                current_latest = (await asyncio.to_thread(latest_file.read_text, encoding="utf-8")).strip()

            if expected_parent_version is None:
                if current_latest is not None:
                    raise VersionConflict(
                        "Initial version exists; expected no parent but latest is present"
                    )
            else:
                if current_latest is None:
                    raise VersionConflict("No existing versions; parent provided unexpectedly")
                if current_latest != expected_parent_version:
                    raise VersionConflict(
                        f"Parent version mismatch (expected {expected_parent_version}, latest is {current_latest})"
                    )

            # store content if missing
            cfile = self.content_dir / manifest.content_sha256
            if not cfile.exists():
                await asyncio.to_thread(cfile.write_bytes, content)

            # write manifest
            mdir = self.manifests_dir / manifest.policy_id
            mdir.mkdir(parents=True, exist_ok=True)
            mfile = mdir / f"{manifest.version}.json"
            if mfile.exists():
                raise VersionConflict("Version already exists")

            # read & update a monotonic revision
            rev_index = self.root / "indexes" / "revisions" / f"{manifest.policy_id}.txt"
            rev_index.parent.mkdir(parents=True, exist_ok=True)
            if rev_index.exists():
                try:
                    rev = int((await asyncio.to_thread(rev_index.read_text, encoding="utf-8")).strip())
                except Exception:
                    rev = 0
            else:
                rev = 0
            rev += 1
            await asyncio.to_thread(rev_index.write_text, str(rev), "utf-8")

            stored = dataclasses.replace(manifest, revision=rev)
            await asyncio.to_thread(mfile.write_text, stored.to_json(), "utf-8")

            # update latest (compare semver)
            if current_latest is None or SemVer.parse(current_latest) < SemVer.parse(manifest.version):
                await asyncio.to_thread(latest_file.write_text, manifest.version, "utf-8")

            return stored

    async def get_content(self, content_sha256: str) -> bytes | None:
        async with self._lock:
            f = self.content_dir / content_sha256
            if not f.exists():
                return None
            return await asyncio.to_thread(f.read_bytes)

    async def has_content(self, content_sha256: str) -> bool:
        async with self._lock:
            return (self.content_dir / content_sha256).exists()


# ----------------------------- Locks -----------------------------


class _PolicyLockManager:
    def __init__(self) -> None:
        self._locks: Dict[str, asyncio.Lock] = {}
        self._global = asyncio.Lock()

    async def acquire(self, policy_id: str) -> asyncio.Lock:
        async with self._global:
            lock = self._locks.get(policy_id)
            if lock is None:
                lock = asyncio.Lock()
                self._locks[policy_id] = lock
            return lock


# ----------------------------- Service -----------------------------


class PolicyVersioningService:
    """
    High-level versioning service orchestrating storage, signing, integrity and diffs.
    """

    def __init__(
        self,
        store: AsyncVersionStore,
        signer: Optional[ManifestSigner] = None,
        default_status: str = "active",
    ) -> None:
        self._store = store
        self._signer = signer
        self._locks = _PolicyLockManager()
        self._default_status = default_status

    async def get_latest(self, policy_id: str) -> PolicyManifest:
        m = await self._store.get_latest_manifest(policy_id)
        if m is None:
            raise PolicyNotFound(f"No versions for policy {policy_id}")
        return m

    async def get(self, policy_id: str, version: str) -> PolicyManifest:
        m = await self._store.get_manifest(policy_id, version)
        if m is None:
            raise PolicyNotFound(f"Policy {policy_id} version {version} not found")
        return m

    async def list(
        self, policy_id: str, limit: int = 50, cursor: Optional[str] = None
    ) -> Tuple[List[PolicyManifest], Optional[str]]:
        return await self._store.list_manifests(policy_id, limit=limit, cursor=cursor)

    async def diff(self, policy_id: str, v_old: str, v_new: str) -> str:
        old_m = await self.get(policy_id, v_old)
        new_m = await self.get(policy_id, v_new)
        old_b = await self._get_content_or_fail(old_m.content_sha256)
        new_b = await self._get_content_or_fail(new_m.content_sha256)
        old_lines = old_b.decode("utf-8", errors="replace").splitlines(keepends=True)
        new_lines = new_b.decode("utf-8", errors="replace").splitlines(keepends=True)
        diff = difflib.unified_diff(
            old_lines, new_lines, fromfile=v_old, tofile=v_new, lineterm=""
        )
        return "".join(diff)

    async def rollback(
        self,
        policy_id: str,
        target_version: str,
        *,
        created_by: str,
        message: str = "Rollback",
        status: Optional[str] = None,
        labels: Optional[Mapping[str, str]] = None,
        bump: str = "patch",
        content_type: str = "text/plain",
    ) -> PolicyManifest:
        """
        Rollback by recommitting the content of target_version as a new version.
        """
        target_m = await self.get(policy_id, target_version)
        content = await self._get_content_or_fail(target_m.content_sha256)
        return await self.commit(
            policy_id=policy_id,
            content=content,
            created_by=created_by,
            message=message,
            status=status or self._default_status,
            labels=labels or {},
            bump=bump,
            content_type=content_type,
        )

    async def commit(
        self,
        *,
        policy_id: str,
        content: str | bytes,
        created_by: str,
        message: str,
        status: Optional[str] = None,
        labels: Optional[Mapping[str, str]] = None,
        bump: Optional[str] = None,  # major|minor|patch; default patch (or 1.0.0 if first)
        content_type: str = "text/plain",
    ) -> PolicyManifest:
        """
        Create a new version. If this is the first version, it's 1.0.0.
        If content hasn't changed (by SHA-256), returns the existing latest manifest (idempotent).
        """
        lock = await self._locks.acquire(policy_id)
        async with lock:
            nb = normalize_newlines(_ensure_bytes(content))
            pc = PolicyContent.from_bytes(nb, content_type=content_type)

            latest = await self._store.get_latest_manifest(policy_id)
            if latest is not None:
                # Idempotent short-circuit
                if latest.content_sha256 == pc.sha256:
                    LOGGER.info("No-op commit for %s: identical content", policy_id)
                    return latest
                base = SemVer.parse(latest.version)
                new_ver = base.bump(bump or "patch")
                parent = str(base)
            else:
                new_ver = SemVer.parse("1.0.0")
                parent = None

            diff_summary = await self._diff_summary(latest, nb)

            manifest = PolicyManifest(
                policy_id=policy_id,
                namespace=None,
                version=str(new_ver),
                created_at=utcnow().isoformat(),
                created_by=created_by,
                message=message,
                parent_version=parent,
                status=(status or self._default_status),
                labels=dict(labels or {}),
                content_sha256=pc.sha256,
                content_size=pc.size,
                content_type=pc.content_type,
                diff=diff_summary,
                signature=None,
                storage_uri=None,
                revision=None,
            )

            if self._signer is not None:
                signature = self._signer.sign(manifest)
                manifest = dataclasses.replace(manifest, signature=signature)

            stored = await self._store.put_version(
                manifest=manifest,
                content=nb,
                expected_parent_version=parent,
            )

            # Verify integrity and signature post-write
            await self._verify_manifest_integrity(stored)
            return stored

    async def verify(self, policy_id: str, version: str) -> bool:
        m = await self.get(policy_id, version)
        await self._verify_manifest_integrity(m)
        return True

    # --------------------- internal helpers ---------------------

    async def _diff_summary(
        self, latest: Optional[PolicyManifest], new_bytes: bytes
    ) -> DiffSummary:
        if latest is None:
            return DiffSummary(lines_added=new_bytes.decode("utf-8", errors="replace").count("\n") + 1, lines_removed=0)
        old = await self._get_content_or_fail(latest.content_sha256)
        return DiffSummary.compute(old, new_bytes)

    async def _get_content_or_fail(self, sha: str) -> bytes:
        b = await self._store.get_content(sha)
        if b is None:
            raise IntegrityError(f"Missing content {sha}")
        # verify hash matches
        if sha256_hex(normalize_newlines(b)) != sha:
            raise IntegrityError("Content hash mismatch")
        return normalize_newlines(b)

    async def _verify_manifest_integrity(self, m: PolicyManifest) -> None:
        # Check content exists and matches hash
        await self._get_content_or_fail(m.content_sha256)
        # Verify signature if present
        if m.signature is not None and self._signer is not None:
            if not self._signer.verify(m):
                raise IntegrityError("Manifest signature verification failed")


# ----------------------------- Utilities -----------------------------


def generate_hmac_secret(length: int = 32) -> bytes:
    return secrets.token_bytes(length)


# ----------------------------- __all__ -----------------------------

__all__ = [
    # Exceptions
    "PolicyVersionError",
    "PolicyNotFound",
    "VersionConflict",
    "IntegrityError",
    "InvalidVersion",
    "StoreError",
    # Models
    "SemVer",
    "PolicyDescriptor",
    "PolicyContent",
    "DiffSummary",
    "PolicyManifest",
    # Signing
    "ManifestSigner",
    "HMACSigner",
    # Store
    "AsyncVersionStore",
    "InMemoryVersionStore",
    "FileVersionStore",
    # Service
    "PolicyVersioningService",
    # Utils
    "generate_hmac_secret",
]
