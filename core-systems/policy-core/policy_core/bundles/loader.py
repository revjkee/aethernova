# policy_core/bundles/loader.py
# Industrial-grade Policy Bundle Loader for policy_core
# License: Apache-2.0 (adjust per project policy)
from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
import fnmatch
import io
import json
import logging
import os
import pathlib
import tarfile
import time
import zipfile
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any,
    AsyncGenerator,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

try:
    import yaml  # type: ignore
    _HAS_YAML = True
except Exception:
    yaml = None
    _HAS_YAML = False

# Local imports from policy_core
from ..context import (
    Policy,
    PolicyMetadata,
    PolicyRef,
    SecurityLabel,
)

# Optional OpenTelemetry
try:
    from opentelemetry import trace  # type: ignore
    _otel_tracer = trace.get_tracer("policy_core.bundles")
except Exception:
    _otel_tracer = None

__all__ = [
    "BundleSourceType",
    "BundleLoaderConfig",
    "BundleIndex",
    "BundleLoader",
    "BundlePolicyStore",
    "SignatureVerifier",
]

log = logging.getLogger("policy_core.bundles")


# -----------------------------
# Enums and config
# -----------------------------
class BundleSourceType(str, Enum):
    DIRECTORY = "directory"
    TARBALL = "tarball"       # .tar.gz or .tgz or .tar
    ZIP = "zip"               # .zip
    AUTO = "auto"             # detect by path
    # Remote schemes could be added by custom readers (http, s3, etc.)


@dataclass(frozen=True)
class BundleLoaderConfig:
    source_uri: str
    source_type: BundleSourceType = BundleSourceType.AUTO
    include_globs: Tuple[str, ...] = ("**/*.json", "**/*.yaml", "**/*.yml", "**/*.rego", "**/*.cel")
    exclude_globs: Tuple[str, ...] = ("**/.git/**", "**/__pycache__/**", "**/*.pyc", "**/.DS_Store")
    verify_signatures: bool = False
    strict_manifest: bool = False
    default_kind: str = "json"  # when kind cannot be inferred
    tenant_id: Optional[str] = None
    polling_interval_s: float = 0.0        # 0 disables polling
    max_file_bytes: int = 4 * 1024 * 1024  # 4 MiB per file
    max_files: int = 5000
    _etag_salt: str = field(default="policy_core_bundle", repr=False)


# -----------------------------
# Bundle readers (in-memory listing of files)
# -----------------------------
@dataclass(frozen=True)
class FileEntry:
    path: str              # normalized POSIX-like path inside bundle
    bytes: bytes
    mtime: float


class BundleReader(ABC):
    @abstractmethod
    async def read_all(self) -> List[FileEntry]:
        ...


class FSDirectoryReader(BundleReader):
    def __init__(self, root: pathlib.Path):
        self._root = root

    async def read_all(self) -> List[FileEntry]:
        entries: List[FileEntry] = []
        root = self._root
        for dirpath, _, filenames in os.walk(root):
            for name in filenames:
                fpath = pathlib.Path(dirpath) / name
                try:
                    rel = fpath.relative_to(root).as_posix()
                except Exception:
                    rel = name
                try:
                    stat = fpath.stat()
                    if stat.st_size < 0:
                        continue
                    with open(fpath, "rb") as fh:
                        data = fh.read()
                    entries.append(FileEntry(path=rel, bytes=data, mtime=stat.st_mtime))
                except Exception as e:
                    log.warning("Skip file on read error: %s (%s)", fpath, e)
        return entries


class TarballReader(BundleReader):
    def __init__(self, tar_path: pathlib.Path):
        self._tar_path = tar_path

    async def read_all(self) -> List[FileEntry]:
        res: List[FileEntry] = []
        mode = "r"
        # auto detect compression
        p = str(self._tar_path)
        if p.endswith(".tar.gz") or p.endswith(".tgz"):
            mode = "r:gz"
        elif p.endswith(".tar.bz2") or p.endswith(".tbz"):
            mode = "r:bz2"
        elif p.endswith(".tar.xz") or p.endswith(".txz"):
            mode = "r:xz"
        with tarfile.open(p, mode) as tf:
            for m in tf.getmembers():
                if not m.isfile():
                    continue
                # normalize path
                rel = pathlib.PurePosixPath(m.name).as_posix()
                try:
                    f = tf.extractfile(m)
                    if not f:
                        continue
                    data = f.read()
                    res.append(FileEntry(path=rel, bytes=data, mtime=float(m.mtime or 0)))
                except Exception as e:
                    log.warning("Skip tar member on read error: %s (%s)", m.name, e)
        return res


class ZipReader(BundleReader):
    def __init__(self, zip_path: pathlib.Path):
        self._zip_path = zip_path

    async def read_all(self) -> List[FileEntry]:
        res: List[FileEntry] = []
        with zipfile.ZipFile(self._zip_path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                rel = pathlib.PurePosixPath(info.filename).as_posix()
                try:
                    with zf.open(info, "r") as fh:
                        data = fh.read()
                    # ZipInfo.date_time is a tuple; convert to epoch best-effort
                    mtime = time.mktime((*info.date_time, 0, 0, -1))
                except Exception as e:
                    log.warning("Skip zip member on read error: %s (%s)", rel, e)
                    continue
                res.append(FileEntry(path=rel, bytes=data, mtime=mtime))
        return res


def _detect_source_type(path: pathlib.Path) -> BundleSourceType:
    p = str(path).lower()
    if path.is_dir():
        return BundleSourceType.DIRECTORY
    if p.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tar.xz", ".txz", ".tar")):
        return BundleSourceType.TARBALL
    if p.endswith(".zip"):
        return BundleSourceType.ZIP
    return BundleSourceType.DIRECTORY


# -----------------------------
# Signature verification (pluggable)
# -----------------------------
class SignatureVerifier(ABC):
    @abstractmethod
    def verify(self, file_path: str, data: bytes, signature: Optional[bytes]) -> bool:
        """
        Return True if signature is valid. If signature is None and verification is required,
        return False. Implementations can locate keys by file_path or external metadata.
        """
        ...


class NoopSignatureVerifier(SignatureVerifier):
    def verify(self, file_path: str, data: bytes, signature: Optional[bytes]) -> bool:
        return signature is None  # no signature expected; treat as valid in noop mode


# -----------------------------
# Parsing registry
# -----------------------------
class PolicyParserRegistry:
    def __init__(self):
        self._by_ext: Dict[str, Callable[[str, bytes], Tuple[str, Mapping[str, Any]]]] = {}
        self.register(".json", self._parse_json)
        if _HAS_YAML:
            self.register(".yaml", self._parse_yaml)
            self.register(".yml", self._parse_yaml)
        self.register(".rego", self._parse_rego)
        self.register(".cel", self._parse_cel)

    def register(self, ext: str, parser: Callable[[str, bytes], Tuple[str, Mapping[str, Any]]]) -> None:
        self._by_ext[ext.lower()] = parser

    def parse(self, path: str, data: bytes, default_kind: str) -> Tuple[str, Mapping[str, Any]]:
        ext = os.path.splitext(path)[1].lower()
        parser = self._by_ext.get(ext)
        if parser:
            return parser(path, data)
        # fallback: treat as JSON if looks like JSON
        try:
            obj = json.loads(data.decode("utf-8"))
            return "json", obj
        except Exception:
            # raw text policy as default kind
            return default_kind, {"raw": data.decode("utf-8", errors="replace")}

    # ---- concrete parsers ----
    def _parse_json(self, path: str, data: bytes) -> Tuple[str, Mapping[str, Any]]:
        obj = json.loads(data.decode("utf-8"))
        return "json", obj

    def _parse_yaml(self, path: str, data: bytes) -> Tuple[str, Mapping[str, Any]]:
        assert yaml is not None
        obj = yaml.safe_load(data.decode("utf-8"))
        if obj is None:
            obj = {}
        return "yaml", obj

    def _parse_rego(self, path: str, data: bytes) -> Tuple[str, Mapping[str, Any]]:
        return "rego", {"rego": data.decode("utf-8", errors="replace")}

    def _parse_cel(self, path: str, data: bytes) -> Tuple[str, Mapping[str, Any]]:
        return "cel", {"cel": data.decode("utf-8", errors="replace")}


# -----------------------------
# Bundle index
# -----------------------------
@dataclass(frozen=True)
class BundleIndex:
    revision: str
    etag: str
    policies: Tuple[Policy, ...]
    by_id: Mapping[str, Policy] = field(default_factory=dict)

    @staticmethod
    def build(revision: str, policies: List[Policy], etag_seed: str) -> "BundleIndex":
        by_id: Dict[str, Policy] = {}
        digest = hashlib.sha256()
        digest.update(etag_seed.encode("utf-8"))
        digest.update(revision.encode("utf-8"))
        # stable ordering by (tenant_id, policy_id, version)
        for p in sorted(policies, key=lambda P: (P.metadata.tenant_id or "", P.metadata.policy_id, P.metadata.version)):
            by_id[p.metadata.policy_id] = p
            digest.update(p.metadata.policy_id.encode("utf-8"))
            digest.update(p.metadata.version.encode("utf-8"))
            digest.update((p.metadata.kind or "").encode("utf-8"))
        return BundleIndex(
            revision=revision,
            etag=digest.hexdigest(),
            policies=tuple(policies),
            by_id=by_id,
        )


# -----------------------------
# Loader
# -----------------------------
class BundleLoader:
    """
    Loads policies from a bundle source (directory, tarball, zip).
    Supports OPA-style bundles (/.manifest) and generic JSON/YAML/Rego/CEL files.

    File formats:
      - JSON/YAML:
        {
          "metadata": { "policy_id": "...", "version": "...", "kind": "...", "tenant_id": "...", "tags": ["..."], "security_label": "internal" },
          "spec": { ... }  # engine-specific
        }
      - Rego/CEL: stored as {"rego": "..."} or {"cel": "..."} with inferred kind.
    """

    def __init__(
        self,
        config: BundleLoaderConfig,
        *,
        signature_verifier: Optional[SignatureVerifier] = None,
        parser_registry: Optional[PolicyParserRegistry] = None,
    ):
        self._cfg = config
        self._verifier = signature_verifier or NoopSignatureVerifier()
        self._parsers = parser_registry or PolicyParserRegistry()
        self._index: Optional[BundleIndex] = None
        self._lock = asyncio.Lock()

    # ---------- public API ----------
    async def load_once(self) -> BundleIndex:
        """
        Loads and indexes the bundle once and replaces the current index.
        """
        entries = await self._reader().read_all()
        filtered = self._filter_entries(entries)
        manifest = _extract_manifest(filtered)
        revision = manifest.get("revision", _auto_revision(filtered))
        policies = self._parse_policies(filtered, revision, manifest)
        index = BundleIndex.build(revision=revision, policies=policies, etag_seed=self._cfg._etag_salt)
        async with self._lock:
            self._index = index
        log.info("Bundle loaded: %d policies, revision=%s etag=%s", len(policies), index.revision, index.etag)
        return index

    async def stream_updates(self) -> AsyncGenerator[BundleIndex, None]:
        """
        Polling-based async generator producing updates when the underlying source changes.
        Disabled if polling_interval_s == 0.
        """
        if self._cfg.polling_interval_s <= 0:
            # Single-shot behavior: yield current (load_once) and exit
            yield await self.load_once()
            return

        prev_etag: Optional[str] = None
        while True:
            try:
                idx = await self.load_once()
                if idx.etag != prev_etag:
                    prev_etag = idx.etag
                    yield idx
            except Exception as e:
                log.exception("Bundle polling iteration error: %s", e)
            await asyncio.sleep(self._cfg.polling_interval_s)

    def current_index(self) -> Optional[BundleIndex]:
        return self._index

    # ---------- internals ----------
    def _reader(self) -> BundleReader:
        uri = self._cfg.source_uri
        path = pathlib.Path(uri)
        st = self._cfg.source_type if self._cfg.source_type != BundleSourceType.AUTO else _detect_source_type(path)
        if st == BundleSourceType.DIRECTORY:
            return FSDirectoryReader(path)
        if st == BundleSourceType.TARBALL:
            return TarballReader(path)
        if st == BundleSourceType.ZIP:
            return ZipReader(path)
        # default: directory
        return FSDirectoryReader(path)

    def _filter_entries(self, entries: List[FileEntry]) -> List[FileEntry]:
        inc = self._cfg.include_globs
        exc = self._cfg.exclude_globs
        out: List[FileEntry] = []
        count = 0
        for e in entries:
            # limit size and file count
            if len(e.bytes) > self._cfg.max_file_bytes:
                log.warning("Skip oversize file: %s (%d bytes)", e.path, len(e.bytes))
                continue
            # exclude
            if any(fnmatch.fnmatch(e.path, g) for g in exc):
                continue
            # include (manifest files always included)
            if e.path.endswith("/.manifest") or e.path.endswith(".manifest") or e.path.endswith("manifest.json"):
                out.append(e)
                continue
            if any(fnmatch.fnmatch(e.path, g) for g in inc):
                out.append(e)
            count += 1
            if count > self._cfg.max_files:
                log.warning("Reached max_files=%d, remaining entries will be ignored", self._cfg.max_files)
                break
        return out

    def _parse_policies(self, entries: List[FileEntry], revision: str, manifest: Mapping[str, Any]) -> List[Policy]:
        roots = manifest.get("roots") or []
        root_prefixes = tuple(pathlib.PurePosixPath(r).as_posix().rstrip("/") + "/" for r in roots if isinstance(r, str))
        strict = self._cfg.strict_manifest and len(root_prefixes) > 0

        sig_map = _extract_signatures(entries)
        policies: List[Policy] = []
        now = dt.datetime.now(dt.timezone.utc)

        for e in entries:
            # skip manifest/signatures
            if _is_meta_file(e.path):
                continue
            # if manifest has roots, enforce them when strict
            if strict and not _under_roots(e.path, root_prefixes):
                continue

            kind, obj = self._parsers.parse(e.path, e.bytes, self._cfg.default_kind)

            # signature verify (if configured and signature mapping present)
            if self._cfg.verify_signatures:
                sig = sig_map.get(e.path)
                if not self._verifier.verify(e.path, e.bytes, sig):
                    raise ValueError(f"Signature verification failed for {e.path}")

            # build Policy and PolicyMetadata
            # schema-friendly: accept either top-level 'metadata/spec' or raw spec body (for rego/cel)
            metadata_obj = {}
            spec_obj: Mapping[str, Any] = {}

            if isinstance(obj, Mapping) and "metadata" in obj and "spec" in obj:
                metadata_obj = obj.get("metadata") or {}
                spec_obj = obj.get("spec") or {}
            else:
                spec_obj = obj if isinstance(obj, Mapping) else {"raw": obj}

            policy_id = _coerce_str(metadata_obj.get("policy_id")) or _derive_policy_id(e.path)
            version = _coerce_str(metadata_obj.get("version")) or revision
            tenant_id = _coerce_optional_str(metadata_obj.get("tenant_id")) or self._cfg.tenant_id
            tags = _coerce_tags(metadata_obj.get("tags"))
            sec_label = _parse_security_label(metadata_obj.get("security_label"))

            updated_at = _parse_dt(metadata_obj.get("updated_at")) or dt.datetime.fromtimestamp(e.mtime, tz=dt.timezone.utc)
            etag = _etag_bytes(e.bytes, policy_id, version)

            meta = PolicyMetadata(
                policy_id=policy_id,
                version=version,
                kind=_coerce_str(metadata_obj.get("kind")) or kind,
                etag=etag,
                updated_at=updated_at,
                tenant_id=tenant_id,
                tags=frozenset(tags),
            )

            policies.append(Policy(metadata=meta, spec=spec_obj, compiled=None))

        return policies


# -----------------------------
# BundlePolicyStore: in-memory store backed by BundleLoader
# -----------------------------
# NOTE: Import placed here to avoid circular import cycles.
from ..context import PolicyStore  # noqa: E402


class BundlePolicyStore(PolicyStore):
    """
    PolicyStore implementation backed by a BundleLoader index.
    Use load_once() before serving, or stream_updates() to keep fresh externally.
    """
    def __init__(self, loader: BundleLoader):
        self._loader = loader

    async def get_policy(self, policy_id: str) -> Optional[Policy]:
        idx = self._loader.current_index() or await self._loader.load_once()
        return idx.by_id.get(policy_id)

    async def list_policies(
        self,
        *,
        tenant_id: Optional[str] = None,
        tags: Optional[Iterable[str]] = None,
        kinds: Optional[Iterable[str]] = None,
    ) -> Sequence[PolicyMetadata]:
        idx = self._loader.current_index() or await self._loader.load_once()
        tag_set = set(tags or [])
        kind_set = set(kinds or [])
        out: List[PolicyMetadata] = []
        for p in idx.policies:
            if tenant_id is not None and p.metadata.tenant_id != tenant_id:
                continue
            if tag_set and not tag_set.issubset(p.metadata.tags):
                continue
            if kind_set and p.metadata.kind not in kind_set:
                continue
            out.append(p.metadata)
        return out

    async def get_etag(self, policy_id: str) -> Optional[str]:
        idx = self._loader.current_index() or await self._loader.load_once()
        p = idx.by_id.get(policy_id)
        return p.metadata.etag if p else None


# -----------------------------
# Helpers
# -----------------------------
def _extract_manifest(entries: List[FileEntry]) -> Mapping[str, Any]:
    """
    OPA bundle manifest lives at /.manifest (JSON).
    Also accept manifest.json for non-OPA bundles.
    """
    for e in entries:
        name = e.path.split("/")[-1]
        if name == ".manifest" or name == "manifest.json":
            try:
                return json.loads(e.bytes.decode("utf-8"))
            except Exception as ex:
                log.warning("Failed to parse manifest %s: %s", e.path, ex)
                return {}
    return {}


def _extract_signatures(entries: List[FileEntry]) -> Mapping[str, Optional[bytes]]:
    """
    Optional signatures file, e.g., signatures.json: { "path": "base64sig", ... }
    This function provides a simple lookup; actual verification handled by SignatureVerifier.
    """
    for e in entries:
        if e.path.endswith("signatures.json"):
            try:
                obj = json.loads(e.bytes.decode("utf-8"))
                out: Dict[str, Optional[bytes]] = {}
                for k, v in obj.items():
                    try:
                        out[k] = None if v is None else bytes.fromhex(v)  # expect hex for safety
                    except Exception:
                        out[k] = None
                return out
            except Exception as ex:
                log.warning("Failed to parse signatures.json: %s", ex)
                return {}
    return {}


def _is_meta_file(path: str) -> bool:
    base = path.split("/")[-1]
    return base in {".manifest", "manifest.json", "signatures.json"}


def _under_roots(path: str, roots: Tuple[str, ...]) -> bool:
    if not roots:
        return True
    p = pathlib.PurePosixPath(path).as_posix()
    return any(p.startswith(r) for r in roots)


def _auto_revision(entries: List[FileEntry]) -> str:
    h = hashlib.sha256()
    for e in sorted(entries, key=lambda x: x.path):
        if _is_meta_file(e.path):
            continue
        h.update(e.bytes)
    return h.hexdigest()[:16]


def _etag_bytes(data: bytes, policy_id: str, version: str) -> str:
    h = hashlib.sha256()
    h.update(data)
    h.update(policy_id.encode("utf-8"))
    h.update(version.encode("utf-8"))
    return h.hexdigest()


def _coerce_str(v: Any) -> str:
    return str(v).strip() if v is not None else ""


def _coerce_optional_str(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None


def _coerce_tags(v: Any) -> List[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v]
    return []


def _parse_dt(v: Any) -> Optional[dt.datetime]:
    if v is None:
        return None
    if isinstance(v, dt.datetime):
        return v if v.tzinfo else v.replace(tzinfo=dt.timezone.utc)
    if isinstance(v, (int, float)):
        return dt.datetime.fromtimestamp(float(v), tz=dt.timezone.utc)
    s = str(v)
    try:
        # fromisoformat supports offsets; ensure tz-aware
        d = dt.datetime.fromisoformat(s)
        return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)
    except Exception:
        return None


def _derive_policy_id(path: str) -> str:
    base = pathlib.PurePosixPath(path).name
    name, _ = os.path.splitext(base)
    return name


def _parse_security_label(v: Any) -> SecurityLabel:
    try:
        if isinstance(v, SecurityLabel):
            return v
        if v is None:
            return SecurityLabel.INTERNAL
        s = str(v).strip().lower()
        return SecurityLabel(s)
    except Exception:
        return SecurityLabel.INTERNAL


# -----------------------------
# Inline usage reference (non-executable)
# -----------------------------
"""
USAGE REFERENCE

from policy_core.bundles.loader import (
    BundleLoaderConfig, BundleLoader, BundlePolicyStore
)
from policy_core.context import PolicyContext, EnforcementMode
# 1) Configure loader
cfg = BundleLoaderConfig(
    source_uri="/opt/policies",                   # or "/opt/policies/bundle.tar.gz"
    source_type=BundleSourceType.AUTO,
    strict_manifest=True,
    verify_signatures=False,                      # plug a real verifier in prod
    polling_interval_s=0.0,                       # set >0 for polling
    tenant_id="acme",
)
loader = BundleLoader(cfg)

# 2) Build a PolicyStore from loader
store = BundlePolicyStore(loader)

# 3) Use with PolicyContext
ctx = PolicyContext(store, enforcement_mode=EnforcementMode.ENFORCE)

# 4) Initial load
await loader.load_once()

# 5) Optional: stream updates (polling)
async for index in loader.stream_updates():
    # react to updates; ctx will read fresh data on next evaluation via store
    print("Updated bundle:", index.revision, index.etag)
"""
