# security-core/security/threat_detection/rules_yara.py
"""
Industrial YARA rules manager and scanner for security-core.

Requirements:
    pip install yara-python

Key features:
- Namespaced rule sets, recursive include resolution, deterministic fingerprint (SHA-256)
- Compile from sources with externals; cache compiled bundle (.yarac) per fingerprint and YARA version
- Thread-safe (read-mostly) with RWLock; lazy load; hot reload via refresh()
- Scan bytes/files/directories/PIDs with timeout and max file size guard
- Allowlist filtering (by rule name, tag, path regex, meta kv)
- Concurrency for directory scans; structured, JSON-friendly results
- Optional disabling of YARA modules for perf/hardening

Notes:
- Process scanning requires appropriate privileges and OS support (yara-python rules.match(pid=...)).
- Include resolution searches relative to the including file and user-provided include_paths.
"""

from __future__ import annotations

import base64
import concurrent.futures
import fnmatch
import hashlib
import io
import os
import re
import threading
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union, Set, Any

try:
    import yara  # type: ignore
except Exception as e:  # pragma: no cover
    raise ImportError("yara-python is required: pip install yara-python") from e


# =========================
# Data models
# =========================

@dataclass(frozen=True)
class RuleSource:
    namespace: str
    paths: Tuple[Path, ...]         # .yar files or directories (recursively globbed)
    include_paths: Tuple[Path, ...] = tuple()  # extra search roots for includes


@dataclass(frozen=True)
class YaraStringHit:
    offset: int
    identifier: str
    data_b64: str


@dataclass(frozen=True)
class YaraMatch:
    rule: str
    namespace: str
    tags: Tuple[str, ...]
    meta: Mapping[str, Any]
    strings: Tuple[YaraStringHit, ...]


@dataclass(frozen=True)
class ScanTarget:
    kind: str            # "bytes" | "file" | "pid"
    value: Union[bytes, Path, int]
    description: Optional[str] = None  # e.g., file path string for reporting


@dataclass
class ScanStats:
    files_scanned: int = 0
    bytes_scanned: int = 0
    duration_sec: float = 0.0
    matches: int = 0
    errors: int = 0


@dataclass(frozen=True)
class ScanResult:
    target: str
    matches: Tuple[YaraMatch, ...]
    stats: ScanStats


@dataclass(frozen=True)
class Allowlist:
    rule_names: Tuple[str, ...] = tuple()          # exact names or glob patterns
    tags: Tuple[str, ...] = tuple()                # tag names
    path_globs: Tuple[str, ...] = tuple()          # file path patterns
    meta_equals: Tuple[Tuple[str, str], ...] = tuple()  # (key,value)


@dataclass(frozen=True)
class CompileMetadata:
    fingerprint: str
    yara_version: str
    rule_count: int
    namespaces: Tuple[str, ...]


# =========================
# Configuration
# =========================

@dataclass
class YaraConfig:
    cache_dir: Path
    timeout_sec: int = 15
    max_file_size_bytes: int = 50 * 1024 * 1024  # 50 MiB safety rail
    workers: int = min(32, (os.cpu_count() or 4) * 5)
    externals: Mapping[str, Union[int, str, bool]] = field(default_factory=dict)
    disable_modules: Sequence[str] = field(default_factory=tuple)  # e.g., ("cuckoo",)
    dir_globs: Sequence[str] = ("**/*.yar",)
    follow_symlinks: bool = False


# =========================
# Internal helpers
# =========================

class _RWLock:
    """Simple RW lock based on two RLocks."""
    def __init__(self) -> None:
        self._read_ready = threading.Condition(threading.RLock())
        self._readers = 0

    def r_acquire(self) -> None:
        with self._read_ready:
            self._readers += 1

    def r_release(self) -> None:
        with self._read_ready:
            self._readers -= 1
            if self._readers == 0:
                self._read_ready.notify_all()

    def w_acquire(self) -> None:
        self._read_ready.acquire()
        while self._readers > 0:
            self._read_ready.wait()

    def w_release(self) -> None:
        self._read_ready.release()


_INCLUDE_RE = re.compile(r'(?m)^\s*include\s+"([^"]+)"\s*;?\s*$')


def _read_file_bytes(p: Path) -> bytes:
    with open(p, "rb") as f:
        return f.read()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _iter_rule_files(paths: Iterable[Path], globs: Sequence[str]) -> List[Path]:
    out: List[Path] = []
    for p in paths:
        if p.is_dir():
            for g in globs:
                out.extend(sorted(p.rglob(g)))
        elif p.suffix.lower() in (".yar", ".yara"):
            out.append(p)
    # unique preserving order
    seen: Set[Path] = set()
    uniq: List[Path] = []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def _resolve_includes(src_path: Path, include_paths: Sequence[Path], visited: Set[Path]) -> str:
    """
    Recursively inline includes to produce a single source string.
    Prevent include cycles via 'visited'.
    """
    if src_path in visited:
        return ""  # avoid cycles; already included
    visited.add(src_path)

    try:
        text = src_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        # YARA sources should be UTF-8; fallback to latin-1 if necessary
        text = src_path.read_text(encoding="latin-1")

    parts = [f"// BEGIN {src_path}\n", text, f"\n// END {src_path}\n"]
    for inc in _INCLUDE_RE.findall(text):
        # Search include in: 1) relative to file, 2) any include_paths
        candidates = [
            (src_path.parent / inc),
            *[(ip / inc) for ip in include_paths],
        ]
        inc_path = next((c for c in candidates if c.exists()), None)
        if inc_path:
            parts.append(_resolve_includes(inc_path, include_paths, visited))
        else:
            raise FileNotFoundError(f'Include "{inc}" not found for {src_path}')
    return "\n".join(parts)


def _fingerprint_sources(namespace_to_source: Mapping[str, str]) -> str:
    h = hashlib.sha256()
    for ns in sorted(namespace_to_source.keys()):
        h.update(f"ns:{ns}\n".encode())
        h.update(namespace_to_source[ns].encode())
    return h.hexdigest()


def _should_allow(al: Allowlist, match: YaraMatch, target_path: Optional[str]) -> bool:
    if not al:
        return False
    # rule names
    for pat in al.rule_names:
        if fnmatch.fnmatch(match.rule, pat):
            return True
    # tags
    if any(t in al.tags for t in match.tags):
        return True
    # path globs
    if target_path:
        for pat in al.path_globs:
            if fnmatch.fnmatch(target_path, pat):
                return True
    # meta k/v equals (stringified)
    for k, v in al.meta_equals:
        mv = match.meta.get(k)
        if mv is not None and str(mv) == v:
            return True
    return False


def _convert_matches(raw_matches: List[Any]) -> Tuple[YaraMatch, ...]:
    out: List[YaraMatch] = []
    for m in raw_matches:
        strings: List[YaraStringHit] = []
        for off, ident, data in getattr(m, "strings", []):
            try:
                b = data if isinstance(data, (bytes, bytearray)) else bytes(data)
            except Exception:
                b = b""  # non-serializable — drop payload
            strings.append(YaraStringHit(offset=int(off), identifier=str(ident), data_b64=_b64(b)))
        out.append(YaraMatch(
            rule=str(m.rule),
            namespace=str(m.namespace),
            tags=tuple(getattr(m, "tags", ()) or ()),
            meta=dict(getattr(m, "meta", {}) or {}),
            strings=tuple(strings),
        ))
    return tuple(out)


# =========================
# Manager
# =========================

class YaraRuleManager:
    def __init__(self, cfg: YaraConfig) -> None:
        self.cfg = cfg
        self._rw = _RWLock()
        self._rules: Optional["yara.Rules"] = None
        self._meta: Optional[CompileMetadata] = None
        self._cache_dir = cfg.cache_dir
        self._cache_dir.mkdir(parents=True, exist_ok=True)

    # ---- Compilation and cache ----

    def compile(self, sources: Sequence[RuleSource]) -> CompileMetadata:
        ns_to_src: Dict[str, str] = {}
        total_rules = 0

        for src in sources:
            files = _iter_rule_files(src.paths, self.cfg.dir_globs)
            if not files:
                continue
            visited: Set[Path] = set()
            merged: List[str] = []
            for f in files:
                merged.append(_resolve_includes(f, src.include_paths, visited))
            ns_to_src[src.namespace] = "\n".join(merged)
            total_rules += len(files)

        if not ns_to_src:
            raise ValueError("No YARA sources found to compile")

        fp = _fingerprint_sources(ns_to_src) + f":yara:{yara.__version__}"
        ns_tuple = tuple(sorted(ns_to_src.keys()))
        meta = CompileMetadata(
            fingerprint=hashlib.sha256(fp.encode()).hexdigest(),
            yara_version=yara.__version__,
            rule_count=total_rules,
            namespaces=ns_tuple,
        )

        cache_path = self._cache_dir / f"{meta.fingerprint}.yarac"
        if cache_path.exists():
            rules = yara.load(filepath=str(cache_path))
            self._rw.w_acquire()
            try:
                self._rules = rules
                self._meta = meta
            finally:
                self._rw.w_release()
            return meta

        # Compile from sources dict
        rules = yara.compile(sources=ns_to_src, externals=dict(self.cfg.externals))

        # Persist compiled bundle
        tmp = self._cache_dir / f".{meta.fingerprint}.yarac.tmp"
        rules.save(filepath=str(tmp))
        os.replace(tmp, cache_path)

        self._rw.w_acquire()
        try:
            self._rules = rules
            self._meta = meta
        finally:
            self._rw.w_release()
        return meta

    def refresh_from_cache(self, fingerprint: str) -> bool:
        """Load precompiled bundle with given fingerprint if present."""
        cache_path = self._cache_dir / f"{fingerprint}.yarac"
        if not cache_path.exists():
            return False
        rules = yara.load(filepath=str(cache_path))
        self._rw.w_acquire()
        try:
            self._rules = rules
            # Keep old meta if matching, or set minimal
            self._meta = self._meta or CompileMetadata(fingerprint=fingerprint, yara_version=yara.__version__, rule_count=0, namespaces=tuple())
        finally:
            self._rw.w_release()
        return True

    def metadata(self) -> Optional[CompileMetadata]:
        return self._meta

    # ---- Scanning ----

    def scan_bytes(
        self,
        data: bytes,
        *,
        externals: Optional[Mapping[str, Union[int, str, bool]]] = None,
        allowlist: Optional[Allowlist] = None,
        timeout_sec: Optional[int] = None,
    ) -> ScanResult:
        rules = self._get_rules_or_raise()
        t0 = time.time()
        stats = ScanStats(files_scanned=0, bytes_scanned=len(data))
        try:
            raw = rules.match(data=data, externals=self._merge_externals(externals), timeout=timeout_sec or self.cfg.timeout_sec, disable_modules=self.cfg.disable_modules)
            matches = _convert_matches(raw)
            filtered = tuple(m for m in matches if not _should_allow(allowlist or Allowlist(), m, None))
            stats.matches = len(filtered)
        except Exception:
            stats.errors += 1
            filtered = tuple()
        stats.duration_sec = time.time() - t0
        return ScanResult(target="bytes", matches=filtered, stats=stats)

    def scan_file(
        self,
        path: Union[str, Path],
        *,
        externals: Optional[Mapping[str, Union[int, str, bool]]] = None,
        allowlist: Optional[Allowlist] = None,
        timeout_sec: Optional[int] = None,
    ) -> ScanResult:
        p = Path(path)
        rules = self._get_rules_or_raise()

        stats = ScanStats(files_scanned=1, bytes_scanned=0)
        t0 = time.time()
        try:
            try:
                size = p.stat().st_size
                stats.bytes_scanned = int(size)
            except Exception:
                size = None
            if size is not None and size > self.cfg.max_file_size_bytes:
                # Guardrail: skip oversized files
                return ScanResult(target=str(p), matches=tuple(), stats=stats)

            raw = rules.match(filepath=str(p), externals=self._merge_externals(externals), timeout=timeout_sec or self.cfg.timeout_sec, disable_modules=self.cfg.disable_modules)
            matches = _convert_matches(raw)
            filtered = tuple(m for m in matches if not _should_allow(allowlist or Allowlist(), m, str(p)))
        except Exception:
            stats.errors += 1
            filtered = tuple()
        stats.duration_sec = time.time() - t0
        return ScanResult(target=str(p), matches=filtered, stats=stats)

    def scan_pid(
        self,
        pid: int,
        *,
        externals: Optional[Mapping[str, Union[int, str, bool]]] = None,
        allowlist: Optional[Allowlist] = None,
        timeout_sec: Optional[int] = None,
    ) -> ScanResult:
        rules = self._get_rules_or_raise()
        stats = ScanStats(files_scanned=0, bytes_scanned=0)
        t0 = time.time()
        try:
            raw = rules.match(pid=int(pid), externals=self._merge_externals(externals), timeout=timeout_sec or self.cfg.timeout_sec, disable_modules=self.cfg.disable_modules)
            matches = _convert_matches(raw)
            filtered = tuple(m for m in matches if not _should_allow(allowlist or Allowlist(), m, f"pid:{pid}"))
            stats.matches = len(filtered)
        except Exception:
            stats.errors += 1
            filtered = tuple()
        stats.duration_sec = time.time() - t0
        return ScanResult(target=f"pid:{pid}", matches=filtered, stats=stats)

    def scan_dir(
        self,
        root: Union[str, Path],
        *,
        file_globs: Sequence[str] = ("**/*",),
        exclude_globs: Sequence[str] = ("**/*.yar", "**/*.yara"),  # usually we don't scan rule files
        externals: Optional[Mapping[str, Union[int, str, bool]]] = None,
        allowlist: Optional[Allowlist] = None,
        timeout_sec: Optional[int] = None,
    ) -> Tuple[ScanResult, ...]:
        root_p = Path(root)
        # Build candidate file list
        cands: List[Path] = []
        for g in file_globs:
            cands.extend(root_p.rglob(g))
        # Exclude
        excluded: Set[Path] = set()
        for g in exclude_globs:
            excluded.update(root_p.rglob(g))
        files = [p for p in cands if p.is_file() and p not in excluded]

        results: List[ScanResult] = []
        externals_merged = self._merge_externals(externals)
        timeout = timeout_sec or self.cfg.timeout_sec
        allow = allowlist or Allowlist()

        def _task(fp: Path) -> ScanResult:
            return self.scan_file(fp, externals=externals_merged, allowlist=allow, timeout_sec=timeout)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.cfg.workers) as ex:
            for res in ex.map(_task, files):
                results.append(res)
        return tuple(results)

    # ---- Management ----

    def _get_rules_or_raise(self) -> "yara.Rules":
        self._rw.r_acquire()
        try:
            if self._rules is None:
                raise RuntimeError("Rules are not compiled/loaded")
            return self._rules
        finally:
            self._rw.r_release()

    def _merge_externals(self, overrides: Optional[Mapping[str, Union[int, str, bool]]]) -> Mapping[str, Union[int, str, bool]]:
        if not overrides:
            return dict(self.cfg.externals)
        merged = dict(self.cfg.externals)
        merged.update(overrides)
        return merged

    # Hot-replace rules (e.g., after external update)
    def replace_with_precompiled(self, yarac_path: Union[str, Path], metadata: Optional[CompileMetadata] = None) -> None:
        rules = yara.load(filepath=str(yarac_path))
        self._rw.w_acquire()
        try:
            self._rules = rules
            if metadata:
                self._meta = metadata
        finally:
            self._rw.w_release()


# =========================
# Example usage (documentation only)
# =========================

if __name__ == "__main__":
    """
    Example:

    cfg = YaraConfig(cache_dir=Path("./.yara-cache"), timeout_sec=10, externals={"env": "prod"})
    mgr = YaraRuleManager(cfg)

    sources = [
        RuleSource(namespace="core", paths=(Path("rules/core"),), include_paths=(Path("rules/includes"),)),
        RuleSource(namespace="community", paths=(Path("rules/community"),)),
    ]
    meta = mgr.compile(sources)
    print("Compiled:", meta)

    res = mgr.scan_file("samples/mal.bin", allowlist=Allowlist(path_globs=("**/benign/*",)))
    print("Matches:", [m.rule for m in res.matches], "in", res.stats.duration_sec, "sec")
    """
    pass
