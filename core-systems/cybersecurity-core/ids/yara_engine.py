from __future__ import annotations

import asyncio
import base64
import functools
import hashlib
import logging
import os
import re
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# --- Optional yara-python -----------------------------------------------------
try:
    import yara  # type: ignore
except Exception:  # pragma: no cover
    yara = None  # type: ignore

# --- Optional app context for log enrichment ---------------------------------
try:
    # Will be available if cybersecurity.context is present in project
    from cybersecurity.context import get_request_context  # type: ignore
except Exception:  # pragma: no cover
    def get_request_context():
        return None


# =============================================================================
# Exceptions
# =============================================================================

class YaraEngineError(Exception):
    """Base YARA engine error."""


class YaraCompileError(YaraEngineError):
    """Compilation failure."""


class YaraScanError(YaraEngineError):
    """Scan failure."""


# =============================================================================
# Models
# =============================================================================

@dataclass(frozen=True)
class YaraStringMatch:
    offset: int
    identifier: str
    data_b64: str


@dataclass(frozen=True)
class YaraMatch:
    rule: str
    namespace: Optional[str]
    tags: Tuple[str, ...]
    meta: Dict[str, Any]
    strings: Tuple[YaraStringMatch, ...]
    source: str  # "FILE" | "BYTES" | "PROCESS"
    filepath: Optional[str] = None
    pid: Optional[int] = None
    matched_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # datetime -> isoformat
        d["matched_at"] = self.matched_at.isoformat()
        return d


@dataclass
class YaraConfig:
    rule_dirs: List[Path] = field(default_factory=list)
    rule_files: List[Path] = field(default_factory=list)
    inline_rules: List[str] = field(default_factory=list)
    include_dirs: List[Path] = field(default_factory=list)
    timeout_ms: int = 2000
    string_max_bytes: int = 96
    enable_cache: bool = True
    compiled_cache_dir: Path = Path(".yara-cache")
    default_externals: Dict[str, Any] = field(default_factory=dict)
    # scanning
    dir_patterns: Tuple[str, ...] = ("*.yar", "*.yara")
    dir_recursive: bool = True
    # concurrency for directory scans
    max_concurrency: int = 4


# =============================================================================
# Logger with context enrichment
# =============================================================================

class _ContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        ctx = get_request_context()
        record.correlation_id = getattr(record, "correlation_id", None)
        record.tenant_id = getattr(record, "tenant_id", None)
        record.user_id = getattr(record, "user_id", None)
        if ctx:
            record.correlation_id = getattr(ctx, "correlation_id", None)
            record.tenant_id = str(getattr(ctx, "tenant_id", None)) if getattr(ctx, "tenant_id", None) else None
            record.user_id = str(getattr(ctx, "user_id", None)) if getattr(ctx, "user_id", None) else None
        return True


_logger = logging.getLogger(__name__)
if not _logger.handlers:
    _h = logging.StreamHandler(sys.stdout)
    _fmt = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s correlation_id=%(correlation_id)s tenant_id=%(tenant_id)s user_id=%(user_id)s"
    )
    _h.setFormatter(_fmt)
    _h.addFilter(_ContextFilter())
    _logger.addHandler(_h)
_logger.setLevel(logging.INFO)


# =============================================================================
# Utility helpers
# =============================================================================

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _b64truncate(data: bytes, limit: int) -> str:
    if limit >= 0 and len(data) > limit:
        data = data[:limit]
    return base64.b64encode(data).decode("ascii")


def _file_fingerprint(paths: Sequence[Path], inline_rules: Sequence[str]) -> str:
    """
    Compute stable fingerprint of rules content (paths + mtimes + sizes + file bytes head/tail).
    This allows deterministic cache invalidation without hashing entire large trees.
    """
    h = hashlib.sha256()
    for p in sorted({str(p.resolve()) for p in paths}):
        try:
            st = os.stat(p)
            h.update(p.encode())
            h.update(str(st.st_mtime_ns).encode())
            h.update(str(st.st_size).encode())
            # sample head and tail up to 4KB each to better catch changes
            with open(p, "rb") as f:
                head = f.read(4096)
                if st.st_size > 4096:
                    f.seek(max(0, st.st_size - 4096))
                    tail = f.read(4096)
                else:
                    tail = b""
            h.update(head)
            h.update(tail)
        except FileNotFoundError:
            continue
    for s in inline_rules:
        h.update(s.encode("utf-8"))
    return h.hexdigest()


def _collect_rule_files(
    rule_dirs: Sequence[Path],
    rule_files: Sequence[Path],
    patterns: Sequence[str],
    recursive: bool,
) -> List[Path]:
    files: List[Path] = []
    seen: set = set()
    for p in rule_files:
        if p and p.exists() and p.is_file():
            rp = p.resolve()
            if rp not in seen:
                files.append(rp)
                seen.add(rp)
    for d in rule_dirs:
        if not d or not d.exists():
            continue
        d = d.resolve()
        if recursive:
            for pattern in patterns:
                for f in d.rglob(pattern):
                    if f.is_file():
                        rf = f.resolve()
                        if rf not in seen:
                            files.append(rf)
                            seen.add(rf)
        else:
            for pattern in patterns:
                for f in d.glob(pattern):
                    if f.is_file():
                        rf = f.resolve()
                        if rf not in seen:
                            files.append(rf)
                            seen.add(rf)
    return files


# =============================================================================
# YaraEngine
# =============================================================================

class YaraEngine:
    """
    Industrial-grade YARA engine wrapper with async scanning, rule caching and normalized results.
    Requires yara-python (https://github.com/VirusTotal/yara-python). If not installed,
    the engine gracefully degrades to a No-Op returning empty matches.
    """

    def __init__(self, config: Optional[YaraConfig] = None) -> None:
        self.config = config or YaraConfig()
        self._rules = None  # type: ignore
        self._digest: Optional[str] = None
        self._lock = asyncio.Lock()

        if self.config.enable_cache:
            try:
                self.config.compiled_cache_dir.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # Compilation
    # -------------------------------------------------------------------------
    async def compile(self, force: bool = False) -> None:
        """
        Compile rules according to configuration, optionally using .yarac disk cache.
        """
        async with self._lock:
            if yara is None:
                _logger.warning("yara-python is not installed; YaraEngine will operate in no-op mode.")
                self._rules = None
                self._digest = None
                return

            files = _collect_rule_files(
                self.config.rule_dirs,
                self.config.rule_files,
                self.config.dir_patterns,
                self.config.dir_recursive,
            )
            digest = _file_fingerprint(files, self.config.inline_rules)
            if not force and self._digest == digest and self._rules is not None:
                return

            compiled_path = self.config.compiled_cache_dir / f"{digest}.yarac"
            # Try load from cache
            if self.config.enable_cache and compiled_path.exists() and compiled_path.is_file():
                try:
                    self._rules = await asyncio.to_thread(yara.load, str(compiled_path))
                    self._digest = digest
                    _logger.info("yara.cache.load success", extra={"path": str(compiled_path)})
                    return
                except Exception as e:  # pragma: no cover
                    _logger.warning("yara.cache.load failed; recompiling", extra={"error": str(e)})

            # Compile from sources
            try:
                compiler = yara.Compiler()
                # Add include dirs: YARA respects working dir of each file for includes;
                # but we additionally push include paths via 'add_file' working directory trick.
                include_dirs = [str(p.resolve()) for p in self.config.include_dirs if p.exists()]
                # Files
                for f in files:
                    with open(f, "rb") as fh:
                        # namespace based on top directory name to help triage
                        ns = f.parent.name
                        compiler.add_file(fh, namespace=ns)
                # Inline rules
                for i, text in enumerate(self.config.inline_rules, start=1):
                    ns = f"inline_{i:03d}"
                    compiler.add_string(text.encode("utf-8"), namespace=ns)

                rules = compiler.compile()
                self._rules = rules
                self._digest = digest

                if self.config.enable_cache:
                    try:
                        rules.save(str(compiled_path))
                        _logger.info("yara.cache.save success", extra={"path": str(compiled_path)})
                    except Exception as e:  # pragma: no cover
                        _logger.warning("yara.cache.save failed", extra={"error": str(e)})
            except Exception as e:
                # Try to extract line/col from yara.SyntaxError message if available
                msg = str(e)
                raise YaraCompileError(f"YARA compilation failed: {msg}") from e

    async def reload(self) -> None:
        await self.compile(force=True)

    # -------------------------------------------------------------------------
    # Scanning primitives
    # -------------------------------------------------------------------------
    async def scan_file(
        self,
        path: Path,
        externals: Optional[Mapping[str, Any]] = None,
        timeout_ms: Optional[int] = None,
    ) -> List[YaraMatch]:
        """
        Scan a single file by path.
        """
        await self.compile()
        if yara is None or self._rules is None:
            return []
        if not path or not Path(path).is_file():
            raise YaraScanError(f"File not found: {path}")

        to = (timeout_ms or self.config.timeout_ms) / 1000.0
        ext = self._merge_externals(externals, {"filename": str(path)})

        try:
            results = await asyncio.to_thread(
                self._rules.match, filepath=str(path), externals=ext, timeout=to
            )
        except yara.TimeoutError as e:  # type: ignore
            raise YaraScanError(f"Scan timeout after {to}s: {path}") from e
        except Exception as e:
            raise YaraScanError(f"Scan error: {path}: {e}") from e

        return self._normalize_matches(results, source="FILE", filepath=str(path))

    async def scan_bytes(
        self,
        data: bytes,
        externals: Optional[Mapping[str, Any]] = None,
        timeout_ms: Optional[int] = None,
    ) -> List[YaraMatch]:
        """
        Scan an in-memory bytes buffer.
        """
        await self.compile()
        if yara is None or self._rules is None or not data:
            return []
        to = (timeout_ms or self.config.timeout_ms) / 1000.0
        ext = self._merge_externals(externals, {})

        try:
            results = await asyncio.to_thread(
                self._rules.match, data=data, externals=ext, timeout=to
            )
        except yara.TimeoutError as e:  # type: ignore
            raise YaraScanError(f"Scan timeout after {to}s (bytes)") from e
        except Exception as e:
            raise YaraScanError(f"Scan error (bytes): {e}") from e

        return self._normalize_matches(results, source="BYTES")

    async def scan_pid(
        self,
        pid: int,
        externals: Optional[Mapping[str, Any]] = None,
        timeout_ms: Optional[int] = None,
    ) -> List[YaraMatch]:
        """
        Scan a live process (requires OS support / privileges).
        """
        await self.compile()
        if yara is None or self._rules is None:
            return []
        to = (timeout_ms or self.config.timeout_ms) / 1000.0
        ext = self._merge_externals(externals, {"pid": int(pid)})

        try:
            results = await asyncio.to_thread(
                self._rules.match, pid=int(pid), externals=ext, timeout=to
            )
        except AttributeError:
            # Some yara-python builds may lack 'pid' support
            raise YaraScanError("This build of yara-python doesn't support process scanning (pid=).")
        except yara.TimeoutError as e:  # type: ignore
            raise YaraScanError(f"Scan timeout after {to}s (pid={pid})") from e
        except Exception as e:
            raise YaraScanError(f"Scan error (pid={pid}): {e}") from e

        return self._normalize_matches(results, source="PROCESS", pid=int(pid))

    async def scan_dir(
        self,
        root: Path,
        patterns: Optional[Sequence[str]] = None,
        recursive: Optional[bool] = None,
        externals: Optional[Mapping[str, Any]] = None,
        timeout_ms: Optional[int] = None,
        max_concurrency: Optional[int] = None,
    ) -> Dict[str, List[YaraMatch]]:
        """
        Scan all files under directory matching patterns; returns mapping path -> matches.
        """
        await self.compile()
        if yara is None or self._rules is None:
            return {}
        if not root or not Path(root).exists():
            raise YaraScanError(f"Root not found: {root}")

        patterns = tuple(patterns or self.config.dir_patterns)
        recursive = self.config.dir_recursive if recursive is None else recursive
        concurrency = max(1, int(max_concurrency or self.config.max_concurrency))
        sem = asyncio.Semaphore(concurrency)

        files: List[Path] = []
        root = Path(root).resolve()
        if recursive:
            for patt in patterns:
                files.extend(root.rglob(patt))
        else:
            for patt in patterns:
                files.extend(root.glob(patt))
        files = [f for f in files if f.is_file()]

        async def _scan_one(p: Path) -> Tuple[str, List[YaraMatch]]:
            async with sem:
                try:
                    res = await self.scan_file(p, externals=externals, timeout_ms=timeout_ms)
                    return (str(p), res)
                except YaraScanError:
                    return (str(p), [])

        results: Dict[str, List[YaraMatch]] = {}
        for chunk in _chunked(files, max(1, 64)):
            rs = await asyncio.gather(*[_scan_one(p) for p in chunk])
            results.update({k: v for k, v in rs})
        return results

    # -------------------------------------------------------------------------
    # Public info
    # -------------------------------------------------------------------------
    def stats(self) -> Dict[str, Any]:
        return {
            "yara_present": bool(yara is not None),
            "rules_compiled": bool(self._rules is not None),
            "digest": self._digest,
            "cache_dir": str(self.config.compiled_cache_dir),
        }

    # -------------------------------------------------------------------------
    # Internals
    # -------------------------------------------------------------------------
    def _merge_externals(
        self, externals: Optional[Mapping[str, Any]], base: Optional[Mapping[str, Any]] = None
    ) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        out.update(self.config.default_externals or {})
        if base:
            out.update(base)
        if externals:
            out.update(externals)
        # Normalize types: yara expects primitives (int/float/bytes/str/bool)
        for k, v in list(out.items()):
            if isinstance(v, Path):
                out[k] = str(v)
            elif isinstance(v, uuid.UUID):
                out[k] = str(v)
            elif isinstance(v, datetime):
                out[k] = int(v.timestamp())
        return out

    def _normalize_matches(
        self,
        raw_matches: Any,  # List[yara.Match]
        source: str,
        filepath: Optional[str] = None,
        pid: Optional[int] = None,
    ) -> List[YaraMatch]:
        normalized: List[YaraMatch] = []
        if not raw_matches:
            return normalized

        limit = max(0, int(self.config.string_max_bytes))
        for m in raw_matches:
            # m.rule, m.namespace, m.tags (list), m.meta (dict), m.strings (list of tuples)
            strings: List[YaraStringMatch] = []
            for tup in getattr(m, "strings", []):
                # tuple shapes in yara-python: (offset, identifier, data)
                try:
                    offset, ident, data = tup
                except ValueError:
                    # some versions include additional values; try common mapping
                    if len(tup) >= 3:
                        offset, ident, data = tup[0], tup[1], tup[2]
                    else:
                        continue
                try:
                    data_b64 = _b64truncate(data if isinstance(data, (bytes, bytearray)) else bytes(str(data), "utf-8"), limit)
                except Exception:
                    data_b64 = ""
                strings.append(YaraStringMatch(offset=int(offset), identifier=str(ident), data_b64=data_b64))

            match = YaraMatch(
                rule=getattr(m, "rule", None) or "",
                namespace=getattr(m, "namespace", None),
                tags=tuple(getattr(m, "tags", []) or []),
                meta=dict(getattr(m, "meta", {}) or {}),
                strings=tuple(strings),
                source=source,
                filepath=filepath,
                pid=pid,
                matched_at=_now_utc(),
            )
            normalized.append(match)
        return normalized


# =============================================================================
# Helpers
# =============================================================================

def _chunked(seq: Sequence[Path], size: int) -> Iterable[Sequence[Path]]:
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


__all__ = [
    "YaraEngine",
    "YaraConfig",
    "YaraMatch",
    "YaraStringMatch",
    "YaraEngineError",
    "YaraCompileError",
    "YaraScanError",
]
