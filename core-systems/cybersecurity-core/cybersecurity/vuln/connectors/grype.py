# cybersecurity-core/cybersecurity/vuln/connectors/grype.py
# -*- coding: utf-8 -*-
"""
Industrial Grype connector for NeuroCity/TeslaAI cybersecurity-core.

Features:
- Async subprocess execution (no shell), timeouts, robust error mapping.
- Source autodetection: container image, directory, file, SBOM (CycloneDX/SPDX) via grype "sbom:<path>".
- Optional DB update, version probe, and health checks.
- Deterministic cache with TTL: avoids repeated scans for unchanged inputs/config.
- Strict severity normalization and filtering; safe allowlist for extra flags.
- Structured normalization of Grype JSON to a stable internal schema.
- Concurrency guard via asyncio.Semaphore.
- Minimal external deps: standard library only.

Python: 3.9+

Author: NeuroCity Security Platform
License: Apache-2.0
"""

from __future__ import annotations

import asyncio
import dataclasses
import enum
import hashlib
import json
import logging
import os
from pathlib import Path
import platform
import shutil
import sys
import tempfile
import time
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union


# ------------------------------- Logging ------------------------------------ #

_LOG = logging.getLogger(__name__)
if not _LOG.handlers:
    # Safe default console handler; project may override logging globally.
    h = logging.StreamHandler()
    fmt = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    h.setFormatter(fmt)
    _LOG.addHandler(h)
    _LOG.setLevel(logging.INFO)


# ------------------------------- Exceptions --------------------------------- #

class GrypeError(Exception):
    """Base exception for Grype connector."""


class GrypeNotInstalledError(GrypeError):
    """Raised when grype binary is not found or unusable."""


class GrypeRunError(GrypeError):
    """Raised when the grype process exits with non-zero code."""


class GrypeTimeoutError(GrypeError):
    """Raised when a scan exceeds the configured timeout."""


class GrypeParseError(GrypeError):
    """Raised when grype output cannot be parsed as expected JSON."""


class GrypeInputError(GrypeError):
    """Raised for invalid input configuration or unsupported source."""


# ------------------------------- Enums & Models ------------------------------ #

class Severity(enum.IntEnum):
    """Severity ordered by risk for straightforward comparisons."""
    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @staticmethod
    def from_str(value: str) -> "Severity":
        v = (value or "").strip().upper()
        mapping = {
            "NEGLIGIBLE": Severity.LOW,  # map negligible→low to simplify policies
            "UNKNOWN": Severity.UNKNOWN,
            "LOW": Severity.LOW,
            "MEDIUM": Severity.MEDIUM,
            "MODERATE": Severity.MEDIUM,
            "HIGH": Severity.HIGH,
            "CRITICAL": Severity.CRITICAL,
        }
        return mapping.get(v, Severity.UNKNOWN)

    def __str__(self) -> str:
        return self.name


class InputType(enum.Enum):
    IMAGE = "image"
    DIRECTORY = "directory"
    FILE = "file"
    SBOM = "sbom"


@dataclasses.dataclass(frozen=True)
class CVSSMetric:
    source: Optional[str]
    version: Optional[str]
    vector: Optional[str]
    base_score: Optional[float]


@dataclasses.dataclass(frozen=True)
class FixInfo:
    state: Optional[str]  # e.g., "fixed", "not-fixed"
    versions: Tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class PackageRef:
    name: str
    version: Optional[str]
    ptype: Optional[str]   # package type (apk, deb, npm, python, etc.)
    locations: Tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class VulnerabilityFinding:
    vuln_id: str
    severity: Severity
    title: Optional[str]
    description: Optional[str]
    package: PackageRef
    fix: Optional[FixInfo]
    cvss: Tuple[CVSSMetric, ...]
    urls: Tuple[str, ...]
    data_source: Optional[str]
    cwe_ids: Tuple[str, ...]
    # Optional fields for policies/analytics
    cvss_max: Optional[float] = None
    ecosystem: Optional[str] = None


@dataclasses.dataclass(frozen=True)
class GrypeScanResult:
    target: str
    input_type: InputType
    grype_version: str
    created_at: float
    raw: Mapping[str, Any]
    findings: Tuple[VulnerabilityFinding, ...]
    stats: Mapping[str, Any]


# ------------------------------- Configuration ------------------------------ #

@dataclasses.dataclass
class GrypeConfig:
    """
    Runtime configuration for the connector.
    """
    binary_path: str = os.environ.get("GRYPE_BINARY", "grype")
    cache_dir: Path = Path(os.environ.get("NEUROCITY_CACHE_DIR", str(Path.home() / ".cache" / "neurocity"))) / "grype"
    cache_ttl_seconds: int = int(os.environ.get("GRYPE_CACHE_TTL", "21600"))  # 6 hours
    timeout_seconds: int = int(os.environ.get("GRYPE_TIMEOUT", "300"))        # 5 minutes per target
    concurrency: int = int(os.environ.get("GRYPE_CONCURRENCY", "2"))
    update_db_on_init: bool = True  # can be disabled for air-gapped
    min_severity: Severity = Severity.UNKNOWN
    only_fixed: bool = False
    add_cpes_if_none: bool = True
    # Additional flags allowlist (key: flag, value: optional value)
    extra_flags: Mapping[str, Optional[str]] = dataclasses.field(default_factory=dict)

    def ensure_dirs(self) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)


# ------------------------------- Utility funcs ------------------------------ #

def _which(binary: str) -> Optional[str]:
    return shutil.which(binary)


def _hash_key(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8", errors="ignore"))
        h.update(b"\x00")
    return h.hexdigest()


def _now() -> float:
    return time.time()


def _is_cache_fresh(path: Path, ttl: int) -> bool:
    try:
        age = _now() - path.stat().st_mtime
        return age <= ttl
    except FileNotFoundError:
        return False


def _safe_json_loads(data: Union[str, bytes]) -> Dict[str, Any]:
    try:
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="replace")
        return json.loads(data)
    except Exception as e:
        raise GrypeParseError(f"Failed to parse Grype JSON: {e}") from e


def _detect_input_type(target: str) -> InputType:
    p = Path(target)
    if p.exists():
        if p.is_dir():
            return InputType.DIRECTORY
        if p.is_file():
            # Treat json/cdx/spdx as SBOMs if recognizable
            lower = p.name.lower()
            if lower.endswith((".json", ".cdx.json", ".cdx", ".spdx", ".spdx.json")):
                try:
                    with p.open("r", encoding="utf-8", errors="ignore") as f:
                        head = f.read(2048)
                    if ("bomFormat" in head or "spdxVersion" in head) and "packages" in head:
                        return InputType.SBOM
                except Exception:
                    pass
            return InputType.FILE
    # Fallback: assume container image reference
    return InputType.IMAGE


def _severity_at_least(sev: Severity, min_sev: Severity) -> bool:
    return sev >= min_sev


def _allowlist_flags(flags: Mapping[str, Optional[str]]) -> List[str]:
    """
    Map of allowed flags to prevent arbitrary CLI injection.
    """
    allowed: Dict[str, bool] = {
        "--scope": True,
        "--fail-on": True,          # used by some workflows; we do not rely on exit code though
        "--only-fixed": False,
        "--add-cpes-if-none": False,
        "--exclude": True,          # path glob
        "--config": True,           # path to grype.yaml
        "--platform": True,         # image platform (linux/amd64)
        "--verbosity": True,
        "--quiet": False,
        "--output": True,           # will be overridden to json
    }
    out: List[str] = []
    for k, v in flags.items():
        if k not in allowed:
            _LOG.warning("Ignoring unsupported grype flag: %s", k)
            continue
        out.append(k)
        if v is not None and allowed[k] is not False:
            out.append(str(v))
    return out


# ------------------------------- Normalization ------------------------------ #

def _extract_locations(match: Mapping[str, Any]) -> Tuple[str, ...]:
    locs: List[str] = []
    art = match.get("artifact", {})
    for l in art.get("locations", []) or []:
        path = l.get("path")
        if path:
            locs.append(str(path))
    return tuple(sorted(set(locs)))


def _extract_cvss(vuln: Mapping[str, Any]) -> Tuple[CVSSMetric, ...]:
    out: List[CVSSMetric] = []
    for cv in vuln.get("cvss", []) or []:
        out.append(
            CVSSMetric(
                source=cv.get("source"),
                version=cv.get("version"),
                vector=cv.get("vector"),
                base_score=cv.get("metrics", {}).get("baseScore"),
            )
        )
    return tuple(out)


def _extract_fix(match: Mapping[str, Any]) -> Optional[FixInfo]:
    fix = match.get("vulnerability", {}).get("fix", {}) or match.get("fix", {}) or {}
    state = fix.get("state")
    vers = tuple(fix.get("versions", []) or [])
    if not state and not vers:
        return None
    return FixInfo(state=state, versions=vers)


def _normalize_match(match: Mapping[str, Any]) -> VulnerabilityFinding:
    vuln = match.get("vulnerability", {}) or {}
    art = match.get("artifact", {}) or {}
    vid = vuln.get("id") or art.get("id") or "UNKNOWN"
    severity = Severity.from_str(vuln.get("severity") or "UNKNOWN")
    pkg = PackageRef(
        name=art.get("name") or "unknown",
        version=art.get("version"),
        ptype=art.get("type"),
        locations=_extract_locations(match),
    )
    cvss = _extract_cvss(vuln)
    cvss_max = max((c.base_score for c in cvss if c.base_score is not None), default=None)
    urls = tuple(vuln.get("urls", []) or [])
    cwes = tuple(vuln.get("cweIds", []) or [])
    return VulnerabilityFinding(
        vuln_id=str(vid),
        severity=severity,
        title=vuln.get("dataSource") or None,
        description=vuln.get("description") or None,
        package=pkg,
        fix=_extract_fix(match),
        cvss=cvss,
        urls=urls,
        data_source=vuln.get("dataSource"),
        cwe_ids=cwes,
        cvss_max=cvss_max,
        ecosystem=art.get("type"),
    )


def _build_stats(findings: Iterable[VulnerabilityFinding]) -> Dict[str, Any]:
    counts = {sev.name: 0 for sev in Severity}
    total = 0
    for f in findings:
        counts[str(f.severity)] = counts.get(str(f.severity), 0) + 1
        total += 1
    return {"total": total, "by_severity": counts}


# ------------------------------- Core Connector ----------------------------- #

class GrypeConnector:
    """
    Asynchronous connector for Grype.

    Example integration (pseudo):
        connector = GrypeConnector()
        result = await connector.scan("alpine:3.18")
        for f in result.findings: ...
    """

    def __init__(self, cfg: Optional[GrypeConfig] = None, logger: Optional[logging.Logger] = None) -> None:
        self.cfg = cfg or GrypeConfig()
        self.cfg.ensure_dirs()
        self._logger = logger or _LOG
        self._sem = asyncio.Semaphore(max(1, int(self.cfg.concurrency)))
        self._grype_path = self._resolve_binary(self.cfg.binary_path)
        self._grype_version = ""

    # --------------------------- Setup & health ---------------------------- #

    @staticmethod
    def _resolve_binary(binary: str) -> str:
        bin_path = _which(binary) or ""
        if not bin_path:
            raise GrypeNotInstalledError(
                f"Grype binary '{binary}' not found in PATH. "
                f"Set GRYPE_BINARY or install grype from https://github.com/anchore/grype."
            )
        return bin_path

    async def init(self) -> None:
        """Optional explicit init to validate environment and update DB if configured."""
        self._grype_version = await self.version()
        self._logger.info("Using grype: %s (%s)", self._grype_path, self._grype_version)
        if self.cfg.update_db_on_init:
            try:
                await self.update_db()
            except Exception as e:
                # Do not fail init on DB update errors (air-gapped envs)
                self._logger.warning("Grype DB update failed (continuing): %s", e)

    async def version(self) -> str:
        code, out, err = await self._exec([self._grype_path, "--version"])
        if code != 0:
            raise GrypeRunError(f"Failed to get grype version: {err.decode('utf-8', 'ignore')}")
        self._grype_version = out.decode("utf-8", errors="ignore").strip()
        return self._grype_version

    async def update_db(self) -> str:
        """Runs 'grype db update' to refresh the vulnerability database."""
        self._logger.info("Updating grype DB...")
        code, out, err = await self._exec([self._grype_path, "db", "update"])
        if code != 0:
            raise GrypeRunError(f"Grype DB update failed: {err.decode('utf-8', 'ignore')}")
        msg = out.decode("utf-8", errors="ignore").strip()
        self._logger.info("Grype DB update: %s", msg)
        return msg

    # ----------------------------- Public API ----------------------------- #

    async def scan(
        self,
        target: str,
        *,
        input_type: Optional[InputType] = None,
        min_severity: Optional[Severity] = None,
        extra_flags: Optional[Mapping[str, Optional[str]]] = None,
        timeout_seconds: Optional[int] = None,
    ) -> GrypeScanResult:
        """
        Run a vulnerability scan with Grype for a given target.

        :param target: Container image ref, local dir/file, or SBOM path.
        :param input_type: Optional explicit input type (auto-detected if None).
        :param min_severity: Filter findings below this severity.
        :param extra_flags: Extra flags (whitelisted) to pass to grype.
        :param timeout_seconds: Per-scan timeout.
        """
        if not target or not isinstance(target, str):
            raise GrypeInputError("Target must be a non-empty string")

        itype = input_type or _detect_input_type(target)
        if itype == InputType.SBOM:
            grype_target = f"sbom:{Path(target).resolve()}"
        elif itype == InputType.DIRECTORY:
            grype_target = f"dir:{Path(target).resolve()}"
        elif itype == InputType.FILE:
            # For a single file (e.g., binary or lockfile), grype can scan parent dir;
            # prefer explicit file scheme to limit scope if supported.
            grype_target = f"file:{Path(target).resolve()}"
        else:
            # IMAGE: use as-is (e.g., "alpine:3.18", "ghcr.io/org/app:sha")
            grype_target = target

        min_sev = min_severity if min_severity is not None else self.cfg.min_severity

        # Build CLI args
        args = [
            self._grype_path,
            grype_target,
            "--output", "json",
        ]

        flags: Dict[str, Optional[str]] = dict(self.cfg.extra_flags or {})
        if self.cfg.only_fixed:
            flags["--only-fixed"] = None
        if self.cfg.add_cpes_if_none:
            flags["--add-cpes-if-none"] = None
        # Merge caller-provided flags (still allowlisted)
        if extra_flags:
            flags.update(extra_flags)

        args.extend(_allowlist_flags(flags))

        # Caching
        cache_key = _hash_key(
            grype_target,
            str(itype.value),
            str(min_sev.value),
            json.dumps(flags, sort_keys=True),
            self._grype_version or await self.version(),
            platform.system(),
            platform.machine(),
        )
        cache_path = self.cfg.cache_dir / f"{cache_key}.json"

        if _is_cache_fresh(cache_path, self.cfg.cache_ttl_seconds):
            self._logger.debug("Using cached grype result: %s", cache_path)
            raw = _safe_json_loads(cache_path.read_bytes())
            findings = self._normalize_and_filter(raw, min_sev)
            stats = _build_stats(findings)
            return GrypeScanResult(
                target=target,
                input_type=itype,
                grype_version=self._grype_version,
                created_at=cache_path.stat().st_mtime,
                raw=raw,
                findings=findings,
                stats=stats,
            )

        # Execute scan
        code, out, err = await self._exec(args, timeout=timeout_seconds or self.cfg.timeout_seconds)
        if code != 0:
            # Grype may use non-0 for policy "fail-on"; still try parse JSON if present.
            err_text = err.decode("utf-8", "ignore")
            try:
                raw = _safe_json_loads(out)
            except GrypeParseError:
                raise GrypeRunError(f"Grype scan failed (code={code}): {err_text}") from None
        else:
            raw = _safe_json_loads(out)

        # Persist cache atomically
        try:
            with tempfile.NamedTemporaryFile("wb", delete=False, dir=str(self.cfg.cache_dir)) as tf:
                tf.write(json.dumps(raw, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
                tmp_name = tf.name
            os.replace(tmp_name, cache_path)
        except Exception as e:
            self._logger.warning("Failed to write cache %s: %s", cache_path, e)

        findings = self._normalize_and_filter(raw, min_sev)
        stats = _build_stats(findings)

        return GrypeScanResult(
            target=target,
            input_type=itype,
            grype_version=self._grype_version,
            created_at=_now(),
            raw=raw,
            findings=findings,
            stats=stats,
        )

    async def scan_many(
        self,
        targets: Sequence[str],
        *,
        input_type: Optional[InputType] = None,
        min_severity: Optional[Severity] = None,
        extra_flags: Optional[Mapping[str, Optional[str]]] = None,
        timeout_seconds: Optional[int] = None,
    ) -> List[GrypeScanResult]:
        """Scan multiple targets concurrently with the configured semaphore."""
        tasks = [
            self._guard(self.scan)(
                t,
                input_type=input_type,
                min_severity=min_severity,
                extra_flags=extra_flags,
                timeout_seconds=timeout_seconds,
            )
            for t in targets
        ]
        return list(await asyncio.gather(*tasks))

    # --------------------------- Internals --------------------------------- #

    def _normalize_and_filter(self, raw: Mapping[str, Any], min_sev: Severity) -> Tuple[VulnerabilityFinding, ...]:
        matches = raw.get("matches", []) or []
        findings: List[VulnerabilityFinding] = []
        for m in matches:
            try:
                f = _normalize_match(m)
                if _severity_at_least(f.severity, min_sev):
                    findings.append(f)
            except Exception as e:
                self._logger.debug("Skipping match due to normalization error: %s", e)
        return tuple(findings)

    async def _exec(
        self,
        args: Sequence[str],
        *,
        env: Optional[Mapping[str, str]] = None,
        timeout: int = 300,
    ) -> Tuple[int, bytes, bytes]:
        """Run a subprocess under semaphore with timeout."""
        async with self._sem:
            self._logger.debug("Executing: %s", " ".join(map(str, args)))
            try:
                proc = await asyncio.create_subprocess_exec(
                    *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env={**os.environ, **(env or {})},
                )
                try:
                    out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                except asyncio.TimeoutError:
                    with contextlib.suppress(ProcessLookupError):
                        proc.kill()
                    raise
