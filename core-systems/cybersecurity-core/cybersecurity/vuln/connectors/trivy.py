# cybersecurity-core/cybersecurity/vuln/connectors/trivy.py
# Industrial-grade Trivy connector for vulnerability management pipelines.
# Features:
# - Supports Trivy CLI and remote server (trivy client --remote)
# - Scans: image, filesystem (fs), repository (repo), SBOM (CycloneDX JSON)
# - JSON normalization to a unified schema (dataclasses)
# - Robust subprocess execution with timeout, retries, exponential backoff
# - Local on-disk caching keyed by request parameters (TTL)
# - Simple token-bucket rate-limiting per target
# - Trivy version validation (min version), DB update helper
# - Severity mapping, CVSS extraction, remediation metadata
# - Thread-safe logging and concurrent multi-target scanning
#
# Dependencies: Python 3.9+, Trivy (binary), optional: orjson for speed
#
# Environment variables (override defaults):
#   TRIVY_PATH=/usr/local/bin/trivy
#   TRIVY_SERVER_URL=http://127.0.0.1:4954
#   TRIVY_TIMEOUT_SEC=300
#   TRIVY_CACHE_DIR=/var/cache/cybersec/trivy
#   TRIVY_CACHE_TTL_SEC=600
#   TRIVY_MIN_VERSION=0.50.0
#   TRIVY_SEVERITY=CRITICAL,HIGH,MEDIUM,LOW
#   TRIVY_IGNORE_UNFIXED=true
#   TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db
#   TRIVY_USERNAME=...
#   TRIVY_PASSWORD=...
#   TRIVY_TOKEN=...                # for registries if needed
#   TRIVY_RATE_CAPACITY=60
#   TRIVY_RATE_REFILL_PER_SEC=2
#
# Notes:
# - Remote mode is auto-enabled when TRIVY_SERVER_URL is set.
# - Caching stores the raw Trivy JSON and normalized result.
# - For SBOM scans we accept CycloneDX JSON and normalize without invoking Trivy.

from __future__ import annotations

import concurrent.futures
import dataclasses
import hashlib
import json
import logging
import os
import platform
import re
import shlex
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# Optional faster JSON
try:
    import orjson as _json
    def _dumps(obj: Any) -> bytes:
        return _json.dumps(obj)
    def _loads(data: bytes) -> Any:
        return _json.loads(data)
except Exception:
    _json = None
    def _dumps(obj: Any) -> bytes:
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    def _loads(data: bytes) -> Any:
        return json.loads(data.decode("utf-8"))

# ----------------------------
# Data models (normalized)
# ----------------------------

SEVERITY_ORDER = {"NONE": 0, "UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

@dataclass(frozen=True)
class Vulnerability:
    id: str
    title: Optional[str]
    description: Optional[str]
    severity: str
    severity_score: int
    cvss_v3_score: Optional[float]
    cvss_vector: Optional[str]
    package_name: Optional[str]
    package_version: Optional[str]
    fixed_version: Optional[str]
    datasource: Optional[str]
    references: List[str] = field(default_factory=list)
    published_date: Optional[str] = None
    last_modified_date: Optional[str] = None

@dataclass(frozen=True)
class Finding:
    target: str                 # image, path, repo or sbom identifier
    type: str                   # "image"|"fs"|"repo"|"sbom"
    class_: str                 # Trivy result class (e.g., "os-pkgs","lang-pkgs","license","secret")
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class ScanResult:
    target: str
    scan_type: str              # "image"|"fs"|"repo"|"sbom"
    trivy_version: str
    findings: List[Finding] = field(default_factory=list)
    started_at: float = 0.0
    finished_at: float = 0.0
    raw: Optional[Dict[str, Any]] = None

# ----------------------------
# Configuration and controls
# ----------------------------

@dataclass
class RateLimitConfig:
    capacity: int = int(os.getenv("TRIVY_RATE_CAPACITY", "60"))
    refill_per_sec: float = float(os.getenv("TRIVY_RATE_REFILL_PER_SEC", "2"))

class TokenBucket:
    def __init__(self, capacity: int, refill_per_sec: float):
        self.capacity = float(capacity)
        self.refill = float(refill_per_sec)
        self.tokens = float(capacity)
        self.last = time.monotonic()
        self.lock = threading.Lock()

    def take(self, n: float = 1.0) -> bool:
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill)
            self.last = now
            if self.tokens >= n:
                self.tokens -= n
                return True
            return False

@dataclass
class TrivyConfig:
    path: str = os.getenv("TRIVY_PATH", "trivy")
    server_url: Optional[str] = os.getenv("TRIVY_SERVER_URL") or None
    timeout_sec: int = int(os.getenv("TRIVY_TIMEOUT_SEC", "300"))
    cache_dir: Path = Path(os.getenv("TRIVY_CACHE_DIR", str(Path.home() / ".cache" / "cybersec" / "trivy-connector")))
    cache_ttl_sec: int = int(os.getenv("TRIVY_CACHE_TTL_SEC", "600"))
    min_version: str = os.getenv("TRIVY_MIN_VERSION", "0.50.0")
    severity: str = os.getenv("TRIVY_SEVERITY", "CRITICAL,HIGH,MEDIUM,LOW")
    ignore_unfixed: bool = os.getenv("TRIVY_IGNORE_UNFIXED", "true").lower() == "true"
    db_repository: Optional[str] = os.getenv("TRIVY_DB_REPOSITORY") or None
    username: Optional[str] = os.getenv("TRIVY_USERNAME") or None
    password: Optional[str] = os.getenv("TRIVY_PASSWORD") or None
    token: Optional[str] = os.getenv("TRIVY_TOKEN") or None
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)

    def __post_init__(self):
        self.cache_dir.mkdir(parents=True, exist_ok=True)

# ----------------------------
# Exceptions
# ----------------------------

class TrivyError(Exception): ...
class TrivyNotFound(TrivyError): ...
class TrivyTimeout(TrivyError): ...
class TrivyAuthError(TrivyError): ...
class TrivyVersionError(TrivyError): ...

# ----------------------------
# Utilities
# ----------------------------

_VERSION_RX = re.compile(r"Version:\s*(\d+\.\d+\.\d+)")

def _compare_semver(a: str, b: str) -> int:
    def parse(v: str) -> Tuple[int, int, int]:
        x = v.strip().split("-")[0]
        maj, min_, patch = x.split(".")
        return int(maj), int(min_), int(patch)
    return (parse(a) > parse(b)) - (parse(a) < parse(b))

def _normalize_severity(s: Optional[str]) -> str:
    if not s:
        return "UNKNOWN"
    s = s.upper()
    return s if s in SEVERITY_ORDER else "UNKNOWN"

def _safe_target_name(kind: str, value: str) -> str:
    if kind == "sbom":
        return f"sbom:{Path(value).name}"
    if kind == "fs":
        return f"fs:{value}"
    if kind == "repo":
        return f"repo:{value}"
    return value

def _hash_request(kind: str, params: Mapping[str, Any]) -> str:
    payload = json.dumps({"kind": kind, "params": params}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()

# ----------------------------
# Connector
# ----------------------------

class TrivyConnector:
    def __init__(self, config: Optional[TrivyConfig] = None, logger: Optional[logging.Logger] = None):
        self.cfg = config or TrivyConfig()
        self.log = logger or logging.getLogger("cybersec.trivy")
        self.log.setLevel(logging.INFO)
        self._bucket = TokenBucket(self.cfg.rate_limit.capacity, self.cfg.rate_limit.refill_per_sec)
        self._trivy_version = None
        self._lock = threading.Lock()

    # Public API

    def ensure_available(self) -> str:
        if self._trivy_version:
            return self._trivy_version
        try:
            proc = subprocess.run(
                [self.cfg.path, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=20,
                check=False,
            )
        except FileNotFoundError:
            raise TrivyNotFound(f"Trivy binary not found at '{self.cfg.path}'")
        except subprocess.TimeoutExpired:
            raise TrivyTimeout("Timeout while checking trivy version")
        out = proc.stdout.decode("utf-8", "ignore")
        m = _VERSION_RX.search(out)
        if not m:
            raise TrivyError(f"Unable to parse trivy version from output: {out}")
        version = m.group(1)
        if _compare_semver(version, self.cfg.min_version) < 0:
            raise TrivyVersionError(f"Trivy {version} < required {self.cfg.min_version}")
        with self._lock:
            self._trivy_version = version
        self.log.info("trivy.available", extra={"version": version})
        return version

    def db_update(self, retries: int = 2) -> None:
        self.ensure_available()
        args = [self.cfg.path, "db", "update"]
        if self.cfg.db_repository:
            args += ["--db-repository", self.cfg.db_repository]
        self._exec_with_retry(args, retries=retries, label="db.update")

    def scan_image(self, image: str, extra_args: Optional[List[str]] = None) -> ScanResult:
        return self._scan("image", image, extra_args=extra_args)

    def scan_fs(self, path: str, extra_args: Optional[List[str]] = None) -> ScanResult:
        return self._scan("fs", path, extra_args=extra_args)

    def scan_repo(self, repo_url: str, extra_args: Optional[List[str]] = None) -> ScanResult:
        return self._scan("repo", repo_url, extra_args=extra_args)

    def scan_sbom_file(self, cyclonedx_json_path: str) -> ScanResult:
        # No Trivy invocation; parse CycloneDX JSON and normalize
        started = time.time()
        raw = self._read_file_json(cyclonedx_json_path)
        normalized = self._normalize_cyclonedx(raw, target=_safe_target_name("sbom", cyclonedx_json_path))
        finished = time.time()
        return ScanResult(
            target=normalized["target"],
            scan_type="sbom",
            trivy_version=self._trivy_version or "N/A",
            findings=normalized["findings"],
            started_at=started,
            finished_at=finished,
            raw=raw,
        )

    def scan_many(self, items: Sequence[Tuple[str, str]], max_workers: int = 4) -> List[ScanResult]:
        # items: list of (kind, target)
        self.ensure_available()
        results: List[ScanResult] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = []
            for kind, target in items:
                if kind not in {"image", "fs", "repo"}:
                    raise ValueError(f"Unsupported kind: {kind}")
                futs.append(ex.submit(self._scan, kind, target))
            for f in concurrent.futures.as_completed(futs):
                results.append(f.result())
        return results

    # Core scan

    def _scan(self, kind: str, target: str, extra_args: Optional[List[str]] = None) -> ScanResult:
        self.ensure_available()
        self._enforce_rate(f"{kind}:{target}")
        started = time.time()
        key = self._cache_key(kind, target, extra_args)
        cached = self._load_cache(key)
        if cached:
            self.log.info("trivy.cache.hit", extra={"key": key, "target": target, "kind": kind})
            return cached

        args = self._build_cmd(kind, target, extra_args or [])
        out = self._exec_with_retry(args, label=f"scan.{kind}", env=self._auth_env())
        raw = _loads(out)

        findings = self._normalize_trivy_json(raw, kind=kind)
        finished = time.time()
        result = ScanResult(
            target=_safe_target_name(kind, target),
            scan_type=kind,
            trivy_version=self._trivy_version or "unknown",
            findings=findings,
            started_at=started,
            finished_at=finished,
            raw=raw,
        )
        self._save_cache(key, result)
        return result

    # Command building

    def _build_cmd(self, kind: str, target: str, extra: List[str]) -> List[str]:
        base = [self.cfg.path]
        if self.cfg.server_url:
            base += ["client", "--remote", self.cfg.server_url]

        common = [
            "--quiet",
            "--format", "json",
            "--severity", self.cfg.severity,
            "--timeout", f"{self.cfg.timeout_sec}s",
        ]
        if self.cfg.ignore_unfixed:
            common.append("--ignore-unfixed")

        # For images we want os+library by default
        if kind == "image":
            cmd = base + ["image"] + common + ["--vuln-type", "os,library", target]
        elif kind == "fs":
            cmd = base + ["fs"] + common + [target]
        elif kind == "repo":
            cmd = base + ["repo"] + common + [target]
        else:
            raise ValueError(f"Unsupported kind: {kind}")

        if extra:
            cmd += extra

        return cmd

    # Execution with retry

    def _exec_with_retry(self, cmd: List[str], retries: int = 2, backoff: float = 1.5,
                         label: str = "exec", env: Optional[Dict[str, str]] = None) -> bytes:
        last_err = None
        for attempt in range(retries + 1):
            try:
                return self._exec(cmd, env=env)
            except TrivyTimeout as e:
                last_err = e
                self.log.warning("trivy.timeout", extra={"label": label, "attempt": attempt, "err": str(e)})
            except TrivyError as e:
                msg = str(e)
                last_err = e
                # Retry transient registry or network issues
                if any(x in msg.lower() for x in ("rate limit", "connection reset", "timeout", "tls handshake", "503", "502", "i/o timeout")):
                    self.log.warning("trivy.retry", extra={"label": label, "attempt": attempt, "err": msg})
                else:
                    break
            time.sleep((backoff ** attempt) if attempt else 0)
        assert last_err is not None
        raise last_err

    def _exec(self, cmd: List[str], env: Optional[Dict[str, str]] = None) -> bytes:
        try:
            self.log.info("trivy.exec", extra={"cmd": self._redact_cmd(cmd)})
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.cfg.timeout_sec,
                env=self._merged_env(env),
                check=False,
            )
        except FileNotFoundError:
            raise TrivyNotFound(f"Trivy binary not found at '{self.cfg.path}'")
        except subprocess.TimeoutExpired:
            raise TrivyTimeout(f"Trivy execution exceeded {self.cfg.timeout_sec}s")

        if proc.returncode not in (0, 5):  # Trivy uses 5 when vulnerabilities found with --exit-code 1; default 0
            stderr = proc.stderr.decode("utf-8", "ignore")
            stdout = proc.stdout.decode("utf-8", "ignore")
            msg = f"Trivy failed rc={proc.returncode} stderr={stderr.strip() or stdout[:2000]}"
            # Auth hints
            if "unauthorized" in msg.lower() or "authentication required" in msg.lower():
                raise TrivyAuthError(msg)
            raise TrivyError(msg)

        out = proc.stdout
        # Trivy may print non-JSON banners in some edge cases; try to strip
        out = self._strip_non_json(out)
        return out

    # Normalization

    def _normalize_trivy_json(self, raw: Dict[str, Any], kind: str) -> List[Finding]:
        results: List[Finding] = []
        # Trivy JSON top-level may contain Results (list). Some variants nest metadata elsewhere.
        trivy_results = raw.get("Results") or []
        class_map = {
            "os-pkgs": "os-pkgs",
            "lang-pkgs": "lang-pkgs",
            "secret": "secret",
            "license": "license",
            "misconfiguration": "misconfiguration",
            None: "unknown",
        }
        for res in trivy_results:
            target = res.get("Target") or raw.get("ArtifactName") or "unknown"
            class_ = class_map.get(res.get("Class"), res.get("Class") or "unknown")
            vulns = []
            for v in res.get("Vulnerabilities") or []:
                sev = _normalize_severity(v.get("Severity"))
                sev_score = SEVERITY_ORDER.get(sev, 0)
                cvss_score, cvss_vec = self._extract_cvss(v)
                references = v.get("References") or []
                if not references and v.get("PrimaryURL"):
                    references = [v["PrimaryURL"]]
                vulns.append(Vulnerability(
                    id=str(v.get("VulnerabilityID") or v.get("VulnID") or "UNKNOWN"),
                    title=v.get("Title"),
                    description=v.get("Description"),
                    severity=sev,
                    severity_score=sev_score,
                    cvss_v3_score=cvss_score,
                    cvss_vector=cvss_vec,
                    package_name=v.get("PkgName"),
                    package_version=v.get("InstalledVersion"),
                    fixed_version=v.get("FixedVersion"),
                    datasource=(v.get("DataSource") or {}).get("ID") if isinstance(v.get("DataSource"), dict) else None,
                    references=references,
                    published_date=v.get("PublishedDate"),
                    last_modified_date=v.get("LastModifiedDate"),
                ))
            metadata = {
                "type": res.get("Type"),
                "target": target,
                "epoch_ms": int(time.time() * 1000),
            }
            results.append(Finding(
                target=_safe_target_name(kind, target),
                type=kind,
                class_=class_,
                vulnerabilities=vulns,
                metadata=metadata,
            ))
        return results

    def _normalize_cyclonedx(self, cd: Dict[str, Any], target: str) -> Dict[str, Any]:
        # CycloneDX JSON 1.4+; vulnerabilities under "vulnerabilities"
        vulns = cd.get("vulnerabilities") or []
        components = {c.get("bom-ref") or c.get("purl") or c.get("name"): c for c in (cd.get("components") or [])}
        findings_map: Dict[str, List[Vulnerability]] = {}
        for v in vulns:
            ratings = v.get("ratings") or []
            cvss_score = None
            cvss_vec = None
            severity = "UNKNOWN"
            if ratings:
                # pick highest score
                best = max(ratings, key=lambda r: r.get("score") or 0)
                cvss_score = best.get("score")
                method = (best.get("method") or "").upper()
                cvss_vec = best.get("vector")
                # Map severity if present
                sev = best.get("severity")
                severity = _normalize_severity(sev if sev else None)
            for aff in v.get("affects") or []:
                ref = aff.get("ref")
                comp = components.get(ref, {})
                pkg_name = comp.get("name")
                pkg_ver = (comp.get("version") or None)
                finding_key = pkg_name or "unknown"
                if finding_key not in findings_map:
                    findings_map[finding_key] = []
                findings_map[finding_key].append(Vulnerability(
                    id=str(v.get("id") or "UNKNOWN"),
                    title=v.get("source", {}).get("name") or v.get("description"),
                    description=v.get("description"),
                    severity=severity,
                    severity_score=SEVERITY_ORDER.get(severity, 0),
                    cvss_v3_score=cvss_score,
                    cvss_vector=cvss_vec,
                    package_name=pkg_name,
                    package_version=pkg_ver,
                    fixed_version=None,
                    datasource=v.get("source", {}).get("url"),
                    references=[a for a in (v.get("advisories") or []) if isinstance(a, str)] or [],
                    published_date=None,
                    last_modified_date=None,
                ))
        findings = []
        for k, vulns_list in findings_map.items():
            findings.append(Finding(
                target=target,
                type="sbom",
                class_="lang-pkgs",
                vulnerabilities=vulns_list,
                metadata={"component": k},
            ))
        return {"target": target, "findings": findings}

    # Helpers

    def _extract_cvss(self, v: Mapping[str, Any]) -> Tuple[Optional[float], Optional[str]]:
        # Trivy CVSS structure example:
        # "CVSS": {"nvd": {"V3Vector": "...", "V3Score": 7.5}}
        cvss = v.get("CVSS") or {}
        for source in ("nvd", "redhat", "ghsa", "osv", "gost", "suse", "oracle"):
            node = cvss.get(source) or {}
            score = node.get("V3Score") or node.get("v3Score")
            vec = node.get("V3Vector") or node.get("vector")
            if score:
                return float(score), vec
        # Fallback to vendorScore
        if v.get("CVSSScore"):
            return float(v["CVSSScore"]), None
        return None, None

    def _cache_key(self, kind: str, target: str, extra: Optional[List[str]]) -> str:
        params = {
            "target": target,
            "severity": self.cfg.severity,
            "ignore_unfixed": self.cfg.ignore_unfixed,
            "remote": bool(self.cfg.server_url),
            "extra": extra or [],
            "version": self._trivy_version or "",
        }
        return _hash_request(kind, params)

    def _cache_path(self, key: str) -> Path:
        return self.cfg.cache_dir / f"{key}.json"

    def _load_cache(self, key: str) -> Optional[ScanResult]:
        p = self._cache_path(key)
        if not p.exists():
            return None
        if (time.time() - p.stat().st_mtime) > self.cfg.cache_ttl_sec:
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass
            return None
        try:
            raw = _loads(p.read_bytes())
            # Reinflate dataclasses
            findings = []
            for f in raw["findings"]:
                vulns = [Vulnerability(**vv) for vv in f["vulnerabilities"]]
                findings.append(Finding(
                    target=f["target"], type=f["type"], class_=f["class_"],
                    vulnerabilities=vulns, metadata=f.get("metadata", {}),
                ))
            return ScanResult(
                target=raw["target"],
                scan_type=raw["scan_type"],
                trivy_version=raw.get("trivy_version", "unknown"),
                findings=findings,
                started_at=raw.get("started_at", 0.0),
                finished_at=raw.get("finished_at", 0.0),
                raw=raw.get("raw"),
            )
        except Exception as e:
            self.log.warning("trivy.cache.read_error", extra={"err": str(e)})
            return None

    def _save_cache(self, key: str, result: ScanResult) -> None:
        p = self._cache_path(key)
        try:
            payload = {
                "target": result.target,
                "scan_type": result.scan_type,
                "trivy_version": result.trivy_version,
                "findings": [
                    {
                        "target": f.target,
                        "type": f.type,
                        "class_": f.class_,
                        "vulnerabilities": [dataclasses.asdict(v) for v in f.vulnerabilities],
                        "metadata": f.metadata,
                    }
                    for f in result.findings
                ],
                "started_at": result.started_at,
                "finished_at": result.finished_at,
                "raw": result.raw,  # raw trivy json
            }
            tmp = p.with_suffix(".tmp")
            tmp.write_bytes(_dumps(payload))
            tmp.replace(p)
        except Exception as e:
            self.log.warning("trivy.cache.write_error", extra={"err": str(e)})

    def _strip_non_json(self, out: bytes) -> bytes:
        s = out.decode("utf-8", "ignore").strip()
        # Try to locate the first '{' and last '}' for JSON
        start = s.find("{")
        end = s.rfind("}")
        if start != -1 and end != -1 and end > start:
            s = s[start:end+1]
        return s.encode("utf-8")

    def _merged_env(self, extra: Optional[Dict[str, str]]) -> Dict[str, str]:
        env = os.environ.copy()
        # Registry auth and tokens if needed by Trivy
        if self.cfg.username is not None:
            env["TRIVY
