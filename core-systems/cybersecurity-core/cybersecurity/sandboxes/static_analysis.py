# cybersecurity-core/cybersecurity/sandboxes/static_analysis.py
# SPDX-License-Identifier: MIT
"""
Static Analysis Sandbox (industrial-grade)

- Unified sandboxed runner for multiple static analyzers.
- Resource limits (CPU / virtual memory / open files) on POSIX via `resource`.
- Hard timeouts with process group kill.
- Parallel execution with bounded workers.
- Tool autodiscovery & graceful degradation when binaries are absent.
- Normalized Finding model (severity, rule, location, fingerprints).
- Parsers for common tools: Bandit, Semgrep, Gitleaks, Trivy FS, pip-audit,
  npm audit, Hadolint, tfsec, Checkov. (Parsed when tool present.)
- Export to JSON and SARIF 2.1.0 minimal profile.
- CLI for typical workflows.

Note:
This module has no external Python deps. It expects scanners to be installed
as system binaries available in PATH. It is safe to import in any environment;
missing tools are skipped with informative diagnostics.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import datetime as dt
import enum
import hashlib
import json
import logging
import os
import platform
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# -----------------------------
# Logging (JSON formatter)
# -----------------------------

class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": dt.datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "lvl": record.levelname,
            "log": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def _get_logger() -> logging.Logger:
    logger = logging.getLogger("cybersecurity.sandboxes.static_analysis")
    if not logger.handlers:
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(_JsonFormatter())
        logger.addHandler(h)
        logger.setLevel(logging.INFO)
    return logger


log = _get_logger()

# -----------------------------
# Utilities & OS features
# -----------------------------

_POSIX = os.name == "posix"

try:
    if _POSIX:
        import resource  # type: ignore
    else:
        resource = None  # type: ignore
except Exception:  # pragma: no cover
    resource = None  # type: ignore


def which(cmd: str) -> Optional[str]:
    """Return full path of command in PATH or None."""
    for p in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(p) / cmd
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def read_text_safely(p: Path, limit: int = 10_000_000) -> str:
    data = p.read_bytes()
    if len(data) > limit:
        return data[:limit].decode("utf-8", errors="replace")
    return data.decode("utf-8", errors="replace")


# -----------------------------
# Finding model & severities
# -----------------------------

class Severity(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


_SEVERITY_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
    Severity.UNKNOWN: 0,
}


def normalize_severity(s: str | None) -> Severity:
    if not s:
        return Severity.UNKNOWN
    s = s.strip().lower()
    if s in ("critical", "crit", "blocker"):
        return Severity.CRITICAL
    if s in ("high", "error", "sev-high"):
        return Severity.HIGH
    if s in ("medium", "moderate", "warn", "warning"):
        return Severity.MEDIUM
    if s in ("low", "minor"):
        return Severity.LOW
    if s in ("info", "informational", "note", "style"):
        return Severity.INFO
    return Severity.UNKNOWN


@dataclass
class Location:
    path: str
    line: Optional[int] = None
    column: Optional[int] = None


@dataclass
class Finding:
    tool: str
    rule_id: str
    message: str
    severity: Severity
    location: Location
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    recommendation: Optional[str] = None
    fingerprint: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def compute_fingerprint(self) -> str:
        base = f"{self.tool}|{self.rule_id}|{self.location.path}|{self.location.line}|{self.message}"
        fp = hashlib.sha1(base.encode("utf-8", errors="replace")).hexdigest()
        self.fingerprint = fp
        return fp


@dataclass
class ScanReport:
    root: str
    started_at: str
    finished_at: str
    findings: List[Finding] = field(default_factory=list)
    tools: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # name -> meta
    errors: List[str] = field(default_factory=list)

    def add_tool_meta(self, name: str, available: bool, version: Optional[str], cmd: str) -> None:
        self.tools[name] = {
            "available": available,
            "version": version,
            "cmd": cmd,
        }

    def summary(self) -> Dict[str, Any]:
        counts: Dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return {
            "total": len(self.findings),
            "by_severity": counts,
        }


# -----------------------------
# Sandbox runner
# -----------------------------

@dataclass
class SandboxLimits:
    timeout_sec: int = 300
    cpu_seconds: Optional[int] = 120
    memory_bytes: Optional[int] = 1_500_000_000  # ~1.5GB
    open_files: Optional[int] = 1024
    env_allowlist: Tuple[str, ...] = ("PATH",)


class SandboxRunner:
    """
    Execute external tools with process isolation features:
    - Create a new process group
    - Enforce wall-clock timeout
    - On POSIX, set resource limits (CPU, AS, NOFILE)
    - Redact environment to an allowlist
    """

    def __init__(self, limits: SandboxLimits):
        self.limits = limits

    def _posix_prlimit(self) -> Optional[callable]:
        if not (_POSIX and resource):
            return None

        def _apply_limits():
            # CPU seconds
            if self.limits.cpu_seconds:
                resource.setrlimit(resource.RLIMIT_CPU, (self.limits.cpu_seconds, self.limits.cpu_seconds))
            # Virtual memory
            if self.limits.memory_bytes:
                resource.setrlimit(resource.RLIMIT_AS, (self.limits.memory_bytes, self.limits.memory_bytes))
            # Open files
            if self.limits.open_files:
                resource.setrlimit(resource.RLIMIT_NOFILE, (self.limits.open_files, self.limits.open_files))
            # New process group
            os.setsid()
        return _apply_limits

    def run(self, cmd: Sequence[str], cwd: Optional[Path] = None) -> Tuple[int, bytes, bytes]:
        env = {k: os.environ.get(k, "") for k in self.limits.env_allowlist}
        preexec = self._posix_prlimit()
        start = time.time()
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(cwd) if cwd else None,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                preexec_fn=preexec,
                creationflags=0 if _POSIX else subprocess.CREATE_NEW_PROCESS_GROUP,  # on Windows
            )
            try:
                out, err = proc.communicate(timeout=self.limits.timeout_sec)
            except subprocess.TimeoutExpired:
                self._kill_tree(proc)
                return 124, b"", f"timeout after {self.limits.timeout_sec}s".encode()
            return proc.returncode, out or b"", err or b""
        except FileNotFoundError as e:
            return 127, b"", str(e).encode()
        except Exception as e:  # pragma: no cover
            return 126, b"", str(e).encode()
        finally:
            elapsed = time.time() - start
            log.info(json.dumps({"event": "cmd_done", "cmd": cmd, "elapsed_s": round(elapsed, 3)}))

    def _kill_tree(self, proc: subprocess.Popen) -> None:
        try:
            if _POSIX:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.send_signal(signal.CTRL_BREAK_EVENT)
                proc.kill()
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


# -----------------------------
# Analyzer abstraction
# -----------------------------

@dataclass
class AnalyzerResult:
    tool: str
    raw_stdout: bytes
    raw_stderr: bytes
    exit_code: int
    findings: List[Finding]


class Analyzer:
    name: str = "analyzer"
    cmdline: str = ""

    def __init__(self, root: Path):
        self.root = root

    @staticmethod
    def _cmd_exists(bin_name: str) -> bool:
        return which(bin_name) is not None

    def available(self) -> bool:
        """Override if needed."""
        return False

    def version_cmd(self) -> Optional[List[str]]:
        return None

    def build_cmd(self) -> List[str]:
        raise NotImplementedError

    def parse(self, stdout: bytes, stderr: bytes, code: int) -> List[Finding]:
        raise NotImplementedError

    def tool_version(self) -> Optional[str]:
        vc = self.version_cmd()
        if not vc:
            return None
        runner = SandboxRunner(SandboxLimits(timeout_sec=10, cpu_seconds=5, memory_bytes=256_000_000))
        code, out, _ = runner.run(vc, cwd=self.root)
        if code == 0:
            return (out.decode("utf-8", errors="ignore").strip().splitlines() or [""])[0][:120]
        return None

    def run(self, runner: SandboxRunner) -> AnalyzerResult:
        cmd = self.build_cmd()
        code, out, err = runner.run(cmd, cwd=self.root)
        findings: List[Finding] = []
        try:
            findings = self.parse(out, err, code)
        except Exception as e:
            log.error(json.dumps({"event": "parse_error", "tool": self.name, "err": str(e)}))
        return AnalyzerResult(tool=self.name, raw_stdout=out, raw_stderr=err, exit_code=code, findings=findings)


# -----------------------------
# Concrete analyzers
# -----------------------------

class BanditAnalyzer(Analyzer):
    name = "bandit"

    def available(self) -> bool:
        return self._cmd_exists("bandit")

    def version_cmd(self) -> Optional[List[str]]:
        return ["bandit", "--version"]

    def build_cmd(self) -> List[str]:
        return ["bandit", "-r", ".", "-f", "json", "--quiet"]

    def parse(self, stdout: bytes, stderr: bytes, code: int) -> List[Finding]:
        data = json.loads(stdout.decode("utf-8", errors="ignore") or "{}")
        out: List[Finding] = []
        for r in data.get("results", []):
            path = r.get("filename") or r.get("file_path") or ""
            line = r.get("line_number")
            sev = normalize_severity(r.get("issue_severity"))
            rule = str(r.get("test_id") or "BANDIT")
            msg = str(r.get("issue_text") or "Bandit finding")
            f = Finding(
                tool=self.name,
                rule_id=rule,
                message=msg,
                severity=sev,
                location=Location(path=path, line=line),
                recommendation=r.get("more_info"),
                extra={"code": r.get("code")},
            )
            f.compute_fingerprint()
            out.append(f)
        return out


class SemgrepAnalyzer(Analyzer):
    name = "semgrep"

    def available(self) -> bool:
        return self._cmd_exists("semgrep")

    def version_cmd(self) -> Optional[List[str]]:
        return ["semgrep", "--version"]

    def build_cmd(self) -> List[str]:
        # --config auto leverages language auto-detection
        return ["semgrep", "--config", "auto", "--json", "--quiet"]

    def parse(self, stdout: bytes, stderr: bytes, code: int) -> List[Finding]:
        data = json.loads(stdout.decode("utf-8", errors="ignore") or "{}")
        out: List[Finding] = []
        for r in data.get("results", []):
            sev = normalize_severity((r.get("extra") or {}).get("severity"))
            rule = r.get("check_id") or "SEMgrep"
            msg = (r.get("extra") or {}).get("message") or "Semgrep finding"
            path = (r.get("path") or "") if isinstance(r.get("path"), str) else ""
            start = ((r.get("start") or {}).get("line")) if isinstance(r.get("start"), dict) else None
            cwe = None
            for m in (r.get("extra") or {}).get("metadata", {}) or {}:
                pass  # not always stable schema
            cwe = ((r.get("extra") or {}).get("metadata") or {}).get("cwe")
            f = Finding(
                tool=self.name,
                rule_id=str(rule),
                message=str(msg),
                severity=sev,
                location=Location(path=path, line=start),
                cwe=str(cwe) if cwe else None,
            )
            f.compute_fingerprint()
            out.append(f)
        return out


class GitleaksAnalyzer(Analyzer):
    name = "gitleaks"

    def available(self) -> bool:
        return self._cmd_exists("gitleaks")

    def version_cmd(self) -> Optional[List[str]]:
        return ["gitleaks", "version"]

    def build_cmd(self) -> List[str]:
        # Report to stdout in JSON
        return ["gitleaks", "detect", "--no-banner", "--redact", "--report-format", "json", "--report-path", "-"]

    def parse(self, stdout: bytes, stderr: bytes, code: int) -> List[Finding]:
        text = stdout.decode("utf-8", errors="ignore").strip()
        if not text:
            return []
        # gitleaks may emit single JSON object or array depending on version
        try:
            data = json.loads(text)
        except Exception:
            # sometimes multiple json objects concatenated; naive fix
            data = []
            for line in text.splitlines():
                try:
                    data.append(json.loads(line))
                except Exception:
                    continue
        arr = data if isinstance(data, list) else data.get("findings", [])
        out: List[Finding] = []
        for it in arr or []:
            rule = it.get("RuleID") or it.get("ruleID") or "GITLEAKS"
            path = it.get("File") or it.get("file") or ""
            line = it.get("StartLine") or it.get("startLine")
            sev = normalize_severity("high")
            msg = it.get("Description") or it.get("description") or "Secret detected"
            f = Finding(
                tool=self.name,
                rule_id=str(rule),
                message=str(msg),
                severity=sev,
                location=Location(path=str(path), line=int(line) if isinstance(line, int) else None),
                recommendation="Remove secret, rotate credentials, add pre-commit secret scanning.",
                extra={"entropy": it.get("Entropy")},
            )
            f.compute_fingerprint()
            out.append(f)
        return out


class TrivyFSAnalyzer(Analyzer):
    name = "trivy-fs"

    def available(self) -> bool:
        return self._cmd_exists("trivy")

    def version_cmd(self) -> Optional[List[str]]:
        return ["trivy", "--version"]

    def build_cmd(self) -> List[str]:
        return [
            "trivy", "fs", ".", "--quiet", "--security-checks", "vuln,config", "--format", "json",
            "--ignore-unfixed",
        ]

    def parse(self, stdout: bytes, stderr: bytes, code: int) -> List[Finding]:
        data = json.loads(stdout.decode("utf-8", errors="ignore") or "{}")
        out: List[Finding] = []
        for r in data.get("Results", []) or []:
            target = r.get("Target") or ""
            # Vulns
            for v in r.get("Vulnerabilities", []) or []:
                sev = normalize_severity(v.get("Severity"))
                rule = v.get("VulnerabilityID") or "TRIVY-VULN"
                msg = f"{v.get('PkgName')} {v.get('InstalledVersion')} -> {v.get('FixedVersion') or 'n/a'}"
                f = Finding(
                    tool=self.name,
                    rule_id=str(rule),
                    message=msg,
                    severity=sev,
                    location=Location(path=str(target)),
                    cwe=(v.get("CweIDs") or [None])[0],
                    extra={"cvss": v.get("CVSS"), "primary_url": v.get("PrimaryURL")},
                )
                f.compute_fingerprint()
                out.append(f)
            # Misconfigurations
            for m in r.get("Misconfigurations", []) or []:
                sev = normalize_severity(m.get("Severity"))
                rule = m.get("ID") or "TRIVY-MISCONF"
                msg = m.get("Message") or m.get("Title") or "Configuration issue"
                loc = Location(path=str(target))
                f = Finding(
                    tool=self.name, rule_id=str(rule), message=str(msg), severity=sev, location=loc,
                    recommendation=m.get("Resolution"),
                    extra={"cause": m.get("CauseMetadata")},
                )
                f.compute_fingerprint()
                out.append(f)
        return out


class PipAuditAnalyzer(Analyzer):
    name = "pip-audit"

    def available(self) -> bool:
        return self._cmd_exists("pip-audit")

    def version_cmd(self) -> Optional[List[str]]:
        return ["pip-audit", "--version"]

    def build_cmd(self) -> List[str]:
        # Prefer requirements.txt if present; fall back to project
        req = self.root / "requirements.txt"
        if req.exists():
            return ["pip-audit", "-r", "requirements.txt", "-f", "json"]
        return ["pip-audit", "-f", "json"]

    def parse(self, stdout: bytes, stderr: bytes, code: int) -> List[Finding]:
        if not stdout:
            return []
        data = json.loads(stdout.decode("utf-8", errors="ignore"))
        out: List[Finding] = []
        for v in data.get("vulnerabilities", []) or []:
            sev = normalize_severity((v.get("fix_versions") and "medium") or "low")
            rule = (v.get("id") or "PIP-AUDIT")
            msg = f"{v.get('dependency',{}).get('name')} {v.get('dependency',{}).get('version')} vulnerable"
            f = Finding(
                tool=self.name, rule_id=str(rule), message=msg, severity=sev,
                location=Location(path="requirements.txt" if (self.root / "requirements.txt").exists() else "."),
                extra={"advisory": v.get("advisory")},
            )
            f.compute_fingerprint()
            out.append(f)
        return out


class NpmAuditAnalyzer(Analyzer):
    name = "npm-audit"

    def available(self) -> bool:
        return self._cmd_exists("npm")

    def version_cmd(self) -> Optional[List[str]]:
        return ["npm", "--version"]

    def build_cmd(self) -> List[str]:
        # npm audit --json returns structured output, but may exit non-zero if vulns found
        return ["npm", "audit", "--json", "--audit-level=low"]

    def parse(self, stdout: bytes, stderr: bytes, code: int) -> List[Finding]:
        if not stdout:
            return []
        data = json.loads(stdout.decode("utf-8", errors="ignore"))
        out: List[Finding] = []
        advisories = data.get("vulnerabilities", {}) or {}
        for pkg, meta in advisories.items():
            sev = normalize_severity(meta.get("severity"))
            count = meta.get("via") if isinstance(meta.get("via"), list) else []
            msg = f"{pkg}: {len(count)} advisories"
            f = Finding(
                tool=self.name, rule_id="NPM-AUDIT", message=msg, severity=sev,
                location=Location(path="package-lock.json" if (self.root / "package-lock.json").exists() else "package.json"),
                extra={"dependency": pkg, "via": meta.get("via")},
            )
            f.compute_fingerprint()
            out.append(f)
        return out


class HadolintAnalyzer(Analyzer):
    name = "hadolint"

    def available(self) -> bool:
        return self._cmd_exists("hadolint") and any(
            p.name.lower() == "dockerfile" for p in self.root.rglob("Dockerfile")
        )

    def version_cmd(self) -> Optional[List[str]]:
        return ["hadolint", "--version"]

    def build_cmd(self) -> List[str]:
        # Analyze all Dockerfiles in repo
        files = [str(p.relative_to(self.root)) for p in self.root.rglob("Dockerfile")]
        return ["hadolint", "-f", "json", *files] if files else ["hadolint", "-f", "json", "Dockerfile"]

    def parse(self, stdout: bytes, stderr: bytes, code: int) -> List[Finding]:
        if not stdout:
            return []
        arr = json.loads(stdout.decode("utf-8", errors="ignore") or "[]")
        out: List[Finding] = []
        for it in arr or []:
            sev = normalize_severity(it.get("level"))
            rule = it.get("code") or "HADOLINT"
            msg = it.get("message") or "Dockerfile issue"
            f = Finding(
                tool=self.name, rule_id=str(rule), message=str(msg), severity=sev,
                location=Location(path=str(it.get("file") or "Dockerfile"), line=it.get("line")),
                recommendation=it.get("documentation"),
            )
            f.compute_fingerprint()
            out.append(f)
        return out


class TfsecAnalyzer(Analyzer):
    name = "tfsec"

    def available(self) -> bool:
        return self._cmd_exists("tfsec")

    def version_cmd(self) -> Optional[List[str]]:
        return ["tfsec", "--version"]

    def build_cmd(self) -> List[str]:
        return ["tfsec", ".", "--format", "json", "--no-color", "--soft-fail"]

    def parse(self, stdout: bytes, stderr: bytes, code: int) -> List[Finding]:
        if not stdout:
            return []
        data = json.loads(stdout.decode("utf-8", errors="ignore") or "{}")
        out: List[Finding] = []
        for r in data.get("results", []) or []:
            sev = normalize_severity(r.get("severity"))
            rule = r.get("rule_id") or "TFSEC"
            msg = r.get("description") or "Terraform misconfiguration"
            loc = r.get("location") or {}
            f = Finding(
                tool=self.name, rule_id=str(rule), message=str(msg), severity=sev,
                location=Location(path=str(loc.get("filename") or "."), line=loc.get("start_line")),
                recommendation=r.get("resolution"),
                extra={"impact": r.get("impact")},
            )
            f.compute_fingerprint()
            out.append(f)
        return out


class CheckovAnalyzer(Analyzer):
    name = "checkov"

    def available(self) -> bool:
        return self._cmd_exists("checkov")

    def version_cmd(self) -> Optional[List[str]]:
        return ["checkov", "--version"]

    def build_cmd(self) -> List[str]:
        # checkov scans IaC (Terraform, CFN, K8s, etc.) and exits non-zero when findings exist
        return ["checkov", "-d", ".", "-o", "json"]

    def parse(self, stdout: bytes, stderr: bytes, code: int) -> List[Finding]:
        if not stdout:
            return []
        data = json.loads(stdout.decode("utf-8", errors="ignore") or "{}")
        out: List[Finding] = []
        for r in data.get("results", {}).get("failed_checks", []) or []:
            sev = normalize_severity(r.get("severity"))
            rule = r.get("check_id") or "CHECKOV"
            msg = r.get("check_name") or "IaC policy violation"
            f = Finding(
                tool=self.name, rule_id=str(rule), message=str(msg), severity=sev,
                location=Location(path=str(r.get("file_path") or "."), line=r.get("file_line_range", [None])[0]),
                recommendation=r.get("guideline"),
                extra={"bc_check_id": r.get("bc_check_id"), "resource": r.get("resource")},
            )
            f.compute_fingerprint()
            out.append(f)
        return out


# -----------------------------
# Orchestrator
# -----------------------------

DEFAULT_ANALYZERS = (
    BanditAnalyzer,
    SemgrepAnalyzer,
    GitleaksAnalyzer,
    TrivyFSAnalyzer,
    PipAuditAnalyzer,
    NpmAuditAnalyzer,
    HadolintAnalyzer,
    TfsecAnalyzer,
    CheckovAnalyzer,
)


@dataclass
class SandboxConfig:
    timeout_sec: int = 420
    cpu_seconds: Optional[int] = 180
    memory_bytes: Optional[int] = 2_000_000_000
    open_files: Optional[int] = 2048
    parallelism: int = max(1, (os.cpu_count() or 2) // 2)


class StaticAnalysisSandbox:
    def __init__(self, root: Path, config: SandboxConfig = SandboxConfig()):
        self.root = root.resolve()
        self.config = config
        self.runner = SandboxRunner(
            SandboxLimits(
                timeout_sec=config.timeout_sec,
                cpu_seconds=config.cpu_seconds,
                memory_bytes=config.memory_bytes,
                open_files=config.open_files,
                env_allowlist=("PATH",),
            )
        )
        self._lock = threading.RLock()

    def _instantiate(self, analyzer_cls: type[Analyzer]) -> Optional[Analyzer]:
        a = analyzer_cls(self.root)
        try:
            if a.available():
                return a
            return None
        except Exception as e:
            log.error(json.dumps({"event": "analyzer_init_fail", "tool": analyzer_cls.__name__, "err": str(e)}))
            return None

    def _auto_select(self, analyzers: Sequence[type[Analyzer]] = DEFAULT_ANALYZERS) -> List[Analyzer]:
        selected: List[Analyzer] = []
        for cls in analyzers:
            inst = self._instantiate(cls)
            if inst:
                selected.append(inst)
        return selected

    def scan(self, analyzers: Optional[Sequence[type[Analyzer]]] = None) -> ScanReport:
        report = ScanReport(
            root=str(self.root),
            started_at=dt.datetime.utcnow().isoformat() + "Z",
            finished_at="",
        )
        tool_instances = self._auto_select(analyzers or DEFAULT_ANALYZERS)
        if not tool_instances:
            report.errors.append("no_tools_available")
            report.finished_at = dt.datetime.utcnow().isoformat() + "Z"
            return report

        # Tool versions/meta
        for t in tool_instances:
            ver = None
            try:
                ver = t.tool_version()
            except Exception:
                pass
            report.add_tool_meta(t.name, True, ver, " ".join(shlex.quote(x) for x in t.build_cmd()))

        # Parallel execution
        findings: List[Finding] = []
        errors: List[str] = []

        def _run_tool(tool: Analyzer) -> Tuple[str, AnalyzerResult]:
            res = tool.run(self.runner)
            return tool.name, res

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.parallelism) as ex:
            fut_to_tool = {ex.submit(_run_tool, t): t for t in tool_instances}
            for fut in concurrent.futures.as_completed(fut_to_tool):
                tool = fut_to_tool[fut]
                try:
                    name, res = fut.result()
                    if res.exit_code in (0, 1):  # many tools use 1 to signal findings
                        findings.extend(res.findings)
                    else:
                        err = res.raw_stderr.decode("utf-8", errors="ignore").strip()
                        errors.append(f"{name}: exit={res.exit_code} err={err[:300]}")
                except Exception as e:
                    errors.append(f"{tool.name}: failed {e}")

        # Finalize
        for f in findings:
            if not f.fingerprint:
                f.compute_fingerprint()
        findings.sort(key=lambda x: (-_SEVERITY_ORDER.get(x.severity, 0), x.tool, x.location.path or "", (x.location.line or 0)))

        report.findings = findings
        report.errors.extend(errors)
        report.finished_at = dt.datetime.utcnow().isoformat() + "Z"
        return report

    # -------------------------
    # Exporters
    # -------------------------
    @staticmethod
    def to_json(report: ScanReport) -> str:
        def _ser(o: Any) -> Any:
            if isinstance(o, enum.Enum):
                return o.value
            if dataclasses.is_dataclass(o):
                return dataclasses.asdict(o)
            if isinstance(o, (dt.datetime, )):
                return o.isoformat()
            return o

        return json.dumps(dataclasses.asdict(report), default=_ser, ensure_ascii=False, indent=2)

    @staticmethod
    def to_sarif(report: ScanReport) -> str:
        # Minimal SARIF 2.1.0 export (one run, all tools as rules grouped by tool name)
        rules: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []

        for f in report.findings:
            rule_key = f"{f.tool}:{f.rule_id}"
            if rule_key not in rules:
                rules[rule_key] = {
                    "id": rule_key,
                    "name": f.rule_id,
                    "shortDescription": {"text": f"{f.tool} {f.rule_id}"},
                    "fullDescription": {"text": f.message[:200]},
                    "properties": {
                        "tool": f.tool,
                        "severity": f.severity.value,
                        "cwe": f.cwe,
                        "owasp": f.owasp,
                    },
                }
            results.append({
                "ruleId": rule_key,
                "level": _sarif_level(f.severity),
                "message": {"text": f.message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.location.path},
                        "region": {"startLine": f.location.line or 1}
                    }
                }],
                "fingerprints": {"primaryLocationLineHash": f.fingerprint or f.compute_fingerprint()},
            })

        sarif = {
            "version": "2.1.0",
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "StaticAnalysisSandbox",
                        "informationUri": "https://example.local/static-sandbox",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": True,
                    "workingDirectory": {"uri": report.root},
                    "properties": {
                        "startedAt": report.started_at,
                        "finishedAt": report.finished_at,
                        "summary": report.summary(),
                        "tools": report.tools,
                        "errors": report.errors,
                    }
                }]
            }]
        }
        return json.dumps(sarif, ensure_ascii=False, indent=2)


def _sarif_level(sev: Severity) -> str:
    # SARIF: "error" | "warning" | "note" | "none"
    if sev in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if sev == Severity.MEDIUM:
        return "warning"
    if sev in (Severity.LOW, Severity.INFO):
        return "note"
    return "none"


# -----------------------------
# CLI
# -----------------------------

def _cli() -> int:
    p = argparse.ArgumentParser(
        prog="static_analysis",
        description="Static Analysis Sandbox — run multiple scanners with resource limits and aggregate findings.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          python static_analysis.py --path . --json out.json --sarif out.sarif
          python static_analysis.py --path repo --timeout 300 --cpu 120 --mem 1500 --parallel 4
        """),
    )
    p.add_argument("--path", required=True, help="Path to project root")
    p.add_argument("--timeout", type=int, default=SandboxConfig.timeout_sec, help="Global timeout per tool (sec)")
    p.add_argument("--cpu", type=int, default=SandboxConfig.cpu_seconds or 0, help="CPU time limit (sec, POSIX)")
    p.add_argument("--mem", type=int, default=(SandboxConfig.memory_bytes or 0) // 1_000_000, help="Memory limit (MB, POSIX)")
    p.add_argument("--nofile", type=int, default=SandboxConfig.open_files, help="Open files limit (POSIX)")
    p.add_argument("--parallel", type=int, default=SandboxConfig.parallelism, help="Concurrent tools")
    p.add_argument("--json", help="Write JSON report to file")
    p.add_argument("--sarif", help="Write SARIF report to file")
    p.add_argument("--only", nargs="*", help="Run only these tools by name (case-insensitive)")
    args = p.parse_args()

    root = Path(args.path).resolve()
    cfg = SandboxConfig(
        timeout_sec=int(args.timeout),
        cpu_seconds=int(args.cpu) if args.cpu > 0 else None,
        memory_bytes=int(args.mem) * 1_000_000 if args.mem > 0 else None,
        open_files=int(args.nofile) if args.nofile else None,
        parallelism=max(1, int(args.parallel)),
    )
    sandbox = StaticAnalysisSandbox(root=root, config=cfg)

    selected_map = {cls(None).__class__.__name__.replace("Analyzer", "").lower(): cls for cls in DEFAULT_ANALYZERS}  # type: ignore
    analyzers: Optional[List[type[Analyzer]]] = None
    if args.only:
        m: List[type[Analyzer]] = []
        name_map = {
            "bandit": BanditAnalyzer,
            "semgrep": SemgrepAnalyzer,
            "gitleaks": GitleaksAnalyzer,
            "trivy-fs": TrivyFSAnalyzer,
            "trivy": TrivyFSAnalyzer,
            "pip-audit": PipAuditAnalyzer,
            "npm-audit": NpmAuditAnalyzer,
            "hadolint": HadolintAnalyzer,
            "tfsec": TfsecAnalyzer,
            "checkov": CheckovAnalyzer,
        }
        for n in args.only:
            key = n.strip().lower()
            if key in name_map:
                m.append(name_map[key])
        analyzers = m

    report = sandbox.scan(analyzers=analyzers)

    if args.json:
        Path(args.json).write_text(StaticAnalysisSandbox.to_json(report), encoding="utf-8")
        log.info(json.dumps({"event": "written", "format": "json", "path": args.json}))
    if args.sarif:
        Path(args.sarif).write_text(StaticAnalysisSandbox.to_sarif(report), encoding="utf-8")
        log.info(json.dumps({"event": "written", "format": "sarif", "path": args.sarif}))

    # Print compact summary to stdout
    print(json.dumps({"summary": report.summary(), "errors": report.errors}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
