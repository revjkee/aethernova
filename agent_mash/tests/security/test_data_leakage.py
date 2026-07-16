from __future__ import annotations

import hashlib
import math
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

import pytest


@dataclass(frozen=True)
class Finding:
    path: Path
    line_no: int
    rule_id: str
    excerpt: str


def _env_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    val = val.strip().lower()
    return val in ("1", "true", "yes", "y", "on")


def _env_int(name: str, default: int, min_value: int = 1, max_value: int = 2_000_000_000) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        v = int(raw.strip())
    except ValueError:
        return default
    if v < min_value:
        return min_value
    if v > max_value:
        return max_value
    return v


def _project_root_from_this_file() -> Path:
    # agent_mash/tests/security/test_data_leakage.py -> project root assumed 3 levels up by default
    # security -> tests -> agent_mash -> (root)
    return Path(__file__).resolve().parents[3]


def _split_csv_env(name: str, default: Sequence[str]) -> List[str]:
    raw = os.getenv(name)
    if raw is None:
        return list(default)
    items = [x.strip() for x in raw.split(",")]
    return [x for x in items if x]


def _safe_read_text(path: Path, limit_bytes: int) -> Optional[str]:
    try:
        data = path.read_bytes()
    except (OSError, IOError):
        return None
    if len(data) > limit_bytes:
        return None
    # Best-effort decode; treat undecodable bytes as replacement to avoid crashes in CI.
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("utf-8", errors="replace")
        except Exception:
            return None


def _iter_files(root: Path, exclude_dirs: Sequence[str], include_exts: Sequence[str]) -> Iterator[Path]:
    exclude_set = set(exclude_dirs)
    include_set = set(e.lower() for e in include_exts)

    for p in root.rglob("*"):
        try:
            rel_parts = p.relative_to(root).parts
        except ValueError:
            rel_parts = p.parts

        if any(part in exclude_set for part in rel_parts):
            continue

        if not p.is_file():
            continue

        ext = p.suffix.lower()
        if ext in include_set:
            yield p


def _line_excerpt(line: str, max_len: int = 240) -> str:
    s = line.rstrip("\n")
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


def _shannon_entropy(s: str) -> float:
    # Shannon entropy per character
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def _is_probably_secret_by_entropy(token: str, min_len: int, min_entropy: float) -> bool:
    if len(token) < min_len:
        return False
    # Skip obvious non-secrets
    if token.startswith(("http://", "https://")):
        return False
    if all(ch.isdigit() for ch in token):
        return False
    ent = _shannon_entropy(token)
    return ent >= min_entropy


def _load_allowlist(allowlist_path: Path) -> List[re.Pattern]:
    """
    Allowlist format:
    - Each non-empty non-comment line is treated as a regex.
    - If regex matches "path:line:excerpt" then finding is allowed.
    """
    if not allowlist_path.exists():
        return []
    try:
        lines = allowlist_path.read_text(encoding="utf-8").splitlines()
    except (OSError, IOError, UnicodeDecodeError):
        return []

    patterns: List[re.Pattern] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            patterns.append(re.compile(line))
        except re.error:
            # Broken allowlist entries are ignored to keep CI stable;
            # if you want strictness, enforce allowlist lint separately.
            continue
    return patterns


def _allowed_by_allowlist(allowlist: Sequence[re.Pattern], finding: Finding) -> bool:
    if not allowlist:
        return False
    hay = f"{finding.path.as_posix()}:{finding.line_no}:{finding.excerpt}"
    return any(p.search(hay) for p in allowlist)


def _hash_stable_id(path: Path, line_no: int, rule_id: str, excerpt: str) -> str:
    h = hashlib.sha256()
    h.update(path.as_posix().encode("utf-8"))
    h.update(b":")
    h.update(str(line_no).encode("utf-8"))
    h.update(b":")
    h.update(rule_id.encode("utf-8"))
    h.update(b":")
    h.update(excerpt.encode("utf-8", errors="replace"))
    return h.hexdigest()[:16]


def _build_rules() -> List[Tuple[str, re.Pattern]]:
    """
    Rules are intentionally conservative to reduce false positives,
    while still catching high-risk patterns.
    """
    rules: List[Tuple[str, re.Pattern]] = []

    # Private keys (PEM)
    rules.append(("pem_private_key", re.compile(r"-----BEGIN (EC|RSA|DSA|OPENSSH) PRIVATE KEY-----")))
    rules.append(("pem_pkcs8_key", re.compile(r"-----BEGIN PRIVATE KEY-----")))

    # AWS Access Key ID
    rules.append(("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")))

    # AWS Secret Access Key (common assignment patterns)
    rules.append(("aws_secret_access_key", re.compile(r"(?i)\baws_secret_access_key\b\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{30,}")))

    # GitHub tokens
    rules.append(("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")))
    rules.append(("github_fine_grained_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")))

    # Slack tokens
    rules.append(("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")))

    # Telegram bot token (digits:35-characters)
    rules.append(("telegram_bot_token", re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{30,}\b")))

    # Generic API key assignment (very common leak form)
    rules.append(("generic_api_key_assignment", re.compile(r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*['\"][^'\"\n]{8,}['\"]")))

    # JWT (three base64url segments)
    rules.append(("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")))

    # Basic auth in URL
    rules.append(("url_basic_auth", re.compile(r"(?i)\bhttps?://[^/\s:@]+:[^/\s@]+@")))

    # OAuth client secret style
    rules.append(("oauth_client_secret", re.compile(r"(?i)\bclient_secret\b\s*[:=]\s*['\"][^'\"\n]{12,}['\"]")))

    return rules


def _scan_text_for_findings(
    text: str,
    path: Path,
    rules: Sequence[Tuple[str, re.Pattern]],
    enable_entropy_heuristic: bool,
    entropy_min_len: int,
    entropy_min_value: float,
) -> List[Finding]:
    findings: List[Finding] = []
    lines = text.splitlines()

    for i, line in enumerate(lines, start=1):
        for rule_id, pattern in rules:
            m = pattern.search(line)
            if m:
                findings.append(
                    Finding(
                        path=path,
                        line_no=i,
                        rule_id=rule_id,
                        excerpt=_line_excerpt(line),
                    )
                )

        if enable_entropy_heuristic:
            # Tokenize by common separators; keep base64-like candidates.
            # This is intentionally strict to limit false positives.
            for token in re.findall(r"[A-Za-z0-9_/\+=-]{20,}", line):
                if _is_probably_secret_by_entropy(token, entropy_min_len, entropy_min_value):
                    findings.append(
                        Finding(
                            path=path,
                            line_no=i,
                            rule_id="entropy_suspected_secret",
                            excerpt=_line_excerpt(line),
                        )
                    )

    return findings


def _format_report(findings: Sequence[Finding], root: Path) -> str:
    out: List[str] = []
    out.append("Data leakage scan failed. Potential secrets detected.")
    out.append("Each item: id | rule | relative_path:line | excerpt")
    out.append("")

    for f in findings:
        rel = f.path
        try:
            rel = f.path.relative_to(root)
        except ValueError:
            rel = f.path
        fid = _hash_stable_id(f.path, f.line_no, f.rule_id, f.excerpt)
        out.append(f"{fid} | {f.rule_id} | {rel.as_posix()}:{f.line_no} | {f.excerpt}")

    out.append("")
    out.append("Tuning via env vars:")
    out.append("  DATA_LEAKAGE_SCAN_ROOT: override scan root directory")
    out.append("  DATA_LEAKAGE_INCLUDE_EXTS: comma-separated extensions (default includes .py,.env,.yaml,.yml,.json,.toml,.ini,.cfg,.md,.txt,.log)")
    out.append("  DATA_LEAKAGE_EXCLUDE_DIRS: comma-separated directory names to skip")
    out.append("  DATA_LEAKAGE_MAX_FILE_BYTES: skip files larger than this size")
    out.append("  DATA_LEAKAGE_ENABLE_ENTROPY: true/false (default false)")
    out.append("  DATA_LEAKAGE_ENTROPY_MIN_LEN: integer (default 28)")
    out.append("  DATA_LEAKAGE_ENTROPY_MIN_VALUE: float-like string (default 4.2)")
    out.append("  DATA_LEAKAGE_ALLOWLIST_PATH: path to allowlist file (default .secrets_allowlist)")
    return "\n".join(out)


@pytest.mark.security
def test_repository_has_no_obvious_secrets() -> None:
    """
    Industrial safety-net test.

    It scans the repository tree for common secret patterns:
    keys, tokens, passwords, JWTs, URLs with embedded credentials.

    Default behavior is conservative to avoid noisy failures.
    For stricter setups, enable entropy heuristic in CI.
    """
    default_root = _project_root_from_this_file()
    root = Path(os.getenv("DATA_LEAKAGE_SCAN_ROOT", str(default_root))).resolve()

    include_exts = _split_csv_env(
        "DATA_LEAKAGE_INCLUDE_EXTS",
        default=(
            ".py",
            ".env",
            ".yaml",
            ".yml",
            ".json",
            ".toml",
            ".ini",
            ".cfg",
            ".md",
            ".txt",
            ".log",
        ),
    )

    exclude_dirs = _split_csv_env(
        "DATA_LEAKAGE_EXCLUDE_DIRS",
        default=(
            ".git",
            ".idea",
            ".vscode",
            "__pycache__",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
            ".tox",
            ".venv",
            "venv",
            "node_modules",
            "dist",
            "build",
            ".next",
            ".turbo",
            "coverage",
            "htmlcov",
            ".cache",
        ),
    )

    max_file_bytes = _env_int("DATA_LEAKAGE_MAX_FILE_BYTES", default=2_000_000, min_value=16_384, max_value=50_000_000)

    enable_entropy = _env_bool("DATA_LEAKAGE_ENABLE_ENTROPY", default=False)
    entropy_min_len = _env_int("DATA_LEAKAGE_ENTROPY_MIN_LEN", default=28, min_value=16, max_value=200)

    # Float parsing without raising
    raw_entropy = os.getenv("DATA_LEAKAGE_ENTROPY_MIN_VALUE", "4.2").strip()
    try:
        entropy_min_value = float(raw_entropy)
    except ValueError:
        entropy_min_value = 4.2
    if entropy_min_value < 3.5:
        entropy_min_value = 3.5
    if entropy_min_value > 6.0:
        entropy_min_value = 6.0

    allowlist_path = Path(os.getenv("DATA_LEAKAGE_ALLOWLIST_PATH", str(root / ".secrets_allowlist"))).resolve()
    allowlist = _load_allowlist(allowlist_path)

    rules = _build_rules()

    findings: List[Finding] = []
    for file_path in _iter_files(root, exclude_dirs=exclude_dirs, include_exts=include_exts):
        text = _safe_read_text(file_path, limit_bytes=max_file_bytes)
        if text is None:
            continue

        file_findings = _scan_text_for_findings(
            text=text,
            path=file_path,
            rules=rules,
            enable_entropy_heuristic=enable_entropy,
            entropy_min_len=entropy_min_len,
            entropy_min_value=entropy_min_value,
        )

        for f in file_findings:
            if _allowed_by_allowlist(allowlist, f):
                continue
            findings.append(f)

    if findings:
        report = _format_report(findings=findings, root=root)
        pytest.fail(report, pytrace=False)
