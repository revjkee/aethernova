# agent_mash/legacy/scripts_archive/utilities/legacy_env_loader.py
"""
legacy_env_loader.py

Industrial-grade environment loader for legacy scripts.

Goals:
- Deterministic, profile-aware loading of environment variables from env files.
- No external dependencies.
- Safe logging (secret redaction).
- Optional validation of required keys.
- CLI for quick use in local/dev/CI.

Supported file formats:
- .env style: KEY=VALUE (quotes supported), comments with '#'
- export KEY=VALUE (bash-like export is accepted)

Precedence rules (highest wins):
1) Explicit overrides passed in code / CLI --set KEY=VALUE
2) Existing process environment (if keep_existing=True) OR loaded files (if keep_existing=False)
3) Profile/local files loaded in declared order (later files override earlier)

Default file discovery order (from lowest to higher precedence):
- .env
- .env.<profile>
- .env.local
- .env.<profile>.local

You may provide an explicit list of files to load, which replaces discovery.

Security:
- Values for secret-like keys are redacted in logs (e.g., *_KEY, *_TOKEN, *_SECRET, PASSWORD, etc.)
"""

from __future__ import annotations

import argparse
import dataclasses
import logging
import os
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

_LOG = logging.getLogger("legacy_env_loader")

_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_SECRET_KEY_HINTS = (
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASS",
    "PWD",
    "KEY",
    "PRIVATE",
    "CREDENTIAL",
    "BEARER",
    "AUTH",
    "SIGNATURE",
)


class EnvLoaderError(RuntimeError):
    """Base error for env loader."""


class EnvParseError(EnvLoaderError):
    """Raised when env file contains invalid syntax."""


class EnvValidationError(EnvLoaderError):
    """Raised when required keys are missing."""


@dataclasses.dataclass(frozen=True)
class LoadReport:
    profile: str
    base_dir: Path
    loaded_files: Tuple[Path, ...]
    applied_keys: Tuple[str, ...]
    skipped_existing_keys: Tuple[str, ...]
    overrides_applied: Tuple[str, ...]


def _is_secret_key(key: str) -> bool:
    u = key.upper()
    return any(h in u for h in _SECRET_KEY_HINTS)


def _redact_if_needed(key: str, value: str) -> str:
    if _is_secret_key(key):
        if not value:
            return ""
        # Keep tiny hint for debugging length without revealing content
        return f"<redacted:{len(value)}>"
    return value


def _strip_inline_comment(raw: str) -> str:
    """
    Remove inline comments while respecting quotes.
    Example: KEY="a#b" #comment  -> keeps a#b
    """
    s = raw
    in_squote = False
    in_dquote = False
    out = []
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "'" and not in_dquote:
            in_squote = not in_squote
            out.append(ch)
            i += 1
            continue
        if ch == '"' and not in_squote:
            in_dquote = not in_dquote
            out.append(ch)
            i += 1
            continue
        if ch == "#" and not in_squote and not in_dquote:
            break
        out.append(ch)
        i += 1
    return "".join(out).rstrip()


def _unquote(value: str) -> str:
    v = value.strip()
    if len(v) >= 2 and ((v[0] == v[-1] == '"') or (v[0] == v[-1] == "'")):
        v = v[1:-1]
        if v and '"' in value[:1]:
            # For double quotes, handle common escapes
            v = (
                v.replace(r"\n", "\n")
                .replace(r"\r", "\r")
                .replace(r"\t", "\t")
                .replace(r"\\", "\\")
                .replace(r"\"", '"')
            )
    return v


def _parse_env_line(line: str, lineno: int, src: Path) -> Optional[Tuple[str, str]]:
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None

    raw = _strip_inline_comment(raw).strip()
    if not raw:
        return None

    # Accept optional "export "
    if raw.startswith("export "):
        raw = raw[len("export ") :].lstrip()

    if "=" not in raw:
        raise EnvParseError(f"Invalid env syntax (missing '=') at {src}:{lineno}")

    key, val = raw.split("=", 1)
    key = key.strip()
    val = val.strip()

    if not key or not _KEY_RE.match(key):
        raise EnvParseError(f"Invalid env key '{key}' at {src}:{lineno}")

    val = _unquote(val)

    # Expand ${VAR} and $VAR from current os.environ only (safe, deterministic).
    # We DO NOT recursively expand using values being loaded to avoid ambiguity.
    val = _expand_from_os_environ(val)

    return key, val


_VAR_BRACED = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_VAR_SIMPLE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")


def _expand_from_os_environ(value: str) -> str:
    def repl_braced(m: re.Match[str]) -> str:
        k = m.group(1)
        return os.environ.get(k, "")

    def repl_simple(m: re.Match[str]) -> str:
        k = m.group(1)
        return os.environ.get(k, "")

    v = _VAR_BRACED.sub(repl_braced, value)
    v = _VAR_SIMPLE.sub(repl_simple, v)
    return v


def parse_env_file(path: Path, encoding: str = "utf-8") -> Dict[str, str]:
    """
    Parse an env file into a dict. Does not mutate os.environ.
    Raises EnvParseError on invalid lines.
    """
    if not path.exists():
        return {}

    if not path.is_file():
        raise EnvLoaderError(f"Env path is not a file: {path}")

    data: Dict[str, str] = {}
    text = path.read_text(encoding=encoding, errors="strict")

    for idx, line in enumerate(text.splitlines(), start=1):
        parsed = _parse_env_line(line, idx, path)
        if parsed is None:
            continue
        k, v = parsed
        data[k] = v

    return data


def default_env_files(base_dir: Path, profile: str) -> List[Path]:
    """
    Discovery list in deterministic order. Later overrides earlier.
    """
    profile = (profile or "dev").strip()
    candidates = [
        base_dir / ".env",
        base_dir / f".env.{profile}",
        base_dir / ".env.local",
        base_dir / f".env.{profile}.local",
    ]
    return candidates


def _normalize_profile(profile: Optional[str]) -> str:
    p = (profile or "").strip()
    return p if p else "dev"


def load_environment(
    *,
    base_dir: Path | str = ".",
    profile: Optional[str] = None,
    env_files: Optional[Sequence[Path | str]] = None,
    apply: bool = True,
    keep_existing: bool = True,
    overrides: Optional[Mapping[str, str]] = None,
    required_keys: Optional[Sequence[str]] = None,
    encoding: str = "utf-8",
    logger: Optional[logging.Logger] = None,
) -> LoadReport:
    """
    Load environment variables from files, optionally apply to os.environ.

    Parameters:
    - base_dir: Directory where env files are searched by default.
    - profile: Profile name used for discovery (e.g., dev, prod).
    - env_files: Explicit list of files; if provided, discovery is skipped.
    - apply: Whether to write loaded values into os.environ.
    - keep_existing: If True, do not override keys already present in os.environ.
    - overrides: Final overrides applied after files are processed.
    - required_keys: If provided, validates that these keys exist after load+overrides+existing.
    - encoding: File encoding.
    - logger: Optional custom logger.

    Returns LoadReport with details.
    """
    lg = logger or _LOG
    prof = _normalize_profile(profile)

    bd = Path(base_dir).expanduser().resolve()

    files: List[Path]
    if env_files is None:
        files = default_env_files(bd, prof)
    else:
        files = [Path(p).expanduser().resolve() for p in env_files]

    loaded_files: List[Path] = []
    merged: Dict[str, str] = {}

    for f in files:
        if not f.exists():
            continue
        chunk = parse_env_file(f, encoding=encoding)
        if chunk:
            loaded_files.append(f)
            merged.update(chunk)

    # Apply merged into os.environ depending on keep_existing
    applied: List[str] = []
    skipped: List[str] = []

    if apply:
        for k, v in merged.items():
            if keep_existing and k in os.environ:
                skipped.append(k)
                continue
            os.environ[k] = v
            applied.append(k)

    # Apply explicit overrides last
    overrides_applied: List[str] = []
    if overrides:
        for k, v in overrides.items():
            if not _KEY_RE.match(k):
                raise EnvLoaderError(f"Override contains invalid key: {k}")
            if apply:
                os.environ[k] = v
            merged[k] = v
            overrides_applied.append(k)

    # Validation uses final view:
    # - if apply=True, validate os.environ
    # - else validate merged + optionally existing (if keep_existing=True)
    if required_keys:
        missing = []
        for k in required_keys:
            kk = k.strip()
            if not kk:
                continue
            if apply:
                if kk not in os.environ or os.environ.get(kk, "") == "":
                    missing.append(kk)
            else:
                if kk in merged and merged.get(kk, "") != "":
                    continue
                if keep_existing and kk in os.environ and os.environ.get(kk, "") != "":
                    continue
                missing.append(kk)
        if missing:
            raise EnvValidationError(f"Missing required env keys: {', '.join(missing)}")

    # Safe log summary
    if loaded_files:
        lg.info("Loaded env files: %s", ", ".join(str(p) for p in loaded_files))
    else:
        lg.info("No env files loaded (none found).")

    if applied:
        lg.info("Applied keys: %s", ", ".join(sorted(applied)))
    if skipped:
        lg.info("Skipped existing keys: %s", ", ".join(sorted(skipped)))
    if overrides_applied:
        lg.info("Overrides applied: %s", ", ".join(sorted(overrides_applied)))

    # Log a small redacted snapshot for debugging deterministically
    snapshot_keys = sorted(set(applied + overrides_applied))
    if snapshot_keys:
        preview = {k: _redact_if_needed(k, os.environ.get(k, "")) for k in snapshot_keys}
        lg.debug("Applied preview (redacted): %s", preview)

    return LoadReport(
        profile=prof,
        base_dir=bd,
        loaded_files=tuple(loaded_files),
        applied_keys=tuple(sorted(applied)),
        skipped_existing_keys=tuple(sorted(skipped)),
        overrides_applied=tuple(sorted(overrides_applied)),
    )


def _parse_set_kv(items: Sequence[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for it in items:
        if "=" not in it:
            raise EnvLoaderError(f"--set expects KEY=VALUE, got: {it}")
        k, v = it.split("=", 1)
        k = k.strip()
        if not _KEY_RE.match(k):
            raise EnvLoaderError(f"Invalid key in --set: {k}")
        out[k] = v
    return out


def _parse_required(items: Sequence[str]) -> List[str]:
    req: List[str] = []
    for it in items:
        s = it.strip()
        if not s:
            continue
        req.append(s)
    return req


def _configure_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="legacy_env_loader",
        description="Industrial env loader for legacy scripts (no external deps).",
    )
    p.add_argument(
        "--base-dir",
        default=".",
        help="Base directory for env discovery (default: current directory).",
    )
    p.add_argument(
        "--profile",
        default="dev",
        help="Profile name used for discovery (default: dev).",
    )
    p.add_argument(
        "--file",
        action="append",
        default=None,
        help="Explicit env file path (repeatable). If provided, discovery is skipped.",
    )
    p.add_argument(
        "--no-apply",
        action="store_true",
        help="Do not write into process environment; parse only.",
    )
    p.add_argument(
        "--override-existing",
        action="store_true",
        help="Override keys already present in process environment.",
    )
    p.add_argument(
        "--set",
        action="append",
        default=[],
        help="Override KEY=VALUE (repeatable). Applied last.",
    )
    p.add_argument(
        "--require",
        action="append",
        default=[],
        help="Require env key to be present and non-empty (repeatable).",
    )
    p.add_argument(
        "--encoding",
        default="utf-8",
        help="Env file encoding (default: utf-8).",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v info, -vv debug).",
    )
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_arg_parser().parse_args(list(argv) if argv is not None else None)
    _configure_logging(args.verbose)

    env_files = args.file if args.file else None
    overrides = _parse_set_kv(args.set) if args.set else None
    required_keys = _parse_required(args.require) if args.require else None

    try:
        load_environment(
            base_dir=args.base_dir,
            profile=args.profile,
            env_files=env_files,
            apply=not args.no_apply,
            keep_existing=not args.override_existing,
            overrides=overrides,
            required_keys=required_keys,
            encoding=args.encoding,
            logger=_LOG,
        )
        return 0
    except EnvLoaderError as e:
        _LOG.error(str(e))
        return 2
    except Exception as e:
        # Keep this explicit: unexpected failures should be visible in CI.
        _LOG.exception("Unexpected error: %s", e)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
