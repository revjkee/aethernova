#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Emergency Fix Runner (industrial one-off script)

Purpose:
- Apply a set of explicitly described file operations from a JSON config.
- Provide safety rails: dry-run, backups, atomic writes, lock file, optional git-clean checks,
  structured logging, and deterministic reporting.

IMPORTANT:
- This is a replacement scaffold for an unknown legacy "emergency_fix_2023_11_02.py".
- The actual fix logic must be expressed via the JSON actions file.

Config format (JSON):
{
  "version": 1,
  "actions": [
    {
      "type": "replace_text",
      "path": "relative/or/absolute/file.txt",
      "encoding": "utf-8",
      "old": "FROM",
      "new": "TO",
      "count": 1,
      "must_change": true
    },
    {
      "type": "regex_sub",
      "path": "file.py",
      "pattern": "foo\\s+bar",
      "repl": "foo_bar",
      "flags": ["MULTILINE"],
      "must_change": false
    },
    {
      "type": "append_line",
      "path": "file.env",
      "line": "KEY=value",
      "ensure_newline": true,
      "dedupe": true
    },
    {
      "type": "ensure_dir",
      "path": "some/dir",
      "mode": "0o755"
    },
    {
      "type": "delete_file",
      "path": "tmp/bad.file",
      "must_exist": false
    },
    {
      "type": "move_file",
      "src": "a.txt",
      "dst": "b.txt",
      "overwrite": false,
      "backup_dst": true
    },
    {
      "type": "chmod",
      "path": "script.sh",
      "mode": "0o755",
      "must_exist": true
    }
  ]
}

Exit codes:
0 - success (or dry-run with no fatal errors)
2 - validation error / bad config
3 - execution error (at least one action failed)
4 - environment safety check failed
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


# -----------------------------
# Constants
# -----------------------------

DEFAULT_ENCODING = "utf-8"
DEFAULT_LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 MiB
DEFAULT_LOG_BACKUP_COUNT = 5
SUPPORTED_CONFIG_VERSION = 1

ACTION_TYPES = {
    "replace_text",
    "regex_sub",
    "append_line",
    "ensure_dir",
    "delete_file",
    "move_file",
    "chmod",
}


# -----------------------------
# Data models
# -----------------------------

@dataclass(frozen=True)
class ActionResult:
    index: int
    action_type: str
    ok: bool
    changed: bool
    message: str
    details: Dict[str, Any]


@dataclass(frozen=True)
class RunSummary:
    ok: bool
    dry_run: bool
    started_at: str
    finished_at: str
    duration_ms: int
    total_actions: int
    succeeded: int
    failed: int
    changed_actions: int
    results: List[ActionResult]


# -----------------------------
# Logging
# -----------------------------

def setup_logging(
    *,
    verbose: bool,
    log_file: Optional[Path],
    log_max_bytes: int,
    log_backup_count: int,
) -> logging.Logger:
    logger = logging.getLogger("emergency_fix")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    logger.propagate = False

    fmt = logging.Formatter(
        fmt="%(asctime)sZ %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    stream = logging.StreamHandler(stream=sys.stdout)
    stream.setLevel(logging.DEBUG if verbose else logging.INFO)
    stream.setFormatter(fmt)
    logger.addHandler(stream)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler(
            filename=str(log_file),
            maxBytes=log_max_bytes,
            backupCount=log_backup_count,
            encoding=DEFAULT_ENCODING,
            delay=True,
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger


# -----------------------------
# Safety checks
# -----------------------------

def require_git_clean(repo_root: Path, logger: logging.Logger) -> None:
    """
    Fail if git working tree has changes.
    This prevents running emergency scripts on a dirty tree by accident.
    """
    try:
        proc = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(repo_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except Exception as e:
        raise RuntimeError(f"git check failed: {e}") from e

    if proc.returncode != 0:
        raise RuntimeError(f"git status failed: {proc.stderr.strip() or 'unknown error'}")

    if proc.stdout.strip():
        raise RuntimeError("git working tree is not clean (status --porcelain not empty)")


class FileLock:
    """
    Minimal lock via exclusive creation of a lock file.
    Works cross-platform using O_CREAT|O_EXCL.
    """

    def __init__(self, lock_path: Path, *, stale_after_seconds: int = 6 * 60 * 60) -> None:
        self._lock_path = lock_path
        self._stale_after_seconds = stale_after_seconds
        self._fd: Optional[int] = None

    def acquire(self) -> None:
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)

        # Clean stale lock if too old
        if self._lock_path.exists():
            try:
                age = time.time() - self._lock_path.stat().st_mtime
                if age > self._stale_after_seconds:
                    self._lock_path.unlink(missing_ok=True)
            except Exception:
                # If we cannot evaluate staleness, do not delete.
                pass

        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        try:
            self._fd = os.open(str(self._lock_path), flags, 0o600)
            payload = f"pid={os.getpid()} time={datetime.now(timezone.utc).isoformat()}\n"
            os.write(self._fd, payload.encode(DEFAULT_ENCODING))
            os.fsync(self._fd)
        except FileExistsError as e:
            raise RuntimeError(f"lock already held: {self._lock_path}") from e
        except Exception as e:
            raise RuntimeError(f"cannot acquire lock: {self._lock_path}: {e}") from e

    def release(self) -> None:
        try:
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None
        finally:
            try:
                self._lock_path.unlink(missing_ok=True)
            except Exception:
                # Best-effort cleanup
                pass

    def __enter__(self) -> "FileLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()


# -----------------------------
# Helpers
# -----------------------------

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def resolve_path(base_dir: Path, p: str) -> Path:
    raw = Path(p)
    return raw if raw.is_absolute() else (base_dir / raw).resolve()


def safe_read_text(path: Path, encoding: str) -> str:
    return path.read_text(encoding=encoding)


def atomic_write_text(
    path: Path,
    content: str,
    *,
    encoding: str,
    newline: Optional[str] = None,
) -> None:
    """
    Atomic write by writing to a temp file in the same directory and then replacing.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    dir_path = str(path.parent)

    # Ensure deterministic newline behavior if requested
    data = content
    if newline is not None:
        data = data.replace("\r\n", "\n").replace("\r", "\n")
        if newline != "\n":
            data = data.replace("\n", newline)

    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.tmp.", dir=dir_path, text=True)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline="") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(str(tmp_path), str(path))
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass


def ensure_backup(path: Path, backup_dir: Path) -> Optional[Path]:
    """
    Create a timestamped backup copy of a file if it exists.
    Returns backup path or None.
    """
    if not path.exists() or not path.is_file():
        return None

    backup_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_name = f"{path.name}.bak.{ts}"
    backup_path = backup_dir / backup_name
    shutil.copy2(str(path), str(backup_path))
    return backup_path


def parse_re_flags(flags: Sequence[str]) -> int:
    mapping = {
        "ASCII": re.ASCII,
        "IGNORECASE": re.IGNORECASE,
        "LOCALE": re.LOCALE,
        "MULTILINE": re.MULTILINE,
        "DOTALL": re.DOTALL,
        "VERBOSE": re.VERBOSE,
    }
    value = 0
    for f in flags:
        if f not in mapping:
            raise ValueError(f"unsupported regex flag: {f}")
        value |= mapping[f]
    return value


# -----------------------------
# Action execution
# -----------------------------

def validate_config(cfg: Dict[str, Any]) -> Tuple[int, List[Dict[str, Any]]]:
    version = cfg.get("version")
    if version != SUPPORTED_CONFIG_VERSION:
        raise ValueError(f"unsupported config version: {version}, expected: {SUPPORTED_CONFIG_VERSION}")

    actions = cfg.get("actions")
    if not isinstance(actions, list) or not actions:
        raise ValueError("config.actions must be a non-empty list")

    for i, a in enumerate(actions):
        if not isinstance(a, dict):
            raise ValueError(f"action[{i}] must be an object")
        t = a.get("type")
        if t not in ACTION_TYPES:
            raise ValueError(f"action[{i}].type must be one of: {sorted(ACTION_TYPES)}")
    return version, actions  # type: ignore[return-value]


def run_action(
    *,
    index: int,
    action: Dict[str, Any],
    base_dir: Path,
    dry_run: bool,
    backup_dir: Path,
    logger: logging.Logger,
) -> ActionResult:
    t = str(action["type"])

    try:
        if t == "replace_text":
            return action_replace_text(
                index=index,
                action=action,
                base_dir=base_dir,
                dry_run=dry_run,
                backup_dir=backup_dir,
                logger=logger,
            )
        if t == "regex_sub":
            return action_regex_sub(
                index=index,
                action=action,
                base_dir=base_dir,
                dry_run=dry_run,
                backup_dir=backup_dir,
                logger=logger,
            )
        if t == "append_line":
            return action_append_line(
                index=index,
                action=action,
                base_dir=base_dir,
                dry_run=dry_run,
                backup_dir=backup_dir,
                logger=logger,
            )
        if t == "ensure_dir":
            return action_ensure_dir(
                index=index,
                action=action,
                base_dir=base_dir,
                dry_run=dry_run,
                logger=logger,
            )
        if t == "delete_file":
            return action_delete_file(
                index=index,
                action=action,
                base_dir=base_dir,
                dry_run=dry_run,
                logger=logger,
            )
        if t == "move_file":
            return action_move_file(
                index=index,
                action=action,
                base_dir=base_dir,
                dry_run=dry_run,
                backup_dir=backup_dir,
                logger=logger,
            )
        if t == "chmod":
            return action_chmod(
                index=index,
                action=action,
                base_dir=base_dir,
                dry_run=dry_run,
                logger=logger,
            )

        return ActionResult(
            index=index,
            action_type=t,
            ok=False,
            changed=False,
            message="unsupported action type",
            details={"type": t},
        )

    except Exception as e:
        return ActionResult(
            index=index,
            action_type=t,
            ok=False,
            changed=False,
            message=str(e),
            details={"exception": repr(e)},
        )


def action_replace_text(
    *,
    index: int,
    action: Dict[str, Any],
    base_dir: Path,
    dry_run: bool,
    backup_dir: Path,
    logger: logging.Logger,
) -> ActionResult:
    path = resolve_path(base_dir, str(action["path"]))
    encoding = str(action.get("encoding", DEFAULT_ENCODING))
    old = str(action["old"])
    new = str(action["new"])
    count = int(action.get("count", 0))  # 0 means replace all
    must_change = bool(action.get("must_change", True))

    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"file not found: {path}")

    content = safe_read_text(path, encoding)
    replaced = content.replace(old, new) if count == 0 else content.replace(old, new, count)
    changed = replaced != content

    if must_change and not changed:
        raise RuntimeError("must_change=true but no changes detected")

    if changed and not dry_run:
        ensure_backup(path, backup_dir)
        atomic_write_text(path, replaced, encoding=encoding)

    logger.info(
        "action[%d]=replace_text path=%s changed=%s dry_run=%s",
        index, str(path), str(changed), str(dry_run),
    )

    return ActionResult(
        index=index,
        action_type="replace_text",
        ok=True,
        changed=changed,
        message="ok",
        details={"path": str(path), "must_change": must_change, "count": count},
    )


def action_regex_sub(
    *,
    index: int,
    action: Dict[str, Any],
    base_dir: Path,
    dry_run: bool,
    backup_dir: Path,
    logger: logging.Logger,
) -> ActionResult:
    path = resolve_path(base_dir, str(action["path"]))
    encoding = str(action.get("encoding", DEFAULT_ENCODING))
    pattern = str(action["pattern"])
    repl = str(action["repl"])
    flags_raw = action.get("flags", [])
    flags_list = list(flags_raw) if isinstance(flags_raw, list) else []
    must_change = bool(action.get("must_change", False))

    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"file not found: {path}")

    flags = parse_re_flags([str(x) for x in flags_list])
    rgx = re.compile(pattern, flags=flags)

    content = safe_read_text(path, encoding)
    replaced, n = rgx.subn(repl, content)
    changed = n > 0

    if must_change and not changed:
        raise RuntimeError("must_change=true but regex made 0 substitutions")

    if changed and not dry_run:
        ensure_backup(path, backup_dir)
        atomic_write_text(path, replaced, encoding=encoding)

    logger.info(
        "action[%d]=regex_sub path=%s substitutions=%d changed=%s dry_run=%s",
        index, str(path), n, str(changed), str(dry_run),
    )

    return ActionResult(
        index=index,
        action_type="regex_sub",
        ok=True,
        changed=changed,
        message="ok",
        details={"path": str(path), "substitutions": n, "must_change": must_change, "flags": flags_list},
    )


def action_append_line(
    *,
    index: int,
    action: Dict[str, Any],
    base_dir: Path,
    dry_run: bool,
    backup_dir: Path,
    logger: logging.Logger,
) -> ActionResult:
    path = resolve_path(base_dir, str(action["path"]))
    encoding = str(action.get("encoding", DEFAULT_ENCODING))
    line = str(action["line"])
    ensure_newline = bool(action.get("ensure_newline", True))
    dedupe = bool(action.get("dedupe", True))
    create_if_missing = bool(action.get("create_if_missing", True))

    if not path.exists():
        if not create_if_missing:
            raise FileNotFoundError(f"file not found and create_if_missing=false: {path}")
        content = ""
    else:
        if not path.is_file():
            raise RuntimeError(f"path is not a file: {path}")
        content = safe_read_text(path, encoding)

    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.split("\n")

    already = any(l == line for l in lines) if dedupe else False
    if already:
        changed = False
        new_content = normalized
    else:
        changed = True
        new_content = normalized
        if ensure_newline and new_content and not new_content.endswith("\n"):
            new_content += "\n"
        new_content += line
        if ensure_newline:
            new_content += "\n"

    if changed and not dry_run:
        if path.exists():
            ensure_backup(path, backup_dir)
        atomic_write_text(path, new_content, encoding=encoding)

    logger.info(
        "action[%d]=append_line path=%s changed=%s dry_run=%s",
        index, str(path), str(changed), str(dry_run),
    )

    return ActionResult(
        index=index,
        action_type="append_line",
        ok=True,
        changed=changed,
        message="ok",
        details={"path": str(path), "dedupe": dedupe, "ensure_newline": ensure_newline},
    )


def action_ensure_dir(
    *,
    index: int,
    action: Dict[str, Any],
    base_dir: Path,
    dry_run: bool,
    logger: logging.Logger,
) -> ActionResult:
    path = resolve_path(base_dir, str(action["path"]))
    mode_raw = action.get("mode")
    mode = int(str(mode_raw), 8) if mode_raw is not None else None

    existed = path.exists()
    changed = False

    if not existed:
        changed = True
        if not dry_run:
            path.mkdir(parents=True, exist_ok=True)
            if mode is not None:
                os.chmod(str(path), mode)

    else:
        if not path.is_dir():
            raise RuntimeError(f"path exists but is not a directory: {path}")

        if mode is not None and not dry_run:
            try:
                current_mode = path.stat().st_mode & 0o777
                if current_mode != mode:
                    os.chmod(str(path), mode)
                    changed = True
            except Exception as e:
                raise RuntimeError(f"chmod failed for dir {path}: {e}") from e

    logger.info(
        "action[%d]=ensure_dir path=%s existed=%s changed=%s dry_run=%s",
        index, str(path), str(existed), str(changed), str(dry_run),
    )

    return ActionResult(
        index=index,
        action_type="ensure_dir",
        ok=True,
        changed=changed,
        message="ok",
        details={"path": str(path), "mode": oct(mode) if mode is not None else None},
    )


def action_delete_file(
    *,
    index: int,
    action: Dict[str, Any],
    base_dir: Path,
    dry_run: bool,
    logger: logging.Logger,
) -> ActionResult:
    path = resolve_path(base_dir, str(action["path"]))
    must_exist = bool(action.get("must_exist", False))

    if not path.exists():
        if must_exist:
            raise FileNotFoundError(f"must_exist=true but file not found: {path}")
        logger.info("action[%d]=delete_file path=%s changed=false dry_run=%s (missing_ok)",
                    index, str(path), str(dry_run))
        return ActionResult(
            index=index,
            action_type="delete_file",
            ok=True,
            changed=False,
            message="ok (missing)",
            details={"path": str(path), "must_exist": must_exist},
        )

    if not path.is_file():
        raise RuntimeError(f"path exists but is not a file: {path}")

    if not dry_run:
        path.unlink(missing_ok=True)

    logger.info("action[%d]=delete_file path=%s changed=true dry_run=%s", index, str(path), str(dry_run))

    return ActionResult(
        index=index,
        action_type="delete_file",
        ok=True,
        changed=True,
        message="ok",
        details={"path": str(path), "must_exist": must_exist},
    )


def action_move_file(
    *,
    index: int,
    action: Dict[str, Any],
    base_dir: Path,
    dry_run: bool,
    backup_dir: Path,
    logger: logging.Logger,
) -> ActionResult:
    src = resolve_path(base_dir, str(action["src"]))
    dst = resolve_path(base_dir, str(action["dst"]))
    overwrite = bool(action.get("overwrite", False))
    backup_dst = bool(action.get("backup_dst", True))

    if not src.exists() or not src.is_file():
        raise FileNotFoundError(f"src file not found: {src}")

    if dst.exists():
        if not overwrite:
            raise RuntimeError(f"dst exists and overwrite=false: {dst}")
        if backup_dst:
            ensure_backup(dst, backup_dir)

    changed = True
    if not dry_run:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))

    logger.info(
        "action[%d]=move_file src=%s dst=%s changed=%s dry_run=%s",
        index, str(src), str(dst), str(changed), str(dry_run),
    )

    return ActionResult(
        index=index,
        action_type="move_file",
        ok=True,
        changed=changed,
        message="ok",
        details={"src": str(src), "dst": str(dst), "overwrite": overwrite, "backup_dst": backup_dst},
    )


def action_chmod(
    *,
    index: int,
    action: Dict[str, Any],
    base_dir: Path,
    dry_run: bool,
    logger: logging.Logger,
) -> ActionResult:
    path = resolve_path(base_dir, str(action["path"]))
    mode_raw = action.get("mode")
    must_exist = bool(action.get("must_exist", True))

    if not path.exists():
        if must_exist:
            raise FileNotFoundError(f"file not found: {path}")
        logger.info("action[%d]=chmod path=%s changed=false dry_run=%s (missing_ok)",
                    index, str(path), str(dry_run))
        return ActionResult(
            index=index,
            action_type="chmod",
            ok=True,
            changed=False,
            message="ok (missing)",
            details={"path": str(path), "must_exist": must_exist},
        )

    if not path.is_file():
        raise RuntimeError(f"path exists but is not a file: {path}")

    if mode_raw is None:
        raise ValueError("chmod requires mode")

    mode = int(str(mode_raw), 8)
    current_mode = path.stat().st_mode & 0o777
    changed = current_mode != mode

    if changed and not dry_run:
        os.chmod(str(path), mode)

    logger.info(
        "action[%d]=chmod path=%s changed=%s dry_run=%s mode=%s",
        index, str(path), str(changed), str(dry_run), oct(mode),
    )

    return ActionResult(
        index=index,
        action_type="chmod",
        ok=True,
        changed=changed,
        message="ok",
        details={"path": str(path), "mode": oct(mode), "previous": oct(current_mode)},
    )


# -----------------------------
# Main runner
# -----------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="emergency_fix_2023_11_02",
        description="Industrial emergency fix runner (JSON-driven, safe one-off operations).",
    )
    p.add_argument(
        "--config",
        required=True,
        help="Path to JSON config describing actions to execute.",
    )
    p.add_argument(
        "--base-dir",
        default=str(Path.cwd()),
        help="Base directory for relative paths in config.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not modify filesystem; only log intended changes.",
    )
    p.add_argument(
        "--backup-dir",
        default=str(Path.cwd() / ".emergency_fix_backups"),
        help="Directory to store backups for modified files.",
    )
    p.add_argument(
        "--lock-file",
        default=str(Path.cwd() / ".emergency_fix.lock"),
        help="Lock file to prevent concurrent runs.",
    )
    p.add_argument(
        "--require-git-clean",
        action="store_true",
        help="Fail if git working tree has uncommitted changes (repo root = base-dir).",
    )
    p.add_argument(
        "--log-file",
        default=str(Path.cwd() / ".logs" / "emergency_fix.log"),
        help="Rotating log file path. Use empty value to disable file logging.",
    )
    p.add_argument(
        "--log-max-bytes",
        type=int,
        default=DEFAULT_LOG_MAX_BYTES,
        help="Max size for rotating log file.",
    )
    p.add_argument(
        "--log-backup-count",
        type=int,
        default=DEFAULT_LOG_BACKUP_COUNT,
        help="Number of rotated log files to keep.",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose console logging (DEBUG).",
    )
    p.add_argument(
        "--report",
        default=str(Path.cwd() / ".emergency_fix_report.json"),
        help="Write a JSON report to this path.",
    )
    return p


def load_config(path: Path) -> Dict[str, Any]:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"config not found: {path}")
    raw = path.read_text(encoding=DEFAULT_ENCODING)
    return json.loads(raw)


def write_report(report_path: Path, summary: RunSummary) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "ok": summary.ok,
        "dry_run": summary.dry_run,
        "started_at": summary.started_at,
        "finished_at": summary.finished_at,
        "duration_ms": summary.duration_ms,
        "total_actions": summary.total_actions,
        "succeeded": summary.succeeded,
        "failed": summary.failed,
        "changed_actions": summary.changed_actions,
        "results": [
            {
                "index": r.index,
                "action_type": r.action_type,
                "ok": r.ok,
                "changed": r.changed,
                "message": r.message,
                "details": r.details,
            }
            for r in summary.results
        ],
    }
    atomic_write_text(report_path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding=DEFAULT_ENCODING)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    base_dir = Path(args.base_dir).resolve()
    config_path = resolve_path(Path.cwd(), str(args.config))
    backup_dir = resolve_path(Path.cwd(), str(args.backup_dir))
    lock_file = resolve_path(Path.cwd(), str(args.lock_file))
    report_path = resolve_path(Path.cwd(), str(args.report))

    log_file_str = str(args.log_file).strip()
    log_file = resolve_path(Path.cwd(), log_file_str) if log_file_str else None

    logger = setup_logging(
        verbose=bool(args.verbose),
        log_file=log_file,
        log_max_bytes=int(args.log_max_bytes),
        log_backup_count=int(args.log_backup_count),
    )

    started = time.time()
    started_at = utc_now_iso()

    logger.info("start base_dir=%s config=%s dry_run=%s", str(base_dir), str(config_path), str(bool(args.dry_run)))

    try:
        cfg = load_config(config_path)
        _, actions = validate_config(cfg)

        if bool(args.require_git_clean):
            require_git_clean(base_dir, logger)

        results: List[ActionResult] = []
        with FileLock(lock_file):
            for i, a in enumerate(actions):
                r = run_action(
                    index=i,
                    action=a,
                    base_dir=base_dir,
                    dry_run=bool(args.dry_run),
                    backup_dir=backup_dir,
                    logger=logger,
                )
                results.append(r)

        succeeded = sum(1 for r in results if r.ok)
        failed = sum(1 for r in results if not r.ok)
        changed_actions = sum(1 for r in results if r.changed)
        ok = failed == 0

        finished_at = utc_now_iso()
        duration_ms = int((time.time() - started) * 1000)

        summary = RunSummary(
            ok=ok,
            dry_run=bool(args.dry_run),
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=duration_ms,
            total_actions=len(results),
            succeeded=succeeded,
            failed=failed,
            changed_actions=changed_actions,
            results=results,
        )

        try:
            write_report(report_path, summary)
        except Exception as e:
            logger.error("report write failed path=%s error=%s", str(report_path), str(e))
            # Reporting failure should not hide action failures; but it should influence exit.
            if ok:
                ok = False

        if ok:
            logger.info("done ok=true actions=%d changed=%d duration_ms=%d report=%s",
                        len(results), changed_actions, duration_ms, str(report_path))
            return 0

        logger.error("done ok=false failed=%d actions=%d changed=%d duration_ms=%d report=%s",
                     failed, len(results), changed_actions, duration_ms, str(report_path))
        return 3

    except ValueError as e:
        logger.error("validation error: %s", str(e))
        return 2
    except RuntimeError as e:
        logger.error("safety/execution error: %s", str(e))
        return 4
    except FileNotFoundError as e:
        logger.error("file not found: %s", str(e))
        return 2
    except json.JSONDecodeError as e:
        logger.error("config json decode error: %s", str(e))
        return 2
    except Exception as e:
        logger.error("unexpected error: %s", str(e))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
