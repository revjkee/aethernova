# oblivionvault-core/cli/tools/run_erasure.py
"""
Secure erasure tool for OblivionVault.
Stdlib-only. Python 3.11+.

Features
- Multi-pass overwrite: random and zero passes
- Atomic fsync of file and parent directory
- Optional verification by sampling
- Rename to random name before unlink
- Recursion for directories (post-order)
- Concurrency control and rate limiting
- Dry-run mode
- JSONL audit log
- Strict confirmation (--yes required unless --dry-run)
- Symlink policy (skip by default; optionally follow)

Exit codes
 0  success (all targets erased or skipped as configured)
 1  partial failures
 2  fatal argument or environment error
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import secrets
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

# -----------------------------
# Structured logging (JSON line)
# -----------------------------

def jlog(event: str, **fields):
    payload = {"ts": round(time.time(), 6), "event": event, **fields}
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()

# -----------------------------
# Data models
# -----------------------------

@dataclass(slots=True)
class ErasurePolicy:
    passes: int = 2                        # total passes
    pattern: Tuple[str, ...] = ("random", "zero")  # sequence applied cyclically
    chunk_size: int = 4 * 1024 * 1024      # 4 MiB
    verify: bool = False                   # verify after overwrite
    verify_samples: int = 4                # number of random sample reads
    verify_sample_bytes: int = 64 * 1024   # 64 KiB per sample
    rename_before_unlink: bool = True
    follow_symlinks: bool = False
    dir_mode_on_fix: int = 0o750           # permissions when fixing
    file_mode_on_fix: int = 0o600
    throttle_mbps: Optional[float] = None  # simple rate limit per worker

@dataclass(slots=True)
class RunConfig:
    parallelism: int = 2
    dry_run: bool = False
    yes: bool = False
    journal_path: Optional[Path] = None

# -----------------------------
# Utilities
# -----------------------------

def _fsync_dir(dir_path: Path) -> None:
    # Best-effort fsync of directory metadata
    try:
        fd = os.open(dir_path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except Exception:
        pass  # best effort

def _random_name(prefix: str = ".ov_shred_", length: int = 8) -> str:
    raw = secrets.token_bytes(length)
    safe = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return f"{prefix}{safe}"

def _fix_perms(path: Path, file: bool, policy: ErasurePolicy) -> None:
    try:
        if file:
            os.chmod(path, policy.file_mode_on_fix)
        else:
            os.chmod(path, policy.dir_mode_on_fix)
    except Exception:
        pass

def _is_symlink(path: Path) -> bool:
    try:
        return path.is_symlink()
    except Exception:
        return False

def _open_rw_exclusive(path: Path) -> int:
    # Cross-platform open for read/write without creating
    return os.open(path, os.O_RDWR)

def _sleep_for_throttle(start_ns: int, bytes_written: int, mbps: float) -> None:
    # Simple token-less throttling: after chunk write, compute ideal time.
    elapsed_s = max(0.0, (time.time_ns() - start_ns) / 1e9)
    ideal_s = (bytes_written / (1024 * 1024)) / max(mbps, 0.1)
    if ideal_s > elapsed_s:
        time.sleep(ideal_s - elapsed_s)

# -----------------------------
# Core erasure primitives
# -----------------------------

def overwrite_file(path: Path, policy: ErasurePolicy) -> Tuple[int, int]:
    """
    Overwrite file contents according to policy.
    Returns (bytes_written, passes_done).
    Raises on error.
    """
    if not path.exists():
        raise FileNotFoundError(str(path))
    if _is_symlink(path):
        raise RuntimeError("refuse_to_overwrite_symlink")
    st = path.stat()
    if not stat.S_ISREG(st.st_mode):
        raise RuntimeError("not_a_regular_file")

    size = st.st_size
    if size == 0:
        # Touch metadata and proceed to rename/unlink stages
        return (0, 0)

    fd = _open_rw_exclusive(path)
    try:
        bytes_written_total = 0
        start_ns = time.time_ns()
        for p in range(policy.passes):
            pattern = policy.pattern[p % len(policy.pattern)]
            os.lseek(fd, 0, os.SEEK_SET)
            remaining = size
            while remaining > 0:
                chunk = min(policy.chunk_size, remaining)
                if pattern == "zero":
                    buf = b"\x00" * chunk
                elif pattern == "random":
                    buf = secrets.token_bytes(chunk)
                else:
                    # fixed byte pattern like "0xFF" (in hex) is allowed
                    if pattern.startswith("0x") and len(pattern) <= 4:
                        val = int(pattern, 16) & 0xFF
                        buf = bytes([val]) * chunk
                    else:
                        raise ValueError(f"unknown pattern: {pattern}")
                written = os.write(fd, buf)
                if written != len(buf):
                    raise RuntimeError("short_write")
                bytes_written_total += written
                remaining -= written
                os.fsync(fd)
                if policy.throttle_mbps:
                    _sleep_for_throttle(start_ns, bytes_written_total, policy.throttle_mbps)
        # Final flush and fsync
        os.fsync(fd)
        return (bytes_written_total, policy.passes)
    finally:
        try:
            os.close(fd)
        except Exception:
            pass

def verify_overwrite(path: Path, policy: ErasurePolicy) -> bool:
    """
    Verify by reading random samples and checking they match last pass pattern.
    If last pass is random, strict verification is statistically weak; we instead
    check that data is not equal to precomputed constant slices filled before verify.
    For robust, set last pass to 'zero' or '0xFF'.
    """
    if not policy.verify:
        return True
    if not path.exists() or not path.is_file():
        return False
    size = path.stat().st_size
    if size == 0:
        return True

    last_pat = policy.pattern[(policy.passes - 1) % len(policy.pattern)]
    def expected_block(length: int) -> bytes:
        if last_pat == "zero":
            return b"\x00" * length
        if last_pat.startswith("0x") and len(last_pat) <= 4:
            val = int(last_pat, 16) & 0xFF
            return bytes([val]) * length
        # for "random", we can only check that sample is not all zeros or a single repeated byte
        return None  # type: ignore

    with open(path, "rb", buffering=0) as f:
        for _ in range(max(1, policy.verify_samples)):
            offset = secrets.randbelow(max(1, size - policy.verify_sample_bytes)) if size > policy.verify_sample_bytes else 0
            f.seek(offset)
            data = f.read(min(policy.verify_sample_bytes, size))
            if last_pat == "random":
                # heuristic: fail only if block equals trivial patterns
                if data == b"\x00" * len(data):
                    return False
                if len(set(data)) == 1:
                    return False
            else:
                exp = expected_block(len(data))
                if exp is None:
                    continue
                if data != exp:
                    return False
    return True

def rename_and_unlink(path: Path, policy: ErasurePolicy) -> str:
    """
    Rename file to random name in the same directory, then unlink.
    Returns final removed name (for journaling).
    """
    parent = path.parent
    removed_name = path.name
    try:
        _fix_perms(path, file=True, policy=policy)
    except Exception:
        pass

    if policy.rename_before_unlink:
        rnd = _random_name()
        tmp = parent / rnd
        try:
            os.replace(path, tmp)
            removed_name = tmp.name
            _fsync_dir(parent)
            path = tmp
        except Exception:
            # If rename fails, continue with original name
            pass

    try:
        os.remove(path)
    finally:
        _fsync_dir(parent)
    return removed_name

def shred_file(path: Path, policy: ErasurePolicy, dry_run: bool) -> dict:
    """
    Full file erasure workflow.
    """
    action = {
        "target": str(path),
        "type": "file",
        "dry_run": dry_run,
        "result": None,
        "bytes_written": 0,
        "passes": 0,
        "renamed_to": None,
        "verified": None,
        "error": None,
    }
    try:
        if _is_symlink(path):
            if not policy.follow_symlinks:
                action["result"] = "skipped_symlink"
                return action
            # resolve if allowed
            path = path.resolve()

        if dry_run:
            action["result"] = "dry_run_ok"
            return action

        if path.exists() and path.is_file():
            bw, done = overwrite_file(path, policy)
            action["bytes_written"] = bw
            action["passes"] = done
            ok = verify_overwrite(path, policy)
            action["verified"] = bool(ok)
            removed_name = rename_and_unlink(path, policy)
            action["renamed_to"] = removed_name
            action["result"] = "ok" if ok else "ok_unverified"
        else:
            action["result"] = "missing"
    except Exception as e:
        action["error"] = f"{type(e).__name__}: {e}"
        action["result"] = "failed"
    return action

def shred_dir(root: Path, policy: ErasurePolicy, dry_run: bool) -> dict:
    """
    Recursively shred directory contents, then remove empty directories bottom-up.
    """
    summary = {
        "target": str(root),
        "type": "dir",
        "dry_run": dry_run,
        "result": None,
        "files_ok": 0,
        "files_failed": 0,
        "dirs_removed": 0,
        "error": None,
    }
    try:
        if _is_symlink(root) and not policy.follow_symlinks:
            summary["result"] = "skipped_symlink_dir"
            return summary

        if dry_run:
            summary["result"] = "dry_run_ok"
            return summary

        # Post-order traversal
        for path in sorted(root.rglob("*")):
            if path.is_file():
                res = shred_file(path, policy, dry_run=False)
                if res["result"] in ("ok", "ok_unverified", "missing"):
                    summary["files_ok"] += 1
                else:
                    summary["files_failed"] += 1

        # Remove empty directories bottom-up
        removed = 0
        for path in sorted((p for p in root.rglob("*") if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
            try:
                _fix_perms(path, file=False, policy=policy)
                path.rmdir()
                _fsync_dir(path.parent)
                removed += 1
            except Exception:
                pass

        # Remove the root itself
        try:
            _fix_perms(root, file=False, policy=policy)
            root.rmdir()
            _fsync_dir(root.parent)
            removed += 1
        except Exception:
            pass

        summary["dirs_removed"] = removed
        summary["result"] = "ok"
    except Exception as e:
        summary["error"] = f"{type(e).__name__}: {e}"
        summary["result"] = "failed"
    return summary

# -----------------------------
# Manifest handling
# -----------------------------

def iter_manifest_entries(manifest_path: Path) -> Iterable[Tuple[str, str]]:
    """
    Yield (kind, path_str) where kind in {"file","dir"} from a JSONL or simple text manifest.
    JSONL line example: {"type":"file","path":"/var/data/secret.bin"}
    Plain text line example: /var/data/secret.bin
    """
    with open(manifest_path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    kind = obj.get("type", "file")
                    p = obj["path"]
                    yield kind, p
                except Exception:
                    continue
            else:
                yield "file", line

# -----------------------------
# Async orchestration
# -----------------------------

async def worker(queue: asyncio.Queue, policy: ErasurePolicy, cfg: RunConfig, journal_fd):
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break
        kind, path_str = item
        path = Path(path_str)
        if kind == "file":
            res = shred_file(path, policy, cfg.dry_run)
            jlog("erasure.file", **res)
            if journal_fd:
                journal_fd.write(json.dumps(res, ensure_ascii=False) + "\n")
                journal_fd.flush()
        elif kind == "dir":
            res = shred_dir(path, policy, cfg.dry_run)
            jlog("erasure.dir", **res)
            if journal_fd:
                journal_fd.write(json.dumps(res, ensure_ascii=False) + "\n")
                journal_fd.flush()
        else:
            jlog("erasure.unknown", target=path_str, type=kind)
        queue.task_done()

async def run_erasure(targets: List[Tuple[str, str]], policy: ErasurePolicy, cfg: RunConfig) -> int:
    queue: asyncio.Queue = asyncio.Queue()
    for item in targets:
        queue.put_nowait(item)

    journal_fd = None
    if cfg.journal_path:
        cfg.journal_path.parent.mkdir(parents=True, exist_ok=True)
        journal_fd = open(cfg.journal_path, "a", encoding="utf-8")

    try:
        tasks = []
        for _ in range(max(1, cfg.parallelism)):
            tasks.append(asyncio.create_task(worker(queue, policy, cfg, journal_fd)))
        await queue.join()
        for _ in tasks:
            queue.put_nowait(None)
        await asyncio.gather(*tasks)
    finally:
        if journal_fd:
            journal_fd.close()

    # Determine final exit code by scanning journal or rely on stdout logs.
    # Here we take a best-effort: if any "failed" was logged, non-zero returned by caller.
    # Caller aggregates via returned integer.
    return 0

# -----------------------------
# CLI
# -----------------------------

def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="run_erasure",
        description="Secure erasure tool for OblivionVault (files and directories).",
    )
    p.add_argument("paths", nargs="*", help="Paths to files or directories to erase")
    p.add_argument("--manifest", type=str, help="Path to manifest file (JSONL or plain list)")
    p.add_argument("--dir", action="store_true", help="Treat provided paths as directories")
    p.add_argument("--passes", type=int, default=2, help="Total overwrite passes (default: 2)")
    p.add_argument("--pattern", type=str, default="random,zero", help="Comma-separated pattern sequence. Supported: random,zero,0xFF")
    p.add_argument("--chunk-size", type=int, default=4 * 1024 * 1024, help="Chunk size in bytes (default: 4MiB)")
    p.add_argument("--verify", action="store_true", help="Verify overwrite by sampling (set last pass to zero for robust check)")
    p.add_argument("--verify-samples", type=int, default=4, help="Number of samples for verification")
    p.add_argument("--verify-sample-bytes", type=int, default=64 * 1024, help="Sample bytes per verification sample")
    p.add_argument("--rename", action="store_true", help="Rename to random name before unlink (default on)")
    p.add_argument("--no-rename", dest="rename", action="store_false", help="Disable rename before unlink")
    p.add_argument("--follow-symlinks", action="store_true", help="Follow symlinks (by default, symlinks are skipped)")
    p.add_argument("--throttle-mbps", type=float, help="Throttle throughput per worker (MB/s)")
    p.add_argument("--parallelism", type=int, default=2, help="Number of concurrent workers")
    p.add_argument("--dry-run", action="store_true", help="Do not modify anything, only log planned actions")
    p.add_argument("--yes", action="store_true", help="Confirm destructive operation")
    p.add_argument("--journal", type=str, help="Write JSONL journal to this path")
    return p.parse_args(argv)

def build_targets(args: argparse.Namespace) -> List[Tuple[str, str]]:
    targets: List[Tuple[str, str]] = []
    # From CLI paths
    for p in args.paths:
        kind = "dir" if args.dir or Path(p).is_dir() else "file"
        targets.append((kind, p))
    # From manifest
    if args.manifest:
        for kind, path_str in iter_manifest_entries(Path(args.manifest)):
            targets.append((kind, path_str))
    if not targets:
        raise SystemExit(2)
    return targets

def main(argv: List[str]) -> int:
    args = parse_args(argv)

    # Confirmation
    if not args.dry_run and not args.yes:
        sys.stderr.write("Refusing to proceed without --yes (or use --dry-run).\n")
        return 2

    policy = ErasurePolicy(
        passes=max(1, int(args.passes)),
        pattern=tuple(x.strip() for x in args.pattern.split(",") if x.strip()),
        chunk_size=max(4096, int(args.chunk_size)),
        verify=bool(args.verify),
        verify_samples=max(1, int(args.verify_samples)),
        verify_sample_bytes=max(1024, int(args.verify_sample_bytes)),
        rename_before_unlink=bool(args.rename if "rename" in args else True),
        follow_symlinks=bool(args.follow_symlinks),
        throttle_mbps=float(args.throttle_mbps) if args.throttle_mbps else None,
    )
    cfg = RunConfig(
        parallelism=max(1, int(args.parallelism)),
        dry_run=bool(args.dry_run),
        yes=bool(args.yes),
        journal_path=Path(args.journal) if args.journal else None,
    )

    jlog("erasure.start", policy=policy.__dict__, cfg=cfg.__dict__)

    # Build target list
    try:
        targets = build_targets(args)
    except SystemExit as e:
        return int(e.code)

    # Normalize targets: filter nonexistent paths if not dry-run only for logging
    norm_targets: List[Tuple[str, str]] = []
    for kind, p in targets:
        norm_targets.append((kind, p))
    jlog("erasure.targets", count=len(norm_targets))

    # Run
    try:
        exit_code = asyncio.run(run_erasure(norm_targets, policy, cfg))
    except KeyboardInterrupt:
        jlog("erasure.abort", reason="keyboard_interrupt")
        return 1

    # Post-scan outcomes: if any failure detected in stdout logs, operators can parse.
    # For CLI, we conservatively rescan targets for existence to derive return code.
    failures = 0
    if not cfg.dry_run:
        for kind, p in norm_targets:
            path = Path(p)
            try:
                if kind == "file":
                    if path.exists() and path.is_file():
                        failures += 1
                elif kind == "dir":
                    if path.exists() and path.is_dir():
                        failures += 1
            except Exception:
                failures += 1

    final_code = 0 if failures == 0 else 1
    jlog("erasure.done", failures=failures, exit_code=final_code)
    return final_code

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
