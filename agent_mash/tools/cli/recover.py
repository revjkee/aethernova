# agent_mash/tools/cli/recover.py
from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import errno
import hashlib
import io
import json
import os
import shutil
import stat
import sys
import tarfile
import tempfile
import textwrap
import zipfile
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

APP_NAME = "agent_mash.recover"
DEFAULT_MANIFEST_NAME = "MANIFEST.json"
DEFAULT_HASH_ALGO = "sha256"


class RecoverError(RuntimeError):
    """Recover domain error."""


@dataclasses.dataclass(frozen=True)
class ExitCodes:
    OK: int = 0
    USAGE: int = 2
    IO: int = 5
    DATA: int = 65
    SOFTWARE: int = 70


def _now_utc_compact() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _eprint(msg: str) -> None:
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


def _print(msg: str) -> None:
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def _is_within_directory(base: Path, target: Path) -> bool:
    try:
        base_resolved = base.resolve(strict=False)
        target_resolved = target.resolve(strict=False)
        return str(target_resolved).startswith(str(base_resolved) + os.sep) or target_resolved == base_resolved
    except Exception:
        return False


def _safe_relpath(p: str) -> str:
    # Normalize path inside archives to POSIX-like
    p = p.replace("\\", "/").lstrip("/")
    while p.startswith("../"):
        p = p[3:]
    return p


def _sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _atomic_replace_dir(src_dir: Path, dst_dir: Path) -> None:
    """
    Best-effort atomic directory replacement:
    - rename dst to backup name
    - rename src to dst
    - cleanup backup
    """
    if not src_dir.exists() or not src_dir.is_dir():
        raise RecoverError(f"Staging directory does not exist or not a directory: {src_dir}")

    dst_parent = dst_dir.parent
    _ensure_dir(dst_parent)

    backup_dir = dst_parent / f".{dst_dir.name}.pre_restore.{_now_utc_compact()}"
    if dst_dir.exists():
        try:
            dst_dir.replace(backup_dir)
        except OSError:
            # On Windows, replace may fail if directory not empty; fallback
            shutil.move(str(dst_dir), str(backup_dir))

    try:
        try:
            src_dir.replace(dst_dir)
        except OSError:
            shutil.move(str(src_dir), str(dst_dir))
    except Exception:
        # rollback best-effort
        if backup_dir.exists() and not dst_dir.exists():
            try:
                backup_dir.replace(dst_dir)
            except OSError:
                shutil.move(str(backup_dir), str(dst_dir))
        raise

    # cleanup backup if everything succeeded
    if backup_dir.exists():
        shutil.rmtree(backup_dir, ignore_errors=True)


def _chmod_writable(path: Path) -> None:
    try:
        mode = path.stat().st_mode
        path.chmod(mode | stat.S_IWUSR)
    except Exception:
        return


def _rmtree_force(path: Path) -> None:
    """
    Robust rmtree that tries to handle readonly bits (Windows-friendly).
    """
    if not path.exists():
        return

    def onerror(func, p, exc_info):
        try:
            _chmod_writable(Path(p))
        except Exception:
            pass
        try:
            func(p)
        except Exception:
            pass

    shutil.rmtree(path, onerror=onerror)


def _detect_archive_type(archive_path: Path) -> str:
    name = archive_path.name.lower()
    if name.endswith(".tar.gz") or name.endswith(".tgz"):
        return "tar.gz"
    if name.endswith(".tar"):
        return "tar"
    if name.endswith(".zip"):
        return "zip"
    raise RecoverError("Unsupported archive format. Use .tar, .tar.gz/.tgz, or .zip")


@dataclasses.dataclass
class ManifestEntry:
    path: str
    size: Optional[int] = None
    sha256: Optional[str] = None


@dataclasses.dataclass
class Manifest:
    version: int
    created_utc: str
    root_prefix: str
    hash_algo: str
    entries: List[ManifestEntry]

    @staticmethod
    def from_json(data: dict) -> "Manifest":
        version = int(data.get("version", 1))
        created_utc = str(data.get("created_utc", ""))
        root_prefix = str(data.get("root_prefix", "")).strip("/")
        hash_algo = str(data.get("hash_algo", DEFAULT_HASH_ALGO))
        raw_entries = data.get("entries", [])
        if not isinstance(raw_entries, list):
            raise RecoverError("MANIFEST.json: 'entries' must be a list")
        entries: List[ManifestEntry] = []
        for item in raw_entries:
            if not isinstance(item, dict):
                raise RecoverError("MANIFEST.json: entry must be an object")
            p = str(item.get("path", ""))
            if not p:
                raise RecoverError("MANIFEST.json: entry.path is required")
            entries.append(
                ManifestEntry(
                    path=_safe_relpath(p),
                    size=item.get("size", None),
                    sha256=item.get("sha256", None),
                )
            )
        return Manifest(
            version=version,
            created_utc=created_utc,
            root_prefix=root_prefix,
            hash_algo=hash_algo,
            entries=entries,
        )


def _read_manifest_from_bytes(b: bytes) -> Manifest:
    try:
        data = json.loads(b.decode("utf-8"))
    except Exception as e:
        raise RecoverError(f"Failed to parse MANIFEST.json: {e}") from e
    if not isinstance(data, dict):
        raise RecoverError("MANIFEST.json: root must be an object")
    return Manifest.from_json(data)


def _list_archive_members(archive_path: Path) -> List[str]:
    t = _detect_archive_type(archive_path)
    members: List[str] = []
    if t in ("tar", "tar.gz"):
        mode = "r:gz" if t == "tar.gz" else "r:"
        with tarfile.open(archive_path, mode) as tf:
            for m in tf.getmembers():
                if m.name is None:
                    continue
                members.append(_safe_relpath(m.name))
    elif t == "zip":
        with zipfile.ZipFile(archive_path, "r") as zf:
            for n in zf.namelist():
                members.append(_safe_relpath(n))
    return members


def _extract_file_bytes(archive_path: Path, internal_path: str) -> Optional[bytes]:
    internal_path = _safe_relpath(internal_path)
    t = _detect_archive_type(archive_path)
    if t in ("tar", "tar.gz"):
        mode = "r:gz" if t == "tar.gz" else "r:"
        with tarfile.open(archive_path, mode) as tf:
            try:
                member = tf.getmember(internal_path)
            except KeyError:
                return None
            if member.isdir():
                return None
            f = tf.extractfile(member)
            if f is None:
                return None
            with f:
                return f.read()
    elif t == "zip":
        with zipfile.ZipFile(archive_path, "r") as zf:
            try:
                with zf.open(internal_path, "r") as f:
                    return f.read()
            except KeyError:
                return None
    return None


def _find_manifest_path(members: List[str]) -> Optional[str]:
    # prefer exact at root
    if DEFAULT_MANIFEST_NAME in members:
        return DEFAULT_MANIFEST_NAME
    # otherwise search anywhere (first match)
    for m in members:
        if m.endswith("/" + DEFAULT_MANIFEST_NAME) or m.endswith("\\" + DEFAULT_MANIFEST_NAME):
            return m
        if m.endswith(DEFAULT_MANIFEST_NAME) and m.split("/")[-1] == DEFAULT_MANIFEST_NAME:
            return m
    return None


def _validate_manifest_vs_members(manifest: Manifest, members: List[str], strict: bool) -> None:
    # Build a set of file members (ignore directories)
    file_members = set()
    for m in members:
        m = _safe_relpath(m)
        if not m or m.endswith("/"):
            continue
        file_members.add(m)

    # If root_prefix present, entries are relative to that prefix inside archive
    prefix = manifest.root_prefix.strip("/")
    for e in manifest.entries:
        expected = _safe_relpath(e.path)
        if prefix:
            expected = f"{prefix}/{expected}".strip("/")
        if expected not in file_members:
            raise RecoverError(f"Archive missing file declared in MANIFEST.json: {expected}")

    if strict:
        # Strict means: every file member (except MANIFEST.json itself) must be declared
        declared = set()
        for e in manifest.entries:
            p = _safe_relpath(e.path)
            if prefix:
                p = f"{prefix}/{p}".strip("/")
            declared.add(p)
        for m in file_members:
            if m.endswith(DEFAULT_MANIFEST_NAME):
                continue
            if m not in declared:
                raise RecoverError(f"MANIFEST.json strict mode: undeclared file in archive: {m}")


def _extract_archive_to_dir(
    archive_path: Path,
    dest_dir: Path,
    root_prefix: str,
    overwrite: bool,
    log: bool,
) -> None:
    """
    Extract archive to dest_dir.
    If root_prefix is given, only extract that subtree and strip the prefix.
    """
    t = _detect_archive_type(archive_path)
    _ensure_dir(dest_dir)

    prefix = root_prefix.strip("/")

    def target_path_for(member_name: str) -> Optional[Path]:
        rel = _safe_relpath(member_name)
        if not rel:
            return None
        if prefix:
            if rel == prefix:
                return None
            if not rel.startswith(prefix + "/"):
                return None
            rel = rel[len(prefix) + 1 :]
        rel = _safe_relpath(rel)
        if not rel:
            return None
        out = dest_dir / rel
        if not _is_within_directory(dest_dir, out):
            raise RecoverError(f"Unsafe path traversal in archive member: {member_name}")
        return out

    if t in ("tar", "tar.gz"):
        mode = "r:gz" if t == "tar.gz" else "r:"
        with tarfile.open(archive_path, mode) as tf:
            for m in tf.getmembers():
                if m.name is None:
                    continue
                out = target_path_for(m.name)
                if out is None:
                    continue

                if m.isdir():
                    _ensure_dir(out)
                    continue

                _ensure_dir(out.parent)

                if out.exists() and not overwrite:
                    raise RecoverError(f"Refusing to overwrite existing file: {out}")

                f = tf.extractfile(m)
                if f is None:
                    continue
                with f:
                    data = f.read()

                with out.open("wb") as wf:
                    wf.write(data)

                if log:
                    _print(f"extracted: {out}")
    elif t == "zip":
        with zipfile.ZipFile(archive_path, "r") as zf:
            for n in zf.namelist():
                out = target_path_for(n)
                if out is None:
                    continue
                info = zf.getinfo(n)
                is_dir = n.endswith("/") or (info.external_attr & 0x10) != 0
                if is_dir:
                    _ensure_dir(out)
                    continue

                _ensure_dir(out.parent)

                if out.exists() and not overwrite:
                    raise RecoverError(f"Refusing to overwrite existing file: {out}")

                with zf.open(n, "r") as rf, out.open("wb") as wf:
                    shutil.copyfileobj(rf, wf)

                if log:
                    _print(f"extracted: {out}")
    else:
        raise RecoverError("Unsupported archive format")


def _create_manifest_for_dir(root_dir: Path, root_prefix: str = "") -> Manifest:
    entries: List[ManifestEntry] = []
    for p in sorted(root_dir.rglob("*")):
        if p.is_dir():
            continue
        rel = p.relative_to(root_dir).as_posix()
        entries.append(ManifestEntry(path=rel, size=p.stat().st_size, sha256=_sha256_file(p)))

    return Manifest(
        version=1,
        created_utc=_now_utc_compact(),
        root_prefix=root_prefix.strip("/"),
        hash_algo=DEFAULT_HASH_ALGO,
        entries=entries,
    )


def _manifest_to_json_bytes(m: Manifest) -> bytes:
    data = {
        "version": m.version,
        "created_utc": m.created_utc,
        "root_prefix": m.root_prefix,
        "hash_algo": m.hash_algo,
        "entries": [
            {"path": e.path, "size": e.size, "sha256": e.sha256}
            for e in m.entries
        ],
    }
    return (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _backup_dir_to_archive(src_dir: Path, archive_path: Path, include_manifest: bool, log: bool) -> None:
    if not src_dir.exists() or not src_dir.is_dir():
        raise RecoverError(f"Source directory does not exist or is not a directory: {src_dir}")

    t = _detect_archive_type(archive_path)
    _ensure_dir(archive_path.parent)

    manifest: Optional[Manifest] = None
    if include_manifest:
        manifest = _create_manifest_for_dir(src_dir)

    if t in ("tar", "tar.gz"):
        mode = "w:gz" if t == "tar.gz" else "w:"
        with tarfile.open(archive_path, mode) as tf:
            # Add files
            for p in sorted(src_dir.rglob("*")):
                arcname = p.relative_to(src_dir).as_posix()
                tf.add(p, arcname=arcname, recursive=False)

                if log and p.is_file():
                    _print(f"added: {arcname}")

            # Add manifest
            if manifest is not None:
                b = _manifest_to_json_bytes(manifest)
                ti = tarfile.TarInfo(name=DEFAULT_MANIFEST_NAME)
                ti.size = len(b)
                ti.mtime = int(_dt.datetime.now().timestamp())
                tf.addfile(ti, io.BytesIO(b))
                if log:
                    _print(f"added: {DEFAULT_MANIFEST_NAME}")
    elif t == "zip":
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for p in sorted(src_dir.rglob("*")):
                if p.is_dir():
                    continue
                arcname = p.relative_to(src_dir).as_posix()
                zf.write(p, arcname)
                if log:
                    _print(f"added: {arcname}")

            if manifest is not None:
                zf.writestr(DEFAULT_MANIFEST_NAME, _manifest_to_json_bytes(manifest))
                if log:
                    _print(f"added: {DEFAULT_MANIFEST_NAME}")
    else:
        raise RecoverError("Unsupported archive format")


def _verify_archive(
    archive_path: Path,
    strict_manifest: bool,
    verify_hashes: bool,
    log: bool,
) -> None:
    if not archive_path.exists() or not archive_path.is_file():
        raise RecoverError(f"Archive not found: {archive_path}")

    members = _list_archive_members(archive_path)
    manifest_path = _find_manifest_path(members)
    manifest: Optional[Manifest] = None

    if manifest_path is not None:
        b = _extract_file_bytes(archive_path, manifest_path)
        if b is None:
            raise RecoverError("MANIFEST.json found but could not be read")
        manifest = _read_manifest_from_bytes(b)
        _validate_manifest_vs_members(manifest, members, strict=strict_manifest)
        if log:
            _print(f"manifest: ok ({manifest_path})")
    else:
        if strict_manifest or verify_hashes:
            raise RecoverError("MANIFEST.json not found in archive (required by selected flags)")
        if log:
            _print("manifest: not present")

    if verify_hashes and manifest is not None:
        # Extract to temp and validate hashes without touching user destination
        with tempfile.TemporaryDirectory(prefix="recover_verify_") as td:
            tmp = Path(td)
            _extract_archive_to_dir(
                archive_path=archive_path,
                dest_dir=tmp,
                root_prefix=manifest.root_prefix,
                overwrite=True,
                log=False,
            )
            for e in manifest.entries:
                p = tmp / _safe_relpath(e.path)
                if not p.exists() or not p.is_file():
                    raise RecoverError(f"Hash verify: missing file after extraction: {e.path}")
                if e.sha256:
                    got = _sha256_file(p)
                    if got.lower() != e.sha256.lower():
                        raise RecoverError(f"Hash mismatch: {e.path} expected={e.sha256} got={got}")
            if log:
                _print("hashes: ok")


def _restore_archive(
    archive_path: Path,
    dest_dir: Path,
    require_manifest: bool,
    strict_manifest: bool,
    verify_hashes: bool,
    make_pre_backup: bool,
    pre_backup_dir: Optional[Path],
    dry_run: bool,
    overwrite: bool,
    log: bool,
) -> None:
    if not archive_path.exists() or not archive_path.is_file():
        raise RecoverError(f"Archive not found: {archive_path}")

    members = _list_archive_members(archive_path)
    manifest_path = _find_manifest_path(members)
    manifest: Optional[Manifest] = None

    if manifest_path is not None:
        b = _extract_file_bytes(archive_path, manifest_path)
        if b is None:
            raise RecoverError("MANIFEST.json found but could not be read")
        manifest = _read_manifest_from_bytes(b)
        _validate_manifest_vs_members(manifest, members, strict=strict_manifest)
    else:
        if require_manifest or strict_manifest or verify_hashes:
            raise RecoverError("MANIFEST.json not found in archive (required by selected flags)")

    root_prefix = manifest.root_prefix if manifest is not None else ""

    # Pre-backup
    pre_backup_path: Optional[Path] = None
    if make_pre_backup and dest_dir.exists():
        backup_base = pre_backup_dir if pre_backup_dir is not None else dest_dir.parent
        _ensure_dir(backup_base)
        pre_backup_path = backup_base / f"{dest_dir.name}.pre_restore.{_now_utc_compact()}.tar.gz"
        if log:
            _print(f"pre-backup: {pre_backup_path}")
        if not dry_run:
            _backup_dir_to_archive(dest_dir, pre_backup_path, include_manifest=True, log=False)

    if dry_run:
        _print("dry-run: no changes applied")
        if pre_backup_path is not None:
            _print(f"dry-run: would create pre-backup at {pre_backup_path}")
        _print(f"dry-run: would restore {archive_path} into {dest_dir}")
        return

    # Stage extraction
    with tempfile.TemporaryDirectory(prefix="recover_stage_") as td:
        stage = Path(td) / "stage"
        _ensure_dir(stage)

        _extract_archive_to_dir(
            archive_path=archive_path,
            dest_dir=stage,
            root_prefix=root_prefix,
            overwrite=True,
            log=log and False,
        )

        # Optional hash verification on staged content
        if verify_hashes and manifest is not None:
            for e in manifest.entries:
                p = stage / _safe_relpath(e.path)
                if not p.exists() or not p.is_file():
                    raise RecoverError(f"Staged content missing file: {e.path}")
                if e.sha256:
                    got = _sha256_file(p)
                    if got.lower() != e.sha256.lower():
                        raise RecoverError(f"Hash mismatch: {e.path} expected={e.sha256} got={got}")

        # If destination exists and overwrite not allowed: fail
        if dest_dir.exists() and not overwrite:
            raise RecoverError(f"Destination exists; use --overwrite to replace: {dest_dir}")

        # Replace destination
        # Ensure parent exists
        _ensure_dir(dest_dir.parent)

        # If destination doesn't exist, just move stage into place
        if not dest_dir.exists():
            try:
                stage.replace(dest_dir)
            except OSError:
                shutil.move(str(stage), str(dest_dir))
        else:
            # Atomic-ish replace by swap
            _atomic_replace_dir(stage, dest_dir)

    if log:
        _print("restore: ok")


def _build_parser() -> argparse.ArgumentParser:
    ep = textwrap.dedent(
        """
        Industrial recovery tool:
        - verify: validate archive + manifest (+ optional hashes)
        - restore: restore archive to destination with staging and optional pre-backup
        - backup: create archive from directory with MANIFEST.json and SHA-256
        """
    ).strip()

    p = argparse.ArgumentParser(
        prog="recover",
        description=ep,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument("--quiet", action="store_true", help="Suppress non-error output")
    p.add_argument("--verbose", action="store_true", help="Verbose output")

    sub = p.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verify", help="Verify archive integrity and optional hashes")
    v.add_argument("archive", type=str, help="Path to archive (.tar/.tar.gz/.tgz/.zip)")
    v.add_argument("--strict-manifest", action="store_true", help="Fail if archive contains undeclared files")
    v.add_argument("--verify-hashes", action="store_true", help="Verify sha256 hashes (requires MANIFEST.json)")

    r = sub.add_parser("restore", help="Restore archive into destination directory")
    r.add_argument("archive", type=str, help="Path to archive (.tar/.tar.gz/.tgz/.zip)")
    r.add_argument("dest", type=str, help="Destination directory to restore into")
    r.add_argument("--require-manifest", action="store_true", help="Require MANIFEST.json in archive")
    r.add_argument("--strict-manifest", action="store_true", help="Fail if archive contains undeclared files")
    r.add_argument("--verify-hashes", action="store_true", help="Verify sha256 hashes (requires MANIFEST.json)")
    r.add_argument("--no-pre-backup", action="store_true", help="Do not create pre-restore backup of destination")
    r.add_argument("--pre-backup-dir", type=str, default=None, help="Directory to store pre-restore backup archives")
    r.add_argument("--dry-run", action="store_true", help="Show what would happen without applying changes")
    r.add_argument("--overwrite", action="store_true", help="Allow replacing existing destination directory")

    b = sub.add_parser("backup", help="Create archive from directory (includes MANIFEST.json by default)")
    b.add_argument("src", type=str, help="Source directory to archive")
    b.add_argument("archive", type=str, help="Output archive path (.tar/.tar.gz/.tgz/.zip)")
    b.add_argument("--no-manifest", action="store_true", help="Do not include MANIFEST.json")
    return p


def _compute_log_flags(args: argparse.Namespace) -> Tuple[bool, bool]:
    quiet = bool(getattr(args, "quiet", False))
    verbose = bool(getattr(args, "verbose", False))
    if quiet:
        return False, True
    if verbose:
        return True, False
    return True, False


def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    p = _build_parser()
    try:
        args = p.parse_args(argv)
        log, quiet = _compute_log_flags(args)

        def log_print(s: str) -> None:
            if log and not quiet:
                _print(s)

        cmd = args.cmd
        if cmd == "verify":
            archive = Path(args.archive)
            _verify_archive(
                archive_path=archive,
                strict_manifest=bool(args.strict_manifest),
                verify_hashes=bool(args.verify_hashes),
                log=log and not quiet,
            )
            log_print("verify: ok")
            return ExitCodes.OK

        if cmd == "restore":
            archive = Path(args.archive)
            dest = Path(args.dest)
            pre_backup_dir = Path(args.pre_backup_dir) if args.pre_backup_dir else None

            _restore_archive(
                archive_path=archive,
                dest_dir=dest,
                require_manifest=bool(args.require_manifest),
                strict_manifest=bool(args.strict_manifest),
                verify_hashes=bool(args.verify_hashes),
                make_pre_backup=not bool(args.no_pre_backup),
                pre_backup_dir=pre_backup_dir,
                dry_run=bool(args.dry_run),
                overwrite=bool(args.overwrite),
                log=log and not quiet,
            )
            return ExitCodes.OK

        if cmd == "backup":
            src = Path(args.src)
            out = Path(args.archive)
            _backup_dir_to_archive(
                src_dir=src,
                archive_path=out,
                include_manifest=not bool(args.no_manifest),
                log=log and not quiet,
            )
            log_print("backup: ok")
            return ExitCodes.OK

        raise RecoverError("Unknown command")

    except RecoverError as e:
        _eprint(f"error: {e}")
        return ExitCodes.DATA
    except FileNotFoundError as e:
        _eprint(f"io error: {e}")
        return ExitCodes.IO
    except PermissionError as e:
        _eprint(f"permission error: {e}")
        return ExitCodes.IO
    except OSError as e:
        # classify common I/O conditions
        if e.errno in (errno.EIO, errno.ENOSPC, errno.EROFS):
            _eprint(f"io error: {e}")
            return ExitCodes.IO
        _eprint(f"os error: {e}")
        return ExitCodes.SOFTWARE
    except Exception as e:
        _eprint(f"fatal: {e}")
        return ExitCodes.SOFTWARE


if __name__ == "__main__":
    raise SystemExit(main())
