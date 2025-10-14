# datafabric/datafabric/tasks/backups/snapshot.py
# Industrial snapshot task for DataFabric:
# - Snapshot source: directory (tar) or command stdout (e.g., pg_dump)
# - Compression: gzip (stdlib) or zstd (if 'zstandard' installed)
# - Optional encryption via OpenSSL AES-256-GCM (streaming)
# - Streaming SHA-256 checksum and manifest (.json)
# - Storage backends: Local FS, S3 (if 'boto3' installed)
# - Retention policy (by count and/or age)
# - Atomic writes with temp files; PID-file locking
# - Robust retries/timeouts via datafabric.utils.retry
# - Structured logging via datafabric.observability.logging

from __future__ import annotations

import contextlib
import dataclasses
import errno
import glob
import hashlib
import io
import json
import os
import random
import shutil
import signal
import string
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# Logging
try:
    from datafabric.observability.logging import get_logger  # type: ignore
    log = get_logger("datafabric.backups.snapshot")
except Exception:
    import logging
    logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    log = logging.getLogger("datafabric.backups.snapshot")

# Retry
try:
    from datafabric.utils.retry import RetryPolicy, retry_call, aretry_call, default_http_retry_policy  # type: ignore
except Exception:
    # Minimal fallback without external deps
    class RetryError(RuntimeError): ...
    class RetryPolicy(dataclasses.dataclass):  # type: ignore
        def __init__(self, **_: Any) -> None: pass
    def retry_call(fn, *, policy=None, **kwargs):
        return fn(**kwargs)
    async def aretry_call(afn, *, policy=None, **kwargs):
        return await afn(**kwargs)
    def default_http_retry_policy(name: str = "http"): return RetryPolicy()

# Optional libs
try:
    import zstandard as zstd  # type: ignore
    HAS_ZSTD = True
except Exception:
    HAS_ZSTD = False

try:
    import boto3  # type: ignore
    from botocore.exceptions import BotoCoreError, ClientError  # type: ignore
    HAS_BOTO3 = True
except Exception:
    HAS_BOTO3 = False
    BotoCoreError = ClientError = Exception  # type: ignore

# ============
# Configuration
# ============
def _env(name: str, default: str = "") -> str:
    v = os.getenv(name)
    return v if v not in (None, "") else default

DF_BACKUP_TMPDIR = _env("DF_BACKUP_TMPDIR", "")
DF_BACKUP_RETENTION_COUNT = int(_env("DF_BACKUP_RETENTION_COUNT", "7"))
DF_BACKUP_RETENTION_DAYS = int(_env("DF_BACKUP_RETENTION_DAYS", "0"))  # 0 disables
DF_BACKUP_ZSTD_LEVEL = int(_env("DF_BACKUP_ZSTD_LEVEL", "10"))  # if zstd available
DF_BACKUP_GZIP_LEVEL = int(_env("DF_BACKUP_GZIP_LEVEL", "6"))
DF_BACKUP_OPENSSL = _env("DF_BACKUP_OPENSSL", "openssl")  # path to openssl or empty to disable encryption
DF_BACKUP_ENC_PASS = _env("DF_BACKUP_ENC_PASS", "")  # passphrase for AES-256-GCM if set
DF_BACKUP_ENC_SALT = _env("DF_BACKUP_ENC_SALT", "datafabric-salt")
DF_BACKUP_ENC_ITER = int(_env("DF_BACKUP_ENC_ITER", "100000"))
DF_BACKUP_ENC_ENABLED = _env("DF_BACKUP_ENC_ENABLED", "0") in ("1", "true", "TRUE", "yes", "YES")
DF_BACKUP_TIMEOUT_SEC = int(_env("DF_BACKUP_TIMEOUT_SEC", "3600"))
DF_BACKUP_NAME = _env("DF_BACKUP_NAME", "snapshot")
DF_BACKUP_LOCK_DIR = _env("DF_BACKUP_LOCK_DIR", "")

# S3 config (optional)
DF_S3_BUCKET = _env("DF_S3_BUCKET", "")
DF_S3_PREFIX = _env("DF_S3_PREFIX", "")
DF_S3_SSE = _env("DF_S3_SSE", "")  # e.g., "AES256" or "aws:kms"
DF_S3_REGION = _env("DF_S3_REGION", "")
DF_S3_ENDPOINT = _env("DF_S3_ENDPOINT", "")
DF_S3_PROFILE = _env("DF_S3_PROFILE", "")

# =============
# Util functions
# =============
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def rand_suffix(n: int = 6) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

@contextlib.contextmanager
def pidfile_lock(lockfile: Path, timeout_sec: int = 10):
    ensure_dir(lockfile.parent)
    start = time.monotonic()
    fd = None
    while True:
        try:
            fd = os.open(str(lockfile), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o640)
            os.write(fd, str(os.getpid()).encode("utf-8"))
            os.close(fd)
            fd = None
            log.debug("Acquired lock %s", lockfile)
            break
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise
            if time.monotonic() - start > timeout_sec:
                raise TimeoutError(f"lock timeout: {lockfile}")
            time.sleep(0.2)
    try:
        yield
    finally:
        with contextlib.suppress(Exception):
            os.unlink(lockfile)
            log.debug("Released lock %s", lockfile)

def sha256_file(path: Path, bufsize: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(bufsize), b""):
            h.update(chunk)
    return h.hexdigest()

# =========
# Compression
# =========
class Compressor:
    def __init__(self, method: str = "gzip"):
        if method not in ("gzip", "zstd"):
            raise ValueError("unsupported compression method")
        if method == "zstd" and not HAS_ZSTD:
            raise RuntimeError("zstd requested but 'zstandard' is not installed")
        self.method = method

    def ext(self) -> str:
        return ".zst" if (self.method == "zstd") else ".gz"

    def open_writer(self, raw: io.BufferedWriter):
        if self.method == "zstd":
            cctx = zstd.ZstdCompressor(level=DF_BACKUP_ZSTD_LEVEL)
            return cctx.stream_writer(raw)
        import gzip
        return gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=DF_BACKUP_GZIP_LEVEL)

# =========
# Encryption (via openssl)
# =========
def encryption_enabled() -> bool:
    return DF_BACKUP_ENC_ENABLED and DF_BACKUP_OPENSSL and DF_BACKUP_ENC_PASS

def openssl_encrypt_stream(outfile: io.BufferedWriter):
    # Open subprocess for streaming AES-256-GCM encryption using PBKDF2
    # echo -n PASS | openssl enc -aes-256-gcm -pbkdf2 -iter ITER -salt -S SALT_HEX -out out.enc
    salt_hex = hashlib.sha256(DF_BACKUP_ENC_SALT.encode("utf-8")).hexdigest()[:32]
    cmd = [
        DF_BACKUP_OPENSSL, "enc", "-aes-256-gcm", "-pbkdf2",
        "-iter", str(DF_BACKUP_ENC_ITER),
        "-salt", "-S", salt_hex,
        "-out", "/dev/stdout"
    ]
    env = os.environ.copy()
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env
    )
    assert proc.stdin and proc.stdout
    # Write passphrase to a separate derivation call: we pass via env var to avoid shell history
    # OpenSSL 'enc' expects password from terminal or -pass; we pass via env and -pass env:NAME
    # For portability, restart with -pass argument:
    proc.kill()
    cmd = [
        DF_BACKUP_OPENSSL, "enc", "-aes-256-gcm", "-pbkdf2",
        "-iter", str(DF_BACKUP_ENC_ITER),
        "-salt", "-S", salt_hex,
        "-pass", f"pass:{DF_BACKUP_ENC_PASS}",
        "-out", "/dev/stdout"
    ]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.stdin and proc.stdout
    return proc  # caller must pump data into stdin and read encrypted stdout into outfile

# =========
# Storage backends
# =========
class StorageBackend:
    def put(self, local_path: Path, dest_name: str) -> str:
        raise NotImplementedError

    def apply_retention(self, prefix: str, keep_count: int, max_age_days: int) -> None:
        raise NotImplementedError

class LocalFilesystemBackend(StorageBackend):
    def __init__(self, dest_dir: Path):
        self.dest = dest_dir
        ensure_dir(self.dest)

    def put(self, local_path: Path, dest_name: str) -> str:
        target = self.dest / dest_name
        tmp = self.dest / f".{dest_name}.tmp-{rand_suffix()}"
        ensure_dir(target.parent)
        shutil.copy2(local_path, tmp)
        os.replace(tmp, target)
        log.info("Stored snapshot locally: %s", target)
        return str(target)

    def apply_retention(self, prefix: str, keep_count: int, max_age_days: int) -> None:
        pattern = str(self.dest / f"{prefix}*")
        files = [Path(p) for p in glob.glob(pattern)]
        files = [p for p in files if p.is_file()]
        files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        now = time.time()
        to_delete: List[Path] = []
        if keep_count > 0 and len(files) > keep_count:
            to_delete += files[keep_count:]
        if max_age_days > 0:
            threshold = now - max_age_days * 86400
            to_delete += [p for p in files if p.stat().st_mtime < threshold]
            # de-dup
            to_delete = list({p: None for p in to_delete}.keys())
        for p in to_delete:
            with contextlib.suppress(Exception):
                p.unlink()
                log.info("Retention removed: %s", p)

class S3Backend(StorageBackend):
    def __init__(self, bucket: str, prefix: str = "", region: str = "", endpoint: str = "", profile: str = "", sse: str = ""):
        if not HAS_BOTO3:
            raise RuntimeError("boto3 is required for S3 backend")
        session_kw = {}
        if profile:
            session_kw["profile_name"] = profile
        self.session = boto3.session.Session(**session_kw)  # type: ignore
        self.client = self.session.client("s3", region_name=region or None, endpoint_url=endpoint or None)  # type: ignore
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.sse = sse

    def _key(self, dest_name: str) -> str:
        if self.prefix:
            return f"{self.prefix}/{dest_name}"
        return dest_name

    def put(self, local_path: Path, dest_name: str) -> str:
        key = self._key(dest_name)
        extra = {}
        if self.sse:
            extra["ServerSideEncryption"] = self.sse
        policy = default_http_retry_policy(name="s3_put")
        def _upload():
            with local_path.open("rb") as f:
                self.client.upload_fileobj(f, self.bucket, key, ExtraArgs=extra or None)  # type: ignore
            return f"s3://{self.bucket}/{key}"
        url = retry_call(_upload, policy=policy)
        log.info("Uploaded snapshot to S3: %s", url)
        return url

    def apply_retention(self, prefix: str, keep_count: int, max_age_days: int) -> None:
        policy = default_http_retry_policy(name="s3_list")
        def _list():
            paginator = self.client.get_paginator("list_objects_v2")  # type: ignore
            it = paginator.paginate(Bucket=self.bucket, Prefix=(self.prefix + "/" + prefix) if self.prefix else prefix)
            keys = []
            for page in it:
                for obj in page.get("Contents", []):
                    keys.append((obj["Key"], obj["LastModified"].timestamp()))
            return keys
        objs = retry_call(_list, policy=policy)
        objs.sort(key=lambda kv: kv[1], reverse=True)
        to_delete = []
        if keep_count > 0 and len(objs) > keep_count:
            to_delete += [k for k, _ in objs[keep_count:]]
        if max_age_days > 0:
            threshold = time.time() - max_age_days * 86400
            to_delete += [k for k, ts in objs if ts < threshold]
            to_delete = list(dict.fromkeys(to_delete))
        if to_delete:
            log.info("S3 retention deleting %d objects", len(to_delete))
            chunks = [to_delete[i:i+1000] for i in range(0, len(to_delete), 1000)]
            for ch in chunks:
                retry_call(lambda keys=ch: self.client.delete_objects(  # type: ignore
                    Bucket=self.bucket, Delete={"Objects": [{"Key": k} for k in keys]}
                ), policy=policy)

# =========
# Snapshot job
# =========
@dataclass
class SnapshotSource:
    kind: str  # "dir" | "command"
    path: Optional[Path] = None            # for kind="dir"
    includes: Tuple[str, ...] = field(default_factory=tuple)
    excludes: Tuple[str, ...] = field(default_factory=tuple)
    command: Optional[Sequence[str]] = None  # for kind="command" (argv)

@dataclass
class SnapshotResult:
    archive_path: Path
    manifest_path: Path
    checksum: str
    size_bytes: int
    dest_url: Optional[str] = None

@dataclass
class SnapshotPolicy:
    name: str = DF_BACKUP_NAME
    compression: str = "zstd" if HAS_ZSTD else "gzip"  # "gzip" | "zstd"
    encrypt: bool = encryption_enabled()
    timeout_sec: int = DF_BACKUP_TIMEOUT_SEC
    retention_keep: int = DF_BACKUP_RETENTION_COUNT
    retention_days: int = DF_BACKUP_RETENTION_DAYS
    labels: Dict[str, str] = field(default_factory=dict)

class SnapshotTask:
    def __init__(self, source: SnapshotSource, storage: StorageBackend, work_dir: Optional[Path] = None, lock_dir: Optional[Path] = None):
        self.source = source
        self.storage = storage
        self.work_dir = Path(work_dir) if work_dir else Path(DF_BACKUP_TMPDIR or tempfile.gettempdir()) / "datafabric-backups"
        self.lock_dir = Path(lock_dir) if lock_dir else Path(DF_BACKUP_LOCK_DIR or (self.work_dir / "locks"))
        ensure_dir(self.work_dir)
        ensure_dir(self.lock_dir)

    def run(self, policy: Optional[SnapshotPolicy] = None) -> SnapshotResult:
        pol = policy or SnapshotPolicy()
        lockfile = self.lock_dir / f"{pol.name}.lock"
        with pidfile_lock(lockfile, timeout_sec=15):
            return self._run_locked(pol)

    # ---- internals ----
    def _run_locked(self, pol: SnapshotPolicy) -> SnapshotResult:
        started = utc_now_iso()
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        suffix = rand_suffix()
        comp = Compressor(pol.compression)
        base_name = f"{pol.name}-{ts}-{suffix}"
        tar_name = base_name + ".tar"
        comp_name = tar_name + comp.ext()
        enc_name = comp_name + ".enc" if pol.encrypt else comp_name

        tmp_dir = Path(tempfile.mkdtemp(prefix="df-snap-", dir=str(self.work_dir)))
        log.info("Snapshot started name=%s work=%s", base_name, tmp_dir)

        tar_path = tmp_dir / tar_name
        comp_path = tmp_dir / comp_name
        out_final_path = tmp_dir / enc_name
        manifest_path = tmp_dir / (base_name + ".json")

        # Produce tar
        self._make_tar(self.source, tar_path)

        # Compress (streaming)
        self._compress_file(tar_path, comp_path, comp)

        # Optionally encrypt
        if pol.encrypt:
            self._encrypt_file(comp_path, out_final_path)
        else:
            out_final_path = comp_path

        # Checksum + size
        checksum = sha256_file(out_final_path)
        size_bytes = out_final_path.stat().st_size

        # Manifest
        manifest = {
            "version": 1,
            "name": pol.name,
            "base_name": base_name,
            "created_at": started,
            "source": dataclasses.asdict(self.source),
            "compression": pol.compression,
            "encrypted": bool(pol.encrypt),
            "archive_file": out_final_path.name,
            "sha256": checksum,
            "size_bytes": size_bytes,
            "labels": pol.labels,
            "env": {
                "hostname": os.uname().nodename if hasattr(os, "uname") else os.getenv("COMPUTERNAME", "unknown"),
                "pid": os.getpid(),
                "python": sys.version.split()[0],
            },
        }
        manifest_tmp = tmp_dir / (manifest_path.name + ".tmp")
        manifest_tmp.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(manifest_tmp, manifest_path)

        # Upload artifact + manifest (atomic put per backend)
        url_art = self.storage.put(out_final_path, out_final_path.name)
        url_manifest = self.storage.put(manifest_path, manifest_path.name)
        log.info("Snapshot uploaded artifact=%s manifest=%s", url_art, url_manifest)

        # Apply retention
        try:
            self.storage.apply_retention(prefix=f"{pol.name}-", keep_count=pol.retention_keep, max_age_days=pol.retention_days)
        except Exception as e:
            log.warning("Retention apply failed: %s", e)

        # Move products into a stable local cache folder (optional)
        # Here we keep within tmp; caller may move if needed.

        result = SnapshotResult(
            archive_path=out_final_path,
            manifest_path=manifest_path,
            checksum=checksum,
            size_bytes=size_bytes,
            dest_url=url_art,
        )
        log.info("Snapshot completed name=%s size=%d sha256=%s", base_name, size_bytes, checksum)
        return result

    # ---- tar creation ----
    def _make_tar(self, source: SnapshotSource, tar_path: Path) -> None:
        if source.kind == "dir":
            assert source.path, "path required for dir snapshot"
            path = source.path.resolve()
            if not path.exists():
                raise FileNotFoundError(path)
            with tarfile.open(tar_path, mode="w", dereference=False) as tar:
                for root, dirs, files in os.walk(path):
                    rel_root = os.path.relpath(root, start=path)
                    # apply exclude rules
                    if self._is_excluded(rel_root, source.excludes):
                        dirs[:] = []  # prune
                        continue
                    for name in files:
                        rel = os.path.normpath(os.path.join(rel_root, name))
                        if self._is_included(rel, source.includes) and not self._is_excluded(rel, source.excludes):
                            full = path / rel
                            tar.add(full, arcname=str(Path(source.path.name) / rel))
            log.info("Tar created from dir: %s", tar_path)
            return
        elif source.kind == "command":
            assert source.command, "command required for command snapshot"
            # We capture stdout to file via temporary plain file, then tar as single file stream
            with tempfile.NamedTemporaryFile(delete=False, dir=str(tar_path.parent)) as tmp:
                tmp_path = Path(tmp.name)
            try:
                self._run_command_to_file(source.command, tmp_path)
                with tarfile.open(tar_path, mode="w") as tar:
                    tar.add(tmp_path, arcname="command_output.bin")
                log.info("Tar created from command output: %s", tar_path)
            finally:
                with contextlib.suppress(Exception):
                    tmp_path.unlink()
            return
        else:
            raise ValueError("unsupported source.kind")

    @staticmethod
    def _is_included(rel: str, includes: Tuple[str, ...]) -> bool:
        if not includes:
            return True
        import fnmatch
        return any(fnmatch.fnmatch(rel, pat) for pat in includes)

    @staticmethod
    def _is_excluded(rel: str, excludes: Tuple[str, ...]) -> bool:
        if not excludes:
            return False
        import fnmatch
        return any(fnmatch.fnmatch(rel, pat) for pat in excludes)

    # ---- compression ----
    def _compress_file(self, src: Path, dst: Path, comp: Compressor, buf: int = 1024 * 1024) -> None:
        with src.open("rb", buffering=0) as fin, dst.open("wb", buffering=0) as raw_out:
            with comp.open_writer(raw_out) as cout:
                # stream copy
                for chunk in iter(lambda: fin.read(buf), b""):
                    cout.write(chunk)
        log.info("Compressed %s -> %s", src, dst)

    # ---- encryption ----
    def _encrypt_file(self, src: Path, dst: Path, buf: int = 1024 * 1024) -> None:
        if not encryption_enabled():
            raise RuntimeError("encryption requested but disabled/misconfigured")
        # Stream through openssl
        proc = openssl_encrypt_stream(dst.open("wb"))
        assert proc.stdin and proc.stdout
        with src.open("rb", buffering=0) as fin, dst.open("wb", buffering=0) as fout:
            # restart proc to bind fout
            proc.kill()
            proc = openssl_encrypt_stream(fout)  # new binding
            assert proc.stdin and proc.stdout
            try:
                for chunk in iter(lambda: fin.read(buf), b""):
                    proc.stdin.write(chunk)
                proc.stdin.close()
                # read all encrypted output from stdout to fout
                for chunk in iter(lambda: proc.stdout.read(buf), b""):
                    fout.write(chunk)
                rc = proc.wait()
                if rc != 0:
                    err = proc.stderr.read().decode("utf-8", errors="ignore") if proc.stderr else ""
                    raise RuntimeError(f"openssl enc failed rc={rc} err={err}")
            finally:
                with contextlib.suppress(Exception):
                    if proc.poll() is None:
                        proc.kill()
        log.info("Encrypted %s -> %s (AES-256-GCM via openssl)", src, dst)

    # ---- command exec ----
    def _run_command_to_file(self, argv: Sequence[str], out_path: Path) -> None:
        log.info("Running command for snapshot: %s", " ".join(argv))
        with out_path.open("wb", buffering=0) as fout:
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            assert proc.stdout and proc.stderr
            try:
                buf = 1024 * 1024
                while True:
                    chunk = proc.stdout.read(buf)
                    if not chunk:
                        break
                    fout.write(chunk)
                stderr = proc.stderr.read().decode("utf-8", errors="ignore")
                rc = proc.wait(timeout=DF_BACKUP_TIMEOUT_SEC)
                if rc != 0:
                    raise RuntimeError(f"command failed rc={rc} stderr={stderr[:2000]}")
            finally:
                with contextlib.suppress(Exception):
                    if proc.poll() is None:
                        proc.kill()

# =========
# Factory helpers for backends
# =========
def make_local_backend(dest_dir: str | Path) -> LocalFilesystemBackend:
    return LocalFilesystemBackend(Path(dest_dir))

def make_s3_backend() -> S3Backend:
    if not DF_S3_BUCKET:
        raise RuntimeError("DF_S3_BUCKET is not set")
    return S3Backend(
        bucket=DF_S3_BUCKET,
        prefix=DF_S3_PREFIX,
        region=DF_S3_REGION,
        endpoint=DF_S3_ENDPOINT,
        profile=DF_S3_PROFILE,
        sse=DF_S3_SSE
    )

# =========
# Example CLI usage (python -m ...)
# =========
def _parse_argv(argv: Sequence[str]) -> Dict[str, Any]:
    import argparse
    p = argparse.ArgumentParser(description="DataFabric Snapshot Task")
    sub = p.add_subparsers(dest="mode", required=True)

    p_dir = sub.add_parser("dir", help="Snapshot a directory")
    p_dir.add_argument("--path", required=True, help="Directory path")
    p_dir.add_argument("--include", action="append", default=[], help="Glob include pattern (repeatable)")
    p_dir.add_argument("--exclude", action="append", default=[], help="Glob exclude pattern (repeatable)")

    p_cmd = sub.add_parser("cmd", help="Snapshot a command stdout")
    p_cmd.add_argument("--", dest="cmd", nargs=argparse.REMAINDER, help="Command argv after --", required=False)

    p.add_argument("--name", default=DF_BACKUP_NAME)
    p.add_argument("--compression", choices=["gzip", "zstd"], default=("zstd" if HAS_ZSTD else "gzip"))
    p.add_argument("--encrypt", action="store_true", default=DF_BACKUP_ENC_ENABLED)
    p.add_argument("--dest-local", help="Destination local directory")
    p.add_argument("--dest-s3", action="store_true", help="Use S3 from env (DF_S3_*)")
    p.add_argument("--labels", action="append", default=[], help="k=v labels")
    p.add_argument("--retention-keep", type=int, default=DF_BACKUP_RETENTION_COUNT)
    p.add_argument("--retention-days", type=int, default=DF_BACKUP_RETENTION_DAYS)
    args = p.parse_args(argv)

    labels = {}
    for kv in args.labels:
        if "=" in kv:
            k, v = kv.split("=", 1)
            labels[k] = v

    if args.dest_s3:
        storage = make_s3_backend()
    else:
        if not args.dest_local:
            raise SystemExit("either --dest-local or --dest-s3 required")
        storage = make_local_backend(args.dest_local)

    if args.mode == "dir":
        source = SnapshotSource(kind="dir", path=Path(args.path), includes=tuple(args.include), excludes=tuple(args.exclude))
    else:
        # everything after first '--' is command
        # Example: python -m datafabric.tasks.backups.snapshot cmd -- pg_dump -h ... -U ...
        cmd = []
        if args.cmd:
            cmd = args.cmd
        if not cmd:
            raise SystemExit("cmd mode requires command after --")
        source = SnapshotSource(kind="command", command=cmd)

    pol = SnapshotPolicy(
        name=args.name,
        compression=args.compression,
        encrypt=bool(args.encrypt),
        retention_keep=args.retention_keep,
        retention_days=args.retention_days,
        labels=labels,
    )
    return {"source": source, "storage": storage, "policy": pol}

def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        opts = _parse_argv(argv or sys.argv[1:])
        task = SnapshotTask(opts["source"], opts["storage"])
        res = task.run(policy=opts["policy"])
        print(json.dumps({
            "archive": str(res.archive_path),
            "manifest": str(res.manifest_path),
            "sha256": res.checksum,
            "size": res.size_bytes,
            "dest_url": res.dest_url,
        }, ensure_ascii=False, indent=2))
        return 0
    except Exception as e:
        log.exception("Snapshot failed: %s", e)
        return 2

if __name__ == "__main__":
    sys.exit(main())
