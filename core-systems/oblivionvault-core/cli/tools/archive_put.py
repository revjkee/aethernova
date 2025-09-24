# file: cli/tools/archive_put.py
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import contextlib
import dataclasses
import fnmatch
import hashlib
import io
import json
import logging
import logging.handlers
import mimetypes
import os
import pathlib
import queue
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import uuid
import zipfile
from dataclasses import dataclass
from typing import Iterable, Iterator, List, Optional, Sequence, Tuple

# ---- Optional project logger (fallback to local JSON if not present)
try:
    from oblivionvault.observability.logging import (
        LogConfig, init_logging, get_logger, set_context
    )  # type: ignore
    _HAS_OV_LOGGER = True
except Exception:
    _HAS_OV_LOGGER = False

    class _JsonFormatter(logging.Formatter):
        SENSITIVE = {k.lower() for k in (
            "password","pass","secret","token","api_key","authorization","cookie","set-cookie","x-api-key",
            "refresh_token","access_token","aws_secret_access_key","aws_session_token"
        )}
        def format(self, record: logging.LogRecord) -> str:
            d = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
                "pid": os.getpid(),
            }
            if record.exc_info:
                d["exc"] = self.formatException(record.exc_info)
            return json.dumps(d, ensure_ascii=False)

    def _fallback_init_logging(level: str = "INFO") -> logging.Logger:
        root = logging.getLogger()
        for h in list(root.handlers):
            root.removeHandler(h)
        root.setLevel(getattr(logging, level.upper(), logging.INFO))
        q = queue.Queue(-1)
        qh = logging.handlers.QueueHandler(q)
        root.addHandler(qh)
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(_JsonFormatter())
        listener = logging.handlers.QueueListener(q, sh, respect_handler_level=False)
        listener.start()
        return logging.getLogger("archive_put")

    def get_logger(name: str = "archive_put") -> logging.Logger:
        return logging.getLogger(name)

# ---- Optional extras
try:
    import boto3  # type: ignore
    from botocore.exceptions import BotoCoreError, ClientError  # type: ignore
    _HAS_BOTO3 = True
except Exception:
    _HAS_BOTO3 = False

# -----------------------
# Helpers and primitives
# -----------------------

CHUNK_SIZE = 1024 * 1024  # 1 MiB streaming
DEFAULT_EXCLUDES = (
    ".git/**", "__pycache__/**", "node_modules/**", "*.pyc", "*.pyo", "*.DS_Store",
)

def uuid4() -> str:
    return str(uuid.uuid4())

def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb", buffering=0) as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def size_of(path: pathlib.Path) -> int:
    return path.stat().st_size

def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def guess_mime(path: pathlib.Path) -> str:
    return mimetypes.guess_type(str(path))[0] or "application/octet-stream"

def expand_sources(sources: Sequence[str]) -> List[pathlib.Path]:
    out: List[pathlib.Path] = []
    for s in sources:
        p = pathlib.Path(s).expanduser().resolve()
        if not p.exists():
            raise FileNotFoundError(f"Source not found: {p}")
        out.append(p)
    return out

def normalize_patterns(patterns: Sequence[str]) -> Tuple[str, ...]:
    return tuple(p.strip() for p in patterns if p and p.strip())

def match_excluded(rel: str, excludes: Tuple[str, ...]) -> bool:
    # glob-style matching against posix path
    r = rel.replace(os.sep, "/")
    for pat in excludes:
        if fnmatch.fnmatch(r, pat):
            return True
    return False

@dataclass
class ManifestEntry:
    path: str
    size: int
    sha256: str

@dataclass
class Manifest:
    schema: str
    version: str
    created_at: str
    host: str
    tool: str
    archive_name: str
    archive_size: int
    archive_sha256: str
    format: str
    compression: str
    source_count: int
    files: List[ManifestEntry]

    def to_dict(self) -> dict:
        return {
            "schema": self.schema,
            "version": self.version,
            "created_at": self.created_at,
            "host": self.host,
            "tool": self.tool,
            "archive_name": self.archive_name,
            "archive_size": self.archive_size,
            "archive_sha256": self.archive_sha256,
            "format": self.format,
            "compression": self.compression,
            "source_count": self.source_count,
            "files": [dataclasses.asdict(f) for f in self.files],
        }

# -----------------------
# Archive builders
# -----------------------

def iter_files(root: pathlib.Path, excludes: Tuple[str, ...]) -> Iterator[Tuple[pathlib.Path, str]]:
    base = root
    if root.is_file():
        rel = root.name
        if not match_excluded(rel, excludes):
            yield root, rel
        return
    for p in base.rglob("*"):
        if p.is_file():
            rel = str(p.relative_to(base)).replace(os.sep, "/")
            if not match_excluded(rel, excludes):
                yield p, rel

def build_tar_gz(sources: Sequence[pathlib.Path],
                 excludes: Tuple[str, ...],
                 tmp_dir: pathlib.Path,
                 base_dir_name: Optional[str] = None) -> Tuple[pathlib.Path, List[ManifestEntry]]:
    # archive path
    arc_path = tmp_dir / f"{base_dir_name or 'archive'}.tar.gz"
    entries: List[ManifestEntry] = []
    # deterministic mtime
    fixed_mtime = 0
    with arc_path.open("wb") as fobj:
        with tarfile.open(fileobj=fobj, mode="w:gz", compresslevel=6) as tf:
            for src in sources:
                root_name = base_dir_name or src.name
                root_prefix = f"{root_name}/" if len(sources) > 1 or src.is_dir() else ""
                if src.is_file():
                    rel = root_prefix + src.name
                    if match_excluded(src.name, excludes):
                        continue
                    ti = tf.gettarinfo(str(src), arcname=rel)
                    ti.mtime = fixed_mtime
                    with src.open("rb") as f:
                        tf.addfile(ti, fileobj=f)
                    entries.append(ManifestEntry(path=rel, size=ti.size or 0, sha256=sha256_file(src)))
                else:
                    for p, rel in iter_files(src, excludes):
                        arcname = root_prefix + rel
                        ti = tf.gettarinfo(str(p), arcname=arcname)
                        ti.mtime = fixed_mtime
                        with p.open("rb") as f:
                            tf.addfile(ti, fileobj=f)
                        entries.append(ManifestEntry(path=arcname, size=ti.size or 0, sha256=sha256_file(p)))
    return arc_path, entries

def build_zip(sources: Sequence[pathlib.Path],
              excludes: Tuple[str, ...],
              tmp_dir: pathlib.Path,
              base_dir_name: Optional[str] = None) -> Tuple[pathlib.Path, List[ManifestEntry]]:
    arc_path = tmp_dir / f"{base_dir_name or 'archive'}.zip"
    entries: List[ManifestEntry] = []
    # deterministic zip: set date_time to epoch
    epoch = (1980, 1, 1, 0, 0, 0)
    with zipfile.ZipFile(arc_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for src in sources:
            root_name = base_dir_name or src.name
            root_prefix = f"{root_name}/" if len(sources) > 1 or src.is_dir() else ""
            if src.is_file():
                rel = root_prefix + src.name
                if match_excluded(src.name, excludes):
                    continue
                zi = zipfile.ZipInfo(rel)
                zi.date_time = epoch
                zi.compress_type = zipfile.ZIP_DEFLATED
                with src.open("rb") as f:
                    data = f.read()
                zf.writestr(zi, data)
                entries.append(ManifestEntry(path=rel, size=len(data), sha256=sha256_bytes(data)))
            else:
                for p, rel in iter_files(src, excludes):
                    arcname = root_prefix + rel
                    zi = zipfile.ZipInfo(arcname)
                    zi.date_time = epoch
                    zi.compress_type = zipfile.ZIP_DEFLATED
                    with p.open("rb") as f:
                        data = f.read()
                    zf.writestr(zi, data)
                    entries.append(ManifestEntry(path=arcname, size=len(data), sha256=sha256_bytes(data)))
    return arc_path, entries

# -----------------------
# Optional GPG encryption
# -----------------------

def gpg_available() -> bool:
    return shutil.which("gpg") is not None

def gpg_encrypt(src: pathlib.Path,
                dst: pathlib.Path,
                *,
                recipient: Optional[Sequence[str]] = None,
                symmetric: bool = False,
                cipher: str = "AES256",
                passphrase: Optional[str] = None,
                armor: bool = False,
                log: logging.Logger) -> None:
    if not gpg_available():
        raise RuntimeError("gpg not found in PATH")
    cmd = ["gpg", "--batch", "--yes", "--cipher-algo", cipher]
    if armor:
        cmd.append("--armor")
    if symmetric:
        cmd.append("--symmetric")
        if passphrase:
            cmd.extend(["--passphrase", passphrase])
    else:
        if not recipient:
            raise ValueError("recipient must be provided for asymmetric encryption")
        for r in recipient:
            cmd.extend(["--recipient", r])
        cmd.append("--encrypt")
    cmd.extend(["--output", str(dst), str(src)])
    log.info("gpg_encrypt_start", extra={"cmd": " ".join(c for c in cmd if c != passphrase)})
    cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if cp.returncode != 0:
        log.error("gpg_encrypt_failed", extra={"code": cp.returncode, "stderr": cp.stderr[:500]})
        raise RuntimeError(f"gpg failed: {cp.stderr}")
    log.info("gpg_encrypt_ok", extra={"out": dst.name})

# -----------------------
# Uploaders
# -----------------------

class Uploader:
    def put(self, src: pathlib.Path, dest_uri: str, *, content_type: str, log: logging.Logger) -> None:
        raise NotImplementedError()
    def verify(self, src: pathlib.Path, dest_uri: str, *, log: logging.Logger) -> bool:
        return True

class FileUploader(Uploader):
    def put(self, src: pathlib.Path, dest_uri: str, *, content_type: str, log: logging.Logger) -> None:
        # dest_uri: file:///abs/path or plain local path
        path = parse_file_uri(dest_uri)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        log.info("file_copy_start", extra={"src": str(src), "dst": str(path)})
        shutil.copyfile(src, tmp)
        os.replace(tmp, path)  # atomic
        log.info("file_copy_ok", extra={"dst": str(path)})

    def verify(self, src: pathlib.Path, dest_uri: str, *, log: logging.Logger) -> bool:
        path = parse_file_uri(dest_uri)
        if not path.exists():
            return False
        ok = size_of(path) == size_of(src) and sha256_file(path) == sha256_file(src)
        log.info("file_verify", extra={"ok": ok})
        return ok

class HTTPUploader(Uploader):
    def put(self, src: pathlib.Path, dest_uri: str, *, content_type: str, log: logging.Logger) -> None:
        # Support PUT (default) and POST if query param method=post
        url = urllib.parse.urlparse(dest_uri)
        qs = urllib.parse.parse_qs(url.query)
        method = "POST" if qs.get("method", ["put"])[0].lower() == "post" else "PUT"
        headers = {
            "Content-Type": content_type,
            "Content-Length": str(size_of(src)),
            "Content-SHA256": sha256_file(src),
        }
        data = src.read_bytes()
        req = urllib.request.Request(dest_uri, method=method, data=data, headers=headers)
        backoff = 0.5
        attempts = 5
        for i in range(1, attempts + 1):
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    if 200 <= resp.status < 300:
                        log.info("http_upload_ok", extra={"status": resp.status})
                        return
                    raise RuntimeError(f"HTTP status {resp.status}")
            except Exception as e:
                if i == attempts:
                    log.error("http_upload_failed", extra={"attempt": i, "error": str(e)})
                    raise
                log.warning("http_upload_retry", extra={"attempt": i, "error": str(e)})
                time.sleep(backoff)
                backoff = min(backoff * 2, 8.0)

class S3Uploader(Uploader):
    def __init__(self):
        self.has_boto = _HAS_BOTO3

    def put(self, src: pathlib.Path, dest_uri: str, *, content_type: str, log: logging.Logger) -> None:
        bucket, key, qs = parse_s3_uri(dest_uri)
        acl = qs.get("acl", [""])[0] or None
        storage_class = qs.get("storage_class", [""])[0] or None
        if self.has_boto:
            s3 = boto3.client("s3")  # type: ignore
            extra = {"ContentType": content_type}
            if acl: extra["ACL"] = acl
            if storage_class: extra["StorageClass"] = storage_class
            backoff = 0.5
            attempts = 5
            for i in range(1, attempts + 1):
                try:
                    s3.upload_file(str(src), bucket, key, ExtraArgs=extra)  # type: ignore
                    log.info("s3_upload_ok", extra={"bucket": bucket, "key": key})
                    return
                except Exception as e:
                    if i == attempts:
                        log.error("s3_upload_failed", extra={"attempt": i, "error": str(e)})
                        raise
                    log.warning("s3_upload_retry", extra={"attempt": i, "error": str(e)})
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 8.0)
        else:
            # fallback to aws cli
            if shutil.which("aws") is None:
                raise RuntimeError("boto3 not installed and aws cli not found")
            cmd = ["aws", "s3", "cp", str(src), f"s3://{bucket}/{key}"]
            if acl:
                cmd.extend(["--acl", acl])
            if storage_class:
                cmd.extend(["--storage-class", storage_class])
            log.info("s3_cli_upload_start", extra={"cmd": " ".join(cmd)})
            cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if cp.returncode != 0:
                log.error("s3_cli_upload_failed", extra={"code": cp.returncode, "stderr": cp.stderr[:500]})
                raise RuntimeError(f"aws s3 cp failed: {cp.stderr}")
            log.info("s3_cli_upload_ok")

    def verify(self, src: pathlib.Path, dest_uri: str, *, log: logging.Logger) -> bool:
        try:
            bucket, key, _ = parse_s3_uri(dest_uri)
            if self.has_boto:
                s3 = boto3.client("s3")  # type: ignore
                head = s3.head_object(Bucket=bucket, Key=key)  # type: ignore
                ok = int(head["ContentLength"]) == size_of(src)
                log.info("s3_verify", extra={"ok": ok})
                return ok
            else:
                # best effort using aws cli: list size
                cmd = ["aws", "s3api", "head-object", "--bucket", bucket, "--key", key]
                cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if cp.returncode != 0:
                    return False
                meta = json.loads(cp.stdout)
                ok = int(meta.get("ContentLength", -1)) == size_of(src)
                log.info("s3_verify", extra={"ok": ok})
                return ok
        except Exception:
            return False

# -----------------------
# URI helpers
# -----------------------

def parse_dest(dest: str) -> Tuple[str, str]:
    parsed = urllib.parse.urlparse(dest)
    scheme = parsed.scheme.lower()
    return scheme, dest

def parse_file_uri(uri: str) -> pathlib.Path:
    p = urllib.parse.urlparse(uri)
    if p.scheme in ("", "file"):
        # if empty scheme, treat as local path
        path = p.path if p.scheme else uri
        return pathlib.Path(path).expanduser().resolve()
    raise ValueError(f"Unsupported file uri: {uri}")

def parse_s3_uri(uri: str) -> Tuple[str, str, dict]:
    p = urllib.parse.urlparse(uri)
    if p.scheme != "s3":
        raise ValueError("not an s3 uri")
    bucket = p.netloc
    key = p.path.lstrip("/")
    qs = urllib.parse.parse_qs(p.query)
    return bucket, key, qs

def get_uploader_for(dest: str) -> Uploader:
    scheme, _ = parse_dest(dest)
    if scheme in ("", "file"):
        return FileUploader()
    if scheme in ("http", "https"):
        return HTTPUploader()
    if scheme == "s3":
        return S3Uploader()
    raise ValueError(f"Unsupported destination scheme: {scheme}")

# -----------------------
# Orchestration
# -----------------------

@dataclass
class BuildResult:
    archive_path: pathlib.Path
    manifest_path: pathlib.Path
    archive_sha256: str
    archive_size: int

def build_archive_and_manifest(
    sources: Sequence[pathlib.Path],
    *,
    fmt: str,
    excludes: Tuple[str, ...],
    temp_dir: pathlib.Path,
    name: Optional[str],
    log: logging.Logger
) -> BuildResult:
    base_dir_name = name or (sources[0].name if len(sources) == 1 else "bundle")
    log.info("archive_build_start", extra={"format": fmt, "base": base_dir_name})
    if fmt == "tar.gz":
        arc_path, files = build_tar_gz(sources, excludes, temp_dir, base_dir_name)
        compression = "gzip"
    elif fmt == "zip":
        arc_path, files = build_zip(sources, excludes, temp_dir, base_dir_name)
        compression = "deflate"
    else:
        raise ValueError("Unsupported format (use tar.gz or zip)")
    arc_sha = sha256_file(arc_path)
    arc_size = size_of(arc_path)
    manifest = Manifest(
        schema="oblivionvault.archive_manifest",
        version="1.0",
        created_at=now_iso(),
        host=os.uname().nodename if hasattr(os, "uname") else "unknown",
        tool="archive_put.py",
        archive_name=arc_path.name,
        archive_size=arc_size,
        archive_sha256=arc_sha,
        format=fmt,
        compression=compression,
        source_count=len(sources),
        files=files,
    )
    man_path = temp_dir / f"{arc_path.name}.manifest.json"
    man_path.write_text(json.dumps(manifest.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    log.info("archive_build_ok", extra={"path": str(arc_path), "size": arc_size, "sha256": arc_sha})
    return BuildResult(archive_path=arc_path, manifest_path=man_path, archive_sha256=arc_sha, archive_size=arc_size)

# -----------------------
# CLI
# -----------------------

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="archive_put",
        description="Create deterministic archive and upload to file/s3/http destinations."
    )
    parser.add_argument("dest", help="Destination URI: file:///abs/path.tar.gz | s3://bucket/key.tar.gz | https://... ")
    parser.add_argument("--src", nargs="+", required=True, help="Paths to include (files/dirs)")
    parser.add_argument("--format", choices=["tar.gz", "zip"], default="tar.gz", help="Archive format")
    parser.add_argument("--name", default=None, help="Base name inside archive (default: deduced)")
    parser.add_argument("--exclude", action="append", default=[], help="Glob patterns to exclude (repeatable)")
    parser.add_argument("--no-default-excludes", action="store_true", help="Disable default excludes")
    parser.add_argument("--manifest-out", default=None, help="Where to write manifest (default: alongside dest)")
    parser.add_argument("--encrypt", action="store_true", help="Encrypt archive via GPG")
    parser.add_argument("--gpg-recipient", action="append", default=[], help="GPG recipient (repeatable). If omitted with --encrypt, symmetric mode is used.")
    parser.add_argument("--gpg-symmetric", action="store_true", help="Use symmetric GPG (requires passphrase)")
    parser.add_argument("--gpg-passphrase", default=None, help="Passphrase for symmetric encryption (use env or stdin in prod)")
    parser.add_argument("--gpg-armor", action="store_true", help="ASCII armor output")
    parser.add_argument("--dry-run", action="store_true", help="Only build archive and manifest, do not upload")
    parser.add_argument("--verify", action="store_true", help="Verify upload (if supported by destination)")
    parser.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "INFO"), help="Logging level")
    args = parser.parse_args(argv)

    # logging
    if _HAS_OV_LOGGER:
        init_logging(LogConfig(service="oblivionvault-cli", env=os.getenv("APP_ENV","dev"), to_console=True, to_file=False, queue_logging=True, sampling_rate=1.0))
        set_context(request_id=uuid4(), tool="archive_put")
        log = get_logger("oblivionvault.cli.archive_put")
    else:
        _fallback_init_logging(args.log_level)
        log = get_logger("oblivionvault.cli.archive_put")
        log.setLevel(getattr(logging, args.log_level.upper(), logging.INFO))

    try:
        sources = expand_sources(args.src)
        excludes = normalize_patterns(args.exclude or [])
        if not args.no_default_excludes:
            excludes = tuple(list(DEFAULT_EXCLUDES) + list(excludes))

        with tempfile.TemporaryDirectory(prefix="ov-archive-") as tdir:
            tmp_dir = pathlib.Path(tdir)

            build = build_archive_and_manifest(
                sources, fmt=args.format, excludes=excludes, temp_dir=tmp_dir, name=args.name, log=log
            )

            out_path = build.archive_path
            # Encryption
            if args.encrypt:
                if not gpg_available():
                    log.error("gpg_not_found")
                    print("I cannot verify this. GPG not found for encryption.", file=sys.stderr)
                    return 2
                enc_suffix = ".gpg" if not args.gpg_armor else ".asc"
                enc_path = tmp_dir / (out_path.name + enc_suffix)
                # default: symmetric if no recipients specified
                try:
                    gpg_encrypt(
                        out_path,
                        enc_path,
                        recipient=args.gpg_recipient if args.gpg_recipient else None,
                        symmetric=(args.gpg_symmetric or not args.gpg_recipient),
                        cipher="AES256",
                        passphrase=args.gpg_passphrase,
                        armor=args.gpg_armor,
                        log=log,
                    )
                finally:
                    # scrub passphrase from memory reference
                    args.gpg_passphrase = None
                out_path = enc_path

            # Manifest output path
            manifest_target: Optional[pathlib.Path] = None
            if args.manifest_out:
                manifest_target = pathlib.Path(args.manifest_out).expanduser().resolve()
            else:
                # alongside destination (if file://) or next to archive temp
                scheme, dest_uri = parse_dest(args.dest)
                if scheme in ("", "file"):
                    manifest_target = parse_file_uri(args.dest).with_suffix(parse_file_uri(args.dest).suffix + ".manifest.json")
                else:
                    # upload the manifest next to the archive in the same destination (same key + .manifest.json)
                    manifest_target = None  # we will upload alongside if not dry-run

            if args.dry_run:
                log.info("dry_run_complete", extra={
                    "archive_path": str(out_path), "archive_size": size_of(out_path),
                    "manifest_path": str(build.manifest_path)
                })
                print(json.dumps({
                    "status": "dry-run",
                    "archive_path": str(out_path),
                    "archive_size": size_of(out_path),
                    "archive_sha256": sha256_file(out_path),
                    "manifest_path": str(build.manifest_path)
                }, ensure_ascii=False, indent=2))
                return 0

            uploader = get_uploader_for(args.dest)
            content_type = guess_mime(out_path)

            # Upload archive
            uploader.put(out_path, args.dest, content_type=content_type, log=log)

            # Upload manifest
            if manifest_target is not None:
                # local file case
                FileUploader().put(build.manifest_path, "file://" + str(manifest_target), content_type="application/json", log=log)
            else:
                # same scheme as dest
                scheme, parsed = parse_dest(args.dest)
                if scheme == "s3":
                    bucket, key, _ = parse_s3_uri(args.dest)
                    man_uri = f"s3://{bucket}/{key}.manifest.json"
                elif scheme in ("http", "https"):
                    man_uri = args.dest + ".manifest.json"
                else:
                    # should not happen (file handled above)
                    man_uri = args.dest + ".manifest.json"
                uploader.put(build.manifest_path, man_uri, content_type="application/json", log=log)

            # Verify
            if args.verify:
                ok_archive = uploader.verify(out_path, args.dest, log=log)
                ok_manifest = True
                if manifest_target is not None:
                    ok_manifest = FileUploader().verify(build.manifest_path, "file://" + str(manifest_target), log=log)
                log.info("verify_done", extra={"archive_ok": ok_archive, "manifest_ok": ok_manifest})
                if not ok_archive or not ok_manifest:
                    print("I cannot verify this.", file=sys.stderr)
                    return 3

            log.info("archive_put_done", extra={"dest": args.dest})
            print(json.dumps({
                "status": "ok",
                "dest": args.dest,
                "archive_size": size_of(out_path),
                "archive_sha256": sha256_file(out_path),
            }, ensure_ascii=False))
            return 0

    except Exception as e:
        log = get_logger("oblivionvault.cli.archive_put")
        log.exception("archive_put_failed")
        print("I cannot verify this.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
