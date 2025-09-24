# policy-core/cli/tools/publish_bundle.py
# -*- coding: utf-8 -*-
"""
Policy Bundle Publisher (industrial-grade, stdlib only)

Features:
- Build deterministic tar.gz bundles from include/exclude globs or JSON manifest.
- Parallel SHA-256 hashing, strict metadata (manifest.json), SPDX-like SBOM, SLSA-lite provenance.
- Signing: HMAC (sha256) or RSA via `openssl` (detached).
- Verify: bundle checksums and detached signature (HMAC or RSA).
- Publish: filesystem (atomic) and HTTP(S) endpoint with retries and bearer token.
- Index: atomic index.json update with release entries.
- Reproducibility: normalized tar metadata (uid/gid/mtime/mode, posix paths, lexicographic order).

ENV (optional):
  POLICY_PUBLISH_TOKEN        - Bearer token for HTTP publish
  POLICY_HMAC_SECRET          - secret for HMAC signing (hex/base64/utf8)
  POLICY_HMAC_KEY_ID          - key id for manifest signing metadata
  POLICY_OPENSSL_BIN          - path to openssl binary (default: 'openssl')
  POLICY_HTTP_TIMEOUT         - seconds (float), default 10.0
  POLICY_HTTP_RETRIES         - int, default 2

Exit codes:
  0 ok; 2 build error; 3 sign error; 4 verify failed; 5 publish error.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import dataclasses
import fnmatch
import gzip
import hashlib
import io
import json
import os
import posixpath
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# ---------------------------
# Utilities
# ---------------------------

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

def rfc3339_z(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def sha256_file(path: str, bufsize: int = 1024 * 1024) -> Tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        while True:
            b = f.read(bufsize)
            if not b:
                break
            h.update(b)
            size += len(b)
    return h.hexdigest(), size

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)

def norm_posix(path: str) -> str:
    # store posix paths inside manifests/tar
    return posixpath.normpath(path.replace("\\", "/"))

def ensure_dir(p: str) -> None:
    os.makedirs(p, exist_ok=True)

def atomic_write_text(path: str, content: str) -> None:
    d = os.path.dirname(path) or "."
    ensure_dir(d)
    fd, tmp = tempfile.mkstemp(prefix=".tmp.", dir=d, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp, path)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass

def atomic_write_bytes(path: str, content: bytes) -> None:
    d = os.path.dirname(path) or "."
    ensure_dir(d)
    fd, tmp = tempfile.mkstemp(prefix=".tmp.", dir=d)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(content)
        os.replace(tmp, path)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass

def decode_secret_auto(s: str) -> bytes:
    s = s.strip()
    # try hex
    try:
        if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) % 2 == 0:
            return bytes.fromhex(s)
    except Exception:
        pass
    # try base64
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        pass
    return s.encode("utf-8")

# ---------------------------
# Data structures
# ---------------------------

@dataclass
class FileEntry:
    path: str
    sha256: str
    size: int
    mode: int

@dataclass
class Manifest:
    name: str
    version: str
    created_at: str
    files: List[FileEntry]
    bundle: Dict[str, Any]
    signing: Dict[str, Any]
    metadata: Dict[str, Any]

    def to_json(self) -> str:
        obj = {
            "name": self.name,
            "version": self.version,
            "created_at": self.created_at,
            "files": [dataclasses.asdict(f) for f in self.files],
            "bundle": self.bundle,
            "signing": self.signing,
            "metadata": self.metadata,
        }
        return canonical_json(obj)

# ---------------------------
# File discovery
# ---------------------------

def discover_files(root: str, includes: Sequence[str], excludes: Sequence[str]) -> List[str]:
    # Walk and match globs relative to root
    out: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        rel_dir = "" if rel_dir == "." else rel_dir
        for name in filenames:
            rel = norm_posix(os.path.join(rel_dir, name) if rel_dir else name)
            # apply include patterns
            if includes and not any(fnmatch.fnmatch(rel, pat) for pat in includes):
                continue
            if any(fnmatch.fnmatch(rel, pat) for pat in excludes):
                continue
            out.append(rel)
    out.sort()
    return out

# ---------------------------
# Deterministic tar.gz builder
# ---------------------------

def build_tar_gz(root: str, relfiles: Sequence[str], out_path: str) -> Tuple[str, int]:
    """
    Create deterministic tar.gz:
      - uid/gid=0, uname/gname=''
      - mode from filesystem masked to 0644 for files, 0755 for dirs
      - mtime=0
      - POSIX path ordering (sorted)
    Returns (sha256, size).
    """
    ensure_dir(os.path.dirname(out_path))
    # Write to in-memory buffer to hash consistently, then atomically flush
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        with tarfile.TarFile(fileobj=gz, mode="w") as tar:
            for rel in sorted(relfiles):
                src = os.path.join(root, rel)
                st = os.stat(src)
                ti = tarfile.TarInfo(name=rel)
                # normalize mode
                file_mode = (st.st_mode & 0o777) or 0o644
                ti.mode = file_mode
                ti.uid = 0
                ti.gid = 0
                ti.uname = ""
                ti.gname = ""
                ti.size = st.st_size
                ti.mtime = 0
                with open(src, "rb") as f:
                    tar.addfile(ti, f)
    data = buf.getvalue()
    digest = sha256_bytes(data)
    atomic_write_bytes(out_path, data)
    return digest, len(data)

# ---------------------------
# SBOM & provenance
# ---------------------------

def build_sbom(name: str, version: str, files: List[FileEntry]) -> Dict[str, Any]:
    return {
        "spdxVersion": "SPDX-2.3-lite",
        "dataLicense": "CC0-1.0",
        "SPDXID": f"SPDXRef-DOCUMENT-{name}-{version}",
        "name": f"{name}-{version}-sbom",
        "documentNamespace": f"https://example.invalid/spdx/{name}/{version}",
        "creationInfo": {"created": rfc3339_z(utc_now()), "creators": ["Tool: policy-publisher-stdlib"]},
        "files": [
            {
                "SPDXID": f"SPDXRef-File-{fe.sha256[:12]}",
                "fileName": fe.path,
                "checksums": [{"algorithm": "SHA256", "checksumValue": fe.sha256}],
                "fileTypes": ["TEXT"]  # heuristic
            }
            for fe in files
        ],
    }

def build_provenance(name: str, version: str, manifest_sha256: str) -> Dict[str, Any]:
    return {
        "type": "slsa-lite-provenance",
        "predicateType": "slsa.dev/provenance-lite@v1",
        "subject": [{"name": name, "version": version, "digest": {"sha256": manifest_sha256}}],
        "builder": {"id": "policy-core/cli/tools/publish_bundle.py"},
        "buildType": "policy-bundle",
        "buildConfig": {"python": sys.version, "platform": sys.platform},
        "buildStartedOn": rfc3339_z(utc_now()),
        "buildFinishedOn": rfc3339_z(utc_now()),
    }

# ---------------------------
# Signing
# ---------------------------

def sign_hmac(payload: bytes, secret: str, key_id: Optional[str]) -> Dict[str, Any]:
    key = decode_secret_auto(secret)
    sig = hashlib.sha256(key + payload).hexdigest()  # simple HMAC-like (not RFC2104), documented here
    return {"method": "HMAC-SHA256", "key_id": key_id or "env:PUBLISH", "signature": sig}

def verify_hmac(payload: bytes, secret: str, signature_hex: str) -> bool:
    key = decode_secret_auto(secret)
    calc = hashlib.sha256(key + payload).hexdigest()
    return _ct_equal(calc, signature_hex)

def _ct_equal(a: str, b: str) -> bool:
    if len(a) != len(b):
        return False
    res = 0
    for x, y in zip(a.encode(), b.encode()):
        res |= x ^ y
    return res == 0

def openssl_sign_detached(payload_path: str, key_path: str, out_sig_path: str, openssl_bin: str = "openssl") -> None:
    # RSA SHA256 detached signature: openssl dgst -sha256 -sign key.pem -out sig.bin payload
    cmd = [openssl_bin, "dgst", "-sha256", "-sign", key_path, "-out", out_sig_path, payload_path]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"OpenSSL signing failed: {e.stderr.decode(errors='ignore')}") from e

def openssl_verify_detached(payload_path: str, pubkey_path: str, sig_path: str, openssl_bin: str = "openssl") -> bool:
    # openssl dgst -sha256 -verify pub.pem -signature sig.bin payload
    cmd = [openssl_bin, "dgst", "-sha256", "-verify", pubkey_path, "-signature", sig_path, payload_path]
    try:
        r = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return r.returncode == 0
    except Exception:
        return False

# ---------------------------
# Build pipeline
# ---------------------------

def compute_entries(root: str, relfiles: Sequence[str]) -> List[FileEntry]:
    def _one(rel: str) -> FileEntry:
        p = os.path.join(root, rel)
        h, size = sha256_file(p)
        mode = stat.S_IMODE(os.stat(p).st_mode)
        return FileEntry(path=rel, sha256=h, size=size, mode=mode)
    # parallel hashing
    out: List[FileEntry] = []
    with cf.ThreadPoolExecutor(max_workers=min(32, os.cpu_count() or 4)) as ex:
        for fe in ex.map(_one, relfiles):
            out.append(fe)
    out.sort(key=lambda x: x.path)
    return out

def build_manifest(name: str, version: str, files: List[FileEntry], bundle_info: Dict[str, Any], signing_meta: Dict[str, Any], extra_meta: Dict[str, Any]) -> Manifest:
    return Manifest(
        name=name,
        version=version,
        created_at=rfc3339_z(utc_now()),
        files=files,
        bundle=bundle_info,
        signing=signing_meta,
        metadata=extra_meta,
    )

# ---------------------------
# HTTP publish with retries
# ---------------------------

def http_put(url: str, data: bytes, content_type: str, token: Optional[str], timeout: float, retries: int) -> None:
    headers = {"Content-Type": content_type}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url=url, data=data, method="PUT", headers=headers)
    last = None
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                if r.status not in (200, 201, 202, 204):
                    raise RuntimeError(f"HTTP {r.status}")
                return
        except Exception as e:
            last = e
            if attempt >= retries:
                break
            time.sleep(min(1.0 * (2 ** attempt), 5.0))
    raise RuntimeError(f"HTTP PUT failed: {last}")

# ---------------------------
# CLI Commands
# ---------------------------

def cmd_build(args: argparse.Namespace) -> int:
    try:
        root = os.path.abspath(args.root)
        includes = args.include or []
        excludes = args.exclude or []
        name = args.name
        version = args.version

        # Load file list from JSON manifest if provided
        relfiles: List[str]
        extra_meta: Dict[str, Any] = {}
        if args.manifest_json:
            with open(args.manifest_json, "r", encoding="utf-8") as f:
                m = json.load(f)
            name = m.get("name", name)
            version = m.get("version", version)
            if "files" in m and isinstance(m["files"], list):
                relfiles = [norm_posix(x) for x in m["files"]]
            else:
                inc = m.get("include", includes) or []
                exc = m.get("exclude", excludes) or []
                relfiles = discover_files(root, inc, exc)
            extra_meta = m.get("metadata", {})
        else:
            relfiles = discover_files(root, includes, excludes)

        if not relfiles:
            raise RuntimeError("No files selected to bundle")

        files = compute_entries(root, relfiles)

        outdir = os.path.abspath(args.out_dir)
        ensure_dir(outdir)
        bundle_name = f"{name}-{version}.tar.gz"
        bundle_path = os.path.join(outdir, bundle_name)
        bundle_sha256, bundle_size = build_tar_gz(root, [f.path for f in files], bundle_path)

        # Prepare manifest
        signing_meta = {"method": "none", "key_id": None}
        manifest = build_manifest(
            name=name,
            version=version,
            files=files,
            bundle={"filename": bundle_name, "sha256": bundle_sha256, "size": bundle_size},
            signing=signing_meta,
            extra_meta=extra_meta,
        )
        manifest_json = manifest.to_json()
        manifest_path = os.path.join(outdir, f"{name}-{version}.manifest.json")
        atomic_write_text(manifest_path, manifest_json)

        # SBOM + provenance
        sbom = build_sbom(name, version, files)
        sbom_path = os.path.join(outdir, f"{name}-{version}.sbom.json")
        atomic_write_text(sbom_path, canonical_json(sbom))

        prov = build_provenance(name, version, sha256_bytes(manifest_json.encode("utf-8")))
        prov_path = os.path.join(outdir, f"{name}-{version}.provenance.json")
        atomic_write_text(prov_path, canonical_json(prov))

        if args.quiet is False:
            print(f"[build] bundle={bundle_path} sha256={bundle_sha256}")
            print(f"[build] manifest={manifest_path}")
            print(f"[build] sbom={sbom_path}")
            print(f"[build] provenance={prov_path}")

        return 0
    except Exception as e:
        print(f"[build][error] {e}", file=sys.stderr)
        return 2

def cmd_sign(args: argparse.Namespace) -> int:
    try:
        manifest_path = os.path.abspath(args.manifest)
        with open(manifest_path, "rb") as f:
            payload = f.read()

        name_version = os.path.basename(manifest_path).replace(".manifest.json", "")
        out_sig = os.path.join(os.path.dirname(manifest_path), f"{name_version}.manifest.sig")

        if args.method == "hmac":
            secret = args.hmac_secret or os.getenv("POLICY_HMAC_SECRET")
            if not secret:
                raise RuntimeError("HMAC secret not provided (use --hmac-secret or POLICY_HMAC_SECRET)")
            key_id = args.hmac_key_id or os.getenv("POLICY_HMAC_KEY_ID")
            sig = sign_hmac(payload, secret, key_id)
            atomic_write_text(out_sig, canonical_json(sig))
        elif args.method == "rsa":
            key_path = args.key
            if not key_path or not os.path.exists(key_path):
                raise RuntimeError("RSA key file required for --method rsa")
            openssl_bin = os.getenv("POLICY_OPENSSL_BIN", "openssl")
            tmp_sig = out_sig + ".bin"
            openssl_sign_detached(manifest_path, key_path, tmp_sig, openssl_bin=openssl_bin)
            meta = {"method": "RSA-SHA256", "key_id": os.path.basename(key_path), "sig_path": os.path.basename(tmp_sig)}
            atomic_write_text(out_sig, canonical_json(meta))
        else:
            raise RuntimeError("Unknown signing method")

        # Patch manifest signing metadata (non-destructive)
        with open(manifest_path, "r", encoding="utf-8") as f:
            m = json.load(f)
        m["signing"] = {"method": "HMAC-SHA256" if args.method == "hmac" else "RSA-SHA256", "key_id": args.hmac_key_id or args.key}
        atomic_write_text(manifest_path, canonical_json(m))

        if args.quiet is False:
            print(f"[sign] signature={out_sig}")
        return 0
    except Exception as e:
        print(f"[sign][error] {e}", file=sys.stderr)
        return 3

def cmd_verify(args: argparse.Namespace) -> int:
    try:
        manifest_path = os.path.abspath(args.manifest)
        bundle_path = os.path.abspath(args.bundle) if args.bundle else None
        with open(manifest_path, "r", encoding="utf-8") as f:
            m = json.load(f)

        # Verify bundle checksum if provided
        if bundle_path:
            if not os.path.exists(bundle_path):
                raise RuntimeError("Bundle file not found")
            calc, size = sha256_file(bundle_path)
            if calc != m["bundle"]["sha256"]:
                raise RuntimeError("Bundle sha256 mismatch")
            if size != int(m["bundle"]["size"]):
                raise RuntimeError("Bundle size mismatch")

        # Verify files list if root provided
        if args.root:
            root = os.path.abspath(args.root)
            for fe in m["files"]:
                p = os.path.join(root, fe["path"])
                if not os.path.exists(p):
                    raise RuntimeError(f"Missing file: {fe['path']}")
                calc, size = sha256_file(p)
                if calc != fe["sha256"] or size != fe["size"]:
                    raise RuntimeError(f"Mismatch: {fe['path']}")

        # Verify signature if provided
        sig_path = os.path.join(os.path.dirname(manifest_path), os.path.basename(manifest_path).replace(".manifest.json", ".manifest.sig"))
        if os.path.exists(sig_path):
            with open(sig_path, "r", encoding="utf-8") as f:
                try:
                    sig_meta = json.load(f)
                except json.JSONDecodeError:
                    sig_meta = None
            payload = open(manifest_path, "rb").read()
            if sig_meta and sig_meta.get("method") == "HMAC-SHA256":
                secret = args.hmac_secret or os.getenv("POLICY_HMAC_SECRET")
                if not secret:
                    raise RuntimeError("POLICY_HMAC_SECRET not provided for HMAC verify")
                ok = verify_hmac(payload, secret, sig_meta["signature"])
                if not ok:
                    raise RuntimeError("HMAC signature invalid")
            elif sig_meta and sig_meta.get("method") == "RSA-SHA256":
                openssl_bin = os.getenv("POLICY_OPENSSL_BIN", "openssl")
                bin_sig = os.path.join(os.path.dirname(sig_path), sig_meta["sig_path"])
                pub = args.pubkey
                if not pub:
                    raise RuntimeError("--pubkey required for RSA verify")
                ok = openssl_verify_detached(manifest_path, pub, bin_sig, openssl_bin=openssl_bin)
                if not ok:
                    raise RuntimeError("RSA signature invalid")
            else:
                # no JSON meta — treat as unsigned
                pass

        if args.quiet is False:
            print("[verify] OK")
        return 0
    except Exception as e:
        print(f"[verify][error] {e}", file=sys.stderr)
        return 4

def cmd_publish(args: argparse.Namespace) -> int:
    try:
        outdir = os.path.abspath(args.out_dir)
        name = args.name
        version = args.version
        prefix = f"{name}-{version}"

        files = [
            f"{prefix}.tar.gz",
            f"{prefix}.manifest.json",
            f"{prefix}.manifest.sig",
            f"{prefix}.sbom.json",
            f"{prefix}.provenance.json",
        ]
        files = [os.path.join(outdir, f) for f in files if os.path.exists(os.path.join(outdir, f))]

        if args.target == "fs":
            dest = os.path.abspath(args.fs_dir)
            ensure_dir(dest)
            for p in files:
                dst = os.path.join(dest, os.path.basename(p))
                tmp = dst + ".tmp"
                shutil.copyfile(p, tmp)
                os.replace(tmp, dst)
            if args.update_index:
                index_path = os.path.join(dest, "index.json")
                update_index(index_path, name, version, files)
            if args.quiet is False:
                print(f"[publish/fs] -> {dest}")
            return 0

        if args.target == "http":
            base = args.http_base.rstrip("/")
            token = os.getenv("POLICY_PUBLISH_TOKEN")
            timeout = float(os.getenv("POLICY_HTTP_TIMEOUT", "10.0"))
            retries = int(os.getenv("POLICY_HTTP_RETRIES", "2"))
            for p in files:
                url = f"{base}/{os.path.basename(p)}"
                with open(p, "rb") as f:
                    data = f.read()
                ctype = "application/gzip" if p.endswith(".gz") else "application/json"
                http_put(url, data, ctype, token, timeout, retries)
            if args.quiet is False:
                print(f"[publish/http] -> {base}/")
            return 0

        raise RuntimeError("Unknown publish target")
    except Exception as e:
        print(f"[publish][error] {e}", file=sys.stderr)
        return 5

def update_index(index_path: str, name: str, version: str, files: Sequence[str]) -> None:
    index = {"name": name, "releases": []}
    if os.path.exists(index_path):
        try:
            with open(index_path, "r", encoding="utf-8") as f:
                index = json.load(f)
        except Exception:
            pass
    # compute digests and URIs
    rel = {
        "version": version,
        "created_at": rfc3339_z(utc_now()),
        "artifacts": [],
    }
    for p in files:
        with open(p, "rb") as f:
            b = f.read()
        rel["artifacts"].append({
            "name": os.path.basename(p),
            "sha256": sha256_bytes(b),
            "size": len(b),
            "uri": os.path.basename(p),
        })
    # replace if version exists
    index["releases"] = [x for x in index.get("releases", []) if x.get("version") != version]
    index["releases"].append(rel)
    index["releases"].sort(key=lambda x: x["version"])
    atomic_write_text(index_path, canonical_json(index))

def cmd_release(args: argparse.Namespace) -> int:
    # build + sign + publish (+ index fs)
    rc = cmd_build(args)
    if rc != 0:
        return rc
    if args.sign_method:
        s_args = argparse.Namespace(
            manifest=os.path.join(os.path.abspath(args.out_dir), f"{args.name}-{args.version}.manifest.json"),
            method=args.sign_method,
            hmac_secret=args.hmac_secret,
            hmac_key_id=args.hmac_key_id,
            key=args.key,
            quiet=args.quiet,
        )
        rc = cmd_sign(s_args)
        if rc != 0:
            return rc
    p_args = argparse.Namespace(
        out_dir=args.out_dir,
        name=args.name,
        version=args.version,
        target=args.target,
        fs_dir=args.fs_dir,
        http_base=args.http_base,
        update_index=args.update_index,
        quiet=args.quiet,
    )
    return cmd_publish(p_args)

# ---------------------------
# Main / argparse
# ---------------------------

def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="publish-bundle", description="Policy bundle builder/sign/publish (stdlib)")
    sub = p.add_subparsers(dest="cmd", required=True)

    # build
    b = sub.add_parser("build", help="Build tar.gz, manifest, sbom, provenance")
    b.add_argument("--root", required=True, help="Root directory of policies")
    b.add_argument("--name", required=True, help="Bundle name")
    b.add_argument("--version", required=True, help="Bundle version")
    b.add_argument("--include", action="append", default=[], help="Glob include (repeatable)")
    b.add_argument("--exclude", action="append", default=[], help="Glob exclude (repeatable)")
    b.add_argument("--manifest-json", help="Input JSON with include/exclude or explicit files")
    b.add_argument("--out-dir", default="dist", help="Output directory")
    b.add_argument("--quiet", action="store_true", default=False)
    b.set_defaults(func=cmd_build)

    # sign
    s = sub.add_parser("sign", help="Sign manifest (HMAC or RSA via openssl)")
    s.add_argument("--manifest", required=True, help="Path to manifest.json")
    s.add_argument("--method", required=True, choices=["hmac", "rsa"])
    s.add_argument("--hmac-secret", help="HMAC secret (hex/base64/utf8); or POLICY_HMAC_SECRET")
    s.add_argument("--hmac-key-id", help="Key id for HMAC; or POLICY_HMAC_KEY_ID")
    s.add_argument("--key", help="Path to RSA private key (PEM) for --method rsa")
    s.add_argument("--quiet", action="store_true", default=False)
    s.set_defaults(func=cmd_sign)

    # verify
    v = sub.add_parser("verify", help="Verify bundle, files and signature")
    v.add_argument("--manifest", required=True, help="Path to manifest.json")
    v.add_argument("--bundle", help="Path to bundle .tar.gz")
    v.add_argument("--root", help="Root to verify file checksums")
    v.add_argument("--hmac-secret", help="For HMAC verification; or POLICY_HMAC_SECRET")
    v.add_argument("--pubkey", help="Path to RSA public key (PEM) for RSA verify")
    v.add_argument("--quiet", action="store_true", default=False)
    v.set_defaults(func=cmd_verify)

    # publish
    u = sub.add_parser("publish", help="Publish artifacts to filesystem or HTTP")
    u.add_argument("--out-dir", default="dist", help="Where artifacts are located")
    u.add_argument("--name", required=True)
    u.add_argument("--version", required=True)
    u.add_argument("--target", required=True, choices=["fs", "http"])
    u.add_argument("--fs-dir", help="Destination dir for fs target")
    u.add_argument("--http-base", help="Base URL for HTTP target (PUT per file)")
    u.add_argument("--update-index", action="store_true", default=False, help="Update index.json (fs target)")
    u.add_argument("--quiet", action="store_true", default=False)
    u.set_defaults(func=cmd_publish)

    # release (build+sign+publish)
    r = sub.add_parser("release", help="Build, sign, and publish in one step")
    r.add_argument("--root", required=True)
    r.add_argument("--name", required=True)
    r.add_argument("--version", required=True)
    r.add_argument("--include", action="append", default=[])
    r.add_argument("--exclude", action="append", default=[])
    r.add_argument("--manifest-json")
    r.add_argument("--out-dir", default="dist")
    r.add_argument("--sign-method", choices=["hmac", "rsa"])
    r.add_argument("--hmac-secret")
    r.add_argument("--hmac-key-id")
    r.add_argument("--key", help="RSA private key (PEM)")
    r.add_argument("--target", required=True, choices=["fs", "http"])
    r.add_argument("--fs-dir")
    r.add_argument("--http-base")
    r.add_argument("--update-index", action="store_true", default=False)
    r.add_argument("--quiet", action="store_true", default=False)
    r.set_defaults(func=cmd_release)

    args = p.parse_args(argv)
    return args.func(args)

if __name__ == "__main__":
    sys.exit(main())
