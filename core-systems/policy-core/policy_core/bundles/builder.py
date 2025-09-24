from __future__ import annotations

import argparse
import asyncio
import contextlib
import fnmatch
import hashlib
import hmac
import io
import json
import logging
import os
import stat
import sys
import tarfile
import time
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

# -----------------------------
# Optional YAML
# -----------------------------
try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

# -----------------------------
# Constants
# -----------------------------
TOOL_VERSION = "policy-bundle-builder/1.0.0"
# Use a stable epoch for deterministic archives: 2000-01-01 00:00:00 UTC
DETERMINISTIC_EPOCH = 946684800
ZIP_DT = (1980, 1, 1, 0, 0, 0)  # Zip stores years >= 1980; metadata in manifest keeps true created_at

# -----------------------------
# Logging
# -----------------------------
def _setup_logger() -> logging.Logger:
    log = logging.getLogger("policy_core.bundles")
    if not log.handlers:
        log.setLevel(logging.INFO)
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        log.addHandler(h)
        log.propagate = False
    return log


# -----------------------------
# Config
# -----------------------------
@dataclass
class BundleConfig:
    src: Union[str, Path]                         # source dir or file
    out: Union[str, Path]                         # artifact path (.zip or .tar.gz)
    fmt: str = "zip"                              # "zip" or "tar.gz"
    include: List[str] = field(default_factory=lambda: ["**/*"])
    exclude: List[str] = field(default_factory=lambda: [".git/**", "**/__pycache__/**"])
    policy_root: str = "policies"                 # subdir (relative to src) or explicit file
    compress_level: int = 9
    deterministic: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
    hmac_key: Optional[bytes] = None              # secret for HMAC (raw bytes)
    # When True, we will also include a canonical merged policy at policy/policy.json
    produce_canonical_policy: bool = True

    @staticmethod
    def from_args(args: argparse.Namespace) -> "BundleConfig":
        key = None
        if args.hmac_key_env:
            raw = os.environ.get(args.hmac_key_env, "")
            key = raw.encode("utf-8") if raw else None
        elif args.hmac_key:
            key = args.hmac_key.encode("utf-8")
        meta = {}
        for m in args.meta or []:
            # key=value
            if "=" in m:
                k, v = m.split("=", 1)
                with contextlib.suppress(Exception):
                    meta[k] = json.loads(v)
                    continue
                meta[k] = v
            else:
                meta[m] = True
        inc = args.include or ["**/*"]
        exc = args.exclude or [".git/**", "**/__pycache__/**"]
        return BundleConfig(
            src=args.src,
            out=args.out,
            fmt=args.fmt,
            include=inc,
            exclude=exc,
            policy_root=args.policy_root,
            compress_level=int(args.compress_level),
            deterministic=not bool(args.no_deterministic),
            metadata=meta,
            hmac_key=key,
            produce_canonical_policy=not bool(args.no_canonical_policy),
        )


# -----------------------------
# Types
# -----------------------------
@dataclass
class ManifestEntry:
    path: str
    sha256: str
    size: int
    mode: int = 0o100644  # regular file, 0644
    # more fields could be added later (owner, gid, etc.)


@dataclass
class Manifest:
    version: str
    created_at: str
    build_id: str
    tool_version: str
    files: List[ManifestEntry]
    policy_version: str
    policy_rules: int
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_json_bytes(self) -> bytes:
        obj = {
            "version": self.version,
            "created_at": self.created_at,
            "build_id": self.build_id,
            "tool_version": self.tool_version,
            "files": [vars(f) for f in self.files],
            "policy": {
                "version": self.policy_version,
                "rules": self.policy_rules,
            },
            "metadata": self.metadata,
        }
        return _canonical_json_bytes(obj)


# -----------------------------
# Utilities
# -----------------------------
def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac_sign(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def _is_textual_policy_file(p: Path) -> bool:
    if not p.is_file():
        return False
    s = p.suffix.lower()
    return s in (".json", ".yaml", ".yml")


def _normalize_relpath(root: Path, file: Path) -> str:
    rel = file.relative_to(root).as_posix()
    # Normalize leading ./ just in case
    return rel.lstrip("./")


def _gitignore_match(path: str, patterns: Sequence[str]) -> bool:
    # Minimalistic matcher: **, *, ?, path segments
    # We also support trailing "/**" implicitly when pattern points to a directory
    path_posix = path.replace("\\", "/")
    for pat in patterns:
        pat = pat.replace("\\", "/")
        if pat.endswith("/"):
            pat = pat + "**"
        if fnmatch.fnmatchcase(path_posix, pat):
            return True
    return False


def _iter_source_files(src_root: Path, include: Sequence[str], exclude: Sequence[str]) -> List[Path]:
    # Collect deterministically
    files: List[Path] = []
    for p in sorted(src_root.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(src_root).as_posix()
        if not _gitignore_match(rel, include):
            continue
        if _gitignore_match(rel, exclude):
            continue
        files.append(p)
    return files


# -----------------------------
# Policy merge / canonicalization
# -----------------------------
def _load_mapping_file(path: Path) -> Dict[str, Any]:
    if path.suffix.lower() in (".yaml", ".yml"):
        if not yaml:
            raise RuntimeError("PyYAML is required to read YAML policies")
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return json.loads(path.read_text(encoding="utf-8") or "{}")


def _merge_policy_dir(policy_root: Path) -> Tuple[Dict[str, Any], int]:
    """
    Merge all policy JSON/YAML files into a single PolicySet:
    - If a file has top-level 'rules': extend
    - Else: treat as a single rule object
    - Sort rules by (priority, id)
    Return (policy_obj, rules_count)
    """
    merged: Dict[str, Any] = {"version": "1", "rules": []}
    count = 0
    for p in sorted(policy_root.rglob("*")):
        if not _is_textual_policy_file(p):
            continue
        data = _load_mapping_file(p)
        if not isinstance(data, dict):
            raise ValueError(f"Policy file must be a mapping: {p}")
        if "rules" in data and isinstance(data["rules"], list):
            merged["rules"].extend(data["rules"])
            count += len(data["rules"])
        else:
            merged["rules"].append(data)
            count += 1
    # Sort rules if keys exist
    def _key(rule: Dict[str, Any]) -> Tuple[int, str]:
        pr = rule.get("priority", 100)
        rid = str(rule.get("id", ""))
        try:
            pr = int(pr)
        except Exception:
            pr = 100
        return pr, rid
    merged["rules"] = sorted(merged["rules"], key=_key)
    if "version" not in merged:
        merged["version"] = "1"
    return merged, count


def _detect_policy_version(policy_obj: Dict[str, Any]) -> str:
    v = str(policy_obj.get("version", "1"))
    return v


# -----------------------------
# Archive writers (deterministic)
# -----------------------------
def _zip_write(zin: zipfile.ZipFile, arcname: str, data: bytes, mode: int = 0o100644, compress_level: int = 9):
    zi = zipfile.ZipInfo(arcname)
    zi.date_time = ZIP_DT
    # Set Unix file mode in external_attr (upper 16 bits)
    zi.external_attr = (mode & 0xFFFF) << 16
    zin.writestr(zi, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=compress_level)


def _tar_add_bytes(tar: tarfile.TarFile, arcname: str, data: bytes, mode: int = 0o100644):
    info = tarfile.TarInfo(name=arcname)
    info.size = len(data)
    info.mtime = DETERMINISTIC_EPOCH
    info.mode = mode & 0o7777
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    tar.addfile(info, io.BytesIO(data))


# -----------------------------
# Build process
# -----------------------------
class BundleBuilder:
    def __init__(self, cfg: BundleConfig, logger: Optional[logging.Logger] = None):
        self.cfg = cfg
        self.log = logger or _setup_logger()

    def build(self) -> Path:
        src_root = Path(self.cfg.src).resolve()
        out_path = Path(self.cfg.out).resolve()
        if not src_root.exists():
            raise FileNotFoundError(f"Source not found: {src_root}")

        files = _iter_source_files(src_root, self.cfg.include, self.cfg.exclude)

        # Prepare canonical policy (optional)
        policy_bytes: Optional[bytes] = None
        policy_version = "0"
        rules_count = 0
        if self.cfg.produce_canonical_policy:
            policy_root = (src_root / self.cfg.policy_root).resolve()
            if policy_root.is_file():
                policy_obj = _load_mapping_file(policy_root)
                if "rules" not in policy_obj:
                    policy_obj = {"version": policy_obj.get("version", "1"), "rules": [policy_obj]}
                # Sort for determinism
                policy_obj["rules"] = sorted(policy_obj["rules"], key=lambda r: (r.get("priority", 100), str(r.get("id", ""))))
                policy_version = _detect_policy_version(policy_obj)
                rules_count = len(policy_obj["rules"])
                policy_bytes = _canonical_json_bytes(policy_obj)
            elif policy_root.is_dir():
                policy_obj, rules_count = _merge_policy_dir(policy_root)
                policy_version = _detect_policy_version(policy_obj)
                policy_bytes = _canonical_json_bytes(policy_obj)
            else:
                self.log.warning(f"Policy root not found: {policy_root}")

        # Read and hash files deterministically
        entries: List[ManifestEntry] = []
        file_blobs: List[Tuple[str, bytes, int]] = []  # (arcname, data, mode)
        for p in files:
            rel = _normalize_relpath(src_root, p)
            # Read bytes
            b = p.read_bytes()
            size = len(b)
            mode = 0o100644
            try:
                st = p.stat()
                # Keep only file permission bits; regular file marker 0100_0000 is left in default
                perm = stat.S_IMODE(st.st_mode)
                mode = 0o100000 | (perm if perm else 0o644)
            except Exception:
                pass
            sha = _sha256_bytes(b)
            entries.append(ManifestEntry(path=rel, sha256=sha, size=size, mode=mode))
            file_blobs.append((rel, b, mode))

        # Add canonical policy into archive if produced
        if policy_bytes is not None:
            rel = "policy/policy.json"
            sha = _sha256_bytes(policy_bytes)
            entries.append(ManifestEntry(path=rel, sha256=sha, size=len(policy_bytes), mode=0o100644))
            file_blobs.append((rel, policy_bytes, 0o100644))

        # Build manifest
        manifest = Manifest(
            version="1",
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            build_id=str(uuid.uuid4()),
            tool_version=TOOL_VERSION,
            files=sorted(entries, key=lambda e: e.path),
            policy_version=policy_version,
            policy_rules=rules_count,
            metadata=self.cfg.metadata,
        )
        manifest_bytes = manifest.to_json_bytes()

        # Sign manifest if needed
        signature_bytes: Optional[bytes] = None
        if self.cfg.hmac_key:
            sig_hex = _hmac_sign(self.cfg.hmac_key, manifest_bytes)
            signature_bytes = _canonical_json_bytes({"algo": "HMAC-SHA256", "sig_hex": sig_hex})

        # Ensure output directory
        out_path.parent.mkdir(parents=True, exist_ok=True)
        temp = out_path.with_suffix(out_path.suffix + ".tmp")

        # Write archive
        if self.cfg.fmt == "zip":
            self._write_zip(temp, file_blobs, manifest_bytes, signature_bytes)
        elif self.cfg.fmt in ("tar.gz", "tgz"):
            self._write_targz(temp, file_blobs, manifest_bytes, signature_bytes)
        else:
            raise ValueError(f"Unknown format: {self.cfg.fmt}")

        # Atomic rename
        temp.replace(out_path)
        self.log.info(f"Bundle written: {out_path} ({self.cfg.fmt})")
        return out_path

    def _write_zip(self, path: Path, file_blobs: List[Tuple[str, bytes, int]], manifest_bytes: bytes, sig_bytes: Optional[bytes]):
        with zipfile.ZipFile(path, "w") as zf:
            # deterministic order
            for rel, data, mode in sorted(file_blobs, key=lambda x: x[0]):
                _zip_write(zf, rel, data, mode=mode, compress_level=self.cfg.compress_level)
            _zip_write(zf, "MANIFEST.json", manifest_bytes, mode=0o100644, compress_level=self.cfg.compress_level)
            if sig_bytes is not None:
                _zip_write(zf, "SIGNATURE.hmac", sig_bytes, mode=0o100644, compress_level=self.cfg.compress_level)

    def _write_targz(self, path: Path, file_blobs: List[Tuple[str, bytes, int]], manifest_bytes: bytes, sig_bytes: Optional[bytes]):
        with tarfile.open(path, "w:gz", compresslevel=self.cfg.compress_level) as tf:
            for rel, data, mode in sorted(file_blobs, key=lambda x: x[0]):
                _tar_add_bytes(tf, rel, data, mode=mode & 0o7777)
            _tar_add_bytes(tf, "MANIFEST.json", manifest_bytes, mode=0o100644)
            if sig_bytes is not None:
                _tar_add_bytes(tf, "SIGNATURE.hmac", sig_bytes, mode=0o100644)


# -----------------------------
# Verification / Inspection
# -----------------------------
class BundleVerifier:
    def __init__(self, bundle: Union[str, Path], hmac_key: Optional[bytes] = None, logger: Optional[logging.Logger] = None):
        self.bundle = Path(bundle).resolve()
        self.log = logger or _setup_logger()
        self.key = hmac_key

    def verify(self) -> Dict[str, Any]:
        fmt = _detect_format(self.bundle)
        files, manifest, signature = _read_bundle(self.bundle, fmt)
        # Verify hashes
        problems: List[str] = []
        file_map: Dict[str, bytes] = {p: b for p, b in files}
        for entry in manifest["files"]:
            p = entry["path"]
            if p not in file_map:
                problems.append(f"missing file: {p}")
                continue
            b = file_map[p]
            calc = hashlib.sha256(b).hexdigest()
            if calc != entry["sha256"]:
                problems.append(f"hash mismatch: {p}")
            if len(b) != int(entry["size"]):
                problems.append(f"size mismatch: {p}")
        # Verify signature if present
        sig_ok = None
        if signature is not None:
            if not self.key:
                problems.append("signature present but no key provided")
                sig_ok = False
            else:
                algo = signature.get("algo")
                sig_hex = signature.get("sig_hex", "")
                if algo != "HMAC-SHA256":
                    problems.append(f"unsupported signature algo: {algo}")
                    sig_ok = False
                else:
                    man_bytes = _canonical_json_bytes(manifest)
                    expected = hmac.new(self.key, man_bytes, hashlib.sha256).hexdigest()
                    sig_ok = (expected == sig_hex)
                    if not sig_ok:
                        problems.append("signature mismatch")
        ok = len(problems) == 0
        return {
            "ok": ok,
            "problems": problems,
            "signature_ok": sig_ok,
            "manifest": manifest,
        }

    def inspect(self) -> Dict[str, Any]:
        fmt = _detect_format(self.bundle)
        _, manifest, signature = _read_bundle(self.bundle, fmt)
        return {
            "manifest": manifest,
            "signature": signature,
        }


def _detect_format(path: Path) -> str:
    s = path.name.lower()
    if s.endswith(".zip"):
        return "zip"
    if s.endswith(".tar.gz") or s.endswith(".tgz"):
        return "tar.gz"
    raise ValueError("Unsupported bundle extension (expect .zip or .tar.gz)")


def _read_bundle(path: Path, fmt: str) -> Tuple[List[Tuple[str, bytes]], Dict[str, Any], Optional[Dict[str, Any]]]:
    files: List[Tuple[str, bytes]] = []
    manifest: Optional[Dict[str, Any]] = None
    signature: Optional[Dict[str, Any]] = None

    if fmt == "zip":
        with zipfile.ZipFile(path, "r") as zf:
            for name in sorted(zf.namelist()):
                b = zf.read(name)
                if name == "MANIFEST.json":
                    manifest = json.loads(b.decode("utf-8"))
                elif name == "SIGNATURE.hmac":
                    signature = json.loads(b.decode("utf-8"))
                else:
                    files.append((name, b))
    else:
        with tarfile.open(path, "r:gz") as tf:
            names = sorted(m.name for m in tf.getmembers() if m.isfile())
            for name in names:
                f = tf.extractfile(name)
                if not f:
                    continue
                b = f.read()
                if name == "MANIFEST.json":
                    manifest = json.loads(b.decode("utf-8"))
                elif name == "SIGNATURE.hmac":
                    signature = json.loads(b.decode("utf-8"))
                else:
                    files.append((name, b))

    if manifest is None:
        raise ValueError("MANIFEST.json is missing")
    return files, manifest, signature


# -----------------------------
# CLI
# -----------------------------
def _build_cli_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="policy-bundle")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="Build bundle from source")
    b.add_argument("--src", required=True, help="Source file or directory")
    b.add_argument("--out", required=True, help="Output bundle path (.zip or .tar.gz)")
    b.add_argument("--fmt", choices=["zip", "tar.gz", "tgz"], default="zip")
    b.add_argument("--include", nargs="*", help="Include globs (default: **/*)")
    b.add_argument("--exclude", nargs="*", help="Exclude globs (.git/** etc.)")
    b.add_argument("--policy-root", default="policies", help="Policy dir or file within src")
    b.add_argument("--compress-level", default="9")
    b.add_argument("--no-deterministic", action="store_true", help="Disable deterministic timestamps/permissions")
    b.add_argument("--meta", nargs="*", help='Metadata entries key=value (value may be JSON)')
    b.add_argument("--hmac-key-env", help="Env var name that holds HMAC secret")
    b.add_argument("--hmac-key", help="HMAC secret literal (unsafe for production)")
    b.add_argument("--no-canonical-policy", action="store_true", help="Do not emit policy/policy.json")
    b.set_defaults(func=_cmd_build)

    v = sub.add_parser("verify", help="Verify hashes and optional signature")
    v.add_argument("--bundle", required=True, help="Bundle path")
    v.add_argument("--hmac-key-env", help="Env var name for HMAC secret")
    v.add_argument("--hmac-key", help="HMAC secret literal")
    v.set_defaults(func=_cmd_verify)

    i = sub.add_parser("inspect", help="Show manifest and signature")
    i.add_argument("--bundle", required=True, help="Bundle path")
    i.set_defaults(func=_cmd_inspect)
    return p


def _cmd_build(args: argparse.Namespace) -> int:
    cfg = BundleConfig.from_args(args)
    builder = BundleBuilder(cfg)
    builder.build()
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    key = None
    if args.hmac_key_env:
        raw = os.environ.get(args.hmac_key_env, "")
        key = raw.encode("utf-8") if raw else None
    elif args.hmac_key:
        key = args.hmac_key.encode("utf-8")
    v = BundleVerifier(args.bundle, hmac_key=key)
    res = v.verify()
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 0 if res["ok"] else 2


def _cmd_inspect(args: argparse.Namespace) -> int:
    v = BundleVerifier(args.bundle)
    info = v.inspect()
    print(json.dumps(info, indent=2, ensure_ascii=False))
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_cli_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
