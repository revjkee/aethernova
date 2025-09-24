#!/usr/bin/env python3
# engine-core/engine/cli/tools/generate_snapshot.py
"""
Deterministic engine state snapshot tool.

Features:
- Deterministic canonical encoding (order-stable), UTF-8, compact separators
- Atomic write to target (tmp file + fsync + rename)
- Integrity: SHA-256 (uncompressed payload), CRC32 (compressed bytes)
- Optional zlib compression (level 0..9)
- Optional HMAC-SHA256 signature (key via --hmac-key or env ENGINE_SNAPSHOT_HMAC_KEY)
- Redaction of sensitive keys by dotted paths (e.g. secrets.token)
- Provider loading: --provider "pkg.mod:StateProvider" with sync/async .get_state()
- Verify mode: checks integrity/signature; prints meta
- Diff mode: structural diff of two snapshots (keys added/removed/changed) with size summary
- Dry-run: dumps to stdout (optionally pretty)
- Progress to stderr; exit codes: 0 ok, 1 error, 2 verification failed, 3 diff detected (when --diff and --fail-on-diff)

File format (container):
  magic: b"ECSS1\\n"
  header: canonical JSON (single line) with meta {schema, created_utc, engine_version, provider, compression, sha256_hex, crc32_hex, size_uncompressed, size_compressed, hmac_alg?, hmac_hex?}
  newline: b"\\n"
  payload: bytes (canonical-encoded state), optionally zlib-compressed
No trailing data.

Copyright:
- No external deps. Copy/paste friendly for engine tools.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import functools
import importlib
import inspect
import io
import json
import os
import sys
import time
import types
import zlib
import hashlib
import hmac
import binascii
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple, List, Union

MAGIC = b"ECSS1\n"
SCHEMA = "engine-core.snapshot/1.0"

# ----------------------------
# Canonical encoder (deterministic)
# ----------------------------

def _uvarint(n: int) -> bytes:
    if n < 0:
        raise ValueError("uvarint >= 0")
    out = bytearray()
    x = n
    while True:
        b = x & 0x7F
        x >>= 7
        if x:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)

def canonical_encode(obj: Any) -> bytes:
    """
    Deterministic, compact, type-tagged encoding:
      N,T,F,I(len)+ascii,D(8 bytes BE),S(len)+utf8,B(len)+bytes,
      L(len)+items,M(len)+sorted(k,v)
    """
    from struct import pack
    if obj is None:
        return b"N"
    t = type(obj)
    if t is bool:
        return b"T" if obj else b"F"
    if t is int:
        b = str(int(obj)).encode("ascii")
        return b"I" + _uvarint(len(b)) + b
    if t is float:
        return b"D" + pack("!d", float(obj))
    if t is str:
        b = obj.encode("utf-8")
        return b"S" + _uvarint(len(b)) + b
    if t is bytes or isinstance(obj, (bytearray, memoryview)):
        b = bytes(obj)
        return b"B" + _uvarint(len(b)) + b
    if dataclasses.is_dataclass(obj):
        obj = dataclasses.asdict(obj)
    if isinstance(obj, (list, tuple)):
        buf = bytearray(b"L" + _uvarint(len(obj)))
        for it in obj:
            buf += canonical_encode(it)
        return bytes(buf)
    if isinstance(obj, dict):
        # Sort by encoded key for full determinism across locales
        items = [(canonical_encode(k), canonical_encode(v)) for k, v in obj.items()]
        items.sort(key=lambda kv: kv[0])
        buf = bytearray(b"M" + _uvarint(len(items)))
        for ek, ev in items:
            buf += ek + ev
        return bytes(buf)
    # Fallback to str
    s = str(obj).encode("utf-8")
    return b"S" + _uvarint(len(s)) + s

def canonical_json(obj: Any) -> bytes:
    """Stable JSON for headers (human-readable), UTF-8, sort_keys, compact."""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

# ----------------------------
# Utilities
# ----------------------------

def utc_iso(ts: Optional[float] = None) -> str:
    import datetime as _dt
    return _dt.datetime.utcfromtimestamp(ts or time.time()).replace(microsecond=0).isoformat() + "Z"

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def crc32_hex(b: bytes) -> str:
    return f"{(binascii.crc32(b) & 0xFFFFFFFF):08x}"

def hmac_hex(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()

def human_size(n: int) -> str:
    units = ["B","KiB","MiB","GiB","TiB"]
    i = 0
    x = float(n)
    while x >= 1024 and i < len(units)-1:
        x /= 1024.0; i += 1
    return f"{x:.2f} {units[i]}"

def eprint(*a, **k):
    print(*a, file=sys.stderr, **k)

# ----------------------------
# Provider loading & redaction
# ----------------------------

def load_provider(spec: str) -> Any:
    """
    spec: "module.path:Symbol" or "module.path" (defaults to 'StateProvider')
    Provider must expose get_state() -> Mapping or awaitable.
    """
    mod_name, _, sym = spec.partition(":")
    if not mod_name:
        raise ValueError("invalid provider spec")
    mod = importlib.import_module(mod_name)
    if not sym:
        sym = "StateProvider"
    provider = getattr(mod, sym, None)
    if provider is None:
        raise ImportError(f"symbol '{sym}' not found in {mod_name}")
    if inspect.isclass(provider):
        return provider()
    return provider  # instance or module-level object

def redact_inplace(obj: Any, dotted_keys: Sequence[str]) -> None:
    """
    Redacts keys (sets to "***") for dotted paths like "auth.token" or "players.*.email".
    Supports '*' for single-level wildcard on dict keys or list indexes.
    """
    for path in dotted_keys:
        parts = path.split(".")
        _redact_path(obj, parts)

def _redact_path(cur: Any, parts: List[str]) -> None:
    if not parts:
        return
    key = parts[0]
    rest = parts[1:]
    if isinstance(cur, dict):
        if key == "*":
            for k in list(cur.keys()):
                _redact_path(cur[k], rest)
        elif key in cur:
            if not rest:
                cur[key] = "***"
            else:
                _redact_path(cur[key], rest)
    elif isinstance(cur, list):
        if key == "*":
            for it in cur:
                _redact_path(it, rest)
        else:
            try:
                idx = int(key)
            except Exception:
                return
            if 0 <= idx < len(cur):
                if not rest:
                    cur[idx] = "***"
                else:
                    _redact_path(cur[idx], rest)

# ----------------------------
# Container IO
# ----------------------------

def write_snapshot(
    *,
    state: Mapping[str, Any],
    dest_path: Optional[str],
    engine_version: str,
    provider_id: str,
    compress_level: int,
    hmac_key: Optional[bytes],
    dry_stdout: bool,
) -> Dict[str, Any]:
    # 1) Canonical encode payload
    payload_raw = canonical_encode(state)
    sha_hex = sha256_hex(payload_raw)

    # 2) Compress
    if compress_level > 0:
        compressor = zlib.compressobj(level=compress_level)
        payload_comp = compressor.compress(payload_raw) + compressor.flush()
    else:
        payload_comp = payload_raw
    crc_hex = crc32_hex(payload_comp)

    # 3) Header
    header = {
        "schema": SCHEMA,
        "created_utc": utc_iso(),
        "engine_version": engine_version,
        "provider": provider_id,
        "compression": {"algo": "zlib" if compress_level > 0 else "none", "level": compress_level},
        "sha256_hex": sha_hex,
        "crc32_hex": crc_hex,
        "size_uncompressed": len(payload_raw),
        "size_compressed": len(payload_comp),
    }
    if hmac_key:
        header["hmac_alg"] = "HMAC-SHA256"
        header["hmac_hex"] = hmac_hex(hmac_key, payload_comp)

    container = MAGIC + canonical_json(header) + b"\n" + payload_comp

    if dry_stdout:
        sys.stdout.buffer.write(container)
        sys.stdout.flush()
        return header

    if not dest_path:
        # default file name: snapshot-<utc>-<sha8>.ecsn
        safe_ts = header["created_utc"].replace(":", "").replace("-", "")
        dest_path = f"snapshot-{safe_ts}-{sha_hex[:8]}.ecsn"

    atomic_write(dest_path, container)
    return header

def read_snapshot(path: str) -> Tuple[Dict[str, Any], bytes]:
    with open(path, "rb") as f:
        data = f.read()
    if not data.startswith(MAGIC):
        raise ValueError("bad magic or not a snapshot")
    rest = data[len(MAGIC):]
    try:
        header_bytes, payload = rest.split(b"\n", 1)
        header = json.loads(header_bytes.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"header parse error: {e}") from e
    return header, payload

def verify_snapshot(path: str, *, hmac_key: Optional[bytes]) -> Tuple[bool, str, Dict[str, Any]]:
    header, payload = read_snapshot(path)
    # checksum
    crc_ok = (header.get("crc32_hex") == crc32_hex(payload))
    # hmac
    hmac_ok = True
    if header.get("hmac_alg") == "HMAC-SHA256":
        if not hmac_key:
            return False, "HMAC key required but not provided", header
        h_ok = (header.get("hmac_hex") == hmac_hex(hmac_key, payload))
        hmac_ok = h_ok
    # sha256 on uncompressed payload (need to decompress if zlib)
    if header.get("compression", {}).get("algo") == "zlib":
        try:
            raw = zlib.decompress(payload)
        except Exception as e:
            return False, f"zlib decompress failed: {e}", header
    else:
        raw = payload
    sha_ok = (header.get("sha256_hex") == sha256_hex(raw))
    ok = bool(crc_ok and sha_ok and hmac_ok)
    msg = "ok" if ok else f"crc_ok={crc_ok} sha_ok={sha_ok} hmac_ok={hmac_ok}"
    return ok, msg, header

def atomic_write(path: str, data: bytes) -> None:
    tmp = f"{path}.tmp.{os.getpid()}"
    dirn = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(dirn, exist_ok=True)
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    # best-effort directory fsync (POSIX)
    try:
        dfd = os.open(dirn, os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except Exception:
        pass
    os.replace(tmp, path)

# ----------------------------
# Diff
# ----------------------------

def load_payload_bytes(path: str) -> bytes:
    header, payload = read_snapshot(path)
    if header.get("compression", {}).get("algo") == "zlib":
        payload = zlib.decompress(payload)
    return payload

def decode_canonical_to_jsonlike(b: bytes) -> Any:
    """
    Minimal decoder for our canonical format back to JSON-like types for diff.
    Only what's needed for structural diff and printing.
    """
    from struct import unpack
    pos = 0
    def rd(n: int) -> bytes:
        nonlocal pos
        if pos + n > len(b): raise ValueError("short read")
        out = b[pos:pos+n]; pos += n; return out
    def rdvarint() -> int:
        shift = 0; res = 0
        for _ in range(10):
            bb = b[pos]; pos_inc(1)
            res |= (bb & 0x7F) << shift
            if (bb & 0x80) == 0: return res
            shift += 7
        raise ValueError("varint too long")
    def pos_inc(n: int) -> None:
        nonlocal pos; pos += n
    def dec() -> Any:
        tag = rd(1)
        if tag == b"N": return None
        if tag == b"T": return True
        if tag == b"F": return False
        if tag == b"I":
            ln = rdvarint(); return int(rd(ln).decode("ascii"))
        if tag == b"D":
            return unpack("!d", rd(8))[0]
        if tag == b"S":
            ln = rdvarint(); return rd(ln).decode("utf-8")
        if tag == b"B":
            ln = rdvarint(); return rd(ln)  # bytes kept as bytes
        if tag == b"L":
            ln = rdvarint(); return [dec() for _ in range(ln)]
        if tag == b"M":
            ln = rdvarint()
            # keys are encoded scalars; decode them
            d: Dict[Any, Any] = {}
            for _ in range(ln):
                k = dec(); v = dec()
                d[k] = v
            return d
        raise ValueError(f"unknown tag {tag!r}")
    return dec()

def dict_diff(a: Any, b: Any, prefix: str = "") -> Tuple[List[str], List[str], List[str]]:
    """
    Returns (added, removed, changed) path lists for JSON-like structures.
    """
    added: List[str] = []; removed: List[str] = []; changed: List[str] = []
    if isinstance(a, dict) and isinstance(b, dict):
        keys = set(a.keys()) | set(b.keys())
        for k in sorted(keys, key=lambda x: str(x)):
            pa = k in a; pb = k in b
            path = f"{prefix}.{k}" if prefix else str(k)
            if pa and not pb: removed.append(path)
            elif pb and not pa: added.append(path)
            else:
                da, db = a[k], b[k]
                if type(da) is not type(db):
                    changed.append(path); continue
                if isinstance(da, (dict, list)):
                    a1, r1, c1 = dict_diff(da, db, path)
                    added += a1; removed += r1; changed += c1
                else:
                    if da != db:
                        changed.append(path)
    elif isinstance(a, list) and isinstance(b, list):
        n = max(len(a), len(b))
        for i in range(n):
            path = f"{prefix}[{i}]"
            if i >= len(a): added.append(path)
            elif i >= len(b): removed.append(path)
            else:
                if isinstance(a[i], (dict, list)) or isinstance(b[i], (dict, list)):
                    a1, r1, c1 = dict_diff(a[i], b[i], path)
                    added += a1; removed += r1; changed += c1
                else:
                    if a[i] != b[i]:
                        changed.append(path)
    else:
        if a != b:
            changed.append(prefix or "$")
    return added, removed, changed

# ----------------------------
# Main
# ----------------------------

def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="generate_snapshot", description="Deterministic engine state snapshot tool")
    sub = p.add_subparsers(dest="cmd", required=False)

    # generate (default)
    p.add_argument("--provider", required=False, default="engine.engine.state.snapshot:StateProvider",
                   help="Provider spec 'module:Symbol' exposing get_state()")
    p.add_argument("--engine-version", default=os.environ.get("ENGINE_VERSION", "0.0.0"),
                   help="Engine version string for metadata")
    p.add_argument("-o", "--output", help="Output file path (.ecsn). If omitted, auto-named")
    p.add_argument("--compress", type=int, default=6, choices=range(0,10),
                   help="zlib compression level (0=none)")
    p.add_argument("--hmac-key", help="HMAC key hex or '@file' or use env ENGINE_SNAPSHOT_HMAC_KEY")
    p.add_argument("--redact", action="append", default=[],
                   help="Redact dotted key path (repeatable). Supports '*' wildcard per level")
    p.add_argument("--dry-run", action="store_true", help="Write to stdout instead of file")
    p.add_argument("--pretty", action="store_true", help="Pretty-print JSON header to stderr")
    p.add_argument("--timeout", type=float, default=60.0, help="Provider call timeout seconds")

    # verify
    v = sub.add_parser("verify", help="Verify snapshot file integrity")
    v.add_argument("path", help="Snapshot file")
    v.add_argument("--hmac-key", help="HMAC key hex or '@file' or env ENGINE_SNAPSHOT_HMAC_KEY")

    # diff
    d = sub.add_parser("diff", help="Diff two snapshots")
    d.add_argument("a", help="Snapshot A")
    d.add_argument("b", help="Snapshot B")
    d.add_argument("--fail-on-diff", action="store_true", help="Exit with code 3 if any differences")

    return p.parse_args(argv)

def load_key_material(spec: Optional[str]) -> Optional[bytes]:
    if not spec:
        env = os.environ.get("ENGINE_SNAPSHOT_HMAC_KEY")
        spec = env if env else None
    if not spec:
        return None
    if spec.startswith("@"):
        with open(spec[1:], "rb") as f:
            return f.read().strip()
    # try hex; else treat as raw utf-8
    try:
        return bytes.fromhex(spec.strip())
    except Exception:
        return spec.encode("utf-8")

async def get_state_from_provider(provider_spec: str, timeout: float) -> Mapping[str, Any]:
    prov = load_provider(provider_spec)
    getter = getattr(prov, "get_state", None)
    if getter is None:
        raise RuntimeError("provider has no get_state()")
    if inspect.iscoroutinefunction(getter):
        return await asyncio.wait_for(getter(), timeout=timeout)
    res = getter()
    if inspect.isawaitable(res):
        return await asyncio.wait_for(res, timeout=timeout)
    return res

def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)

    if args.cmd == "verify":
        key = load_key_material(args.hmac_key)
        try:
            ok, msg, header = verify_snapshot(args.path, hmac_key=key)
        except Exception as e:
            eprint(f"Verify error: {e}")
            return 1
        if args.pretty:
            eprint(json.dumps(header, ensure_ascii=False, indent=2, sort_keys=True))
        eprint(f"Verification: {msg}")
        return 0 if ok else 2

    if args.cmd == "diff":
        try:
            a = decode_canonical_to_jsonlike(load_payload_bytes(args.a))
            b = decode_canonical_to_jsonlike(load_payload_bytes(args.b))
        except Exception as e:
            eprint(f"Diff load error: {e}")
            return 1
        added, removed, changed = dict_diff(a, b)
        eprint(f"Added: {len(added)}, Removed: {len(removed)}, Changed: {len(changed)}")
        if args.pretty:
            if added: eprint("  +", "\n  + ".join(added))
            if removed: eprint("  -", "\n  - ".join(removed))
            if changed: eprint("  ~", "\n  ~ ".join(changed))
        if args.fail_on_diff and (added or removed or changed):
            return 3
        return 0

    # Generate
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        state = loop.run_until_complete(get_state_from_provider(args.provider, args.timeout))
    except Exception as e:
        eprint(f"Provider error: {e}")
        return 1

    if not isinstance(state, Mapping):
        eprint("Provider returned non-mapping state")
        return 1

    # Redact if requested (work on a shallow copy to avoid mutating provider data)
    state_copy = json.loads(json.dumps(state))  # cheap deep copy via JSON (assumes JSONable)
    if args.redact:
        redact_inplace(state_copy, args.redact)

    key = load_key_material(args.hmac_key)

    try:
        header = write_snapshot(
            state=state_copy,
            dest_path=args.output,
            engine_version=args.engine_version,
            provider_id=args.provider,
            compress_level=int(args.compress),
            hmac_key=key,
            dry_stdout=bool(args.dry_run),
        )
    except Exception as e:
        eprint(f"Write error: {e}")
        return 1

    if args.pretty:
        eprint(json.dumps(header, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        eprint(f"Snapshot: sha256={header['sha256_hex'][:12]} size={human_size(header['size_compressed'])} comp={header['compression']['algo']}:{header['compression']['level']}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
