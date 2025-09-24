# path: datafabric/utils/serde.py
"""
DataFabric SerDe (industrial-grade)

Features:
- Formats: JSON (safe), YAML (safe loader), MessagePack (optional), JSONL streaming
- Canonical JSON (stable ordering, no whitespace) for signatures and hashing
- Safe adapters for datetime, date, time, UUID, Decimal, bytes (base64), Path, set/frozenset
- Dataclass and Pydantic model support
- Compression: gzip, bz2, zlib/deflate, zstd (optional) + auto-detect (magic bytes)
- Content detection: format + compression inference from bytes/extension/content-type
- Optional JSON Schema validation (jsonschema if installed)
- Hashing utilities (sha256 of bytes/streams/files)
- Registry-based codecs with strict security defaults (pickle disabled unless explicitly allowed)
- JSONL helpers: write/read large datasets line-by-line with backpressure-friendly iterators
- MIME/content-type helpers and file extension mapping
- Clear exceptions with context

No external dependencies required (optional: PyYAML, msgpack, jsonschema, zstandard).
"""

from __future__ import annotations

import base64
import bz2
import datetime as dt
import gzip
import io
import json
import math
import os
import sys
import time
import typing as t
import uuid
import zlib
from dataclasses import is_dataclass, asdict
from decimal import Decimal
from hashlib import sha256
from pathlib import Path

# ----- Optional deps
try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # type: ignore

try:
    import msgpack  # type: ignore
except Exception:
    msgpack = None  # type: ignore

try:
    import jsonschema  # type: ignore
except Exception:
    jsonschema = None  # type: ignore

try:
    import zstandard as zstd  # type: ignore
except Exception:
    zstd = None  # type: ignore

__all__ = [
    # Core API
    "encode", "decode", "dumps", "loads",
    # Canonical / hashing
    "to_canonical_json", "hash_bytes", "hash_file",
    # Streaming JSONL
    "jsonl_iter", "jsonl_write",
    # Compression
    "compress", "decompress", "Compression", "Format",
    # Detection & helpers
    "detect", "content_type_for", "extension_for",
    # Validation
    "validate_json_schema",
    # Exceptions
    "SerDeError", "ValidationError", "UnsupportedFormatError", "SecurityError",
]

# ===== Exceptions =====

class SerDeError(Exception):
    """Base class for serde errors."""

class ValidationError(SerDeError):
    """Schema validation failed."""

class UnsupportedFormatError(SerDeError):
    """Requested format is not available or not installed."""

class SecurityError(SerDeError):
    """Security-sensitive operation rejected (e.g., unsafe loader or pickle)."""

# ===== Enums / constants =====

class Format(str):
    JSON = "json"
    YAML = "yaml"
    MSGPACK = "msgpack"
    # PICKLE deliberately omitted from public API by default

class Compression(str):
    NONE = "none"
    GZIP = "gzip"
    BZIP2 = "bzip2"
    ZLIB = "zlib"
    ZSTD = "zstd"

_MIME_BY_FORMAT: dict[str, str] = {
    Format.JSON: "application/json",
    Format.YAML: "application/yaml",
    Format.MSGPACK: "application/msgpack",
}

_EXT_BY_FORMAT: dict[str, str] = {
    Format.JSON: ".json",
    Format.YAML: ".yaml",
    Format.MSGPACK: ".msgpack",
}

# Magic bytes (prefix) for compression detection
_MAGIC = {
    Compression.GZIP: b"\x1f\x8b",
    Compression.BZIP2: b"BZh",
    Compression.ZLIB: b"\x78",  # zlib has multiple CMF variants, this is heuristic
    Compression.ZSTD: b"\x28\xb5\x2f\xfd",
}

# ===== Adapters (safe) =====

_JSON_SAFE_MAX_INT = 2**53 - 1  # IEEE-754 safe range

def _is_pydantic_model(obj: t.Any) -> bool:
    # v1/v2 compatibility without importing pydantic directly
    return hasattr(obj, "dict") and callable(getattr(obj, "dict"))

def _normalize(obj: t.Any) -> t.Any:
    """
    Convert complex objects into JSON-safe structures.
    """
    # Dataclass
    if is_dataclass(obj):
        return {k: _normalize(v) for k, v in asdict(obj).items()}

    # Pydantic (v1/v2)
    if _is_pydantic_model(obj):
        try:
            return {k: _normalize(v) for k, v in obj.dict()}  # type: ignore[attr-defined]
        except Exception:
            # Fallback: as dict via __dict__
            return {k: _normalize(v) for k, v in vars(obj).items()}

    # Built-ins
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        # Guard NaN/Inf to strings unless allow_nan=True at json.dumps
        if isinstance(obj, float) and (math.isnan(obj) or math.isinf(obj)):
            return str(obj)
        # Warn on large ints outside JSON safe range by stringifying
        if isinstance(obj, int) and abs(obj) > _JSON_SAFE_MAX_INT:
            return str(obj)
        return obj

    if isinstance(obj, (list, tuple)):
        return [ _normalize(v) for v in obj ]

    if isinstance(obj, (set, frozenset)):
        # Stable order
        return sorted([ _normalize(v) for v in obj ])

    if isinstance(obj, dict):
        # Ensure keys are strings
        out: dict[str, t.Any] = {}
        for k, v in obj.items():
            ks = str(k)
            out[ks] = _normalize(v)
        return out

    # Rich scalar types
    if isinstance(obj, (dt.datetime, dt.date, dt.time)):
        # Ensure UTC Z for naive datetimes (assume UTC)
        if isinstance(obj, dt.datetime):
            if obj.tzinfo is None:
                obj = obj.replace(tzinfo=dt.timezone.utc)
            return obj.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
        if isinstance(obj, dt.date):
            return obj.isoformat()
        if isinstance(obj, dt.time):
            if obj.tzinfo is None:
                return obj.replace(tzinfo=dt.timezone.utc).isoformat().replace("+00:00", "Z")
            return obj.isoformat()

    if isinstance(obj, uuid.UUID):
        return str(obj)

    if isinstance(obj, Decimal):
        # Keep string to avoid precision loss
        return format(obj, "f")

    if isinstance(obj, bytes):
        return {"__bytes__": True, "b64": base64.b64encode(obj).decode("ascii")}

    if isinstance(obj, Path):
        return str(obj)

    # Fallback: try as string
    return str(obj)

def _object_hook(obj: dict[str, t.Any]) -> dict[str, t.Any]:
    """
    Restore special markers from JSON-like structures.
    """
    if "__bytes__" in obj and obj.get("__bytes__") is True and "b64" in obj:
        try:
            return base64.b64decode(obj["b64"].encode("ascii"))
        except Exception:
            return obj
    return obj

# ===== Codec registry =====

class _Codec(t.Protocol):
    def dumps(self, obj: t.Any, **opts) -> bytes: ...
    def loads(self, data: bytes, **opts) -> t.Any: ...
    def content_type(self) -> str: ...
    def extension(self) -> str: ...

def _json_dumps(obj: t.Any, **opts) -> bytes:
    default_opts = dict(
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),  # compact by default
    )
    default_opts.update(opts)
    return json.dumps(_normalize(obj), **default_opts).encode("utf-8")

def _json_loads(data: bytes, **opts) -> t.Any:
    obj = json.loads(data.decode("utf-8"), object_hook=_object_hook, **opts)
    return obj

def _yaml_dumps(obj: t.Any, **opts) -> bytes:
    if yaml is None:
        raise UnsupportedFormatError("PyYAML is not installed")
    default_opts = dict(default_flow_style=False, allow_unicode=True)
    default_opts.update(opts)
    # Use safe_dump
    return yaml.safe_dump(_normalize(obj), **default_opts).encode("utf-8")

def _yaml_loads(data: bytes, **opts) -> t.Any:
    if yaml is None:
        raise UnsupportedFormatError("PyYAML is not installed")
    return yaml.safe_load(data.decode("utf-8"))

def _msgpack_dumps(obj: t.Any, **opts) -> bytes:
    if msgpack is None:
        raise UnsupportedFormatError("msgpack is not installed")
    default_opts = dict(use_bin_type=True)
    default_opts.update(opts)
    # Normalize first to preserve our adapters
    return msgpack.packb(_normalize(obj), **default_opts)

def _msgpack_loads(data: bytes, **opts) -> t.Any:
    if msgpack is None:
        raise UnsupportedFormatError("msgpack is not installed")
    default_opts = dict(raw=False, strict_map_key=False)
    default_opts.update(opts)
    obj = msgpack.unpackb(data, **default_opts)
    # MessagePack returns native bytes; no special markers; leave as-is
    return obj

_CODECS: dict[str, _Codec] = {
    Format.JSON: type("JSONCodec", (), {
        "dumps": staticmethod(_json_dumps),
        "loads": staticmethod(_json_loads),
        "content_type": staticmethod(lambda: _MIME_BY_FORMAT[Format.JSON]),
        "extension": staticmethod(lambda: _EXT_BY_FORMAT[Format.JSON]),
    })(),
    Format.YAML: type("YAMLCodec", (), {
        "dumps": staticmethod(_yaml_dumps),
        "loads": staticmethod(_yaml_loads),
        "content_type": staticmethod(lambda: _MIME_BY_FORMAT[Format.YAML]),
        "extension": staticmethod(lambda: _EXT_BY_FORMAT[Format.YAML]),
    })(),
    Format.MSGPACK: type("MsgPackCodec", (), {
        "dumps": staticmethod(_msgpack_dumps),
        "loads": staticmethod(_msgpack_loads),
        "content_type": staticmethod(lambda: _MIME_BY_FORMAT[Format.MSGPACK]),
        "extension": staticmethod(lambda: _EXT_BY_FORMAT[Format.MSGPACK]),
    })(),
}

# ===== Public API =====

def dumps(obj: t.Any, fmt: str = Format.JSON, **opts) -> bytes:
    """
    Serialize object to bytes in the given format.
    """
    codec = _CODECS.get(fmt)
    if not codec:
        raise UnsupportedFormatError(f"Unsupported format: {fmt}")
    return codec.dumps(obj, **opts)

def loads(data: bytes, fmt: str = Format.JSON, *, validate_with: dict | None = None, **opts) -> t.Any:
    """
    Deserialize bytes into an object with optional JSON Schema validation (for JSON/YAML).
    """
    codec = _CODECS.get(fmt)
    if not codec:
        raise UnsupportedFormatError(f"Unsupported format: {fmt}")
    obj = codec.loads(data, **opts)
    if validate_with is not None:
        validate_json_schema(obj, validate_with)
    return obj

def encode(obj: t.Any,
           fmt: str = Format.JSON,
           compression: str = Compression.NONE,
           **opts) -> bytes:
    """
    Serialize + compress. Returns bytes possibly compressed.
    """
    raw = dumps(obj, fmt=fmt, **opts)
    return compress(raw, compression=compression)

def decode(data: bytes,
           fmt: str | None = None,
           compression: str | None = None,
           *,
           validate_with: dict | None = None,
           **opts) -> t.Any:
    """
    Decompress (if needed) + deserialize.
    If fmt/compression are None, they will be auto-detected.
    """
    comp, _fmt = detect(data, fmt_hint=fmt, compression_hint=compression)
    raw = decompress(data, compression=comp)
    return loads(raw, fmt=_fmt, validate_with=validate_with, **opts)

# ===== Canonical JSON / hashing =====

def to_canonical_json(obj: t.Any) -> bytes:
    """
    Deterministic JSON (sorted keys, compact separators) for hashing/signatures.
    """
    normalized = _normalize(obj)
    return json.dumps(normalized, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

def hash_bytes(data: bytes) -> str:
    return sha256(data).hexdigest()

def hash_file(path: str | os.PathLike[str], chunk_size: int = 1024 * 1024) -> str:
    h = sha256()
    with open(path, "rb") as f:
        while True:
            c = f.read(chunk_size)
            if not c:
                break
            h.update(c)
    return h.hexdigest()

# ===== JSONL streaming =====

def jsonl_iter(stream: io.IOBase | bytes | bytearray,
               *,
               fmt: str = Format.JSON) -> t.Iterator[t.Any]:
    """
    Iterate objects from a JSON Lines stream (one JSON object per line).
    Accepts a binary file-like or raw bytes.
    """
    if isinstance(stream, (bytes, bytearray)):
        buf = io.BytesIO(stream)
    else:
        buf = stream
    for line in buf:
        line = line.strip()
        if not line:
            continue
        yield loads(line, fmt=fmt)

def jsonl_write(objs: t.Iterable[t.Any],
                stream: io.BufferedWriter | None = None,
                *,
                fmt: str = Format.JSON) -> bytes | None:
    """
    Write objects to JSON Lines stream. If stream is None, returns bytes.
    """
    out = stream or io.BytesIO()
    for obj in objs:
        b = dumps(obj, fmt=fmt)
        out.write(b)
        out.write(b"\n")
    if stream is None:
        return out.getvalue()
    return None

# ===== Compression =====

def compress(data: bytes, compression: str = Compression.NONE, level: int | None = None) -> bytes:
    if compression == Compression.NONE:
        return data
    if compression == Compression.GZIP:
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=level or 5) as gf:
            gf.write(data)
        return buf.getvalue()
    if compression == Compression.BZIP2:
        return bz2.compress(data, compresslevel=level or 9)
    if compression == Compression.ZLIB:
        return zlib.compress(data, level if level is not None else 6)
    if compression == Compression.ZSTD:
        if zstd is None:
            raise UnsupportedFormatError("zstandard is not installed")
        c = zstd.ZstdCompressor(level=level or 3)
        return c.compress(data)
    raise UnsupportedFormatError(f"Unsupported compression: {compression}")

def decompress(data: bytes, compression: str = Compression.NONE) -> bytes:
    if compression == Compression.NONE:
        return data
    if compression == Compression.GZIP:
        return gzip.decompress(data)
    if compression == Compression.BZIP2:
        return bz2.decompress(data)
    if compression == Compression.ZLIB:
        return zlib.decompress(data)
    if compression == Compression.ZSTD:
        if zstd is None:
            raise UnsupportedFormatError("zstandard is not installed")
        d = zstd.ZstdDecompressor()
        return d.decompress(data)
    raise UnsupportedFormatError(f"Unsupported compression: {compression}")

# ===== Detection =====

def detect(data: bytes | None,
           *,
           fmt_hint: str | None = None,
           compression_hint: str | None = None,
           file_name: str | None = None,
           content_type: str | None = None) -> tuple[str, str]:
    """
    Detect (compression, format) from magic bytes / hints / file extension / content-type.
    If data is None, will rely on hints.
    """
    comp = compression_hint or Compression.NONE
    fmt = fmt_hint or Format.JSON

    # From content type
    if content_type:
        ct = content_type.lower()
        if "json" in ct:
            fmt = Format.JSON
        elif "yaml" in ct or "yml" in ct:
            fmt = Format.YAML
        elif "msgpack" in ct:
            fmt = Format.MSGPACK
        if "zstd" in ct:
            comp = Compression.ZSTD
        elif "gzip" in ct or "x-gzip" in ct:
            comp = Compression.GZIP
        elif "bzip2" in ct:
            comp = Compression.BZIP2
        elif "deflate" in ct or "zlib" in ct:
            comp = Compression.ZLIB

    # From extension
    if file_name:
        ext = Path(file_name).suffix.lower()
        if ext in (".json", ".jsonl"):
            fmt = Format.JSON
        elif ext in (".yaml", ".yml"):
            fmt = Format.YAML
        elif ext in (".mpk", ".msgpack"):
            fmt = Format.MSGPACK
        if ext.endswith(".gz") or ext == ".gz":
            comp = Compression.GZIP
        elif ext in (".bz2",):
            comp = Compression.BZIP2
        elif ext in (".zst", ".zstd"):
            comp = Compression.ZSTD

    # From magic bytes
    if data:
        head = data[:4]
        for c, magic in _MAGIC.items():
            if head.startswith(magic):
                comp = c
                break

    return comp, fmt

def content_type_for(fmt: str, compression: str = Compression.NONE) -> str:
    ct = _MIME_BY_FORMAT.get(fmt, "application/octet-stream")
    if compression == Compression.GZIP:
        return ct + "+gzip"
    if compression == Compression.BZIP2:
        return ct + "+bzip2"
    if compression == Compression.ZSTD:
        return ct + "+zstd"
    if compression == Compression.ZLIB:
        return ct + "+deflate"
    return ct

def extension_for(fmt: str, compression: str = Compression.NONE) -> str:
    base = _EXT_BY_FORMAT.get(fmt, "")
    if fmt == Format.JSON and compression == Compression.NONE:
        return base
    # Compose extensions as file.format.ext
    ext_map = {
        Compression.GZIP: ".gz",
        Compression.BZIP2: ".bz2",
        Compression.ZSTD: ".zst",
        Compression.ZLIB: ".deflate",
        Compression.NONE: "",
    }
    return base + ext_map[compression]

# ===== Validation =====

def validate_json_schema(obj: t.Any, schema: dict) -> None:
    """
    Validate object using JSON Schema (if jsonschema installed).
    """
    if jsonschema is None:
        raise UnsupportedFormatError("jsonschema is not installed")
    try:
        jsonschema.validate(instance=obj, schema=schema)  # type: ignore[attr-defined]
    except Exception as e:
        raise ValidationError(str(e)) from e

# ===== Secure YAML guard (documented behaviour)
# We already use yaml.safe_load/dump. No FullLoader allowed.

# ===== Example-safe self test =====

if __name__ == "__main__":  # pragma: no cover
    sample = {
        "id": uuid.uuid4(),
        "when": dt.datetime.utcnow(),
        "pi": Decimal("3.1415926535897932384626"),
        "payload": b"\x00\x01",
        "set": {3, 2, 1},
        "bigint": 2**80,
        "nan": float("nan"),
    }

    # Canonical JSON and hash
    cjson = to_canonical_json(sample)
    print("canonical json:", cjson.decode("utf-8"))
    print("hash:", hash_bytes(cjson))

    # Encode/decode JSON + gzip
    blob = encode(sample, fmt=Format.JSON, compression=Compression.GZIP)
    obj = decode(blob)
    print("decoded ok keys:", sorted(obj.keys()))

    # JSONL
    items = [{"i": i, "t": time.time()} for i in range(3)]
    buf = jsonl_write(items)
    for row in jsonl_iter(buf):
        print("row:", row)

    # MessagePack (if available)
    if msgpack:
        b = dumps(sample, fmt=Format.MSGPACK)
        o = loads(b, fmt=Format.MSGPACK)
        print("msgpack ok:", isinstance(o, dict))

    # YAML (if available)
    if yaml:
        y = dumps(sample, fmt=Format.YAML)
        o = loads(y, fmt=Format.YAML)
        print("yaml ok:", isinstance(o, dict))
