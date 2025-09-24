# physical-integration-core/physical_integration/telemetry/parsers.py
"""
Industrial telemetry parsers for NeuroCity physical-integration-core.

Features:
- Unified TelemetryRecord (Pydantic) with strict typing and safe defaults.
- Pluggable parsers (+ registry + decorator) with consistent Parser protocol.
- Formats: JSON/NDJSON, CSV (with header), key=value lines, Influx Line Protocol (subset),
  NMEA0183 (GPRMC/GPGGA).
- Autodetection heuristics with ordered preference and Prometheus metrics (optional).
- Structured logging with redaction, exception fencing, and payload truncation.
- Minimal dependencies: pydantic (required); prometheus_client/cbor2/msgpack (optional).

Public API:
    - TelemetryRecord
    - register_parser(name), get_parser(name, **cfg)
    - parse_with(name, payload: bytes|str, **cfg)
    - autodetect_and_parse(payload: bytes|str, prefer: list[str] | None = None, **cfg)

Environment (optional):
    TELEMETRY_LOG_LEVEL=INFO
"""

from __future__ import annotations

import csv
import datetime as dt
import json
import logging
import math
import os
import re
import sys
import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple, Union

try:
    import ujson as _json_fast  # type: ignore
except Exception:
    _json_fast = None

try:
    from pydantic import BaseModel, Field, validator
except Exception as e:
    raise RuntimeError("pydantic>=1.10 is required for telemetry parsers") from e

# Optional metrics
try:
    from prometheus_client import Counter  # type: ignore
    _PROM = True
except Exception:
    _PROM = False

    class _Noop:
        def __init__(self, *a, **kw): ...
        def labels(self, *a, **kw): return self
        def inc(self, *_): ...
    Counter = _Noop  # type: ignore


# ---------------------------- Logging -----------------------------------------

def _configure_logger() -> logging.Logger:
    lvl = os.environ.get("TELEMETRY_LOG_LEVEL", "INFO").upper()
    logger = logging.getLogger("telemetry.parsers")
    if not logger.handlers:
        h = logging.StreamHandler(sys.stdout)
        fmt = logging.Formatter("%(asctime)sZ %(levelname)s %(name)s %(message)s", "%Y-%m-%dT%H:%M:%S")
        h.setFormatter(fmt)
        logger.addHandler(h)
        logger.propagate = False
    logger.setLevel(getattr(logging, lvl, logging.INFO))
    return logger

log = _configure_logger()

def _truncate_for_log(s: str, limit: int = 512) -> str:
    return s if len(s) <= limit else (s[:limit] + "...[truncated]")


# ---------------------------- Metrics -----------------------------------------

_parsed_ok = Counter("telemetry_parsed_ok_total", "Parsed records total").labels()
_parsed_err = Counter("telemetry_parsed_error_total", "Parse errors total").labels()
_autodetect_hits = Counter("telemetry_autodetect_hits_total", "Autodetect hits by type")


# ---------------------------- Core model --------------------------------------

class TelemetryRecord(BaseModel):
    """
    Unified telemetry record.
    - ts: UTC timestamp; if not provided, set by parser as 'now'.
    - source: physical/logical source identifier (camera-01, plc-07, etc.)
    - stream: logical stream/measurement (e.g., "env", "power", "gps").
    - tags: low-cardinality labels (site, line, device_model).
    - fields: actual measured values; numbers/bools/strings.
    - seq: monotonically increasing sequence if provided by source.
    - checksum: sha256 of raw payload (hex), for traceability.
    """
    ts: dt.datetime = Field(default_factory=lambda: dt.datetime.now(dt.timezone.utc))
    source: str = Field(default="unknown")
    stream: str = Field(default="generic")
    tags: Dict[str, str] = Field(default_factory=dict)
    fields: Dict[str, Union[int, float, str, bool]] = Field(default_factory=dict)
    seq: Optional[int] = None
    checksum: Optional[str] = None

    @validator("ts", pre=True)
    def _ensure_utc(cls, v: Any) -> dt.datetime:
        if isinstance(v, (int, float)):
            # assume seconds
            return dt.datetime.fromtimestamp(float(v), tz=dt.timezone.utc)
        if isinstance(v, str):
            # try ISO8601
            try:
                # Accept Z suffix
                if v.endswith("Z"):
                    v = v[:-1] + "+00:00"
                return dt.datetime.fromisoformat(v).astimezone(dt.timezone.utc)
            except Exception:
                # fallback: epoch milliseconds
                if re.fullmatch(r"\d{13}", v):
                    ms = int(v) / 1000.0
                    return dt.datetime.fromtimestamp(ms, tz=dt.timezone.utc)
                raise
        if isinstance(v, dt.datetime):
            return v.astimezone(dt.timezone.utc) if v.tzinfo else v.replace(tzinfo=dt.timezone.utc)
        # default now
        return dt.datetime.now(dt.timezone.utc)


# ---------------------------- Parser protocol & registry ----------------------

class Parser(Protocol):
    """
    Parser protocol.
    parse(payload) -> list[TelemetryRecord]
    Implementations must not raise on individual record errors; they should
    either skip or produce no records and raise only on fatal configuration errors.
    """
    def parse(self, payload: Union[str, bytes]) -> List[TelemetryRecord]: ...


_REGISTRY: Dict[str, type] = {}

def register_parser(name: str):
    def _decorator(cls: type) -> type:
        if name in _REGISTRY:
            raise RuntimeError(f"Parser '{name}' already registered")
        _REGISTRY[name] = cls
        return cls
    return _decorator

def get_parser(name: str, **cfg) -> Parser:
    cls = _REGISTRY.get(name)
    if not cls:
        raise KeyError(f"Unknown parser '{name}'")
    return cls(**cfg) if cfg else cls()  # type: ignore

def parse_with(name: str, payload: Union[str, bytes], **cfg) -> List[TelemetryRecord]:
    parser = get_parser(name, **cfg)
    return parser.parse(payload)


# ---------------------------- Utilities ---------------------------------------

_NUM_RX = re.compile(r"^[+-]?(?:\d+\.\d*|\d*\.\d+|\d+)(?:[eE][+-]?\d+)?$")
_INT_RX = re.compile(r"^[+-]?\d+$")

def _auto_cast(v: str) -> Union[int, float, str, bool]:
    s = v.strip()
    if s.lower() in ("true", "false"):
        return s.lower() == "true"
    if _INT_RX.match(s):
        try:
            i = int(s)
            # guard against huge ints becoming seq, keep as int anyway
            return i
        except Exception:
            pass
    if _NUM_RX.match(s):
        try:
            return float(s)
        except Exception:
            pass
    return s

def _checksum(raw: Union[str, bytes]) -> str:
    b = raw.encode("utf-8") if isinstance(raw, str) else raw
    return hashlib.sha256(b).hexdigest()

def _dict_partition(d: Dict[str, Any], tag_prefixes: Iterable[str]) -> Tuple[Dict[str, str], Dict[str, Any]]:
    tag_pfx = tuple(tag_prefixes)
    tags: Dict[str, str] = {}
    fields: Dict[str, Any] = {}
    for k, v in d.items():
        if any(k.startswith(p) for p in tag_pfx):
            tags[k.split(".", 1)[-1] if "." in k else k] = str(v)
        else:
            fields[k] = v
    return tags, fields

def _to_str(payload: Union[str, bytes]) -> str:
    return payload if isinstance(payload, str) else payload.decode("utf-8", errors="replace")

def _now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


# ---------------------------- JSON / NDJSON -----------------------------------

@register_parser("json")
class JSONParser:
    """
    JSON/NDJSON parser.
    Config:
        ts_field: Optional[str]     # field name for timestamp
        ts_format: Optional[str]    # strptime format if ts not ISO (e.g., "%Y-%m-%d %H:%M:%S")
        source_field: Optional[str]
        stream_field: Optional[str]
        tag_prefixes: List[str] = ["tag.", "t_"]
        rename: Dict[str, str]      # mapping old->new keys
        drop_unknown: bool = False  # drop keys not in rename
    """
    def __init__(
        self,
        ts_field: Optional[str] = None,
        ts_format: Optional[str] = None,
        source_field: Optional[str] = None,
        stream_field: Optional[str] = None,
        tag_prefixes: Optional[List[str]] = None,
        rename: Optional[Dict[str, str]] = None,
        drop_unknown: bool = False,
    ):
        self.ts_field = ts_field
        self.ts_format = ts_format
        self.source_field = source_field
        self.stream_field = stream_field
        self.tag_prefixes = tag_prefixes or ["tag.", "t_"]
        self.rename = rename or {}
        self.drop_unknown = drop_unknown

    def _parse_obj(self, obj: Dict[str, Any], raw: str) -> Optional[TelemetryRecord]:
        # Renaming and filtering
        mapped: Dict[str, Any] = {}
        if self.rename:
            for k, v in obj.items():
                nk = self.rename.get(k, None)
                if nk:
                    mapped[nk] = v
                elif not self.drop_unknown:
                    mapped[k] = v
        else:
            mapped = dict(obj)

        # Extract timestamp
        ts = None
        if self.ts_field and self.ts_field in mapped:
            val = mapped.pop(self.ts_field)
            if self.ts_format and isinstance(val, str):
                ts = dt.datetime.strptime(val, self.ts_format).replace(tzinfo=dt.timezone.utc)
            else:
                ts = TelemetryRecord.__fields__["ts"].validate(val, {}, loc="ts")[0]

        source = str(mapped.pop(self.source_field, "unknown")) if self.source_field else "unknown"
        stream = str(mapped.pop(self.stream_field, "generic")) if self.stream_field else "generic"

        tags, fields_raw = _dict_partition(mapped, self.tag_prefixes)

        # Auto-cast fields
        fields: Dict[str, Union[int, float, str, bool]] = {}
        for k, v in fields_raw.items():
            if isinstance(v, str):
                fields[k] = _auto_cast(v)
            elif isinstance(v, (int, float, bool)):
                fields[k] = v  # already scalar
            else:
                # keep JSON sub-objects as stringified for storage; upstream can enrich
                fields[k] = json.dumps(v, separators=(",", ":"), ensure_ascii=False)

        rec = TelemetryRecord(
            ts=ts or _now_utc(),
            source=source,
            stream=stream,
            tags=tags,
            fields=fields,
            checksum=_checksum(raw),
        )
        return rec

    def parse(self, payload: Union[str, bytes]) -> List[TelemetryRecord]:
        s = _to_str(payload).strip()
        out: List[TelemetryRecord] = []
        if not s:
            return out

        # NDJSON: multiple lines, each JSON object
        if "\n" in s and not s.lstrip().startswith("["):
            for i, line in enumerate(s.splitlines()):
                ln = line.strip()
                if not ln:
                    continue
                try:
                    obj = (_json_fast or json).loads(ln)
                    if isinstance(obj, dict):
                        rec = self._parse_obj(obj, ln)
                        if rec:
                            out.append(rec)
                            _parsed_ok.inc()
                    else:
                        _parsed_err.inc()
                except Exception as e:
                    _parsed_err.inc()
                    log.warning("JSON line parse error", extra={"line": i, "err": repr(e), "payload": _truncate_for_log(ln)})
            return out

        # Single JSON (object or array of objects)
        try:
            data = (_json_fast or json).loads(s)
        except Exception as e:
            _parsed_err.inc()
            raise ValueError(f"Invalid JSON payload: {e}") from e

        if isinstance(data, dict):
            rec = self._parse_obj(data, s)
            if rec:
                out.append(rec)
                _parsed_ok.inc()
        elif isinstance(data, list):
            for i, item in enumerate(data):
                if not isinstance(item, dict):
                    _parsed_err.inc()
                    continue
                rec = self._parse_obj(item, json.dumps(item, ensure_ascii=False))
                if rec:
                    out.append(rec)
                    _parsed_ok.inc()
        else:
            _parsed_err.inc()

        return out


# ---------------------------- CSV (with header) -------------------------------

@register_parser("csv")
class CSVParser:
    """
    CSV parser (expects header). Use for CSV or TSV.
    Config:
        delimiter: str = ","
        decimal: str = "."
        ts_field: Optional[str]
        source_field: Optional[str]
        stream_field: Optional[str]
        tag_prefixes: List[str] = ["tag.", "t_"]
        header: Optional[List[str]]   # if not present in payload
        skip_initial_space: bool = True
    """
    def __init__(
        self,
        delimiter: str = ",",
        decimal: str = ".",
        ts_field: Optional[str] = None,
        source_field: Optional[str] = None,
        stream_field: Optional[str] = None,
        tag_prefixes: Optional[List[str]] = None,
        header: Optional[List[str]] = None,
        skip_initial_space: bool = True,
    ):
        self.delimiter = delimiter
        self.decimal = decimal
        self.ts_field = ts_field
        self.source_field = source_field
        self.stream_field = stream_field
        self.tag_prefixes = tag_prefixes or ["tag.", "t_"]
        self.header = header
        self.skip_initial_space = skip_initial_space

    def parse(self, payload: Union[str, bytes]) -> List[TelemetryRecord]:
        s = _to_str(payload)
        out: List[TelemetryRecord] = []
        lines = [ln for ln in s.splitlines() if ln.strip()]
        if not lines:
            return out

        rdr_iter: Iterable[List[str]]
        if self.header is None:
            header = next(csv.reader([lines[0]], delimiter=self.delimiter, skipinitialspace=self.skip_initial_space))
            data_lines = lines[1:]
        else:
            header = self.header
            data_lines = lines

        rdr_iter = csv.reader(data_lines, delimiter=self.delimiter, skipinitialspace=self.skip_initial_space)
        for idx, row in enumerate(rdr_iter, start=1):
            if len(row) != len(header):
                _parsed_err.inc()
                log.warning("CSV row length mismatch", extra={"row_index": idx, "expected": len(header), "got": len(row)})
                continue
            rec_d = dict(zip(header, row))
            # decimal normalization
            for k, v in rec_d.items():
                if isinstance(v, str) and self.decimal != ".":
                    rec_d[k] = v.replace(self.decimal, ".")
            # timestamp
            ts = None
            if self.ts_field and self.ts_field in rec_d:
                ts = TelemetryRecord.__fields__["ts"].validate(rec_d.pop(self.ts_field), {}, loc="ts")[0]
            source = str(rec_d.pop(self.source_field, "unknown")) if self.source_field else "unknown"
            stream = str(rec_d.pop(self.stream_field, "generic")) if self.stream_field else "generic"
            tags, fields_raw = _dict_partition(rec_d, self.tag_prefixes)
            # cast
            fields: Dict[str, Union[int, float, str, bool]] = {}
            for k, v in fields_raw.items():
                fields[k] = _auto_cast(v) if isinstance(v, str) else v

            raw_line = self.delimiter.join(row)
            out.append(TelemetryRecord(
                ts=ts or _now_utc(),
                source=source,
                stream=stream,
                tags=tags,
                fields=fields,
                checksum=_checksum(raw_line),
            ))
            _parsed_ok.inc()

        return out


# ---------------------------- key=value ---------------------------------------

_KV_SPLIT = re.compile(r"[,\s;]+")

@register_parser("kv")
class KeyValueParser:
    """
    key=value parser. Supports separators: space, comma, semicolon.
    Config:
        ts_key: Optional[str]
        source_key: Optional[str]
        stream_key: Optional[str]
        tag_prefixes: List[str] = ["tag.", "t_"]
    """
    def __init__(
        self,
        ts_key: Optional[str] = None,
        source_key: Optional[str] = None,
        stream_key: Optional[str] = None,
        tag_prefixes: Optional[List[str]] = None,
    ):
        self.ts_key = ts_key
        self.source_key = source_key
        self.stream_key = stream_key
        self.tag_prefixes = tag_prefixes or ["tag.", "t_"]

    def parse(self, payload: Union[str, bytes]) -> List[TelemetryRecord]:
        s = _to_str(payload).strip()
        out: List[TelemetryRecord] = []
        if not s:
            return out
        # support multiple lines
        for line in s.splitlines():
            line = line.strip()
            if not line:
                continue
            kvs = {}
            for token in _KV_SPLIT.split(line):
                if not token or "=" not in token:
                    continue
                k, v = token.split("=", 1)
                kvs[k.strip()] = v.strip()
            if not kvs:
                _parsed_err.inc()
                continue
            ts = None
            if self.ts_key and self.ts_key in kvs:
                ts = TelemetryRecord.__fields__["ts"].validate(kvs.pop(self.ts_key), {}, loc="ts")[0]
            source = str(kvs.pop(self.source_key, "unknown")) if self.source_key else "unknown"
            stream = str(kvs.pop(self.stream_key, "generic")) if self.stream_key else "generic"
            tags, fields_raw = _dict_partition(kvs, self.tag_prefixes)
            fields: Dict[str, Union[int, float, str, bool]] = {k: _auto_cast(v) for k, v in fields_raw.items()}
            out.append(TelemetryRecord(
                ts=ts or _now_utc(),
                source=source,
                stream=stream,
                tags=tags,
                fields=fields,
                checksum=_checksum(line),
            ))
            _parsed_ok.inc()
        return out


# ---------------------------- Influx Line Protocol (subset) -------------------

_ILP_LINE = re.compile(
    r"""
    ^\s*
    (?P<measurement>[a-zA-Z_][\w\-]*)                                   # measurement
    (?P<tags>(?:,[a-zA-Z_][\w\-]*=[^,\s]+)*)                             # ,tag=value...
    \s+
    (?P<fields>[a-zA-Z_][\w\-]*=[^=,\s]+(?:,[a-zA-Z_][\w\-]*=[^=,\s]+)*)  # f1=v1,f2=v2
    (?:\s+(?P<ts>-?\d{9,}))?                                             # optional timestamp
    \s*$
    """,
    re.VERBOSE,
)

def _parse_ilp_kvs(segment: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for part in segment.split(","):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        # integer suffix i (Influx)
        if v.endswith("i") and v[:-1].lstrip("+-").isdigit():
            out[k] = int(v[:-1])
        else:
            out[k] = _auto_cast(v)
    return out

@register_parser("influx_lp")
class InfluxLineProtocolParser:
    """
    Minimal Influx Line Protocol parser.
    - measurement[,tag1=val1,tag2=val2] field1=val1,field2=val2 [timestamp]
    - timestamp may be in ns/us/ms/s (auto-normalized).
    """
    def __init__(self, source: str = "unknown"):
        self.source = source

    @staticmethod
    def _normalize_epoch(ts_raw: str) -> dt.datetime:
        n = int(ts_raw)
        # choose scale by order of magnitude
        if abs(n) > 1_000_000_000_000_000:   # ns
            sec = n / 1_000_000_000
        elif abs(n) > 1_000_000_000_000:     # us
            sec = n / 1_000_000
        elif abs(n) > 1_000_000_000:         # ms
            sec = n / 1_000
        else:                                 # s
            sec = float(n)
        return dt.datetime.fromtimestamp(sec, tz=dt.timezone.utc)

    def parse(self, payload: Union[str, bytes]) -> List[TelemetryRecord]:
        s = _to_str(payload)
        out: List[TelemetryRecord] = []
        for idx, line in enumerate(s.splitlines()):
            line = line.strip()
            if not line:
                continue
            m = _ILP_LINE.match(line)
            if not m:
                _parsed_err.inc()
                log.warning("Influx LP parse error", extra={"line_index": idx, "payload": _truncate_for_log(line)})
                continue
            measurement = m.group("measurement")
            tag_seg = m.group("tags") or ""
            field_seg = m.group("fields")
            ts_raw = m.group("ts")
            tags = _parse_ilp_kvs(tag_seg[1:] if tag_seg.startswith(",") else tag_seg)
            fields = _parse_ilp_kvs(field_seg)
            ts = self._normalize_epoch(ts_raw) if ts_raw else _now_utc()
            out.append(TelemetryRecord(
                ts=ts,
                source=self.source,
                stream=measurement,
                tags={k: str(v) for k, v in tags.items()},
                fields=fields,
                checksum=_checksum(line),
            ))
            _parsed_ok.inc()
        return out


# ---------------------------- NMEA0183 (GPRMC/GPGGA) -------------------------

_NMEA_RE = re.compile(r"^\$(?P<body>[^*]+)\*(?P<cs>[0-9A-Fa-f]{2})")

def _nmea_checksum(body: str) -> str:
    c = 0
    for ch in body:
        c ^= ord(ch)
    return f"{c:02X}"

def _deg_min_to_decimal(dm: str, hemi: str) -> Optional[float]:
    if not dm or not hemi:
        return None
    try:
        # latitude:  ddmm.mmmm, longitude: dddmm.mmmm
        if "." not in dm:
            return None
        dot = dm.index(".")
        deg_len = dot - 2
        deg = float(dm[:deg_len])
        mins = float(dm[deg_len:])
        val = deg + mins / 60.0
        if hemi in ("S", "W"):
            val = -val
        return val
    except Exception:
        return None

@register_parser("nmea")
class NMEAParser:
    """
    NMEA0183 parser for GPRMC and GPGGA sentences.
    Produces stream 'gps' with fields: lat, lon, speed_knots, altitude_m, sats, fix_quality.
    Tags: talker, type.
    """
    def __init__(self, source: str = "unknown"):
        self.source = source

    def parse(self, payload: Union[str, bytes]) -> List[TelemetryRecord]:
        s = _to_str(payload)
        out: List[TelemetryRecord] = []
        for idx, line in enumerate(s.splitlines()):
            line = line.strip()
            if not line:
                continue
            m = _NMEA_RE.match(line)
            if not m:
                _parsed_err.inc()
                log.warning("NMEA: invalid frame", extra={"line_index": idx})
                continue
            body, cs = m.group("body"), m.group("cs").upper()
            if _nmea_checksum(body).upper() != cs:
                _parsed_err.inc()
                log.warning("NMEA: checksum mismatch", extra={"line_index": idx})
                continue
            parts = body.split(",")
            talker_type = parts[0] if parts else ""
            talker = talker_type[:2]
            typ = talker_type[2:]
            fields: Dict[str, Union[int, float, str, bool]] = {}
            tags = {"talker": talker, "type": typ}
            ts = _now_utc()
            try:
                if typ == "RMC" and len(parts) >= 12:
                    # time, status, lat, N/S, lon, E/W, speed(knots), course, date
                    # parts[1]=hhmmss.sss, parts[9]=ddmmyy
                    hhmmss = parts[1]
                    ddmmyy = parts[9]
                    if hhmmss and ddmmyy and len(ddmmyy) == 6:
                        tt = dt.datetime.strptime(ddmmyy + hhmmss[:6], "%d%m%y%H%M%S").replace(tzinfo=dt.timezone.utc)
                        ts = tt
                    lat = _deg_min_to_decimal(parts[3], parts[4])
                    lon = _deg_min_to_decimal(parts[5], parts[6])
                    spd = _auto_cast(parts[7])  # knots
                    if lat is not None: fields["lat"] = lat
                    if lon is not None: fields["lon"] = lon
                    if isinstance(spd, (int, float)): fields["speed_knots"] = float(spd)
                elif typ == "GGA" and len(parts) >= 15:
                    lat = _deg_min_to_decimal(parts[2], parts[3])
                    lon = _deg_min_to_decimal(parts[4], parts[5])
                    fix_q = int(parts[6]) if parts[6].isdigit() else 0
                    sats = int(parts[7]) if parts[7].isdigit() else 0
                    alt = float(parts[9]) if parts[9] else math.nan
                    if lat is not None: fields["lat"] = lat
                    if lon is not None: fields["lon"] = lon
                    fields["fix_quality"] = fix_q
                    fields["sats"] = sats
                    if not math.isnan(alt): fields["altitude_m"] = alt
                else:
                    # Unknown NMEA sentence: skip silently
                    continue
            except Exception as e:
                _parsed_err.inc()
                log.warning("NMEA parse exception", extra={"err": repr(e)})
                continue

            out.append(TelemetryRecord(
                ts=ts,
                source=self.source,
                stream="gps",
                tags=tags,
                fields=fields,
                checksum=_checksum(line),
            ))
            _parsed_ok.inc()
        return out


# ---------------------------- Autodetection -----------------------------------

# Heuristics ordered by specificity
_DETECTORS: List[Tuple[str, re.Pattern]] = [
    ("nmea", re.compile(r"^\$[A-Z]{5},.*\*[0-9A-Fa-f]{2}", re.MULTILINE)),
    ("influx_lp", re.compile(r"^[A-Za-z_]\w*(?:,[A-Za-z_]\w*=[^,\s]+)*\s+[A-Za-z_]\w*=", re.MULTILINE)),
    ("json", re.compile(r"^\s*(\{|\[|\{\"\w+\"|\[\{)", re.MULTILINE)),
    ("kv", re.compile(r"^\s*\w+=\S+", re.MULTILINE)),
    ("csv", re.compile(r"^\s*[\w\-\.]+\s*,\s*[\w\-\.]+", re.MULTILINE)),
]

def autodetect(payload: Union[str, bytes], prefer: Optional[List[str]] = None) -> Optional[str]:
    s = _to_str(payload)
    # honor prefer list first
    if prefer:
        for name in prefer:
            cls = _REGISTRY.get(name)
            if not cls:
                continue
            try:
                # cheap probe: if format regex matches
                rx = next((r for n, r in _DETECTORS if n == name), None)
                if rx and rx.search(s):
                    _autodetect_hits.labels(name).inc()
                    return name
            except Exception:
                continue
    for name, rx in _DETECTORS:
        if name not in _REGISTRY:
            continue
        if rx.search(s):
            _autodetect_hits.labels(name).inc()
            return name
    return None


def autodetect_and_parse(payload: Union[str, bytes], prefer: Optional[List[str]] = None, **cfg) -> List[TelemetryRecord]:
    name = autodetect(payload, prefer=prefer)
    if not name:
        raise ValueError("Unable to autodetect telemetry format")
    parser = get_parser(name, **cfg)
    try:
        return parser.parse(payload)
    except Exception as e:
        _parsed_err.inc()
        log.error("Parse failed after autodetect", extra={"parser": name, "err": repr(e), "payload": _truncate_for_log(_to_str(payload))})
        raise


# ---------------------------- Self-check / Example ----------------------------

EXAMPLE_JSON = """
{"ts":"2025-08-22T10:00:00Z","source":"sensor-1","stream":"env","tag.site":"A","temp":22.5,"hum":45}
{"ts":"2025-08-22T10:00:01Z","source":"sensor-1","stream":"env","tag.site":"A","temp":22.6,"hum":45}
""".strip()

EXAMPLE_CSV = """ts,source,stream,tag.site,temp,hum
2025-08-22T10:00:00Z,sensor-2,env,A,23.1,40
2025-08-22T10:00:01Z,sensor-2,env,A,23.2,41
""".strip()

EXAMPLE_KV = """ts=2025-08-22T10:00:00Z source=sensor-3 stream=env tag.site=B temp=24.2 hum=39
ts=2025-08-22T10:00:01Z source=sensor-3 stream=env tag.site=B temp=24.1 hum=38
""".strip()

EXAMPLE_ILP = """env,site=C temp=25.1,hum=37i 1724311200000000000
env,site=C temp=25.2,hum=38i 1724311201000000000
""".strip()

EXAMPLE_NMEA = """$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A
$GPGGA,123520,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47
""".strip()

if __name__ == "__main__":
    # Quick smoke test without external deps
    samples = [
        ("json", EXAMPLE_JSON, dict(ts_field="ts", source_field="source", stream_field="stream")),
        ("csv", EXAMPLE_CSV, dict(ts_field="ts", source_field="source", stream_field="stream")),
        ("kv", EXAMPLE_KV, dict(ts_key="ts", source_key="source", stream_key="stream")),
        ("influx_lp", EXAMPLE_ILP, dict(source="sensor-4")),
        ("nmea", EXAMPLE_NMEA, dict(source="gps-1")),
    ]
    for name, payload, cfg in samples:
        parser = get_parser(name, **cfg)
        recs = parser.parse(payload)
        print(f"[{name}] -> {len(recs)} records, first:", recs[0].dict())
    # Autodetect demo
    auto = autodetect_and_parse(EXAMPLE_JSON, ts_field="ts", source_field="source", stream_field="stream")
    print(f"[autodetect] json -> {len(auto)} records")
