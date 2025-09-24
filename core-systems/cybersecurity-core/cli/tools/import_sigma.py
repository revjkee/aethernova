#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cybersecurity-core/cli/tools/import_sigma.py

Industrial-grade CLI tool to validate and import Sigma rules from YAML files
into JSONL or SQLite storage with robust parsing, normalization, de-duplication,
and structured logging.

Key features:
- Safe YAML loading with duplicate-key detection
- Optional JSON Schema validation (if jsonschema is installed)
- Batch import from files, folders, and glob patterns
- Deterministic rule identity strategies (hash, uuid, or native sigma 'id')
- Outputs to JSONL (atomic write) or SQLite (ACID with WAL)
- Structured JSON logs, strict/lenient error modes, and reproducible hashing
- Type hints, mypy-friendly, minimal external deps (PyYAML required)

Usage examples:
  import-sigma validate -i rules/**/*.yml --schema path/to/schema.json
  import-sigma import -i rules/ -o out/rules.jsonl --format jsonl --strict
  import-sigma import -i rules/**/*.yaml -o out/sigma.db --format sqlite --id-strategy hash

Note:
- Requires PyYAML. Optionally uses jsonschema if --schema is provided.
- No network access; schema must be local if used.

Copyright:
- This file is delivered as-is. Integrate into your project’s packaging and CI.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import dataclasses
import datetime as dt
import fnmatch
import gzip
import hashlib
import io
import json
import logging
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple, Union, TypedDict

# Third-party: required
try:
    import yaml
except Exception as exc:  # pragma: no cover
    raise SystemExit(
        "PyYAML is required. Install with: pip install pyyaml"
    ) from exc

# Third-party: optional
with contextlib.suppress(Exception):
    import jsonschema  # type: ignore


APP_NAME = "import-sigma"
DEFAULT_GLOB_PATTERNS = ("*.yml", "*.yaml")
SUPPORTED_OUT_FORMATS = ("jsonl", "sqlite")
SQLITE_SCHEMA_VERSION = 1
_SQLITE_LOCK = threading.Lock()


class JsonLogRecord(TypedDict, total=False):
    ts: str
    level: str
    msg: str
    event: str
    extra: Dict[str, Any]


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_now() -> str:
    return _utc_now().isoformat()


def configure_logging(level: int = logging.INFO, json_format: bool = True) -> None:
    logger = logging.getLogger()
    logger.handlers.clear()
    logger.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)
    if json_format:
        def emit_json(record: logging.LogRecord) -> None:
            payload: JsonLogRecord = {
                "ts": _utc_now().isoformat(),
                "level": record.levelname.lower(),
                "msg": record.getMessage(),
            }
            # Attach event if present
            if hasattr(record, "event"):
                payload["event"] = getattr(record, "event")
            # Attach extra fields
            extras: Dict[str, Any] = {}
            for k, v in record.__dict__.items():
                if k in ("args", "asctime", "created", "exc_info", "exc_text", "filename",
                         "funcName", "levelname", "levelno", "lineno", "message", "module",
                         "msecs", "msg", "name", "pathname", "process", "processName",
                         "relativeCreated", "stack_info", "thread", "threadName"):
                    continue
                extras[k] = v
            if extras:
                payload["extra"] = extras
            sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
        # Bind a custom emit function
        class _JsonHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:  # type: ignore[override]
                emit_json(record)
        handler = _JsonHandler()
    else:
        fmt = "[%(levelname)s] %(message)s"
        handler.setFormatter(logging.Formatter(fmt))
    logger.addHandler(handler)


class DuplicateKeySafeLoader(yaml.SafeLoader):
    """
    YAML Loader that raises on duplicate keys to protect rule integrity.
    """
    pass


def _construct_mapping(loader: DuplicateKeySafeLoader, node: yaml.nodes.MappingNode, deep: bool = False) -> Any:
    mapping: Dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key: {key!r}",
                key_node.start_mark,
            )
        value = loader.construct_object(value_node, deep=deep)
        mapping[key] = value
    return mapping


DuplicateKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


@dataclasses.dataclass(frozen=True)
class SigmaRule:
    # Core
    rule_id: str
    title: str
    detection: Dict[str, Any]
    logsource: Dict[str, Any]

    # Optional metadata
    status: Optional[str] = None
    description: Optional[str] = None
    level: Optional[str] = None
    tags: Tuple[str, ...] = ()
    references: Tuple[str, ...] = ()
    author: Optional[str] = None
    created: Optional[str] = None
    modified: Optional[str] = None
    falsepositives: Tuple[str, ...] = ()

    # Provenance
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    import_ts: Optional[str] = None
    sigma_id_source: Optional[str] = None

    # Raw content
    raw: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_serializable(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "detection": self.detection,
            "logsource": self.logsource,
            "status": self.status,
            "description": self.description,
            "level": self.level,
            "tags": list(self.tags),
            "references": list(self.references),
            "author": self.author,
            "created": self.created,
            "modified": self.modified,
            "falsepositives": list(self.falsepositives),
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "import_ts": self.import_ts,
            "sigma_id_source": self.sigma_id_source,
            "raw": self.raw,
        }


def sha256_hex(data: Union[bytes, str]) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8", errors="strict")
    return hashlib.sha256(data).hexdigest()


def file_sha256_hex(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def deterministic_rule_hash(payload: Dict[str, Any]) -> str:
    """
    Create a deterministic hash over normalized significant fields.
    """
    normalized: Dict[str, Any] = {
        "title": payload.get("title"),
        "detection": payload.get("detection"),
        "logsource": payload.get("logsource"),
        "level": payload.get("level"),
        "status": payload.get("status"),
        "tags": sorted(payload.get("tags") or []),
    }
    # Ensure stable JSON encoding
    blob = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256_hex(blob)


def _as_tuple_str(value: Any) -> Tuple[str, ...]:
    if value is None:
        return tuple()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(str(x) for x in value)
    return (str(value),)


def parse_sigma_yaml(content: str, src_path: Optional[Path]) -> Dict[str, Any]:
    return yaml.load(content, Loader=DuplicateKeySafeLoader) or {}


def validate_sigma_payload(payload: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Minimal structural validation (schema-free).
    Returns (ok, errors).
    """
    errors: List[str] = []

    if not isinstance(payload, dict):
        return False, ["Root is not a mapping"]

    if "title" not in payload or not payload.get("title"):
        errors.append("Missing required field: title")

    detection = payload.get("detection")
    if not isinstance(detection, dict) or not detection:
        errors.append("Missing or invalid required field: detection (must be non-empty mapping)")

    logsource = payload.get("logsource")
    if not isinstance(logsource, dict) or not logsource:
        errors.append("Missing or invalid required field: logsource (must be non-empty mapping)")

    # Optional fields sanity
    for opt_key in ("tags", "references", "falsepositives"):
        opt_val = payload.get(opt_key)
        if opt_val is not None and not isinstance(opt_val, (list, tuple)):
            errors.append(f"Optional field {opt_key} must be a list if present")

    return (len(errors) == 0), errors


def schema_validate_if_available(payload: Dict[str, Any], schema: Optional[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    if not schema:
        return True, []
    if "jsonschema" not in sys.modules:
        return False, ["jsonschema not installed but a schema was provided"]
    assert "jsonschema" in sys.modules  # for type checkers
    try:
        jsonschema.validate(payload, schema)  # type: ignore[name-defined]
        return True, []
    except Exception as exc:
        return False, [str(exc)]


def build_sigma_rule(
    payload: Dict[str, Any],
    *,
    path: Optional[Path],
    id_strategy: str,
) -> SigmaRule:
    sigma_id_src = None
    if id_strategy == "sigma_id":
        sigma_id_src = str(payload.get("id") or "")
        if not sigma_id_src:
            # Fallback deterministically if rule lacks native id
            rule_id = deterministic_rule_hash(payload)
        else:
            rule_id = sigma_id_src
    elif id_strategy == "uuid":
        # UUID v5-like deterministic over normalized content (not requiring uuid lib)
        rule_id = deterministic_rule_hash(payload)[:32]
    else:
        # Default: hash
        rule_id = deterministic_rule_hash(payload)

    file_hash = file_sha256_hex(path) if path else None
    import_ts = iso_now()

    return SigmaRule(
        rule_id=rule_id,
        title=str(payload.get("title") or ""),
        detection=dict(payload.get("detection") or {}),
        logsource=dict(payload.get("logsource") or {}),
        status=str(payload.get("status") or "") or None,
        description=str(payload.get("description") or "") or None,
        level=str(payload.get("level") or "") or None,
        tags=_as_tuple_str(payload.get("tags")),
        references=_as_tuple_str(payload.get("references")),
        author=str(payload.get("author") or "") or None,
        created=str(payload.get("date") or payload.get("created") or "") or None,
        modified=str(payload.get("modified") or "") or None,
        falsepositives=_as_tuple_str(payload.get("falsepositives")),
        file_path=str(path) if path else None,
        file_hash=file_hash,
        import_ts=import_ts,
        sigma_id_source=sigma_id_src,
        raw=payload,
    )


def iter_files(
    inputs: Sequence[str],
    recursive: bool,
    patterns: Sequence[str] = DEFAULT_GLOB_PATTERNS,
) -> Iterator[Path]:
    seen: Set[Path] = set()
    for item in inputs:
        p = Path(item)
        if p.is_file():
            if any(fnmatch.fnmatch(p.name, pat) for pat in patterns):
                if p not in seen:
                    seen.add(p)
                    yield p
        elif p.is_dir():
            it = p.rglob("*") if recursive else p.glob("*")
            for f in it:
                if f.is_file() and any(fnmatch.fnmatch(f.name, pat) for pat in patterns):
                    if f not in seen:
                        seen.add(f)
                        yield f
        else:
            # Treat as glob
            for f in Path().glob(item):
                if f.is_file() and any(fnmatch.fnmatch(f.name, pat) for pat in patterns):
                    if f not in seen:
                        seen.add(f)
                        yield f


def load_schema_from_file(schema_path: Optional[str]) -> Optional[Dict[str, Any]]:
    if not schema_path:
        return None
    sp = Path(schema_path)
    if not sp.exists():
        raise FileNotFoundError(f"Schema file not found: {schema_path}")
    text = sp.read_text(encoding="utf-8")
    return json.loads(text)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def process_file(
    path: Path,
    *,
    strict: bool,
    schema: Optional[Dict[str, Any]],
    id_strategy: str,
) -> Tuple[Optional[SigmaRule], List[str]]:
    try:
        content = read_text(path)
        payload = parse_sigma_yaml(content, path)
    except Exception as exc:
        err = f"Failed to parse YAML: {path} -> {exc}"
        if strict:
            raise
        logging.error(err, extra={"event": "parse_error", "path": str(path)})
        return None, [err]

    ok_basic, errors_basic = validate_sigma_payload(payload)
    ok_schema, errors_schema = schema_validate_if_available(payload, schema)

    errors = errors_basic + errors_schema
    if not (ok_basic and ok_schema):
        msg = f"Validation failed: {path}; errors={errors}"
        if strict:
            raise ValueError(msg)
        logging.warning(msg, extra={"event": "validation_failed", "path": str(path), "errors": errors})
        return None, errors

    rule = build_sigma_rule(payload, path=path, id_strategy=id_strategy)
    return rule, []


def atomic_write_text(path: Path, data: str, mode: str = "w", encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", delete=False, dir=str(path.parent), encoding=encoding) as tmp:
        tmp.write(data)
        tmppath = Path(tmp.name)
    tmppath.replace(path)


def open_atomic(path: Path, mode: str = "wb") -> io.BufferedWriter:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = tempfile.NamedTemporaryFile(delete=False, dir=str(path.parent))
    return tmp  # caller must replace


def write_jsonl_atomic(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    gz = str(path).endswith(".gz")
    if gz:
        with tempfile.NamedTemporaryFile(delete=False, dir=str(path.parent)) as tmp:
            tmppath = Path(tmp.name)
        with gzip.open(tmppath, "wt", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        tmppath.replace(path)
    else:
        with tempfile.NamedTemporaryFile("w", delete=False, dir=str(path.parent), encoding="utf-8") as tmp:
            for row in rows:
                tmp.write(json.dumps(row, ensure_ascii=False) + "\n")
            tmppath = Path(tmp.name)
        tmppath.replace(path)


def sqlite_connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def sqlite_init(conn: sqlite3.Connection) -> None:
    with conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS rules (
                rule_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                detection_json TEXT NOT NULL,
                logsource_json TEXT NOT NULL,
                status TEXT,
                description TEXT,
                level TEXT,
                tags_json TEXT NOT NULL,
                references_json TEXT NOT NULL,
                author TEXT,
                created TEXT,
                modified TEXT,
                falsepositives_json TEXT NOT NULL,
                file_path TEXT,
                file_hash TEXT,
                import_ts TEXT NOT NULL,
                sigma_id_source TEXT,
                raw_json TEXT NOT NULL
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rules_level ON rules(level);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rules_status ON rules(status);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rules_file_hash ON rules(file_hash);")
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?);", (str(SQLITE_SCHEMA_VERSION),))


def sqlite_insert_rules(conn: sqlite3.Connection, rules: Iterable[SigmaRule]) -> int:
    rows = [
        (
            r.rule_id,
            r.title,
            json.dumps(r.detection, ensure_ascii=False),
            json.dumps(r.logsource, ensure_ascii=False),
            r.status,
            r.description,
            r.level,
            json.dumps(list(r.tags), ensure_ascii=False),
            json.dumps(list(r.references), ensure_ascii=False),
            r.author,
            r.created,
            r.modified,
            json.dumps(list(r.falsepositives), ensure_ascii=False),
            r.file_path,
            r.file_hash,
            r.import_ts or iso_now(),
            r.sigma_id_source,
            json.dumps(r.raw, ensure_ascii=False),
        )
        for r in rules
    ]
    with _SQLITE_LOCK:
        with conn:
            cur = conn.executemany(
                """
                INSERT OR REPLACE INTO rules(
                    rule_id, title, detection_json, logsource_json, status, description, level,
                    tags_json, references_json, author, created, modified, falsepositives_json,
                    file_path, file_hash, import_ts, sigma_id_source, raw_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            return cur.rowcount or 0


def command_validate(args: argparse.Namespace) -> int:
    configure_logging(level=logging.DEBUG if args.verbose else logging.INFO, json_format=args.log_json)
    schema = None
    if args.schema:
        schema = load_schema_from_file(args.schema)
        logging.info("Loaded schema", extra={"event": "schema_loaded", "path": args.schema})

    files = list(iter_files(args.input, recursive=args.recursive))
    if not files:
        logging.warning("No files found", extra={"event": "no_files"})
        return 2

    logging.info("Validation started", extra={"event": "validation_start", "files": len(files)})

    errors_total = 0
    def _task(path: Path) -> Tuple[Path, List[str]]:
        try:
            content = read_text(path)
            payload = parse_sigma_yaml(content, path)
            ok_basic, errs_basic = validate_sigma_payload(payload)
            ok_schema, errs_schema = schema_validate_if_available(payload, schema)
            errs = []
            if not ok_basic:
                errs.extend(errs_basic)
            if not ok_schema:
                errs.extend(errs_schema)
            return path, errs
        except Exception as exc:
            return path, [f"Unhandled: {exc}"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(_task, f) for f in files]
        for fut in concurrent.futures.as_completed(futs):
            p, errs = fut.result()
            if errs:
                errors_total += 1
                logging.error(
                    "Validation errors",
                    extra={"event": "file_invalid", "path": str(p), "errors": errs},
                )
            else:
                logging.info("Valid", extra={"event": "file_valid", "path": str(p)})

    if errors_total == 0:
        logging.info("All files valid", extra={"event": "validation_ok", "files": len(files)})
        return 0
    else:
        logging.warning("Validation completed with errors", extra={"event": "validation_errors", "error_files": errors_total, "files": len(files)})
        return 1


def command_import(args: argparse.Namespace) -> int:
    configure_logging(level=logging.DEBUG if args.verbose else logging.INFO, json_format=args.log_json)
    schema = None
    if args.schema:
        schema = load_schema_from_file(args.schema)
        logging.info("Loaded schema", extra={"event": "schema_loaded", "path": args.schema})

    files = list(iter_files(args.input, recursive=args.recursive))
    if not files:
        logging.warning("No files found", extra={"event": "no_files"})
        return 2

    logging.info("Import started", extra={"event": "import_start", "files": len(files), "output": args.output, "format": args.format})

    rules: List[SigmaRule] = []
    errors_count = 0
    seen_ids: Set[str] = set()

    def _task(path: Path) -> Tuple[Optional[SigmaRule], List[str]]:
        return process_file(path, strict=args.strict, schema=schema, id_strategy=args.id_strategy)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(_task, f) for f in files]
        for fut in concurrent.futures.as_completed(futs):
            try:
                rule, errs = fut.result()
            except Exception as exc:
                errs = [f"Unhandled exception: {exc}"]
                rule = None
            if errs:
                errors_count += 1
            if rule:
                if rule.rule_id in seen_ids:
                    logging.info(
                        "Duplicate rule skipped",
                        extra={"event": "duplicate_rule", "rule_id": rule.rule_id, "path": rule.file_path},
                    )
                    continue
                seen_ids.add(rule.rule_id)
                rules.append(rule)
                logging.debug(
                    "Rule accepted",
                    extra={"event": "rule_ok", "rule_id": rule.rule_id, "path": rule.file_path},
                )

    # Output
    out_path = Path(args.output)

    if args.format == "jsonl":
        rows = (r.to_serializable() for r in rules)
        write_jsonl_atomic(out_path, rows)
        logging.info(
            "JSONL written",
            extra={"event": "jsonl_written", "path": str(out_path), "rules": len(rules)},
        )
    elif args.format == "sqlite":
        conn = sqlite_connect(out_path)
        try:
            sqlite_init(conn)
            inserted = sqlite_insert_rules(conn, rules)
            logging.info(
                "SQLite updated",
                extra={"event": "sqlite_written", "path": str(out_path), "inserted": inserted, "rules": len(rules)},
            )
        finally:
            conn.close()
    else:
        logging.error("Unsupported format", extra={"event": "unsupported_format", "format": args.format})
        return 2

    logging.info(
        "Import completed",
        extra={
            "event": "import_done",
            "rules": len(rules),
            "errors": errors_count,
            "deduplicated": len(files) - len(rules),
            "output": str(out_path),
            "format": args.format,
        },
    )
    return 0 if (rules and errors_count == 0) or (rules and not args.strict) else (1 if errors_count else 0)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=APP_NAME,
        description="Validate and import Sigma YAML rules to JSONL or SQLite.",
    )

    sub = p.add_subparsers(dest="command", required=True)

    base = argparse.ArgumentParser(add_help=False)
    base.add_argument("-i", "--input", nargs="+", required=True, help="Files, directories, or glob patterns to read")
    base.add_argument("-r", "--recursive", action="store_true", help="Recurse into directories")
    base.add_argument("--workers", type=int, default=min(8, (os.cpu_count() or 4) * 2), help="Parallel workers for parsing")
    base.add_argument("--schema", type=str, default=None, help="Path to JSON schema for Sigma (optional)")
    base.add_argument("--id-strategy", choices=("hash", "uuid", "sigma_id"), default="hash", help="Rule identity strategy")
    base.add_argument("--strict", action="store_true", help="Fail on first parse/validation error")
    base.add_argument("--verbose", action="store_true", help="Verbose logging")
    base.add_argument("--log-json", action="store_true", help="Log in JSON format")

    p_validate = sub.add_parser("validate", parents=[base], help="Validate Sigma rules")
    p_validate.set_defaults(func=command_validate)

    p_import = sub.add_parser("import", parents=[base], help="Import Sigma rules to storage")
    p_import.add_argument("-o", "--output", required=True, help="Output path to JSONL or SQLite db")
    p_import.add_argument("--format", choices=SUPPORTED_OUT_FORMATS, default=None, help="Output format (jsonl or sqlite). If omitted, inferred from path")
    p_import.set_defaults(func=command_import)

    return p


def infer_format_from_output(path: str) -> str:
    if path.endswith(".db") or path.endswith(".sqlite") or path.endswith(".sqlite3"):
        return "sqlite"
    return "jsonl"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if getattr(args, "format", None) is None and getattr(args, "output", None):
        fmt = infer_format_from_output(args.output)
        setattr(args, "format", fmt)

    try:
        return args.func(args)  # type: ignore[attr-defined]
    except KeyboardInterrupt:
        logging.error("Interrupted", extra={"event": "keyboard_interrupt"})
        return 130
    except Exception as exc:
        logging.error(
            "Fatal error",
            extra={
                "event": "fatal",
                "error": str(exc),
                "traceback": traceback.format_exc(limit=3),
            },
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
