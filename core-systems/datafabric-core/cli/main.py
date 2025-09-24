#!/usr/bin/env python3
# datafabric/cli/main.py
# Industrial CLI for DataFabric Core
# Stdlib-only. Provides subcommands: catalog, dq, security, bus, transforms, config.
# Safe lazy-imports of internal modules. JSON/human logs. Strict exit codes.

from __future__ import annotations

import argparse
import contextlib
import importlib
import json
import os
import signal
import sys
import textwrap
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

APP_NAME = "datafabric"
DEFAULT_CONFIG_ENV = "DATAFABRIC_CONFIG"
DEFAULT_TIMEOUT_ENV = "DATAFABRIC_TIMEOUT_SECONDS"
DEFAULT_TIMEOUT = 600

# -----------------------------
# Exit codes (stable contract)
# -----------------------------
class Exit:
    OK = 0
    CONFIG = 10
    USAGE = 11
    NOT_FOUND = 12
    ACCESS = 13
    CONFLICT = 14
    BACKEND = 15
    TIMEOUT = 16
    INTERRUPTED = 17
    UNKNOWN = 19

# -----------------------------
# Logging (human/JSON)
# -----------------------------
def is_tty() -> bool:
    try:
        return sys.stderr.isatty()
    except Exception:
        return False

def _ansi(level: str) -> str:
    if not is_tty():
        return ""
    colors = {
        "INFO": "\033[36m",   # cyan
        "WARN": "\033[33m",   # yellow
        "ERROR": "\033[31m",  # red
        "RESET": "\033[0m",
    }
    return colors.get(level, "")

def log(level: str, message: str, **kwargs) -> None:
    mode = _LogCtx.mode
    rec = {"level": level, "message": message, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    if kwargs:
        rec.update(kwargs)
    if mode == "json":
        sys.stderr.write(json.dumps(rec, ensure_ascii=False) + "\n")
    else:
        color = _ansi(level)
        reset = _ansi("RESET")
        extra = " ".join(f"{k}={json.dumps(v, ensure_ascii=False)}" for k, v in kwargs.items())
        sys.stderr.write(f"{color}[{level}] {message}{reset}" + (f" {extra}" if extra else "") + "\n")
    sys.stderr.flush()

class _LogCtx:
    mode = "human"  # or "json"

# -----------------------------
# Configuration loader
# -----------------------------
@dataclass
class AppConfig:
    # минимальный набор; можно расширять конфигом модулей
    profile: str = "default"
    # пример для backend’ов
    metadata_backend: str = "memory"
    bus_backend: str = "memory"

def load_config(path: Optional[str]) -> Tuple[AppConfig, Dict[str, Any]]:
    # порядок: явный путь -> ENV -> ~/.config/datafabric/config.json
    candidates = []
    if path:
        candidates.append(Path(path))
    elif os.getenv(DEFAULT_CONFIG_ENV):
        candidates.append(Path(os.environ[DEFAULT_CONFIG_ENV]))
    else:
        candidates.append(Path.home() / ".config" / APP_NAME / "config.json")

    raw: Dict[str, Any] = {}
    for p in candidates:
        try:
            if p.exists():
                raw = json.loads(p.read_text(encoding="utf-8"))
                break
        except Exception as e:
            log("ERROR", "Failed to read config", path=str(p), error=str(e))
            raise

    # ENV overrides (flat)
    overrides = {}
    for k, v in os.environ.items():
        if not k.startswith("DATAFABRIC_"):
            continue
        key = k[len("DATAFABRIC_") :].lower()
        # пропускаем служебные
        if key in ("config", "timeout_seconds"):
            continue
        overrides[key] = v

    merged = {**raw, **overrides}
    cfg = AppConfig(**{k: merged.get(k, getattr(AppConfig, k)) for k in AppConfig.__annotations__.keys()})
    return cfg, merged

# -----------------------------
# Utilities
# -----------------------------
def lazy_import(dotted: str):
    try:
        return importlib.import_module(dotted)
    except Exception as e:
        log("ERROR", "Module import failed", module=dotted, error=str(e))
        sys.exit(Exit.BACKEND)

@contextlib.contextmanager
def deadline(seconds: int):
    timed_out = {"value": False}

    def _handler(signum, frame):
        timed_out["value"] = True
        raise TimeoutError("operation timed out")

    old = signal.signal(signal.SIGALRM, _handler)
    try:
        signal.alarm(max(1, seconds))
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)
        if timed_out["value"]:
            sys.exit(Exit.TIMEOUT)

def setup_signals():
    def _int_handler(signum, frame):
        log("WARN", "Interrupted by user", sig=signum)
        sys.exit(Exit.INTERRUPTED)
    signal.signal(signal.SIGINT, _int_handler)
    signal.signal(signal.SIGTERM, _int_handler)

def require_file(path: str) -> Path:
    p = Path(path)
    if not p.exists():
        log("ERROR", "File not found", path=str(p))
        sys.exit(Exit.NOT_FOUND)
    return p

# -----------------------------
# Command handlers
# -----------------------------
def cmd_config(args: argparse.Namespace) -> int:
    cfg, merged = load_config(args.path)
    if args.show_raw:
        print(json.dumps(merged, indent=2, ensure_ascii=False))
    else:
        print(json.dumps(asdict(cfg), indent=2, ensure_ascii=False))
    return Exit.OK

def cmd_catalog(args: argparse.Namespace) -> int:
    mod = lazy_import("datafabric.metadata.catalog_service")
    CatalogService = getattr(mod, "CatalogService")
    SchemaDef = getattr(mod, "SchemaDef")
    ColumnDef = getattr(mod, "ColumnDef")
    PartitionDef = getattr(mod, "PartitionDef")

    svc = CatalogService()

    if args.action == "register":
        schema_dict = json.loads(Path(args.schema).read_text(encoding="utf-8")) if args.schema else {"columns": []}
        schema = SchemaDef(columns=[ColumnDef(**c) for c in schema_dict.get("columns", [])])
        ds = svc.register_dataset(
            actor=args.actor,
            name=args.name,
            layer=args.layer,
            system=args.system,
            path=args.path,
            schema=schema,
            description=args.description,
            tags=set(args.tag or []),
            owners=set(args.owner or []),
        )
        print(json.dumps(ds.__dict__, ensure_ascii=False, default=str))
        return Exit.OK

    if args.action == "get":
        ds = svc.get_dataset(actor=args.actor, dataset_id=args.id)
        print(json.dumps(ds.__dict__, ensure_ascii=False, default=str))
        return Exit.OK

    if args.action == "list":
        lst = svc.list_datasets(actor=args.actor, layer=args.layer, tag=args.tag, text=args.text, limit=args.limit, offset=args.offset, include_deleted=args.include_deleted)
        print(json.dumps([d.__dict__ for d in lst], ensure_ascii=False, default=str))
        return Exit.OK

    if args.action == "export":
        blob = svc.export_json(actor=args.actor, include_deleted=args.include_deleted)
        if args.out:
            Path(args.out).write_text(blob, encoding="utf-8")
        else:
            print(blob)
        return Exit.OK

    if args.action == "import":
        blob = require_file(args.file).read_text(encoding="utf-8")
        count = svc.import_json(actor=args.actor, blob=blob, overwrite=args.overwrite)
        print(json.dumps({"imported": count}, ensure_ascii=False))
        return Exit.OK

    log("ERROR", "Unsupported catalog action", action=args.action)
    return Exit.USAGE

def cmd_dq(args: argparse.Namespace) -> int:
    mod = lazy_import("datafabric.quality.expectations")
    (SuiteConfig, expect_schema, expect_not_null, expect_unique, run_suite, report_to_json) = (
        getattr(mod, "SuiteConfig"),
        getattr(mod, "expect_schema"),
        getattr(mod, "expect_not_null"),
        getattr(mod, "expect_unique"),
        getattr(mod, "run_suite"),
        getattr(mod, "report_to_json"),
    )

    # Для демонстрации: читаем входной DataFrame из Parquet/CSV опционально через PySpark, но импортируем лениво
    if args.input.endswith(".parquet") or args.input.endswith(".csv"):
        spark = None
        with contextlib.suppress(Exception):
            pyspark = importlib.import_module("pyspark.sql")
            spark = pyspark.SparkSession.builder.appName(APP_NAME).getOrCreate()
        if spark is None:
            log("ERROR", "PySpark is required to read the dataset file")
            return Exit.BACKEND
        if args.input.endswith(".parquet"):
            df = spark.read.parquet(args.input)
        else:
            df = spark.read.option("header", "true").csv(args.input)
    else:
        log("ERROR", "Unsupported dataset format. Use CSV or Parquet.")
        return Exit.USAGE

    suite = SuiteConfig(
        expectations=[
            expect_schema(json.loads(args.schema)) if args.schema else expect_schema({}, unknown_ok=True),
        ],
        fail_fast=args.fail_fast,
        dataset_metrics=True,
    )
    if args.require_not_null:
        suite.expectations.append(expect_not_null(args.require_not_null.split(",")))
    if args.unique:
        suite.expectations.append(expect_unique(args.unique.split(","), allow_nulls=False))

    report = run_suite(df, suite)
    print(report_to_json(report))
    return Exit.OK if report.success else Exit.CONFLICT

def cmd_security(args: argparse.Namespace) -> int:
    mod = lazy_import("datafabric.security.key_rotation")
    (KeyRotationService, RotationPolicy) = (getattr(mod, "KeyRotationService"), getattr(mod, "RotationPolicy"))
    svc = KeyRotationService()

    if args.action == "create":
        pol = RotationPolicy()
        mk = svc.create_master(actor=args.actor, name=args.name, policy=pol, owners=args.owner, approvers_required=args.approvers)
        print(json.dumps(mk.__dict__, ensure_ascii=False, default=str))
        return Exit.OK

    if args.action == "rotate":
        mk = svc.rotate_now(actor=args.actor, key_id=args.id)
        print(json.dumps({"key_id": mk.key_id, "versions": [v.__dict__ for v in mk.versions]}, ensure_ascii=False, default=str))
        return Exit.OK

    if args.action == "activate":
        req = svc.request_activate(actor=args.actor, key_id=args.id, version_id=args.version)
        # имитируем второй апрув, если указан через --approve-as
        if args.approve_as:
            svc.approve(actor=args.approve_as, key_id=args.id, op_id=req)
        mk = svc.activate_version(actor=args.actor, key_id=args.id, version_id=args.version)
        print(json.dumps({"key_id": mk.key_id, "active_version": mk.active_version_id}, ensure_ascii=False))
        return Exit.OK

    if args.action == "rewrap":
        res = svc.rewrap_envelopes(actor=args.actor, key_id=args.id, target_version_id=args.version, batch_limit=args.batch)
        print(json.dumps(res, ensure_ascii=False))
        return Exit.OK

    log("ERROR", "Unsupported security action", action=args.action)
    return Exit.USAGE

def cmd_bus(args: argparse.Namespace) -> int:
    mod = lazy_import("datafabric.io.bus")
    (EventBus, Message, Ack) = (getattr(mod, "EventBus"), getattr(mod, "Message"), getattr(mod, "Ack"))

    bus = EventBus()
    bus.set_acl(args.topic, producers={"*"}, consumers={"*"})
    if args.mode == "publish":
        env = bus.publish(producer=args.producer, message=Message(topic=args.topic, headers={"type": args.type}, payload=json.loads(args.payload)), idempotency_key=args.idem)
        print(json.dumps({"message_id": env.message_id, "trace_id": env.trace_id}, ensure_ascii=False))
        return Exit.OK

    if args.mode == "consume":
        def handler(env):
            # для демо печатаем и подтверждаем
            print(json.dumps({"message_id": env.message_id, "payload": env.message.payload}, ensure_ascii=False))
            return Ack.ACK
        bus.subscribe(consumer=args.consumer, topic=args.topic, group=args.group, fn=handler)
        bus.start(workers_per_topic=1)
        # простой рабочий цикл с таймаутом
        timeout = int(os.getenv(DEFAULT_TIMEOUT_ENV, str(DEFAULT_TIMEOUT)))
        with deadline(timeout):
            while True:
                time.sleep(0.25)

    log("ERROR", "Unsupported bus mode", mode=args.mode)
    return Exit.USAGE

def cmd_transforms(args: argparse.Namespace) -> int:
    if args.op == "dedup":
        mod = lazy_import("datafabric.processing.transforms.dedup")
        (deduplicate, DedupConfig, OrderBy) = (getattr(mod, "deduplicate"), getattr(mod, "DedupConfig"), getattr(mod, "OrderBy"))

        # Читаем входные данные Spark (CSV/Parquet)
        try:
            pyspark = importlib.import_module("pyspark.sql")
            spark = pyspark.SparkSession.builder.appName(APP_NAME).getOrCreate()
        except Exception:
            log("ERROR", "PySpark is required for transforms")
            return Exit.BACKEND

        if args.input.endswith(".parquet"):
            df = spark.read.parquet(args.input)
        else:
            df = spark.read.option("header", "true").csv(args.input)

        cfg = DedupConfig(
            keys=args.keys.split(","),
            order_by=[OrderBy(col=c, dir="desc", nulls="nulls_last") for c in (args.order_by.split(",") if args.order_by else [])],
            canonicalize_strings=not args.no_canon,
            to_lower=args.to_lower,
            collapse_spaces=not args.no_collapse,
            final_tiebreaker_cols=(args.tiebreakers.split(",") if args.tiebreakers else []),
            repartition_by_keys=args.repartition,
            sample_groups_n=args.sample,
        )
        winners, metrics = deduplicate(df, cfg)
        if args.output:
            winners.write.mode("overwrite").parquet(args.output) if args.output.endswith(".parquet") else winners.write.mode("overwrite").csv(args.output, header=True)
        print(json.dumps(metrics, ensure_ascii=False))
        return Exit.OK

    log("ERROR", "Unsupported transforms operation", op=args.op)
    return Exit.USAGE

# -----------------------------
# Argument parser
# -----------------------------
def build_parser() -> argparse.ArgumentParser:
    desc = f"""{APP_NAME}: DataFabric command-line interface
Examples:
  {APP_NAME} catalog register --actor alice --name orders --layer curated --schema schema.json
  {APP_NAME} dq run --input data.parquet --schema '{{"order_id":"long"}}'
  {APP_NAME} security create --actor alice --name df-master --owner alice --owner bob --approvers 2
  {APP_NAME} bus publish --topic dq.events --producer dq --type report --payload '{{"ok":1}}'
  {APP_NAME} transforms dedup --input data.parquet --keys user_id,event_id --order-by event_ts
"""
    parser = argparse.ArgumentParser(prog=APP_NAME, description=desc, formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument("--config", dest="config", default=None, help="Path to config JSON (overrides ENV)")
    parser.add_argument("--log-json", dest="log_json", action="store_true", help="Enable JSON logging to stderr")
    parser.add_argument("--timeout", dest="timeout", type=int, default=int(os.getenv(DEFAULT_TIMEOUT_ENV, str(DEFAULT_TIMEOUT))), help="Global timeout seconds")
    parser.add_argument("--version", action="version", version="datafabric-cli 1.0.0")

    sub = parser.add_subparsers(dest="cmd", required=True)

    # config
    p_cfg = sub.add_parser("config", help="Show effective configuration")
    p_cfg.add_argument("--path", default=None, help="Config path (default: env or ~/.config/datafabric/config.json)")
    p_cfg.add_argument("--show-raw", action="store_true", help="Print full merged config")
    p_cfg.set_defaults(func=cmd_config)

    # catalog
    p_cat = sub.add_parser("catalog", help="Metadata catalog operations")
    cat_sub = p_cat.add_subparsers(dest="action", required=True)

    cat_reg = cat_sub.add_parser("register", help="Register dataset")
    cat_reg.add_argument("--actor", required=True)
    cat_reg.add_argument("--name", required=True)
    cat_reg.add_argument("--layer", required=True, choices=["raw", "staging", "curated", "mart"])
    cat_reg.add_argument("--system", default=None)
    cat_reg.add_argument("--path", default=None)
    cat_reg.add_argument("--schema", default=None, help="Path to schema JSON with 'columns'")
    cat_reg.add_argument("--description", default=None)
    cat_reg.add_argument("--tag", action="append")
    cat_reg.add_argument("--owner", action="append")
    cat_reg.set_defaults(func=cmd_catalog)

    cat_get = cat_sub.add_parser("get", help="Get dataset by id")
    cat_get.add_argument("--actor", required=True)
    cat_get.add_argument("--id", required=True)
    cat_get.set_defaults(func=cmd_catalog)

    cat_list = cat_sub.add_parser("list", help="List datasets")
    cat_list.add_argument("--actor", required=True)
    cat_list.add_argument("--layer", default=None)
    cat_list.add_argument("--tag", default=None)
    cat_list.add_argument("--text", default=None)
    cat_list.add_argument("--limit", type=int, default=100)
    cat_list.add_argument("--offset", type=int, default=0)
    cat_list.add_argument("--include-deleted", action="store_true")
    cat_list.set_defaults(func=cmd_catalog)

    cat_exp = cat_sub.add_parser("export", help="Export catalog to JSON")
    cat_exp.add_argument("--actor", required=True)
    cat_exp.add_argument("--out", default=None)
    cat_exp.add_argument("--include-deleted", action="store_true")
    cat_exp.set_defaults(func=cmd_catalog)

    cat_imp = cat_sub.add_parser("import", help="Import catalog from JSON")
    cat_imp.add_argument("--actor", required=True)
    cat_imp.add_argument("--file", required=True)
    cat_imp.add_argument("--overwrite", action="store_true")
    cat_imp.set_defaults(func=cmd_catalog)

    # dq
    p_dq = sub.add_parser("dq", help="Data quality checks")
    dq_sub = p_dq.add_subparsers(dest="action", required=True)
    dq_run = dq_sub.add_parser("run", help="Run DQ suite on a dataset file (CSV/Parquet via PySpark)")
    dq_run.add_argument("--input", required=True)
    dq_run.add_argument("--schema", default=None, help="JSON string with required columns & types (pass as string)")
    dq_run.add_argument("--require-not-null", default=None, help="Comma-separated columns")
    dq_run.add_argument("--unique", default=None, help="Comma-separated columns")
    dq_run.add_argument("--fail-fast", action="store_true")
    dq_run.set_defaults(func=cmd_dq)

    # security
    p_sec = sub.add_parser("security", help="Key rotation operations")
    sec_sub = p_sec.add_subparsers(dest="action", required=True)

    sec_create = sec_sub.add_parser("create", help="Create master key record")
    sec_create.add_argument("--actor", required=True)
    sec_create.add_argument("--name", required=True)
    sec_create.add_argument("--owner", action="append", required=True)
    sec_create.add_argument("--approvers", type=int, default=2)
    sec_create.set_defaults(func=cmd_security)

    sec_rotate = sec_sub.add_parser("rotate", help="Create a new key version (pending)")
    sec_rotate.add_argument("--actor", required=True)
    sec_rotate.add_argument("--id", required=True)
    sec_rotate.set_defaults(func=cmd_security)

    sec_activate = sec_sub.add_parser("activate", help="Activate key version (requires approvals)")
    sec_activate.add_argument("--actor", required=True)
    sec_activate.add_argument("--id", required=True)
    sec_activate.add_argument("--version", required=True)
    sec_activate.add_argument("--approve-as", default=None, help="Optional second approver for demo")
    sec_activate.set_defaults(func=cmd_security)

    sec_rewrap = sec_sub.add_parser("rewrap", help="Rewrap envelopes to target version (demo)")
    sec_rewrap.add_argument("--actor", required=True)
    sec_rewrap.add_argument("--id", required=True)
    sec_rewrap.add_argument("--version", required=True)
    sec_rewrap.add_argument("--batch", type=int, default=1000)
    sec_rewrap.set_defaults(func=cmd_security)

    # bus
    p_bus = sub.add_parser("bus", help="Application event bus")
    p_bus.add_argument("--topic", required=True)
    bus_sub = p_bus.add_subparsers(dest="mode", required=True)

    bus_pub = bus_sub.add_parser("publish", help="Publish a message")
    bus_pub.add_argument("--producer", required=True)
    bus_pub.add_argument("--type", required=True)
    bus_pub.add_argument("--payload", required=True, help="JSON string")
    bus_pub.add_argument("--idem", default=None, help="Idempotency key")
    bus_pub.set_defaults(func=cmd_bus)

    bus_cons = bus_sub.add_parser("consume", help="Consume messages")
    bus_cons.add_argument("--consumer", required=True)
    bus_cons.add_argument("--group", required=True)
    bus_cons.set_defaults(func=cmd_bus)

    # transforms
    p_tr = sub.add_parser("transforms", help="Local transforms (PySpark)")
    tr_sub = p_tr.add_subparsers(dest="op", required=True)
    tr_dedup = tr_sub.add_parser("dedup", help="Deterministic deduplication")
    tr_dedup.add_argument("--input", required=True)
    tr_dedup.add_argument("--output", default=None)
    tr_dedup.add_argument("--keys", required=True, help="Comma-separated keys")
    tr_dedup.add_argument("--order-by", default=None, help="Comma-separated priority columns")
    tr_dedup.add_argument("--tiebreakers", default=None)
    tr_dedup.add_argument("--no-canon", action="store_true")
    tr_dedup.add_argument("--to-lower", action="store_true")
    tr_dedup.add_argument("--no-collapse", action="store_true")
    tr_dedup.add_argument("--repartition", type=int, default=None)
    tr_dedup.add_argument("--sample", type=int, default=5)
    tr_dedup.set_defaults(func=cmd_transforms)

    return parser

# -----------------------------
# Main
# -----------------------------
def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    _LogCtx.mode = "json" if args.log_json else "human"
    setup_signals()

    # Load config early (even if not used by all subcommands) for uniformity
    try:
        cfg, _ = load_config(args.config)
        log("INFO", "Config loaded", profile=cfg.profile)
    except Exception as e:
        log("ERROR", "Config error", error=str(e))
        return Exit.CONFIG

    try:
        with deadline(int(args.timeout)):
            return args.func(args)
    except SystemExit as se:
        # argparse or explicit exits
        code = int(se.code) if isinstance(se.code, int) else Exit.UNKNOWN
        return code
    except TimeoutError:
        return Exit.TIMEOUT
    except KeyboardInterrupt:
        return Exit.INTERRUPTED
    except Exception as e:
        # Best-effort error classification (based on message)
        msg = str(e)
        if "NotFound" in msg or "not found" in msg:
            log("ERROR", "Not found", error=msg)
            return Exit.NOT_FOUND
        if "AccessDenied" in msg or "denied" in msg:
            log("ERROR", "Access denied", error=msg)
            return Exit.ACCESS
        if "Conflict" in msg or "etag" in msg:
            log("ERROR", "Conflict", error=msg)
            return Exit.CONFLICT
        if "ProviderError" in msg or "Backend" in msg:
            log("ERROR", "Backend error", error=msg)
            return Exit.BACKEND
        log("ERROR", "Unhandled exception", error=msg)
        return Exit.UNKNOWN

if __name__ == "__main__":
    sys.exit(main())
