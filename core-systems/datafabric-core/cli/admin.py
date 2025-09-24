# -*- coding: utf-8 -*-
"""
DataFabric | CLI Admin Tool

Промышленный CLI для администрирования подсистем DataFabric:
- health/version
- config validate
- schema registry: list/register/test/export/import
- udf registry: list
- quality profiler: profile
- io streams: copy
- signature: create/verify

Зависимости: стандартная библиотека + внутренние модули DataFabric.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from dataclasses import asdict, is_dataclass
from typing import Any, Dict, Iterable, List, Tuple

# Внутренние модули (опциональны в окружении, ошибки — в рантайме при вызове команд)
# metadata
try:
    from datafabric.metadata.schema_registry import (
        SchemaRegistry,
        SchemaType,
        Compatibility,
        SchemaReference,
        normalize_and_fingerprint,
    )
except Exception:  # модуль может отсутствовать в окружении
    SchemaRegistry = None  # type: ignore

# udf
try:
    from datafabric.processing.udf.python_udf import _default_registry as udf_registry  # type: ignore
except Exception:
    udf_registry = None

# quality
try:
    from datafabric.quality.profiler import DataProfiler, ProfilerConfig  # type: ignore
except Exception:
    DataProfiler = None  # type: ignore
    ProfilerConfig = None  # type: ignore

# io streams
try:
    from datafabric.io.streams import (
        copy_file_to_file,
        StreamConfig,
    )  # type: ignore
except Exception:
    copy_file_to_file = None  # type: ignore
    StreamConfig = None  # type: ignore

# security/signature
try:
    from datafabric.security.signature import (
        create_detached_signature,
        verify_detached_signature,
        create_envelope,
        verify_envelope,
        KeyRef,
        SigAlg,
        DigestAlg,
    )  # type: ignore
except Exception:
    create_detached_signature = None  # type: ignore
    verify_detached_signature = None  # type: ignore
    create_envelope = None  # type: ignore
    verify_envelope = None  # type: ignore
    KeyRef = None  # type: ignore
    SigAlg = None  # type: ignore
    DigestAlg = None  # type: ignore


LOG = logging.getLogger("datafabric.cli")

# -------------------------------
# Общие утилиты
# -------------------------------

def setup_logging(verbosity: int, as_json: bool) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    handler = logging.StreamHandler(sys.stderr)
    if as_json:
        fmt = '{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}'
    else:
        fmt = "%(asctime)s %(levelname)s %(name)s %(message)s"
    handler.setFormatter(logging.Formatter(fmt))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)


def _json_default(o: Any) -> Any:
    if is_dataclass(o):
        return asdict(o)
    if isinstance(o, (set,)):
        return sorted(list(o))
    # объекты DataFabric с .to_dict()
    to_dict = getattr(o, "to_dict", None)
    if callable(to_dict):
        return o.to_dict()
    return repr(o)


def emit(payload: Any, as_json: bool) -> None:
    if as_json:
        sys.stdout.write(json.dumps(payload, ensure_ascii=False, sort_keys=True, default=_json_default) + "\n")
    else:
        if isinstance(payload, (dict, list, tuple)):
            sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2, default=_json_default) + "\n")
        else:
            sys.stdout.write(str(payload) + "\n")
    sys.stdout.flush()


def die(msg: str, code: int = 1, as_json: bool = False) -> None:
    if as_json:
        emit({"ok": False, "error": msg}, True)
    else:
        sys.stderr.write(f"ERROR: {msg}\n")
        sys.stderr.flush()
    sys.exit(code)


def read_all_stdin() -> bytes:
    data = sys.stdin.buffer.read()
    return data


# -------------------------------
# Команды: health / version
# -------------------------------

def cmd_health(args: argparse.Namespace) -> None:
    # Простая диагностика наличия внутренних модулей
    checks = {
        "schema_registry": SchemaRegistry is not None,
        "udf_registry": udf_registry is not None,
        "quality_profiler": DataProfiler is not None,
        "io_streams": copy_file_to_file is not None and StreamConfig is not None,
        "security_signature": create_detached_signature is not None,
    }
    ok = all(checks.values())
    out = {"ok": ok, "components": checks, "ts": int(time.time())}
    emit(out, args.json)
    sys.exit(0 if ok else 2)


def cmd_version(args: argparse.Namespace) -> None:
    info = {
        "app": "datafabric-admin",
        "version": "1.0.0",
        "python": sys.version.split()[0],
        "platform": sys.platform,
    }
    emit(info, args.json)


# -------------------------------
# Команды: config
# -------------------------------

def cmd_config_validate(args: argparse.Namespace) -> None:
    # В этой заготовке просто проверяем, что JSON корректен
    try:
        if args.path == "-":
            data = read_all_stdin()
        else:
            with open(args.path, "rb") as f:
                data = f.read()
        obj = json.loads(data.decode("utf-8"))
        emit({"ok": True, "keys": list(obj.keys()) if isinstance(obj, dict) else None}, args.json)
    except Exception as e:
        die(f"invalid config: {e}", 3, args.json)


# -------------------------------
# Команды: schema registry
# -------------------------------

def _ensure_schema_registry() -> "SchemaRegistry":
    if SchemaRegistry is None:
        die("SchemaRegistry module is unavailable", 10, False)
    return SchemaRegistry()  # type: ignore


def cmd_schema_list(args: argparse.Namespace) -> None:
    reg = _ensure_schema_registry()
    subs = reg.list_subjects()
    result: Dict[str, List[int]] = {}
    for s in subs:
        result[s] = reg.list_versions(s)
    emit({"subjects": result}, args.json)


def cmd_schema_register(args: argparse.Namespace) -> None:
    reg = _ensure_schema_registry()
    path = args.path
    schema_str = sys.stdin.read() if path == "-" else open(path, "r", encoding="utf-8").read()
    stype = SchemaType.JSON_SCHEMA if args.type.lower() == "json" else SchemaType.AVRO
    refs: List[SchemaReference] = []
    for r in args.ref or []:
        subj, ver = r.split("@", 1)
        refs.append(SchemaReference(subject=subj, version=int(ver)))
    try:
        entry = reg.register_schema(
            subject=args.subject,
            schema_str=schema_str,
            schema_type=stype,
            references=refs,
            metadata={"source": "cli"},
            trace="cli",
        )
        emit({"ok": True, "id": entry.id, "subject": entry.subject, "version": entry.version}, args.json)
    except Exception as e:
        die(f"register failed: {e}", 11, args.json)


def cmd_schema_test(args: argparse.Namespace) -> None:
    reg = _ensure_schema_registry()
    schema_str = sys.stdin.read() if args.path == "-" else open(args.path, "r", encoding="utf-8").read()
    stype = SchemaType.JSON_SCHEMA if args.type.lower() == "json" else SchemaType.AVRO
    try:
        ok = reg.test_compatibility(args.subject, schema_str, stype, level=Compatibility(args.level))
        emit({"ok": bool(ok)}, args.json)
        sys.exit(0 if ok else 12)
    except Exception as e:
        die(f"compatibility test failed: {e}", 12, args.json)


def cmd_schema_export(args: argparse.Namespace) -> None:
    reg = _ensure_schema_registry()
    snap = reg.snapshot_export()
    if args.out == "-":
        emit(snap, True)
    else:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(snap, f, ensure_ascii=False, indent=2, sort_keys=True)
        emit({"ok": True, "path": args.out}, args.json)


def cmd_schema_import(args: argparse.Namespace) -> None:
    reg = _ensure_schema_registry()
    snap = json.load(sys.stdin) if args.path == "-" else json.load(open(args.path, "r", encoding="utf-8"))
    try:
        reg.snapshot_import(snap)
        emit({"ok": True}, args.json)
    except Exception as e:
        die(f"import failed: {e}", 13, args.json)


# -------------------------------
# Команды: udf registry
# -------------------------------

def cmd_udf_list(args: argparse.Namespace) -> None:
    if udf_registry is None:
        die("UDF registry is unavailable", 20, args.json)
    listing = udf_registry.list()  # type: ignore
    emit({"udf": listing}, args.json)


# -------------------------------
# Команды: quality profiler
# -------------------------------

def cmd_quality_profile(args: argparse.Namespace) -> None:
    if DataProfiler is None or ProfilerConfig is None:
        die("Quality profiler is unavailable", 30, args.json)
    cfg = ProfilerConfig(
        max_rows=args.max_rows,
        timeout_sec=args.timeout,
        reservoir_size=args.reservoir,
        histogram_bins=args.bins,
        hll_precision_p=args.hll_p,
        topk_k=args.topk,
    )
    src = args.path
    profile = DataProfiler(cfg).profile(src if src != "-" else [])
    # Приводим к json‑дружественному виду
    out = {
        "rows": profile.n_rows_scanned,
        "cols": profile.n_cols,
        "elapsed_sec": profile.elapsed_sec,
        "truncated": profile.truncated,
        "timed_out": profile.timed_out,
        "columns": [
            {
                "name": c.name,
                "type": c.col_type.base,
                "count": c.count,
                "nulls": c.nulls,
                "min": c.min,
                "max": c.max,
                "mean": c.mean,
                "stddev": c.stddev,
                "distinct_estimate": c.distinct_estimate,
                "p50": c.p50,
                "topk": c.topk[: min(len(c.topk), 10)],
            }
            for c in profile.columns
        ],
    }
    emit(out, args.json)


# -------------------------------
# Команды: io streams
# -------------------------------

def cmd_io_copy(args: argparse.Namespace) -> None:
    if copy_file_to_file is None or StreamConfig is None:
        die("IO streams are unavailable", 40, args.json)
    cfg = StreamConfig(
        chunk_size=args.chunk,
        retries=args.retries,
        retry_backoff_base=args.backoff,
        compress=args.compress,
        checksum=not args.no_checksum,
        digest_alg=args.digest,
        rate_limit_bytes_per_sec=args.rate,
        timeout_sec=args.timeout,
    )
    try:
        manifest = copy_file_to_file(args.src, args.dst, cfg=cfg)
        emit(asdict(manifest), args.json)
    except Exception as e:
        die(f"copy failed: {e}", 41, args.json)


# -------------------------------
# Команды: signature
# -------------------------------

def _ensure_sig_available() -> None:
    if any(x is None for x in [create_detached_signature, verify_detached_signature, create_envelope, verify_envelope, KeyRef, SigAlg, DigestAlg]):
        die("Signature module is unavailable", 50, False)

def _keyref_from_args(args: argparse.Namespace, need_private: bool) -> "KeyRef":
    kid = args.kid or "cli"
    if args.hmac_secret:
        return KeyRef(kid=kid, secret=args.hmac_secret.encode("utf-8"))  # type: ignore
    if args.pem_private and need_private:
        return KeyRef(kid=kid, private_pem=open(args.pem_private, "rb").read())  # type: ignore
    if args.pem_public and not need_private:
        return KeyRef(kid=kid, public_pem=open(args.pem_public, "rb").read())  # type: ignore
    die("key material is missing or incompatible with operation", 51, False)
    raise RuntimeError()

def cmd_sign_create(args: argparse.Namespace) -> None:
    _ensure_sig_available()
    alg = SigAlg[args.alg]
    dig = DigestAlg[args.digest]
    key = _keyref_from_args(args, need_private=True)
    payload: Any
    if args.path == "-":
        payload = sys.stdin.buffer.read()
    else:
        payload = open(args.path, "rb").read()
    if args.envelope:
        env = create_envelope(payload, key=key, alg=alg, digest_alg=dig, meta={"source": "cli"})  # type: ignore
        emit({"ok": True, "envelope": env}, args.json)
    else:
        sig = create_detached_signature(payload, key=key, alg=alg, digest_alg=dig)  # type: ignore
        emit({"ok": True, "signature": sig}, args.json)

def cmd_sign_verify(args: argparse.Namespace) -> None:
    _ensure_sig_available()
    if args.envelope:
        env = json.load(sys.stdin if args.path == "-" else open(args.path, "r", encoding="utf-8"))
        pub = _keyref_from_args(args, need_private=False)
        ok, reason, data = verify_envelope(env, public_key=pub, max_skew_sec=args.max_skew)  # type: ignore
        emit({"ok": bool(ok), "reason": reason, "payload_size": len(data)}, args.json)
        sys.exit(0 if ok else 52)
    else:
        payload = sys.stdin.buffer.read() if args.data == "-" else open(args.data, "rb").read()
        sig = json.load(sys.stdin if args.sig == "-" else open(args.sig, "r", encoding="utf-8"))
        pub = _keyref_from_args(args, need_private=False)
        ok, reason = verify_detached_signature(payload, signature_dict=sig, public_key=pub, max_skew_sec=args.max_skew)  # type: ignore
        emit({"ok": bool(ok), "reason": reason}, args.json)
        sys.exit(0 if ok else 52)


# -------------------------------
# Парсер аргументов
# -------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="datafabric-admin", description="DataFabric Administrative CLI")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("-v", "--verbose", action="count", default=0, help="verbosity (repeat for more)")
    sub = p.add_subparsers(dest="cmd", required=True)

    # health/version
    sp = sub.add_parser("health", help="health check of available components")
    sp.set_defaults(func=cmd_health)

    sp = sub.add_parser("version", help="show CLI version and runtime")
    sp.set_defaults(func=cmd_version)

    # config
    spc = sub.add_parser("config", help="config utilities")
    sc = spc.add_subparsers(dest="sub", required=True)
    v = sc.add_parser("validate", help="validate JSON config")
    v.add_argument("path", help="path to JSON or '-' for stdin")
    v.set_defaults(func=cmd_config_validate)

    # schema registry
    sreg = sub.add_parser("schema", help="schema registry operations")
    sr = sreg.add_subparsers(dest="sub", required=True)

    l = sr.add_parser("list", help="list subjects and versions")
    l.set_defaults(func=cmd_schema_list)

    r = sr.add_parser("register", help="register schema from file or stdin")
    r.add_argument("--subject", required=True, help="subject name")
    r.add_argument("--type", choices=["json", "avro"], default="json", help="schema type")
    r.add_argument("--ref", action="append", help="reference in form subject@version", default=[])
    r.add_argument("path", help="path to schema file or '-'")
    r.set_defaults(func=cmd_schema_register)

    t = sr.add_parser("test", help="test compatibility against latest")
    t.add_argument("--subject", required=True)
    t.add_argument("--type", choices=["json", "avro"], default="json")
    t.add_argument("--level", choices=[c.value for c in Compatibility], default=Compatibility.BACKWARD.value)
    t.add_argument("path", help="path to schema file or '-'")
    t.set_defaults(func=cmd_schema_test)

    ex = sr.add_parser("export", help="export registry snapshot to file or stdout")
    ex.add_argument("--out", default="-", help="output path or '-'")
    ex.set_defaults(func=cmd_schema_export)

    im = sr.add_parser("import", help="import registry snapshot from file or stdin")
    im.add_argument("path", help="path to snapshot file or '-'")
    im.set_defaults(func=cmd_schema_import)

    # udf
    u = sub.add_parser("udf", help="udf registry operations")
    us = u.add_subparsers(dest="sub", required=True)
    ul = us.add_parser("list", help="list UDFs and versions")
    ul.set_defaults(func=cmd_udf_list)

    # quality profiler
    q = sub.add_parser("quality", help="data quality utilities")
    qs = q.add_subparsers(dest="sub", required=True)
    qp = qs.add_parser("profile", help="profile CSV or DataFrame-compatible source (path to CSV)")
    qp.add_argument("path", help="path to CSV (use '-' to profile empty)")
    qp.add_argument("--max-rows", type=int, default=None)
    qp.add_argument("--timeout", type=float, default=None)
    qp.add_argument("--reservoir", type=int, default=50000)
    qp.add_argument("--bins", type=int, default=50)
    qp.add_argument("--hll-p", type=int, default=14)
    qp.add_argument("--topk", type=int, default=20)
    qp.set_defaults(func=cmd_quality_profile)

    # io streams
    io_ = sub.add_parser("io", help="streaming I/O utilities")
    ios = io_.add_subparsers(dest="sub", required=True)
    cp = ios.add_parser("copy", help="copy file to file using streaming with integrity")
    cp.add_argument("src", help="source path")
    cp.add_argument("dst", help="destination path")
    cp.add_argument("--chunk", type=int, default=1024 * 1024)
    cp.add_argument("--retries", type=int, default=3)
    cp.add_argument("--backoff", type=float, default=0.15)
    cp.add_argument("--compress", choices=["gzip", "auto", "none"], default="none")
    cp.add_argument("--no-checksum", action="store_true")
    cp.add_argument("--digest", choices=["sha256", "sha512"], default="sha256")
    cp.add_argument("--rate", type=int, default=None, help="bytes per second")
    cp.add_argument("--timeout", type=float, default=None)
    cp.set_defaults(func=cmd_io_copy)

    # signature
    s = sub.add_parser("sign", help="signing and verification")
    ss = s.add_subparsers(dest="sub", required=True)

    sc = ss.add_parser("create", help="create detached signature or envelope")
    sc.add_argument("--alg", choices=["ED25519", "ECDSA_P256_SHA256", "RSA_PSS_SHA256", "HMAC_SHA256"], default="ED25519")
    sc.add_argument("--digest", choices=["SHA256", "SHA512"], default="SHA256")
    sc.add_argument("--kid", default=None)
    sc.add_argument("--pem-private", default=None, help="PEM private key for asymmetric")
    sc.add_argument("--hmac-secret", default=None, help="secret for HMAC")
    sc.add_argument("--envelope", action="store_true", help="create envelope instead of detached signature")
    sc.add_argument("path", help="payload path or '-' for stdin")
    sc.set_defaults(func=cmd_sign_create)

    sv = ss.add_parser("verify", help="verify detached signature or envelope")
    sv.add_argument("--envelope", action="store_true", help="verify envelope JSON instead of detached signature")
    sv.add_argument("--kid", default=None)
    sv.add_argument("--pem-public", default=None, help="PEM public key for asymmetric")
    sv.add_argument("--hmac-secret", default=None, help="secret for HMAC")
    sv.add_argument("--max-skew", type=int, default=None, help="max timestamp skew (seconds)")
    sv.add_argument("--sig", default="-", help="path to signature JSON (for detached)")
    sv.add_argument("--data", default="-", help="path to payload data (for detached)")
    sv.add_argument("path", nargs="?", default="-", help="path to envelope JSON (when --envelope)")
    sv.set_defaults(func=cmd_sign_verify)

    return p


# -------------------------------
# Entry point
# -------------------------------

def main(argv: List[str] | None = None) -> None:
    argv = argv if argv is not None else sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.verbose, args.json)
    try:
        args.func(args)  # type: ignore[attr-defined]
    except SystemExit:
        raise
    except KeyboardInterrupt:
        die("interrupted", 130, args.json)
    except Exception as e:
        die(f"unhandled error: {e}", 1, args.json)


if __name__ == "__main__":
    main()
