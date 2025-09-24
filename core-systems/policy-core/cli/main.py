# policy-core/cli/main.py
"""
Policy-Core CLI

Subcommands:
  validate-policy   Validate policy JSON files (or bundle) for schema & semantics
  bundle-create     Create PolicyBundle from policy files/directories, optionally sign
  bundle-verify     Verify HMAC signature of an existing bundle
  bundle-revision   Compute stable revision hash from bundle or raw policy docs
  pdp-eval          Evaluate PDP decision for a request using provided policies

Features:
  - No third-party dependencies
  - Robust error handling with exit codes
  - NDJSON batch evaluation
  - HMAC signing (bundles and decisions)
  - Structured audit logging (stdout/file), optional integrity chain
  - Works with policy_core.* modules

Exit codes:
  0  success
  1  validation error (policies/bundle/request)
  2  runtime/IO error
  3  signature verification failed
  4  file not found / nothing matched
"""

from __future__ import annotations

import argparse
import asyncio
import glob
import json
import os
import sys
from dataclasses import asdict
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

# --- Imports from policy_core ---
from policy_core.models.policies import (
    Policy,
    PolicyBundle,
    ValidationError,
    SchemaError,
    policy_json_schema,
    bundle_json_schema,
    compute_bundle_revision_from_docs,
    migrate_policy,
)
from policy_core.pdp.decision_engine import (
    DecisionEngine,
    DecisionEngineConfig,
    DecisionRequest,
    build_store_from_docs,
)
from policy_core.audit.logger import (
    AuditConfig,
    AuditLogger,
    Level as AuditLevel,
    set_context as audit_set_context,
)

# ---------------------------- Utilities ----------------------------

EXIT_OK = 0
EXIT_VALIDATION = 1
EXIT_RUNTIME = 2
EXIT_SIGFAIL = 3
EXIT_NOTFOUND = 4

def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)

def load_json(path: str) -> Any:
    if path == "-":
        try:
            return json.load(sys.stdin)
        except Exception as e:
            raise ValueError(f"Failed to read JSON from stdin: {e}") from e
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError as e:
        raise FileNotFoundError(f"File not found: {path}") from e
    except Exception as e:
        raise ValueError(f"Failed to parse JSON: {path}: {e}") from e

def dump_json(obj: Any, path: Optional[str]) -> None:
    out = json.dumps(obj, ensure_ascii=False, indent=2)
    if path and path != "-":
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(out + "\n")
    else:
        print(out)

def read_secret(path: Optional[str]) -> Optional[bytes]:
    if not path:
        return None
    try:
        with open(path, "rb") as f:
            return f.read().strip()
    except Exception as e:
        raise ValueError(f"Failed to read secret from {path}: {e}") from e

def iter_paths(inputs: Sequence[str]) -> List[str]:
    matched: List[str] = []
    for p in inputs:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for fn in files:
                    if fn.lower().endswith(".json"):
                        matched.append(os.path.join(root, fn))
        else:
            gl = glob.glob(p)
            if gl:
                matched.extend([x for x in gl if os.path.isfile(x)])
            elif os.path.isfile(p):
                matched.append(p)
    # De-dup & stable order
    seen = set()
    result = []
    for x in sorted(matched):
        if x not in seen:
            seen.add(x)
            result.append(x)
    return result

def is_bundle_doc(doc: Mapping[str, Any]) -> bool:
    return isinstance(doc, Mapping) and "policies" in doc and isinstance(doc["policies"], list)

def policies_from_files(paths: Sequence[str]) -> Tuple[List[Dict[str, Any]], Optional[PolicyBundle]]:
    """
    Returns (policy_docs, bundle_if_any). If a bundle file is provided, returns bundle and empty docs.
    """
    docs: List[Dict[str, Any]] = []
    bundle: Optional[PolicyBundle] = None
    for p in paths:
        raw = load_json(p)
        if is_bundle_doc(raw):
            # Only one bundle allowed per invocation
            if bundle is not None:
                raise ValueError("Multiple bundles provided. Provide a single bundle or raw policies.")
            try:
                bundle = PolicyBundle.from_dict(raw)
            except (ValidationError, SchemaError) as e:
                raise ValueError(f"Invalid bundle {p}: {e}") from e
        else:
            if isinstance(raw, list):
                for i, it in enumerate(raw):
                    if not isinstance(it, Mapping):
                        raise ValueError(f"{p}[{i}]: each element must be an object")
                    docs.append(dict(it))
            elif isinstance(raw, Mapping):
                docs.append(dict(raw))
            else:
                raise ValueError(f"{p}: unsupported JSON root (must be object or array)")
    return docs, bundle

def bundle_to_docs(bundle: PolicyBundle) -> List[Dict[str, Any]]:
    return [p.to_dict() for p in bundle.policies]

def make_audit_logger(args: argparse.Namespace) -> AuditLogger:
    level = AuditLevel.parse(args.audit_level)
    cfg = AuditConfig(
        sink=args.audit_sink,
        file_path=args.audit_file,
        max_bytes=args.audit_max_bytes,
        backup_count=args.audit_backup_count,
        rotate_on_start=args.audit_rotate_on_start,
        level=level,
        flush_immediately=not args.audit_buffered,
        async_mode=args.audit_async,
        queue_maxsize=args.audit_queue,
        redact_keys=tuple(("password","pass","secret","token","authorization","cookie","api_key","apikey","private_key","access_key","refresh_token")),
        include_signature=bool(args.audit_sign),
        hmac_secret=read_secret(args.audit_hmac_secret) if args.audit_sign else None,
        include_integrity_chain=not args.audit_no_chain,
        service="policy-core",
        service_version=args.service_version,
        include_pid=True,
        include_hostname=True,
        sampling={},  # can be extended via flags
    )
    return AuditLogger(cfg)

def set_audit_context(args: argparse.Namespace) -> None:
    audit_set_context(
        request_id=args.request_id or "",
        span_id=args.span_id or "",
        tenant_id=args.tenant_id or "",
        subject_id=args.subject_id or "",
        session_id=args.session_id or "",
    )

# ---------------------------- Commands ----------------------------

def cmd_validate_policy(args: argparse.Namespace) -> int:
    try:
        paths = iter_paths(args.input)
        if not paths:
            eprint("No input files matched.")
            return EXIT_NOTFOUND
        docs, bundle = policies_from_files(paths)
        ok = True
        if bundle:
            # Also validate shape by serializing & re-parsing quickly
            _ = PolicyBundle.from_dict(bundle.to_dict())
            print(f"[OK] bundle: policies={len(bundle.policies)} revision={bundle.revision}")
        for pth in paths:
            raw = load_json(pth)
            if is_bundle_doc(raw):
                continue
            # Normalize potential v1 -> v2 shape
            norm = migrate_policy(raw, str(raw.get("schema_version", "2.0")))
            try:
                p = Policy.from_dict(norm)
                # Round-trip
                _ = Policy.from_dict(p.to_dict())
                print(f"[OK] policy:{p.id} priority={p.priority} rules={len(p.rules)}")
            except ValidationError as ve:
                ok = False
                eprint(f"[ERR] {pth}: {ve} :: {getattr(ve, 'path', None)}")
        return EXIT_OK if ok else EXIT_VALIDATION
    except (ValidationError, SchemaError, ValueError, FileNotFoundError) as e:
        eprint(f"Validation error: {e}")
        return EXIT_VALIDATION
    except Exception as e:
        eprint(f"Runtime error: {e}")
        return EXIT_RUNTIME

def cmd_bundle_create(args: argparse.Namespace) -> int:
    try:
        paths = iter_paths(args.input)
        if not paths:
            eprint("No input files matched.")
            return EXIT_NOTFOUND
        docs, bundle = policies_from_files(paths)
        if bundle and docs:
            eprint("Provide either a bundle OR raw policy docs, not both.")
            return EXIT_VALIDATION
        if not bundle:
            # Build from docs
            policies: List[Policy] = []
            for i, d in enumerate(docs):
                p = Policy.from_dict(migrate_policy(d, str(d.get("schema_version", "2.0"))))
                policies.append(p)
            bundle = PolicyBundle(policies=tuple(policies))
        # Recompute revision deterministically
        bundle = PolicyBundle.from_dict(bundle.to_dict())  # normalize & recompute revision in __post_init__
        if args.sign_hmac_secret:
            secret = read_secret(args.sign_hmac_secret)
            bundle = bundle.sign(secret or b"")
        dump_json(bundle.to_dict(include_signature=True), args.output)
        print(f"Bundle created. policies={len(bundle.policies)} revision={bundle.revision}")
        return EXIT_OK
    except (ValidationError, SchemaError, ValueError) as e:
        eprint(f"Validation error: {e}")
        return EXIT_VALIDATION
    except Exception as e:
        eprint(f"Runtime error: {e}")
        return EXIT_RUNTIME

def cmd_bundle_verify(args: argparse.Namespace) -> int:
    try:
        doc = load_json(args.bundle)
        if not is_bundle_doc(doc):
            eprint("Provided file is not a bundle.")
            return EXIT_VALIDATION
        bundle = PolicyBundle.from_dict(doc)
        secret = read_secret(args.hmac_secret)
        ok = bundle.verify_signature(secret or b"")
        print(json.dumps({"verified": bool(ok), "revision": bundle.revision}, ensure_ascii=False))
        return EXIT_OK if ok else EXIT_SIGFAIL
    except (ValidationError, SchemaError, ValueError) as e:
        eprint(f"Validation error: {e}")
        return EXIT_VALIDATION
    except Exception as e:
        eprint(f"Runtime error: {e}")
        return EXIT_RUNTIME

def cmd_bundle_revision(args: argparse.Namespace) -> int:
    try:
        paths = iter_paths(args.input)
        if not paths:
            eprint("No input files matched.")
            return EXIT_NOTFOUND
        docs, bundle = policies_from_files(paths)
        if bundle:
            print(bundle.revision)
            return EXIT_OK
        if not docs:
            eprint("No policy docs found.")
            return EXIT_NOTFOUND
        rev = compute_bundle_revision_from_docs(docs)
        print(rev)
        return EXIT_OK
    except Exception as e:
        eprint(f"Runtime error: {e}")
        return EXIT_RUNTIME

async def _run_pdp_eval_async(args: argparse.Namespace) -> int:
    try:
        # Load policies
        paths = iter_paths(args.policies)
        if not paths:
            eprint("No policy inputs matched.")
            return EXIT_NOTFOUND
        docs, bundle = policies_from_files(paths)
        if bundle:
            docs = bundle_to_docs(bundle)
        if not docs:
            eprint("No policies to evaluate.")
            return EXIT_NOTFOUND

        # PDP config
        dec_cfg = DecisionEngineConfig(
            cache_ttl_seconds=args.cache_ttl,
            cache_max_entries=args.cache_max_entries,
            fail_closed=not args.fail_open,
            log_decisions=False,  # audit logger will handle logging
            metrics_enabled=True,
            enable_signature=bool(args.sign_decision),
            hmac_secret=read_secret(args.sign_hmac_secret) if args.sign_decision else None,
            precompile=not args.no_precompile,
        )
        engine = DecisionEngine(store=build_store_from_docs(docs), config=dec_cfg)
        if dec_cfg.precompile:
            await engine.load_and_precompile()

        # Audit
        audit = make_audit_logger(args)
        if args.audit_async:
            await audit.start_async()
        set_audit_context(args)

        # Input mode: single JSON or NDJSON stream
        if args.ndjson:
            # Read NDJSON from stdin or file
            source = sys.stdin if args.request == "-" else open(args.request, "r", encoding="utf-8")
            processed = 0
            try:
                for line in source:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        req_obj = json.loads(line)
                    except Exception as e:
                        eprint(f"[SKIP] invalid JSON line: {e}")
                        continue
                    rc = await _eval_once(engine, audit, req_obj, args, print_result=True)
                    processed += 1
                if processed == 0:
                    eprint("No requests processed from NDJSON input.")
            finally:
                if source is not sys.stdin:
                    source.close()
        else:
            req = load_json(args.request)
            rc = await _eval_once(engine, audit, req, args, print_result=True)
            if rc != EXIT_OK:
                return rc

        if args.audit_async:
            await audit.stop_async()
        audit.close()
        return EXIT_OK
    except FileNotFoundError as e:
        eprint(str(e))
        return EXIT_NOTFOUND
    except (ValidationError, SchemaError, ValueError) as e:
        eprint(f"Validation error: {e}")
        return EXIT_VALIDATION
    except Exception as e:
        eprint(f"Runtime error: {e}")
        return EXIT_RUNTIME

async def _eval_once(engine: DecisionEngine, audit: AuditLogger, req_obj: Mapping[str, Any], args: argparse.Namespace, print_result: bool) -> int:
    # Normalize request
    if not isinstance(req_obj, Mapping):
        eprint("Request must be a JSON object.")
        return EXIT_VALIDATION
    subject = dict(req_obj.get("subject", {}))
    resource = dict(req_obj.get("resource", {}))
    action = req_obj.get("action")
    env = dict(req_obj.get("env", {}))
    if not isinstance(action, str) or not action:
        eprint("Request.action must be a non-empty string.")
        return EXIT_VALIDATION

    decision = await engine.evaluate(DecisionRequest(subject=subject, resource=resource, action=action, env=env))
    # Audit record with redaction handled inside AuditLogger
    audit.decision({
        "decision": decision.decision.value,
        "policy_id": decision.policy_id,
        "matched_rules": decision.matched_rules,
        "latency_ms": decision.latency_ms,
        "reason": decision.reason,
        "decision_id": decision.decision_id,
        "signature": decision.signature,
    })

    if print_result:
        print(json.dumps(decision.to_dict(), ensure_ascii=False))
    return EXIT_OK

def cmd_pdp_eval(args: argparse.Namespace) -> int:
    return asyncio.run(_run_pdp_eval_async(args))

# ---------------------------- Argument Parser ----------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="policy-core", description="Policy-Core command line interface")
    p.add_argument("--service-version", default="1.0", help="Service version tag for audit logs")

    sub = p.add_subparsers(dest="cmd", required=True)

    # validate-policy
    sp = sub.add_parser("validate-policy", help="Validate policy JSON files (or bundle)")
    sp.add_argument("input", nargs="+", help="Files/dirs/globs (JSON). Can include a bundle.")
    sp.set_defaults(func=cmd_validate_policy)

    # bundle-create
    sp = sub.add_parser("bundle-create", help="Create a PolicyBundle from policies")
    sp.add_argument("input", nargs="+", help="Files/dirs/globs with policy JSON (not bundle) or a single bundle")
    sp.add_argument("-o", "--output", default="-", help="Output path (default: stdout)")
    sp.add_argument("--sign-hmac-secret", help="Path to HMAC secret file to sign the bundle")
    sp.set_defaults(func=cmd_bundle_create)

    # bundle-verify
    sp = sub.add_parser("bundle-verify", help="Verify HMAC signature of a bundle")
    sp.add_argument("bundle", help="Bundle JSON file")
    sp.add_argument("--hmac-secret", required=True, help="Path to HMAC secret file")
    sp.set_defaults(func=cmd_bundle_verify)

    # bundle-revision
    sp = sub.add_parser("bundle-revision", help="Compute revision from bundle or raw policy docs")
    sp.add_argument("input", nargs="+", help="Files/dirs/globs (bundle or policies)")
    sp.set_defaults(func=cmd_bundle_revision)

    # pdp-eval
    sp = sub.add_parser("pdp-eval", help="Evaluate PDP decision for a request")
    sp.add_argument("-p", "--policies", nargs="+", required=True, help="Policy files/dirs/globs or a bundle")
    sp.add_argument("-r", "--request", required=True, help="Request JSON file or '-' for stdin")
    sp.add_argument("--ndjson", action="store_true", help="Interpret request input as NDJSON stream")
    sp.add_argument("--cache-ttl", type=int, default=60, help="Decision cache TTL seconds")
    sp.add_argument("--cache-max-entries", type=int, default=10000, help="Decision cache max entries")
    sp.add_argument("--fail-open", action="store_true", help="Do not fail-closed on indeterminate")
    sp.add_argument("--sign-decision", action="store_true", help="Attach HMAC signature to decisions")
    sp.add_argument("--sign-hmac-secret", help="Path to HMAC secret for decision signing")
    sp.add_argument("--no-precompile", action="store_true", help="Disable AST precompilation for policies")

    # Audit options (shared for pdp-eval)
    sp.add_argument("--audit-sink", default="stdout", choices=["stdout", "stderr", "file", "noop"], help="Audit sink")
    sp.add_argument("--audit-file", help="Path for file sink")
    sp.add_argument("--audit-max-bytes", type=int, default=50 * 1024 * 1024, help="Rotate after this many bytes")
    sp.add_argument("--audit-backup-count", type=int, default=10, help="Number of rotated files to keep")
    sp.add_argument("--audit-rotate-on-start", action="store_true", help="Rotate active file on start")
    sp.add_argument("--audit-level", default="info", help="Audit level (debug/info/notice/warn/error/critical)")
    sp.add_argument("--audit-buffered", action="store_true", help="Buffer writes (do not flush every line)")
    sp.add_argument("--audit-async", action="store_true", help="Enable async audit queue")
    sp.add_argument("--audit-queue", type=int, default=10000, help="Async audit queue size")
    sp.add_argument("--audit-sign", action="store_true", help="HMAC-sign audit records")
    sp.add_argument("--audit-hmac-secret", help="Path to HMAC secret for audit signing")
    sp.add_argument("--audit-no-chain", action="store_true", help="Disable integrity chain in audit")

    # Context
    sp.add_argument("--request-id", help="Audit context: request_id")
    sp.add_argument("--span-id", help="Audit context: span_id")
    sp.add_argument("--tenant-id", help="Audit context: tenant_id")
    sp.add_argument("--subject-id", help="Audit context: subject_id")
    sp.add_argument("--session-id", help="Audit context: session_id")

    return p

# ---------------------------- Entry ----------------------------

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        eprint("Interrupted.")
        return EXIT_RUNTIME

if __name__ == "__main__":
    sys.exit(main())
