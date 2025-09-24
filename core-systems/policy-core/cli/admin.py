# -*- coding: utf-8 -*-
"""
policy_core.cli.admin
Промышленный админ-CLI для policy-core.

Команды:
  opa status                      - проверка здоровья OPA
  opa list                        - список политик в OPA
  opa push    --id <POLICY_ID> --file <path.rego>
  opa delete  --id <POLICY_ID>
  opa eval    --path <data.path or path/like> --input <file.json|yaml> [--explain notes|full] [--no-cache]
  opa compile --path <data.path or path/like> --input <file.json|yaml>
  audit verify --file <audit.jsonl> [--hmac-secret-base64 <b64>]
  cache warm  --file <cases.json|yaml> [--concurrency N]
  gen request-id [--count N]
  gen hmac-secret [--bytes N]
  health check                    - быстрый комплексный self-check CLI

Конфигурация окружения:
  OPA_BASE_URL (default: http://127.0.0.1:8181)
  OPA_TOKEN
  OPA_VERIFY_SSL=0|1 (default: 1)
  OPA_NAMESPACE (default: policy-core)
  AUDIT_HMAC_SECRET_BASE64  (для audit verify по умолчанию)

Пример:
  python -m policy_core.cli.admin opa eval --path authz/allow --input input.json --json
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import os
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, List

# Внутренние зависимости policy-core
try:
    from policy_core.pdp.evaluator_rego import PDPConfig, RegoEvaluator
    from policy_core.models.attributes import ABACInput
    from policy_core.audit.trail import AuditTrail
except Exception as e:
    print("FATAL: policy_core modules not found or import failed:", e, file=sys.stderr)
    sys.exit(121)

# Внешние (уже используемые проектом)
try:
    import httpx  # используется и в RegoEvaluator
except Exception as e:
    print("FATAL: httpx is required for this CLI:", e, file=sys.stderr)
    sys.exit(122)

# ------------------------------
# Логирование и утилиты
# ------------------------------

_LOG = logging.getLogger("policy_core.cli.admin")

SENSITIVE_KEYS = {
    "authorization", "token", "access_token", "id_token", "refresh_token",
    "password", "secret", "api_key", "x-api-key", "x-auth-token", "cookie"
}

def setup_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

def stable_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

def mask_secrets(data: Any) -> Any:
    if isinstance(data, dict):
        return {k: ("***" if k.lower() in SENSITIVE_KEYS else mask_secrets(v)) for k, v in data.items()}
    if isinstance(data, list):
        return [mask_secrets(v) for v in data]
    return data

def load_json_or_yaml(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    # Сначала JSON
    try:
        return json.loads(text)
    except Exception:
        pass
    # Затем YAML (опционально)
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text)
    except Exception as e:
        raise ValueError(f"Failed to parse {path.name} as JSON or YAML: {e}")

def exit_with_error(msg: str, code: int = 2, payload: Optional[Dict[str, Any]] = None, as_json: bool = False) -> None:
    if as_json:
        out = {"ok": False, "error": msg}
        if payload:
            out["details"] = payload
        print(stable_json(out))
    else:
        print(f"ERROR: {msg}", file=sys.stderr)
        if payload:
            try:
                print(stable_json(payload), file=sys.stderr)
            except Exception:
                pass
    sys.exit(code)

@dataclass
class OPAOpts:
    base_url: str
    token: Optional[str]
    verify_ssl: bool
    namespace: str

def resolve_opa_opts(args: argparse.Namespace) -> OPAOpts:
    base_url = args.opa_url or os.getenv("OPA_BASE_URL", "http://127.0.0.1:8181")
    token = args.opa_token or os.getenv("OPA_TOKEN")
    verify = (not args.insecure_no_verify) and (os.getenv("OPA_VERIFY_SSL", "1") != "0")
    ns = args.namespace or os.getenv("OPA_NAMESPACE", "policy-core")
    return OPAOpts(base_url=base_url, token=token, verify_ssl=verify, namespace=ns)

# ------------------------------
# OPA HTTP helpers
# ------------------------------

async def opa_http_get(opts: OPAOpts, path: str, timeout_s: float = 3.0) -> httpx.Response:
    headers = {}
    if opts.token:
        headers["Authorization"] = f"Bearer {opts.token}"
    async with httpx.AsyncClient(base_url=opts.base_url, timeout=timeout_s, verify=opts.verify_ssl, headers=headers) as client:
        return await client.get(path)

async def opa_http_put_text(opts: OPAOpts, path: str, text_body: str, timeout_s: float = 5.0) -> httpx.Response:
    headers = {"Content-Type": "text/plain"}
    if opts.token:
        headers["Authorization"] = f"Bearer {opts.token}"
    async with httpx.AsyncClient(base_url=opts.base_url, timeout=timeout_s, verify=opts.verify_ssl, headers=headers) as client:
        return await client.put(path, content=text_body)

async def opa_http_delete(opts: OPAOpts, path: str, timeout_s: float = 5.0) -> httpx.Response:
    headers = {}
    if opts.token:
        headers["Authorization"] = f"Bearer {opts.token}"
    async with httpx.AsyncClient(base_url=opts.base_url, timeout=timeout_s, verify=opts.verify_ssl, headers=headers) as client:
        return await client.delete(path)

# ------------------------------
# Команды OPA
# ------------------------------

async def cmd_opa_status(args: argparse.Namespace) -> int:
    opts = resolve_opa_opts(args)
    try:
        r = await opa_http_get(opts, "/health")
        ok = r.status_code == 200
        if args.json:
            print(stable_json({"ok": ok, "status_code": r.status_code}))
        else:
            print(f"OPA health: {'OK' if ok else 'NOT OK'} ({r.status_code})")
        return 0 if ok else 10
    except Exception as e:
        exit_with_error(f"OPA health check failed: {e}", code=10, as_json=args.json)
        return 10

async def cmd_opa_list(args: argparse.Namespace) -> int:
    opts = resolve_opa_opts(args)
    try:
        r = await opa_http_get(opts, "/v1/policies", timeout_s=5.0)
        if r.status_code != 200:
            exit_with_error(f"OPA returned {r.status_code}: {r.text}", code=11, as_json=args.json)
        data = r.json()
        if args.json:
            print(stable_json({"ok": True, "policies": data.get("result", [])}))
        else:
            result = data.get("result", [])
            print(f"Total policies: {len(result)}")
            for p in result:
                pid = p.get("id")
                path = p.get("ast_path") or "-"
                print(f" - {pid} ({path})")
        return 0
    except Exception as e:
        exit_with_error(f"OPA list failed: {e}", code=11, as_json=args.json)
        return 11

async def cmd_opa_push(args: argparse.Namespace) -> int:
    opts = resolve_opa_opts(args)
    pid = args.id
    file = Path(args.file)
    if not file.exists():
        exit_with_error(f"Policy file not found: {file}", code=12, as_json=args.json)
    body = file.read_text(encoding="utf-8")
    try:
        r = await opa_http_put_text(opts, f"/v1/policies/{pid}", body, timeout_s=10.0)
        ok = r.status_code in (200, 201)
        if args.json:
            print(stable_json({"ok": ok, "status_code": r.status_code, "text": r.text}))
        else:
            print(f"Push policy '{pid}': {'OK' if ok else 'FAILED'} ({r.status_code})")
            if not ok:
                print(r.text)
        return 0 if ok else 12
    except Exception as e:
        exit_with_error(f"OPA push failed: {e}", code=12, as_json=args.json)
        return 12

async def cmd_opa_delete(args: argparse.Namespace) -> int:
    opts = resolve_opa_opts(args)
    pid = args.id
    try:
        r = await opa_http_delete(opts, f"/v1/policies/{pid}", timeout_s=10.0)
        ok = r.status_code in (200, 204)
        if args.json:
            print(stable_json({"ok": ok, "status_code": r.status_code, "text": r.text}))
        else:
            print(f"Delete policy '{pid}': {'OK' if ok else 'FAILED'} ({r.status_code})")
            if not ok:
                print(r.text)
        return 0 if ok else 13
    except Exception as e:
        exit_with_error(f"OPA delete failed: {e}", code=13, as_json=args.json)
        return 13

async def _build_evaluator(args: argparse.Namespace) -> RegoEvaluator:
    opts = resolve_opa_opts(args)
    cfg = PDPConfig(
        base_url=opts.base_url,
        token=opts.token,
        verify_ssl=opts.verify_ssl,
        namespace=opts.namespace,
        timeout_seconds= float(args.timeout) if args.timeout else 3.0,
        connect_timeout_seconds=1.0,
        retries= int(args.retries) if args.retries else 1,
        log_decision_payloads=args.verbose >= 2,
    )
    ev = RegoEvaluator(cfg)
    await ev.start()
    return ev

async def cmd_opa_eval(args: argparse.Namespace) -> int:
    path = args.path.strip().lstrip("data.").lstrip("/")
    input_file = Path(args.input)
    if not input_file.exists():
        exit_with_error(f"Input file not found: {input_file}", code=14, as_json=args.json)

    try:
        payload = load_json_or_yaml(input_file)
        # Поддержка как полного ABACInput, так и произвольного словаря
        if args.assume_abac:
            abac = ABACInput.from_context(**payload) if isinstance(payload, dict) else ABACInput.from_context(action={"action": "unknown"})
            inp = abac.to_opa_input()
        else:
            if not isinstance(payload, dict):
                exit_with_error("Input must be a JSON/YAML object", code=14, as_json=args.json)
            inp = payload

        ev = await _build_evaluator(args)
        try:
            res = await ev.evaluate(path, inp, explain=args.explain, use_cache=(not args.no_cache))
        finally:
            await ev.aclose()

        out = {
            "ok": True,
            "policy_path": path,
            "decision": res.decision,
            "latency_ms": round(res.latency_ms, 2),
            "from_cache": res.from_cache,
            "raw": res.raw_result if args.raw else None,
        }
        if args.json:
            print(stable_json(out))
        else:
            print(f"Decision: {res.decision}  latency={round(res.latency_ms,2)}ms  cache={res.from_cache}")
            if args.raw:
                print(stable_json(res.raw_result))
        return 0
    except Exception as e:
        exit_with_error(f"OPA eval failed: {e}", code=14, as_json=args.json)
        return 14

async def cmd_opa_compile(args: argparse.Namespace) -> int:
    path = args.path.strip().lstrip("data.").lstrip("/")
    input_file = Path(args.input)
    if not input_file.exists():
        exit_with_error(f"Input file not found: {input_file}", code=15, as_json=args.json)

    try:
        payload = load_json_or_yaml(input_file)
        if not isinstance(payload, dict):
            exit_with_error("Input must be a JSON/YAML object", code=15, as_json=args.json)
        ev = await _build_evaluator(args)
        try:
            raw = await ev.compile_partial(path, payload)
        finally:
            await ev.aclose()

        if args.json:
            print(stable_json({"ok": True, "compiled": raw}))
        else:
            print("Partial evaluation (queries/support):")
            print(stable_json(raw))
        return 0
    except Exception as e:
        exit_with_error(f"OPA compile failed: {e}", code=15, as_json=args.json)
        return 15

# ------------------------------
# Команды AUDIT
# ------------------------------

def cmd_audit_verify(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.exists():
        exit_with_error(f"Audit file not found: {path}", code=21, as_json=args.json)
    secret_b64 = args.hmac_secret_base64 or os.getenv("AUDIT_HMAC_SECRET_BASE64")
    secret = None
    if secret_b64:
        try:
            secret = base64.b64decode(secret_b64)
        except Exception as e:
            exit_with_error(f"Invalid base64 secret: {e}", code=21, as_json=args.json)

    ok, line, reason = AuditTrail.verify_jsonl_chain(str(path), hmac_secret=secret)
    if args.json:
        print(stable_json({"ok": ok, "line": line, "reason": reason}))
    else:
        if ok:
            print("Audit chain: OK")
        else:
            print(f"Audit chain: FAILED at line {line or '-'}; reason: {reason}")
    return 0 if ok else 21

# ------------------------------
# Команды CACHE
# ------------------------------

async def cmd_cache_warm(args: argparse.Namespace) -> int:
    """
    Формат файла:
    JSON/YAML: список объектов {policy_path: "...", input: {...}} или
               объект с ключом "cases": [ ... ]
    """
    cases_file = Path(args.file)
    if not cases_file.exists():
        exit_with_error(f"Cases file not found: {cases_file}", code=31, as_json=args.json)

    data = load_json_or_yaml(cases_file)
    if isinstance(data, dict) and "cases" in data:
        cases = data["cases"]
    else:
        cases = data
    if not isinstance(cases, list):
        exit_with_error("Cases must be a list", code=31, as_json=args.json)

    ev = await _build_evaluator(args)
    sem = asyncio.Semaphore(args.concurrency or 16)

    successes = 0
    failures = 0

    async def one(case: Dict[str, Any]) -> None:
        nonlocal successes, failures
        try:
            path = str(case.get("policy_path", "")).strip().lstrip("data.").lstrip("/")
            if not path:
                raise ValueError("case.policy_path is required")
            inp = case.get("input")
            if not isinstance(inp, dict):
                raise ValueError("case.input must be an object")
            async with sem:
                await ev.evaluate(path, inp, use_cache=True)
            successes += 1
        except Exception as e:
            _LOG.error("Warm case failed: %s", e)
            failures += 1

    try:
        await asyncio.gather(*(one(c) for c in cases))
    finally:
        await ev.aclose()

    out = {"ok": failures == 0, "successes": successes, "failures": failures}
    if args.json:
        print(stable_json(out))
    else:
        print(f"Cache warm finished: ok={out['ok']} successes={successes} failures={failures}")
    return 0 if failures == 0 else 31

# ------------------------------
# GEN & HEALTH
# ------------------------------

def cmd_gen_request_id(args: argparse.Namespace) -> int:
    import uuid
    count = args.count or 1
    ids = [str(uuid.uuid4()) for _ in range(count)]
    if args.json:
        print(stable_json({"ok": True, "ids": ids}))
    else:
        for i in ids:
            print(i)
    return 0

def cmd_gen_hmac_secret(args: argparse.Namespace) -> int:
    n = args.bytes or 32
    sec = os.urandom(n)
    b64 = base64.b64encode(sec).decode("ascii")
    if args.json:
        print(stable_json({"ok": True, "bytes": n, "base64": b64}))
    else:
        print(b64)
    return 0

async def cmd_health_check(args: argparse.Namespace) -> int:
    # 1) OPA
    rc_opa = await cmd_opa_status(args)
    # 2) Простая запись во временный каталог (проверка прав)
    try:
        p = Path("./.health_check_tmp")
        p.write_text("ok", encoding="utf-8")
        p.unlink(missing_ok=True)
        fs_ok = True
    except Exception:
        fs_ok = False
    out = {"ok": rc_opa == 0 and fs_ok, "opa_ok": rc_opa == 0, "fs_ok": fs_ok}
    if args.json:
        print(stable_json(out))
    else:
        print(f"Health: ok={out['ok']} opa={out['opa_ok']} fs={out['fs_ok']}")
    return 0 if out["ok"] else 40

# ------------------------------
# Парсер аргументов
# ------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="policy-core-admin",
        description="Admin CLI for policy-core",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(__doc__ or "")
    )
    p.add_argument("--opa-url", dest="opa_url", help="OPA base URL (env OPA_BASE_URL)")
    p.add_argument("--opa-token", dest="opa_token", help="OPA bearer token (env OPA_TOKEN)")
    p.add_argument("--namespace", dest="namespace", help="Namespace for logs/metrics (env OPA_NAMESPACE)")
    p.add_argument("--insecure-no-verify", action="store_true", help="Disable TLS verification")
    p.add_argument("--timeout", type=float, default=3.0, help="Request timeout seconds")
    p.add_argument("--retries", type=int, default=1, help="Transient retries for evaluator calls")
    p.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    p.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v, -vv)")
    sp = p.add_subparsers(dest="cmd")

    # opa
    sp_opa = sp.add_parser("opa", help="OPA related commands")
    sp_opa_sub = sp_opa.add_subparsers(dest="subcmd")
    sp_opa_status = sp_opa_sub.add_parser("status", help="OPA health")
    sp_opa_status.set_defaults(func=lambda a: asyncio.run(cmd_opa_status(a)))

    sp_opa_list = sp_opa_sub.add_parser("list", help="List policies")
    sp_opa_list.set_defaults(func=lambda a: asyncio.run(cmd_opa_list(a)))

    sp_opa_push = sp_opa_sub.add_parser("push", help="Push Rego policy to OPA")
    sp_opa_push.add_argument("--id", required=True, help="Policy ID in OPA")
    sp_opa_push.add_argument("--file", required=True, help="Path to .rego file")
    sp_opa_push.set_defaults(func=lambda a: asyncio.run(cmd_opa_push(a)))

    sp_opa_delete = sp_opa_sub.add_parser("delete", help="Delete policy from OPA")
    sp_opa_delete.add_argument("--id", required=True, help="Policy ID in OPA")
    sp_opa_delete.set_defaults(func=lambda a: asyncio.run(cmd_opa_delete(a)))

    sp_opa_eval = sp_opa_sub.add_parser("eval", help="Evaluate policy with input")
    sp_opa_eval.add_argument("--path", required=True, help="Policy data path, e.g. authz/allow or data.authz.allow")
    sp_opa_eval.add_argument("--input", required=True, help="Path to JSON/YAML input file")
    sp_opa_eval.add_argument("--explain", choices=["notes", "full"], help="OPA explain level")
    sp_opa_eval.add_argument("--no-cache", action="store_true", help="Disable local decision cache")
    sp_opa_eval.add_argument("--assume-abac", action="store_true", help="Treat input as ABACInput context")
    sp_opa_eval.add_argument("--raw", action="store_true", help="Print raw OPA result object")
    sp_opa_eval.set_defaults(func=lambda a: asyncio.run(cmd_opa_eval(a)))

    sp_opa_compile = sp_opa_sub.add_parser("compile", help="Partial evaluation /v1/compile")
    sp_opa_compile.add_argument("--path", required=True, help="Policy data path")
    sp_opa_compile.add_argument("--input", required=True, help="Path to JSON/YAML input file")
    sp_opa_compile.set_defaults(func=lambda a: asyncio.run(cmd_opa_compile(a)))

    # audit
    sp_audit = sp.add_parser("audit", help="Audit trail commands")
    sp_audit_sub = sp_audit.add_subparsers(dest="subcmd")
    sp_audit_verify = sp_audit_sub.add_parser("verify", help="Verify audit JSONL hash chain")
    sp_audit_verify.add_argument("--file", required=True, help="Path to audit JSONL")
    sp_audit_verify.add_argument("--hmac-secret-base64", dest="hmac_secret_base64", help="Base64 HMAC secret (optional)")
    sp_audit_verify.set_defaults(func=cmd_audit_verify)

    # cache
    sp_cache = sp.add_parser("cache", help="Evaluator cache utilities")
    sp_cache_sub = sp_cache.add_subparsers(dest="subcmd")
    sp_cache_warm = sp_cache_sub.add_parser("warm", help="Warm decision cache from cases file")
    sp_cache_warm.add_argument("--file", required=True, help="Path to JSON/YAML with cases")
    sp_cache_warm.add_argument("--concurrency", type=int, default=16, help="Parallel warm concurrency")
    sp_cache_warm.set_defaults(func=lambda a: asyncio.run(cmd_cache_warm(a)))

    # gen
    sp_gen = sp.add_parser("gen", help="Generators")
    sp_gen_sub = sp_gen.add_subparsers(dest="subcmd")
    sp_gen_req = sp_gen_sub.add_parser("request-id", help="Generate UUID v4 request IDs")
    sp_gen_req.add_argument("--count", type=int, default=1, help="How many IDs to generate")
    sp_gen_req.set_defaults(func=cmd_gen_request_id)

    sp_gen_hmac = sp_gen_sub.add_parser("hmac-secret", help="Generate random HMAC secret (base64)")
    sp_gen_hmac.add_argument("--bytes", type=int, default=32, help="Secret length in bytes")
    sp_gen_hmac.set_defaults(func=cmd_gen_hmac_secret)

    # health
    sp_health = sp.add_parser("health", help="Self-check")
    sp_health_sub = sp_health.add_subparsers(dest="subcmd")
    sp_health_check = sp_health_sub.add_parser("check", help="Run basic health checks")
    sp_health_check.set_defaults(func=lambda a: asyncio.run(cmd_health_check(a)))

    return p

# ------------------------------
# main
# ------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.verbose)

    if not getattr(args, "cmd", None):
        parser.print_help()
        return 0
    if not hasattr(args, "func"):
        parser.print_help()
        return 0

    try:
        rc = args.func(args)
        if isinstance(rc, int):
            return rc
        return 0
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        return 130
    except SystemExit as se:
        return int(se.code)
    except Exception as e:
        exit_with_error(f"Unhandled error: {e}", code=1, as_json=getattr(args, "json", False))
        return 1

if __name__ == "__main__":
    sys.exit(main())
