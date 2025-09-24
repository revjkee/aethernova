# File: veilmind-core/cli/main.py
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import logging
import os
import signal
import sys
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional

# ----------------------------- Exit codes (sysexits-like) -----------------------------
EX_OK = 0
EX_GENERAL = 1
EX_USAGE = 64
EX_DATAERR = 65
EX_NOINPUT = 66
EX_UNAVAILABLE = 69
EX_SOFTWARE = 70
EX_OSERR = 71
EX_CANTCREAT = 73
EX_IOERR = 74
EX_CONFIG = 78

# ------------------------------------ Logging ----------------------------------------

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "trace_id": getattr(record, "trace_id", ""),
            "span_id": getattr(record, "span_id", ""),
            "service": getattr(record, "service_name", os.getenv("OTEL_SERVICE_NAME", "veilmind-core")),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

def setup_logging(verbosity: int, json_logs: bool) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    handler = logging.StreamHandler(sys.stderr)
    if json_logs:
        handler.setFormatter(JsonFormatter())
    else:
        fmt = "%(asctime)s %(levelname)s %(name)s %(message)s"
        handler.setFormatter(logging.Formatter(fmt))
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers = [handler]

# ----------------------------- Safe JSON and file helpers -----------------------------

def _read_all_stdin_text() -> str:
    return sys.stdin.read()

def _read_text(path: Optional[str]) -> str:
    if not path or path == "-":
        return _read_all_stdin_text()
    p = Path(path)
    if not p.exists():
        _fatal(f"input file not found: {p}", EX_NOINPUT)
    return p.read_text(encoding="utf-8")

def _write_text(path: Optional[str], data: str) -> None:
    if not path or path == "-":
        sys.stdout.write(data)
        return
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(data, encoding="utf-8")

def _read_json_obj(path: Optional[str]) -> Any:
    raw = _read_text(path)
    try:
        return json.loads(raw)
    except Exception as e:
        _fatal(f"invalid JSON: {e}", EX_DATAERR)
        return None  # unreachable

def _json_dump(obj: Any) -> str:
    try:
        if is_dataclass(obj):
            obj = asdict(obj)
        return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)
    except TypeError:
        # fallback for generators
        return json.dumps(_json_normalize(obj), ensure_ascii=False, indent=2, sort_keys=True)

def _json_normalize(x: Any) -> Any:
    if is_dataclass(x):
        return asdict(x)
    if isinstance(x, dict):
        return {k: _json_normalize(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [_json_normalize(v) for v in x]
    return x

def _fatal(msg: str, code: int = EX_GENERAL) -> None:
    logging.error(msg)
    sys.exit(code)

# -------------------------------- Optional imports ------------------------------------

def _try_import_redactor():
    try:
        from veilmind.redact.format_preserving import FormatPreservingRedactor, default_rules  # type: ignore
        return FormatPreservingRedactor, default_rules
    except Exception:
        return None, None

def _try_import_reid():
    try:
        from veilmind.risk.reid_scoring import (  # type: ignore
            ReidConfig, ReidScorer, ScoringWeights, AttackerModel,
            gen_identity, gen_str_lower, gen_numeric_bin, gen_date_trunc,
        )
        return {
            "ReidConfig": ReidConfig,
            "ReidScorer": ReidScorer,
            "ScoringWeights": ScoringWeights,
            "AttackerModel": AttackerModel,
            "gen_identity": gen_identity,
            "gen_str_lower": gen_str_lower,
            "gen_numeric_bin": gen_numeric_bin,
            "gen_date_trunc": gen_date_trunc,
        }
    except Exception:
        return None

def _try_import_policy():
    try:
        from veilmind.adapters.policy_core_adapter import (  # type: ignore
            PolicyCoreAdapter, RemotePDPClient, PolicyRequest, Subject, ResourceRef
        )
        return {
            "PolicyCoreAdapter": PolicyCoreAdapter,
            "RemotePDPClient": RemotePDPClient,
            "PolicyRequest": PolicyRequest,
            "Subject": Subject,
            "ResourceRef": ResourceRef,
        }
    except Exception:
        return None

def _try_import_tracing():
    try:
        from veilmind.telemetry.tracing import (  # type: ignore
            setup_tracing, shutdown_tracing, start_span, traced, install_logging_correlation,
            current_traceparent, ensure_request_id, instrument_requests, instrument_httpx
        )
        return {
            "setup_tracing": setup_tracing,
            "shutdown_tracing": shutdown_tracing,
            "start_span": start_span,
            "traced": traced,
            "install_logging_correlation": install_logging_correlation,
            "current_traceparent": current_traceparent,
            "ensure_request_id": ensure_request_id,
            "instrument_requests": instrument_requests,
            "instrument_httpx": instrument_httpx,
        }
    except Exception:
        return None

def _try_import_graphql_create_app():
    # поддержим обе возможные схемы импортов
    try:
        from veilmind_core.api.graphql.server import create_app  # type: ignore
        return create_app
    except Exception:
        pass
    try:
        from veilmind.api.graphql.server import create_app  # type: ignore
        return create_app
    except Exception:
        return None

# ---------------------------------- Redact command ------------------------------------

def cmd_redact(args: argparse.Namespace) -> int:
    FPR, default_rules = _try_import_redactor()
    if not FPR:
        _fatal("module veilmind.redact.format_preserving is not available", EX_UNAVAILABLE)
    key = args.key or os.getenv("FPR_KEY") or "please_change_me_in_env"
    redactor = FPR(key)
    text = _read_text(args.input)
    rules = None
    if args.only:
        # фильтрация дефолтных правил по маскам имен
        rules_all = default_rules(redactor)
        selected = []
        name_map = {
            "email": "RE_EMAIL",
            "ipv4": "RE_IPV4",
            "uuid": "RE_UUID",
            "iban": "RE_IBAN",
            "pan": "RE_PAN",
        }
        only = {t.strip().lower() for t in args.only.split(",")}
        for r in rules_all:
            # грубая фильтрация по объекту repl
            pat = getattr(r, "pattern", None)
            for k, ident in name_map.items():
                if k in only and ident in repr(pat):
                    selected.append(r)
        rules = selected
    out = redactor.redact_text(text, rules=rules)
    _write_text(args.output, out)
    return EX_OK

# ---------------------------------- Risk score command -------------------------------

def _iter_records_from_csv(path: str) -> Iterator[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            yield row

def _iter_records_from_jsonl(path: str) -> Iterator[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)

def _make_generalizers(specs: List[str], env: Dict[str, Any]) -> Dict[str, Any]:
    """
    Парсер строк вида:
      col=identity
      col=str_lower
      col=bin:5
      col=date_trunc:month|year|day
    """
    gens: Dict[str, Any] = {}
    for s in specs:
        if "=" not in s:
            _fatal(f"bad generalizer spec: {s}", EX_USAGE)
        col, val = s.split("=", 1)
        col = col.strip()
        val = val.strip().lower()
        if val == "identity":
            gens[col] = env["gen_identity"]
        elif val in ("str_lower", "lower"):
            gens[col] = env["gen_str_lower"]
        elif val.startswith("bin:"):
            try:
                width = float(val.split(":", 1)[1])
            except Exception:
                _fatal(f"invalid bin width: {val}", EX_USAGE)
            gens[col] = env["gen_numeric_bin"](width)
        elif val.startswith("date_trunc:"):
            unit = val.split(":", 1)[1]
            gens[col] = env["gen_date_trunc"](unit)
        else:
            _fatal(f"unknown generalizer: {s}", EX_USAGE)
    return gens

def cmd_risk_score(args: argparse.Namespace) -> int:
    env = _try_import_reid()
    if not env:
        _fatal("module veilmind.risk.reid_scoring is not available", EX_UNAVAILABLE)
    ReidConfig = env["ReidConfig"]; ReidScorer = env["ReidScorer"]
    ScoringWeights = env["ScoringWeights"]; AttackerModel = env["AttackerModel"]

    # входные данные
    fmt = args.format.lower()
    if fmt == "csv":
        if not args.input or args.input == "-":
            _fatal("csv input requires --input file path", EX_USAGE)
        records = list(_iter_records_from_csv(args.input))
    elif fmt in ("jsonl", "ndjson"):
        if not args.input or args.input == "-":
            _fatal("jsonl input requires --input file path", EX_USAGE)
        records = list(_iter_records_from_jsonl(args.input))
    elif fmt == "json":
        obj = _read_json_obj(args.input)
        if not isinstance(obj, list):
            _fatal("json input must be an array of objects", EX_DATAERR)
        records = list(obj)
    else:
        _fatal(f"unknown format: {args.format}", EX_USAGE)

    qi = [c.strip() for c in args.qi.split(",")] if args.qi else []
    if not qi:
        _fatal("quasi identifiers are required: --qi col1,col2", EX_USAGE)
    sa = [c.strip() for c in args.sa.split(",")] if args.sa else []

    gens = _make_generalizers(args.generalize or [], env)
    models = (
        AttackerModel("prosecutor", sampling_fraction=1.0, weight=args.w_prosecutor),
        AttackerModel("journalist", sampling_fraction=1.0, weight=args.w_journalist),
        AttackerModel("marketer", sampling_fraction=args.marketer_sampling, weight=args.w_marketer),
    )
    weights = ScoringWeights(attacker=args.w_attacker, l_diversity=args.w_ldiv, t_closeness=args.w_tclose)

    cfg = ReidConfig(
        quasi_identifiers=qi,
        sensitive_attributes=tuple(sa),
        generalizers=gens,
        attacker_models=models,
        weights=weights,
        t_distance=args.t_distance,
        score_scale_max=100.0,
    )

    scorer = ReidScorer(cfg).fit(records)
    # отчет
    report = scorer.report()
    # запись скорингов
    out_scores_path = args.out_scores
    if out_scores_path:
        with open(out_scores_path, "w", encoding="utf-8") as f:
            for s in scorer.score_records(records):
                f.write(_json_dump({
                    "index": s.index,
                    "key": [str(v) for v in s.key],
                    "k": s.k,
                    "attacker_risk": s.attacker_risk,
                    "l_penalty": s.l_penalty,
                    "t_penalty": s.t_penalty,
                    "score": s.score,
                    "explain": s.explain if args.verbose_explain else {},
                }))
                f.write("\n")

    # вывод отчета
    sys.stdout.write(_json_dump({
        "report": report,
        "n_records": len(records),
        "params": {
            "qi": qi, "sa": sa, "t_distance": args.t_distance,
        }
    }) + "\n")
    return EX_OK

# ---------------------------------- Policy eval command --------------------------------

def _parse_headers(hs: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for h in hs or []:
        if ":" not in h:
            _fatal(f"bad header format (expect k:v): {h}", EX_USAGE)
        k, v = h.split(":", 1)
        out[k.strip()] = v.strip()
    return out

def cmd_policy_eval(args: argparse.Namespace) -> int:
    env = _try_import_policy()
    if not env:
        _fatal("module veilmind.adapters.policy_core_adapter is not available", EX_UNAVAILABLE)
    PolicyCoreAdapter = env["PolicyCoreAdapter"]; RemotePDPClient = env["RemotePDPClient"]
    PolicyRequest = env["PolicyRequest"]; Subject = env["Subject"]; ResourceRef = env["ResourceRef"]

    rules = []
    if args.rules:
        obj = _read_json_obj(args.rules)
        if isinstance(obj, list):
            rules = obj
        else:
            _fatal("rules must be a JSON array", EX_DATAERR)

    headers = _parse_headers(args.pdp_header or [])
    remote = None
    if args.pdp_url:
        remote = RemotePDPClient(args.pdp_url, package=args.pdp_package, timeout_sec=args.pdp_timeout, headers=headers)

    adapter = PolicyCoreAdapter(local_rules=rules, remote_pdp=remote, hmac_key=os.getenv("POLICY_HMAC_KEY", "change_me"))

    req_obj = _read_json_obj(args.input) if args.input else _fatal("policy request JSON is required", EX_USAGE)
    try:
        subj = req_obj.get("subject") or {}
        res = req_obj.get("resource") or {}
        req = PolicyRequest(
            subject=Subject(id=str(subj.get("id", "")), tenant=subj.get("tenant"), scopes=tuple(subj.get("scopes") or ())),
            action=str(req_obj.get("action")),
            resource=ResourceRef(type=str(res.get("type")), id=res.get("id"), attributes=res.get("attributes") or {}),
            context=req_obj.get("context") or {},
            request_id=req_obj.get("request_id"),
        )
    except Exception as e:
        _fatal(f"invalid request shape: {e}", EX_DATAERR)

    result = adapter.evaluate(req)
    sys.stdout.write(_json_dump(result) + "\n")
    return EX_OK

# ---------------------------------- Tracing demo command -------------------------------

def cmd_tracing(args: argparse.Namespace) -> int:
    env = _try_import_tracing()
    if not env:
        _fatal("module veilmind.telemetry.tracing is not available", EX_UNAVAILABLE)
    setup_tracing = env["setup_tracing"]; shutdown_tracing = env["shutdown_tracing"]
    start_span = env["start_span"]; install_logging_correlation = env["install_logging_correlation"]
    current_traceparent = env["current_traceparent"]; ensure_request_id = env["ensure_request_id"]
    instrument_requests = env["instrument_requests"]; instrument_httpx = env["instrument_httpx"]

    ok = setup_tracing(service_name=args.service, service_version=args.version, environment=args.environment, console_export=args.console, log_correlation=True)
    install_logging_correlation()

    # инструментируем опциональные клиенты, если пакеты установлены
    try:
        instrument_requests()
        instrument_httpx()
    except Exception:
        pass

    headers = {}
    ensure_request_id(headers)

    with start_span("cli.tracing.demo"):
        logging.info("tracing initialized ok=%s", ok)
        logging.info("traceparent=%s", current_traceparent())
        logging.info("request headers after inject: %s", headers)

    shutdown_tracing()
    return EX_OK

# ---------------------------------- GraphQL server command -----------------------------

def _install_signal_handlers(loop: Optional[asyncio.AbstractEventLoop] = None):
    def _graceful_exit(signum, frame):
        logging.info("received signal %s, shutting down", signum)
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        finally:
            os._exit(0)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _graceful_exit)
        except Exception:
            pass

def cmd_graphql(args: argparse.Namespace) -> int:
    create_app = _try_import_graphql_create_app()
    if not create_app:
        _fatal("GraphQL app factory not found (veilmind_core.api.graphql.server or veilmind.api.graphql.server)", EX_UNAVAILABLE)
    try:
        import uvicorn  # type: ignore
    except Exception:
        _fatal("uvicorn is not installed; cannot start ASGI server", EX_UNAVAILABLE)

    app = create_app(service=None)
    _install_signal_handlers()
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")  # type: ignore
    return EX_OK

# ---------------------------------- Argparse setup -------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="veilmind",
        description="Veilmind Core CLI: redact, risk scoring, policy evaluation, tracing, GraphQL server",
    )
    p.add_argument("-v", "--verbose", action="count", default=0, help="verbosity: -v info, -vv debug")
    p.add_argument("--json-logs", action="store_true", help="emit JSON logs to stderr")

    sub = p.add_subparsers(dest="cmd", required=True)

    # redact
    pr = sub.add_parser("redact", help="format-preserving pseudonymization of input text")
    pr.add_argument("-i", "--input", default="-", help="input file path or - for stdin")
    pr.add_argument("-o", "--output", default="-", help="output file path or - for stdout")
    pr.add_argument("--key", help="secret key for pseudonymization (or env FPR_KEY)")
    pr.add_argument("--only", help="comma list of rule names to apply: email,ipv4,uuid,iban,pan")
    pr.set_defaults(func=cmd_redact)

    # risk-score
    prs = sub.add_parser("risk-score", help="re-identification risk scoring for datasets")
    prs.add_argument("--input", required=True, help="path to CSV, JSONL or JSON array")
    prs.add_argument("--format", required=True, choices=["csv", "jsonl", "ndjson", "json"], help="input format")
    prs.add_argument("--qi", required=True, help="comma-separated quasi identifiers")
    prs.add_argument("--sa", help="comma-separated sensitive attributes")
    prs.add_argument("--generalize", action="append", help="column generalizers, e.g. age=bin:5, zip=str_lower, dob=date_trunc:month; can be repeated")
    prs.add_argument("--t-distance", default="tv", choices=["tv", "emd"], help="distance used in t-closeness")
    prs.add_argument("--out-scores", help="path to write per-record scores as JSONL")
    prs.add_argument("--verbose-explain", action="store_true", help="include explain payload in per-record scores")
    # weights and attacker models
    prs.add_argument("--w-attacker", type=float, default=0.7, help="weight of attacker risk")
    prs.add_argument("--w-ldiv", type=float, default=0.2, help="weight of l-diversity penalty")
    prs.add_argument("--w-tclose", type=float, default=0.1, help="weight of t-closeness penalty")
    prs.add_argument("--w-prosecutor", type=float, default=0.5, help="weight of prosecutor model inside attacker component")
    prs.add_argument("--w-journalist", type=float, default=0.3, help="weight of journalist model inside attacker component")
    prs.add_argument("--w-marketer", type=float, default=0.2, help="weight of marketer model inside attacker component")
    prs.add_argument("--marketer-sampling", type=float, default=0.1, help="sampling fraction for marketer model")
    prs.set_defaults(func=cmd_risk_score)

    # policy-eval
    pp = sub.add_parser("policy-eval", help="evaluate access policy for a single JSON request")
    pp.add_argument("--rules", help="path to JSON array of local rules")
    pp.add_argument("--pdp-url", help="remote PDP base URL (e.g. http://127.0.0.1:8181)")
    pp.add_argument("--pdp-package", default="veilmind.authz", help="PDP package for OPA (e.g. veilmind.authz)")
    pp.add_argument("--pdp-timeout", type=float, default=2.0, help="HTTP timeout seconds")
    pp.add_argument("--pdp-header", action="append", help="extra header k:v for PDP request; can be repeated")
    pp.add_argument("--input", required=True, help="path to policy request JSON (subject/action/resource/context)")
    pp.set_defaults(func=cmd_policy_eval)

    # tracing
    pt = sub.add_parser("tracing", help="initialize OpenTelemetry and emit a demo span")
    pt.add_argument("--service", default=os.getenv("OTEL_SERVICE_NAME", "veilmind-cli"), help="service.name resource")
    pt.add_argument("--version", default=os.getenv("APP_VERSION", "0.0.0"), help="service.version resource")
    pt.add_argument("--environment", default=os.getenv("ENVIRONMENT", "dev"), help="deployment.environment resource")
    pt.add_argument("--console", action="store_true", help="also export spans to console")
    pt.set_defaults(func=cmd_tracing)

    # graphql
    pg = sub.add_parser("start-graphql", help="start GraphQL ASGI server (requires uvicorn)")
    pg.add_argument("--host", default="0.0.0.0", help="bind host")
    pg.add_argument("--port", type=int, default=8000, help="bind port")
    pg.set_defaults(func=cmd_graphql)

    return p

# ---------------------------------------- Main ----------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.verbose, args.json_logs)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        logging.warning("interrupted by user")
        return EX_GENERAL
    except BrokenPipeError:
        # respect downstream pipe closures
        return EX_OK
    except SystemExit as e:
        raise
    except Exception as e:
        logging.exception("unhandled error: %s", e)
        return EX_SOFTWARE

if __name__ == "__main__":
    sys.exit(main())
