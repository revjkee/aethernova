#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
veilmind-core CLI admin tool (stdlib only)

Назначение:
  - Диагностика и канарейки (health, echo, chaos)
  - Синтетические решения/скоринг (/v1/synthetic/decision, /risk/score)
  - Отправка телеметрии (/v1/synthetic/telemetry/events)
  - Управление согласиями через GraphQL (/graphql get_consent/set_consent)
  - Валидация ConsentPolicy (policy-validate)
  - Генерация идентификаторов (idgen)

Особенности:
  - Без внешних зависимостей: argparse, urllib.request, ssl, json
  - TLS-проверка (по умолчанию включена), --insecure для тестов
  - Заголовки безопасности: X-Trace-Id, Idempotency-Key, Authorization: Bearer
  - Ретраи с экспоненциальной задержкой и джиттером, таймауты
  - Чтение JSON из файла или STDIN ("-")
  - Вывод JSON; YAML если установлен PyYAML
  - Нормализованные коды выхода:
      0 - успех; 2 - сетевые/HTTP ошибки; 3 - валидация входа; 4 - логика сервера (problem)
  - Максимально «шумонезависимый» вывод: только результат в выбранном формате, ошибки на STDERR

ENV (дефолты можно переопределить):
  VEILMIND_API_BASE=https://localhost:8443
  VEILMIND_TOKEN=<Bearer-token>
  VEILMIND_TIMEOUT=5.0
  VEILMIND_VERIFY_TLS=1

Примеры:
  python -m veilmind.cli.admin health --api-base https://core.local
  python -m veilmind.cli.admin decision --action write --resource-id file:1 --labels sensitivity=high --subject-privilege admin
  echo '{"events":[{"type":"audit","fields":{"x":1}}]}' | python -m veilmind.cli.admin telemetry -
  python -m veilmind.cli.admin consent-get --subject alice@example.com --purposes analytics ads
  python -m veilmind.cli.admin policy-validate configs/templates/consent_policy.example.yaml
  python -m veilmind.cli.admin idgen --what trace idempotency --hmac-secret secret --hmac-input alice@example.com
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import random
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

# --------------- Утилиты вывода ----------------

def _have_yaml() -> bool:
    try:
        import yaml  # type: ignore
        return True
    except Exception:
        return False

def _print_obj(obj: Any, fmt: str = "json") -> None:
    if fmt == "yaml" and _have_yaml():
        import yaml  # type: ignore
        sys.stdout.write(yaml.safe_dump(obj, allow_unicode=True, sort_keys=False))
        return
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, sort_keys=False, indent=2))
    sys.stdout.write("\n")

def _eprint(msg: str) -> None:
    sys.stderr.write(msg.rstrip() + "\n")

# --------------- HTTP обвязка ------------------

class HttpClient:
    def __init__(self, base_url: str, token: Optional[str], verify_tls: bool, timeout: float) -> None:
        self.base = base_url.rstrip("/")
        self.token = token
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.ctx = ssl.create_default_context()
        if not verify_tls:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def _build_url(self, path_or_url: str) -> str:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            return path_or_url
        return f"{self.base}{path_or_url if path_or_url.startswith('/') else '/' + path_or_url}"

    def _headers(self, extra: Optional[Mapping[str, str]] = None,
                 trace_id: Optional[str] = None, idem: Optional[str] = None) -> Dict[str, str]:
        h = {
            "Accept": "application/json",
            "User-Agent": "veilmind-admin-cli/1.0",
        }
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if trace_id:
            h["X-Trace-Id"] = trace_id
        if idem:
            h["Idempotency-Key"] = idem
        if extra:
            h.update({k: v for k, v in extra.items() if v is not None})
        return h

    def request(self, method: str, path_or_url: str, *,
                json_body: Optional[Any] = None,
                headers: Optional[Mapping[str, str]] = None,
                trace_id: Optional[str] = None,
                idem: Optional[str] = None,
                retries: int = 2,
                backoff_base: float = 0.2,
                backoff_max: float = 2.0) -> Tuple[int, Dict[str, str], Any]:
        url = self._build_url(path_or_url)
        data = None
        hdrs = self._headers(headers, trace_id, idem)
        if json_body is not None:
            data = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
            hdrs["Content-Type"] = "application/json; charset=utf-8"

        last_err: Optional[Exception] = None
        for attempt in range(retries + 1):
            req = urllib.request.Request(url=url, data=data, headers=hdrs, method=method.upper())
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                    status = int(resp.getcode())
                    raw = resp.read()
                    ctype = resp.headers.get("Content-Type", "")
                    body: Any
                    if "application/json" in ctype or (raw.startswith(b"{") or raw.startswith(b"[")):
                        try:
                            body = json.loads(raw.decode("utf-8") or "null")
                        except Exception:
                            body = {"raw": raw.decode("utf-8", "replace")}
                    else:
                        body = {"raw": raw.decode("utf-8", "replace")}
                    return status, dict(resp.headers.items()), body
            except urllib.error.HTTPError as e:
                try:
                    raw = e.read()
                    body = json.loads(raw.decode("utf-8") or "null")
                except Exception:
                    body = {"error": e.reason, "status": e.code}
                return int(e.code), dict(e.headers.items() if e.headers else {}), body
            except Exception as e:
                last_err = e
                if attempt >= retries:
                    break
                # backoff с джиттером
                sleep = min(backoff_max, backoff_base * (2 ** attempt)) * (0.5 + random.random() / 2.0)
                time.sleep(sleep)
                continue
        assert last_err is not None
        raise last_err

# --------------- Парсинг аргументов ----------

def _parse_labels(items: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for s in items:
        if "=" not in s:
            raise SystemExit(f"invalid label '{s}', expected key=value")
        k, v = s.split("=", 1)
        out[k.strip()] = v.strip()
    return out

def _load_json_stdin_or_file(path: str) -> Any:
    data = sys.stdin.read() if path == "-" else open(path, "rb").read()
    try:
        return json.loads(data.decode("utf-8"))
    except Exception as e:
        _eprint(f"Failed to parse JSON from {'STDIN' if path=='-' else path}: {e}")
        sys.exit(3)

def _gen_trace_id() -> str:
    return os.urandom(16).hex()

def _gen_idempotency() -> str:
    import uuid
    return str(uuid.uuid4())

def _hmac_sha256(secret: str, msg: str) -> str:
    return hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()

# --------------- Команды ---------------------

def cmd_health(cli: HttpClient, args: argparse.Namespace) -> int:
    status1, hdr1, body1 = cli.request("GET", "/v1/synthetic/healthz", trace_id=args.trace_id)
    status2, hdr2, body2 = cli.request("GET", "/v1/synthetic/readyz", trace_id=args.trace_id)
    out = {"healthz": {"status": status1, "body": body1}, "readyz": {"status": status2, "body": body2}}
    _print_obj(out, args.format)
    return 0 if status1 == 200 and status2 == 200 else 2

def _subject_dict(args: argparse.Namespace) -> Dict[str, Any]:
    user: Dict[str, Any] = {}
    if args.subject_user: user.update({"id": args.subject_user})
    if args.subject_privilege: user.update({"privilege": args.subject_privilege})
    device: Dict[str, Any] = {}
    if args.device_id: device.update({"id": args.device_id})
    session: Dict[str, Any] = {}
    if args.session_id: session.update({"id": args.session_id})
    out: Dict[str, Any] = {}
    if user: out["user"] = user
    if device: out["device"] = device
    if session: out["session"] = session
    return out

def _environment_dict(args: argparse.Namespace) -> Dict[str, Any]:
    env: Dict[str, Any] = {}
    if args.ip: env["ip"] = args.ip
    if args.geo: env["geo"] = args.geo
    if args.asn is not None: env["asn"] = args.asn
    if args.user_agent: env["userAgent"] = args.user_agent
    return env

def _signals_dict(args: argparse.Namespace) -> Dict[str, Any]:
    sig = {}
    if args.idp_risk is not None:
        sig.setdefault("idp", {})["risk_score"] = float(args.idp_risk)
    if args.ti_score is not None:
        sig.setdefault("threat_intel", {})["score"] = float(args.ti_score)
    if args.posture_score is not None:
        sig.setdefault("posture", {})["score"] = float(args.posture_score)
    return sig

def cmd_decision(cli: HttpClient, args: argparse.Namespace) -> int:
    if args.body:
        payload = _load_json_stdin_or_file(args.body)
    else:
        payload = {
            "subject": _subject_dict(args),
            "action": args.action,
            "resource": {"id": args.resource_id, "labels": _parse_labels(args.labels or [])},
            "environment": _environment_dict(args),
            "context": {"signals": _signals_dict(args)} if any([args.idp_risk, args.ti_score, args.posture_score]) else None,
            "idempotencyKey": args.idempotency_key,
        }
    status, hdrs, body = cli.request("POST", "/v1/synthetic/decision", json_body=payload,
                                     trace_id=args.trace_id, idem=args.idempotency_key, retries=args.retries)
    _print_obj({"status": status, "headers": {"X-Trace-Id": hdrs.get("X-Trace-Id"), "Idempotency-Key": hdrs.get("Idempotency-Key")}, "body": body},
               args.format)
    return 0 if status in (200, 201) else (4 if isinstance(body, dict) and body.get("title") else 2)

def cmd_risk(cli: HttpClient, args: argparse.Namespace) -> int:
    if args.body:
        payload = _load_json_stdin_or_file(args.body)
    else:
        payload = {
            "subject": _subject_dict(args),
            "action": args.action,
            "resource": {"id": args.resource_id, "labels": _parse_labels(args.labels or [])} if args.resource_id or args.labels else None,
            "environment": _environment_dict(args),
            "signals": _signals_dict(args),
        }
    status, hdrs, body = cli.request("POST", "/v1/synthetic/risk/score", json_body=payload,
                                     trace_id=args.trace_id, retries=args.retries)
    _print_obj({"status": status, "body": body}, args.format)
    return 0 if status in (200, 201) else 2

def cmd_telemetry(cli: HttpClient, args: argparse.Namespace) -> int:
    payload = _load_json_stdin_or_file(args.body)
    status, hdrs, body = cli.request("POST", "/v1/synthetic/telemetry/events", json_body=payload,
                                     trace_id=args.trace_id, retries=args.retries)
    _print_obj({"status": status, "body": body}, args.format)
    return 0 if status in (200, 202) else 2

def cmd_echo(cli: HttpClient, args: argparse.Namespace) -> int:
    if args.method.upper() == "GET":
        qs = {}
        if args.delay_ms is not None: qs["delay_ms"] = str(args.delay_ms)
        if args.status_code is not None: qs["status_code"] = str(args.status_code)
        url = "/v1/synthetic/echo?" + urllib.parse.urlencode(qs) if qs else "/v1/synthetic/echo"
        status, hdrs, body = cli.request("GET", url, trace_id=args.trace_id, retries=args.retries)
    else:
        body_in = None
        if args.body:
            body_in = _load_json_stdin_or_file(args.body)
        status, hdrs, body = cli.request("POST", "/v1/synthetic/echo",
                                         json_body=body_in, trace_id=args.trace_id, retries=args.retries)
    _print_obj({"status": status, "body": body}, args.format)
    return 0 if status in (200, 204) else 2

def cmd_chaos(cli: HttpClient, args: argparse.Namespace) -> int:
    qs = {"kind": args.kind}
    if args.ms is not None: qs["ms"] = str(args.ms)
    if args.code is not None: qs["code"] = str(args.code)
    url = "/v1/synthetic/chaos?" + urllib.parse.urlencode(qs)
    status, hdrs, body = cli.request("GET", url, trace_id=args.trace_id, retries=args.retries)
    _print_obj({"status": status, "body": body}, args.format)
    return 0 if (status in (200, 500) and body) else 2

# ----------------- GraphQL (consent) -----------------

def _graphql(cli: HttpClient, query: str, variables: Optional[Dict[str, Any]], args: argparse.Namespace) -> Tuple[int, Any]:
    payload = {"query": query, "variables": variables or {}}
    status, hdrs, body = cli.request("POST", "/graphql", json_body=payload,
                                     trace_id=args.trace_id, retries=args.retries)
    return status, body

def cmd_consent_get(cli: HttpClient, args: argparse.Namespace) -> int:
    query = """
    query GetConsent($subject_id: String!, $purposes: [String!]) {
      get_consent(subjectId: $subject_id, purposes: $purposes) {
        __typename
        ... on ConsentKV { purpose state }
        ... on Problem { title status detail traceId }
      }
    }"""
    vars = {"subject_id": args.subject, "purposes": args.purposes or None}
    status, body = _graphql(cli, query, vars, args)
    if status != 200:
        _print_obj({"status": status, "body": body}, args.format)
        return 2
    # Strawberry возвращает список или Problem; нормализуем
    data = body.get("data", {}).get("get_consent")
    out = {"status": 200, "consent": data}
    _print_obj(out, args.format)
    return 0

def cmd_consent_set(cli: HttpClient, args: argparse.Namespace) -> int:
    query = """
    mutation SetConsent($input: ConsentSetInput!) {
      set_consent(input: $input) {
        __typename
        ... on ConsentKV { purpose state }
        ... on Problem { title status detail traceId }
      }
    }"""
    # changes: key=value ...
    changes = _parse_labels(args.changes or [])
    evidence = _parse_labels(args.evidence or [])
    vars = {"input": {"subjectId": args.subject, "changes": changes, "evidence": evidence or None}}
    status, body = _graphql(cli, query, vars, args)
    if status != 200:
        _print_obj({"status": status, "body": body}, args.format)
        return 2
    data = body.get("data", {}).get("set_consent")
    out = {"status": 200, "updated": data}
    _print_obj(out, args.format)
    return 0

# ----------------- ConsentPolicy validation -----------

def _load_yaml_or_json(path: str) -> Any:
    raw = sys.stdin.read() if path == "-" else open(path, "rb").read()
    text = raw.decode("utf-8")
    # Пытаемся YAML (если есть PyYAML), иначе JSON
    if _have_yaml():
        import yaml  # type: ignore
        try:
            return yaml.safe_load(text)
        except Exception as e:
            _eprint(f"YAML parse failed, trying JSON: {e}")
    return json.loads(text)

def _policy_validate(obj: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if not isinstance(obj, dict):
        return ["policy must be an object"]
    if obj.get("apiVersion") != "veilmind.io/v1":
        errors.append("apiVersion must be 'veilmind.io/v1'")
    if obj.get("kind") != "ConsentPolicy":
        errors.append("kind must be 'ConsentPolicy'")
    spec = obj.get("spec")
    if not isinstance(spec, dict):
        errors.append("spec must be an object")
        return errors
    purposes = spec.get("purposes")
    if not isinstance(purposes, list) or not purposes:
        errors.append("spec.purposes must be a non-empty list")
    else:
        ids = []
        for i, p in enumerate(purposes):
            if not isinstance(p, dict):
                errors.append(f"spec.purposes[{i}] must be an object")
                continue
            pid = p.get("id")
            if not pid or not isinstance(pid, str):
                errors.append(f"spec.purposes[{i}].id must be a non-empty string")
            else:
                ids.append(pid)
            st = p.get("defaultState", "deny")
            if st not in ("allow", "deny", "prompt"):
                errors.append(f"spec.purposes[{i}].defaultState invalid: {st}")
        if len(ids) != len(set(ids)):
            errors.append("spec.purposes ids must be unique")
    # jurisdictions optional: check code strings
    jurs = spec.get("jurisdictions", [])
    if jurs and not isinstance(jurs, list):
        errors.append("spec.jurisdictions must be a list")
    # evaluation defaults
    evals = spec.get("evaluation", {})
    if evals and not isinstance(evals, dict):
        errors.append("spec.evaluation must be an object")
    return errors

def cmd_policy_validate(_: HttpClient, args: argparse.Namespace) -> int:
    try:
        obj = _load_yaml_or_json(args.file)
    except Exception as e:
        _eprint(f"Failed to load policy: {e}")
        return 3
    errs = _policy_validate(obj)
    out = {"valid": not errs, "errors": errs, "purposes": [p.get("id") for p in obj.get("spec", {}).get("purposes", [])] if isinstance(obj, dict) else []}
    _print_obj(out, args.format)
    return 0 if not errs else 4

# ----------------- ID generation ----------------------

def cmd_idgen(_: HttpClient, args: argparse.Namespace) -> int:
    res: Dict[str, Any] = {}
    if "trace" in args.what:
        res["trace_id"] = args.trace_id or _gen_trace_id()
    if "idempotency" in args.what:
        res["idempotency_key"] = args.idempotency_key or _gen_idempotency()
    if args.hmac_secret and args.hmac_input:
        res["hmac_sha256"] = _hmac_sha256(args.hmac_secret, args.hmac_input)
    _print_obj(res, args.format)
    return 0

# --------------- Главный парсер ----------------------

def _common_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--api-base", default=os.getenv("VEILMIND_API_BASE", "https://localhost:8443"), help="Base URL, e.g. https://core.local")
    p.add_argument("--token", default=os.getenv("VEILMIND_TOKEN"), help="Bearer token")
    p.add_argument("--timeout", type=float, default=float(os.getenv("VEILMIND_TIMEOUT", "5.0")), help="HTTP timeout seconds")
    p.add_argument("--insecure", action="store_true", default=(os.getenv("VEILMIND_VERIFY_TLS", "1") == "0"), help="Disable TLS verification")
    p.add_argument("--trace-id", default=None, help="X-Trace-Id header")
    p.add_argument("--idempotency-key", default=None, help="Idempotency-Key header")
    p.add_argument("--retries", type=int, default=2, help="Network retries")
    p.add_argument("--format", choices=["json", "yaml"], default="json", help="Output format (yaml requires PyYAML)")

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="veilmind-admin", description="veilmind-core administrative CLI")
    sub = ap.add_subparsers(dest="cmd", required=True)

    # health
    p = sub.add_parser("health", help="Liveness/readiness probes")
    _common_args(p)
    p.set_defaults(func=cmd_health)

    # decision
    p = sub.add_parser("decision", help="Synthetic PEP decision")
    _common_args(p)
    p.add_argument("--action", choices=["read","list","write","delete","admin"], required=False, default="read")
    p.add_argument("--resource-id", default=None)
    p.add_argument("--labels", nargs="*", help="key=value ...")
    # subject
    p.add_argument("--subject-user", default=None)
    p.add_argument("--subject-privilege", choices=["admin","ops","user"], default=None)
    p.add_argument("--device-id", default=None)
    p.add_argument("--session-id", default=None)
    # env
    p.add_argument("--ip", default=None); p.add_argument("--geo", default=None)
    p.add_argument("--asn", type=int, default=None); p.add_argument("--user-agent", default=None)
    # signals
    p.add_argument("--idp-risk", type=float, default=None)
    p.add_argument("--ti-score", type=float, default=None)
    p.add_argument("--posture-score", type=float, default=None)
    # raw body
    p.add_argument("--body", default=None, help='JSON file path or "-" for STDIN')
    p.set_defaults(func=cmd_decision)

    # risk-score
    p = sub.add_parser("risk-score", help="Synthetic risk scoring")
    _common_args(p)
    p.add_argument("--action", choices=["read","list","write","delete","admin"], default=None)
    p.add_argument("--resource-id", default=None)
    p.add_argument("--labels", nargs="*", help="key=value ...")
    p.add_argument("--subject-user", default=None)
    p.add_argument("--subject-privilege", choices=["admin","ops","user"], default=None)
    p.add_argument("--device-id", default=None)
    p.add_argument("--session-id", default=None)
    p.add_argument("--ip", default=None); p.add_argument("--geo", default=None); p.add_argument("--asn", type=int, default=None)
    p.add_argument("--user-agent", default=None)
    p.add_argument("--idp-risk", type=float, default=None)
    p.add_argument("--ti-score", type=float, default=None)
    p.add_argument("--posture-score", type=float, default=None)
    p.add_argument("--body", default=None, help='JSON file path or "-" for STDIN')
    p.set_defaults(func=cmd_risk)

    # telemetry
    p = sub.add_parser("telemetry", help="Send telemetry batch")
    _common_args(p)
    p.add_argument("body", help='JSON file path or "-" for STDIN')
    p.set_defaults(func=cmd_telemetry)

    # echo
    p = sub.add_parser("echo", help="Echo endpoint for testing")
    _common_args(p)
    p.add_argument("--method", choices=["GET","POST"], default="GET")
    p.add_argument("--delay-ms", type=int, default=None)
    p.add_argument("--status-code", type=int, default=None)
    p.add_argument("--body", default=None, help='JSON file path or "-" for STDIN (POST)')
    p.set_defaults(func=cmd_echo)

    # chaos
    p = sub.add_parser("chaos", help="Chaos endpoint (latency/error/jitter)")
    _common_args(p)
    p.add_argument("--kind", choices=["latency","error","jitter"], default="latency")
    p.add_argument("--ms", type=int, default=250)
    p.add_argument("--code", type=int, default=500)
    p.set_defaults(func=cmd_chaos)

    # consent-get
    p = sub.add_parser("consent-get", help="Get consent state (GraphQL)")
    _common_args(p)
    p.add_argument("--subject", required=True)
    p.add_argument("--purposes", nargs="*", help="List of purposes (optional)")
    p.set_defaults(func=cmd_consent_get)

    # consent-set
    p = sub.add_parser("consent-set", help="Set consent state (GraphQL)")
    _common_args(p)
    p.add_argument("--subject", required=True)
    p.add_argument("--changes", nargs="*", required=True, help="purpose=allow|deny ...")
    p.add_argument("--evidence", nargs="*", help="key=value evidence")
    p.set_defaults(func=cmd_consent_set)

    # policy-validate
    p = sub.add_parser("policy-validate", help="Validate ConsentPolicy YAML/JSON")
    _common_args(p)
    p.add_argument("file", help='Path to policy file or "-" for STDIN')
    p.set_defaults(func=cmd_policy_validate)

    # idgen
    p = sub.add_parser("idgen", help="Generate identifiers and HMAC")
    _common_args(p)
    p.add_argument("--what", nargs="+", choices=["trace","idempotency"], default=["trace","idempotency"])
    p.add_argument("--hmac-secret", default=None)
    p.add_argument("--hmac-input", default=None)
    p.set_defaults(func=cmd_idgen)

    return ap

def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cli = HttpClient(base_url=args.api_base, token=args.token, verify_tls=not args.insecure, timeout=args.timeout)
    # Автогенерация trace/idempotency при необходимости
    if getattr(args, "trace_id", None) is None and args.cmd in ("decision","risk-score","telemetry","echo","chaos","consent-get","consent-set"):
        args.trace_id = _gen_trace_id()
    if getattr(args, "idempotency_key", None) is None and args.cmd in ("decision",):
        args.idempotency_key = _gen_idempotency()
    try:
        return args.func(cli, args)  # type: ignore[attr-defined]
    except KeyboardInterrupt:
        _eprint("Interrupted")
        return 130
    except Exception as e:
        _eprint(f"Error: {e}")
        return 2

if __name__ == "__main__":
    sys.exit(main())
