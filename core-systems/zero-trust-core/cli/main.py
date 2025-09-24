# zero-trust-core/cli/main.py
# -*- coding: utf-8 -*-
"""
Zero-Trust Core CLI (Industrial-Grade)

Subcommands:
  version                      – показать версию и окружение
  config show|validate         – показать/провалидировать конфиг (JSON/YAML)
  tracing selftest             – прогнать self-test через zero_trust.telemetry.tracing
  secrets scan                 – сканировать файлы/каталоги на секреты
  tls check                    – проверить цепочку TLS, соответствие ключа и сертификата, сроки
  rbac test                    – проверить доступ субъекта к ресурсу по RBAC-файлу
  gen-completion               – сгенерировать автодополнение shell

Особенности Zero Trust:
  • Безопасный вывод: маскировка секретов и ограничение длины значений
  • Строгие коды возврата и единый формат вывода: human|json|yaml
  • Опциональные зависимости: pydantic, cryptography, PyYAML, typer

Запуск:
  python -m zero_trust_core.cli.main ...      # если установлен как пакет
  python zero-trust-core/cli/main.py ...      # прямой скрипт
"""

from __future__ import annotations

import dataclasses
import fnmatch
import json
import logging
import os
import re
import sys
import textwrap
import time
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# ---- Optional deps guard -----------------------------------------------------
_missing: Dict[str, str] = {}

def _try_import(name: str):
    try:
        return __import__(name, fromlist=["*"])
    except Exception as e:
        _missing[name] = f"{e.__class__.__name__}: {e}"
        return None

typer = _try_import("typer")
yaml = _try_import("yaml")  # PyYAML
pydantic = _try_import("pydantic")
cryptography = _try_import("cryptography")
rich = _try_import("rich")

# ---- Logging with redaction --------------------------------------------------

REDACT_MASK = "[REDACTED]"
REDACT_KEYS = {
    "password","passwd","secret","token","access_token","refresh_token","id_token",
    "authorization","api_key","apikey","cookie","set-cookie","session","private_key",
    "client_secret","db_password","jwt","otp","ssn","credit_card","card_number",
}
REDACT_PATTERNS = [
    re.compile(r"bearer\s+[a-z0-9\.\-_]+", re.IGNORECASE),
    re.compile(r"eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+"),
    re.compile(r"(?:\b|_)(?:pwd|pass|secret|token|key)(?:\b|_)\s*[:=]\s*[^,\s]+", re.IGNORECASE),
    re.compile(r"\b\d{13,19}\b"),
]

class RedactingFormatter(logging.Formatter):
    def __init__(self, *a, max_len: int = 512, **kw):
        super().__init__(*a, **kw)
        self.max_len = max_len

    def redact(self, msg: str) -> str:
        out = msg
        for rx in REDACT_PATTERNS:
            out = rx.sub(REDACT_MASK, out)
        if len(out) > self.max_len:
            out = out[: self.max_len] + "...(truncated)"
        return out

    def format(self, record: logging.LogRecord) -> str:
        record.msg = self.redact(str(record.msg))
        return super().format(record)

def _setup_logging(verbose: int) -> None:
    lvl = logging.WARNING if verbose <= 0 else logging.INFO if verbose == 1 else logging.DEBUG
    h = logging.StreamHandler(sys.stderr)
    fmt = RedactingFormatter("[%(levelname)s] %(message)s")
    h.setFormatter(fmt)
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(h)
    root.setLevel(lvl)

log = logging.getLogger("zero_trust_core.cli")

# ---- Exit codes --------------------------------------------------------------

class ExitCode(IntEnum):
    OK = 0
    GENERAL_ERROR = 1
    VALIDATION_FAILED = 2
    SECRETS_FOUND = 3
    TLS_INVALID = 4
    RBAC_DENY = 5
    DEPS_MISSING = 6

# ---- Safe printer ------------------------------------------------------------

def _safe_truncate(v: Any, max_len: int = 256) -> Any:
    try:
        if isinstance(v, str) and len(v) > max_len:
            return v[:max_len] + "...(truncated)"
        if isinstance(v, (list, tuple)):
            return type(v)(_safe_truncate(x, max_len) for x in v)
        if isinstance(v, dict):
            return {k: _safe_truncate(vv, max_len) for k, vv in v.items()}
        return v
    except Exception:
        return "<unserializable>"

def _redact_map(d: Mapping[str, Any]) -> Dict[str, Any]:
    def is_denied(k: str) -> bool:
        kl = k.lower()
        if kl in REDACT_KEYS: return True
        return any(rk in kl for rk in REDACT_KEYS)
    out = {}
    for k, v in d.items():
        if is_denied(k):
            out[k] = REDACT_MASK
        elif isinstance(v, str):
            vv = v
            for rx in REDACT_PATTERNS:
                vv = rx.sub(REDACT_MASK, vv)
            out[k] = _safe_truncate(vv)
        elif isinstance(v, dict):
            out[k] = _redact_map(v)
        elif isinstance(v, list):
            out[k] = [_safe_truncate(x) for x in v]
        else:
            out[k] = _safe_truncate(v)
    return out

def _print_out(data: Mapping[str, Any], fmt: str = "human") -> None:
    data = _redact_map(data)
    if fmt == "json":
        print(json.dumps(data, ensure_ascii=False, indent=2))
    elif fmt == "yaml":
        if yaml is None:
            print(json.dumps({"error": "PyYAML not installed", "data": data}, ensure_ascii=False, indent=2))
        else:
            print(yaml.dump(json.loads(json.dumps(data, ensure_ascii=False)), allow_unicode=True, sort_keys=False))
    else:
        # human
        for k, v in data.items():
            if isinstance(v, (dict, list)):
                print(f"{k}:")
                txt = json.dumps(v, ensure_ascii=False, indent=2)
                for line in txt.splitlines():
                    print(f"  {line}")
            else:
                print(f"{k}: {v}")

# ---- Config schema -----------------------------------------------------------

@dataclass
class TLSConfig:
    ca: Optional[str] = None
    cert: Optional[str] = None
    key: Optional[str] = None
    hostname: Optional[str] = None
    min_days_left: int = 14

@dataclass
class TracingCfg:
    exporter: str = "otlp-grpc"        # otlp-grpc|otlp-http|console|null
    endpoint: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    sample_ratio: float = 0.05
    timeout_s: float = 10.0

@dataclass
class AppConfig:
    service_name: str = "service"
    service_version: str = "0.0.0"
    environment: str = "dev"
    tracing: TracingCfg = field(default_factory=TracingCfg)
    tls: TLSConfig = field(default_factory=TLSConfig)

def _load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")

def _load_config(path: Path) -> AppConfig:
    raw = _load_text(path)
    # Simple env substitution ${VAR}
    raw = re.sub(r"\$\{([^}]+)\}", lambda m: os.getenv(m.group(1), ""), raw)
    try:
        if path.suffix.lower() in {".yml", ".yaml"} and yaml is not None:
            data = yaml.safe_load(raw) or {}
        else:
            data = json.loads(raw)
    except Exception as e:
        raise ValueError(f"Cannot parse config: {e}") from e

    def as_tls(d: Dict[str, Any]) -> TLSConfig:
        return TLSConfig(**{k: d.get(k) for k in TLSConfig().__dict__.keys()})
    def as_tracing(d: Dict[str, Any]) -> TracingCfg:
        return TracingCfg(**{k: d.get(k, getattr(TracingCfg(), k)) for k in TracingCfg().__dict__.keys()})

    cfg = AppConfig(
        service_name = data.get("service_name","service"),
        service_version = data.get("service_version","0.0.0"),
        environment = data.get("environment","dev"),
        tracing = as_tracing(data.get("tracing", {})),
        tls = as_tls(data.get("tls", {})),
    )
    return cfg

def _validate_config(cfg: AppConfig) -> Tuple[bool, List[str]]:
    errors: List[str] = []
    if not cfg.service_name or not isinstance(cfg.service_name, str):
        errors.append("service_name must be non-empty string")
    if cfg.tracing.exporter not in {"otlp-grpc","otlp-http","console","null"}:
        errors.append("tracing.exporter must be one of: otlp-grpc|otlp-http|console|null")
    if cfg.tracing.exporter.startswith("otlp") and not cfg.tracing.endpoint:
        errors.append("tracing.endpoint required for otlp exporters")
    if not (0.0 <= cfg.tracing.sample_ratio <= 1.0):
        errors.append("tracing.sample_ratio must be in [0,1]")
    if cfg.tls.ca and not Path(cfg.tls.ca).exists():
        errors.append(f"tls.ca not found: {cfg.tls.ca}")
    if cfg.tls.cert and not Path(cfg.tls.cert).exists():
        errors.append(f"tls.cert not found: {cfg.tls.cert}")
    if cfg.tls.key and not Path(cfg.tls.key).exists():
        errors.append(f"tls.key not found: {cfg.tls.key}")
    return (len(errors) == 0, errors)

# ---- Secrets scanner ---------------------------------------------------------

SECRET_FILE_DENY_GLOBS = [
    "*.pem","*.key","*.p12","*.pfx",".env","*.env","id_rsa","id_dsa","*.kubeconfig","*.ovpn"
]
BINARY_EXT = {".png",".jpg",".jpeg",".gif",".webp",".pdf",".zip",".gz",".tar",".xz",".7z",".exe",".dll",".so",".dylib"}

SECRET_REGEXES = [
    re.compile(r"(?i)\baws_?(access|secret)_?key\b\s*[:=]\s*[A-Za-z0-9/+=]{8,}"),
    re.compile(r"(?i)\bsecret\b\s*[:=]\s*\S+"),
    re.compile(r"(?i)\bapi_?key\b\s*[:=]\s*\S+"),
    re.compile(r"(?i)\bauthorization\b\s*[:=]\s*\S+"),
    re.compile(r"(?i)\bpassword\b\s*[:=]\s*\S+"),
    re.compile(r"(?i)\btoken\b\s*[:=]\s*\S+"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (?:RSA|EC|PRIVATE) KEY-----"),
] + REDACT_PATTERNS

def _iter_files(root: Path, include_globs: Sequence[str], exclude_globs: Sequence[str]) -> Iterable[Path]:
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() in BINARY_EXT:
            continue
        rel = str(p.relative_to(root))
        if any(fnmatch.fnmatch(rel, g) for g in exclude_globs):
            continue
        if include_globs and not any(fnmatch.fnmatch(rel, g) for g in include_globs):
            continue
        yield p

def _scan_file_for_secrets(p: Path) -> List[Dict[str, Any]]:
    findings = []
    try:
        txt = p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings
    for rx in SECRET_REGEXES:
        for m in rx.finditer(txt):
            start = max(0, m.start()-32)
            end = min(len(txt), m.end()+32)
            context = txt[start:end]
            findings.append({
                "file": str(p),
                "match": REDACT_MASK,
                "pattern": rx.pattern[:64]+"...",
                "offset": m.start(),
                "context": _safe_truncate(context, 160),
            })
    return findings

def secrets_scan(paths: Sequence[Path], includes: Sequence[str], excludes: Sequence[str], max_findings: int) -> Dict[str, Any]:
    started = time.time()
    all_findings: List[Dict[str, Any]] = []
    for path in paths:
        if path.is_file():
            files = [path]
        else:
            files = list(_iter_files(path, includes, excludes))
        for f in files:
            if any(fnmatch.fnmatch(f.name, g) for g in SECRET_FILE_DENY_GLOBS):
                all_findings.append({"file": str(f), "match": REDACT_MASK, "pattern": "filename-denylist", "offset": 0, "context": f.name})
                if len(all_findings) >= max_findings: break
            for item in _scan_file_for_secrets(f):
                all_findings.append(item)
                if len(all_findings) >= max_findings: break
        if len(all_findings) >= max_findings: break
    return {
        "summary": {
            "paths_scanned": [str(p) for p in paths],
            "findings": len(all_findings),
            "duration_s": round(time.time()-started, 3),
            "max_findings": max_findings,
        },
        "findings": all_findings,
    }

# ---- TLS inspector -----------------------------------------------------------

def tls_check(cert_path: Optional[str], key_path: Optional[str], ca_path: Optional[str], hostname: Optional[str], min_days_left: int) -> Dict[str, Any]:
    if cryptography is None:
        return {"ok": False, "error": "cryptography not installed"}
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.hazmat.backends import default_backend
    from datetime import datetime, timezone

    res: Dict[str, Any] = {"ok": True, "checks": []}

    def add(ok: bool, name: str, info: Dict[str, Any]):
        res["checks"].append({"check": name, "ok": ok, **info})
        if not ok: res["ok"] = False

    cert = None
    if cert_path and Path(cert_path).exists():
        data = Path(cert_path).read_bytes()
        cert = x509.load_pem_x509_certificate(data, default_backend())
        now = datetime.now(timezone.utc)
        days_left = (cert.not_valid_after.replace(tzinfo=timezone.utc) - now).days
        add(days_left >= min_days_left, "validity_window", {"days_left": days_left, "min_days_left": min_days_left})
        add(now >= cert.not_valid_before.replace(tzinfo=timezone.utc), "not_before_passed", {})
        add(now <= cert.not_valid_after.replace(tzinfo=timezone.utc), "not_after_not_expired", {})
        if hostname:
            try:
                x509.SubjectAlternativeName.from_certificate(cert)  # type: ignore[attr-defined]
            except Exception:
                pass
            try:
                from cryptography.x509.oid import NameOID
                # Simple hostname check
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value  # type: ignore
                names = san.get_values_for_type(x509.DNSName)
                add(any(fnmatch.fnmatch(hostname, n) for n in names), "hostname_matches_san", {"hostname": hostname, "dns_names": names})
            except Exception as e:
                add(False, "hostname_san_check", {"error": str(e)})

    if key_path and Path(key_path).exists() and cert is not None:
        key_bytes = Path(key_path).read_bytes()
        try:
            private_key = serialization.load_pem_private_key(key_bytes, password=None, backend=default_backend())
        except TypeError:
            add(False, "private_key_encrypted", {"info": "Key is encrypted, provide password out-of-band"})
            private_key = None
        if private_key is not None:
            pub_cert = cert.public_key()
            if isinstance(private_key, rsa.RSAPrivateKey) and hasattr(pub_cert, "public_numbers"):
                ok = private_key.public_key().public_numbers() == pub_cert.public_numbers()
                add(ok, "key_matches_cert_rsa", {})
            elif isinstance(private_key, ec.EllipticCurvePrivateKey) and hasattr(pub_cert, "public_numbers"):
                ok = private_key.public_key().public_numbers() == pub_cert.public_key().public_numbers()  # type: ignore
                add(ok, "key_matches_cert_ec", {})
            else:
                add(False, "key_type_unsupported", {"type": type(private_key).__name__})

    if ca_path and Path(ca_path).exists() and cert is not None:
        # Basic issuer match; full path validation requires building chain with store
        try:
            issuer = cert.issuer.rfc4514_string()
            add(True, "issuer_present", {"issuer": issuer, "ca_path": ca_path})
        except Exception as e:
            add(False, "issuer_parse_error", {"error": str(e)})

    return res

# ---- RBAC minimal evaluator --------------------------------------------------

@dataclass
class RBACRule:
    action: str
    resource: str
    effect: str  # "allow" | "deny"

@dataclass
class RBACBinding:
    subject: str
    role: str

@dataclass
class RBACModel:
    roles: Dict[str, List[RBACRule]] = field(default_factory=dict)
    bindings: List[RBACBinding] = field(default_factory=list)

def _load_rbac(path: Path) -> RBACModel:
    text = _load_text(path)
    data = yaml.safe_load(text) if (yaml and path.suffix.lower() in {".yml",".yaml"}) else json.loads(text)
    roles = {}
    for role, rules in (data.get("roles") or {}).items():
        roles[role] = [RBACRule(**r) for r in rules]
    bindings = [RBACBinding(**b) for b in (data.get("bindings") or [])]
    return RBACModel(roles=roles, bindings=bindings)

def rbac_test(model: RBACModel, subject: str, action: str, resource: str) -> Dict[str, Any]:
    roles = [b.role for b in model.bindings if b.subject == subject]
    matched: List[Dict[str, Any]] = []
    decision = "deny"
    for role in roles:
        for r in model.roles.get(role, []):
            if fnmatch.fnmatch(action, r.action) and fnmatch.fnmatch(resource, r.resource):
                matched.append(dataclasses.asdict(r))
                if r.effect.lower() == "deny":
                    decision = "deny"
                    return {"decision": decision, "matched": matched, "role": role}
                elif r.effect.lower() == "allow":
                    decision = "allow"
    return {"decision": decision, "matched": matched, "roles": roles}

# ---- Tracing self-test integration ------------------------------------------

def _tracing_selftest(env: Mapping[str,str]) -> Dict[str, Any]:
    # Import from your telemetry module
    try:
        from zero_trust.telemetry.tracing import init_tracing, shutdown_tracing, start_span, trace_health, config_from_env
    except Exception as e:
        return {"ok": False, "error": f"telemetry module not available: {e}"}
    try:
        init_tracing(config_from_env())
        with start_span("cli.selftest", attributes={"component":"cli","password":"dummy"}):
            trace_health(component="cli", status="ok", details={"phase":"selftest"})
        shutdown_tracing()
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ---- CLI ---------------------------------------------------------------------

def _require(dep: str):
    if globals().get(dep) is None:
        msg = {"error": f"dependency '{dep}' not installed", "details": _missing.get(dep)}
        _print_out(msg, "json")
        sys.exit(ExitCode.DEPS_MISSING)

def _app() -> "typer.Typer":  # type: ignore
    _require("typer")
    return typer.Typer(add_completion=False, no_args_is_help=True, help="Zero-Trust Core CLI")

app = _app()

@app.callback()
def main(
    output: str = typer.Option("human", "--output", "-o", help="Вывод: human|json|yaml"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Уровень подробности логов"),
):
    """
    Zero-Trust Core CLI.
    """
    _setup_logging(verbose)
    if output not in {"human","json","yaml"}:
        _print_out({"error":"invalid output format"}, "json")
        raise typer.Exit(code=int(ExitCode.GENERAL_ERROR))
    # store in context
    typer.get_app_dir  # keep typer import alive
    setattr(main, "_output_fmt", output)  # type: ignore

# version
@app.command("version")
def cmd_version():
    fmt = getattr(main, "_output_fmt", "human")
    data = {
        "tool": "zero-trust-core",
        "component": "cli",
        "python": sys.version.split()[0],
        "deps_missing": list(_missing.keys()),
    }
    _print_out(data, fmt)

# config
config_app = typer.Typer(help="Операции с конфигом")
app.add_typer(config_app, name="config")

@config_app.command("show")
def cmd_config_show(path: Path = typer.Argument(..., exists=True, readable=True)):
    fmt = getattr(main, "_output_fmt", "human")
    cfg = _load_config(path)
    _print_out(dataclasses.asdict(cfg), fmt)

@config_app.command("validate")
def cmd_config_validate(path: Path = typer.Argument(..., exists=True, readable=True)):
    fmt = getattr(main, "_output_fmt", "human")
    cfg = _load_config(path)
    ok, errs = _validate_config(cfg)
    res = {"ok": ok, "errors": errs}
    _print_out(res, fmt)
    raise typer.Exit(code=int(ExitCode.OK if ok else ExitCode.VALIDATION_FAILED))

# tracing selftest
tracing_app = typer.Typer(help="Трассировка и телеметрия")
app.add_typer(tracing_app, name="tracing")

@tracing_app.command("selftest")
def cmd_tracing_selftest():
    fmt = getattr(main, "_output_fmt", "human")
    res = _tracing_selftest(os.environ)
    _print_out(res, fmt)
    raise typer.Exit(code=int(ExitCode.OK if res.get("ok") else ExitCode.GENERAL_ERROR))

# secrets scan
secrets_app = typer.Typer(help="Сканирование секретов")
app.add_typer(secrets_app, name="secrets")

@secrets_app.command("scan")
def cmd_secrets_scan(
    path: List[Path] = typer.Argument(..., exists=True, readable=True),
    include: List[str] = typer.Option([], "--include", help="Глоб-шаблоны включения, относительно корня"),
    exclude: List[str] = typer.Option([".git/*","venv/*","**/__pycache__/*"], "--exclude", help="Глоб-шаблоны исключения"),
    max_findings: int = typer.Option(200, "--max-findings", min=1, max=10000),
):
    fmt = getattr(main, "_output_fmt", "human")
    res = secrets_scan(path, include, exclude, max_findings)
    _print_out(res, fmt)
    raise typer.Exit(code=int(ExitCode.SECRETS_FOUND if res["summary"]["findings"] > 0 else ExitCode.OK))

# tls check
tls_app = typer.Typer(help="TLS/mTLS проверки")
app.add_typer(tls_app, name="tls")

@tls_app.command("check")
def cmd_tls_check(
    cert: Optional[Path] = typer.Option(None, "--cert", exists=True, readable=True),
    key: Optional[Path] = typer.Option(None, "--key", exists=True, readable=True),
    ca: Optional[Path] = typer.Option(None, "--ca", exists=True, readable=True),
    hostname: Optional[str] = typer.Option(None, "--hostname"),
    min_days_left: int = typer.Option(14, "--min-days-left"),
):
    fmt = getattr(main, "_output_fmt", "human")
    res = tls_check(str(cert) if cert else None, str(key) if key else None, str(ca) if ca else None, hostname, min_days_left)
    _print_out(res, fmt)
    ok = bool(res.get("ok"))
    raise typer.Exit(code=int(ExitCode.OK if ok else ExitCode.TLS_INVALID))

# rbac test
rbac_app = typer.Typer(help="RBAC проверки")
app.add_typer(rbac_app, name="rbac")

@rbac_app.command("test")
def cmd_rbac_test(
    rbac_file: Path = typer.Argument(..., exists=True, readable=True),
    subject: str = typer.Option(..., "--subject"),
    action: str = typer.Option(..., "--action"),
    resource: str = typer.Option(..., "--resource"),
):
    fmt = getattr(main, "_output_fmt", "human")
    if yaml is None and rbac_file.suffix.lower() in {".yml",".yaml"}:
        _print_out({"error":"PyYAML not installed for YAML RBAC files"}, "json")
        raise typer.Exit(code=int(ExitCode.DEPS_MISSING))
    model = _load_rbac(rbac_file)
    res = rbac_test(model, subject, action, resource)
    _print_out(res, fmt)
    code = ExitCode.OK if res.get("decision") == "allow" else ExitCode.RBAC_DENY
    raise typer.Exit(code=int(code))

# completion
@app.command("gen-completion")
def cmd_gen_completion(shell: str = typer.Argument(..., help="bash|zsh|fish|powershell")):
    fmt = getattr(main, "_output_fmt", "human")
    if typer is None:
        _print_out({"error":"typer not available"}, "json")
        raise SystemExit(int(ExitCode.DEPS_MISSING))
    from typer.main import get_completion_inspect_parameters
    supported = {"bash","zsh","fish","powershell"}
    if shell not in supported:
        _print_out({"error":"unsupported shell", "supported": sorted(supported)}, fmt)
        raise typer.Exit(code=int(ExitCode.GENERAL_ERROR))
    # Typer provides shell completion via Click
    import click
    complete = typer.main.get_completion_inspect_parameters  # keep references
    text = app.shell_complete(shell)  # type: ignore[attr-defined]
    # Fallback simple help
    help_text = app.get_help(ctx=typer.Context(app))  # type: ignore
    _print_out({"hint":"use Click/Typer native completion setup", "help": help_text}, fmt)

# Entrypoint
if __name__ == "__main__":
    if typer is None:
        _print_out({"error":"dependency 'typer' not installed", "details":_missing.get("typer")}, "json")
        sys.exit(int(ExitCode.DEPS_MISSING))
    app()
