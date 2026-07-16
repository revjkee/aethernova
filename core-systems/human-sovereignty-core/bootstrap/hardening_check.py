# human-sovereignty-core/bootstrap/hardening_check.py
# Industrial-grade hardening check for WebUI secure-mode startup.
#
# Design goals:
# - Deterministic, non-invasive checks by default (no network calls unless enabled).
# - Clear failure reasons + machine-readable output (JSON).
# - Defense-in-depth: config sanity, environment safety, secure headers, cookie flags, CORS, CSP, HSTS, TLS posture hints.
# - Safe defaults: refuse to pass if critical conditions are not met.
#
# Notes:
# - This module does not assume any specific framework (FastAPI/Express/Next/etc.).
# - It can be used in CI, container entrypoints, or as a pre-flight gate.
#
# Usage example (optional):
#   python -m human_sovereignty_core.bootstrap.hardening_check --config /path/to/webui.yaml --json
#
# This file asserts no external facts; it implements checks.

from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import json
import os
import re
import socket
import ssl
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None


SEVERITY_ORDER = {"INFO": 0, "WARN": 1, "FAIL": 2}


@dataclass(frozen=True)
class Finding:
    id: str
    severity: str  # INFO | WARN | FAIL
    title: str
    detail: str
    remediation: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
            "evidence": self.evidence,
        }


@dataclass
class Report:
    ok: bool
    generated_at_utc: str
    target: Dict[str, Any]
    findings: List[Finding]
    summary: Dict[str, Any]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "generated_at_utc": self.generated_at_utc,
            "target": self.target,
            "summary": self.summary,
            "findings": [f.as_dict() for f in self.findings],
        }


class HardeningCheckError(RuntimeError):
    pass


def _utc_now_iso() -> str:
    return _dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _add_finding(findings: List[Finding], f: Finding) -> None:
    if f.severity not in SEVERITY_ORDER:
        raise HardeningCheckError(f"Invalid severity: {f.severity}")
    findings.append(f)


def _worst_severity(findings: Iterable[Finding]) -> str:
    worst = "INFO"
    for f in findings:
        if SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[worst]:
            worst = f.severity
    return worst


def _is_truthy_env(name: str) -> Optional[bool]:
    if name not in os.environ:
        return None
    v = os.environ.get(name, "").strip().lower()
    if v in {"1", "true", "yes", "y", "on"}:
        return True
    if v in {"0", "false", "no", "n", "off"}:
        return False
    return None


def _read_text_file(path: str, max_bytes: int = 512_000) -> str:
    with open(path, "rb") as f:
        data = f.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise HardeningCheckError(f"File too large: {path}")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace")


def _safe_load_yaml(path: str) -> Dict[str, Any]:
    if yaml is None:
        raise HardeningCheckError(
            "PyYAML is not installed. Install pyyaml or pass config via environment."
        )
    raw = _read_text_file(path)
    obj = yaml.safe_load(raw) or {}
    if not isinstance(obj, dict):
        raise HardeningCheckError("Config root must be a mapping/dict")
    return obj


def _get(d: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
    cur: Any = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        if k not in cur:
            return default
        cur = cur[k]
    return cur


def _as_bool(v: Any) -> Optional[bool]:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)) and v in (0, 1):
        return bool(v)
    if isinstance(v, str):
        x = v.strip().lower()
        if x in {"true", "1", "yes", "y", "on"}:
            return True
        if x in {"false", "0", "no", "n", "off"}:
            return False
    return None


def _as_int(v: Any) -> Optional[int]:
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v.strip())
        except Exception:
            return None
    return None


def _normalize_host(host: str) -> str:
    return host.strip().lower()


def _is_loopback_or_private(host: str) -> bool:
    # Conservative: treat localhost and RFC1918 as non-public.
    host = _normalize_host(host)
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return False
    if ip.startswith("10."):
        return True
    if ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                return True
        except Exception:
            return False
    return False


def _parse_header_kv(raw: Any) -> Dict[str, str]:
    # Accept dict or list of "Key: Value"
    if raw is None:
        return {}
    if isinstance(raw, dict):
        out: Dict[str, str] = {}
        for k, v in raw.items():
            if isinstance(k, str) and isinstance(v, str):
                out[k.strip().lower()] = v.strip()
        return out
    if isinstance(raw, list):
        out = {}
        for item in raw:
            if not isinstance(item, str):
                continue
            if ":" not in item:
                continue
            k, v = item.split(":", 1)
            out[k.strip().lower()] = v.strip()
        return out
    return {}


def _contains_token(value: str, token: str) -> bool:
    # Tokenized check for directive fragments.
    parts = [p.strip().lower() for p in re.split(r"[;,]", value)]
    return token.strip().lower() in parts


def _check_env_debug_flags(findings: List[Finding]) -> None:
    # Common debug toggles across stacks.
    suspects = [
        "DEBUG",
        "FLASK_DEBUG",
        "NODE_ENV",
        "NEXT_PUBLIC_DEBUG",
        "FASTAPI_DEBUG",
        "DJANGO_DEBUG",
    ]
    evidence: Dict[str, Any] = {}
    debug_on = False

    for name in suspects:
        if name not in os.environ:
            continue
        val = os.environ.get(name, "")
        evidence[name] = val
        lowered = val.strip().lower()
        if name == "NODE_ENV":
            if lowered != "production":
                debug_on = True
        else:
            truth = _is_truthy_env(name)
            if truth is True:
                debug_on = True

    if debug_on:
        _add_finding(
            findings,
            Finding(
                id="env.debug.enabled",
                severity="FAIL",
                title="Debug mode is enabled in environment",
                detail="At least one debug-related environment variable indicates non-production behavior.",
                remediation="Disable debug flags (DEBUG/FLASK_DEBUG/DJANGO_DEBUG etc.) and ensure NODE_ENV=production.",
                evidence=evidence,
            ),
        )
    else:
        _add_finding(
            findings,
            Finding(
                id="env.debug.disabled",
                severity="INFO",
                title="Debug mode not detected in environment",
                detail="No obvious debug flags enabled in current environment snapshot.",
                remediation="Maintain production-safe env defaults and prevent accidental debug toggles.",
                evidence=evidence,
            ),
        )


def _check_env_secrets_hygiene(findings: List[Finding]) -> None:
    # Detect obvious placeholder secrets (best-effort, no claims).
    secret_like = [
        "SECRET",
        "TOKEN",
        "API_KEY",
        "PRIVATE_KEY",
        "PASSWORD",
        "JWT_SECRET",
        "SESSION_SECRET",
    ]
    bad_patterns = [
        r"^changeme$",
        r"^change_me$",
        r"^default$",
        r"^password$",
        r"^secret$",
        r"^test$",
        r"^example$",
        r"^123456$",
    ]

    hits: List[Tuple[str, str]] = []
    for k, v in os.environ.items():
        up = k.upper()
        if any(s in up for s in secret_like):
            if not isinstance(v, str):
                continue
            sv = v.strip()
            if not sv:
                hits.append((k, "<empty>"))
                continue
            for bp in bad_patterns:
                if re.match(bp, sv, flags=re.IGNORECASE):
                    hits.append((k, sv))
                    break

    if hits:
        _add_finding(
            findings,
            Finding(
                id="env.secrets.placeholder",
                severity="FAIL",
                title="Possible placeholder/weak secret detected",
                detail="One or more environment values that look like secrets appear empty or set to common placeholders.",
                remediation="Set strong secrets via secret manager (not plain env), rotate any exposed values, and block placeholders in CI.",
                evidence={"suspects": [{"name": k, "value": v} for k, v in hits]},
            ),
        )
    else:
        _add_finding(
            findings,
            Finding(
                id="env.secrets.no_placeholders_detected",
                severity="INFO",
                title="No obvious placeholder secrets detected",
                detail="No empty/common-placeholder values were detected among env vars that look like secrets (best-effort).",
                remediation="Keep enforcing secret scanning and avoid plaintext env secrets where possible.",
                evidence={},
            ),
        )


def _check_bind_host_port(findings: List[Finding], host: str, port: int) -> None:
    if port <= 0 or port > 65535:
        _add_finding(
            findings,
            Finding(
                id="webui.port.invalid",
                severity="FAIL",
                title="Invalid WebUI port",
                detail=f"Port {port} is outside valid range 1..65535.",
                remediation="Set a valid TCP port for WebUI.",
                evidence={"port": port},
            ),
        )
        return

    is_private = _is_loopback_or_private(host)
    if is_private:
        _add_finding(
            findings,
            Finding(
                id="webui.bind.private",
                severity="INFO",
                title="WebUI bind host appears non-public",
                detail=f"Bind host '{host}' resolves to loopback/private (best-effort).",
                remediation="If WebUI must be public, enforce TLS and reverse-proxy hardening. If not, keep it private.",
                evidence={"host": host, "port": port},
            ),
        )
    else:
        _add_finding(
            findings,
            Finding(
                id="webui.bind.public",
                severity="WARN",
                title="WebUI bind host may be public",
                detail=f"Bind host '{host}' does not look like loopback/private (best-effort).",
                remediation="If public exposure is intended, enforce TLS, strict headers, rate limiting, WAF, and least-privilege network policy.",
                evidence={"host": host, "port": port},
            ),
        )


def _check_tls_config(findings: List[Finding], cfg: Dict[str, Any]) -> None:
    tls_enabled = _as_bool(_get(cfg, ["webui", "tls", "enabled"]))
    cert_path = _get(cfg, ["webui", "tls", "cert_file"])
    key_path = _get(cfg, ["webui", "tls", "key_file"])
    behind_proxy = _as_bool(_get(cfg, ["webui", "behind_proxy"])) or False

    evidence = {
        "tls_enabled": tls_enabled,
        "cert_file": cert_path,
        "key_file": key_path,
        "behind_proxy": behind_proxy,
    }

    if tls_enabled is True:
        if not (isinstance(cert_path, str) and cert_path) or not (isinstance(key_path, str) and key_path):
            _add_finding(
                findings,
                Finding(
                    id="tls.enabled.missing_files",
                    severity="FAIL",
                    title="TLS enabled but certificate/key paths are missing",
                    detail="TLS is enabled but cert_file/key_file is not configured.",
                    remediation="Configure webui.tls.cert_file and webui.tls.key_file or disable TLS only if a hardened reverse proxy terminates TLS.",
                    evidence=evidence,
                ),
            )
            return

        missing = []
        if isinstance(cert_path, str) and not os.path.exists(cert_path):
            missing.append(cert_path)
        if isinstance(key_path, str) and not os.path.exists(key_path):
            missing.append(key_path)
        if missing:
            _add_finding(
                findings,
                Finding(
                    id="tls.enabled.files_not_found",
                    severity="FAIL",
                    title="TLS certificate/key files not found",
                    detail="Configured TLS files do not exist on filesystem (in current runtime).",
                    remediation="Mount the cert/key as secrets, ensure correct paths and permissions, and verify container/host mounts.",
                    evidence={"missing_paths": missing, **evidence},
                ),
            )
        else:
            _add_finding(
                findings,
                Finding(
                    id="tls.enabled.configured",
                    severity="INFO",
                    title="TLS appears enabled and configured",
                    detail="TLS is enabled and certificate/key paths exist (filesystem check).",
                    remediation="Ensure cert rotation, strong ciphersuites, and HSTS at the edge if applicable.",
                    evidence=evidence,
                ),
            )
    else:
        if behind_proxy:
            _add_finding(
                findings,
                Finding(
                    id="tls.disabled.behind_proxy",
                    severity="WARN",
                    title="TLS disabled; behind-proxy mode is enabled",
                    detail="TLS is disabled in WebUI app, and it is expected that an upstream reverse proxy terminates TLS.",
                    remediation="Ensure the proxy enforces TLS, HSTS, secure headers, and strips unsafe forwarded headers.",
                    evidence=evidence,
                ),
            )
        else:
            _add_finding(
                findings,
                Finding(
                    id="tls.disabled.direct",
                    severity="FAIL",
                    title="TLS appears disabled for direct WebUI exposure",
                    detail="TLS is not enabled and no hardened reverse proxy mode is declared.",
                    remediation="Enable TLS in WebUI or run behind a hardened TLS-terminating reverse proxy with strict security headers.",
                    evidence=evidence,
                ),
            )


def _check_reverse_proxy_trust(findings: List[Finding], cfg: Dict[str, Any]) -> None:
    behind_proxy = _as_bool(_get(cfg, ["webui", "behind_proxy"])) or False
    trusted_proxies = _get(cfg, ["webui", "trusted_proxies"], default=[])
    forward_headers = _as_bool(_get(cfg, ["webui", "trust_forwarded_headers"]))  # may be None

    evidence = {
        "behind_proxy": behind_proxy,
        "trusted_proxies": trusted_proxies,
        "trust_forwarded_headers": forward_headers,
    }

    if behind_proxy:
        if not isinstance(trusted_proxies, list) or not trusted_proxies:
            _add_finding(
                findings,
                Finding(
                    id="proxy.trusted_proxies.missing",
                    severity="FAIL",
                    title="Behind-proxy mode enabled but trusted proxies not configured",
                    detail="When behind a proxy, you must explicitly declare trusted proxy IPs/CIDRs to prevent spoofing.",
                    remediation="Set webui.trusted_proxies to explicit IP/CIDR list and disable blind trust of forwarded headers.",
                    evidence=evidence,
                ),
            )
        else:
            _add_finding(
                findings,
                Finding(
                    id="proxy.trusted_proxies.present",
                    severity="INFO",
                    title="Trusted proxies configured",
                    detail="Behind-proxy mode has a non-empty trusted proxy list.",
                    remediation="Keep the list minimal and align it with network policy; log and alert on invalid forwarded chains.",
                    evidence=evidence,
                ),
            )

        if forward_headers is True:
            _add_finding(
                findings,
                Finding(
                    id="proxy.forwarded_headers.enabled",
                    severity="WARN",
                    title="Forwarded headers are trusted",
                    detail="Trusting forwarded headers is risky unless strictly limited to trusted proxies.",
                    remediation="Ensure forwarded header parsing is restricted to trusted_proxies and strips untrusted input.",
                    evidence=evidence,
                ),
            )
        elif forward_headers is False:
            _add_finding(
                findings,
                Finding(
                    id="proxy.forwarded_headers.disabled",
                    severity="INFO",
                    title="Forwarded headers trust is disabled",
                    detail="The app does not blindly trust forwarded headers.",
                    remediation="If you need client IP or scheme from proxy, enable it only with strict trusted_proxies.",
                    evidence=evidence,
                ),
            )
        else:
            _add_finding(
                findings,
                Finding(
                    id="proxy.forwarded_headers.unspecified",
                    severity="WARN",
                    title="Forwarded headers trust not explicitly configured",
                    detail="The configuration does not clearly declare whether forwarded headers are trusted.",
                    remediation="Explicitly set webui.trust_forwarded_headers to true/false and configure trusted_proxies accordingly.",
                    evidence=evidence,
                ),
            )
    else:
        _add_finding(
            findings,
            Finding(
                id="proxy.not_enabled",
                severity="INFO",
                title="Behind-proxy mode not enabled",
                detail="WebUI is not declared to run behind a reverse proxy.",
                remediation="If deploying behind a proxy, enable behind_proxy and set trusted_proxies to prevent spoofing.",
                evidence=evidence,
            ),
        )


def _check_security_headers(findings: List[Finding], cfg: Dict[str, Any]) -> None:
    headers_cfg = _parse_header_kv(_get(cfg, ["webui", "security_headers"]))
    # Allow reading from environment override
    env_headers_raw = os.environ.get("WEBUI_SECURITY_HEADERS")
    if env_headers_raw:
        try:
            env_obj = json.loads(env_headers_raw)
            if isinstance(env_obj, dict):
                headers_cfg.update({str(k).strip().lower(): str(v).strip() for k, v in env_obj.items()})
        except Exception:
            # Keep config headers; environment malformed is itself a warning.
            _add_finding(
                findings,
                Finding(
                    id="headers.env.malformed",
                    severity="WARN",
                    title="WEBUI_SECURITY_HEADERS environment override is malformed",
                    detail="WEBUI_SECURITY_HEADERS exists but is not valid JSON object.",
                    remediation="Provide valid JSON object, e.g. {'content-security-policy':'...'} (as JSON).",
                    evidence={"WEBUI_SECURITY_HEADERS": env_headers_raw[:256]},
                ),
            )

    # Required baseline
    required = {
        "x-content-type-options": lambda v: v.strip().lower() == "nosniff",
        "x-frame-options": lambda v: v.strip().upper() in {"DENY", "SAMEORIGIN"},
        "referrer-policy": lambda v: len(v.strip()) > 0,
        "permissions-policy": lambda v: len(v.strip()) > 0,
    }

    for name, predicate in required.items():
        if name not in headers_cfg:
            _add_finding(
                findings,
                Finding(
                    id=f"headers.missing.{name}",
                    severity="FAIL",
                    title=f"Missing security header: {name}",
                    detail=f"'{name}' is not configured in webui.security_headers.",
                    remediation=f"Configure '{name}' with a safe value and ensure it is returned on all responses.",
                    evidence={"configured_headers": sorted(list(headers_cfg.keys()))},
                ),
            )
        else:
            ok = False
            try:
                ok = bool(predicate(headers_cfg[name]))
            except Exception:
                ok = False
            if ok:
                _add_finding(
                    findings,
                    Finding(
                        id=f"headers.present.{name}",
                        severity="INFO",
                        title=f"Security header configured: {name}",
                        detail=f"'{name}' exists and passes a basic sanity predicate.",
                        remediation="Keep consistent across routes and verify at edge/proxy as well.",
                        evidence={name: headers_cfg[name]},
                    ),
                )
            else:
                _add_finding(
                    findings,
                    Finding(
                        id=f"headers.weak.{name}",
                        severity="WARN",
                        title=f"Security header may be weak: {name}",
                        detail=f"'{name}' is present but does not match safe baseline checks.",
                        remediation=f"Review '{name}' value and align with your threat model.",
                        evidence={name: headers_cfg[name]},
                    ),
                )

    # HSTS is essential when TLS is used at the client boundary.
    hsts = headers_cfg.get("strict-transport-security")
    tls_enabled = _as_bool(_get(cfg, ["webui", "tls", "enabled"]))
    behind_proxy = _as_bool(_get(cfg, ["webui", "behind_proxy"])) or False
    if (tls_enabled is True) or behind_proxy:
        if not hsts:
            _add_finding(
                findings,
                Finding(
                    id="headers.missing.hsts",
                    severity="WARN",
                    title="HSTS header not configured",
                    detail="Strict-Transport-Security is not configured while TLS/proxy mode is expected.",
                    remediation="Enable HSTS at the edge (recommended) with an appropriate max-age and includeSubDomains if applicable.",
                    evidence={"strict-transport-security": hsts},
                ),
            )
        else:
            _add_finding(
                findings,
                Finding(
                    id="headers.present.hsts",
                    severity="INFO",
                    title="HSTS header configured",
                    detail="Strict-Transport-Security is present (value not fully validated).",
                    remediation="Ensure it is only served over HTTPS and has appropriate max-age.",
                    evidence={"strict-transport-security": hsts},
                ),
            )

    # CSP baseline
    csp = headers_cfg.get("content-security-policy")
    if not csp:
        _add_finding(
            findings,
            Finding(
                id="headers.missing.csp",
                severity="FAIL",
                title="Missing Content-Security-Policy",
                detail="CSP is not configured. This increases risk of XSS and data exfiltration.",
                remediation="Configure a strict CSP, avoid 'unsafe-inline', and define script-src/style-src/connect-src/frame-ancestors.",
                evidence={},
            ),
        )
    else:
        lc = csp.lower()
        if "unsafe-inline" in lc or "unsafe-eval" in lc:
            _add_finding(
                findings,
                Finding(
                    id="headers.csp.unsafe_tokens",
                    severity="WARN",
                    title="CSP contains unsafe tokens",
                    detail="CSP contains 'unsafe-inline' or 'unsafe-eval', weakening XSS protections.",
                    remediation="Remove unsafe tokens, use nonces/hashes, and tighten script-src/style-src.",
                    evidence={"content-security-policy": csp[:512]},
                ),
            )
        else:
            _add_finding(
                findings,
                Finding(
                    id="headers.csp.present",
                    severity="INFO",
                    title="CSP configured without obvious unsafe tokens",
                    detail="CSP is present and does not include 'unsafe-inline'/'unsafe-eval' (best-effort).",
                    remediation="Still validate CSP coverage and report-only rollout strategy if needed.",
                    evidence={"content-security-policy": csp[:512]},
                ),
            )


def _check_cors(findings: List[Finding], cfg: Dict[str, Any]) -> None:
    cors = _get(cfg, ["webui", "cors"], default={})
    if not isinstance(cors, dict):
        cors = {}

    enabled = _as_bool(cors.get("enabled"))
    allow_origins = cors.get("allow_origins", [])
    allow_credentials = _as_bool(cors.get("allow_credentials"))
    evidence = {"enabled": enabled, "allow_origins": allow_origins, "allow_credentials": allow_credentials}

    if enabled is False:
        _add_finding(
            findings,
            Finding(
                id="cors.disabled",
                severity="INFO",
                title="CORS disabled",
                detail="CORS appears disabled at app level.",
                remediation="If WebUI is accessed cross-origin, enable CORS with strict allowlist and avoid wildcard with credentials.",
                evidence=evidence,
            ),
        )
        return

    if enabled is None:
        _add_finding(
            findings,
            Finding(
                id="cors.unspecified",
                severity="WARN",
                title="CORS configuration not explicit",
                detail="CORS enabled/disabled is not explicitly configured.",
                remediation="Explicitly set webui.cors.enabled true/false and specify strict allowlist if enabled.",
                evidence=evidence,
            ),
        )

    # If enabled or unspecified, validate allowlist.
    if isinstance(allow_origins, str):
        allow_origins = [allow_origins]
    if not isinstance(allow_origins, list):
        allow_origins = []

    lowered = [str(o).strip().lower() for o in allow_origins if str(o).strip()]
    if "*" in lowered:
        if allow_credentials is True:
            _add_finding(
                findings,
                Finding(
                    id="cors.wildcard.with_credentials",
                    severity="FAIL",
                    title="CORS uses wildcard with credentials",
                    detail="Allowing '*' origins together with credentials is unsafe.",
                    remediation="Replace wildcard with explicit origin allowlist and keep allow_credentials minimal.",
                    evidence=evidence,
                ),
            )
        else:
            _add_finding(
                findings,
                Finding(
                    id="cors.wildcard",
                    severity="WARN",
                    title="CORS uses wildcard origins",
                    detail="Wildcard origins can be risky depending on endpoints and tokens.",
                    remediation="Use explicit allowlist of trusted origins.",
                    evidence=evidence,
                ),
            )
    else:
        if lowered:
            _add_finding(
                findings,
                Finding(
                    id="cors.allowlist.present",
                    severity="INFO",
                    title="CORS allowlist present",
                    detail="CORS allow_origins is an explicit list (best-effort).",
                    remediation="Ensure allowlist matches production domains only; avoid dev origins in prod.",
                    evidence=evidence,
                ),
            )
        else:
            _add_finding(
                findings,
                Finding(
                    id="cors.allowlist.missing",
                    severity="WARN",
                    title="CORS enabled but allowlist is empty",
                    detail="CORS appears enabled but allow_origins is empty or invalid.",
                    remediation="Set explicit allow_origins to trusted domains or disable CORS.",
                    evidence=evidence,
                ),
            )


def _check_session_cookie(findings: List[Finding], cfg: Dict[str, Any]) -> None:
    cookie = _get(cfg, ["webui", "session_cookie"], default={})
    if not isinstance(cookie, dict):
        cookie = {}

    secure = _as_bool(cookie.get("secure"))
    http_only = _as_bool(cookie.get("http_only"))
    same_site = str(cookie.get("same_site", "")).strip()
    evidence = {"secure": secure, "http_only": http_only, "same_site": same_site}

    if secure is not True:
        _add_finding(
            findings,
            Finding(
                id="cookie.secure.missing",
                severity="FAIL",
                title="Session cookie Secure flag not enforced",
                detail="Session cookie Secure flag is not explicitly true.",
                remediation="Set webui.session_cookie.secure=true and ensure HTTPS at client boundary.",
                evidence=evidence,
            ),
        )
    else:
        _add_finding(
            findings,
            Finding(
                id="cookie.secure.ok",
                severity="INFO",
                title="Session cookie Secure flag enforced",
                detail="Session cookie Secure appears enabled.",
                remediation="Keep HTTPS-only session cookies and verify proxy doesn't strip flags.",
                evidence=evidence,
            ),
        )

    if http_only is not True:
        _add_finding(
            findings,
            Finding(
                id="cookie.http_only.missing",
                severity="FAIL",
                title="Session cookie HttpOnly flag not enforced",
                detail="HttpOnly is not explicitly true; JS access to cookies increases XSS impact.",
                remediation="Set webui.session_cookie.http_only=true.",
                evidence=evidence,
            ),
        )
    else:
        _add_finding(
            findings,
            Finding(
                id="cookie.http_only.ok",
                severity="INFO",
                title="Session cookie HttpOnly flag enforced",
                detail="HttpOnly appears enabled.",
                remediation="Maintain HttpOnly and use CSP to reduce XSS risk.",
                evidence=evidence,
            ),
        )

    if same_site.lower() not in {"lax", "strict", "none"}:
        _add_finding(
            findings,
            Finding(
                id="cookie.same_site.invalid",
                severity="WARN",
                title="Session cookie SameSite is not configured to a known value",
                detail="SameSite should be one of: Lax, Strict, None.",
                remediation="Set webui.session_cookie.same_site to 'Lax' or 'Strict' for most cases; 'None' only with Secure and cross-site needs.",
                evidence=evidence,
            ),
        )
    else:
        if same_site.lower() == "none" and secure is not True:
            _add_finding(
                findings,
                Finding(
                    id="cookie.same_site.none_without_secure",
                    severity="FAIL",
                    title="SameSite=None without Secure",
                    detail="SameSite=None requires Secure for modern browsers and for safety.",
                    remediation="Set Secure=true or avoid SameSite=None.",
                    evidence=evidence,
                ),
            )
        else:
            _add_finding(
                findings,
                Finding(
                    id="cookie.same_site.ok",
                    severity="INFO",
                    title="Session cookie SameSite configured",
                    detail="SameSite is configured to a known value.",
                    remediation="Validate cross-site flows; prefer Lax/Strict where possible.",
                    evidence=evidence,
                ),
            )


def _check_rate_limit_and_csrf(findings: List[Finding], cfg: Dict[str, Any]) -> None:
    rl = _get(cfg, ["webui", "rate_limit"], default={})
    csrf = _get(cfg, ["webui", "csrf"], default={})
    if not isinstance(rl, dict):
        rl = {}
    if not isinstance(csrf, dict):
        csrf = {}

    rl_enabled = _as_bool(rl.get("enabled"))
    csrf_enabled = _as_bool(csrf.get("enabled"))
    evidence = {"rate_limit_enabled": rl_enabled, "csrf_enabled": csrf_enabled}

    if rl_enabled is True:
        _add_finding(
            findings,
            Finding(
                id="ratelimit.enabled",
                severity="INFO",
                title="Rate limiting enabled",
                detail="Rate limiting appears enabled.",
                remediation="Ensure limits are tuned, include per-IP/per-token controls, and protect auth endpoints.",
                evidence=evidence,
            ),
        )
    else:
        _add_finding(
            findings,
            Finding(
                id="ratelimit.disabled_or_unspecified",
                severity="WARN",
                title="Rate limiting disabled or not configured",
                detail="Rate limiting is not explicitly enabled.",
                remediation="Enable rate limiting at the edge (preferred) or in-app to mitigate brute force and abuse.",
                evidence=evidence,
            ),
        )

    if csrf_enabled is True:
        _add_finding(
            findings,
            Finding(
                id="csrf.enabled",
                severity="INFO",
                title="CSRF protection enabled",
                detail="CSRF protection appears enabled.",
                remediation="Ensure state-changing routes require CSRF tokens and SameSite cookies are aligned.",
                evidence=evidence,
            ),
        )
    else:
        _add_finding(
            findings,
            Finding(
                id="csrf.disabled_or_unspecified",
                severity="WARN",
                title="CSRF protection disabled or not configured",
                detail="CSRF protection is not explicitly enabled.",
                remediation="Enable CSRF defenses for cookie-based sessions and validate origin/referer where appropriate.",
                evidence=evidence,
            ),
        )


def _check_logging_audit(findings: List[Finding], cfg: Dict[str, Any]) -> None:
    audit = _get(cfg, ["webui", "audit_log"], default={})
    if not isinstance(audit, dict):
        audit = {}
    enabled = _as_bool(audit.get("enabled"))
    sink = audit.get("sink")
    pii_redaction = _as_bool(audit.get("pii_redaction"))
    evidence = {"enabled": enabled, "sink": sink, "pii_redaction": pii_redaction}

    if enabled is True and isinstance(sink, str) and sink.strip():
        _add_finding(
            findings,
            Finding(
                id="audit.enabled",
                severity="INFO",
                title="Audit logging configured",
                detail="Audit logging appears enabled with a sink configured.",
                remediation="Ensure immutable storage, retention policy, and access controls around audit logs.",
                evidence=evidence,
            ),
        )
    else:
        _add_finding(
            findings,
            Finding(
                id="audit.missing",
                severity="WARN",
                title="Audit logging not fully configured",
                detail="Audit logging is disabled or missing sink configuration.",
                remediation="Enable audit logging for auth, admin actions, config changes, and security events with secure retention.",
                evidence=evidence,
            ),
        )

    if pii_redaction is True:
        _add_finding(
            findings,
            Finding(
                id="audit.pii_redaction.enabled",
                severity="INFO",
                title="PII redaction enabled for audit logs",
                detail="PII redaction is enabled (config-level).",
                remediation="Validate redaction coverage and add tests for sensitive fields.",
                evidence=evidence,
            ),
        )
    else:
        _add_finding(
            findings,
            Finding(
                id="audit.pii_redaction.disabled_or_unspecified",
                severity="WARN",
                title="PII redaction not enabled or not configured",
                detail="PII redaction is not explicitly enabled.",
                remediation="Enable redaction/tokenization for sensitive fields to reduce impact of log exposure.",
                evidence=evidence,
            ),
        )


def _tls_probe(host: str, port: int, timeout_s: float = 2.5) -> Dict[str, Any]:
    # Best-effort, no guarantees. Used only if --probe-network is set.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    info: Dict[str, Any] = {}
    with socket.create_connection((host, port), timeout=timeout_s) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            info["tls_version"] = ssock.version()
            cipher = ssock.cipher()
            if cipher:
                info["cipher"] = {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]}
            cert = ssock.getpeercert(binary_form=False)
            info["peer_cert_present"] = bool(cert)
    return info


def _check_optional_tls_probe(findings: List[Finding], host: str, port: int, probe: bool) -> None:
    if not probe:
        _add_finding(
            findings,
            Finding(
                id="tls.probe.skipped",
                severity="INFO",
                title="TLS probe skipped",
                detail="Network TLS probe is disabled by default to avoid side effects.",
                remediation="Enable --probe-network only in controlled environments if you want runtime TLS handshake info.",
                evidence={"probe_enabled": False},
            ),
        )
        return

    try:
        info = _tls_probe(host, port)
        _add_finding(
            findings,
            Finding(
                id="tls.probe.ok",
                severity="INFO",
                title="TLS probe succeeded",
                detail="A TLS handshake was performed to gather runtime info (best-effort).",
                remediation="Use this info as an indicator only; enforce TLS configuration at proxy/app level.",
                evidence=info,
            ),
        )
    except Exception as e:
        _add_finding(
            findings,
            Finding(
                id="tls.probe.failed",
                severity="WARN",
                title="TLS probe failed",
                detail="TLS handshake probe failed (best-effort). This may indicate TLS not enabled, port not reachable, or handshake issues.",
                remediation="Verify service reachability, TLS termination, and network policies.",
                evidence={"error": str(e)},
            ),
        )


def run_hardening_check(
    config: Dict[str, Any],
    *,
    probe_network: bool,
    target_override: Optional[Dict[str, Any]] = None,
) -> Report:
    findings: List[Finding] = []

    host = str(_get(config, ["webui", "bind_host"], default="127.0.0.1"))
    port = _as_int(_get(config, ["webui", "port"], default=3000)) or 3000

    target = {
        "component": "webui",
        "bind_host": host,
        "port": port,
        "behind_proxy": _as_bool(_get(config, ["webui", "behind_proxy"])) or False,
        "tls_enabled": _as_bool(_get(config, ["webui", "tls", "enabled"])),
    }
    if target_override:
        target.update(target_override)

    _check_env_debug_flags(findings)
    _check_env_secrets_hygiene(findings)

    _check_bind_host_port(findings, host, port)
    _check_tls_config(findings, config)
    _check_reverse_proxy_trust(findings, config)
    _check_security_headers(findings, config)
    _check_cors(findings, config)
    _check_session_cookie(findings, config)
    _check_rate_limit_and_csrf(findings, config)
    _check_logging_audit(findings, config)

    _check_optional_tls_probe(findings, host, port, probe_network)

    worst = _worst_severity(findings)
    ok = worst != "FAIL"

    summary = {
        "worst_severity": worst,
        "counts": {
            "INFO": sum(1 for f in findings if f.severity == "INFO"),
            "WARN": sum(1 for f in findings if f.severity == "WARN"),
            "FAIL": sum(1 for f in findings if f.severity == "FAIL"),
        },
    }

    return Report(
        ok=ok,
        generated_at_utc=_utc_now_iso(),
        target=target,
        findings=findings,
        summary=summary,
    )


def _load_config_from_env() -> Dict[str, Any]:
    # Minimal env-based config to allow running without YAML.
    # Values are best-effort and intentionally limited.
    cfg: Dict[str, Any] = {"webui": {}}
    webui = cfg["webui"]

    if "WEBUI_BIND_HOST" in os.environ:
        webui["bind_host"] = os.environ["WEBUI_BIND_HOST"]
    if "WEBUI_PORT" in os.environ:
        p = _as_int(os.environ["WEBUI_PORT"])
        if p is not None:
            webui["port"] = p

    tls_enabled = _is_truthy_env("WEBUI_TLS_ENABLED")
    if tls_enabled is not None:
        webui.setdefault("tls", {})["enabled"] = tls_enabled
        if "WEBUI_TLS_CERT_FILE" in os.environ:
            webui["tls"]["cert_file"] = os.environ["WEBUI_TLS_CERT_FILE"]
        if "WEBUI_TLS_KEY_FILE" in os.environ:
            webui["tls"]["key_file"] = os.environ["WEBUI_TLS_KEY_FILE"]

    behind_proxy = _is_truthy_env("WEBUI_BEHIND_PROXY")
    if behind_proxy is not None:
        webui["behind_proxy"] = behind_proxy

    if "WEBUI_TRUSTED_PROXIES" in os.environ:
        # Comma-separated list
        items = [x.strip() for x in os.environ["WEBUI_TRUSTED_PROXIES"].split(",") if x.strip()]
        webui["trusted_proxies"] = items

    trust_fwd = _is_truthy_env("WEBUI_TRUST_FORWARDED_HEADERS")
    if trust_fwd is not None:
        webui["trust_forwarded_headers"] = trust_fwd

    # Security headers via JSON
    if "WEBUI_SECURITY_HEADERS" in os.environ:
        try:
            obj = json.loads(os.environ["WEBUI_SECURITY_HEADERS"])
            if isinstance(obj, dict):
                webui["security_headers"] = obj
        except Exception:
            # keep as-is; handled by checker
            webui["security_headers"] = {"__malformed__": os.environ["WEBUI_SECURITY_HEADERS"][:256]}

    # Cookie flags
    cookie: Dict[str, Any] = {}
    if "WEBUI_COOKIE_SECURE" in os.environ:
        b = _is_truthy_env("WEBUI_COOKIE_SECURE")
        if b is not None:
            cookie["secure"] = b
    if "WEBUI_COOKIE_HTTPONLY" in os.environ:
        b = _is_truthy_env("WEBUI_COOKIE_HTTPONLY")
        if b is not None:
            cookie["http_only"] = b
    if "WEBUI_COOKIE_SAMESITE" in os.environ:
        cookie["same_site"] = os.environ["WEBUI_COOKIE_SAMESITE"].strip()
    if cookie:
        webui["session_cookie"] = cookie

    # CORS
    cors: Dict[str, Any] = {}
    cors_enabled = _is_truthy_env("WEBUI_CORS_ENABLED")
    if cors_enabled is not None:
        cors["enabled"] = cors_enabled
    if "WEBUI_CORS_ALLOW_ORIGINS" in os.environ:
        cors["allow_origins"] = [x.strip() for x in os.environ["WEBUI_CORS_ALLOW_ORIGINS"].split(",") if x.strip()]
    cors_creds = _is_truthy_env("WEBUI_CORS_ALLOW_CREDENTIALS")
    if cors_creds is not None:
        cors["allow_credentials"] = cors_creds
    if cors:
        webui["cors"] = cors

    # Rate limit / CSRF / Audit
    rl_enabled = _is_truthy_env("WEBUI_RATELIMIT_ENABLED")
    if rl_enabled is not None:
        webui["rate_limit"] = {"enabled": rl_enabled}
    csrf_enabled = _is_truthy_env("WEBUI_CSRF_ENABLED")
    if csrf_enabled is not None:
        webui["csrf"] = {"enabled": csrf_enabled}
    audit_enabled = _is_truthy_env("WEBUI_AUDIT_ENABLED")
    if audit_enabled is not None:
        webui["audit_log"] = {"enabled": audit_enabled, "sink": os.environ.get("WEBUI_AUDIT_SINK")}
        red = _is_truthy_env("WEBUI_AUDIT_PII_REDACTION")
        if red is not None:
            webui["audit_log"]["pii_redaction"] = red

    return cfg


def _format_human(report: Report) -> str:
    lines: List[str] = []
    lines.append(f"Hardening report (generated_at={report.generated_at_utc})")
    lines.append(f"Target: {report.target}")
    lines.append(f"Summary: {report.summary}")
    lines.append("")
    # Sort findings by severity then id for stable output
    ordered = sorted(
        report.findings,
        key=lambda f: (-SEVERITY_ORDER[f.severity], f.id),
    )
    for f in ordered:
        lines.append(f"[{f.severity}] {f.id} - {f.title}")
        lines.append(f"  Detail: {f.detail}")
        lines.append(f"  Remediation: {f.remediation}")
        if f.evidence:
            ev = json.dumps(f.evidence, ensure_ascii=False, sort_keys=True)
            lines.append(f"  Evidence: {ev}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="hardening_check",
        description="Pre-flight hardening check for WebUI secure-mode startup.",
    )
    parser.add_argument(
        "--config",
        default="",
        help="Path to WebUI YAML config (optional). If omitted, environment-based config is used.",
    )
    parser.add_argument(
        "--probe-network",
        action="store_true",
        help="Enable best-effort TLS handshake probe to bind_host:port (disabled by default).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON report.",
    )
    parser.add_argument(
        "--fail-on-warn",
        action="store_true",
        help="Exit non-zero if any WARN is present (stricter gate).",
    )
    args = parser.parse_args(argv)

    if args.config:
        cfg = _safe_load_yaml(args.config)
    else:
        cfg = _load_config_from_env()

    report = run_hardening_check(cfg, probe_network=args.probe_network)

    if args.json:
        sys.stdout.write(json.dumps(report.as_dict(), ensure_ascii=False, indent=2) + "\n")
    else:
        sys.stdout.write(_format_human(report))

    if not report.ok:
        return 2
    if args.fail_on_warn and report.summary.get("counts", {}).get("WARN", 0) > 0:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
